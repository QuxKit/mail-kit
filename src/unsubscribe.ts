// Unsubscribe: per-recipient tokens and the RFC 8058 one-click handler.
//
// A token is an HMAC over (tenant, recipient, list) under the mail key —
// nothing is written when it is minted, so a campaign to a million people
// costs a million HMACs and no rows, and a token stays valid for as long as
// the key does (mailbox providers press the button months later). Presenting
// it back is what writes: `handleOneClick` verifies and adds a suppression
// with reason `unsubscribe`, scoped to the tenant and, when the token names
// one, the list. `send` mints and sets `List-Unsubscribe` +
// `List-Unsubscribe-Post` itself when `config.unsubscribeUrl` is present, and
// drops recipients that have unsubscribed from the message's list.

import { hmacSha256, keyFromHex, safeEqual } from './crypto.ts';
import { MailError } from './errors.ts';
import { normaliseForSuppression, type SuppressionApi } from './suppression.ts';
import type { MailConfig, Suppression, TenantId } from './types.ts';

export interface UnsubscribeOptions {
  suppression: SuppressionApi;
  config: MailConfig;
}

export interface UnsubscribeInput {
  tenantId: TenantId;
  recipient: string;
  /** Scope the unsubscribe to one list; absent means the whole tenant. */
  listId?: string;
}

export interface UnsubscribeClaims {
  tenantId: TenantId;
  recipient: string;
  listId: string | null;
}

/**
 * The request shape `handleOneClick` reads: what every framework can produce
 * in two lines. `headers` may be a plain record or anything with `get`
 * (the Fetch `Headers` class); `body` is the raw text body, if any.
 */
export interface OneClickRequest {
  method: string;
  /** Absolute or path-and-query; the token is read from `?token=` or, failing
   *  that, the last path segment. Or hand it in via `opts.token`. */
  url: string;
  headers?: Record<string, string | string[] | undefined> | { get(name: string): string | null };
  body?: string | null;
}

export interface OneClickResponse {
  status: 200 | 400 | 405;
  body: string;
  /** The row written (or found) on success. */
  suppression?: Suppression;
  claims?: UnsubscribeClaims;
}

export interface UnsubscribeApi {
  /** Mint a token. Requires `config.dkimKey` (`mail_key_required`). */
  token(input: UnsubscribeInput): string;
  /** The absolute URL for a token, from `config.unsubscribeUrl`
   *  (`{token}` substituted, or `?token=` appended). Null without a template. */
  url(input: UnsubscribeInput): string | null;
  /** Check a token and return what it names, or throw `signature_invalid`. */
  verify(token: string): UnsubscribeClaims;
  /**
   * The RFC 8058 endpoint. A `POST` whose body is `List-Unsubscribe=One-Click`
   * with a valid token adds the suppression and answers 200; a wrong method
   * is 405, anything else 400 — never a reason a probe could learn from. Also
   * fine to call from a confirmation page's own submit: same effect.
   */
  handleOneClick(req: OneClickRequest, opts?: { token?: string }): Promise<OneClickResponse>;
  /** What `handleOneClick` does once the token is verified, for a host that
   *  drives its own page: add the suppression for the claims. */
  apply(claims: UnsubscribeClaims): Promise<Suppression>;
}

const VERSION = 'u1';
const SEP = '\n';

const b64url = (b: Uint8Array | string): string => Buffer.from(b).toString('base64url');

export function createUnsubscribe(opts: UnsubscribeOptions): UnsubscribeApi {
  const { suppression, config } = opts;
  let derived: Buffer | null = null;
  // A key of its own, derived from the mail key, so the AES key never keys
  // an HMAC directly and the two uses cannot be confused.
  const key = (): Buffer => {
    if (!derived) {
      if (!config.dkimKey) throw new MailError({ code: 'mail_key_required', purpose: 'unsubscribe tokens' });
      derived = hmacSha256(keyFromHex(config.dkimKey, 'config.dkimKey'), 'mail-kit/unsubscribe/v1');
    }
    return derived;
  };
  const payloadOf = (c: UnsubscribeClaims): string => [c.tenantId, c.recipient, c.listId ?? ''].join(SEP);
  const bad = (reason: string) => new MailError({ code: 'signature_invalid', reason: `unsubscribe token ${reason}` });

  const api: UnsubscribeApi = {
    token(input) {
      const claims: UnsubscribeClaims = {
        tenantId: input.tenantId,
        recipient: normaliseForSuppression(input.recipient),
        listId: input.listId ?? null,
      };
      if (
        !claims.tenantId ||
        !claims.recipient ||
        claims.tenantId.includes(SEP) ||
        (input.listId ?? '').includes(SEP)
      ) {
        throw new MailError({ code: 'invalid_input', reason: 'unsubscribe token needs a tenantId and recipient' });
      }
      const payload = payloadOf(claims);
      return `${VERSION}.${b64url(payload)}.${b64url(hmacSha256(key(), payload))}`;
    },

    url(input) {
      const template = config.unsubscribeUrl;
      if (!template) return null;
      const t = api.token(input);
      if (template.includes('{token}')) return template.replace('{token}', t);
      return `${template}${template.includes('?') ? '&' : '?'}token=${t}`;
    },

    verify(token) {
      if (typeof token !== 'string' || token.length > 4096) throw bad('is malformed');
      const [version, payload64, sig64, extra] = token.split('.');
      if (version !== VERSION || !payload64 || !sig64 || extra !== undefined) throw bad('is malformed');
      const payload = Buffer.from(payload64, 'base64url').toString('utf8');
      const expected = hmacSha256(key(), payload);
      const given = Buffer.from(sig64, 'base64url');
      // Re-encode to refuse a token whose base64 was altered without changing
      // the bytes (a padding trick would otherwise pass safeEqual).
      if (b64url(payload) !== payload64 || b64url(given) !== sig64) throw bad('is malformed');
      if (!safeEqual(expected, given)) throw bad('does not verify');
      const [tenantId, recipient, listId, more] = payload.split(SEP);
      if (!tenantId || !recipient || listId === undefined || more !== undefined) throw bad('is malformed');
      return { tenantId, recipient, listId: listId === '' ? null : listId };
    },

    async apply(claims) {
      return suppression.add(claims.tenantId, {
        address: claims.recipient,
        reason: 'unsubscribe',
        detail: 'one-click',
        listId: claims.listId ?? undefined,
      });
    },

    async handleOneClick(req, o) {
      if (req.method.toUpperCase() !== 'POST') return { status: 405, body: 'POST required' };
      const contentType = header(req.headers, 'content-type') ?? '';
      const body = req.body ?? '';
      // RFC 8058 §3.2: the body carries exactly `List-Unsubscribe=One-Click`,
      // as form-urlencoded or multipart/form-data. Either way the literal is
      // in the body; a JSON or empty POST is not a one-click.
      const oneClick =
        (/^application\/x-www-form-urlencoded/i.test(contentType) && formHas(body, 'List-Unsubscribe', 'One-Click')) ||
        (/^multipart\/form-data/i.test(contentType) && /List-Unsubscribe.*\r?\n\r?\nOne-Click/s.test(body));
      if (!oneClick) return { status: 400, body: 'expected List-Unsubscribe=One-Click' };
      const token = o?.token ?? tokenFromUrl(req.url);
      if (!token) return { status: 400, body: 'invalid token' };
      let claims: UnsubscribeClaims;
      try {
        claims = api.verify(token);
      } catch (error) {
        if (MailError.is(error) && error.code !== 'mail_key_required') return { status: 400, body: 'invalid token' };
        throw error;
      }
      const written = await api.apply(claims);
      return { status: 200, body: 'unsubscribed', suppression: written, claims };
    },
  };
  return api;
}

function header(headers: OneClickRequest['headers'], name: string): string | undefined {
  if (!headers) return undefined;
  if (typeof (headers as { get?: unknown }).get === 'function') {
    return (headers as { get(n: string): string | null }).get(name) ?? undefined;
  }
  for (const [k, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
    if (k.toLowerCase() === name) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

function formHas(body: string, name: string, value: string): boolean {
  for (const pair of body.split('&')) {
    const [k, v] = pair.split('=');
    try {
      if (k !== undefined && decodeURIComponent(k.replace(/\+/g, ' ')) === name) {
        return decodeURIComponent((v ?? '').replace(/\+/g, ' ')) === value;
      }
    } catch {
      return false;
    }
  }
  return false;
}

function tokenFromUrl(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url, 'http://placeholder.invalid');
  } catch {
    return null;
  }
  const q = u.searchParams.get('token');
  if (q) return q;
  const last = u.pathname.split('/').filter(Boolean).pop();
  return last ? decodeURIComponent(last) : null;
}
