// A minimal, correct RFC 5322 / MIME builder.
//
// It exists because every transport (SES raw, SMTP DATA, a memory sink that
// tests can read) wants the same finished bytes, and because DKIM signs those
// bytes: the message has to be built once, deterministically, and handed round
// unchanged. Nothing here is clever — CRLF everywhere, quoted-printable for
// text, base64 for binary, encoded-words for non-ASCII headers, headers checked
// for line breaks before they are written.

import { randomBytes } from 'node:crypto';
import { encodeWord, type ParsedAddress, renderAddress } from './address.ts';
import { MailError } from './errors.ts';
import type { Attachment, ListUnsubscribe } from './types.ts';

export interface MimeInput {
  from: ParsedAddress;
  to: ParsedAddress[];
  cc?: ParsedAddress[];
  replyTo?: ParsedAddress[];
  subject: string;
  text?: string;
  html?: string;
  headers?: Record<string, string>;
  attachments?: readonly Attachment[];
  listUnsubscribe?: ListUnsubscribe;
  messageId: string;
  date: Date;
  /**
   * Multipart boundaries to use, in the order `buildMimeDetailed` reported
   * them, instead of fresh random ones — what makes a rebuild byte-identical
   * to the original. Extra entries are ignored; missing ones are generated.
   */
  boundaries?: readonly string[];
}

const CRLF = '\r\n';

/** Header names mail-kit sets itself; a caller's `headers` may not override
 *  them, because they are what the envelope, threading and DKIM rely on. */
const RESERVED = new Set([
  'from',
  'to',
  'cc',
  'bcc',
  'subject',
  'date',
  'message-id',
  'mime-version',
  'content-type',
  'content-transfer-encoding',
  'reply-to',
  'return-path',
]);

export function assertHeaderSafe(name: string, value: string): void {
  if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) throw new MailError({ code: 'header_injection', header: name });
  if (!/^[!-9;-~]+$/.test(name))
    throw new MailError({
      code: 'invalid_input',
      reason: `header name ${JSON.stringify(name)} is not a valid field name`,
    });
}

/** `<random@domain>` — the domain is the sender's, so the id is attributable. */
export function newMessageId(domain: string): string {
  return `<${randomBytes(16).toString('hex')}@${domain}>`;
}

/** Encode a free-text header value (Subject) — encoded-word if non-ASCII. */
export function headerText(value: string): string {
  return /[^\u0020-\u007e]/.test(value) ? encodeWord(value) : value;
}

/** RFC 5322 date. */
export function rfc5322Date(d: Date): string {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const p = (n: number) => String(n).padStart(2, '0');
  return (
    `${days[d.getUTCDay()]}, ${p(d.getUTCDate())} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`
  );
}

/** Quoted-printable (RFC 2045 §6.7): soft line breaks at 76, trailing
 *  whitespace protected, `=` escaped, CRLF preserved. */
export function quotedPrintable(text: string): string {
  const bytes = Buffer.from(text.replace(/\r?\n/g, CRLF), 'utf8');
  const out: string[] = [];
  let line = '';
  const flush = (soft: boolean) => {
    out.push(soft ? `${line}=` : line);
    line = '';
  };
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i] ?? 0;
    if (b === 0x0d && bytes[i + 1] === 0x0a) {
      // protect trailing whitespace on the line before a hard break
      if (line.endsWith(' ') || line.endsWith('\t')) {
        const last = line.charCodeAt(line.length - 1);
        line = `${line.slice(0, -1)}=${last.toString(16).toUpperCase().padStart(2, '0')}`;
      }
      flush(false);
      i += 1;
      continue;
    }
    let token: string;
    if ((b >= 0x21 && b <= 0x7e && b !== 0x3d) || b === 0x20 || b === 0x09) token = String.fromCharCode(b);
    else token = `=${b.toString(16).toUpperCase().padStart(2, '0')}`;
    if (line.length + token.length > 75) flush(true);
    line += token;
  }
  if (line.length) out.push(line);
  return out.join(CRLF);
}

/** base64 in 76-char lines. */
export function base64Lines(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
  return lines.join(CRLF);
}

const newBoundary = (): string => `----=_qk_${randomBytes(12).toString('hex')}`;

/** Hands out boundaries: the caller's first, then fresh ones; records all. */
class Boundaries {
  used: string[] = [];
  private queue: string[];
  constructor(preset: readonly string[] = []) {
    this.queue = [...preset];
  }
  next(): string {
    const b = this.queue.shift() ?? newBoundary();
    if (!/^[0-9A-Za-z'()+_,\-./:=?]{1,70}$/.test(b) || b.endsWith(' ')) {
      throw new MailError({
        code: 'invalid_input',
        reason: `multipart boundary ${JSON.stringify(b)} is not RFC 2046 bchars`,
      });
    }
    this.used.push(b);
    return b;
  }
}

/** Fold a header at 78 chars on whitespace where it can (RFC 5322 §2.2.3). */
function fold(name: string, value: string): string {
  const full = `${name}: ${value}`;
  if (full.length <= 78) return full;
  const words = value.split(' ');
  const lines: string[] = [];
  let cur = `${name}:`;
  for (const w of words) {
    if (cur.length + 1 + w.length > 78 && cur !== `${name}:`) {
      lines.push(cur);
      cur = ` ${w}`;
    } else {
      cur += ` ${w}`;
    }
  }
  lines.push(cur);
  return lines.join(CRLF);
}

function textPart(contentType: string, body: string): string {
  return (
    `Content-Type: ${contentType}; charset=UTF-8${CRLF}` +
    `Content-Transfer-Encoding: quoted-printable${CRLF}${CRLF}` +
    quotedPrintable(body)
  );
}

// RFC 2045 token: printable ASCII minus tspecials, space and controls.
const TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
const CONTENT_TYPE = new RegExp(`^${TOKEN}/${TOKEN}(?:\\s*;\\s*${TOKEN}=(?:${TOKEN}|"[^"\\\\\\r\\n\\u0000]*"))*$`);
// RFC 2231 attribute-char: what may stand unencoded in an extended parameter.
const RFC2231_SAFE = /^[A-Za-z0-9!#$&+\-.^_`|~]$/;

/**
 * Refuse an attachment whose metadata cannot be written into a header
 * without either breaking the header (CR/LF/NUL) or changing its meaning
 * (a `contentType` that is not `type/subtype`, a `contentId` that is not a
 * bare id). Called by `normaliseInput` before any row exists, and again by
 * `buildMime`, which is public.
 */
export function assertAttachmentSafe(a: Attachment): void {
  if (typeof a.filename !== 'string' || a.filename.length === 0 || a.filename.length > 255) {
    throw new MailError({ code: 'invalid_input', reason: 'attachment filename must be 1-255 characters' });
  }
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point
  if (/[\r\n\u0000]/.test(a.filename)) throw new MailError({ code: 'header_injection', header: 'Content-Disposition' });
  if (a.contentType !== undefined) {
    // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point
    if (/[\r\n\u0000]/.test(a.contentType)) throw new MailError({ code: 'header_injection', header: 'Content-Type' });
    if (!CONTENT_TYPE.test(a.contentType)) {
      throw new MailError({
        code: 'invalid_input',
        reason: `attachment contentType ${JSON.stringify(a.contentType)} is not a type/subtype media type`,
      });
    }
  }
  if (a.contentId !== undefined) {
    // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point
    if (/[\r\n\u0000]/.test(a.contentId)) throw new MailError({ code: 'header_injection', header: 'Content-ID' });
    if (!/^[!-;=?-~]{1,200}$/.test(a.contentId)) {
      throw new MailError({
        code: 'invalid_input',
        reason: `attachment contentId ${JSON.stringify(a.contentId)} must be printable ASCII without <, > or whitespace`,
      });
    }
  }
}

/**
 * A `cid:` part is only reachable from an HTML body. Building
 * `multipart/related` around a text part would carry bytes nothing can
 * reference, and dropping the part (what happened before) lost them without
 * a word — so a message with inline attachments and no `html` is refused.
 * Called by `normaliseInput` before any row exists, and by `buildMime`.
 */
export function assertInlineHasHtml(attachments: readonly Attachment[] | undefined, html: string | undefined): void {
  if (html) return;
  const first = attachments?.find((a) => a.contentId !== undefined);
  if (first) throw new MailError({ code: 'inline_needs_html', contentId: first.contentId ?? '' });
}

/** RFC 2231 `filename*=UTF-8''...` value: percent-encode every byte that is
 *  not an attribute-char (encodeURIComponent leaves `'()*` bare, which RFC
 *  2231 does not allow). */
function rfc2231Value(value: string): string {
  let out = '';
  for (const byte of Buffer.from(value, 'utf8')) {
    const ch = String.fromCharCode(byte);
    out += RFC2231_SAFE.test(ch) ? ch : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return `UTF-8''${out}`;
}

function attachmentPart(a: Attachment): string {
  assertAttachmentSafe(a);
  const bytes = typeof a.content === 'string' ? Buffer.from(a.content, 'base64') : a.content;
  const type = a.contentType ?? 'application/octet-stream';
  const ascii = !/[^\u0020-\u007e]/.test(a.filename);
  const quoted = `"${a.filename.replace(/(["\\])/g, '\\$1')}"`;
  // ASCII: a quoted-string in both places. Non-ASCII: RFC 2231 in
  // Content-Disposition, and no `name=` at all rather than raw bytes.
  const filename = ascii ? `filename=${quoted}` : `filename*=${rfc2231Value(a.filename)}`;
  const name = ascii ? `; name=${quoted}` : '';
  const disposition = a.contentId ? 'inline' : 'attachment';
  const cid = a.contentId ? `Content-ID: <${a.contentId}>${CRLF}` : '';
  return (
    `Content-Type: ${type}${name}${CRLF}` +
    `Content-Transfer-Encoding: base64${CRLF}` +
    `Content-Disposition: ${disposition}; ${filename}${CRLF}` +
    cid +
    CRLF +
    base64Lines(bytes)
  );
}

function multipart(bounds: Boundaries, subtype: string, parts: string[]): string {
  const b = bounds.next();
  const body = `${parts.map((p) => `--${b}${CRLF}${p}`).join(CRLF)}${CRLF}--${b}--`;
  return `Content-Type: multipart/${subtype}; boundary="${b}"${CRLF}${CRLF}${body}`;
}

/** Build the message. */
export function buildMime(input: MimeInput): Uint8Array {
  return buildMimeDetailed(input).raw;
}

/** Build the message and report the multipart boundaries used, in
 *  consumption order, so the same bytes can be rebuilt later (`input.boundaries`). */
export function buildMimeDetailed(input: MimeInput): { raw: Uint8Array; boundaries: string[] } {
  const bounds = new Boundaries(input.boundaries);
  if (!input.text && !input.html)
    throw new MailError({ code: 'invalid_input', reason: 'a message needs text or html (or both)' });
  if (input.to.length === 0)
    throw new MailError({ code: 'invalid_input', reason: 'a message needs at least one To recipient' });
  assertHeaderSafe('Subject', input.subject);
  for (const a of input.attachments ?? []) assertAttachmentSafe(a);
  assertInlineHasHtml(input.attachments, input.html);

  const headers: string[] = [];
  headers.push(fold('From', renderAddress(input.from)));
  headers.push(fold('To', input.to.map(renderAddress).join(', ')));
  if (input.cc?.length) headers.push(fold('Cc', input.cc.map(renderAddress).join(', ')));
  if (input.replyTo?.length) headers.push(fold('Reply-To', input.replyTo.map(renderAddress).join(', ')));
  headers.push(fold('Subject', headerText(input.subject)));
  headers.push(`Date: ${rfc5322Date(input.date)}`);
  headers.push(`Message-ID: ${input.messageId}`);
  headers.push('MIME-Version: 1.0');

  if (input.listUnsubscribe && (input.listUnsubscribe.url || input.listUnsubscribe.mailto)) {
    const parts: string[] = [];
    if (input.listUnsubscribe.url) parts.push(`<${input.listUnsubscribe.url}>`);
    if (input.listUnsubscribe.mailto) parts.push(`<mailto:${input.listUnsubscribe.mailto}>`);
    for (const p of parts) assertHeaderSafe('List-Unsubscribe', p);
    headers.push(fold('List-Unsubscribe', parts.join(', ')));
    if (input.listUnsubscribe.url) headers.push('List-Unsubscribe-Post: List-Unsubscribe=One-Click');
  }

  for (const [name, value] of Object.entries(input.headers ?? {})) {
    assertHeaderSafe(name, value);
    if (RESERVED.has(name.toLowerCase())) {
      throw new MailError({
        code: 'invalid_input',
        reason: `header ${name} is set by mail-kit and cannot be overridden`,
      });
    }
    headers.push(fold(name, headerText(value)));
  }

  // Body structure:
  //   text only              → text/plain
  //   html only              → text/html
  //   both                   → multipart/alternative
  //   + attachments          → multipart/mixed( <above>, attachments… )
  //   inline (cid) images    → multipart/related( html, inline… ) in place of html
  //                            (refused above when there is no html)
  let body: string;
  const inline = (input.attachments ?? []).filter((a) => a.contentId);
  const attached = (input.attachments ?? []).filter((a) => !a.contentId);

  const htmlPart = input.html
    ? inline.length
      ? multipart(bounds, 'related', [textPart('text/html', input.html), ...inline.map(attachmentPart)])
      : textPart('text/html', input.html)
    : null;
  const plainPart = input.text ? textPart('text/plain', input.text) : null;

  if (plainPart && htmlPart) body = multipart(bounds, 'alternative', [plainPart, htmlPart]);
  else if (plainPart) body = plainPart;
  else if (htmlPart) body = htmlPart;
  else throw new MailError({ code: 'invalid_input', reason: 'a message needs text or html (or both)' });

  if (attached.length) body = multipart(bounds, 'mixed', [body, ...attached.map(attachmentPart)]);

  return { raw: Buffer.from(headers.join(CRLF) + CRLF + body + CRLF, 'utf8'), boundaries: bounds.used };
}
