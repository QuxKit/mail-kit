// Outbound webhooks: subscriptions, a delivery queue, and signing.
//
// Signing follows the Standard Webhooks spec (`webhook-id`,
// `webhook-timestamp`, `webhook-signature: v1,<base64 hmac>` over
// `${id}.${timestamp}.${body}`), which is what Resend, Svix-based products and
// most consumers' libraries already verify. `verifyWebhookSignature` is
// exported so a consumer of your product needs no library at all.
//
// Delivery is a table, not a process: `enqueue` writes rows, `deliverPending`
// is what a worker calls in a loop. That is what makes it survive a restart
// and what makes it testable without a network.

import { hmacSha256, keyFromHex, randomToken, safeEqual, seal, unseal } from './crypto.ts';
import { MailError } from './errors.ts';
import { clampLimit, MAX_BATCH, MAX_LIST_LIMIT } from './limits.ts';
import { assertWebhookUrlAllowed, type HostResolver } from './ssrf.ts';
import type {
  Clock,
  CreatedWebhook,
  Fetch,
  Logger,
  SqlExecutor,
  TenantId,
  WebhookDelivery,
  WebhookEventType,
  WebhookSubscription,
} from './types.ts';

export interface WebhooksOptions {
  db: SqlExecutor;
  fetch: Fetch;
  clock?: Clock;
  logger?: Logger;
  maxAttempts?: number;
  /** Per-request timeout. Default 10s. */
  timeoutMs?: number;
  /**
   * Resolves a webhook host to its addresses so loopback/private/link-local
   * targets can be refused (`webhook_url_forbidden`) at `create` and again at
   * delivery. Default: node's `dns.lookup`. Tests hand in a map.
   */
  resolve?: HostResolver;
  /** Permit `http:` webhook URLs (development only). Default false. */
  allowInsecureHttp?: boolean;
  /**
   * 32 bytes as 64 hex chars. When set, subscription secrets are sealed
   * (AES-256-GCM) before they reach the database and unsealed to sign each
   * delivery; `createMail` passes `config.dkimKey`, the same key that seals
   * DKIM private keys. Without it, secrets are stored as written. Rows
   * written either way are read either way, so the key can be introduced
   * on a live database; new rows are sealed from then on.
   */
  sealKey?: string;
}

export interface CreateWebhookInput {
  url: string;
  events: readonly WebhookEventType[];
}

export interface WebhookPayload {
  type: WebhookEventType;
  created_at: string;
  data: Record<string, unknown>;
}

export interface WebhooksApi {
  create(tenantId: TenantId, input: CreateWebhookInput): Promise<CreatedWebhook>;
  list(tenantId: TenantId): Promise<WebhookSubscription[]>;
  setEnabled(tenantId: TenantId, id: string, enabled: boolean): Promise<void>;
  remove(tenantId: TenantId, id: string): Promise<boolean>;
  /** Queue one delivery per enabled subscription of `tenantId` that wants
   *  `type`. Returns how many were queued. */
  enqueue(tenantId: TenantId, type: WebhookEventType, data: Record<string, unknown>, at?: Date): Promise<number>;
  /** Attempt every due delivery, up to `limit` (default 50, capped at
   *  `MAX_BATCH`). Safe to run concurrently —
   *  rows are claimed (`FOR UPDATE SKIP LOCKED`) and leased in one committed
   *  statement, then posted with no lock held. */
  deliverPending(limit?: number, now?: Date): Promise<{ delivered: number; failed: number; retried: number }>;
  /** Newest first; `limit` defaults to 100, capped at `MAX_LIST_LIMIT`. */
  listDeliveries(tenantId: TenantId, opts?: { limit?: number; subscriptionId?: string }): Promise<WebhookDelivery[]>;
}

/** Retry schedule after the first attempt: 5s, 5m, 30m, 2h, 5h, 10h. */
export const RETRY_SCHEDULE_S = [5, 300, 1800, 7200, 18000, 36000];

/** How long a claimed delivery is invisible to other workers before it is
 *  retried; covers the request timeout with room to record the outcome. */
const LEASE_S = 90;

/** The header set the receiver checks. */
export function signWebhook(secret: string, id: string, timestamp: Date, body: string): Record<string, string> {
  const ts = Math.floor(timestamp.getTime() / 1000);
  const sig = hmacSha256(secretBytes(secret), `${id}.${ts}.${body}`).toString('base64');
  return {
    'webhook-id': id,
    'webhook-timestamp': String(ts),
    'webhook-signature': `v1,${sig}`,
  };
}

/** `whsec_` + base64 — Standard Webhooks; the raw key is the decoded bytes. */
function secretBytes(secret: string): Buffer {
  const b64 = secret.startsWith('whsec_') ? secret.slice(6) : secret;
  return Buffer.from(b64, 'base64');
}

export interface VerifyOptions {
  /** How far a timestamp may be from `now`. Default 5 minutes. */
  toleranceSeconds?: number;
  now?: Date;
}

/**
 * For the receiving side. Throws `MailError` (`signature_invalid`) with the
 * reason on failure; returns the parsed body on success.
 */
export function verifyWebhookSignature(
  secret: string,
  headers: Record<string, string | undefined>,
  body: string,
  opts: VerifyOptions = {},
): unknown {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) if (v !== undefined) lower[k.toLowerCase()] = v;
  const id = lower['webhook-id'];
  const ts = lower['webhook-timestamp'];
  const sigs = lower['webhook-signature'];
  if (!id || !ts || !sigs) throw new MailError({ code: 'signature_invalid', reason: 'missing webhook headers' });
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) throw new MailError({ code: 'signature_invalid', reason: 'bad timestamp' });
  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (Math.abs(now - tsNum) > (opts.toleranceSeconds ?? 300)) {
    throw new MailError({ code: 'signature_invalid', reason: 'timestamp outside tolerance' });
  }
  const expected = hmacSha256(secretBytes(secret), `${id}.${ts}.${body}`);
  const ok = sigs
    .split(' ')
    .map((s) => s.trim())
    .filter((s) => s.startsWith('v1,'))
    .some((s) => safeEqual(Buffer.from(s.slice(3), 'base64'), expected));
  if (!ok) throw new MailError({ code: 'signature_invalid', reason: 'no matching signature' });
  return JSON.parse(body);
}

interface SubRow {
  id: string;
  tenant_id: string;
  url: string;
  events: WebhookEventType[];
  enabled: boolean;
  created_at: Date;
}

interface DeliveryRow {
  id: string;
  subscription_id: string;
  tenant_id: string;
  event_type: WebhookEventType;
  payload: WebhookPayload;
  status: 'pending' | 'delivered' | 'failed';
  attempts: number;
  last_status_code: number | null;
  last_error: string | null;
  next_attempt_at: Date | null;
  created_at: Date;
  delivered_at: Date | null;
  url?: string;
  secret?: string | null;
  secret_sealed?: string | null;
}

const toSubscription = (r: SubRow): WebhookSubscription => ({
  id: r.id,
  tenantId: r.tenant_id,
  url: r.url,
  events: r.events,
  enabled: r.enabled,
  createdAt: r.created_at,
});

const toDelivery = (r: DeliveryRow): WebhookDelivery => ({
  id: r.id,
  subscriptionId: r.subscription_id,
  tenantId: r.tenant_id,
  eventType: r.event_type,
  status: r.status,
  attempts: r.attempts,
  lastStatusCode: r.last_status_code,
  lastError: r.last_error,
  nextAttemptAt: r.next_attempt_at,
  createdAt: r.created_at,
  deliveredAt: r.delivered_at,
});

export const ALL_WEBHOOK_EVENTS: readonly WebhookEventType[] = [
  'email.sent',
  'email.delivered',
  'email.delivery_delayed',
  'email.bounced',
  'email.complained',
  'email.failed',
  'email.opened',
  'email.clicked',
  'domain.verified',
  'domain.failed',
];

/**
 * Queue one delivery per enabled subscription of `tenantId` that wants
 * `type`, on `db` — which may be a transaction, and is when `events.record`
 * calls it, so an event's row, status change, suppression and webhook rows
 * commit or roll back together. Returns how many were queued.
 */
export async function enqueueWebhookDeliveries(
  db: SqlExecutor,
  tenantId: TenantId,
  type: WebhookEventType,
  data: Record<string, unknown>,
  at: Date,
  now: Date,
): Promise<number> {
  const payload: WebhookPayload = { type, created_at: at.toISOString(), data };
  const rows = await db.query<{ id: string }>(
    `INSERT INTO mail.webhook_deliveries (subscription_id, tenant_id, event_type, payload, next_attempt_at)
     SELECT id, tenant_id, $2, $3::jsonb, $4
       FROM mail.webhook_subscriptions
      WHERE tenant_id = $1 AND enabled AND $2 = ANY(events)
     RETURNING id`,
    [tenantId, type, JSON.stringify(payload), now],
  );
  return rows.length;
}

export function createWebhooks(opts: WebhooksOptions): WebhooksApi {
  const { db, fetch } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const maxAttempts = opts.maxAttempts ?? RETRY_SCHEDULE_S.length + 1;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const resolve: HostResolver = opts.resolve ?? lazyNodeLookup();
  const sealKey = opts.sealKey ? keyFromHex(opts.sealKey, 'sealKey') : null;
  /** The signing secret for a delivery row, whichever way it was stored. */
  const secretOf = (row: DeliveryRow): string => {
    if (row.secret_sealed) {
      if (!sealKey) throw new Error('mail-kit: webhook secret is sealed but no sealKey (config.dkimKey) is configured');
      return unseal(sealKey, row.secret_sealed);
    }
    if (row.secret) return row.secret;
    throw new Error('mail-kit: webhook subscription has no secret');
  };
  const guard = { resolve, allowInsecureHttp: opts.allowInsecureHttp ?? false };

  return {
    async create(tenantId, input) {
      let url: URL;
      try {
        url = new URL(input.url);
      } catch {
        throw new MailError({ code: 'invalid_input', reason: 'webhook url is not a URL' });
      }
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        throw new MailError({ code: 'invalid_input', reason: 'webhook url must be http(s)' });
      }
      await assertWebhookUrlAllowed(url, guard);
      const events = [...new Set(input.events)];
      for (const e of events) {
        if (!ALL_WEBHOOK_EVENTS.includes(e))
          throw new MailError({ code: 'invalid_input', reason: `unknown webhook event ${e}` });
      }
      if (events.length === 0)
        throw new MailError({ code: 'invalid_input', reason: 'a webhook needs at least one event' });
      const secret = `whsec_${Buffer.from(randomToken(24), 'base64url').toString('base64')}`;
      const rows = await db.query<SubRow>(
        `INSERT INTO mail.webhook_subscriptions (tenant_id, url, secret, secret_sealed, events)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, tenant_id, url, events, enabled, created_at`,
        [tenantId, url.toString(), sealKey ? null : secret, sealKey ? seal(sealKey, secret) : null, events],
      );
      // biome-ignore lint/style/noNonNullAssertion: INSERT … RETURNING always yields one row
      return { ...toSubscription(rows[0]!), secret };
    },

    async list(tenantId) {
      const rows = await db.query<SubRow>(
        `SELECT id, tenant_id, url, events, enabled, created_at FROM mail.webhook_subscriptions
          WHERE tenant_id = $1 ORDER BY created_at DESC`,
        [tenantId],
      );
      return rows.map(toSubscription);
    },

    async setEnabled(tenantId, id, enabled) {
      const rows = await db.query<{ id: string }>(
        'UPDATE mail.webhook_subscriptions SET enabled = $3 WHERE tenant_id = $1 AND id = $2 RETURNING id',
        [tenantId, id, enabled],
      );
      if (!rows.length) throw new MailError({ code: 'not_found', what: 'webhook', id });
    },

    async remove(tenantId, id) {
      const rows = await db.query<{ id: string }>(
        'DELETE FROM mail.webhook_subscriptions WHERE tenant_id = $1 AND id = $2 RETURNING id',
        [tenantId, id],
      );
      return rows.length > 0;
    },

    enqueue: (tenantId, type, data, at) => enqueueWebhookDeliveries(db, tenantId, type, data, at ?? clock(), clock()),

    async deliverPending(limit = 50, now = clock()) {
      const out = { delivered: 0, failed: 0, retried: 0 };
      // Claim, then commit, then post. The claim leases each due row (its
      // next_attempt_at moves past the lease) in one autocommitted statement,
      // so no row lock is held while an endpoint takes its time to answer;
      // the outcome is recorded afterwards. A worker that dies mid-post
      // leaves the row to be retried when the lease lapses — at-least-once,
      // and the receiver has webhook-id to de-duplicate on.
      const claimed = await db.query<DeliveryRow>(
        `UPDATE mail.webhook_deliveries d
            SET next_attempt_at = $2
           FROM mail.webhook_subscriptions s
          WHERE d.id IN (
                  SELECT id FROM mail.webhook_deliveries
                   WHERE status = 'pending' AND next_attempt_at <= $1
                   ORDER BY next_attempt_at LIMIT $3
                   FOR UPDATE SKIP LOCKED)
            AND s.id = d.subscription_id
          RETURNING d.id, d.subscription_id, d.tenant_id, d.event_type, d.payload, d.status, d.attempts,
                    d.last_status_code, d.last_error, d.next_attempt_at, d.created_at, d.delivered_at,
                    s.url, s.secret, s.secret_sealed`,
        [now, new Date(now.getTime() + LEASE_S * 1000), clampLimit(limit, 50, MAX_BATCH)],
      );
      for (const row of claimed) {
        const body = JSON.stringify(row.payload);
        const attempt = row.attempts + 1;
        let secret: string;
        try {
          secret = secretOf(row);
        } catch (error) {
          // A configuration problem, not the endpoint's: leave the row to
          // retry once the key is configured, and say why.
          const detail = error instanceof Error ? error.message : String(error);
          opts.logger?.error('webhook secret unavailable', { id: row.id, error: detail });
          await db.query(`UPDATE mail.webhook_deliveries SET last_error = $2, next_attempt_at = $3 WHERE id = $1`, [
            row.id,
            detail,
            new Date(now.getTime() + (RETRY_SCHEDULE_S[0] ?? 5) * 1000),
          ]);
          out.retried += 1;
          continue;
        }
        const result = await guardedPost(fetch, guard, row.url ?? '', secret, row.id, body, now, timeoutMs);
        if (result.ok) {
          await db.query(
            `UPDATE mail.webhook_deliveries
                SET status = 'delivered', attempts = $2, last_status_code = $3, last_error = NULL,
                    next_attempt_at = NULL, delivered_at = $4
              WHERE id = $1`,
            [row.id, attempt, result.status, now],
          );
          out.delivered += 1;
          continue;
        }
        if (result.permanent || attempt >= maxAttempts) {
          await db.query(
            `UPDATE mail.webhook_deliveries
                SET status = 'failed', attempts = $2, last_status_code = $3, last_error = $4, next_attempt_at = NULL
              WHERE id = $1`,
            [row.id, attempt, result.status, result.error],
          );
          out.failed += 1;
          opts.logger?.warn('webhook delivery failed permanently', { id: row.id, url: row.url, attempts: attempt });
          continue;
        }
        const delay = RETRY_SCHEDULE_S[Math.min(attempt - 1, RETRY_SCHEDULE_S.length - 1)] ?? 0;
        await db.query(
          `UPDATE mail.webhook_deliveries
              SET attempts = $2, last_status_code = $3, last_error = $4, next_attempt_at = $5
            WHERE id = $1`,
          [row.id, attempt, result.status, result.error, new Date(now.getTime() + delay * 1000)],
        );
        out.retried += 1;
      }
      return out;
    },

    async listDeliveries(tenantId, o) {
      const rows = await db.query<DeliveryRow>(
        `SELECT id, subscription_id, tenant_id, event_type, payload, status, attempts, last_status_code,
                last_error, next_attempt_at, created_at, delivered_at
           FROM mail.webhook_deliveries
          WHERE tenant_id = $1 AND ($3::uuid IS NULL OR subscription_id = $3)
          ORDER BY created_at DESC LIMIT $2`,
        [tenantId, clampLimit(o?.limit, 100, MAX_LIST_LIMIT), o?.subscriptionId ?? null],
      );
      return rows.map(toDelivery);
    },
  };
}

interface PostResult {
  ok: boolean;
  status: number | null;
  error: string | null;
  /** True when retrying cannot help (the URL is forbidden). */
  permanent?: boolean;
}

/** Re-check the URL against the guard at delivery time, then post. A URL
 *  that has become forbidden (DNS now answers a private address) is a
 *  permanent failure; a resolver error is a retryable one. */
async function guardedPost(
  fetch: Fetch,
  guard: { resolve: HostResolver; allowInsecureHttp: boolean },
  url: string,
  secret: string,
  id: string,
  body: string,
  now: Date,
  timeoutMs: number,
): Promise<PostResult> {
  try {
    await assertWebhookUrlAllowed(new URL(url), guard);
  } catch (error) {
    if (MailError.hasCode(error, 'webhook_url_forbidden')) {
      return { ok: false, status: null, error: `webhook_url_forbidden: ${error.failure.reason}`, permanent: true };
    }
    return { ok: false, status: null, error: error instanceof Error ? error.message : String(error) };
  }
  return post(fetch, url, secret, id, body, now, timeoutMs);
}

async function post(
  fetch: Fetch,
  url: string,
  secret: string,
  id: string,
  body: string,
  now: Date,
  timeoutMs: number,
): Promise<PostResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': 'quxkit-mail-kit/0.1',
        ...signWebhook(secret, id, now, body),
      },
      body,
      signal: controller.signal,
      redirect: 'error',
    });
    if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status, error: null };
    return { ok: false, status: res.status, error: `HTTP ${res.status}` };
  } catch (error) {
    return { ok: false, status: null, error: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timer);
  }
}

/** Import node:dns only when the default resolver is actually used. */
function lazyNodeLookup(): HostResolver {
  let real: HostResolver | null = null;
  return async (hostname) => {
    if (!real) real = (await import('./dns.ts')).nodeLookup;
    return real(hostname);
  };
}
