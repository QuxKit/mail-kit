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

import { hmacSha256, randomToken, safeEqual } from './crypto.ts';
import { MailError } from './errors.ts';
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
  /** Attempt every due delivery, up to `limit`. Safe to run concurrently —
   *  rows are claimed with `FOR UPDATE SKIP LOCKED`. */
  deliverPending(limit?: number, now?: Date): Promise<{ delivered: number; failed: number; retried: number }>;
  listDeliveries(tenantId: TenantId, opts?: { limit?: number; subscriptionId?: string }): Promise<WebhookDelivery[]>;
}

/** Retry schedule after the first attempt: 5s, 5m, 30m, 2h, 5h, 10h. */
export const RETRY_SCHEDULE_S = [5, 300, 1800, 7200, 18000, 36000];

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
  secret: string;
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
  secret?: string;
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
  'email.sent', 'email.delivered', 'email.delivery_delayed', 'email.bounced', 'email.complained',
  'email.failed', 'email.opened', 'email.clicked', 'domain.verified', 'domain.failed',
];

export function createWebhooks(opts: WebhooksOptions): WebhooksApi {
  const { db, fetch } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const maxAttempts = opts.maxAttempts ?? RETRY_SCHEDULE_S.length + 1;
  const timeoutMs = opts.timeoutMs ?? 10_000;

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
      const events = [...new Set(input.events)];
      for (const e of events) {
        if (!ALL_WEBHOOK_EVENTS.includes(e)) throw new MailError({ code: 'invalid_input', reason: `unknown webhook event ${e}` });
      }
      if (events.length === 0) throw new MailError({ code: 'invalid_input', reason: 'a webhook needs at least one event' });
      const secret = `whsec_${Buffer.from(randomToken(24), 'base64url').toString('base64')}`;
      const rows = await db.query<SubRow>(
        `INSERT INTO mail.webhook_subscriptions (tenant_id, url, secret, events)
         VALUES ($1, $2, $3, $4) RETURNING id, tenant_id, url, secret, events, enabled, created_at`,
        [tenantId, url.toString(), secret, events],
      );
      return { ...toSubscription(rows[0]!), secret };
    },

    async list(tenantId) {
      const rows = await db.query<SubRow>(
        `SELECT id, tenant_id, url, secret, events, enabled, created_at FROM mail.webhook_subscriptions
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

    async enqueue(tenantId, type, data, at) {
      const payload: WebhookPayload = { type, created_at: (at ?? clock()).toISOString(), data };
      const rows = await db.query<{ id: string }>(
        `INSERT INTO mail.webhook_deliveries (subscription_id, tenant_id, event_type, payload, next_attempt_at)
         SELECT id, tenant_id, $2, $3::jsonb, $4
           FROM mail.webhook_subscriptions
          WHERE tenant_id = $1 AND enabled AND $2 = ANY(events)
         RETURNING id`,
        [tenantId, type, JSON.stringify(payload), clock()],
      );
      return rows.length;
    },

    async deliverPending(limit = 50, now = clock()) {
      const out = { delivered: 0, failed: 0, retried: 0 };
      // Claim a batch of ids, then process each in its own transaction so a
      // slow endpoint holds one row lock, not the batch.
      const due = await db.query<{ id: string }>(
        `SELECT id FROM mail.webhook_deliveries
          WHERE status = 'pending' AND next_attempt_at <= $1
          ORDER BY next_attempt_at LIMIT $2`,
        [now, limit],
      );
      for (const { id } of due) {
        await db.transaction(async (tx) => {
          const rows = await tx.query<DeliveryRow>(
            `SELECT d.*, s.url, s.secret
               FROM mail.webhook_deliveries d JOIN mail.webhook_subscriptions s ON s.id = d.subscription_id
              WHERE d.id = $1 AND d.status = 'pending' FOR UPDATE OF d SKIP LOCKED`,
            [id],
          );
          const row = rows[0];
          if (!row) return;
          const body = JSON.stringify(row.payload);
          const attempt = row.attempts + 1;
          const result = await post(fetch, row.url!, row.secret!, row.id, body, now, timeoutMs);
          if (result.ok) {
            await tx.query(
              `UPDATE mail.webhook_deliveries
                  SET status = 'delivered', attempts = $2, last_status_code = $3, last_error = NULL,
                      next_attempt_at = NULL, delivered_at = $4
                WHERE id = $1`,
              [row.id, attempt, result.status, now],
            );
            out.delivered += 1;
            return;
          }
          if (attempt >= maxAttempts) {
            await tx.query(
              `UPDATE mail.webhook_deliveries
                  SET status = 'failed', attempts = $2, last_status_code = $3, last_error = $4, next_attempt_at = NULL
                WHERE id = $1`,
              [row.id, attempt, result.status, result.error],
            );
            out.failed += 1;
            opts.logger?.warn('webhook delivery failed permanently', { id: row.id, url: row.url, attempts: attempt });
            return;
          }
          const delay = RETRY_SCHEDULE_S[Math.min(attempt - 1, RETRY_SCHEDULE_S.length - 1)]!;
          await tx.query(
            `UPDATE mail.webhook_deliveries
                SET attempts = $2, last_status_code = $3, last_error = $4, next_attempt_at = $5
              WHERE id = $1`,
            [row.id, attempt, result.status, result.error, new Date(now.getTime() + delay * 1000)],
          );
          out.retried += 1;
        });
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
        [tenantId, o?.limit ?? 100, o?.subscriptionId ?? null],
      );
      return rows.map(toDelivery);
    },
  };
}

async function post(
  fetch: Fetch,
  url: string,
  secret: string,
  id: string,
  body: string,
  now: Date,
  timeoutMs: number,
): Promise<{ ok: boolean; status: number | null; error: string | null }> {
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
    });
    if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status, error: null };
    return { ok: false, status: res.status, error: `HTTP ${res.status}` };
  } catch (error) {
    return { ok: false, status: null, error: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timer);
  }
}
