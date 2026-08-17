// Sending: validate, authorise the From, drop suppressed recipients, store,
// deliver — inline or from a queue — and retry what the transport says is
// retryable.
//
// The row is written before the transport is called, always. A send is
// therefore never lost between "the API returned" and "the mail left", and a
// worker crash after the transport accepted but before the row was updated
// re-sends rather than drops (at-least-once; the lease below is what bounds
// the window). Idempotency keys exist so the caller's retry does not become a
// second message.

import { type ParsedAddress, parseAddress, parseAddressList } from './address.ts';
import { sha256Hex } from './crypto.ts';
import { dkimSign } from './dkim.ts';
import type { DomainsApi } from './domains.ts';
import { MailError } from './errors.ts';
import { type EventsApi, messageData } from './events.ts';
import { assertHeaderSafe, buildMime, newMessageId } from './mime.ts';
import type { SuppressionApi } from './suppression.ts';
import type {
  Attachment,
  Clock,
  DeliveryEvent,
  Logger,
  MailConfig,
  MailTransport,
  Message,
  MessageStatus,
  SendInput,
  SendingDomain,
  SendOptions,
  SqlExecutor,
  TenantId,
} from './types.ts';
import type { WebhooksApi } from './webhooks.ts';

export interface MessagesOptions {
  db: SqlExecutor;
  transport: MailTransport;
  domains: DomainsApi;
  suppression: SuppressionApi;
  events: EventsApi;
  webhooks: WebhooksApi;
  config: MailConfig;
  clock?: Clock;
  logger?: Logger;
}

export interface ListMessagesOptions {
  status?: MessageStatus;
  limit?: number;
  /** Page: rows created before this instant. */
  before?: Date;
}

export interface MessagesApi {
  send(tenantId: TenantId, input: SendInput, opts?: SendOptions): Promise<Message>;
  /** Independent sends; one failing does not stop the rest. */
  sendBatch(
    tenantId: TenantId,
    inputs: readonly SendInput[],
    opts?: SendOptions,
  ): Promise<Array<{ ok: true; message: Message } | { ok: false; error: MailError }>>;
  get(tenantId: TenantId, id: string): Promise<Message | null>;
  list(tenantId: TenantId, opts?: ListMessagesOptions): Promise<Message[]>;
  /** A queued or scheduled message will not be sent. */
  cancel(tenantId: TenantId, id: string): Promise<Message>;
  /** Move a scheduled message; `at` in the past means "now". */
  reschedule(tenantId: TenantId, id: string, at: Date): Promise<Message>;
  /** The stored, normalised input for a message (bodies, attachments) — what
   *  `render` builds from, exposed for a dashboard's detail view. */
  payload(tenantId: TenantId, id: string): Promise<StoredPayload | null>;
  /** Deliver everything due — queued, scheduled, or waiting on a retry. What a
   *  worker calls in a loop. Safe to run from several processes. */
  deliverPending(limit?: number, now?: Date): Promise<{ sent: number; failed: number; retried: number }>;
  /** Rebuild the exact bytes for a stored message (dashboard "view source"). */
  render(tenantId: TenantId, id: string): Promise<Uint8Array>;
}

/** Retry backoff after a retryable transport failure: 30s, 2m, 10m, 30m, 1h. */
export const SEND_RETRY_SCHEDULE_S = [30, 120, 600, 1800, 3600];

/** How long a claimed row is invisible to other workers before it is retried. */
const LEASE_S = 90;

interface StoredAddress {
  email: string;
  name: string | null;
}

/** The normalised send input, as stored in `payload`. */
export interface StoredPayload {
  from: StoredAddress;
  to: StoredAddress[];
  cc: StoredAddress[];
  bcc: StoredAddress[];
  replyTo: StoredAddress[];
  subject: string;
  text: string | null;
  html: string | null;
  headers: Record<string, string>;
  attachments: Array<{ filename: string; content: string; contentType: string | null; contentId: string | null }>;
  listUnsubscribe: { url?: string; mailto?: string } | null;
}

interface Row {
  id: string;
  tenant_id: string;
  domain_id: string | null;
  status: MessageStatus;
  from_address: string;
  to_addresses: string[];
  cc_addresses: string[];
  bcc_addresses: string[];
  subject: string;
  message_id: string;
  provider_message_id: string | null;
  payload: StoredPayload;
  content_hash: string;
  tags: Record<string, string>;
  idempotency_key: string | null;
  attempts: number;
  last_error: string | null;
  next_attempt_at: Date | null;
  suppressed_recipients: string[];
  scheduled_at: Date | null;
  created_at: Date;
  updated_at: Date;
  sent_at: Date | null;
}

const COLUMNS =
  'id, tenant_id, domain_id, status, from_address, to_addresses, cc_addresses, bcc_addresses, subject, message_id, ' +
  'provider_message_id, payload, content_hash, tags, idempotency_key, attempts, last_error, next_attempt_at, ' +
  'suppressed_recipients, scheduled_at, created_at, updated_at, sent_at';

const toMessage = (r: Row): Message => ({
  id: r.id,
  tenantId: r.tenant_id,
  status: r.status,
  from: r.from_address,
  to: r.to_addresses,
  cc: r.cc_addresses,
  bcc: r.bcc_addresses,
  subject: r.subject,
  messageId: r.message_id,
  providerMessageId: r.provider_message_id,
  tags: r.tags,
  idempotencyKey: r.idempotency_key,
  attempts: r.attempts,
  lastError: r.last_error,
  suppressedRecipients: r.suppressed_recipients,
  scheduledAt: r.scheduled_at,
  createdAt: r.created_at,
  sentAt: r.sent_at,
  updatedAt: r.updated_at,
});

const stored = (a: ParsedAddress): StoredAddress => ({ email: a.email, name: a.name });
const parsed = (a: StoredAddress): ParsedAddress => ({
  email: a.email,
  name: a.name,
  domain: a.email.slice(a.email.lastIndexOf('@') + 1),
});

const attachmentBase64 = (a: Attachment): string =>
  typeof a.content === 'string' ? a.content : Buffer.from(a.content).toString('base64');

/** Validate and normalise. Everything that can be rejected without the
 *  database is rejected here, so a bad request never leaves a row behind. */
export function normaliseInput(input: SendInput): {
  payload: StoredPayload;
  from: ParsedAddress;
  tags: Record<string, string>;
} {
  const from = parseAddress(input.from);
  const to = parseAddressList(input.to);
  const cc = parseAddressList(input.cc);
  const bcc = parseAddressList(input.bcc);
  const replyTo = parseAddressList(input.replyTo);
  if (to.length === 0)
    throw new MailError({ code: 'invalid_input', reason: 'a message needs at least one To recipient' });
  if (to.length + cc.length + bcc.length > 50)
    throw new MailError({ code: 'invalid_input', reason: 'at most 50 recipients per message' });
  if (typeof input.subject !== 'string') throw new MailError({ code: 'invalid_input', reason: 'subject is required' });
  assertHeaderSafe('Subject', input.subject);
  if (!input.text && !input.html)
    throw new MailError({ code: 'invalid_input', reason: 'a message needs text or html (or both)' });
  for (const [k, v] of Object.entries(input.headers ?? {})) assertHeaderSafe(k, v);
  const tags: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.tags ?? {})) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(k) || !/^[A-Za-z0-9_-]{0,256}$/.test(v)) {
      throw new MailError({
        code: 'invalid_input',
        reason: `tag ${JSON.stringify(k)} must be [A-Za-z0-9_-], name ≤64 and value ≤256 chars`,
      });
    }
    tags[k] = v;
  }
  if (input.idempotencyKey !== undefined && (input.idempotencyKey.length === 0 || input.idempotencyKey.length > 256)) {
    throw new MailError({ code: 'invalid_input', reason: 'idempotencyKey must be 1–256 chars' });
  }
  const payload: StoredPayload = {
    from: stored(from),
    to: to.map(stored),
    cc: cc.map(stored),
    bcc: bcc.map(stored),
    replyTo: replyTo.map(stored),
    subject: input.subject,
    text: input.text ?? null,
    html: input.html ?? null,
    headers: { ...(input.headers ?? {}) },
    attachments: (input.attachments ?? []).map((a) => ({
      filename: a.filename,
      content: attachmentBase64(a),
      contentType: a.contentType ?? null,
      contentId: a.contentId ?? null,
    })),
    listUnsubscribe: input.listUnsubscribe ?? null,
  };
  return { payload, from, tags };
}

export function createMessages(opts: MessagesOptions): MessagesApi {
  const { db, transport, domains, suppression, events, webhooks, config } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const requireVerified = config.requireVerifiedDomain ?? true;
  const maxAttempts = config.maxAttempts ?? SEND_RETRY_SCHEDULE_S.length;

  const authoriseFrom = async (tenantId: TenantId, from: ParsedAddress): Promise<SendingDomain | null> => {
    const domain = await domains.find(tenantId, from.domain);
    if (!requireVerified) return domain;
    if (!domain) throw new MailError({ code: 'domain_not_verified', domain: from.domain, status: 'missing' });
    if (domain.status !== 'verified')
      throw new MailError({ code: 'domain_not_verified', domain: from.domain, status: domain.status });
    return domain;
  };

  const buildRaw = async (row: Row, at: Date): Promise<{ raw: Uint8Array; domain: SendingDomain | null }> => {
    const p = row.payload;
    let raw = buildMime({
      from: parsed(p.from),
      to: p.to.map(parsed),
      cc: p.cc.map(parsed),
      replyTo: p.replyTo.map(parsed),
      subject: p.subject,
      text: p.text ?? undefined,
      html: p.html ?? undefined,
      headers: p.headers,
      attachments: p.attachments.map((a) => ({
        filename: a.filename,
        content: a.content,
        contentType: a.contentType ?? undefined,
        contentId: a.contentId ?? undefined,
      })),
      listUnsubscribe: p.listUnsubscribe ?? undefined,
      messageId: row.message_id,
      date: at,
    });
    let domain: SendingDomain | null = null;
    if (row.domain_id) domain = await domains.get(row.tenant_id, row.domain_id);
    if (domain) {
      const signer = await domains.signerFor(domain);
      if (signer) raw = dkimSign(raw, { ...signer, now: at });
    }
    return { raw, domain };
  };

  /** One delivery attempt for a row that has already been claimed. */
  const attempt = async (row: Row, now: Date): Promise<'sent' | 'retried' | 'failed'> => {
    const attemptNo = row.attempts + 1;
    try {
      const { raw, domain } = await buildRaw(row, now);
      const returnPath = domain?.returnPathHost ? `bounces@${domain.returnPathHost}` : row.from_address;
      const recipients = [...new Set([...row.to_addresses, ...row.cc_addresses, ...row.bcc_addresses])];
      const result = await transport.send({
        tenantId: row.tenant_id,
        id: row.id,
        messageId: row.message_id,
        from: row.from_address,
        returnPath,
        recipients,
        raw,
        tags: row.tags,
      });
      await db.query(
        `UPDATE mail.messages
            SET status = 'sent', provider_message_id = $2, attempts = $3, sent_at = $4, next_attempt_at = NULL, last_error = NULL
          WHERE id = $1`,
        [row.id, result.providerMessageId, attemptNo, now],
      );
      await events.record([
        { type: 'sent', messageId: row.id, providerMessageId: result.providerMessageId, at: now },
        ...(result.rejected ?? []).map(
          (r): DeliveryEvent => ({
            type: 'bounced',
            messageId: row.id,
            providerMessageId: result.providerMessageId,
            recipient: r.recipient,
            at: now,
            bounce: { kind: 'hard', subtype: 'RejectedAtSubmission', diagnostic: r.detail },
          }),
        ),
      ]);
      return 'sent';
    } catch (error) {
      const retryable = MailError.hasCode(error, 'transport') && error.failure.retryable;
      const detail = error instanceof Error ? error.message : String(error);
      if (retryable && attemptNo < maxAttempts) {
        const delay = SEND_RETRY_SCHEDULE_S[Math.min(attemptNo - 1, SEND_RETRY_SCHEDULE_S.length - 1)] ?? 0;
        await db.query(
          `UPDATE mail.messages SET status = 'queued', attempts = $2, last_error = $3, next_attempt_at = $4 WHERE id = $1`,
          [row.id, attemptNo, detail, new Date(now.getTime() + delay * 1000)],
        );
        opts.logger?.warn('send failed, will retry', { id: row.id, attempt: attemptNo, error: detail });
        return 'retried';
      }
      await db.query(
        `UPDATE mail.messages SET status = 'failed', attempts = $2, last_error = $3, next_attempt_at = NULL WHERE id = $1`,
        [row.id, attemptNo, detail],
      );
      opts.logger?.error('send failed', { id: row.id, attempt: attemptNo, error: detail });
      await webhooks.enqueue(row.tenant_id, 'email.failed', { ...messageData(row), error: detail }, now);
      return 'failed';
    }
  };

  const getRow = async (tenantId: TenantId, id: string): Promise<Row | null> => {
    const rows = await db.query<Row>(`SELECT ${COLUMNS} FROM mail.messages WHERE tenant_id = $1 AND id = $2`, [
      tenantId,
      id,
    ]);
    return rows[0] ?? null;
  };

  const api: MessagesApi = {
    async send(tenantId, input, o) {
      const now = clock();
      const { payload, from, tags } = normaliseInput(input);
      const domain = await authoriseFrom(tenantId, from);

      // Suppression: drop, don't fail. A campaign to fifty people with one
      // unsubscribed among them should still reach forty-nine.
      const all = [...payload.to, ...payload.cc, ...payload.bcc].map((a) => a.email);
      const suppressed = await suppression.check(tenantId, all);
      const keep = (a: StoredAddress) => !suppressed.has(a.email.toLowerCase());
      const to = payload.to.filter(keep);
      const cc = payload.cc.filter(keep);
      const bcc = payload.bcc.filter(keep);
      const dropped = all.filter((e) => suppressed.has(e.toLowerCase()));
      const stored: StoredPayload = { ...payload, to, cc, bcc };

      const contentHash = sha256Hex(
        JSON.stringify({ payload: stored, tags, scheduledAt: input.scheduledAt?.toISOString() ?? null }),
      );
      const nothingLeft = to.length + cc.length + bcc.length === 0;
      const scheduledAt = input.scheduledAt && input.scheduledAt.getTime() > now.getTime() ? input.scheduledAt : null;
      const status: MessageStatus = nothingLeft ? 'suppressed' : scheduledAt ? 'scheduled' : 'queued';
      const nextAttempt = nothingLeft ? null : (scheduledAt ?? now);

      const inserted = await db.query<Row>(
        `INSERT INTO mail.messages
           (tenant_id, domain_id, status, from_address, to_addresses, cc_addresses, bcc_addresses, subject, message_id,
            payload, content_hash, tags, idempotency_key, next_attempt_at, suppressed_recipients, scheduled_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12::jsonb, $13, $14, $15, $16)
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
         RETURNING ${COLUMNS}`,
        [
          tenantId,
          domain?.id ?? null,
          status,
          from.email,
          to.map((a) => a.email),
          cc.map((a) => a.email),
          bcc.map((a) => a.email),
          payload.subject,
          newMessageId(from.domain),
          JSON.stringify(stored),
          contentHash,
          JSON.stringify(tags),
          input.idempotencyKey ?? null,
          nextAttempt,
          dropped,
          input.scheduledAt ?? null,
        ],
      );

      let row = inserted[0];
      if (!row) {
        // The key exists. Same content → that message; different → conflict.
        const existing = await db.query<Row>(
          `SELECT ${COLUMNS} FROM mail.messages WHERE tenant_id = $1 AND idempotency_key = $2`,
          [tenantId, input.idempotencyKey],
        );
        const prior = existing[0];
        const key = input.idempotencyKey ?? '';
        if (!prior) throw new MailError({ code: 'not_found', what: 'message', id: key });
        if (prior.content_hash !== contentHash) throw new MailError({ code: 'idempotency_conflict', key });
        return toMessage(prior);
      }

      if (row.status === 'queued' && !o?.defer) {
        // Claim it the same way the worker would, so a worker that starts
        // between the insert and here does not send it twice.
        const claimed = await db.query<Row>(
          `UPDATE mail.messages SET next_attempt_at = $2 WHERE id = $1 AND status = 'queued' RETURNING ${COLUMNS}`,
          [row.id, new Date(now.getTime() + LEASE_S * 1000)],
        );
        if (claimed[0]) {
          await attempt(claimed[0], now);
          row = (await getRow(tenantId, row.id)) ?? row;
        }
      }
      return toMessage(row);
    },

    async sendBatch(tenantId, inputs, o) {
      const out: Array<{ ok: true; message: Message } | { ok: false; error: MailError }> = [];
      for (const input of inputs) {
        try {
          out.push({ ok: true, message: await api.send(tenantId, input, o) });
        } catch (error) {
          if (MailError.is(error)) out.push({ ok: false, error });
          else throw error;
        }
      }
      return out;
    },

    async get(tenantId, id) {
      const row = await getRow(tenantId, id);
      return row ? toMessage(row) : null;
    },

    async list(tenantId, o) {
      const rows = await db.query<Row>(
        `SELECT ${COLUMNS} FROM mail.messages
          WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2) AND ($3::timestamptz IS NULL OR created_at < $3)
          ORDER BY created_at DESC LIMIT $4`,
        [tenantId, o?.status ?? null, o?.before ?? null, o?.limit ?? 50],
      );
      return rows.map(toMessage);
    },

    async cancel(tenantId, id) {
      const rows = await db.query<Row>(
        `UPDATE mail.messages SET status = 'canceled', next_attempt_at = NULL
          WHERE tenant_id = $1 AND id = $2 AND status IN ('queued', 'scheduled') RETURNING ${COLUMNS}`,
        [tenantId, id],
      );
      if (rows[0]) return toMessage(rows[0]);
      const current = await getRow(tenantId, id);
      if (!current) throw new MailError({ code: 'not_found', what: 'message', id });
      throw new MailError({ code: 'invalid_state', id, status: current.status, operation: 'cancel' });
    },

    async reschedule(tenantId, id, at) {
      const now = clock();
      const future = at.getTime() > now.getTime();
      const rows = await db.query<Row>(
        `UPDATE mail.messages
            SET status = CASE WHEN $3::boolean THEN 'scheduled' ELSE 'queued' END, scheduled_at = $4, next_attempt_at = $4
          WHERE tenant_id = $1 AND id = $2 AND status = 'scheduled' RETURNING ${COLUMNS}`,
        [tenantId, id, future, future ? at : now],
      );
      if (rows[0]) return toMessage(rows[0]);
      const current = await getRow(tenantId, id);
      if (!current) throw new MailError({ code: 'not_found', what: 'message', id });
      throw new MailError({ code: 'invalid_state', id, status: current.status, operation: 'reschedule' });
    },

    async payload(tenantId, id) {
      const row = await getRow(tenantId, id);
      return row?.payload ?? null;
    },

    async deliverPending(limit = 50, now = clock()) {
      const out = { sent: 0, failed: 0, retried: 0 };
      // Claim: bump next_attempt_at by the lease so no other worker sees the
      // row, then send outside any transaction. A crash mid-send leaves the
      // row to be retried after the lease — at-least-once, never lost.
      const claimed = await db.query<Row>(
        `UPDATE mail.messages SET status = 'queued', next_attempt_at = $2
          WHERE id IN (
            SELECT id FROM mail.messages
             WHERE status IN ('queued', 'scheduled') AND next_attempt_at <= $1
             ORDER BY next_attempt_at LIMIT $3 FOR UPDATE SKIP LOCKED)
          RETURNING ${COLUMNS}`,
        [now, new Date(now.getTime() + LEASE_S * 1000), limit],
      );
      for (const row of claimed) {
        const r = await attempt(row, now);
        out[r] += 1;
      }
      return out;
    },

    async render(tenantId, id) {
      const row = await getRow(tenantId, id);
      if (!row) throw new MailError({ code: 'not_found', what: 'message', id });
      return (await buildRaw(row, row.sent_at ?? row.created_at)).raw;
    },
  };
  return api;
}
