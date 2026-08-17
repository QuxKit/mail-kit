// Delivery events: what the provider says happened, made uniform.
//
// A transport parses its provider's notification into `DeliveryEvent`s;
// `record` does everything that follows — the event row, the message's status,
// the suppression entry a hard bounce or complaint earns, and the webhook
// deliveries the tenant asked for. It is one function on purpose: the host
// wires the provider's callback to it and is done, and no host ever forgets
// to suppress a complainer.

import { createSuppression, normaliseForSuppression, type SuppressionApi } from './suppression.ts';
import type {
  Clock,
  DeliveryEvent,
  DeliveryEventType,
  Logger,
  MessageStatus,
  RecordedEvent,
  SqlExecutor,
  WebhookEventType,
} from './types.ts';
import { enqueueWebhookDeliveries, type WebhooksApi } from './webhooks.ts';

export interface EventsOptions {
  db: SqlExecutor;
  /** Kept for compatibility. `record` writes suppressions and webhook rows
   *  through its own transaction, not through this instance's executor. */
  suppression: SuppressionApi;
  /** Kept for compatibility; see `suppression`. */
  webhooks: WebhooksApi;
  clock?: Clock;
  logger?: Logger;
}

export interface EventsApi {
  /**
   * Record events; returns what was stored, in order. Unknown messages are
   * kept as orphan rows (no tenant, no webhook) rather than dropped. A replay
   * — same provider id, type, recipient and instant as a stored event — is
   * returned with `deduplicated: true` and does nothing else: no status
   * change, no suppression, no webhook.
   */
  record(events: readonly DeliveryEvent[]): Promise<RecordedEvent[]>;
  list(tenantId: string, messageId: string): Promise<RecordedEvent[]>;
}

/** Message row fields the event path needs. */
interface MessageRow {
  id: string;
  tenant_id: string;
  status: MessageStatus;
  from_address: string;
  to_addresses: string[];
  subject: string;
  tags: Record<string, string>;
  provider_message_id: string | null;
  created_at: Date;
}

interface EventRow {
  id: string;
  message_id: string | null;
  tenant_id: string | null;
  type: DeliveryEventType;
  recipient: string | null;
  occurred_at: Date;
  detail: Record<string, unknown>;
}

const toEvent = (r: EventRow): RecordedEvent => ({
  id: r.id,
  messageId: r.message_id,
  tenantId: r.tenant_id,
  type: r.type,
  recipient: r.recipient,
  at: r.occurred_at,
  detail: r.detail,
});

const WEBHOOK_TYPE: Record<DeliveryEventType, WebhookEventType> = {
  sent: 'email.sent',
  delivered: 'email.delivered',
  delayed: 'email.delivery_delayed',
  bounced: 'email.bounced',
  complained: 'email.complained',
  rejected: 'email.failed',
  opened: 'email.opened',
  clicked: 'email.clicked',
};

/** Terminal states an event may not walk back from. */
const TERMINAL: ReadonlySet<MessageStatus> = new Set(['bounced', 'complained', 'failed', 'canceled']);

/** The status a message should carry after this event, or null for no change. */
export function nextStatus(current: MessageStatus, event: DeliveryEvent): MessageStatus | null {
  switch (event.type) {
    case 'sent':
      return current === 'queued' || current === 'scheduled' ? 'sent' : null;
    case 'delivered':
      return TERMINAL.has(current) ? null : 'delivered';
    case 'delayed':
      return TERMINAL.has(current) || current === 'delivered' ? null : 'delayed';
    case 'bounced':
      if (event.bounce?.kind === 'soft') return TERMINAL.has(current) || current === 'delivered' ? null : 'delayed';
      return current === 'complained' ? null : 'bounced';
    case 'complained':
      return 'complained';
    case 'rejected':
      return TERMINAL.has(current) ? null : 'failed';
    case 'opened':
    case 'clicked':
      return null;
  }
}

/** The webhook `data` for a message, Resend-shaped. */
export function messageData(m: MessageRow, event?: DeliveryEvent): Record<string, unknown> {
  const data: Record<string, unknown> = {
    email_id: m.id,
    tenant_id: m.tenant_id,
    from: m.from_address,
    to: m.to_addresses,
    subject: m.subject,
    tags: m.tags,
    provider_message_id: m.provider_message_id,
    created_at: m.created_at.toISOString(),
  };
  if (event?.recipient) data.recipient = event.recipient;
  if (event?.bounce) data.bounce = event.bounce;
  if (event?.url) data.click = { url: event.url, user_agent: event.userAgent ?? null };
  return data;
}

export function createEvents(opts: EventsOptions): EventsApi {
  const { db } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());

  const findMessage = async (tx: SqlExecutor, e: DeliveryEvent): Promise<MessageRow | null> => {
    const cols = 'id, tenant_id, status, from_address, to_addresses, subject, tags, provider_message_id, created_at';
    if (e.messageId) {
      const rows = await tx.query<MessageRow>(`SELECT ${cols} FROM mail.messages WHERE id = $1 FOR UPDATE`, [
        e.messageId,
      ]);
      if (rows[0]) return rows[0];
    }
    if (e.providerMessageId) {
      const rows = await tx.query<MessageRow>(
        `SELECT ${cols} FROM mail.messages WHERE provider_message_id = $1 ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
        [e.providerMessageId],
      );
      if (rows[0]) return rows[0];
    }
    return null;
  };

  return {
    async record(events) {
      const out: RecordedEvent[] = [];
      for (const e of events) {
        const stored = await db.transaction(async (tx) => {
          const message = await findMessage(tx, e);
          const detail: Record<string, unknown> = {};
          if (e.bounce) detail.bounce = e.bounce;
          if (e.url) detail.url = e.url;
          if (e.userAgent) detail.userAgent = e.userAgent;
          if (e.raw !== undefined) detail.raw = e.raw;

          const recipient = e.recipient ? normaliseForSuppression(e.recipient) : null;
          const providerMessageId = e.providerMessageId ?? message?.provider_message_id ?? null;
          const rows = await tx.query<EventRow>(
            `INSERT INTO mail.events (message_id, tenant_id, type, recipient, provider_message_id, occurred_at, detail)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
             ON CONFLICT (provider_message_id, COALESCE(message_id::text, ''), type, COALESCE(recipient, ''), occurred_at)
               WHERE provider_message_id IS NOT NULL DO NOTHING
             RETURNING id, message_id, tenant_id, type, recipient, occurred_at, detail`,
            [
              message?.id ?? null,
              message?.tenant_id ?? null,
              e.type,
              recipient,
              providerMessageId,
              e.at,
              JSON.stringify(detail),
            ],
          );
          let row = rows[0];
          if (!row) {
            // A replay: the provider redelivered a notification we already
            // hold. Nothing follows — the status, the suppression and the
            // webhooks all happened the first time.
            const existing = await tx.query<EventRow>(
              `SELECT id, message_id, tenant_id, type, recipient, occurred_at, detail FROM mail.events
                WHERE provider_message_id = $1 AND COALESCE(message_id::text, '') = $2 AND type = $3
                  AND COALESCE(recipient, '') = $4 AND occurred_at = $5`,
              [providerMessageId, message?.id ?? '', e.type, recipient ?? '', e.at],
            );
            row = existing[0];
            if (!row) throw new Error('mail-kit: event insert conflicted but no row was found');
            return { ...toEvent(row), deduplicated: true };
          }
          if (!message) {
            opts.logger?.warn('delivery event for unknown message', {
              type: e.type,
              providerMessageId: e.providerMessageId,
            });
            return toEvent(row);
          }

          const status = nextStatus(message.status, e);
          if (status) await tx.query('UPDATE mail.messages SET status = $2 WHERE id = $1', [message.id, status]);

          // Suppression is the point of the whole event path. Hard bounce → the
          // tenant's list; complaint → the global list (mailbox providers do
          // not forgive per-tenant). Both on `tx`: if the webhook insert below
          // fails, the suppression does not outlive the event it came with.
          const suppression = createSuppression({ db: tx, clock });
          if (e.recipient && e.type === 'bounced' && e.bounce?.kind !== 'soft') {
            await suppression.add(message.tenant_id, {
              address: e.recipient,
              reason: 'bounce',
              detail: e.bounce?.diagnostic ?? e.bounce?.subtype,
            });
          } else if (e.recipient && e.type === 'complained') {
            await suppression.add(null, {
              address: e.recipient,
              reason: 'complaint',
              detail: `via ${message.tenant_id}`,
            });
          }

          await enqueueWebhookDeliveries(
            tx,
            message.tenant_id,
            WEBHOOK_TYPE[e.type],
            messageData(message, e),
            e.at,
            clock(),
          );
          return toEvent(row);
        });
        out.push(stored);
      }
      return out;
    },

    async list(tenantId, messageId) {
      const rows = await db.query<EventRow>(
        `SELECT id, message_id, tenant_id, type, recipient, occurred_at, detail FROM mail.events
          WHERE tenant_id = $1 AND message_id = $2 ORDER BY occurred_at, created_at`,
        [tenantId, messageId],
      );
      return rows.map(toEvent);
    },
  };
}
