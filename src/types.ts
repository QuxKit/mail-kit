// The shared vocabulary: the executor, the seams, and the shapes that cross
// between them.
//
// The executor, clock and logger are the same interfaces identity-kit,
// tenant-kit and billing-kit use, on purpose — the `tenantId` a domain or a
// message is keyed on here is tenant-kit's opaque `TenantId`, and a send is the
// kind of thing billing-kit meters. There is no runtime code in this file, and
// nothing reads `process.env`: a library that reads the environment cannot be
// instantiated twice in one process, which a test suite and a multi-region
// worker both need.

// --- database ---------------------------------------------------------------

/**
 * The whole database dependency. A bare `pg.Pool` satisfies it; Prisma is not
 * required at runtime. Values arrive as the driver produces them — node-postgres
 * gives TIMESTAMPTZ as a Date, JSONB as a parsed value and TEXT as a string,
 * which is what the queries here expect.
 */
export interface SqlExecutor {
  query<T = Record<string, unknown>>(text: string, params?: readonly unknown[]): Promise<T[]>;
  /**
   * Run `fn` in one transaction, committing on resolve and rolling back on
   * throw. The executor handed to `fn` must be pinned to a single connection;
   * one that hands back the pool runs the body on different connections and the
   * rollback covers nothing.
   */
  transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T>;
}

/** Injected so tests, schedules and retry backoff do not depend on wall-clock drift. */
export type Clock = () => Date;

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

/** The subset of `fetch` the webhook and SES code needs. Injected — never the
 *  global — so tests, proxies and per-region clients are all just arguments. */
export type Fetch = (url: string, init: FetchInit) => Promise<FetchResponse>;

export interface FetchInit {
  method: string;
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  /** Webhook posts are sent with `'error'`: a redirect is a failure, never
   *  followed — a 3xx to an internal address must not get past the URL guard. */
  redirect?: 'error' | 'follow' | 'manual';
}

export interface FetchResponse {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

// --- tenancy ----------------------------------------------------------------

/**
 * Opaque. tenant-kit's `TenantId` when tenant-kit is present; any constant
 * string in a single-tenant application. Every domain, message, suppression
 * and webhook row is keyed on it, which is what makes tenant-kit's row-level
 * isolation apply to this schema unchanged.
 */
export type TenantId = string;

// --- configuration ----------------------------------------------------------

export interface MailConfig {
  /**
   * 32 bytes as 64 hex chars (`openssl rand -hex 32`). Required only when a
   * domain is added on a transport that does not sign — mail-kit then generates
   * the DKIM key pair and this is the AES-256-GCM key its private half is
   * sealed under before it reaches the database. Kept out of the database and
   * out of the backup, like identity-kit's pepper.
   */
  dkimKey?: string;
  /**
   * Whether `send` refuses a `from` address on a domain that has not verified.
   * True in production; false lets a dev database send from anything, through
   * a memory transport, without DNS.
   */
  requireVerifiedDomain?: boolean;
  /**
   * The address DMARC aggregate reports should be sent to (`dmarc@example.com`).
   * When set, the recommended `_dmarc` record for every domain names it.
   */
  dmarcReportAddress?: string;
  /** Sends that fail with a retryable transport error are attempted this many
   *  times in total before they are marked failed. Default 5. */
  maxAttempts?: number;
  /** Webhook deliveries are attempted this many times in total. Default 7. */
  webhookMaxAttempts?: number;
  /**
   * Permit `http:` webhook URLs. Default false: a webhook endpoint must be
   * `https:`. For development against a local receiver only — and even then
   * the host must not be loopback or private (`webhook_url_forbidden`), so
   * point it at a tunnel, not at 127.0.0.1.
   */
  allowInsecureHttp?: boolean;
}

// --- addresses and messages -------------------------------------------------

/** `"ada@example.com"` or `{ email, name }`. Rendered as `Name <addr>` when
 *  named; names with specials are quoted, non-ASCII names are RFC 2047 encoded. */
export type Address = string | { email: string; name?: string };

export interface Attachment {
  filename: string;
  /** Raw bytes, or a base64 string. */
  content: Uint8Array | string;
  contentType?: string;
  /** Set to embed as `cid:` for an inline image in the HTML part. */
  contentId?: string;
}

/**
 * The one-click unsubscribe pair (RFC 8058). Bulk senders to Gmail and Yahoo
 * are required to carry it since 2024; transactional mail may omit it.
 */
export interface ListUnsubscribe {
  /** A URL that accepts `POST` with body `List-Unsubscribe=One-Click`. */
  url?: string;
  /** A mailto: alternative. */
  mailto?: string;
}

export interface SendInput {
  from: Address;
  to: Address | readonly Address[];
  cc?: Address | readonly Address[];
  bcc?: Address | readonly Address[];
  replyTo?: Address | readonly Address[];
  subject: string;
  text?: string;
  html?: string;
  /** Extra headers. Names and values are checked for CR/LF — a header injection
   *  is refused, not folded. */
  headers?: Record<string, string>;
  attachments?: readonly Attachment[];
  listUnsubscribe?: ListUnsubscribe;
  /** Opaque key/value tags. Passed to the transport where it supports them
   *  (SES message tags), stored on the message, echoed in webhook payloads. */
  tags?: Record<string, string>;
  /**
   * A caller-chosen key, unique per tenant. A retry with the same key and the
   * same content returns the original message; the same key with different
   * content is a conflict, not a second send.
   */
  idempotencyKey?: string;
  /** Deliver at or after this time rather than now. */
  scheduledAt?: Date;
}

export type MessageStatus =
  | 'queued'
  | 'scheduled'
  | 'sent'
  | 'delivered'
  | 'delayed'
  | 'bounced'
  | 'complained'
  | 'failed'
  | 'suppressed'
  | 'canceled';

export interface Message {
  id: string;
  tenantId: TenantId;
  status: MessageStatus;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  /** The RFC 5322 Message-ID mail-kit stamped on the message. */
  messageId: string;
  /** The transport's own id, once sent. Delivery events key on this. */
  providerMessageId: string | null;
  tags: Record<string, string>;
  idempotencyKey: string | null;
  attempts: number;
  lastError: string | null;
  /** Recipients dropped before sending because they were on a suppression list. */
  suppressedRecipients: string[];
  scheduledAt: Date | null;
  createdAt: Date;
  sentAt: Date | null;
  updatedAt: Date;
}

export interface SendOptions {
  /** Store the message as queued and return without delivering. A worker
   *  running `deliverPending` picks it up. Default false: deliver inline. */
  defer?: boolean;
}

// --- domains ----------------------------------------------------------------

export type DnsRecordType = 'TXT' | 'CNAME' | 'MX';

export type DnsRecordPurpose = 'dkim' | 'spf' | 'dmarc' | 'return_path' | 'verification';

export interface DnsRecord {
  type: DnsRecordType;
  /** Fully qualified, no trailing dot. */
  name: string;
  value: string;
  priority?: number;
  purpose: DnsRecordPurpose;
  /** Required records gate verification. Recommended ones (DMARC) are checked
   *  and reported but do not block. */
  required: boolean;
}

export type DomainStatus = 'pending' | 'verified' | 'failed';

export interface RecordCheck {
  record: DnsRecord;
  ok: boolean;
  /** What DNS actually returned, for the dashboard. */
  found: string[];
}

export interface SendingDomain {
  id: string;
  tenantId: TenantId;
  name: string;
  status: DomainStatus;
  /** `'transport'` when the transport signs (SES); `'local'` when mail-kit
   *  holds the DKIM key and signs before handing off. */
  signing: 'transport' | 'local';
  dkimSelector: string | null;
  /** The MAIL FROM / Return-Path host, when one is configured. */
  returnPathHost: string | null;
  records: DnsRecord[];
  lastCheck: RecordCheck[] | null;
  createdAt: Date;
  verifiedAt: Date | null;
  lastCheckedAt: Date | null;
}

export interface AddDomainInput {
  name: string;
  /**
   * Subdomain for the envelope sender (`bounce` → `bounce.example.com`).
   * Aligns SPF with the visible From domain, which is what DMARC wants. Default
   * `'bounce'`; pass `null` for none.
   */
  returnPathSubdomain?: string | null;
}

// --- DNS (a seam) -----------------------------------------------------------

/** What verification needs from a resolver. `node:dns/promises` satisfies it;
 *  tests hand in a map. */
export interface DnsResolver {
  resolveTxt(name: string): Promise<string[]>;
  resolveCname(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<Array<{ exchange: string; priority: number }>>;
  /** Hostname → every address (A + AAAA). Used by the webhook URL guard; when
   *  absent, node's `dns.lookup` is used. */
  lookup?(hostname: string): Promise<string[]>;
}

// --- transport (the seam) ---------------------------------------------------

/** What a transport is asked to carry. The MIME is already built and, when
 *  the domain signs locally, already DKIM-signed. */
export interface OutboundEnvelope {
  tenantId: TenantId;
  /** mail-kit's message row id. */
  id: string;
  /** The RFC 5322 Message-ID inside `raw`. */
  messageId: string;
  /** The visible From address (bare). */
  from: string;
  /** Envelope sender (MAIL FROM / Return-Path), bare. Falls back to `from`. */
  returnPath: string;
  /** Every envelope recipient — to + cc + bcc — bare, deduplicated. */
  recipients: string[];
  /** The complete RFC 5322 message, CRLF line endings. */
  raw: Uint8Array;
  tags: Record<string, string>;
}

export interface TransportResult {
  /** The transport's own id for the message. Events must key on this. */
  providerMessageId: string;
  /** Recipients the transport refused outright at submission (an SMTP 5xx on
   *  RCPT TO). mail-kit records a hard bounce for each; the rest were sent. */
  rejected?: Array<{ recipient: string; detail: string }>;
}

export interface DomainRegistration {
  /** Records the transport needs published before it will sign/send. */
  records: DnsRecord[];
  /** Whatever the transport needs to find the identity again. Stored opaque. */
  providerRef?: string;
}

/**
 * The transport seam. Three implementations ship (`memory`, `ses`, `smtp`);
 * anything with `send` is one. A transport that manages sending identities
 * (SES) also implements the domain methods, and then it signs. One that does
 * not (an SMTP relay) leaves them off, and mail-kit generates and holds the
 * DKIM key and signs before `send`.
 */
export interface MailTransport {
  readonly name: string;
  /** The `include:` for the SPF record on the return-path host, if the
   *  transport's IPs need it. `amazonses.com` for SES. */
  readonly spfInclude?: string;

  send(envelope: OutboundEnvelope): Promise<TransportResult>;

  registerDomain?(domain: string, opts: { returnPathHost: string | null }): Promise<DomainRegistration>;
  checkDomain?(domain: string, providerRef: string | null): Promise<{ verified: boolean; detail?: string }>;
  removeDomain?(domain: string, providerRef: string | null): Promise<void>;
}

// --- delivery events --------------------------------------------------------

export type DeliveryEventType =
  | 'sent'
  | 'delivered'
  | 'delayed'
  | 'bounced'
  | 'complained'
  | 'rejected'
  | 'opened'
  | 'clicked';

/**
 * A provider-neutral delivery event. Transports parse their provider's
 * notification into this; `recordEvents` does the rest — status, suppression,
 * webhooks. Identify the message by `providerMessageId` (what a provider
 * knows) or `messageId` (mail-kit's row id, for a transport that echoes it).
 */
export interface DeliveryEvent {
  type: DeliveryEventType;
  providerMessageId?: string;
  messageId?: string;
  /** The recipient the event is about, when the provider says. */
  recipient?: string;
  at: Date;
  bounce?: {
    kind: 'hard' | 'soft';
    /** Provider sub-type, e.g. `General`, `NoEmail`, `MailboxFull`. */
    subtype?: string;
    diagnostic?: string;
  };
  /** For `clicked`. */
  url?: string;
  /** For `opened`/`clicked`. */
  userAgent?: string;
  /** The provider payload, kept on the event row for debugging. */
  raw?: unknown;
}

export interface RecordedEvent {
  id: string;
  messageId: string | null;
  tenantId: TenantId | null;
  type: DeliveryEventType;
  recipient: string | null;
  at: Date;
  detail: Record<string, unknown>;
}

// --- suppression ------------------------------------------------------------

export type SuppressionReason = 'bounce' | 'complaint' | 'unsubscribe' | 'manual';

export interface Suppression {
  id: string;
  /** null = the global list, which every tenant's sends are checked against. */
  tenantId: TenantId | null;
  address: string;
  reason: SuppressionReason;
  detail: string | null;
  createdAt: Date;
}

// --- webhooks ---------------------------------------------------------------

/** Webhook event names, Resend-shaped so a consumer's switch reads naturally. */
export type WebhookEventType =
  | 'email.sent'
  | 'email.delivered'
  | 'email.delivery_delayed'
  | 'email.bounced'
  | 'email.complained'
  | 'email.failed'
  | 'email.opened'
  | 'email.clicked'
  | 'domain.verified'
  | 'domain.failed';

export interface WebhookSubscription {
  id: string;
  tenantId: TenantId;
  url: string;
  events: WebhookEventType[];
  enabled: boolean;
  createdAt: Date;
}

export interface CreatedWebhook extends WebhookSubscription {
  /** Shown once. The consumer verifies signatures with it. */
  secret: string;
}

export type WebhookDeliveryStatus = 'pending' | 'delivered' | 'failed';

export interface WebhookDelivery {
  id: string;
  subscriptionId: string;
  tenantId: TenantId;
  eventType: WebhookEventType;
  status: WebhookDeliveryStatus;
  attempts: number;
  lastStatusCode: number | null;
  lastError: string | null;
  nextAttemptAt: Date | null;
  createdAt: Date;
  deliveredAt: Date | null;
}
