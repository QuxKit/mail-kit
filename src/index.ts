// @quxkit/mail-kit — transactional email as a library, over a transport you choose.
//
// The public surface. Transports live under their own entry points
// (`@quxkit/mail-kit/ses`, `/smtp`, `/memory`) so an app that uses one does
// not compile the others.

export { createMail } from './instance.ts';
export type { Mail, MailOptions } from './instance.ts';

export { createMessages, normaliseInput, SEND_RETRY_SCHEDULE_S } from './messages.ts';
export type { MessagesApi, MessagesOptions, ListMessagesOptions, StoredPayload } from './messages.ts';

export { createDomains, recordSatisfied } from './domains.ts';
export type { DomainsApi, DomainsOptions, LocalSigner } from './domains.ts';

export { createEvents, nextStatus, messageData } from './events.ts';
export type { EventsApi, EventsOptions } from './events.ts';

export { createSuppression, normaliseForSuppression } from './suppression.ts';
export type { SuppressionApi, SuppressionOptions, AddSuppressionInput } from './suppression.ts';

export {
  createWebhooks,
  signWebhook,
  verifyWebhookSignature,
  RETRY_SCHEDULE_S as WEBHOOK_RETRY_SCHEDULE_S,
  ALL_WEBHOOK_EVENTS,
} from './webhooks.ts';
export type { WebhooksApi, WebhooksOptions, CreateWebhookInput, WebhookPayload, VerifyOptions } from './webhooks.ts';

export { buildMime, quotedPrintable, newMessageId, rfc5322Date } from './mime.ts';
export type { MimeInput } from './mime.ts';

export { parseAddress, parseAddressList, renderAddress, normaliseDomain } from './address.ts';
export type { ParsedAddress } from './address.ts';

export { generateDkimKey, dkimSign, dkimVerify, dkimTxtRecord, DEFAULT_SIGNED_HEADERS } from './dkim.ts';
export type { DkimKeyPair, DkimSignOptions, DkimVerifyResult } from './dkim.ts';

export { nodeDnsResolver } from './dns.ts';

export { MailError } from './errors.ts';
export type { MailFailure, MailErrorCode } from './errors.ts';

export type {
  SqlExecutor,
  Clock,
  Logger,
  Fetch,
  FetchInit,
  FetchResponse,
  TenantId,
  MailConfig,
  Address,
  Attachment,
  ListUnsubscribe,
  SendInput,
  SendOptions,
  Message,
  MessageStatus,
  DnsRecord,
  DnsRecordType,
  DnsRecordPurpose,
  DomainStatus,
  RecordCheck,
  SendingDomain,
  AddDomainInput,
  DnsResolver,
  OutboundEnvelope,
  TransportResult,
  DomainRegistration,
  MailTransport,
  DeliveryEvent,
  DeliveryEventType,
  RecordedEvent,
  Suppression,
  SuppressionReason,
  WebhookEventType,
  WebhookSubscription,
  CreatedWebhook,
  WebhookDelivery,
  WebhookDeliveryStatus,
} from './types.ts';
