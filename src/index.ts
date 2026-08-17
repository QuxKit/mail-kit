// @quxkit/mail-kit — transactional email as a library, over a transport you choose.
//
// The public surface. Transports live under their own entry points
// (`@quxkit/mail-kit/ses`, `/smtp`, `/memory`) so an app that uses one does
// not compile the others.

export type { ParsedAddress } from './address.ts';
export { normaliseDomain, parseAddress, parseAddressList, renderAddress } from './address.ts';
export type { DkimKeyPair, DkimSignOptions, DkimVerifyResult } from './dkim.ts';
export { DEFAULT_SIGNED_HEADERS, dkimSign, dkimTxtRecord, dkimVerify, generateDkimKey } from './dkim.ts';
export { nodeDnsResolver, nodeLookup } from './dns.ts';
export type { DomainsApi, DomainsOptions, LocalSigner } from './domains.ts';
export { createDomains, recordSatisfied } from './domains.ts';
export type { MailErrorCode, MailFailure } from './errors.ts';
export { MailError } from './errors.ts';
export type { EventsApi, EventsOptions } from './events.ts';
export { createEvents, messageData, nextStatus } from './events.ts';
export type { Mail, MailOptions } from './instance.ts';
export { createMail } from './instance.ts';
export type { ListMessagesOptions, MessagesApi, MessagesOptions, StoredPayload } from './messages.ts';
export { createMessages, normaliseInput, SEND_RETRY_SCHEDULE_S } from './messages.ts';
export type { MimeInput } from './mime.ts';
export { assertAttachmentSafe, buildMime, newMessageId, quotedPrintable, rfc5322Date } from './mime.ts';
export type { HostResolver, UrlGuardOptions } from './ssrf.ts';
export { assertWebhookUrlAllowed, forbiddenAddressReason } from './ssrf.ts';
export type { AddSuppressionInput, SuppressionApi, SuppressionOptions } from './suppression.ts';
export { createSuppression, normaliseForSuppression } from './suppression.ts';
export type {
  AddDomainInput,
  Address,
  Attachment,
  Clock,
  CreatedWebhook,
  DeliveryEvent,
  DeliveryEventType,
  DnsRecord,
  DnsRecordPurpose,
  DnsRecordType,
  DnsResolver,
  DomainRegistration,
  DomainStatus,
  Fetch,
  FetchInit,
  FetchResponse,
  ListUnsubscribe,
  Logger,
  MailConfig,
  MailTransport,
  Message,
  MessageStatus,
  OutboundEnvelope,
  RecordCheck,
  RecordedEvent,
  SendInput,
  SendingDomain,
  SendOptions,
  SqlExecutor,
  Suppression,
  SuppressionReason,
  TenantId,
  TransportResult,
  WebhookDelivery,
  WebhookDeliveryStatus,
  WebhookEventType,
  WebhookSubscription,
} from './types.ts';
export type { CreateWebhookInput, VerifyOptions, WebhookPayload, WebhooksApi, WebhooksOptions } from './webhooks.ts';
export {
  ALL_WEBHOOK_EVENTS,
  createWebhooks,
  RETRY_SCHEDULE_S as WEBHOOK_RETRY_SCHEDULE_S,
  signWebhook,
  verifyWebhookSignature,
} from './webhooks.ts';
