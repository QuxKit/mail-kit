// Amazon SES, over its v2 HTTP API — no SDK.
//
// SES is the default transport for a hosted product because it is where a
// fresh sender gets warm IPs and a reputation it did not have to earn. It
// manages sending identities, so it signs (Easy DKIM) and hands back the
// CNAMEs; it takes a configuration set per send, which is how one SES account
// keeps tenants' reputations apart; and it reports delivery, bounces and
// complaints through SNS, which `parseSesEvents` turns into DeliveryEvents and
// `verifySnsMessage` authenticates before you believe a word of it.

import { createVerify } from 'node:crypto';
import { MailError } from '../errors.ts';
import type {
  DeliveryEvent,
  DnsRecord,
  DomainRegistration,
  Fetch,
  FetchResponse,
  MailTransport,
  OutboundEnvelope,
  TransportResult,
} from '../types.ts';
import { type AwsCredentials, signV4 } from './sigv4.ts';

export interface SesTransportOptions {
  region: string;
  credentials: AwsCredentials;
  fetch: Fetch;
  /** A fixed configuration set, or one chosen per envelope (per tenant). */
  configurationSet?: string | ((envelope: OutboundEnvelope) => string | undefined);
  /** Override the endpoint (VPC endpoint, local emulator). */
  endpoint?: string;
  clock?: () => Date;
  timeoutMs?: number;
}

const RETRYABLE_TYPES = new Set([
  'TooManyRequestsException',
  'LimitExceededException',
  'SendingPausedException',
  'InternalServiceErrorException',
  'ServiceUnavailableException',
]);

export function sesTransport(opts: SesTransportOptions): MailTransport {
  const endpoint = (opts.endpoint ?? `https://email.${opts.region}.amazonaws.com`).replace(/\/$/, '');
  const clock = opts.clock ?? (() => new Date());
  const timeoutMs = opts.timeoutMs ?? 30_000;

  const call = async <T>(method: string, path: string, body?: unknown): Promise<{ status: number; data: T }> => {
    const url = `${endpoint}${path}`;
    const text = body === undefined ? '' : JSON.stringify(body);
    const headers = signV4({
      method,
      url,
      headers: { 'content-type': 'application/json' },
      body: text,
      service: 'ses',
      region: opts.region,
      credentials: opts.credentials,
      now: clock(),
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res: FetchResponse;
    try {
      res = await opts.fetch(url, { method, headers, body: text || undefined, signal: controller.signal });
    } catch (error) {
      throw new MailError({
        code: 'transport',
        transport: 'ses',
        retryable: true,
        detail: `network: ${error instanceof Error ? error.message : String(error)}`,
      });
    } finally {
      clearTimeout(timer);
    }
    const raw = await res.text();
    let data: unknown = null;
    try {
      data = raw ? JSON.parse(raw) : null;
    } catch {
      data = { message: raw };
    }
    if (res.status >= 200 && res.status < 300) return { status: res.status, data: data as T };
    const type =
      (res.headers.get('x-amzn-errortype') ?? '').split(':')[0] || (data as { __type?: string })?.__type || 'unknown';
    const message =
      (data as { message?: string; Message?: string })?.message ?? (data as { Message?: string })?.Message ?? raw;
    const retryable = res.status === 429 || res.status >= 500 || RETRYABLE_TYPES.has(type);
    throw new MailError({
      code: 'transport',
      transport: 'ses',
      retryable,
      status: res.status,
      detail: `${type}: ${message}`,
    });
  };

  const identityPath = (domain: string) => `/v2/email/identities/${encodeURIComponent(domain)}`;

  const recordsFor = (domain: string, tokens: string[], returnPathHost: string | null): DnsRecord[] => {
    const records: DnsRecord[] = tokens.map((t) => ({
      type: 'CNAME',
      name: `${t}._domainkey.${domain}`,
      value: `${t}.dkim.amazonses.com`,
      purpose: 'dkim',
      required: true,
    }));
    if (returnPathHost) {
      records.push({
        type: 'MX',
        name: returnPathHost,
        value: `feedback-smtp.${opts.region}.amazonses.com`,
        priority: 10,
        purpose: 'return_path',
        required: true,
      });
      records.push({
        type: 'TXT',
        name: returnPathHost,
        value: 'v=spf1 include:amazonses.com ~all',
        purpose: 'spf',
        required: true,
      });
    }
    return records;
  };

  interface Identity {
    VerifiedForSendingStatus?: boolean;
    DkimAttributes?: { Status?: string; Tokens?: string[] };
    MailFromAttributes?: { MailFromDomain?: string; MailFromDomainStatus?: string };
  }

  return {
    name: 'ses',
    spfInclude: 'amazonses.com',

    async send(envelope): Promise<TransportResult> {
      const configurationSet =
        typeof opts.configurationSet === 'function' ? opts.configurationSet(envelope) : opts.configurationSet;
      const body: Record<string, unknown> = {
        FromEmailAddress: envelope.from,
        Destination: { ToAddresses: envelope.recipients },
        Content: { Raw: { Data: Buffer.from(envelope.raw).toString('base64') } },
      };
      if (configurationSet) body.ConfigurationSetName = configurationSet;
      const tags = Object.entries(envelope.tags);
      if (tags.length) body.EmailTags = tags.map(([Name, Value]) => ({ Name, Value }));
      const { data } = await call<{ MessageId: string }>('POST', '/v2/email/outbound-emails', body);
      return { providerMessageId: data.MessageId };
    },

    async registerDomain(domain, { returnPathHost }): Promise<DomainRegistration> {
      let tokens: string[] = [];
      try {
        const { data } = await call<Identity>('POST', '/v2/email/identities', { EmailIdentity: domain });
        tokens = data.DkimAttributes?.Tokens ?? [];
      } catch (error) {
        // Already known to this account (a re-add) — read it back instead.
        if (!(MailError.hasCode(error, 'transport') && /AlreadyExists/i.test(error.failure.detail))) throw error;
        const { data } = await call<Identity>('GET', identityPath(domain));
        tokens = data.DkimAttributes?.Tokens ?? [];
      }
      if (returnPathHost) {
        await call('PUT', `${identityPath(domain)}/mail-from`, {
          MailFromDomain: returnPathHost,
          BehaviorOnMxFailure: 'USE_DEFAULT_VALUE',
        });
      }
      return { records: recordsFor(domain, tokens, returnPathHost), providerRef: domain };
    },

    async checkDomain(domain) {
      const { data } = await call<Identity>('GET', identityPath(domain));
      const dkim = data.DkimAttributes?.Status;
      const verified = data.VerifiedForSendingStatus === true && dkim === 'SUCCESS';
      return {
        verified,
        detail: `sending=${data.VerifiedForSendingStatus ?? 'unknown'} dkim=${dkim ?? 'unknown'} mailfrom=${data.MailFromAttributes?.MailFromDomainStatus ?? 'n/a'}`,
      };
    },

    async removeDomain(domain) {
      try {
        await call('DELETE', identityPath(domain));
      } catch (error) {
        if (MailError.hasCode(error, 'transport') && error.failure.status === 404) return;
        throw error;
      }
    },
  };
}

// --- SNS → DeliveryEvent ----------------------------------------------------

interface SesRecipient {
  emailAddress: string;
  diagnosticCode?: string;
  status?: string;
}

interface SesMessage {
  eventType?: string;
  notificationType?: string;
  mail: { messageId: string; timestamp?: string; destination?: string[]; tags?: Record<string, string[]> };
  bounce?: { bounceType: string; bounceSubType?: string; bouncedRecipients: SesRecipient[]; timestamp?: string };
  complaint?: {
    complainedRecipients: Array<{ emailAddress: string }>;
    complaintFeedbackType?: string;
    timestamp?: string;
  };
  delivery?: { recipients?: string[]; timestamp?: string };
  deliveryDelay?: { delayType?: string; delayedRecipients?: SesRecipient[]; timestamp?: string };
  reject?: { reason?: string };
  open?: { timestamp?: string; userAgent?: string };
  click?: { timestamp?: string; userAgent?: string; link?: string };
}

/**
 * Turn an SES notification — either the SNS envelope (`{ Type, Message }`) or
 * the inner SES JSON — into DeliveryEvents. One event per affected recipient
 * for bounces/complaints/delays, one per message otherwise.
 */
export function parseSesEvents(input: string | Record<string, unknown>): DeliveryEvent[] {
  let obj: unknown = typeof input === 'string' ? JSON.parse(input) : input;
  if (
    obj &&
    typeof obj === 'object' &&
    'Type' in obj &&
    'Message' in obj &&
    typeof (obj as { Message: unknown }).Message === 'string'
  ) {
    if ((obj as { Type: string }).Type !== 'Notification') return [];
    obj = JSON.parse((obj as { Message: string }).Message);
  }
  const m = obj as SesMessage;
  if (!m || typeof m !== 'object' || !m.mail?.messageId) return [];
  const kind = (m.eventType ?? m.notificationType ?? '').toLowerCase();
  const id = m.mail.messageId;
  const when = (s?: string) => (s ? new Date(s) : m.mail.timestamp ? new Date(m.mail.timestamp) : new Date());

  switch (kind) {
    case 'send':
      return [{ type: 'sent', providerMessageId: id, at: when(), raw: m }];
    case 'delivery':
      return (m.delivery?.recipients?.length ? m.delivery.recipients : [undefined]).map((r) => ({
        type: 'delivered',
        providerMessageId: id,
        recipient: r,
        at: when(m.delivery?.timestamp),
        raw: m,
      }));
    case 'bounce': {
      const hard = m.bounce?.bounceType === 'Permanent';
      return (m.bounce?.bouncedRecipients ?? []).map((r) => ({
        type: 'bounced',
        providerMessageId: id,
        recipient: r.emailAddress,
        at: when(m.bounce?.timestamp),
        bounce: { kind: hard ? 'hard' : 'soft', subtype: m.bounce?.bounceSubType, diagnostic: r.diagnosticCode },
        raw: m,
      }));
    }
    case 'complaint':
      return (m.complaint?.complainedRecipients ?? []).map((r) => ({
        type: 'complained',
        providerMessageId: id,
        recipient: r.emailAddress,
        at: when(m.complaint?.timestamp),
        raw: m,
      }));
    case 'deliverydelay':
      return (
        m.deliveryDelay?.delayedRecipients?.length
          ? m.deliveryDelay.delayedRecipients
          : [{ emailAddress: undefined as unknown as string }]
      ).map((r) => ({
        type: 'delayed',
        providerMessageId: id,
        recipient: r.emailAddress,
        at: when(m.deliveryDelay?.timestamp),
        bounce: { kind: 'soft', subtype: m.deliveryDelay?.delayType, diagnostic: r.diagnosticCode },
        raw: m,
      }));
    case 'reject':
      return [
        {
          type: 'rejected',
          providerMessageId: id,
          at: when(),
          bounce: { kind: 'hard', diagnostic: m.reject?.reason },
          raw: m,
        },
      ];
    case 'open':
      return [
        { type: 'opened', providerMessageId: id, at: when(m.open?.timestamp), userAgent: m.open?.userAgent, raw: m },
      ];
    case 'click':
      return [
        {
          type: 'clicked',
          providerMessageId: id,
          at: when(m.click?.timestamp),
          url: m.click?.link,
          userAgent: m.click?.userAgent,
          raw: m,
        },
      ];
    default:
      return [];
  }
}

// --- SNS signature ----------------------------------------------------------

export interface SnsMessage {
  Type: string;
  MessageId: string;
  TopicArn: string;
  Message: string;
  Timestamp: string;
  SignatureVersion: string;
  Signature: string;
  SigningCertURL: string;
  Subject?: string;
  SubscribeURL?: string;
  Token?: string;
}

const certCache = new Map<string, string>();

/**
 * Verify an SNS message's signature against Amazon's certificate. Refuses a
 * SigningCertURL that is not an https `sns.<region>.amazonaws.com` host — the
 * one check that turns "verified" from a formality into a fact. Throws
 * `MailError` (`signature_invalid`) on failure.
 */
export async function verifySnsMessage(message: SnsMessage, deps: { fetch: Fetch }): Promise<void> {
  const fail = (reason: string): never => {
    throw new MailError({ code: 'signature_invalid', reason });
  };
  let certUrl: URL;
  try {
    certUrl = new URL(message.SigningCertURL);
  } catch {
    return fail('SigningCertURL is not a URL');
  }
  if (certUrl.protocol !== 'https:' || !/^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$/.test(certUrl.hostname)) {
    return fail('SigningCertURL is not an SNS host');
  }
  const fields =
    message.Type === 'Notification'
      ? ['Message', 'MessageId', ...(message.Subject !== undefined ? ['Subject'] : []), 'Timestamp', 'TopicArn', 'Type']
      : message.Type === 'SubscriptionConfirmation' || message.Type === 'UnsubscribeConfirmation'
        ? ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type']
        : fail(`unknown SNS message type ${message.Type}`);
  const canonical = (fields as string[])
    .map((f) => `${f}\n${(message as unknown as Record<string, string>)[f]}\n`)
    .join('');

  let cert = certCache.get(certUrl.href);
  if (!cert) {
    const res = await deps.fetch(certUrl.href, { method: 'GET', headers: {} });
    if (res.status !== 200) return fail(`could not fetch signing certificate (${res.status})`);
    cert = await res.text();
    certCache.set(certUrl.href, cert);
  }
  const algorithm = message.SignatureVersion === '2' ? 'RSA-SHA256' : 'RSA-SHA1';
  let ok = false;
  try {
    ok = createVerify(algorithm).update(canonical, 'utf8').verify(cert, message.Signature, 'base64');
  } catch (error) {
    return fail(`verify failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!ok) fail('signature mismatch');
}
