// The SES transport, offline: the SigV4 signature against AWS's published test
// vector, the request shapes, error → retryable mapping, SNS event parsing and
// SNS signature verification.

import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { parseSesEvents, type SnsMessage, sesTransport, verifySnsMessage } from '../src/transports/ses.ts';
import { signV4 } from '../src/transports/sigv4.ts';
import type { FetchInit, OutboundEnvelope } from '../src/types.ts';

describe('mail-kit/ses: sigv4', () => {
  it('reproduces the AWS "get-vanilla" test-suite signature', () => {
    // From the AWS SigV4 test suite (aws-sig-v4-test-suite/get-vanilla).
    const headers = signV4({
      method: 'GET',
      url: 'https://example.amazonaws.com/',
      headers: {},
      body: '',
      service: 'service',
      region: 'us-east-1',
      credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' },
      now: new Date('2015-08-30T12:36:00Z'),
    });
    assert.equal(headers['x-amz-date'], '20150830T123600Z');
    assert.equal(
      headers.authorization,
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' +
        'SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
    );
  });

  it('sorts and encodes the query string and carries a session token', () => {
    const headers = signV4({
      method: 'GET',
      url: 'https://example.amazonaws.com/?Param2=value2&Param1=value1',
      headers: {},
      body: '',
      service: 'service',
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'AKIDEXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        sessionToken: 'tok',
      },
      now: new Date('2015-08-30T12:36:00Z'),
    });
    assert.equal(headers['x-amz-security-token'], 'tok');
    assert.match(headers.authorization!, /SignedHeaders=host;x-amz-date;x-amz-security-token/);
  });

  it('reproduces get-vanilla-query-order-key-case from the suite', () => {
    const headers = signV4({
      method: 'GET',
      url: 'https://example.amazonaws.com/?Param2=value2&Param1=value1',
      headers: {},
      body: '',
      service: 'service',
      region: 'us-east-1',
      credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' },
      now: new Date('2015-08-30T12:36:00Z'),
    });
    assert.match(headers.authorization!, /Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500$/);
  });
});

const envelope: OutboundEnvelope = {
  tenantId: 't1',
  id: 'msg-1',
  messageId: '<m1@example.com>',
  from: 'ada@example.com',
  returnPath: 'bounces@bounce.example.com',
  recipients: ['bob@example.org', 'carol@example.org'],
  raw: Buffer.from('From: ada@example.com\r\nTo: bob@example.org\r\nSubject: hi\r\n\r\nbody\r\n'),
  tags: { campaign: 'welcome' },
};

function fakeFetch(
  handler: (url: string, init: FetchInit) => { status: number; body?: unknown; headers?: Record<string, string> },
) {
  const calls: Array<{ url: string; init: FetchInit }> = [];
  const fetch = async (url: string, init: FetchInit) => {
    calls.push({ url, init });
    const r = handler(url, init);
    return {
      status: r.status,
      headers: { get: (n: string) => r.headers?.[n.toLowerCase()] ?? null },
      text: async () => (r.body === undefined ? '' : JSON.stringify(r.body)),
    };
  };
  return { fetch, calls };
}

describe('mail-kit/ses: transport', () => {
  const creds = { accessKeyId: 'AKIA', secretAccessKey: 'secret' };

  it('sends raw MIME through SendEmail with a per-tenant configuration set and tags', async () => {
    const f = fakeFetch(() => ({ status: 200, body: { MessageId: '0100018-abc' } }));
    const t = sesTransport({
      region: 'eu-west-1',
      credentials: creds,
      fetch: f.fetch,
      configurationSet: (e) => `tenant-${e.tenantId}`,
    });
    const result = await t.send(envelope);
    assert.equal(result.providerMessageId, '0100018-abc');
    const call = f.calls[0]!;
    assert.equal(call.url, 'https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails');
    assert.equal(call.init.method, 'POST');
    assert.match(
      call.init.headers.authorization!,
      /^AWS4-HMAC-SHA256 Credential=AKIA\/\d{8}\/eu-west-1\/ses\/aws4_request/,
    );
    const body = JSON.parse(call.init.body!);
    assert.equal(body.ConfigurationSetName, 'tenant-t1');
    assert.deepEqual(body.Destination.ToAddresses, ['bob@example.org', 'carol@example.org']);
    assert.deepEqual(body.EmailTags, [{ Name: 'campaign', Value: 'welcome' }]);
    assert.equal(Buffer.from(body.Content.Raw.Data, 'base64').toString(), Buffer.from(envelope.raw).toString());
  });

  it('maps errors: 429/5xx retryable, MessageRejected not', async () => {
    const throttled = sesTransport({
      region: 'us-east-1',
      credentials: creds,
      fetch: fakeFetch(() => ({
        status: 429,
        body: { message: 'slow down' },
        headers: { 'x-amzn-errortype': 'TooManyRequestsException' },
      })).fetch,
    });
    await assert.rejects(
      throttled.send(envelope),
      (e: unknown) => MailError.hasCode(e, 'transport') && e.failure.retryable === true && e.failure.status === 429,
    );
    const rejected = sesTransport({
      region: 'us-east-1',
      credentials: creds,
      fetch: fakeFetch(() => ({
        status: 400,
        body: { message: 'Email address is not verified.' },
        headers: { 'x-amzn-errortype': 'MessageRejected' },
      })).fetch,
    });
    await assert.rejects(
      rejected.send(envelope),
      (e: unknown) =>
        MailError.hasCode(e, 'transport') && e.failure.retryable === false && /MessageRejected/.test(e.failure.detail),
    );
    const down = sesTransport({
      region: 'us-east-1',
      credentials: creds,
      fetch: async () => {
        throw new Error('ECONNRESET');
      },
    });
    await assert.rejects(
      down.send(envelope),
      (e: unknown) => MailError.hasCode(e, 'transport') && e.failure.retryable === true,
    );
  });

  it('registers a domain: identity + mail-from, and returns the CNAME/MX/TXT checklist', async () => {
    const f = fakeFetch((url, init) => {
      if (init.method === 'POST' && url.endsWith('/v2/email/identities'))
        return { status: 200, body: { DkimAttributes: { Tokens: ['t1', 't2', 't3'] } } };
      if (init.method === 'PUT' && url.endsWith('/mail-from')) return { status: 200, body: {} };
      if (init.method === 'GET')
        return {
          status: 200,
          body: {
            VerifiedForSendingStatus: true,
            DkimAttributes: { Status: 'SUCCESS' },
            MailFromAttributes: { MailFromDomainStatus: 'SUCCESS' },
          },
        };
      return { status: 404 };
    });
    const t = sesTransport({ region: 'us-east-1', credentials: creds, fetch: f.fetch });
    const reg = await t.registerDomain!('example.com', { returnPathHost: 'bounce.example.com' });
    assert.deepEqual(
      reg.records.map((r) => [r.type, r.name, r.value]),
      [
        ['CNAME', 't1._domainkey.example.com', 't1.dkim.amazonses.com'],
        ['CNAME', 't2._domainkey.example.com', 't2.dkim.amazonses.com'],
        ['CNAME', 't3._domainkey.example.com', 't3.dkim.amazonses.com'],
        ['MX', 'bounce.example.com', 'feedback-smtp.us-east-1.amazonses.com'],
        ['TXT', 'bounce.example.com', 'v=spf1 include:amazonses.com ~all'],
      ],
    );
    assert.equal(JSON.parse(f.calls[1]!.init.body!).MailFromDomain, 'bounce.example.com');
    assert.deepEqual(await t.checkDomain!('example.com', 'example.com'), {
      verified: true,
      detail: 'sending=true dkim=SUCCESS mailfrom=SUCCESS',
    });
  });

  it('re-reads an identity that already exists instead of failing', async () => {
    const f = fakeFetch((_url, init) => {
      if (init.method === 'POST')
        return {
          status: 400,
          body: { message: 'already exists' },
          headers: { 'x-amzn-errortype': 'AlreadyExistsException' },
        };
      if (init.method === 'GET') return { status: 200, body: { DkimAttributes: { Tokens: ['x'] } } };
      return { status: 200, body: {} };
    });
    const t = sesTransport({ region: 'us-east-1', credentials: creds, fetch: f.fetch });
    const reg = await t.registerDomain!('example.com', { returnPathHost: null });
    assert.equal(reg.records.length, 1);
    assert.equal(reg.records[0]!.name, 'x._domainkey.example.com');
  });
});

describe('mail-kit/ses: events', () => {
  const mail = { messageId: 'ses-1', timestamp: '2026-08-16T12:00:00.000Z', destination: ['bob@example.org'] };

  it('parses bounce, complaint, delivery, delay, open and click, from the SNS envelope or the inner message', () => {
    const bounce = parseSesEvents({
      Type: 'Notification',
      Message: JSON.stringify({
        eventType: 'Bounce',
        mail,
        bounce: {
          bounceType: 'Permanent',
          bounceSubType: 'General',
          bouncedRecipients: [{ emailAddress: 'bob@example.org', diagnosticCode: 'smtp; 550 no such user' }],
          timestamp: '2026-08-16T12:00:05.000Z',
        },
      }),
    });
    assert.equal(bounce.length, 1);
    assert.equal(bounce[0]!.type, 'bounced');
    assert.equal(bounce[0]!.providerMessageId, 'ses-1');
    assert.equal(bounce[0]!.recipient, 'bob@example.org');
    assert.deepEqual(bounce[0]!.bounce, { kind: 'hard', subtype: 'General', diagnostic: 'smtp; 550 no such user' });
    assert.equal(bounce[0]!.at.toISOString(), '2026-08-16T12:00:05.000Z');

    const soft = parseSesEvents({
      notificationType: 'Bounce',
      mail,
      bounce: {
        bounceType: 'Transient',
        bounceSubType: 'MailboxFull',
        bouncedRecipients: [{ emailAddress: 'bob@example.org' }],
      },
    });
    assert.equal(soft[0]!.bounce!.kind, 'soft');

    const complaint = parseSesEvents({
      eventType: 'Complaint',
      mail,
      complaint: { complainedRecipients: [{ emailAddress: 'bob@example.org' }], complaintFeedbackType: 'abuse' },
    });
    assert.equal(complaint[0]!.type, 'complained');

    const delivered = parseSesEvents({
      eventType: 'Delivery',
      mail,
      delivery: { recipients: ['bob@example.org'], timestamp: '2026-08-16T12:00:03.000Z' },
    });
    assert.equal(delivered[0]!.type, 'delivered');
    assert.equal(delivered[0]!.recipient, 'bob@example.org');

    const delayed = parseSesEvents({
      eventType: 'DeliveryDelay',
      mail,
      deliveryDelay: {
        delayType: 'TransientCommunicationFailure',
        delayedRecipients: [{ emailAddress: 'bob@example.org' }],
      },
    });
    assert.equal(delayed[0]!.type, 'delayed');

    assert.equal(parseSesEvents({ eventType: 'Open', mail, open: { userAgent: 'UA' } })[0]!.userAgent, 'UA');
    assert.equal(
      parseSesEvents({ eventType: 'Click', mail, click: { link: 'https://x.example' } })[0]!.url,
      'https://x.example',
    );
    assert.equal(parseSesEvents({ eventType: 'Send', mail })[0]!.type, 'sent');
    assert.equal(parseSesEvents({ eventType: 'Reject', mail, reject: { reason: 'Bad content' } })[0]!.type, 'rejected');
    assert.deepEqual(parseSesEvents({ Type: 'SubscriptionConfirmation', Message: '{}' }), []);
    assert.deepEqual(parseSesEvents({ eventType: 'Nope', mail }), []);
  });

  it('verifies an SNS signature and refuses a foreign certificate host', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const message: SnsMessage = {
      Type: 'Notification',
      MessageId: 'id-1',
      TopicArn: 'arn:aws:sns:us-east-1:123:ses',
      Message: '{"eventType":"Send"}',
      Timestamp: '2026-08-16T12:00:00.000Z',
      SignatureVersion: '1',
      Signature: '',
      SigningCertURL: 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem',
    };
    const canonical = ['Message', 'MessageId', 'Timestamp', 'TopicArn', 'Type']
      .map((f) => `${f}\n${(message as unknown as Record<string, string>)[f]}\n`)
      .join('');
    message.Signature = createSign('RSA-SHA1').update(canonical).sign(privateKey, 'base64');
    const fetch = async () => ({ status: 200, headers: { get: () => null }, text: async () => pem });

    await verifySnsMessage(message, { fetch });
    await assert.rejects(verifySnsMessage({ ...message, Message: 'tampered' }, { fetch }), (e: unknown) =>
      MailError.hasCode(e, 'signature_invalid'),
    );
    await assert.rejects(
      verifySnsMessage({ ...message, SigningCertURL: 'https://evil.example/cert.pem' }, { fetch }),
      (e: unknown) => MailError.hasCode(e, 'signature_invalid') && /SNS host/.test(e.failure.reason),
    );
    await assert.rejects(
      verifySnsMessage({ ...message, SigningCertURL: 'http://sns.us-east-1.amazonaws.com/x.pem' }, { fetch }),
      (e: unknown) => MailError.hasCode(e, 'signature_invalid'),
    );
  });
});
