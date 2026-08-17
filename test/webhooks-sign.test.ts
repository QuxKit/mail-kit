// The Standard-Webhooks signature pair: what we emit verifies, and the
// verifier refuses the things it must.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { signWebhook, verifyWebhookSignature } from '../src/webhooks.ts';

describe('mail-kit/webhooks: signature', () => {
  const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
  const body = JSON.stringify({ type: 'email.delivered', data: { email_id: 'x' } });
  const now = new Date('2026-08-16T12:00:00Z');

  it('round-trips', () => {
    const headers = signWebhook(secret, 'msg_1', now, body);
    assert.equal(headers['webhook-timestamp'], '1786881600');
    assert.match(headers['webhook-signature']!, /^v1,[A-Za-z0-9+/=]+$/);
    const parsed = verifyWebhookSignature(secret, headers, body, { now }) as { type: string };
    assert.equal(parsed.type, 'email.delivered');
    // header names are case-insensitive on the receiving side
    assert.ok(
      verifyWebhookSignature(
        secret,
        {
          'Webhook-Id': headers['webhook-id'],
          'Webhook-Timestamp': headers['webhook-timestamp'],
          'Webhook-Signature': headers['webhook-signature'],
        },
        body,
        { now },
      ),
    );
  });

  it('refuses a tampered body, a wrong secret, a stale timestamp and missing headers', () => {
    const headers = signWebhook(secret, 'msg_1', now, body);
    const bad = (h: Record<string, string | undefined>, b = body, o = { now }) =>
      assert.throws(
        () => verifyWebhookSignature(secret, h, b, o),
        (e: unknown) => MailError.hasCode(e, 'signature_invalid'),
      );
    bad(headers, body.replace('delivered', 'bounced'));
    assert.throws(
      () => verifyWebhookSignature('whsec_other', headers, body, { now }),
      (e: unknown) => MailError.hasCode(e, 'signature_invalid'),
    );
    bad(headers, body, { now: new Date(now.getTime() + 10 * 60_000) });
    bad({ 'webhook-id': 'msg_1' });
    // an extra unknown-version signature alongside a valid one is fine
    assert.ok(
      verifyWebhookSignature(
        secret,
        { ...headers, 'webhook-signature': `v2,zzz ${headers['webhook-signature']}` },
        body,
        { now },
      ),
    );
  });
});
