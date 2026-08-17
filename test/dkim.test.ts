// DKIM: a message signed here verifies with the published key, and stops
// verifying when the body or a signed header is touched.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseAddress } from '../src/address.ts';
import { dkimSign, dkimTxtRecord, dkimVerify, generateDkimKey } from '../src/dkim.ts';
import { buildMime } from '../src/mime.ts';

const pair = generateDkimKey();
const keys = async (selector: string, domain: string) =>
  selector === 'qk1' && domain === 'example.com' ? pair.publicKeyBase64 : null;

const message = () =>
  buildMime({
    from: parseAddress({ email: 'ada@example.com', name: 'Ada' }),
    to: [parseAddress('bob@example.org')],
    subject: 'Signed hello with a long subject line that will need folding at some point ok',
    text: 'body line one  \r\nline two\r\n\r\n\r\n',
    html: '<p>hi</p>',
    messageId: '<m1@example.com>',
    date: new Date('2026-08-16T12:00:00Z'),
  });

describe('mail-kit/dkim', () => {
  it('produces a publishable TXT record', () => {
    const txt = dkimTxtRecord(pair.publicKeyBase64);
    assert.match(txt, /^v=DKIM1; k=rsa; p=MII/);
  });

  it('signs and verifies (relaxed/relaxed, rsa-sha256)', async () => {
    const signed = dkimSign(message(), {
      domain: 'example.com',
      selector: 'qk1',
      privateKeyPem: pair.privateKeyPem,
      now: new Date('2026-08-16T12:00:01Z'),
    });
    const text = Buffer.from(signed).toString();
    assert.match(text, /^DKIM-Signature: v=1; a=rsa-sha256; c=relaxed\/relaxed; d=example.com;/);
    for (const line of text.split('\r\n\r\n')[0]!.split('\r\n')) assert.ok(line.length <= 998);
    const result = await dkimVerify(signed, keys);
    assert.deepEqual(result, { ok: true, domain: 'example.com', selector: 'qk1' });
  });

  it('fails when the body or a signed header changes, or the key is unknown', async () => {
    const signed = Buffer.from(
      dkimSign(message(), { domain: 'example.com', selector: 'qk1', privateKeyPem: pair.privateKeyPem }),
    ).toString('latin1');
    const bodyTampered = Buffer.from(signed.replace('line two', 'line 2'), 'latin1');
    assert.equal((await dkimVerify(bodyTampered, keys)).reason, 'body hash mismatch');
    const headerTampered = Buffer.from(signed.replace('Subject: Signed', 'Subject: Forged'), 'latin1');
    assert.equal((await dkimVerify(headerTampered, keys)).reason, 'signature mismatch');
    assert.equal((await dkimVerify(Buffer.from(signed, 'latin1'), async () => null)).reason, 'no public key');
    assert.equal((await dkimVerify(message(), keys)).reason, 'no DKIM-Signature');
  });

  it('survives whitespace changes relaxed canonicalisation forgives', async () => {
    const signed = Buffer.from(
      dkimSign(message(), { domain: 'example.com', selector: 'qk1', privateKeyPem: pair.privateKeyPem }),
    ).toString('latin1');
    // an MTA that re-folds a header and collapses runs of spaces in the body
    const refolded = signed
      .replace('Subject: Signed hello', 'Subject:   Signed\r\n  hello')
      .replace('line one  ', 'line one ');
    assert.equal((await dkimVerify(Buffer.from(refolded, 'latin1'), keys)).ok, true);
  });
});
