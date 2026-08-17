// The MIME builder: structure, encodings, and the header-injection gate.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseAddress, renderAddress } from '../src/address.ts';
import { MailError } from '../src/errors.ts';
import { buildMime, quotedPrintable, rfc5322Date } from '../src/mime.ts';

const from = parseAddress({ email: 'Ada@Example.COM', name: 'Ada Lovelace' });
const to = [parseAddress('bob@example.org')];
const base = { from, to, subject: 'Hello', messageId: '<abc@example.com>', date: new Date('2026-08-16T12:00:00Z') };

describe('mail-kit/mime', () => {
  it('normalises the domain, keeps the local part, renders names', () => {
    assert.equal(from.email, 'Ada@example.com');
    assert.equal(from.domain, 'example.com');
    assert.equal(renderAddress(from), 'Ada Lovelace <Ada@example.com>');
    assert.equal(renderAddress(parseAddress({ email: 'x@example.com', name: 'Smith, J.' })), '"Smith, J." <x@example.com>');
    assert.match(renderAddress(parseAddress({ email: 'x@example.com', name: 'Zoë' })), /^=\?UTF-8\?B\?.*\?= <x@example.com>$/);
    assert.equal(parseAddress('x@Bücher.example').domain, 'xn--bcher-kva.example');
    assert.deepEqual(parseAddress('Ada Lovelace <ada@example.com>'), { email: 'ada@example.com', name: 'Ada Lovelace', domain: 'example.com' });
    assert.deepEqual(parseAddress('"Smith, J." <j@example.com>'), { email: 'j@example.com', name: 'Smith, J.', domain: 'example.com' });
    assert.equal(parseAddress('<bare@example.com>').name, null);
  });

  it('rejects addresses that are not addresses', () => {
    for (const bad of ['', 'nope', '@x.com', 'a@', 'a b@x.com', 'a@x', 'a@-x.com', 'a\r\nb@x.com']) {
      assert.throws(() => parseAddress(bad), (e: unknown) => MailError.hasCode(e, 'invalid_address'), bad);
    }
  });

  it('builds text-only, html-only and alternative bodies with CRLF and QP', () => {
    const t = Buffer.from(buildMime({ ...base, text: 'plain body' })).toString();
    assert.match(t, /^From: Ada Lovelace <Ada@example.com>\r\nTo: bob@example.org\r\nSubject: Hello\r\n/);
    assert.match(t, /Content-Type: text\/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nplain body\r\n$/);
    assert.ok(!/[^\r]\n/.test(t), 'no bare LF');

    const both = Buffer.from(buildMime({ ...base, text: 'hi', html: '<b>hi</b>' })).toString();
    assert.match(both, /Content-Type: multipart\/alternative; boundary="([^"]+)"/);
    const b = /boundary="([^"]+)"/.exec(both)![1]!;
    assert.equal(both.split(`--${b}`).length, 4, 'two parts + terminator');
    assert.ok(both.indexOf('text/plain') < both.indexOf('text/html'), 'plain first');
  });

  it('nests attachments and inline images correctly', () => {
    const m = Buffer.from(
      buildMime({
        ...base,
        html: '<img src="cid:logo">',
        attachments: [
          { filename: 'logo.png', content: Buffer.from('PNG'), contentType: 'image/png', contentId: 'logo' },
          { filename: 'invoice.pdf', content: Buffer.from('%PDF').toString('base64'), contentType: 'application/pdf' },
        ],
      }),
    ).toString();
    assert.match(m, /^Content-Type: multipart\/mixed/m);
    assert.match(m, /Content-Type: multipart\/related/);
    assert.match(m, /Content-ID: <logo>/);
    assert.match(m, /Content-Disposition: attachment; filename="invoice.pdf"/);
    assert.match(m, /JVBERg==/, 'pdf bytes base64');
  });

  it('encodes non-ASCII subjects and quoted-printable edge cases', () => {
    const m = Buffer.from(buildMime({ ...base, subject: 'Zoë — invoice', text: 'a=b trailing \nline' })).toString();
    assert.match(m, /^Subject: =\?UTF-8\?B\?/m);
    assert.match(m, /a=3Db trailing=20\r\nline/);
    const long = quotedPrintable('x'.repeat(200));
    for (const line of long.split('\r\n')) assert.ok(line.length <= 76, `qp line ${line.length}`);
    assert.equal(long.replace(/=\r\n/g, ''), 'x'.repeat(200));
  });

  it('adds List-Unsubscribe and the one-click header, and refuses injection', () => {
    const m = Buffer.from(buildMime({ ...base, text: 'x', listUnsubscribe: { url: 'https://u.example/1', mailto: 'un@example.com' } })).toString();
    assert.match(m, /List-Unsubscribe: <https:\/\/u.example\/1>, <mailto:un@example.com>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click/);
    assert.throws(() => buildMime({ ...base, text: 'x', subject: 'a\r\nBcc: evil@x.com' }), (e: unknown) => MailError.hasCode(e, 'header_injection'));
    assert.throws(() => buildMime({ ...base, text: 'x', headers: { 'X-Foo': 'a\nb' } }), (e: unknown) => MailError.hasCode(e, 'header_injection'));
    assert.throws(() => buildMime({ ...base, text: 'x', headers: { From: 'spoof@x.com' } }), (e: unknown) => MailError.hasCode(e, 'invalid_input'));
    assert.throws(() => buildMime({ ...base }), (e: unknown) => MailError.hasCode(e, 'invalid_input'));
  });

  it('formats the date per RFC 5322', () => {
    assert.equal(rfc5322Date(new Date('2026-08-16T12:00:05Z')), 'Sun, 16 Aug 2026 12:00:05 +0000');
  });
});
