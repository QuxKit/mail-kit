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
    assert.equal(
      renderAddress(parseAddress({ email: 'x@example.com', name: 'Smith, J.' })),
      '"Smith, J." <x@example.com>',
    );
    assert.match(
      renderAddress(parseAddress({ email: 'x@example.com', name: 'Zoë' })),
      /^=\?UTF-8\?B\?.*\?= <x@example.com>$/,
    );
    assert.equal(parseAddress('x@Bücher.example').domain, 'xn--bcher-kva.example');
    assert.deepEqual(parseAddress('Ada Lovelace <ada@example.com>'), {
      email: 'ada@example.com',
      name: 'Ada Lovelace',
      domain: 'example.com',
    });
    assert.deepEqual(parseAddress('"Smith, J." <j@example.com>'), {
      email: 'j@example.com',
      name: 'Smith, J.',
      domain: 'example.com',
    });
    assert.equal(parseAddress('<bare@example.com>').name, null);
  });

  it('rejects addresses that are not addresses', () => {
    for (const bad of ['', 'nope', '@x.com', 'a@', 'a b@x.com', 'a@x', 'a@-x.com', 'a\r\nb@x.com']) {
      assert.throws(
        () => parseAddress(bad),
        (e: unknown) => MailError.hasCode(e, 'invalid_address'),
        bad,
      );
    }
  });

  it('builds text-only, html-only and alternative bodies with CRLF and QP', () => {
    const t = Buffer.from(buildMime({ ...base, text: 'plain body' })).toString();
    assert.match(t, /^From: Ada Lovelace <Ada@example.com>\r\nTo: bob@example.org\r\nSubject: Hello\r\n/);
    assert.match(
      t,
      /Content-Type: text\/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nplain body\r\n$/,
    );
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
    const m = Buffer.from(
      buildMime({ ...base, text: 'x', listUnsubscribe: { url: 'https://u.example/1', mailto: 'un@example.com' } }),
    ).toString();
    assert.match(
      m,
      /List-Unsubscribe: <https:\/\/u.example\/1>, <mailto:un@example.com>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click/,
    );
    assert.throws(
      () => buildMime({ ...base, text: 'x', subject: 'a\r\nBcc: evil@x.com' }),
      (e: unknown) => MailError.hasCode(e, 'header_injection'),
    );
    assert.throws(
      () => buildMime({ ...base, text: 'x', headers: { 'X-Foo': 'a\nb' } }),
      (e: unknown) => MailError.hasCode(e, 'header_injection'),
    );
    assert.throws(
      () => buildMime({ ...base, text: 'x', headers: { From: 'spoof@x.com' } }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input'),
    );
    assert.throws(
      () => buildMime({ ...base }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input'),
    );
  });

  it('refuses a cid: attachment on a message with no html part, rather than dropping it', () => {
    const logo = { filename: 'logo.png', content: Buffer.from('PNG'), contentType: 'image/png', contentId: 'logo' };
    // before the fix this built a bare text/plain message: the part vanished
    assert.throws(
      () => buildMime({ ...base, text: 'see the logo', attachments: [logo] }),
      (e: unknown) => MailError.hasCode(e, 'inline_needs_html') && e.failure.contentId === 'logo',
    );
    // a plain attachment on a text-only message is fine
    const plain = Buffer.from(
      buildMime({
        ...base,
        text: 't',
        attachments: [{ filename: 'a.pdf', content: 'JVBERg==', contentType: 'application/pdf' }],
      }),
    ).toString();
    assert.match(plain, /^Content-Type: multipart\/mixed/m);
    // with html the inline part is carried in multipart/related, as before
    const related = Buffer.from(
      buildMime({ ...base, text: 't', html: '<img src="cid:logo">', attachments: [logo] }),
    ).toString();
    assert.match(related, /multipart\/related/);
    assert.match(related, /Content-ID: <logo>/);
    // metadata problems still win, so the caller sees the more specific error first
    assert.throws(
      () => buildMime({ ...base, text: 't', attachments: [{ ...logo, contentId: 'has space' }] }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input'),
    );
  });

  it('refuses attachment metadata that would break or bend a header', () => {
    const png = { content: Buffer.from('PNG'), contentType: 'image/png' };
    const bad = (a: Record<string, unknown>, code: string) =>
      assert.throws(
        () => buildMime({ ...base, text: 'x', attachments: [{ filename: 'a.png', ...png, ...a } as never] }),
        (e: unknown) => MailError.is(e) && e.code === code,
        JSON.stringify(a),
      );
    // an injection attempt: a second header smuggled through the filename
    bad({ filename: 'a.png"\r\nContent-Type: text/html\r\n\r\n<script>' }, 'header_injection');
    bad({ filename: 'a\u0000.png' }, 'header_injection');
    bad({ contentType: 'image/png\r\nX-Injected: 1' }, 'header_injection');
    bad({ contentId: 'logo\r\nBcc: x@y' }, 'header_injection');
    bad({ contentType: 'not a type' }, 'invalid_input');
    bad({ contentType: 'image/png; charset' }, 'invalid_input');
    bad({ contentType: 'image/' }, 'invalid_input');
    bad({ contentId: '<logo>' }, 'invalid_input');
    bad({ contentId: 'has space' }, 'invalid_input');
    bad({ filename: '' }, 'invalid_input');
    // parameters with a token or quoted-string value are fine
    const ok = Buffer.from(
      buildMime({
        ...base,
        text: 'x',
        attachments: [{ filename: 'a.txt', content: Buffer.from('a'), contentType: 'text/plain; charset="utf-8"' }],
      }),
    ).toString();
    assert.match(ok, /Content-Type: text\/plain; charset="utf-8"; name="a.txt"\r\n/);
  });

  it('encodes non-ASCII and quote-bearing filenames instead of writing them raw', () => {
    const m = Buffer.from(
      buildMime({
        ...base,
        text: 'x',
        attachments: [
          { filename: 'Rechnung Zoë (2026)*.pdf', content: Buffer.from('%PDF') },
          { filename: 'say "hi".txt', content: Buffer.from('hi'), contentType: 'text/plain' },
        ],
      }),
    ).toString();
    assert.ok(
      Buffer.from(m, 'utf8').every((b) => b < 0x80),
      'no raw non-ASCII anywhere in the message',
    );
    // RFC 2231 in Content-Disposition, no name= at all
    assert.match(m, /Content-Type: application\/octet-stream\r\nContent-Transfer-Encoding: base64\r\n/);
    assert.match(m, /Content-Disposition: attachment; filename\*=UTF-8''Rechnung%20Zo%C3%AB%20%282026%29%2A.pdf\r\n/);
    // ASCII with quotes: quoted and escaped in both places
    assert.match(m, /Content-Type: text\/plain; name="say \\"hi\\".txt"\r\n/);
    assert.match(m, /Content-Disposition: attachment; filename="say \\"hi\\".txt"\r\n/);
  });

  it('formats the date per RFC 5322', () => {
    assert.equal(rfc5322Date(new Date('2026-08-16T12:00:05Z')), 'Sun, 16 Aug 2026 12:00:05 +0000');
  });
});
