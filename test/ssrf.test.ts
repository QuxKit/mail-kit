// The webhook URL guard: every forbidden address class, https-by-default,
// literal hosts, and resolution through an injected resolver.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { assertWebhookUrlAllowed, forbiddenAddressReason } from '../src/ssrf.ts';

describe('mail-kit/ssrf: address classes', () => {
  const forbidden: Array<[string, RegExp]> = [
    ['127.0.0.1', /loopback/],
    ['127.255.255.254', /loopback/],
    ['10.0.0.5', /private/],
    ['172.16.0.1', /private/],
    ['172.31.255.255', /private/],
    ['192.168.1.1', /private/],
    ['169.254.169.254', /link-local/],
    ['169.254.0.1', /link-local/],
    ['0.0.0.0', /this-network/],
    ['0.1.2.3', /this-network/],
    ['100.64.0.1', /shared/],
    ['224.0.0.1', /multicast/],
    ['239.255.255.250', /multicast/],
    ['255.255.255.255', /reserved/],
    ['::1', /loopback/],
    ['::', /unspecified/],
    ['fc00::1', /unique-local/],
    ['fd12:3456:789a::1', /unique-local/],
    ['fe80::1', /link-local/],
    ['febf::1', /link-local/],
    ['fec0::1', /site-local/],
    ['ff02::1', /multicast/],
    ['::ffff:127.0.0.1', /loopback/],
    ['::ffff:10.0.0.1', /private/],
    ['::ffff:169.254.169.254', /link-local/],
    ['::ffff:a9fe:a9fe', /link-local/],
    ['64:ff9b::7f00:1', /loopback/],
    ['64:ff9b::192.168.0.1', /private/],
  ];
  for (const [address, why] of forbidden) {
    it(`refuses ${address}`, () => {
      const reason = forbiddenAddressReason(address);
      assert.ok(reason, `${address} should be forbidden`);
      assert.match(reason, why);
    });
  }

  it('allows public addresses', () => {
    for (const ok of [
      '93.184.216.34',
      '203.0.113.10',
      '8.8.8.8',
      '172.32.0.1',
      '172.15.255.255',
      '100.63.255.255',
      '100.128.0.1',
      '2606:4700::6810:84e5',
      '2001:db8::1',
      '::ffff:93.184.216.34',
      '64:ff9b::5db8:d822',
    ]) {
      assert.equal(forbiddenAddressReason(ok), null, ok);
    }
  });

  it('calls a non-address what it is', () => {
    assert.match(forbiddenAddressReason('nope') ?? '', /not an IP/);
    assert.match(forbiddenAddressReason('1.2.3') ?? '', /not an IP/);
    assert.match(forbiddenAddressReason('300.1.1.1') ?? '', /not an IP/);
  });
});

describe('mail-kit/ssrf: assertWebhookUrlAllowed', () => {
  const table = new Map<string, string[]>([
    ['hooks.example', ['203.0.113.10']],
    ['dual.example', ['203.0.113.10', '2001:db8::10']],
    ['metadata.example', ['169.254.169.254']],
    ['mixed.example', ['203.0.113.10', '10.0.0.1']],
    ['v6local.example', ['fd00::1']],
    ['nowhere.example', []],
  ]);
  const resolve = async (h: string) => table.get(h) ?? [];
  const forbidden = (url: string, why: RegExp, allowInsecureHttp = false) =>
    assert.rejects(
      assertWebhookUrlAllowed(new URL(url), { resolve, allowInsecureHttp }),
      (e: unknown) =>
        MailError.hasCode(e, 'webhook_url_forbidden') &&
        why.test(e.failure.reason) &&
        e.failure.url === new URL(url).toString(),
      url,
    );

  it('allows https to a public host, and returns the checked addresses', async () => {
    assert.deepEqual(await assertWebhookUrlAllowed(new URL('https://hooks.example/x'), { resolve }), ['203.0.113.10']);
    assert.deepEqual(await assertWebhookUrlAllowed(new URL('https://dual.example/x'), { resolve }), [
      '203.0.113.10',
      '2001:db8::10',
    ]);
    assert.deepEqual(await assertWebhookUrlAllowed(new URL('https://93.184.216.34/x'), { resolve }), ['93.184.216.34']);
    assert.deepEqual(await assertWebhookUrlAllowed(new URL('https://[2001:db8::1]/x'), { resolve }), ['2001:db8::1']);
  });

  it('requires https unless allowInsecureHttp, and never allows other schemes', async () => {
    await forbidden('http://hooks.example/x', /http: is not allowed/);
    assert.deepEqual(
      await assertWebhookUrlAllowed(new URL('http://hooks.example/x'), { resolve, allowInsecureHttp: true }),
      ['203.0.113.10'],
    );
    await forbidden('ftp://hooks.example/x', /not http/, true);
    await forbidden('file:///etc/passwd', /not http/, true);
  });

  it('refuses literal internal hosts without resolving', async () => {
    let resolved = false;
    const spy = async () => {
      resolved = true;
      return ['203.0.113.10'];
    };
    for (const url of [
      'https://127.0.0.1/',
      'https://[::1]/',
      'https://169.254.169.254/latest/meta-data/',
      'https://10.1.2.3:5432/',
      'https://localhost/',
      'https://api.localhost/',
      'https://[::ffff:127.0.0.1]/',
      'https://0.0.0.0/',
    ]) {
      await assert.rejects(
        assertWebhookUrlAllowed(new URL(url), { resolve: spy }),
        (e: unknown) => MailError.hasCode(e, 'webhook_url_forbidden'),
        url,
      );
    }
    assert.equal(resolved, false);
  });

  it('refuses a name that resolves to any internal address, and one that does not resolve', async () => {
    await forbidden('https://metadata.example/', /169\.254\.169\.254.*link-local/);
    await forbidden('https://mixed.example/', /10\.0\.0\.1.*private/);
    await forbidden('https://v6local.example/', /unique-local/);
    await forbidden('https://nowhere.example/', /did not resolve/);
  });

  it('refuses credentials in the URL', async () => {
    await forbidden('https://user:pw@hooks.example/', /credentials/);
  });
});
