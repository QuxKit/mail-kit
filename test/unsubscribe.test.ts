// Unsubscribe tokens (offline) and the one-click handler + list-scoped
// suppression through send (store-backed).

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { createMail, type Mail } from '../src/instance.ts';
import { createSuppression, type SuppressionApi } from '../src/suppression.ts';
import { type MemoryTransport, memoryTransport } from '../src/transports/memory.ts';
import { createUnsubscribe } from '../src/unsubscribe.ts';
import { FakeDns, FakeFetch, type Harness, SKIP_REASON, setupDatabase, testDkimKey } from './harness.ts';

const otherKey = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

describe('mail-kit/unsubscribe: tokens', () => {
  const noDb: SuppressionApi = {
    add: async () => {
      throw new Error('not here');
    },
    remove: async () => false,
    list: async () => [],
    check: async () => new Set(),
  };
  const u = createUnsubscribe({
    suppression: noDb,
    config: { dkimKey: testDkimKey, unsubscribeUrl: 'https://app.example/u/{token}' },
  });

  it('mints a URL-safe token that verifies back to its claims, with the recipient normalised', () => {
    const t = u.token({ tenantId: 't1', recipient: '  Ada@Example.ORG ' });
    assert.match(t, /^u1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(u.verify(t), { tenantId: 't1', recipient: 'ada@example.org', listId: null });
    const withList = u.token({ tenantId: 't1', recipient: 'ada@example.org', listId: 'news' });
    assert.notEqual(withList, t);
    assert.deepEqual(u.verify(withList), { tenantId: 't1', recipient: 'ada@example.org', listId: 'news' });
    assert.equal(u.token({ tenantId: 't1', recipient: 'ada@example.org' }), t, 'deterministic: no row, no nonce');
    assert.equal(u.url({ tenantId: 't1', recipient: 'ada@example.org' }), `https://app.example/u/${t}`);
    const appended = createUnsubscribe({
      suppression: noDb,
      config: { dkimKey: testDkimKey, unsubscribeUrl: 'https://app.example/unsub?src=mail' },
    });
    assert.equal(
      appended.url({ tenantId: 't1', recipient: 'ada@example.org' }),
      `https://app.example/unsub?src=mail&token=${t}`,
    );
    assert.equal(
      createUnsubscribe({ suppression: noDb, config: { dkimKey: testDkimKey } }).url({
        tenantId: 't1',
        recipient: 'a@b.c',
      }),
      null,
    );
  });

  it('refuses a tampered token, a foreign key, and malformed shapes', () => {
    const t = u.token({ tenantId: 't1', recipient: 'ada@example.org', listId: 'news' });
    const [v, p, s] = t.split('.') as [string, string, string];
    const invalid = (token: string, why: string) =>
      assert.throws(
        () => u.verify(token),
        (e: unknown) => MailError.hasCode(e, 'signature_invalid'),
        why,
      );
    // claims changed: another recipient under the same signature
    const other = Buffer.from('t1\nmallory@example.org\nnews').toString('base64url');
    invalid(`${v}.${other}.${s}`, 'payload swapped');
    // signature flipped
    const flipped = s.slice(0, -1) + (s.endsWith('A') ? 'B' : 'A');
    invalid(`${v}.${p}.${flipped}`, 'signature altered');
    invalid(`${v}.${p}.${s}=`, 'trailing padding');
    invalid(`${v}.${p}.${s}.x`, 'extra segment');
    invalid(`u0.${p}.${s}`, 'wrong version');
    invalid('', 'empty');
    invalid('u1..', 'empty parts');
    invalid(`${v}.${p.slice(1)}.${s}`, 'truncated payload');
    // a payload with a fourth field, signed correctly, is still malformed
    const foreign = createUnsubscribe({ suppression: noDb, config: { dkimKey: otherKey } });
    invalid(foreign.token({ tenantId: 't1', recipient: 'ada@example.org', listId: 'news' }), 'another key');
    assert.throws(
      () => u.token({ tenantId: '', recipient: 'x@y.z' }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input'),
    );
    assert.throws(
      () => u.token({ tenantId: 't\n1', recipient: 'x@y.z' }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input'),
    );
  });

  it('needs the mail key', () => {
    const noKey = createUnsubscribe({ suppression: noDb, config: {} });
    assert.throws(
      () => noKey.token({ tenantId: 't1', recipient: 'a@b.c' }),
      (e: unknown) => MailError.hasCode(e, 'mail_key_required') && /config.dkimKey/.test(e.message),
    );
    assert.throws(
      () => noKey.verify('u1.YQ.YQ'),
      (e: unknown) => MailError.hasCode(e, 'mail_key_required'),
    );
  });
});

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('mail-kit/unsubscribe: one-click and send', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const T1 = 'tenant_unsub';
  const dns = new FakeDns();
  const fetch = new FakeFetch();
  let transport: MemoryTransport;
  let mail: Mail;
  before(async () => {
    transport = memoryTransport({ manageDomains: true });
    mail = createMail({
      db: h.db,
      transport,
      dns,
      fetch: fetch.fetch,
      config: { dkimKey: testDkimKey, unsubscribeUrl: 'https://app.example/u/{token}' },
    });
    const d = await mail.domains.add(T1, { name: 'unsub.example' });
    dns.publish(d.records);
    await mail.domains.verify(T1, d.id);
  });

  it('send() sets List-Unsubscribe + List-Unsubscribe-Post itself for a single-recipient message', async () => {
    transport.clear();
    const m = await mail.send(T1, { from: 'a@unsub.example', to: 'Bob@example.org', subject: 's', text: 't' });
    assert.equal(m.status, 'sent');
    const text = transport.sent[0]!.text;
    const line = /^List-Unsubscribe: <(https:\/\/app\.example\/u\/[^>]+)>\r\n/m.exec(text);
    assert.ok(line, 'header present');
    assert.match(text, /^List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n/m);
    const token = line![1]!.slice('https://app.example/u/'.length);
    assert.deepEqual(mail.unsubscribe.verify(token), { tenantId: T1, recipient: 'bob@example.org', listId: null });
    assert.equal((await mail.payload(T1, m.id))!.listUnsubscribe!.url, line![1]);
    // a list-scoped send carries the list in the token
    const n = await mail.send(T1, {
      from: 'a@unsub.example',
      to: 'bob@example.org',
      subject: 'news',
      text: 't',
      listId: 'news',
    });
    const t2 = /^List-Unsubscribe: <https:\/\/app\.example\/u\/([^>]+)>/m.exec(transport.sent[1]!.text)![1]!;
    assert.equal(mail.unsubscribe.verify(t2).listId, 'news');
    assert.equal((await mail.payload(T1, n.id))!.listId, 'news');
  });

  it('does not add the header to a multi-recipient message, nor override a caller-supplied one', async () => {
    transport.clear();
    await mail.send(T1, {
      from: 'a@unsub.example',
      to: ['bob@example.org', 'carol@example.org'],
      subject: 's',
      text: 't',
    });
    assert.doesNotMatch(transport.sent[0]!.text, /List-Unsubscribe/);
    await mail.send(T1, {
      from: 'a@unsub.example',
      to: 'bob@example.org',
      subject: 's',
      text: 't',
      listUnsubscribe: { mailto: 'unsub@unsub.example' },
    });
    assert.match(transport.sent[1]!.text, /^List-Unsubscribe: <mailto:unsub@unsub.example>\r\n/m);
    assert.doesNotMatch(transport.sent[1]!.text, /List-Unsubscribe-Post/);
    // and nothing at all when the URL is not configured
    const plain = createMail({ db: h.db, transport, dns, fetch: fetch.fetch, config: { dkimKey: testDkimKey } });
    await plain.send(T1, { from: 'a@unsub.example', to: 'bob@example.org', subject: 's', text: 't' });
    assert.doesNotMatch(transport.sent[2]!.text, /List-Unsubscribe/);
    // configured URL without a key: the typed error, before any row
    const before = (await mail.list(T1)).length;
    const keyless = createMail({
      db: h.db,
      transport,
      dns,
      fetch: fetch.fetch,
      config: { unsubscribeUrl: 'https://x/u/{token}' },
    });
    await assert.rejects(
      keyless.send(T1, { from: 'a@unsub.example', to: 'bob@example.org', subject: 's', text: 't' }),
      (e: unknown) => MailError.hasCode(e, 'mail_key_required'),
    );
    assert.equal((await mail.list(T1)).length, before);
  });

  it('handleOneClick: an RFC 8058 POST adds an unsubscribe suppression, scoped to the token', async () => {
    const token = mail.unsubscribe.token({ tenantId: T1, recipient: 'Dave@example.org', listId: 'news' });
    const req = {
      method: 'POST',
      url: `https://app.example/u/${token}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'List-Unsubscribe=One-Click',
    };
    const res = await mail.unsubscribe.handleOneClick(req);
    assert.equal(res.status, 200);
    assert.deepEqual(res.claims, { tenantId: T1, recipient: 'dave@example.org', listId: 'news' });
    assert.equal(res.suppression!.reason, 'unsubscribe');
    assert.equal(res.suppression!.listId, 'news');
    assert.equal(res.suppression!.tenantId, T1);
    // idempotent
    const again = await mail.unsubscribe.handleOneClick(req);
    assert.equal(again.status, 200);
    assert.equal(again.suppression!.id, res.suppression!.id);
    // the list-scoped entry stops list sends and not the tenant's other mail
    transport.clear();
    const news = await mail.send(T1, {
      from: 'a@unsub.example',
      to: 'dave@example.org',
      subject: 'n',
      text: 't',
      listId: 'news',
    });
    assert.equal(news.status, 'suppressed');
    const other = await mail.send(T1, {
      from: 'a@unsub.example',
      to: 'dave@example.org',
      subject: 'receipt',
      text: 't',
      listId: 'receipts',
    });
    assert.equal(other.status, 'sent');
    const txn = await mail.send(T1, { from: 'a@unsub.example', to: 'dave@example.org', subject: 'txn', text: 't' });
    assert.equal(txn.status, 'sent');
    assert.deepEqual(
      [...(await mail.suppression.check(T1, ['dave@example.org'], { listId: 'news' }))],
      ['dave@example.org'],
    );
    assert.equal((await mail.suppression.check(T1, ['dave@example.org'])).size, 0);
    assert.equal((await mail.suppression.list(T1, { listId: 'news' })).length, 1);
    assert.equal((await mail.suppression.list(T1, { listId: 'receipts' })).length, 0);

    // a tenant-wide token stops everything for the tenant, and only the tenant
    const all = mail.unsubscribe.token({ tenantId: T1, recipient: 'dave@example.org' });
    const wide = await mail.unsubscribe.handleOneClick({ ...req, url: `/u?token=${encodeURIComponent(all)}` });
    assert.equal(wide.status, 200);
    assert.equal(wide.suppression!.listId, null);
    const blocked = await mail.send(T1, { from: 'a@unsub.example', to: 'dave@example.org', subject: 'txn', text: 't' });
    assert.equal(blocked.status, 'suppressed');
    assert.equal((await mail.suppression.check('tenant_other', ['dave@example.org'])).size, 0);

    // remove(): with a list, only that entry; without, everything for the address
    assert.equal(await mail.suppression.remove(T1, 'dave@example.org', { listId: 'news' }), true);
    assert.equal((await mail.suppression.list(T1, { listId: 'news' })).length, 0);
    assert.equal((await mail.suppression.check(T1, ['dave@example.org'])).size, 1, 'the tenant-wide entry stays');
    assert.equal(await mail.suppression.remove(T1, 'dave@example.org'), true);
    assert.equal((await mail.suppression.check(T1, ['dave@example.org'], { listId: 'news' })).size, 0);
  });

  it('handleOneClick refuses the wrong method, a non-one-click body, and a tampered or missing token', async () => {
    const token = mail.unsubscribe.token({ tenantId: T1, recipient: 'erin@example.org' });
    const good = {
      method: 'POST',
      url: `https://app.example/u/${token}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: 'List-Unsubscribe=One-Click',
    };
    assert.equal((await mail.unsubscribe.handleOneClick({ ...good, method: 'GET' })).status, 405);
    assert.equal((await mail.unsubscribe.handleOneClick({ ...good, body: '' })).status, 400);
    assert.equal((await mail.unsubscribe.handleOneClick({ ...good, body: 'List-Unsubscribe=Later' })).status, 400);
    assert.equal(
      (await mail.unsubscribe.handleOneClick({ ...good, headers: { 'content-type': 'application/json' }, body: '{}' }))
        .status,
      400,
    );
    assert.equal((await mail.unsubscribe.handleOneClick({ ...good, body: '%E0%A4%A=x' })).status, 400, 'bad escape');
    const tampered = `${token.slice(0, -2)}${token.endsWith('AA') ? 'BB' : 'AA'}`;
    const t = await mail.unsubscribe.handleOneClick({ ...good, url: `https://app.example/u/${tampered}` });
    assert.equal(t.status, 400);
    assert.equal(t.body, 'invalid token');
    assert.equal((await mail.unsubscribe.handleOneClick({ ...good, url: 'https://app.example/' })).status, 400);
    assert.equal((await mail.unsubscribe.handleOneClick({ ...good, url: 'http://[bad' })).status, 400);
    assert.equal((await mail.suppression.check(T1, ['erin@example.org'])).size, 0, 'nothing written');
    // Fetch-style Headers, multipart body, token handed in explicitly, string[] header values
    const headers = new Headers({ 'content-type': 'multipart/form-data; boundary=xyz' });
    const multipart = `--xyz\r\nContent-Disposition: form-data; name="List-Unsubscribe"\r\n\r\nOne-Click\r\n--xyz--\r\n`;
    const ok = await mail.unsubscribe.handleOneClick(
      { method: 'post', url: '/ignored', headers, body: multipart },
      { token },
    );
    assert.equal(ok.status, 200);
    assert.equal(ok.suppression!.address, 'erin@example.org');
    const arr = await mail.unsubscribe.handleOneClick({
      ...good,
      headers: { 'Content-Type': ['application/x-www-form-urlencoded'] },
    });
    assert.equal(arr.status, 200);
    assert.equal((await mail.unsubscribe.handleOneClick({ ...good, headers: undefined })).status, 400);
    await mail.suppression.remove(T1, 'erin@example.org');
  });

  it('createSuppression: the global list, list-scoped, still de-duplicates per scope', async () => {
    const s = createSuppression({ db: h.db });
    const a = await s.add(null, { address: 'g@example.org', reason: 'manual', listId: 'promo' });
    const b = await s.add(null, { address: 'g@example.org', reason: 'complaint', listId: 'promo' });
    assert.equal(a.id, b.id);
    assert.equal(b.reason, 'manual', 'first reason kept');
    const c = await s.add(null, { address: 'g@example.org', reason: 'complaint' });
    assert.notEqual(c.id, a.id, 'a different scope is a different row');
    assert.equal(await s.remove(null, 'g@example.org'), true);
    assert.equal((await s.list(null, { listId: 'promo' })).length, 0);
  });
});
