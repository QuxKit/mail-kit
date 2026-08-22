// Re-issuing a domain's DNS checklist when the transport changes (issue #19).
//
// The migration this exists for: a host on one relay moves to another whose
// SPF `include:` differs. Before this, the stored SPF record still demanded
// the old provider forever, and the only way to change it — remove and re-add
// — minted a new DKIM selector, invalidating the record the host had already
// published and every signature still in flight behind cached DNS.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createMail } from '../src/instance.ts';
import { memoryTransport } from '../src/transports/memory.ts';
import { FakeDns, FakeFetch, setupDatabase, testDkimKey } from './harness.ts';

const T1 = 'tenant_reissue';

const h = await setupDatabase();

describe('reissueRecords', { skip: h === null ? 'no database' : false }, () => {
  const db = (h as NonNullable<typeof h>).db;
  const dns = new FakeDns();
  const clock = () => new Date('2026-08-22T00:00:00Z');
  const config = { dkimKey: testDkimKey, dmarcReportAddress: 'dmarc@ops.test' };
  const build = (spfInclude: string) =>
    createMail({
      db,
      transport: memoryTransport({ spfInclude }),
      dns,
      fetch: new FakeFetch().fetch,
      clock,
      config,
    });

  it('changes the SPF include and keeps the DKIM key, without touching the selector', async () => {
    const before = build('amazonses.com');
    const added = await before.domains.add(T1, { name: 'migrate.test' });
    const dkimBefore = added.records.find((r) => r.purpose === 'dkim')!;

    // Publish everything and get to verified, so the reset below is observable.
    dns.publish(added.records.filter((r) => r.required));
    const verified = await before.domains.verify(T1, added.id);
    assert.equal(verified.status, 'verified');

    // Same domain, new relay.
    const after = build('_spf.mx.cloudflare.net');
    const reissued = await after.domains.reissueRecords(T1, added.id);

    const spf = reissued.records.find((r) => r.purpose === 'spf')!;
    assert.equal(spf.value, 'v=spf1 include:_spf.mx.cloudflare.net ~all', 'the new relay is what SPF authorises');

    const dkimAfter = reissued.records.find((r) => r.purpose === 'dkim')!;
    assert.equal(reissued.dkimSelector, added.dkimSelector, 'the selector is the one already published');
    assert.equal(dkimAfter.value, dkimBefore.value, 'the key is unchanged, so the published record still holds');

    // The old answer is not evidence about the new question.
    assert.equal(reissued.status, 'pending');
    assert.equal(reissued.verifiedAt, null);
    assert.equal(reissued.lastCheck, null);
  });

  it('can still sign with the key it kept', async () => {
    const after = build('_spf.mx.cloudflare.net');
    const domain = await after.domains.find(T1, 'migrate.test');
    const signer = await after.domains.signerFor(domain!);
    assert.ok(signer, 'the sealed private key survived the re-issue');
    assert.equal(signer.selector, domain!.dkimSelector);
    assert.match(signer.privateKeyPem, /BEGIN PRIVATE KEY/);
  });

  it('is a no-op when nothing changed, so it is safe to call on every boot', async () => {
    const same = build('_spf.mx.cloudflare.net');
    const domain = await same.domains.find(T1, 'migrate.test');
    dns.publish(domain!.records.filter((r) => r.required));
    const verified = await same.domains.verify(T1, domain!.id);
    assert.equal(verified.status, 'verified');

    const again = await same.domains.reissueRecords(T1, domain!.id);
    assert.equal(again.status, 'verified', 'an unchanged checklist must not knock a live domain back to pending');
    assert.ok(again.verifiedAt);
  });

  it('re-issues without the DKIM key, since it is only needed to mint one', async () => {
    // The publishing tool holds the database and does not sign. Requiring the
    // sealing key to re-derive a checklist around a key already on file locked
    // that caller out for no reason.
    const noKey = createMail({
      db,
      transport: memoryTransport({ spfInclude: 'later.example' }),
      dns,
      fetch: new FakeFetch().fetch,
      clock,
      config: { dmarcReportAddress: 'dmarc@ops.test' },
    });
    const domain = await noKey.domains.find(T1, 'migrate.test');
    const again = await noKey.domains.reissueRecords(T1, domain!.id);
    assert.equal(again.records.find((r) => r.purpose === 'spf')?.value, 'v=spf1 include:later.example ~all');
    assert.equal(again.dkimSelector, domain!.dkimSelector, 'the existing key is untouched');
  });

  it('still refuses to ADD a locally signed domain with no key', async () => {
    const noKey = createMail({
      db,
      transport: memoryTransport({ spfInclude: 'x.example' }),
      dns,
      fetch: new FakeFetch().fetch,
      clock,
      config: {},
    });
    await assert.rejects(noKey.domains.add(T1, { name: 'nokey.test' }));
  });

  it('refuses a domain that is not this tenant’s', async () => {
    const m = build('_spf.mx.cloudflare.net');
    const domain = await m.domains.find(T1, 'migrate.test');
    await assert.rejects(m.domains.reissueRecords('tenant_other', domain!.id));
  });
});
