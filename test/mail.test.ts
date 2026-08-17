// The store-backed surface against a real Postgres, through the memory
// transport: domains on both signing paths, the send path end to end (DKIM
// signed, suppression-filtered, idempotent, scheduled, retried), delivery
// events driving status + suppression + webhooks, and webhook delivery.

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { dkimVerify } from '../src/dkim.ts';
import { MailError } from '../src/errors.ts';
import { createMail, type Mail } from '../src/instance.ts';
import { clampLimit, MAX_BATCH, MAX_LIST_LIMIT } from '../src/limits.ts';
import { type MemoryTransport, memoryTransport } from '../src/transports/memory.ts';
import { parseSesEvents } from '../src/transports/ses.ts';
import type { SqlExecutor } from '../src/types.ts';
import { verifyWebhookSignature } from '../src/webhooks.ts';
import { FakeDns, FakeFetch, type Harness, SKIP_REASON, setupDatabase, testDkimKey } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('mail-kit', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  let now = new Date('2026-08-16T12:00:00Z');
  const clock = () => now;
  const T1 = 'tenant_a';
  const T2 = 'tenant_b';

  describe('the shipped pg adapter', () => {
    it('pins a connection per transaction and turns nested transactions into savepoints', async () => {
      await h.db.query('CREATE TABLE IF NOT EXISTS mail.pg_probe (v text)');
      await h.db.query('DELETE FROM mail.pg_probe');
      await assert.rejects(
        h.db.transaction(async (tx) => {
          await tx.query("INSERT INTO mail.pg_probe VALUES ('outer')");
          await tx
            .transaction(async (inner) => {
              await inner.query("INSERT INTO mail.pg_probe VALUES ('inner')");
              throw new Error('inner boom');
            })
            .catch(() => {});
          const [row] = await tx.query<{ n: string }>('SELECT count(*)::text AS n FROM mail.pg_probe');
          assert.equal(row!.n, '1', 'the inner insert was rolled back to the savepoint, the outer survives');
          await tx.query("INSERT INTO mail.pg_probe VALUES ('after')");
          throw new Error('outer boom');
        }),
        /outer boom/,
      );
      const [after] = await h.db.query<{ n: string }>('SELECT count(*)::text AS n FROM mail.pg_probe');
      assert.equal(after!.n, '0', 'the outer rollback covers everything');
      const kept = await h.db.transaction(async (tx) => {
        await tx.query("INSERT INTO mail.pg_probe VALUES ('kept')");
        return tx.transaction(async (inner) => {
          await inner.query("INSERT INTO mail.pg_probe VALUES ('kept-inner')");
          return 'ok';
        });
      });
      assert.equal(kept, 'ok');
      const [done] = await h.db.query<{ n: string }>('SELECT count(*)::text AS n FROM mail.pg_probe');
      assert.equal(done!.n, '2');
      await h.db.query('DROP TABLE mail.pg_probe');
    });
  });

  describe('domains, locally signed (relay-style transport)', () => {
    const dns = new FakeDns();
    const fetch = new FakeFetch();
    const transport = memoryTransport({ spfInclude: 'relay.test' });
    const mail = createMail({
      db: h.db,
      transport,
      dns,
      fetch: fetch.fetch,
      clock,
      config: { dkimKey: testDkimKey, dmarcReportAddress: 'dmarc@ops.test' },
    });

    it('adds a domain with a DKIM key it holds, an SPF record for the return path, and a recommended DMARC', async () => {
      const d = await mail.domains.add(T1, { name: 'Example.COM' });
      assert.equal(d.name, 'example.com');
      assert.equal(d.status, 'pending');
      assert.equal(d.signing, 'local');
      assert.equal(d.returnPathHost, 'bounce.example.com');
      assert.match(d.dkimSelector!, /^qk[0-9a-f]{8}$/);
      const byPurpose = Object.fromEntries(d.records.map((r) => [r.purpose, r]));
      assert.equal(byPurpose.dkim!.name, `${d.dkimSelector}._domainkey.example.com`);
      assert.match(byPurpose.dkim!.value, /^v=DKIM1; k=rsa; p=MII/);
      assert.equal(byPurpose.spf!.name, 'bounce.example.com');
      assert.equal(byPurpose.spf!.value, 'v=spf1 include:relay.test ~all');
      assert.equal(byPurpose.dmarc!.value, 'v=DMARC1; p=none; rua=mailto:dmarc@ops.test;');
      assert.equal(byPurpose.dmarc!.required, false);
      // the sealed private key is not on the public shape
      assert.equal((d as unknown as Record<string, unknown>).dkim_private_key, undefined);
    });

    it('is pending until DNS carries the required records; DMARC is reported but not required', async () => {
      const [d] = await mail.domains.list(T1);
      await mail.webhooks.create(T1, { url: 'https://hooks.example/a', events: ['domain.verified', 'domain.failed'] });

      let v = await mail.domains.verify(T1, d!.id);
      assert.equal(v.status, 'pending');
      assert.ok(v.lastCheck!.every((c) => !c.ok));

      // publish the required ones only
      dns.publish(d!.records.filter((r) => r.required));
      v = await mail.domains.verify(T1, d!.id);
      assert.equal(v.status, 'verified');
      assert.ok(v.verifiedAt);
      assert.equal(v.lastCheck!.find((c) => c.record.purpose === 'dmarc')!.ok, false, 'dmarc reported missing');
      const deliveries = await mail.webhooks.listDeliveries(T1);
      assert.equal(deliveries.length, 1);
      assert.equal(deliveries[0]!.eventType, 'domain.verified');

      // records pulled → verified domain becomes failed, once
      dns.txt.clear();
      v = await mail.domains.verify(T1, d!.id);
      assert.equal(v.status, 'failed');
      assert.equal((await mail.webhooks.listDeliveries(T1)).filter((x) => x.eventType === 'domain.failed').length, 1);
      dns.publish(d!.records);
      v = await mail.domains.verify(T1, d!.id);
      assert.equal(v.status, 'verified');
    });

    it('refuses a domain another tenant holds, a non-domain, and (without dkimKey) a local-signing add', async () => {
      await assert.rejects(
        mail.domains.add(T2, { name: 'example.com' }),
        (e: unknown) => MailError.hasCode(e, 'invalid_input') && /another tenant/.test(e.message),
      );
      await assert.rejects(mail.domains.add(T2, { name: 'not a domain' }), (e: unknown) =>
        MailError.hasCode(e, 'invalid_input'),
      );
      const noKey = createMail({ db: h.db, transport, dns, fetch: fetch.fetch, clock });
      await assert.rejects(noKey.domains.add(T2, { name: 'nokey.example' }), (e: unknown) =>
        MailError.hasCode(e, 'dkim_key_required'),
      );
      assert.equal(
        await mail.domains.get(T2, (await mail.domains.list(T1))[0]!.id),
        null,
        'not visible across tenants',
      );
    });

    it('signs sends with the domain key so the message verifies with the published record', async () => {
      const [d] = await mail.domains.list(T1);
      const m = await mail.send(T1, {
        from: { email: 'ada@example.com', name: 'Ada' },
        to: 'bob@example.org',
        subject: 'Hi',
        text: 'hello',
      });
      assert.equal(m.status, 'sent');
      assert.equal(m.providerMessageId, 'mem-1');
      const sent = transport.sent[0]!;
      assert.equal(sent.envelope.returnPath, 'bounces@bounce.example.com');
      assert.deepEqual(sent.envelope.recipients, ['bob@example.org']);
      const dkim = d!.records.find((r) => r.purpose === 'dkim')!;
      const p = /p=(.*)$/.exec(dkim.value)![1]!;
      const result = await dkimVerify(sent.envelope.raw, async (s, dom) =>
        dom === 'example.com' && s === d!.dkimSelector ? p : null,
      );
      assert.deepEqual(result, { ok: true, domain: 'example.com', selector: d!.dkimSelector });
      // render() rebuilds the same bytes
      const rendered = Buffer.from(await mail.render(T1, m.id)).toString();
      assert.equal(rendered, sent.text);
    });

    it('render() returns exactly the bytes that were sent — boundaries and DKIM signature included', async () => {
      transport.clear();
      const m = await mail.send(T1, {
        from: 'ada@example.com',
        to: 'bob@example.org',
        subject: 'multipart',
        text: 'plain',
        html: '<p>rich <img src="cid:logo"></p>',
        attachments: [
          { filename: 'logo.png', content: Buffer.from('PNG'), contentType: 'image/png', contentId: 'logo' },
          { filename: 'invoice.pdf', content: Buffer.from('%PDF'), contentType: 'application/pdf' },
        ],
      });
      assert.equal(m.status, 'sent');
      const sentRaw = Buffer.from(transport.sent[0]!.envelope.raw);
      assert.equal((sentRaw.toString().match(/boundary="/g) ?? []).length, 3, 'mixed > alternative > related');
      assert.match(sentRaw.toString(), /^DKIM-Signature: /);
      const rendered = Buffer.from(await mail.render(T1, m.id));
      assert.ok(rendered.equals(sentRaw), 'byte-identical to what the transport was handed');
      // still identical after the clock moves and (if it were rotated) the key would differ
      now = new Date(now.getTime() + 60_000);
      assert.ok(Buffer.from(await mail.render(T1, m.id)).equals(sentRaw));
      now = new Date(now.getTime() - 60_000);
      // an unsent (scheduled) message renders a fresh build
      const later = await mail.send(T1, {
        from: 'ada@example.com',
        to: 'bob@example.org',
        subject: 'later',
        text: 'a',
        html: '<b>a</b>',
        scheduledAt: new Date(now.getTime() + 3_600_000),
      });
      assert.equal(later.status, 'scheduled');
      assert.match(Buffer.from(await mail.render(T1, later.id)).toString(), /multipart\/alternative/);
      await mail.cancel(T1, later.id);
    });

    it('removes a domain', async () => {
      const [d] = await mail.domains.list(T1);
      assert.equal(await mail.domains.remove(T1, d!.id), true);
      assert.equal(await mail.domains.remove(T1, d!.id), false);
    });
  });

  describe('domains, transport-managed (SES-style)', () => {
    const dns = new FakeDns();
    const transport = memoryTransport({ manageDomains: true });
    const mail = createMail({ db: h.db, transport, dns, fetch: new FakeFetch().fetch, clock });

    it('takes the checklist from the transport and needs both DNS and the transport to agree', async () => {
      const d = await mail.domains.add(T2, { name: 'shop.example', returnPathSubdomain: 'mail' });
      assert.equal(d.signing, 'transport');
      assert.deepEqual(transport.registeredDomains, ['shop.example']);
      assert.deepEqual(
        d.records.map((r) => `${r.type} ${r.name}`),
        [
          'CNAME mem1._domainkey.shop.example',
          'CNAME mem2._domainkey.shop.example',
          'MX mail.shop.example',
          'TXT mail.shop.example',
          'TXT _dmarc.shop.example',
        ],
      );
      dns.publish(d.records);
      transport.domainVerified = false;
      assert.equal((await mail.domains.verify(T2, d.id)).status, 'pending', 'DNS ok, transport not yet');
      transport.domainVerified = true;
      assert.equal((await mail.domains.verify(T2, d.id)).status, 'verified');
      assert.equal(await mail.domains.signerFor(d), null, 'the transport signs, mail-kit does not');
      assert.equal(await mail.domains.remove(T2, d.id), true);
      assert.deepEqual(transport.registeredDomains, []);
    });

    it('verifyPending re-checks pending domains that have not been checked recently', async () => {
      const d = await mail.domains.add(T2, { name: 'pending.example' });
      const first = await mail.domains.verifyPending();
      assert.deepEqual(
        first.map((x) => x.id),
        [d.id],
      );
      const again = await mail.domains.verifyPending();
      assert.deepEqual(again, [], 'checked a moment ago, skipped');
      now = new Date(now.getTime() + 6 * 60_000);
      assert.equal((await mail.domains.verifyPending()).length, 1);
      await mail.domains.remove(T2, d.id);
    });
  });

  describe('sending', () => {
    const dns = new FakeDns();
    const fetch = new FakeFetch();
    let transport: MemoryTransport;
    let mail: Mail;
    before(async () => {
      transport = memoryTransport({ manageDomains: true });
      mail = createMail({ db: h.db, transport, dns, fetch: fetch.fetch, clock });
      const d = await mail.domains.add(T1, { name: 'app.example' });
      dns.publish(d.records);
      await mail.domains.verify(T1, d.id);
      await mail.webhooks.create(T1, {
        url: 'https://hooks.example/all',
        events: ['email.sent', 'email.failed', 'email.delivered', 'email.bounced', 'email.complained'],
      });
    });

    it('refuses a From on an unregistered or unverified domain, unless configured not to', async () => {
      await assert.rejects(
        mail.send(T1, { from: 'x@other.example', to: 'b@example.org', subject: 's', text: 't' }),
        (e: unknown) => MailError.hasCode(e, 'domain_not_verified') && e.failure.status === 'missing',
      );
      const pending = await mail.domains.add(T1, { name: 'pending2.example' });
      await assert.rejects(
        mail.send(T1, { from: 'x@pending2.example', to: 'b@example.org', subject: 's', text: 't' }),
        (e: unknown) => MailError.hasCode(e, 'domain_not_verified') && e.failure.status === 'pending',
      );
      // another tenant cannot send from app.example
      await assert.rejects(
        mail.send(T2, { from: 'x@app.example', to: 'b@example.org', subject: 's', text: 't' }),
        (e: unknown) => MailError.hasCode(e, 'domain_not_verified'),
      );
      await mail.domains.remove(T1, pending.id);

      const lax = createMail({
        db: h.db,
        transport,
        dns,
        fetch: fetch.fetch,
        clock,
        config: { requireVerifiedDomain: false },
      });
      const m = await lax.send(T1, { from: 'dev@anything.local', to: 'b@example.org', subject: 's', text: 't' });
      assert.equal(m.status, 'sent');
    });

    it('rejects bad input before touching the database', async () => {
      const before = (await mail.list(T1)).length;
      const bad = (input: Record<string, unknown>, code: string) =>
        assert.rejects(
          mail.send(T1, { from: 'a@app.example', to: 'b@example.org', subject: 's', text: 't', ...input } as never),
          (e: unknown) => MailError.is(e) && e.code === code,
          JSON.stringify(input),
        );
      await bad({ to: [] }, 'invalid_input');
      await bad({ to: 'nope' }, 'invalid_address');
      await bad({ text: undefined }, 'invalid_input');
      await bad({ subject: 'x\r\nBcc: y@z' }, 'header_injection');
      await bad({ headers: { 'X-Y': 'a\nb' } }, 'header_injection');
      await bad({ tags: { 'bad key!': 'v' } }, 'invalid_input');
      await bad({ to: Array.from({ length: 51 }, (_, i) => `r${i}@example.org`) }, 'invalid_input');
      await bad({ attachments: [{ filename: 'l.png', content: 'UE5H', contentId: 'logo' }] }, 'inline_needs_html');
      assert.equal((await mail.list(T1)).length, before);
    });

    it('sends: row first, then transport; records the sent event and queues the webhook', async () => {
      transport.clear();
      const m = await mail.send(T1, {
        from: 'Ada <ada@app.example>',
        to: ['bob@example.org', { email: 'carol@example.org', name: 'Carol' }],
        cc: 'cc@example.org',
        bcc: 'hidden@example.org',
        replyTo: 'reply@app.example',
        subject: 'Order #1',
        text: 'thanks',
        html: '<p>thanks</p>',
        tags: { kind: 'order' },
        headers: { 'X-Entity-Ref-ID': 'ord_1' },
      });
      assert.equal(m.status, 'sent');
      assert.equal(m.from, 'ada@app.example');
      assert.deepEqual(m.to, ['bob@example.org', 'carol@example.org']);
      assert.deepEqual(m.bcc, ['hidden@example.org']);
      assert.equal(m.attempts, 1);
      assert.ok(m.sentAt);
      const s = transport.sent[0]!;
      assert.deepEqual(s.envelope.recipients, [
        'bob@example.org',
        'carol@example.org',
        'cc@example.org',
        'hidden@example.org',
      ]);
      assert.ok(!s.text.includes('hidden@example.org'), 'bcc is not in the headers');
      assert.match(s.text, /^To: bob@example.org, Carol <carol@example.org>\r\n/m);
      assert.match(s.text, /^X-Entity-Ref-ID: ord_1\r\n/m);
      assert.match(s.text, new RegExp(`^Message-ID: ${m.messageId.replace(/[<>]/g, (c) => `\\${c}`)}\\r\\n`, 'm'));
      assert.deepEqual(s.envelope.tags, { kind: 'order' });
      const events = await mail.events.list(T1, m.id);
      assert.deepEqual(
        events.map((e) => e.type),
        ['sent'],
      );
      const hooks = await mail.webhooks.listDeliveries(T1);
      assert.equal(hooks[0]!.eventType, 'email.sent');
      assert.equal(await mail.get(T2, m.id), null, 'not visible to another tenant');
    });

    it('is idempotent on a key: same content returns the original, different content conflicts', async () => {
      transport.clear();
      const input = {
        from: 'ada@app.example',
        to: 'bob@example.org',
        subject: 'once',
        text: 'only',
        idempotencyKey: 'order-42',
      };
      const a = await mail.send(T1, input);
      const b = await mail.send(T1, input);
      assert.equal(a.id, b.id);
      assert.equal(transport.sent.length, 1);
      await assert.rejects(mail.send(T1, { ...input, subject: 'twice' }), (e: unknown) =>
        MailError.hasCode(e, 'idempotency_conflict'),
      );
      // keys are per tenant
      await assert.rejects(mail.send(T2, input), (e: unknown) => MailError.hasCode(e, 'domain_not_verified'));
    });

    it('drops suppressed recipients, and suppresses the whole send when none remain', async () => {
      transport.clear();
      await mail.suppression.add(null, { address: 'Complainer@example.org', reason: 'complaint' });
      await mail.suppression.add(T1, { address: 'unsub@example.org', reason: 'unsubscribe' });
      await mail.suppression.add(T2, { address: 'other-tenant@example.org', reason: 'unsubscribe' });

      const m = await mail.send(T1, {
        from: 'ada@app.example',
        to: ['bob@example.org', 'complainer@example.org', 'unsub@example.org', 'other-tenant@example.org'],
        subject: 's',
        text: 't',
      });
      assert.equal(m.status, 'sent');
      assert.deepEqual(m.to, ['bob@example.org', 'other-tenant@example.org'], "another tenant's list does not apply");
      assert.deepEqual(m.suppressedRecipients, ['complainer@example.org', 'unsub@example.org']);
      assert.deepEqual(transport.sent[0]!.envelope.recipients, ['bob@example.org', 'other-tenant@example.org']);

      const none = await mail.send(T1, { from: 'ada@app.example', to: 'unsub@example.org', subject: 's', text: 't' });
      assert.equal(none.status, 'suppressed');
      assert.equal(transport.sent.length, 1, 'nothing went to the transport');

      assert.equal(await mail.suppression.remove(T1, 'unsub@example.org'), true);
      assert.deepEqual(
        [...(await mail.suppression.check(T1, ['unsub@example.org', 'complainer@example.org']))],
        ['complainer@example.org'],
      );
      assert.equal((await mail.suppression.list(null)).length, 1);
    });

    it('schedules, delivers when due, and cancels', async () => {
      transport.clear();
      const later = new Date(now.getTime() + 60 * 60_000);
      const m = await mail.send(T1, {
        from: 'ada@app.example',
        to: 'bob@example.org',
        subject: 'later',
        text: 't',
        scheduledAt: later,
      });
      assert.equal(m.status, 'scheduled');
      assert.equal(transport.sent.length, 0);
      assert.deepEqual(await mail.deliverPending(50, now), { sent: 0, failed: 0, retried: 0 });
      assert.deepEqual(await mail.deliverPending(50, later), { sent: 1, failed: 0, retried: 0 });
      assert.equal((await mail.get(T1, m.id))!.status, 'sent');
      await assert.rejects(mail.cancel(T1, m.id), (e: unknown) => MailError.hasCode(e, 'invalid_state'));

      const c = await mail.send(T1, {
        from: 'ada@app.example',
        to: 'bob@example.org',
        subject: 'never',
        text: 't',
        scheduledAt: later,
      });
      const moved = await mail.reschedule(T1, c.id, new Date(later.getTime() + 60_000));
      assert.equal(moved.status, 'scheduled');
      assert.equal(moved.scheduledAt!.getTime(), later.getTime() + 60_000);
      assert.equal((await mail.payload(T1, c.id))!.subject, 'never');
      assert.equal((await mail.cancel(T1, c.id)).status, 'canceled');
      await assert.rejects(mail.reschedule(T1, c.id, later), (e: unknown) => MailError.hasCode(e, 'invalid_state'));
      assert.deepEqual(await mail.deliverPending(50, later), { sent: 0, failed: 0, retried: 0 });
      await assert.rejects(mail.cancel(T1, '00000000-0000-0000-0000-000000000000'), (e: unknown) =>
        MailError.hasCode(e, 'not_found'),
      );
    });

    it('defers when asked, and a worker picks it up', async () => {
      transport.clear();
      const m = await mail.send(
        T1,
        { from: 'ada@app.example', to: 'bob@example.org', subject: 'q', text: 't' },
        { defer: true },
      );
      assert.equal(m.status, 'queued');
      assert.equal(transport.sent.length, 0);
      const r = await mail.tick(now);
      assert.equal(r.sent, 1);
      assert.equal((await mail.get(T1, m.id))!.status, 'sent');
    });

    it('retries a retryable transport failure on the schedule, and fails a permanent one with a webhook', async () => {
      transport.clear();
      transport.failNext(1, { retryable: true, status: 429 });
      const m = await mail.send(T1, { from: 'ada@app.example', to: 'bob@example.org', subject: 'retry', text: 't' });
      assert.equal(m.status, 'queued');
      assert.equal(m.attempts, 1);
      assert.match(m.lastError!, /simulated failure/);
      assert.deepEqual(await mail.deliverPending(50, now), { sent: 0, failed: 0, retried: 0 }, 'not due yet');
      const due = new Date(now.getTime() + 31_000);
      assert.deepEqual(await mail.deliverPending(50, due), { sent: 1, failed: 0, retried: 0 });
      const after1 = (await mail.get(T1, m.id))!;
      assert.equal(after1.status, 'sent');
      assert.equal(after1.attempts, 2);
      assert.equal(after1.lastError, null);

      transport.failNext(1, { retryable: false, status: 400 });
      const f = await mail.send(T1, { from: 'ada@app.example', to: 'bob@example.org', subject: 'perm', text: 't' });
      assert.equal(f.status, 'failed');
      const hooks = await mail.webhooks.listDeliveries(T1);
      assert.equal(hooks[0]!.eventType, 'email.failed');

      // exhausts the schedule
      const strict = createMail({ db: h.db, transport, dns, fetch: fetch.fetch, clock, config: { maxAttempts: 2 } });
      transport.failNext(5, { retryable: true });
      const x = await strict.send(T1, {
        from: 'ada@app.example',
        to: 'bob@example.org',
        subject: 'exhaust',
        text: 't',
      });
      assert.equal(x.status, 'queued');
      const r = await strict.deliverPending(50, new Date(now.getTime() + 60_000));
      assert.equal(r.failed, 1);
      assert.equal((await strict.get(T1, x.id))!.status, 'failed');
      transport.failNext(0);
    });

    it('sendBatch reports per-item results', async () => {
      const out = await mail.sendBatch(T1, [
        { from: 'ada@app.example', to: 'bob@example.org', subject: 'b1', text: 't' },
        { from: 'ada@app.example', to: 'nope', subject: 'b2', text: 't' },
      ]);
      assert.equal(out[0]!.ok, true);
      assert.equal(out[1]!.ok, false);
      assert.equal((out[1] as { error: MailError }).error.code, 'invalid_address');
    });

    it('caps list limits at MAX_LIST_LIMIT and worker batches at MAX_BATCH', async () => {
      assert.equal(MAX_LIST_LIMIT, 200);
      assert.equal(MAX_BATCH, 500);
      // 220 suppressions for a scratch tenant; a list asking for 10,000 gets 200
      const T7 = 'tenant_caps';
      for (let i = 0; i < 220; i += 1)
        await mail.suppression.add(T7, { address: `u${i}@caps.example`, reason: 'manual' });
      assert.equal((await mail.suppression.list(T7, { limit: 10_000 })).length, 200);
      assert.equal((await mail.suppression.list(T7, { limit: 5 })).length, 5);
      assert.equal((await mail.suppression.list(T7, { limit: 0 })).length, 1, 'clamped up to 1');
      assert.equal((await mail.suppression.list(T7, { limit: Number.NaN })).length, 100, 'default when not a number');
      assert.equal((await mail.list(T1, { limit: 100_000 })).length <= 200, true);
      assert.equal((await mail.webhooks.listDeliveries(T1, { limit: 100_000 })).length <= 200, true);
      // a batch of 10,000 claims at most 500: with 3 queued rows, all 3 — the
      // SQL parameter is what is bounded, so assert through the clamp itself
      assert.equal(clampLimit(10_000, 50, MAX_BATCH), 500);
      assert.equal(clampLimit(undefined, 50, MAX_BATCH), 50);
      assert.equal(clampLimit(-3, 50, MAX_BATCH), 1);
      assert.equal(clampLimit(2.9, 50, MAX_BATCH), 2);
      const queued = await Promise.all(
        [1, 2, 3].map((i) =>
          mail.send(
            T1,
            { from: 'ada@app.example', to: 'bob@example.org', subject: `q${i}`, text: 't' },
            { defer: true },
          ),
        ),
      );
      assert.deepEqual(await mail.deliverPending(10_000, now), { sent: 3, failed: 0, retried: 0 });
      for (const q of queued) assert.equal((await mail.get(T1, q.id))!.status, 'sent');
    });

    it('lists with status filter and paging', async () => {
      const all = await mail.list(T1, { limit: 100 });
      const sent = await mail.list(T1, { status: 'sent', limit: 100 });
      assert.ok(sent.length > 0 && sent.length < all.length);
      assert.ok(sent.every((m) => m.status === 'sent'));
      const page = await mail.list(T1, { limit: 2 });
      const next = await mail.list(T1, { limit: 2, before: page[1]!.createdAt });
      assert.ok(next.every((m) => m.createdAt < page[1]!.createdAt));
    });
  });

  describe('delivery events', () => {
    const dns = new FakeDns();
    const fetch = new FakeFetch();
    const transport = memoryTransport({ manageDomains: true });
    const mail = createMail({ db: h.db, transport, dns, fetch: fetch.fetch, clock });
    let id = '';
    let providerId = '';
    before(async () => {
      const d = await mail.domains.add(T2, { name: 'events.example' });
      dns.publish(d.records);
      await mail.domains.verify(T2, d.id);
      await mail.webhooks.create(T2, {
        url: 'https://hooks.example/ev',
        events: ['email.delivered', 'email.bounced', 'email.complained', 'email.opened'],
      });
      const m = await mail.send(T2, {
        from: 'a@events.example',
        to: ['bob@example.org', 'carol@example.org'],
        subject: 'ev',
        text: 't',
      });
      id = m.id;
      providerId = m.providerMessageId!;
    });

    it('delivered → status delivered, webhook queued', async () => {
      const [e] = await mail.events.record([
        { type: 'delivered', providerMessageId: providerId, recipient: 'Bob@example.org', at: now },
      ]);
      assert.equal(e!.messageId, id);
      assert.equal(e!.recipient, 'bob@example.org');
      assert.equal((await mail.get(T2, id))!.status, 'delivered');
      assert.equal((await mail.webhooks.listDeliveries(T2))[0]!.eventType, 'email.delivered');
    });

    it('a soft bounce is delayed, not suppressed; a hard bounce suppresses for the tenant', async () => {
      await mail.events.record([
        {
          type: 'bounced',
          providerMessageId: providerId,
          recipient: 'carol@example.org',
          at: now,
          bounce: { kind: 'soft', subtype: 'MailboxFull' },
        },
      ]);
      assert.equal((await mail.get(T2, id))!.status, 'delivered', 'delivered stays delivered on a later soft bounce');
      assert.equal((await mail.suppression.check(T2, ['carol@example.org'])).size, 0);

      await mail.events.record([
        {
          type: 'bounced',
          providerMessageId: providerId,
          recipient: 'carol@example.org',
          at: new Date(now.getTime() + 1000), // a later event, not a replay of the soft one
          bounce: { kind: 'hard', subtype: 'General', diagnostic: '550 5.1.1' },
        },
      ]);
      assert.equal((await mail.get(T2, id))!.status, 'bounced');
      const sup = await mail.suppression.list(T2);
      assert.equal(sup[0]!.address, 'carol@example.org');
      assert.equal(sup[0]!.reason, 'bounce');
      assert.equal(sup[0]!.detail, '550 5.1.1');
      assert.equal((await mail.suppression.check(T1, ['carol@example.org'])).size, 0, 'a bounce is per tenant');
    });

    it('a complaint suppresses globally and wins over bounced', async () => {
      await mail.events.record([
        { type: 'complained', providerMessageId: providerId, recipient: 'bob@example.org', at: now },
      ]);
      assert.equal((await mail.get(T2, id))!.status, 'complained');
      const global = await mail.suppression.list(null);
      assert.ok(global.some((s) => s.address === 'bob@example.org' && s.reason === 'complaint'));
      assert.equal((await mail.suppression.check(T1, ['bob@example.org'])).size, 1, 'every tenant is protected');
    });

    it('opens and clicks are recorded without changing status; unknown ids are kept as orphans', async () => {
      await mail.events.record([
        { type: 'opened', providerMessageId: providerId, at: now, userAgent: 'UA' },
        { type: 'clicked', providerMessageId: providerId, at: now, url: 'https://x.example' },
      ]);
      assert.equal((await mail.get(T2, id))!.status, 'complained');
      const events = await mail.events.list(T2, id);
      assert.deepEqual(
        events.map((e) => e.type),
        ['sent', 'delivered', 'bounced', 'complained', 'opened', 'clicked', 'bounced'],
        'ordered by when they occurred; the hard bounce came a second later',
      );
      assert.equal(events.find((e) => e.type === 'clicked')!.detail.url, 'https://x.example');
      const [orphan] = await mail.events.record([{ type: 'delivered', providerMessageId: 'never-seen', at: now }]);
      assert.equal(orphan!.messageId, null);
      assert.equal(orphan!.tenantId, null);
    });

    it('a replayed provider notification is de-duplicated: no second suppression, no second webhook', async () => {
      const m = await mail.send(T2, {
        from: 'a@events.example',
        to: ['dave@example.org'],
        subject: 'replay',
        text: 't',
      });
      const sns = {
        Type: 'Notification',
        Message: JSON.stringify({
          eventType: 'Bounce',
          mail: { messageId: m.providerMessageId, timestamp: '2026-08-16T12:00:00.000Z' },
          bounce: {
            bounceType: 'Permanent',
            bounceSubType: 'General',
            bouncedRecipients: [{ emailAddress: 'dave@example.org', diagnosticCode: 'smtp; 550' }],
            timestamp: '2026-08-16T12:00:07.000Z',
          },
        }),
      };
      const hooksBefore = (await mail.webhooks.listDeliveries(T2)).length;
      const first = await mail.events.record(parseSesEvents(sns));
      assert.equal(first.length, 1);
      assert.equal(first[0]!.deduplicated, undefined);
      assert.equal((await mail.get(T2, m.id))!.status, 'bounced');
      assert.equal((await mail.webhooks.listDeliveries(T2)).length, hooksBefore + 1);
      const suppressedAt = (await mail.suppression.list(T2)).find((s) => s.address === 'dave@example.org')!;
      assert.ok(suppressedAt);

      // SNS retries the same notification (and a host replays its queue)
      await mail.suppression.remove(T2, 'dave@example.org');
      const again = await mail.events.record(parseSesEvents(sns));
      assert.equal(again.length, 1);
      assert.equal(again[0]!.deduplicated, true);
      assert.equal(again[0]!.id, first[0]!.id, 'the stored row is returned');
      assert.equal((await mail.webhooks.listDeliveries(T2)).length, hooksBefore + 1, 'no second webhook');
      assert.equal((await mail.suppression.check(T2, ['dave@example.org'])).size, 0, 'not re-suppressed');
      assert.deepEqual(
        (await mail.events.list(T2, m.id)).map((e) => e.type).sort(),
        ['bounced', 'sent'],
        'one bounce row',
      );
      // an orphan replay is de-duplicated too
      const [o1] = await mail.events.record([{ type: 'delivered', providerMessageId: 'orphan-replay', at: now }]);
      const [o2] = await mail.events.record([{ type: 'delivered', providerMessageId: 'orphan-replay', at: now }]);
      assert.equal(o2!.deduplicated, true);
      assert.equal(o2!.id, o1!.id);
    });

    it('record is one transaction: a failing webhook insert rolls back the event, the status and the suppression', async () => {
      const m = await mail.send(T2, {
        from: 'a@events.example',
        to: ['erin@example.org'],
        subject: 'atomic',
        text: 't',
      });
      const boom = (text: string) => /INSERT INTO mail\.webhook_deliveries/.test(text);
      const wrap = (inner: SqlExecutor): SqlExecutor => ({
        query: (text, params) =>
          boom(text) ? Promise.reject(new Error('webhook insert boom')) : inner.query(text, params),
        transaction: (fn) => inner.transaction((tx) => fn(wrap(tx))),
      });
      const flaky = createMail({ db: wrap(h.db), transport, dns, fetch: fetch.fetch, clock });
      const eventsBefore = (await mail.events.list(T2, m.id)).length;
      await assert.rejects(
        flaky.events.record([
          {
            type: 'bounced',
            providerMessageId: m.providerMessageId!,
            recipient: 'erin@example.org',
            at: now,
            bounce: { kind: 'hard', subtype: 'General' },
          },
        ]),
        /webhook insert boom/,
      );
      assert.equal((await mail.get(T2, m.id))!.status, 'sent', 'status not changed');
      assert.equal((await mail.suppression.check(T2, ['erin@example.org'])).size, 0, 'suppression rolled back');
      assert.equal((await mail.events.list(T2, m.id)).length, eventsBefore, 'event row rolled back');
      // and the same event then records cleanly — it was not half-stored
      const [ok] = await mail.events.record([
        {
          type: 'bounced',
          providerMessageId: m.providerMessageId!,
          recipient: 'erin@example.org',
          at: now,
          bounce: { kind: 'hard', subtype: 'General' },
        },
      ]);
      assert.equal(ok!.deduplicated, undefined);
      assert.equal((await mail.get(T2, m.id))!.status, 'bounced');
    });
  });

  describe('webhook delivery', () => {
    const fetch = new FakeFetch();
    // dkimKey set: subscription secrets are sealed at rest (and this instance
    // can drain the sealed rows earlier suites queued)
    const mail = createMail({
      db: h.db,
      transport: memoryTransport(),
      fetch: fetch.fetch,
      clock,
      dns: new FakeDns(),
      config: { dkimKey: testDkimKey },
    });
    const T3 = 'tenant_hooks';

    it('signs and posts, retries on failure with backoff, and gives up after the schedule', async () => {
      // drain what earlier suites queued (including sealed rows an unkeyed
      // instance's tick() pushed 5s out)
      await mail.webhooks.deliverPending(500, new Date(now.getTime() + 3_600_000));
      const hook = await mail.webhooks.create(T3, { url: 'https://hooks.example/x', events: ['email.delivered'] });
      assert.match(hook.secret, /^whsec_/);
      assert.equal((await mail.webhooks.list(T3))[0]!.id, hook.id);
      assert.equal(await mail.webhooks.enqueue(T3, 'email.bounced', {}), 0, 'not subscribed');
      assert.equal(await mail.webhooks.enqueue(T3, 'email.delivered', { email_id: 'e1' }), 1);

      fetch.respondNext(500);
      let r = await mail.webhooks.deliverPending(50, now);
      assert.deepEqual(r, { delivered: 0, failed: 0, retried: 1 });
      let [d] = await mail.webhooks.listDeliveries(T3);
      assert.equal(d!.attempts, 1);
      assert.equal(d!.lastStatusCode, 500);
      assert.equal(d!.nextAttemptAt!.getTime(), now.getTime() + 5000);

      r = await mail.webhooks.deliverPending(50, now);
      assert.deepEqual(r, { delivered: 0, failed: 0, retried: 0 }, 'not due');
      r = await mail.webhooks.deliverPending(50, new Date(now.getTime() + 5000));
      assert.deepEqual(r, { delivered: 1, failed: 0, retried: 0 });
      [d] = await mail.webhooks.listDeliveries(T3);
      assert.equal(d!.status, 'delivered');

      const call = fetch.calls.at(-1)!;
      assert.equal(call.url, 'https://hooks.example/x');
      const parsed = verifyWebhookSignature(hook.secret, call.init.headers, call.init.body!, {
        now: new Date(now.getTime() + 5000),
      }) as { type: string; data: { email_id: string } };
      assert.equal(parsed.type, 'email.delivered');
      assert.equal(parsed.data.email_id, 'e1');
      assert.equal(call.init.headers['webhook-id'], d!.id);

      // give up
      const strict = createMail({
        db: h.db,
        transport: memoryTransport(),
        fetch: fetch.fetch,
        clock,
        dns: new FakeDns(),
        config: { webhookMaxAttempts: 2, dkimKey: testDkimKey },
      });
      await strict.webhooks.enqueue(T3, 'email.delivered', { email_id: 'e2' });
      fetch.respondNext(503, 503);
      await strict.webhooks.deliverPending(50, now);
      const out = await strict.webhooks.deliverPending(50, new Date(now.getTime() + 5000));
      assert.equal(out.failed, 1);
      assert.equal((await strict.webhooks.listDeliveries(T3))[0]!.status, 'failed');

      // disabled subscriptions get nothing; removal cascades
      await mail.webhooks.setEnabled(T3, hook.id, false);
      assert.equal(await mail.webhooks.enqueue(T3, 'email.delivered', {}), 0);
      assert.equal(await mail.webhooks.remove(T3, hook.id), true);
      assert.deepEqual(await mail.webhooks.listDeliveries(T3), []);
      await assert.rejects(mail.webhooks.create(T3, { url: 'ftp://x', events: ['email.sent'] }), (e: unknown) =>
        MailError.hasCode(e, 'invalid_input'),
      );
    });

    it('seals secrets at rest under config.dkimKey, and reads plaintext rows from before the key', async () => {
      const T8 = 'tenant_sealed';
      const hook = await mail.webhooks.create(T8, { url: 'https://hooks.example/sealed', events: ['email.sent'] });
      const [row] = await h.db.query<{ secret: string | null; secret_sealed: string | null }>(
        'SELECT secret, secret_sealed FROM mail.webhook_subscriptions WHERE id = $1',
        [hook.id],
      );
      assert.equal(row!.secret, null, 'plaintext column empty');
      assert.ok(row!.secret_sealed, 'sealed column set');
      assert.ok(!row!.secret_sealed!.includes(hook.secret.slice(6, 20)), 'ciphertext does not carry the secret');
      // and it still signs with the secret the caller was shown once
      await mail.webhooks.enqueue(T8, 'email.sent', { email_id: 'sealed-1' });
      assert.deepEqual(await mail.webhooks.deliverPending(50, now), { delivered: 1, failed: 0, retried: 0 });
      const call = fetch.calls.at(-1)!;
      assert.ok(verifyWebhookSignature(hook.secret, call.init.headers, call.init.body!, { now }));

      // an instance without the key stores as written; a keyed instance still delivers that row
      const plain = createMail({
        db: h.db,
        transport: memoryTransport(),
        fetch: fetch.fetch,
        clock,
        dns: new FakeDns(),
      });
      const legacy = await plain.webhooks.create(T8, { url: 'https://hooks.example/plain', events: ['email.bounced'] });
      const [prow] = await h.db.query<{ secret: string | null; secret_sealed: string | null }>(
        'SELECT secret, secret_sealed FROM mail.webhook_subscriptions WHERE id = $1',
        [legacy.id],
      );
      assert.equal(prow!.secret, legacy.secret);
      assert.equal(prow!.secret_sealed, null);
      await mail.webhooks.enqueue(T8, 'email.bounced', { email_id: 'plain-1' });
      assert.deepEqual(await mail.webhooks.deliverPending(50, now), { delivered: 1, failed: 0, retried: 0 });
      assert.ok(
        verifyWebhookSignature(legacy.secret, fetch.calls.at(-1)!.init.headers, fetch.calls.at(-1)!.init.body!, {
          now,
        }),
      );

      // an unkeyed instance cannot sign for a sealed row: left to retry, with the reason recorded
      await mail.webhooks.enqueue(T8, 'email.sent', { email_id: 'sealed-2' });
      assert.deepEqual(await plain.webhooks.deliverPending(50, now), { delivered: 0, failed: 0, retried: 1 });
      const [stuck] = await plain.webhooks.listDeliveries(T8);
      assert.equal(stuck!.status, 'pending');
      assert.match(stuck!.lastError!, /sealed but no sealKey/);
      assert.deepEqual(await mail.webhooks.deliverPending(50, new Date(now.getTime() + 5000)), {
        delivered: 1,
        failed: 0,
        retried: 0,
      });
      await mail.webhooks.remove(T8, hook.id);
      await mail.webhooks.remove(T8, legacy.id);
    });

    it('refuses webhook URLs that point inside: at create, and again at delivery', async () => {
      const dns = new FakeDns();
      dns.a.set('metadata.example', ['169.254.169.254']);
      dns.a.set('flip.example', ['203.0.113.7']);
      const guarded = createMail({ db: h.db, transport: memoryTransport(), fetch: fetch.fetch, clock, dns });
      const T4 = 'tenant_ssrf';
      const refused = (url: string) =>
        assert.rejects(
          guarded.webhooks.create(T4, { url, events: ['email.sent'] }),
          (e: unknown) => MailError.hasCode(e, 'webhook_url_forbidden'),
          url,
        );
      await refused('https://metadata.example/latest/meta-data/');
      await refused('https://127.0.0.1:8080/hook');
      await refused('https://[::1]/hook');
      await refused('https://10.0.0.1/hook');
      await refused('https://192.168.1.10/hook');
      await refused('https://172.16.5.5/hook');
      await refused('https://169.254.169.254/hook');
      await refused('https://0.0.0.0/hook');
      await refused('https://224.0.0.1/hook');
      await refused('https://[fd00::1]/hook');
      await refused('https://[fe80::1]/hook');
      await refused('https://localhost/hook');
      // http: needs the explicit dev switch — and even then, not to an internal host
      await refused('http://hooks.example/hook');
      const dev = createMail({
        db: h.db,
        transport: memoryTransport(),
        fetch: fetch.fetch,
        clock,
        dns,
        config: { allowInsecureHttp: true },
      });
      const devHook = await dev.webhooks.create(T4, { url: 'http://hooks.example/dev', events: ['email.sent'] });
      assert.equal(devHook.url, 'http://hooks.example/dev');
      await assert.rejects(
        dev.webhooks.create(T4, { url: 'http://127.0.0.1/dev', events: ['email.sent'] }),
        (e: unknown) => MailError.hasCode(e, 'webhook_url_forbidden'),
      );
      await dev.webhooks.remove(T4, devHook.id);
      assert.deepEqual(await guarded.webhooks.list(T4), []);

      // a host that was public at create time and points inside by delivery time
      const hook = await guarded.webhooks.create(T4, { url: 'https://flip.example/hook', events: ['email.sent'] });
      assert.equal(await guarded.webhooks.enqueue(T4, 'email.sent', { email_id: 'e-flip' }), 1);
      dns.a.set('flip.example', ['10.0.0.9']);
      const before = fetch.calls.length;
      const r = await guarded.webhooks.deliverPending(50, now);
      assert.deepEqual(r, { delivered: 0, failed: 1, retried: 0 }, 'permanent, not retried');
      assert.equal(fetch.calls.length, before, 'nothing was posted');
      const [d] = await guarded.webhooks.listDeliveries(T4);
      assert.equal(d!.status, 'failed');
      assert.match(d!.lastError!, /webhook_url_forbidden.*10\.0\.0\.9/);
      await guarded.webhooks.remove(T4, hook.id);
    });

    it('does not hold a row lock while the endpoint is slow: the claim commits before the POST', async () => {
      const T6 = 'tenant_slow';
      await mail.webhooks.deliverPending(500, now); // drain
      let release: () => void = () => {};
      const gate = new Promise<void>((r) => {
        release = r;
      });
      let entered: () => void = () => {};
      const inFlight = new Promise<void>((r) => {
        entered = r;
      });
      const slow = createMail({
        db: h.db,
        transport: memoryTransport(),
        clock,
        dns: new FakeDns(),
        fetch: async () => {
          entered();
          await gate;
          return { status: 200, headers: { get: () => null }, text: async () => '' };
        },
      });
      await slow.webhooks.create(T6, { url: 'https://hooks.example/slow', events: ['email.sent'] });
      await slow.webhooks.enqueue(T6, 'email.sent', { email_id: 'slow-1' });
      const [pending] = await slow.webhooks.listDeliveries(T6);

      const run = slow.webhooks.deliverPending(50, now);
      await inFlight; // the worker is inside fetch now
      // Another connection can lock the row: NOWAIT would raise 55P03 if the
      // worker still held it inside an open transaction.
      const client = await h.pool.connect();
      try {
        await client.query('BEGIN');
        const locked = await client.query(
          'SELECT id, status, next_attempt_at FROM mail.webhook_deliveries WHERE id = $1 FOR UPDATE NOWAIT',
          [pending!.id],
        );
        assert.equal(locked.rows.length, 1);
        assert.equal(locked.rows[0].status, 'pending');
        assert.ok(locked.rows[0].next_attempt_at.getTime() > now.getTime(), 'leased: not due until the lease lapses');
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }
      // and a second worker sees nothing due meanwhile
      assert.deepEqual(await mail.webhooks.deliverPending(50, now), { delivered: 0, failed: 0, retried: 0 });
      release();
      assert.deepEqual(await run, { delivered: 1, failed: 0, retried: 0 });
      assert.equal((await slow.webhooks.listDeliveries(T6))[0]!.status, 'delivered');
    });

    it('posts with redirect: "error" so a 3xx cannot walk past the guard', async () => {
      const T5 = 'tenant_redirect';
      await mail.webhooks.create(T5, { url: 'https://hooks.example/r', events: ['email.sent'] });
      await mail.webhooks.enqueue(T5, 'email.sent', {});
      fetch.respondNext(302);
      const r = await mail.webhooks.deliverPending(50, now);
      assert.deepEqual(r, { delivered: 0, failed: 0, retried: 1 });
      assert.equal(fetch.calls.at(-1)!.init.redirect, 'error');
      const [d] = await mail.webhooks.listDeliveries(T5);
      assert.equal(d!.lastStatusCode, 302);
    });
  });
});
