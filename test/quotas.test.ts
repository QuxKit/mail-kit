// Per-tenant quotas: token-bucket maths, set/get, and — the part that
// matters — N parallel sends admitting exactly the limit under the row lock.

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { createMail, type Mail } from '../src/instance.ts';
import { createQuotas } from '../src/quotas.ts';
import { memoryTransport } from '../src/transports/memory.ts';
import { FakeDns, FakeFetch, type Harness, SKIP_REASON, setupDatabase } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('mail-kit/quotas', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const T1 = 'tenant_quota';
  const T2 = 'tenant_quota_free';
  let now = new Date('2026-08-17T10:00:00Z');
  const clock = () => now;
  const dns = new FakeDns();
  const transport = memoryTransport({ manageDomains: true });
  let mail: Mail;
  const from = 'q@quota.example';
  const send = (m: Mail, tenant: string, subject: string, extra: Record<string, unknown> = {}) =>
    m.send(tenant, { from, to: 'r@example.org', subject, text: 't', ...extra });

  before(async () => {
    mail = createMail({
      db: h.db,
      transport,
      dns,
      fetch: new FakeFetch().fetch,
      clock,
      config: { requireVerifiedDomain: false, quotas: { perMinute: 5, perDay: null } },
    });
  });

  it('admits exactly the limit under N parallel sends, then refuses with retryAfterMs; refills at the rate', async () => {
    const results = await Promise.allSettled(Array.from({ length: 12 }, (_, i) => send(mail, T1, `p${i}`)));
    const admitted = results.filter((r) => r.status === 'fulfilled');
    const refused = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
    assert.equal(admitted.length, 5);
    assert.equal(refused.length, 7);
    for (const r of refused) {
      assert.ok(MailError.hasCode(r.reason, 'quota_exceeded'), String(r.reason));
      assert.equal(r.reason.failure.window, 'minute');
      assert.equal(r.reason.failure.limit, 5);
      assert.equal(r.reason.failure.tenantId, T1);
      assert.ok(
        r.reason.failure.retryAfterMs > 0 && r.reason.failure.retryAfterMs <= 12_000,
        String(r.reason.failure.retryAfterMs),
      );
      assert.match(r.reason.message, /minute quota of 5; retry in \d+ms/);
    }
    assert.equal((await mail.list(T1)).length, 5, 'a refused send leaves no row');
    const q = await mail.quotas.get(T1);
    assert.equal(q.custom, false);
    assert.equal(q.perMinute, 5);
    assert.equal(q.perDay, null);
    assert.equal(q.remaining.minute, 0);
    assert.equal(q.remaining.day, null);
    // 12s later one token is back (5/min = one per 12s); 11s is not enough
    now = new Date(now.getTime() + 11_000);
    await assert.rejects(send(mail, T1, 'early'), (e: unknown) => MailError.hasCode(e, 'quota_exceeded'));
    now = new Date(now.getTime() + 1_000);
    assert.equal((await send(mail, T1, 'refilled')).status, 'sent');
    await assert.rejects(send(mail, T1, 'again'), (e: unknown) => MailError.hasCode(e, 'quota_exceeded'));
    // a full minute later the bucket is full again, and never fuller
    now = new Date(now.getTime() + 10 * 60_000);
    assert.equal((await mail.quotas.get(T1)).remaining.minute, 5);
    // another tenant has its own bucket
    assert.equal((await send(mail, T2, 'other')).status, 'sent');
  });

  it('does not charge a keyed replay, a fully suppressed send, or a worker retry', async () => {
    now = new Date(now.getTime() + 60_000);
    const first = await send(mail, T1, 'keyed', { idempotencyKey: 'k1' });
    const before = (await mail.quotas.get(T1)).remaining.minute!;
    const again = await send(mail, T1, 'keyed', { idempotencyKey: 'k1' });
    assert.equal(again.id, first.id);
    assert.equal((await mail.quotas.get(T1)).remaining.minute, before, 'replay is free');
    await assert.rejects(send(mail, T1, 'changed', { idempotencyKey: 'k1' }), (e: unknown) =>
      MailError.hasCode(e, 'idempotency_conflict'),
    );
    assert.equal((await mail.quotas.get(T1)).remaining.minute, before, 'a conflict is free too');
    await mail.suppression.add(T1, { address: 'r@example.org', reason: 'manual' });
    assert.equal((await send(mail, T1, 'suppressed')).status, 'suppressed');
    assert.equal((await mail.quotas.get(T1)).remaining.minute, before, 'nothing left to send: free');
    await mail.suppression.remove(T1, 'r@example.org');
    // a retryable transport failure and its retry cost one token, at accept time
    transport.failNext(1, { retryable: true });
    const retrying = await send(mail, T1, 'retry');
    assert.equal(retrying.status, 'queued');
    const afterAccept = (await mail.quotas.get(T1)).remaining.minute!;
    assert.equal(Math.round(before - afterAccept), 1);
    now = new Date(now.getTime() + 31_000);
    assert.equal((await mail.deliverPending(50, now)).sent, 1);
    const expected = Math.min(5, afterAccept + 31 / 12);
    assert.ok(Math.abs(expected - (await mail.quotas.get(T1)).remaining.minute!) < 0.01, 'the retry took nothing');
  });

  it('set() gives a tenant its own limits, null per bucket disables it, set(null) reverts to the default', async () => {
    now = new Date(now.getTime() + 60 * 60_000);
    const own = await mail.quotas.set(T1, { perMinute: null, perDay: 2 });
    assert.equal(own.custom, true);
    assert.deepEqual([own.perMinute, own.perDay], [null, 2]);
    assert.deepEqual(own.remaining, { minute: null, day: 2 });
    for (let i = 0; i < 2; i += 1) assert.equal((await send(mail, T1, `d${i}`)).status, 'sent');
    await assert.rejects(
      send(mail, T1, 'd3'),
      (e: unknown) =>
        MailError.hasCode(e, 'quota_exceeded') &&
        e.failure.window === 'day' &&
        e.failure.limit === 2 &&
        e.failure.retryAfterMs === 43_200_000,
    );
    // ten more in the same minute would have hit the default's 5; not with the tenant's own null
    // (they still hit the day bucket, so check via the effective view instead)
    assert.equal((await mail.quotas.get(T1)).perMinute, null);
    // lowering a bucket clamps; raising does not hand out tokens retroactively
    const raised = await mail.quotas.set(T1, { perMinute: 100, perDay: 1000 });
    assert.equal(raised.remaining.day, 0, 'was empty, stays empty');
    assert.equal(raised.remaining.minute, 100, 'a bucket that had no limit starts full');
    const lowered = await mail.quotas.set(T1, { perMinute: 3, perDay: 1000 });
    assert.equal(lowered.remaining.minute, 3, 'clamped to the new capacity');
    // back to the default
    const reverted = await mail.quotas.set(T1, null);
    assert.equal(reverted.custom, false);
    assert.equal(reverted.perMinute, 5);
    assert.equal(reverted.perDay, null);
    assert.equal(reverted.remaining.minute, 3, 'kept its level');
    // both null: unlimited, and consume takes the fast path
    await mail.quotas.set(T1, { perMinute: null, perDay: null });
    for (let i = 0; i < 8; i += 1) assert.equal((await send(mail, T1, `u${i}`)).status, 'sent');
    assert.deepEqual((await mail.quotas.get(T1)).remaining, { minute: null, day: null });
    await mail.quotas.set(T1, null);
  });

  it('validates limits and n; a mail without config quotas enforces nothing and writes no row', async () => {
    for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 40]) {
      await assert.rejects(mail.quotas.set(T1, { perMinute: bad, perDay: null }), (e: unknown) =>
        MailError.hasCode(e, 'invalid_input'),
      );
      await assert.rejects(mail.quotas.set(T1, { perMinute: null, perDay: bad }), (e: unknown) =>
        MailError.hasCode(e, 'invalid_input'),
      );
    }
    await assert.rejects(mail.quotas.consume(T1, 0), (e: unknown) => MailError.hasCode(e, 'invalid_input'));
    assert.throws(
      () => createQuotas({ db: h.db, config: { quotas: { perMinute: 0 } } }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input'),
    );
    const free = createMail({
      db: h.db,
      transport,
      dns,
      fetch: new FakeFetch().fetch,
      clock,
      config: { requireVerifiedDomain: false },
    });
    const T3 = 'tenant_quota_none';
    for (let i = 0; i < 3; i += 1) assert.equal((await send(free, T3, `f${i}`)).status, 'sent');
    assert.equal((await h.db.query('SELECT 1 FROM mail.quotas WHERE tenant_id = $1', [T3])).length, 0);
    const q = await free.quotas.get(T3);
    assert.deepEqual(q, {
      tenantId: T3,
      perMinute: null,
      perDay: null,
      custom: false,
      remaining: { minute: null, day: null },
    });
    // consume(n) takes n from both buckets or neither
    await free.quotas.set(T3, { perMinute: 10, perDay: 3 });
    assert.deepEqual(await free.quotas.consume(T3, 3), { ok: true });
    const r = await free.quotas.consume(T3, 2);
    assert.equal(r.ok, false);
    assert.equal((r as { window: string }).window, 'day');
    assert.equal(
      (await free.quotas.get(T3)).remaining.minute,
      7,
      'the minute bucket was not charged for the refused call',
    );
    // sendBatch surfaces quota_exceeded per item
    const out = await free.sendBatch(
      T3,
      [1, 2].map((i) => ({ from, to: 'r@example.org', subject: `b${i}`, text: 't' })),
    );
    assert.equal(out.filter((o) => o.ok).length, 0);
    assert.ok(out.every((o) => !o.ok && o.error.code === 'quota_exceeded'));
  });
});
