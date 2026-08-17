// sendBatch parallelism: the limiter itself (offline) and the batch through
// the memory transport — the cap is honoured, results come back in input
// order, and per-item failures stay per item.

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { createMail, type Mail } from '../src/instance.ts';
import { mapLimit } from '../src/limiter.ts';
import { type MemoryTransport, memoryTransport } from '../src/transports/memory.ts';
import type { OutboundEnvelope } from '../src/types.ts';
import { FakeDns, FakeFetch, type Harness, SKIP_REASON, setupDatabase } from './harness.ts';

/** A gate: `onSend` parks every call until `release()`; tracks in-flight peaks. */
class Gate {
  inFlight = 0;
  peak = 0;
  started: string[] = [];
  private waiters: Array<() => void> = [];
  hold = true;
  onSend = async (e: OutboundEnvelope) => {
    this.started.push(e.recipients[0] ?? '');
    this.inFlight += 1;
    this.peak = Math.max(this.peak, this.inFlight);
    if (this.hold) await new Promise<void>((r) => this.waiters.push(r));
    this.inFlight -= 1;
  };
  release(n = Number.POSITIVE_INFINITY) {
    while (n > 0 && this.waiters.length) {
      this.waiters.shift()?.();
      n -= 1;
    }
  }
  reset() {
    this.inFlight = 0;
    this.peak = 0;
    this.started = [];
    this.waiters = [];
    this.hold = true;
  }
}

const tick = () => new Promise<void>((r) => setTimeout(r, 5));

describe('mail-kit/limiter', () => {
  it('runs at most `concurrency` at once, in input order of start, and returns results in input order', async () => {
    let inFlight = 0;
    let peak = 0;
    const started: number[] = [];
    const out = await mapLimit([5, 1, 4, 2, 3, 0], 2, async (ms, i) => {
      started.push(i);
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, ms));
      inFlight -= 1;
      return `r${i}:${ms}`;
    });
    assert.equal(peak, 2);
    assert.deepEqual(started, [0, 1, 2, 3, 4, 5]);
    assert.deepEqual(out, ['r0:5', 'r1:1', 'r2:4', 'r3:2', 'r4:3', 'r5:0'], 'input order, not completion order');
    assert.deepEqual(await mapLimit([], 4, async () => 1), []);
    assert.deepEqual(await mapLimit([1, 2], 0, async (x) => x * 2), [2, 4], 'a width below 1 runs serially');
    assert.deepEqual(await mapLimit([1, 2], Number.NaN, async (x) => x), [1, 2]);
    await assert.rejects(
      mapLimit([1, 2, 3], 2, async (x) => {
        if (x === 2) throw new Error('boom');
        return x;
      }),
      /boom/,
    );
  });
});

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('mail-kit/sendBatch', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const T1 = 'tenant_batch';
  const gate = new Gate();
  let transport: MemoryTransport;
  let mail: Mail;
  const from = 'b@batch.example';
  const inputs = (n: number) =>
    Array.from({ length: n }, (_, i) => ({ from, to: `r${i}@example.org`, subject: `s${i}`, text: 't' }));

  before(async () => {
    transport = memoryTransport({ onSend: gate.onSend });
    mail = createMail({
      db: h.db,
      transport,
      dns: new FakeDns(),
      fetch: new FakeFetch().fetch,
      config: { requireVerifiedDomain: false },
    });
  });

  it('keeps at most config.batchConcurrency (default 8) sends in flight and returns results in input order', async () => {
    gate.reset();
    const p = mail.sendBatch(T1, inputs(20));
    // let the first wave reach the transport
    for (let i = 0; i < 20 && gate.inFlight < 8; i += 1) await tick();
    assert.equal(gate.inFlight, 8, 'exactly the cap in flight while the gate holds');
    gate.release(3);
    for (let i = 0; i < 20 && gate.started.length < 11; i += 1) await tick();
    assert.equal(gate.inFlight, 8, 'each release lets one more through');
    gate.hold = false;
    gate.release();
    const out = await p;
    assert.equal(gate.peak, 8);
    assert.equal(out.length, 20);
    for (const [i, r] of out.entries()) {
      assert.ok(r.ok, `item ${i}`);
      assert.deepEqual(r.message.to, [`r${i}@example.org`], 'input order');
      assert.equal(r.message.status, 'sent');
    }
    assert.equal(transport.sent.length, 20);
  });

  it('honours a per-call concurrency and a config one; a width below 1 is invalid_input', async () => {
    gate.reset();
    const p = mail.sendBatch(T1, inputs(6), { concurrency: 2 });
    for (let i = 0; i < 20 && gate.inFlight < 2; i += 1) await tick();
    await tick();
    assert.equal(gate.inFlight, 2);
    gate.hold = false;
    gate.release();
    assert.equal((await p).length, 6);
    assert.equal(gate.peak, 2);

    gate.reset();
    const three = createMail({
      db: h.db,
      transport,
      dns: new FakeDns(),
      fetch: new FakeFetch().fetch,
      config: { requireVerifiedDomain: false, batchConcurrency: 3 },
    });
    const q = three.sendBatch(T1, inputs(7));
    for (let i = 0; i < 20 && gate.inFlight < 3; i += 1) await tick();
    await tick();
    assert.equal(gate.inFlight, 3);
    gate.hold = false;
    gate.release();
    assert.equal((await q).filter((r) => r.ok).length, 7);
    assert.equal(gate.peak, 3);

    await assert.rejects(mail.sendBatch(T1, inputs(1), { concurrency: 0 }), (e: unknown) =>
      MailError.hasCode(e, 'invalid_input'),
    );
    // serial: one at a time, still in order
    gate.reset();
    gate.hold = false;
    const s = await mail.sendBatch(T1, inputs(4), { concurrency: 1 });
    assert.equal(gate.peak, 1);
    assert.deepEqual(
      s.map((r) => (r.ok ? r.message.to[0] : 'x')),
      ['r0@example.org', 'r1@example.org', 'r2@example.org', 'r3@example.org'],
    );
  });

  it('reports MailErrors per item in place, honours defer, and lets anything else propagate', async () => {
    gate.reset();
    gate.hold = false;
    const mixed = [
      { from, to: 'ok1@example.org', subject: 'a', text: 't' },
      { from, to: 'nope', subject: 'b', text: 't' },
      { from, to: 'ok2@example.org', subject: 'c', text: 't', headers: { 'X-Y': 'a\nb' } },
      { from, to: 'ok3@example.org', subject: 'd', text: 't' },
    ];
    const out = await mail.sendBatch(T1, mixed, { defer: true, concurrency: 4 });
    assert.deepEqual(
      out.map((r) => (r.ok ? r.message.status : r.error.code)),
      ['queued', 'invalid_address', 'header_injection', 'queued'],
    );
    const boom = memoryTransport({
      onSend: async () => {
        throw new TypeError('not a MailError');
      },
    });
    const broken = createMail({
      db: h.db,
      transport: boom,
      dns: new FakeDns(),
      fetch: new FakeFetch().fetch,
      config: { requireVerifiedDomain: false },
    });
    // a non-MailError inside the transport is caught by the attempt and becomes a failed message …
    const failed = await broken.sendBatch(T1, inputs(2));
    assert.ok(failed.every((r) => r.ok && r.message.status === 'failed'));
    // … but one thrown outside the send path (a broken executor) rejects the batch
    const badDb = {
      ...h.db,
      query: async () => {
        throw new TypeError('db down');
      },
    };
    const down = createMail({
      db: badDb as typeof h.db,
      transport,
      dns: new FakeDns(),
      fetch: new FakeFetch().fetch,
      config: { requireVerifiedDomain: false },
    });
    await assert.rejects(down.sendBatch(T1, inputs(2)), /db down/);
  });
});
