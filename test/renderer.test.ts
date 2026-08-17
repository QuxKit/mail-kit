// The renderer seam: sendRendered with a plain function renderer (sync and
// async), subject precedence, and the failure shapes.

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { createMail, type Mail } from '../src/instance.ts';
import { type MemoryTransport, memoryTransport } from '../src/transports/memory.ts';
import type { RenderedContent, Renderer } from '../src/types.ts';
import { FakeDns, FakeFetch, type Harness, SKIP_REASON, setupDatabase } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('mail-kit/sendRendered', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const T1 = 'tenant_render';
  let transport: MemoryTransport;
  let mail: Mail;
  const from = 'r@render.example';

  interface Welcome {
    name: string;
    plan: string;
  }
  const welcome: Renderer<Welcome> = ({ name, plan }) => ({
    subject: `Welcome, ${name}`,
    html: `<h1>Hi ${name}</h1><p>You are on ${plan}.</p>`,
    text: `Hi ${name}\n\nYou are on ${plan}.`,
  });

  before(async () => {
    transport = memoryTransport();
    mail = createMail({
      db: h.db,
      transport,
      dns: new FakeDns(),
      fetch: new FakeFetch().fetch,
      config: { requireVerifiedDomain: false },
    });
  });

  it('renders through a plain function and sends the result in the envelope', async () => {
    transport.clear();
    const m = await mail.sendRendered(
      T1,
      welcome,
      { name: 'Ada', plan: 'Pro' },
      { from, to: 'ada@example.org', tags: { kind: 'welcome' }, idempotencyKey: 'welcome-ada' },
    );
    assert.equal(m.status, 'sent');
    assert.equal(m.subject, 'Welcome, Ada');
    assert.deepEqual(m.tags, { kind: 'welcome' });
    const text = transport.sent[0]!.text;
    assert.match(text, /^Subject: Welcome, Ada\r\n/m);
    assert.match(text, /multipart\/alternative/);
    assert.match(text, /<h1>Hi Ada<\/h1>/);
    assert.match(text, /You are on Pro\./);
    const payload = await mail.payload(T1, m.id);
    assert.equal(payload!.html, '<h1>Hi Ada</h1><p>You are on Pro.</p>');
    // idempotent like send: same input, same key → same message
    const again = await mail.sendRendered(
      T1,
      welcome,
      { name: 'Ada', plan: 'Pro' },
      { from, to: 'ada@example.org', tags: { kind: 'welcome' }, idempotencyKey: 'welcome-ada' },
    );
    assert.equal(again.id, m.id);
    assert.equal(transport.sent.length, 1);
  });

  it('accepts an async renderer, lets the envelope subject win, and passes SendOptions through', async () => {
    transport.clear();
    const asyncText: Renderer<{ n: number }> = async ({ n }) => {
      await new Promise((r) => setTimeout(r, 2));
      return { text: `n=${n}`, subject: 'from renderer' };
    };
    const m = await mail.sendRendered(
      T1,
      asyncText,
      { n: 7 },
      { from, to: 'bob@example.org', subject: 'from envelope' },
      { defer: true },
    );
    assert.equal(m.status, 'queued');
    assert.equal(m.subject, 'from envelope');
    await mail.deliverPending(50);
    assert.match(transport.sent[0]!.text, /^Content-Type: text\/plain/m);
    assert.match(transport.sent[0]!.text, /n=3D7/, 'quoted-printable');
    // renderer-only subject
    const r = await mail.sendRendered(T1, asyncText, { n: 8 }, { from, to: 'bob@example.org' });
    assert.equal(r.subject, 'from renderer');
  });

  it('is invalid_input when neither side has a subject, when the renderer yields no body or not an object; a throwing renderer throws', async () => {
    const before = (await mail.list(T1)).length;
    const bodyOnly: Renderer<void> = () => ({ text: 'x' });
    await assert.rejects(
      mail.sendRendered(T1, bodyOnly, undefined, { from, to: 'c@example.org' }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input') && /subject is required/.test(e.message),
    );
    const empty: Renderer<void> = () => ({ subject: 's' });
    await assert.rejects(
      mail.sendRendered(T1, empty, undefined, { from, to: 'c@example.org' }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input') && /text or html/.test(e.message),
    );
    const notObject = (() => 'html') as unknown as Renderer<void>;
    await assert.rejects(
      mail.sendRendered(T1, notObject, undefined, { from, to: 'c@example.org' }),
      (e: unknown) => MailError.hasCode(e, 'invalid_input') && /renderer must return/.test(e.message),
    );
    const nul = (() => null) as unknown as Renderer<void>;
    await assert.rejects(mail.sendRendered(T1, nul, undefined, { from, to: 'c@example.org' }), (e: unknown) =>
      MailError.hasCode(e, 'invalid_input'),
    );
    const boom: Renderer<void> = () => {
      throw new TypeError('template exploded');
    };
    await assert.rejects(
      mail.sendRendered(T1, boom, undefined, { from, to: 'c@example.org', subject: 's' }),
      /template exploded/,
    );
    // header-injection through a rendered subject is still refused
    const evil: Renderer<void> = (): RenderedContent => ({ subject: 'x\r\nBcc: y@z', text: 't' });
    await assert.rejects(mail.sendRendered(T1, evil, undefined, { from, to: 'c@example.org' }), (e: unknown) =>
      MailError.hasCode(e, 'header_injection'),
    );
    assert.equal((await mail.list(T1)).length, before, 'no row for any of them');
  });
});
