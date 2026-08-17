// messages.search: every filter, keyset paging, and the indexes it leans on.

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { createMail, type Mail } from '../src/instance.ts';
import { memoryTransport } from '../src/transports/memory.ts';
import type { Message } from '../src/types.ts';
import { FakeDns, FakeFetch, type Harness, SKIP_REASON, setupDatabase } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('mail-kit/search', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const T1 = 'tenant_search';
  const T2 = 'tenant_search_other';
  let now = new Date('2026-08-17T09:00:00Z');
  const clock = () => now;
  const dns = new FakeDns();
  const transport = memoryTransport({ manageDomains: true });
  let mail: Mail;
  const seeded: Message[] = [];

  before(async () => {
    mail = createMail({ db: h.db, transport, dns, fetch: new FakeFetch().fetch, clock });
    for (const t of [T1, T2]) {
      const d = await mail.domains.add(t, { name: `${t.replace(/_/g, '-')}.example` });
      dns.publish(d.records);
      await mail.domains.verify(t, d.id);
    }
    const from = 'a@tenant-search.example';
    const inputs: Array<{ to: string | string[]; subject: string; tags: Record<string, string> }> = [
      { to: 'ada@example.org', subject: 'Order #100 confirmed', tags: { kind: 'order', region: 'eu' } },
      { to: 'bob@example.org', subject: 'Order #101 confirmed', tags: { kind: 'order', region: 'us' } },
      { to: ['ada@example.org', 'carol@example.org'], subject: 'Weekly digest', tags: { kind: 'digest' } },
      { to: 'dave@example.org', subject: '50% off_everything', tags: {} },
      { to: 'ada@example.org', subject: 'Password reset', tags: { kind: 'auth' } },
    ];
    for (const [i, input] of inputs.entries()) {
      // one minute apart, so created_at and sent_at order is known
      now = new Date(Date.UTC(2026, 7, 17, 9, i));
      seeded.push(await mail.send(T1, { from, text: 't', ...input }));
    }
    // a scheduled (unsent) one, newest
    now = new Date(Date.UTC(2026, 7, 17, 9, 10));
    seeded.push(
      await mail.send(T1, {
        from,
        to: 'ada@example.org',
        subject: 'Later',
        text: 't',
        scheduledAt: new Date(now.getTime() + 3_600_000),
      }),
    );
    // another tenant's message with a matching subject
    await mail.send(T2, {
      from: 'x@tenant-search-other.example',
      to: 'ada@example.org',
      subject: 'Order #100 confirmed',
      text: 't',
    });
  });

  const subjects = (r: { messages: Message[] }) => r.messages.map((m) => m.subject);

  it('is scoped to the tenant and newest first', async () => {
    const r = await mail.search({ tenantId: T1 });
    assert.deepEqual(subjects(r), [
      'Later',
      'Password reset',
      '50% off_everything',
      'Weekly digest',
      'Order #101 confirmed',
      'Order #100 confirmed',
    ]);
    assert.equal(r.nextCursor, null);
    assert.ok(r.messages.every((m) => m.tenantId === T1));
  });

  it('filters by recipient, subject substring (LIKE-escaped), tags, status and time windows', async () => {
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, to: 'ada@Example.ORG' })).sort(), [
      'Later',
      'Order #100 confirmed',
      'Password reset',
      'Weekly digest',
    ]);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, to: 'carol@example.org' })), ['Weekly digest']);
    await assert.rejects(mail.search({ tenantId: T1, to: 'not an address' }), (e: unknown) =>
      MailError.hasCode(e, 'invalid_address'),
    );
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, subject: 'order #10' })), [
      'Order #101 confirmed',
      'Order #100 confirmed',
    ]);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, subject: '50% off_' })), ['50% off_everything']);
    assert.deepEqual(
      subjects(await mail.search({ tenantId: T1, subject: '5_% off' })),
      [],
      '_ is literal, not a wildcard',
    );
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, subject: '%' })), ['50% off_everything']);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, tag: { kind: 'order' } })), [
      'Order #101 confirmed',
      'Order #100 confirmed',
    ]);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, tag: { kind: 'order', region: 'us' } })), [
      'Order #101 confirmed',
    ]);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, tag: { region: 'apac' } })), []);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, status: 'scheduled' })), ['Later']);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, status: ['scheduled', 'sent'] })).length, 6);
    // sent window: 09:01 <= sent_at < 09:03 → #101 and the digest; the scheduled one never matches
    const sent = await mail.search({
      tenantId: T1,
      sentAfter: new Date(Date.UTC(2026, 7, 17, 9, 1)),
      sentBefore: new Date(Date.UTC(2026, 7, 17, 9, 3)),
    });
    assert.deepEqual(subjects(sent), ['Weekly digest', 'Order #101 confirmed']);
    assert.deepEqual(
      subjects(await mail.search({ tenantId: T1, sentAfter: new Date(0) })).length,
      5,
      'unsent excluded',
    );
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, createdAfter: seeded[4]!.createdAt })), [
      'Later',
      'Password reset',
    ]);
    assert.deepEqual(subjects(await mail.search({ tenantId: T1, createdBefore: seeded[1]!.createdAt })), [
      'Order #100 confirmed',
    ]);
    // combined
    assert.deepEqual(
      subjects(await mail.search({ tenantId: T1, to: 'ada@example.org', tag: { kind: 'order' }, status: 'sent' })),
      ['Order #100 confirmed'],
    );
  });

  it('pages with an opaque keyset cursor, stable across inserts, and refuses a cursor that is not its own', async () => {
    const all = subjects(await mail.search({ tenantId: T1 }));
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const r: { messages: Message[]; nextCursor: string | null } = await mail.search(
        { tenantId: T1 },
        { limit: 2, cursor },
      );
      assert.ok(r.messages.length <= 2);
      seen.push(...subjects(r));
      cursor = r.nextCursor;
      pages += 1;
      // a newer message arriving between pages does not shift the next page
      if (pages === 1) {
        now = new Date(Date.UTC(2026, 7, 17, 9, 30));
        await mail.send(T1, { from: 'a@tenant-search.example', to: 'zed@example.org', subject: 'Newer', text: 't' });
      }
    } while (cursor);
    assert.deepEqual(seen, all);
    assert.equal(pages, 3, 'exactly-full last page reports no cursor without a fourth round trip');
    assert.match(cursor ?? '', /^$/);
    // an exactly-full page still knows it is last
    const exact = await mail.search({ tenantId: T1, status: 'scheduled' }, { limit: 1 });
    assert.equal(exact.messages.length, 1);
    assert.equal(exact.nextCursor, null);
    // limit is clamped, cursor validated
    assert.equal((await mail.search({ tenantId: T1 }, { limit: 10_000 })).messages.length, 7);
    assert.equal((await mail.search({ tenantId: T1 }, { limit: 0 })).messages.length, 1);
    for (const bad of [
      'nope',
      Buffer.from('2026-08-17T09:00:00.000Z|not-a-uuid').toString('base64url'),
      Buffer.from('|').toString('base64url'),
      Buffer.from('garbage|00000000-0000-0000-0000-000000000000').toString('base64url'),
    ]) {
      await assert.rejects(
        mail.search({ tenantId: T1 }, { cursor: bad }),
        (e: unknown) => MailError.hasCode(e, 'invalid_input'),
        bad,
      );
    }
    // a cursor from one tenant's page applied to another just bounds by time — no leak
    const first = await mail.search({ tenantId: T1 }, { limit: 1 });
    const other = await mail.search({ tenantId: T2 }, { cursor: first.nextCursor });
    assert.ok(other.messages.every((m) => m.tenantId === T2));
  });

  it('has the indexes 004_search.sql promises', async () => {
    const rows = await h.db.query<{ indexname: string; indexdef: string }>(
      `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'mail' AND tablename = 'messages'`,
    );
    const names = rows.map((r) => r.indexname);
    for (const n of [
      'messages_to_addresses_idx',
      'messages_tags_idx',
      'messages_tenant_created_id_idx',
      'messages_tenant_sent_idx',
    ]) {
      assert.ok(names.includes(n), n);
    }
    assert.ok(!names.includes('messages_tenant_idx'), 'superseded index dropped');
    assert.match(rows.find((r) => r.indexname === 'messages_tags_idx')!.indexdef, /gin \(tags jsonb_path_ops\)/);
    assert.match(rows.find((r) => r.indexname === 'messages_to_addresses_idx')!.indexdef, /gin \(to_addresses\)/);
  });
});
