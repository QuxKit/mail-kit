// A sending domain, a send, a delivery event and a webhook — end to end,
// against a real Postgres, with nothing leaving the machine.
//
//   createdb mail_kit_example
//   psql -v ON_ERROR_STOP=1 -d mail_kit_example -f ../../sql/001_mail.sql
//   psql -v ON_ERROR_STOP=1 -d mail_kit_example -f ../../sql/002_hardening.sql
//   pnpm install && pnpm start

import { createMail } from '@quxkit/mail-kit';
import { memoryTransport } from '@quxkit/mail-kit/memory';
import { pgExecutor } from '@quxkit/mail-kit/pg';
import pg from 'pg';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgres://localhost:5432/mail_kit_example',
});

const transport = memoryTransport({ manageDomains: true });
const posted: string[] = [];

// Dev only: "DNS" is a map this script fills in with the records the domain
// asks for (as if you had published them), and webhooks post to a fetch that
// just records them. In production leave `dns` and `fetch` off: node's
// resolver and the global fetch are the defaults.
const published = {
  txt: new Map<string, string[]>(),
  cname: new Map<string, string[]>(),
  mx: new Map<string, string[]>(),
};
const mail = createMail({
  db: pgExecutor(pool),
  transport,
  dns: {
    resolveTxt: async (name) => published.txt.get(name) ?? [],
    resolveCname: async (name) => published.cname.get(name) ?? [],
    resolveMx: async (name) => (published.mx.get(name) ?? []).map((exchange) => ({ exchange, priority: 10 })),
    lookup: async () => ['203.0.113.10'], // every webhook host "resolves" to a public address here
  },
  fetch: async (url, init) => {
    posted.push(`${init.method} ${url} ${init.headers['webhook-signature']}`);
    return { status: 200, headers: { get: () => null }, text: async () => '' };
  },
});

const tenantId = 'acme';

// 1. a sending domain: publish the checklist, then verify
// re-runnable: clear what a previous run left
for (const d of await mail.domains.list(tenantId)) await mail.domains.remove(tenantId, d.id);
for (const w of await mail.webhooks.list(tenantId)) await mail.webhooks.remove(tenantId, w.id);
const domain = await mail.domains.add(tenantId, { name: 'example.com' });
console.log(
  'records to publish:',
  domain.records.map((r) => `${r.type} ${r.name} -> ${r.value}`),
);
for (const r of domain.records) {
  const bucket = r.type === 'TXT' ? published.txt : r.type === 'CNAME' ? published.cname : published.mx;
  bucket.set(r.name, [...(bucket.get(r.name) ?? []), r.value]);
}
const verified = await mail.domains.verify(tenantId, domain.id);
console.log('domain status:', verified.status);

// 2. a webhook subscription
const hook = await mail.webhooks.create(tenantId, { url: 'https://hooks.example/mail', events: ['email.delivered'] });
console.log('webhook secret (shown once):', hook.secret);

// 3. send
const message = await mail.send(tenantId, {
  from: 'Acme <hello@example.com>',
  to: 'ada@example.org',
  subject: 'Welcome',
  text: 'Hello from mail-kit',
  idempotencyKey: 'welcome-ada',
});
console.log('message:', message.status, message.providerMessageId);
console.log(
  'bytes sent:',
  Buffer.from(await mail.render(tenantId, message.id))
    .toString()
    .split('\r\n')[0],
);

// 4. what came back
await mail.events.record([
  {
    type: 'delivered',
    providerMessageId: message.providerMessageId ?? '',
    recipient: 'ada@example.org',
    at: new Date(),
  },
]);
console.log('status now:', (await mail.get(tenantId, message.id))?.status);

// 5. the worker tick delivers the webhook
await mail.tick();
console.log('webhook posts:', posted);

await mail.domains.remove(tenantId, domain.id);
await pool.end();
