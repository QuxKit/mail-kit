# @quxkit/mail-kit

<img src="https://raw.githubusercontent.com/QuxKit/quxkit-brand/main/mail-kit/sizes/mail-kit-128.png" width="76" align="right" alt="">

**QuxKit** · ruby stone · sending domains, sends, delivery events, suppression, webhooks

![status](https://img.shields.io/badge/status-shipped-2ea043) ![licence](https://img.shields.io/badge/licence-Apache--2.0-d6a94b) ![npm](https://img.shields.io/badge/npm-%40quxkit%2Fmail--kit-cb3837)

Transactional email as a library, for the app you already run — over a
transport you choose.

```
 send(tenantId, { from, to, subject, html })            your app
   │                                                    ────────
   ▼                                                    your database
 ┌────────────────────────────────────────────┐         (mail schema)
 │  domains      DNS checklist · verify       │  SqlExecutor  ▲
 │               DKIM key when nobody else    │───────────────┘
 │               holds one                    │
 │  messages     validate · idempotency key   │  MailTransport
 │               drop suppressed · MIME       │───────────────▶  ses · smtp · memory
 │               sign · queue · retry         │                  (or your own)
 │  events       delivered · bounced …        │◀ ─ ─ ─ ─ ─ ─ ─   DeliveryEvent
 │       └──▶ suppression   tenant + global   │
 │       └──▶ webhooks      signed · retried  │  fetch
 │                                            │───────────────▶  your customer's endpoint
 └────────────────────────────────────────────┘
   @quxkit/mail-kit — Apache-2.0
```

_Rendered diagrams (mermaid): [docs/DIAGRAMS.md](https://github.com/QuxKit/mail-kit/blob/main/docs/DIAGRAMS.md)._

mail-kit owns the framed box: what a **sending domain** is and how it is
proven, what a **send** is (idempotent, suppression-filtered, MIME-built,
DKIM-signed, queued and retried), what **came back** (delivered, bounced,
complained, opened) and what follows from that (a suppression entry, a signed
webhook to whoever asked). Your app owns the database it writes to (through a
narrow executor) and the wire it goes out on (through a transport seam).

Apache-2.0, sibling to [identity-kit](https://github.com/QuxKit/identity-kit),
[tenant-kit](https://github.com/QuxKit/tenant-kit) and
[billing-kit](https://github.com/QuxKit/billing-kit): same executor interface,
same design rules, same "library not platform" stance.

## Where it sits in the family

identity-kit composes its verification and reset mail and hands it to a
`MailSender` seam the host has to fill. This is what fills it — and what a
product built on the family sends everything else through:

```
 @quxkit/identity-kit     who you are            ──MailSender──▶  mail-kit
 @quxkit/tenant-kit       what you belong to     ──tenantId───▶   mail-kit
 @quxkit/mail-kit         what you send, and what came back
 @quxkit/billing-kit      what you owe           ◀──sends per tenant──
```

Every domain, message, suppression and webhook row carries an opaque
`tenant_id` — tenant-kit's `TenantId` when tenant-kit is present, any constant
otherwise — so `tenancy.protect('mail.messages')` isolates this schema like
any other. mail-kit has no opinion about accounts, roles or money.

## The problem it solves

Sending mail usually arrives in one of two shapes, and both put your sending
identity somewhere you don't control:

- **A hosted platform** — Resend, Postmark, SendGrid — that owns your domains,
  your logs and your webhooks, and bills per message.
- **A mail server you run** — Postal, Postfix — that you operate as a separate
  system with its own database, API and dashboard.

mail-kit is a third shape: **a library you embed.** Domains, sends, events,
suppression and webhooks compile into the app you already run, over the
Postgres you already have. The transport is a seam — Amazon SES over raw HTTP,
any SMTP relay, or your own MTA — and switching it changes nothing above it.

It is **not** an MTA and does not try to be. It does not accept mail, hold a
queue on disk, or negotiate with Gmail; SES, Postal or KumoMTA do that. This
is the layer a product needs *above* the MTA — the one every "Resend
alternative" rebuilds — done once, with clean seams.

## Quickstart

```ts
import { createMail } from '@quxkit/mail-kit';
import { pgExecutor } from '@quxkit/mail-kit/pg';
import { sesTransport } from '@quxkit/mail-kit/ses';
import pg from 'pg';

const mail = createMail({
  db: pgExecutor(new pg.Pool({ connectionString: process.env.DATABASE_URL })), // or any SqlExecutor
  config: { dkimKey: process.env.MAIL_KIT_KEY },   // 64 hex chars: seals DKIM keys and webhook secrets at rest
  transport: sesTransport({
    region: 'eu-west-1',
    credentials: { accessKeyId, secretAccessKey },
    fetch: (url, init) => fetch(url, init),
    configurationSet: (e) => `tenant-${e.tenantId}`, // one SES reputation per tenant
  }),
});

// 1. a sending domain — publish what it hands back, then verify
const domain = await mail.domains.add(tenantId, { name: 'example.com' });
domain.records; // [{ type: 'CNAME', name: 'abc._domainkey.example.com', value: 'abc.dkim.amazonses.com', … }, …]
await mail.domains.verify(tenantId, domain.id); // → status 'verified' once DNS (and SES) agree

// 2. send — the row is written first, then the transport is called
const message = await mail.send(tenantId, {
  from: 'Acme <hello@example.com>',
  to: 'ada@example.org',
  subject: 'Your invoice',
  html: '<p>…</p>',
  idempotencyKey: 'invoice-1042',
});
message.status; // 'sent' | 'queued' (retrying) | 'suppressed' | 'failed'

// 3. what came back — wire the provider's callback to recordEvents
await mail.events.record(parseSesEvents(snsBody)); // → status, suppression, webhooks

// 4. a worker tick — due sends, due webhooks, pending domain checks
setInterval(() => mail.tick(), 5000);
```

Apply the schema first, in order:

```sh
psql -v ON_ERROR_STOP=1 -f node_modules/@quxkit/mail-kit/sql/001_mail.sql
psql -v ON_ERROR_STOP=1 -f node_modules/@quxkit/mail-kit/sql/002_hardening.sql
psql -v ON_ERROR_STOP=1 -f node_modules/@quxkit/mail-kit/sql/003_unsubscribe.sql
```

`@quxkit/mail-kit/pg` is the shipped `SqlExecutor` over a `pg.Pool` (`pg` is
an optional peer). Any other driver is the same ~30 lines: `query` and a
pinned-connection `transaction`. A runnable end-to-end example lives in
[`examples/quickstart`](examples/quickstart/README.md).

## What it does carefully

Deliverability is adversarial — mailbox providers grade you on the mistakes
you didn't know you made — so the reasoning is in the code. The load-bearing
parts:

- **The row is written before the transport is called, always.** A send is
  never lost between "the API returned" and "the mail left". Workers claim
  rows with `FOR UPDATE SKIP LOCKED` and a lease, so a crash mid-send retries
  rather than drops (at-least-once), and two workers never send one message.
- **Idempotency keys are compared by content.** Same key + same content
  returns the original message; same key + different content is a
  `idempotency_conflict`, not a second send. The unique index does the race.
- **Suppression is automatic and scoped.** A hard bounce suppresses the
  address for that tenant; a complaint suppresses it globally — the mailbox
  provider's memory of the complaint is not per-tenant either; an
  unsubscribe is scoped to the tenant or to one list within it. `send` drops
  suppressed recipients rather than failing the message, and says which.
- **Unsubscribe is a token, not a row.** `unsubscribe.token()` is an HMAC
  over (tenant, recipient, list) under the mail key; `send` writes
  `List-Unsubscribe` + `List-Unsubscribe-Post` itself, and the RFC 8058
  handler verifies and suppresses. See [Unsubscribe](#unsubscribe).
- **The From must be a verified domain the tenant holds.** Verification asks
  DNS for every required record and the transport for its view, and keeps
  reporting the recommended DMARC record it does not require. A domain whose
  records vanish goes `verified → failed`, once, with a webhook.
- **Who signs is decided, not assumed.** A transport that manages identities
  (SES) signs and hands back CNAMEs. One that does not (SMTP relay, memory)
  gets an RSA-2048 key generated here, sealed under `config.dkimKey`
  (AES-256-GCM, out of the backup), and mail-kit DKIM-signs relaxed/relaxed
  before the transport ever sees the bytes.
- **The MIME is built once, deterministically, and handed round unchanged** —
  CRLF, quoted-printable text, base64 attachments, RFC 2047 headers, inline
  `cid:` images, `List-Unsubscribe` + one-click. Header injection is refused
  (`header_injection`), not folded.
- **Webhooks are Standard-Webhooks signed** (`webhook-id`,
  `webhook-timestamp`, `webhook-signature: v1,…`) — what Resend and Svix-based
  products emit, so consumers' existing verifiers work — retried on
  5s · 5m · 30m · 2h · 5h · 10h, and kept as rows so they survive a restart
  and can be replayed. `verifyWebhookSignature` is exported for the other side.
- **SNS is verified before it is believed.** `verifySnsMessage` checks the
  signing certificate came from an `sns.<region>.amazonaws.com` https URL
  and that `SignatureVersion` is `2` (RSA-SHA256; SHA1 is refused) before
  checking the signature — the tests that turn "verified" from a formality
  into a fact.
- **A replayed event is recorded once.** SNS retries until it gets a 200 and
  hosts replay queues; the same provider id + type + recipient + instant is
  de-duplicated in the database (`ON CONFLICT DO NOTHING`), returned with
  `deduplicated: true`, and does not re-suppress or re-fire webhooks. The
  event row, status change, suppression and webhook rows commit together or
  not at all.
- **Webhook URLs are checked before they are trusted.** A tenant's endpoint
  must be `https:` (`config.allowInsecureHttp` for development), and its host
  is resolved and refused when it points at loopback, RFC 1918, link-local
  (the cloud metadata address), shared address space, multicast, or their
  IPv6 forms — at `create` and again before every POST, which is sent with
  `redirect: 'error'`. Typed as `webhook_url_forbidden`. Secrets are sealed
  at rest under `config.dkimKey`. Delivery leases a row and commits before
  posting, so a slow endpoint holds no lock.
- **`render()` gives back what was sent.** The multipart boundaries and the
  DKIM-Signature header are stored with the `sent` update, so a dashboard's
  "view source" is byte-identical to what the transport was handed — not a
  fresh build over a possibly rotated key.
- **Attachment metadata is validated**, not interpolated: CR/LF/NUL in
  `filename`, `contentType` or `contentId` is `header_injection`; `contentType`
  must be `type/subtype`; non-ASCII filenames go out as RFC 2231
  `filename*=`, never raw.
- **Pages and batches are bounded.** `list` limits cap at 200 and worker
  batches at 500 (`MAX_LIST_LIMIT`, `MAX_BATCH`), clamped rather than refused.

## What it delegates

- **The MTA** — the `MailTransport` seam. Three ship; anything with `send` is one.
- **Templates and HTML** — you pass `html`; a template layer is a product decision.
- **HTTP** — no endpoints, no framework. `send` is a function; how it is routed,
  authenticated (identity-kit's API keys) and rate-limited is the host's.
- **Marketing lists, contacts, audiences** — out of scope. Suppression is the
  one list mail-kit keeps, because it is the one deliverability depends on.
- **Inbound mail** — not yet. `dkimVerify` exists because the signer needed a
  witness; a receiving chapter is plausible later.

## Transports

Separate entry points, so an app that uses one compiles neither of the others.

### `@quxkit/mail-kit/ses` — Amazon SES v2 over HTTP

```ts
import { sesTransport, parseSesEvents, verifySnsMessage } from '@quxkit/mail-kit/ses';

const transport = sesTransport({ region, credentials, fetch, configurationSet: (e) => `tenant-${e.tenantId}` });

// the SNS endpoint your app exposes:
const sns = JSON.parse(body);
await verifySnsMessage(sns, { fetch });          // throws signature_invalid
await mail.events.record(parseSesEvents(sns));   // bounce, complaint, delivery, delay, open, click, reject
```

No SDK: SigV4 is ~80 lines, pinned to AWS's published test vectors. SES
manages the identity, so `domains.add` returns its three DKIM CNAMEs plus the
custom MAIL FROM `MX`/`TXT` (`bounce.<domain>` by default). `configurationSet`
per tenant is how one SES account keeps tenants' reputations apart.

### `@quxkit/mail-kit/smtp` — any relay

```ts
import { smtpTransport } from '@quxkit/mail-kit/smtp';

const transport = smtpTransport({ host: 'smtp.postal.example', port: 587, auth: { user, pass }, spfInclude: 'spf.postal.example' });
```

A small client (EHLO, STARTTLS — required by default — AUTH PLAIN/LOGIN,
MAIL FROM, RCPT TO, dot-stuffed DATA). Recipients a server refuses at
`RCPT TO` are recorded as hard bounces; the rest are sent. This transport
does not manage identities, so `domains.add` needs `config.dkimKey` and
mail-kit signs.

### `@quxkit/mail-kit/memory` — tests, dry runs, local dev

```ts
import { memoryTransport } from '@quxkit/mail-kit/memory';

const transport = memoryTransport({ manageDomains: true }); // SES-like, or leave off for the local-signing path
transport.sent[0].text;   // the exact bytes, for asserting on headers
transport.failNext(1, { retryable: true }); // exercise the retry path
```

### Your own

```ts
const transport: MailTransport = {
  name: 'acme-mta',
  spfInclude: 'spf.acme.example',
  async send(envelope) { /* envelope.raw is the finished, signed RFC 5322 message */ return { providerMessageId }; },
};
```

## Unsubscribe

Bulk senders to Gmail and Yahoo must carry RFC 8058 one-click unsubscribe;
mail-kit does the whole loop without a table:

```ts
const mail = createMail({
  db, transport,
  config: {
    dkimKey: process.env.MAIL_KIT_KEY,                 // keys the token
    unsubscribeUrl: 'https://app.example/u/{token}',   // where the button lands
  },
});

// send(): List-Unsubscribe + List-Unsubscribe-Post are set for you
await mail.send(tenantId, { from, to: 'ada@example.org', subject, html, listId: 'newsletter' });

// the endpoint (any framework — the shape is { method, url, headers, body })
app.post('/u/:token', async (req, res) => {
  const r = await mail.unsubscribe.handleOneClick({
    method: req.method, url: req.originalUrl, headers: req.headers, body: req.rawBody,
  });
  res.status(r.status).send(r.body);
});
```

- **The token is stateless.** `unsubscribe.token({ tenantId, recipient,
  listId? })` is `u1.<claims>.<HMAC-SHA256>` under a key derived from
  `config.dkimKey`, URL-safe, deterministic, and valid for as long as the
  key is — mailbox providers press the button months later. Nothing is
  written when it is minted; a million recipients cost a million HMACs.
  `unsubscribe.verify(token)` returns the claims or throws
  `signature_invalid`; a tampered claim, a foreign key, a padding trick or a
  fourth field all fail.
- **The handler is RFC 8058.** A `POST` whose body is
  `List-Unsubscribe=One-Click` (form-urlencoded or multipart) with a valid
  token (from `?token=`, the last path segment, or `opts.token`) adds a
  suppression with reason `unsubscribe` and answers `200`; a wrong method is
  `405`, anything else `400 invalid token` — never a reason a probe could
  learn from. Idempotent. `unsubscribe.apply(claims)` is the same write for
  a host's own confirmation page (a `GET` should show a page, not act).
- **Scope follows the token.** A send with `listId: 'newsletter'` mints a
  token naming the list, so pressing it stops the newsletter and not the
  receipts; a send without one mints a tenant-wide token. `send` checks the
  global list, the tenant's list-less entries and the message's list, in one
  query; `suppression.add/list/remove/check` take `listId`.
- **One recipient, one header.** The automatic pair is set only when the
  message has exactly one recipient left after suppression, and never when
  the caller supplies `listUnsubscribe`. A message to several people gets
  none — mint per recipient and send one message each (`sendBatch`), which
  is what a mailbox provider expects anyway.
- `unsubscribeUrl` without `dkimKey` is `mail_key_required` at the first
  send, before any row.

## The worker

`send` delivers inline by default. Scheduled sends, retries, webhook
deliveries and domain re-checks need something to run them:

```ts
setInterval(() => mail.tick(), 5000);
// or, individually:
await mail.deliverPending(50);          // due sends: queued, scheduled, retrying
await mail.webhooks.deliverPending(50); // due webhook posts
await mail.domains.verifyPending();     // pending domains not checked in 5 min
```

Every method claims its rows (`FOR UPDATE SKIP LOCKED`), so any number of
processes can call it. `send(…, { defer: true })` queues without delivering,
for a host that wants every send to go through the worker.

## Schema

Everything lives in a `mail` schema so it cannot collide with a host
application's tables. `sql/001_mail.sql` declares `domains`, `messages`,
`events`, `suppressions`, `webhook_subscriptions` and `webhook_deliveries`;
`sql/002_hardening.sql` adds the event de-duplication index,
`messages.rendering` and `webhook_subscriptions.secret_sealed`;
`sql/003_unsubscribe.sql` adds `suppressions.list_id` and re-keys the
scope index on (tenant, list, address). Files are
numbered, re-runnable and applied in order. Events and deliveries cascade
from their parents; a message keeps its history when its domain is removed.

## Errors

One class, `MailError`, carrying a discriminated union — `invalid_address`,
`header_injection`, `invalid_input`, `domain_not_verified`,
`idempotency_conflict`, `not_found`, `invalid_state`, `transport`
(with `retryable`), `dkim_key_required`, `mail_key_required` (with
`purpose`), `signature_invalid`,
`webhook_url_forbidden` (with `url` and `reason`: not https, or a host that
is or resolves to loopback / private / link-local / multicast). Narrow with
`MailError.hasCode(e, 'domain_not_verified')`; never match the message.

## Development

```sh
pnpm install
createdb mail_kit_test   # the store-backed tests exercise real SQL; they skip without a DB
pnpm lint && pnpm typecheck && pnpm test
pnpm test:coverage       # c8, with thresholds
```

The unit suites (MIME, DKIM sign/verify, SigV4 against AWS's vectors, SES
parsing and SNS verification, the SMTP client against a scripted server, the
webhook signature pair, the URL guard) run offline. The store-backed suite
runs the domain, send, event and webhook paths end to end through the memory
transport; `REQUIRE_DB=1` (set in CI) makes a missing database a failure
rather than a skip. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
issue → branch → PR flow and [SECURITY.md](SECURITY.md) for reporting.


## The QuxKit family

Libraries you embed, not services you operate. Each kit owns one narrow thing
and composes with the rest over shared shapes — one executor interface, one
opaque tenant id, one Money type.

| Package | Stone | What it owns |
|---|---|---|
| [`@quxkit/identity-kit`](https://github.com/QuxKit/identity-kit) | gold | Accounts, argon2id credentials, revocable sessions — produces a `UserId`. |
| [`@quxkit/tenant-kit`](https://github.com/QuxKit/tenant-kit) | green | Tenant directory, request→tenant resolution, row-level-security isolation. |
| [`@quxkit/mail-kit`](https://github.com/QuxKit/mail-kit) | ruby | Sending domains, idempotent sends, delivery events, suppression, signed webhooks. |
| [`@quxkit/billing-kit`](https://github.com/QuxKit/billing-kit) | blue | Metering, exact pricing, a double-entry ledger, provider settlement. |
| [`@quxkit/billing-kit-adapters`](https://github.com/QuxKit/billing-kit-adapters) | blue | Payment providers beyond Stripe and Paddle. |
| [`tenant-kit-adapters`](https://github.com/QuxKit/tenant-kit-adapters) | green | Enterprise SSO, SCIM provisioning, RBAC-engine bridges. |
| [`billing-kit-components`](https://github.com/QuxKit/billing-kit-components) | blue | shadcn-compatible billing UI, per seat. |
| [`@quxkit/billing-kit-mcp`](https://github.com/QuxKit/billing-kit-mcp) | blue | Exact money math for AI assistants over MCP. |

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`. The MIME builder, DKIM signer, SMTP
client and SigV4 signer are original implementations against their RFCs; no
provider SDK is bundled.
