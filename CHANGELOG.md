# Changelog

All notable changes to `@quxkit/mail-kit` are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Renderer seam: `Renderer<T>`, `RenderedContent`, `RenderedEnvelope`;
  `mail.sendRendered(tenantId, renderer, input, envelope, opts?)`;
  `docs/TEMPLATES.md` (plain function, react-email, mjml recipes).
- `sendBatch` runs with a concurrency cap (`config.batchConcurrency`,
  default 8, or `SendBatchOptions.concurrency`), results in input order;
  `mapLimit` and `DEFAULT_BATCH_CONCURRENCY` exported.
- Per-tenant send quotas: `mail.quotas.set/get/consume` (`createQuotas`,
  `QuotaLimits`, `Quota`, `ConsumeResult`), `MailConfig.quotas` default,
  `send()` → typed `quota_exceeded { tenantId, window, limit, retryAfterMs }`
  before any row is written; `sql/005_quotas.sql` (`mail.quotas`).
- `messages.search(query, page)`: filter by `to`, `subject`, `tag`, `status`,
  `sentAfter/Before`, `createdAfter/Before`; keyset paging with an opaque
  cursor (`SearchQuery`, `SearchPage`, `SearchResult`); `sql/004_search.sql`
  (GIN on `to_addresses` and `tags`, `(tenant_id, created_at, id)`, partial
  `(tenant_id, sent_at)`; drops the superseded `messages_tenant_idx`).
- Unsubscribe tokens and the RFC 8058 one-click handler:
  `mail.unsubscribe.token/url/verify/apply/handleOneClick`
  (`createUnsubscribe`); `MailConfig.unsubscribeUrl` makes `send()` set
  `List-Unsubscribe` + `List-Unsubscribe-Post` for single-recipient
  messages; `SendInput.listId`; `Suppression.listId`,
  `AddSuppressionInput.listId`, `SuppressionScope` on
  `suppression.remove/list/check`; `sql/003_unsubscribe.sql`
  (`suppressions.list_id`, scope index re-keyed); typed error
  `mail_key_required { purpose }`.
- `@quxkit/mail-kit/pg`: `pgExecutor(pool)` — the shipped node-postgres
  adapter (pinned-connection transactions, nested transactions as savepoints).
  `pg` is an optional peer dependency.
- `messages.reschedule(tenantId, id, at)` and `messages.payload(tenantId, id)`.
- Webhook URL guard (`src/ssrf.ts`): `assertWebhookUrlAllowed`,
  `forbiddenAddressReason`, `HostResolver`; `WebhooksOptions.resolve` /
  `allowInsecureHttp`; `MailConfig.allowInsecureHttp`; optional
  `DnsResolver.lookup`; `nodeLookup`; `FetchInit.redirect`.
- `assertAttachmentSafe`, `buildMimeDetailed`, `MimeInput.boundaries`.
- `enqueueWebhookDeliveries(db, …)` for hosts composing their own event path.
- `RecordedEvent.deduplicated`.
- `Rendering` type; `mail.messages.rendering` column.
- `WebhooksOptions.sealKey`; `mail.webhook_subscriptions.secret_sealed`.
- `MAX_LIST_LIMIT` (200), `MAX_BATCH` (500), `clampLimit`.
- `sql/002_hardening.sql` (event de-dup index, `messages.rendering`,
  `webhook_subscriptions.secret_sealed`).
- Typed error `webhook_url_forbidden { url, reason }`.
- `examples/quickstart`; CI on GitHub Actions (Node 20/22, Postgres 16) and
  Gitea; release workflow (`v*` tags, npm provenance); Dependabot;
  `CODEOWNERS`, `SECURITY.md`, `CONTRIBUTING.md`; Biome lint/format; c8
  coverage with thresholds; `REQUIRE_DB` for the test harness.

### Fixed
- A `cid:` (`contentId`) attachment on a message with no `html` part was
  silently dropped; it is now refused with typed `inline_needs_html
  { contentId }` at `send` (before any row) and in `buildMime`
  (`assertInlineHasHtml` exported).

### Changed
- `render()` returns exactly the bytes the transport was handed for a sent
  message (boundaries and DKIM signature stored at send time) instead of a
  fresh build.
- `events.record` writes the event, status, suppression and webhook rows in
  one transaction.
- Webhook delivery leases due rows in one committed statement and posts with
  no row lock held; posts are sent with `redirect: 'error'`.
- `list` limits are capped at 200; `deliverPending` / `verifyPending`
  batches at 500 (clamped, not rejected).
- Webhook `create` requires `https:` unless `allowInsecureHttp` is set.
- `webhooks.list` no longer selects the secret column.

### Fixed
- Replayed delivery events (SNS retries, queue replays) no longer re-suppress
  the recipient or re-fire webhooks; `record` returns the stored row with
  `deduplicated: true`.
- `unseal` refuses a malformed sealed value instead of throwing from
  `createDecipheriv`.

### Security
- Webhook endpoint URLs are resolved and refused when they point at loopback,
  RFC 1918, link-local (169.254.169.254), shared address space, 0.0.0.0/8,
  multicast/reserved, or their IPv6 equivalents (ULA, link-local, site-local,
  multicast, IPv4-mapped/NAT64) — at `create` and again before every POST.
- Attachment `filename` / `contentType` / `contentId` are refused when they
  carry CR/LF/NUL and validated against a token grammar; non-ASCII filenames
  go out as RFC 2231 `filename*=` and never raw.
- `verifySnsMessage` refuses `SignatureVersion` other than `2` (RSA-SHA256).
- Webhook subscription secrets are sealed at rest (AES-256-GCM) when
  `config.dkimKey` is set.

## [0.1.0] - 2026-08-16

### Added
- Initial release: sending domains (DNS checklist, verification, local DKIM
  signing or transport-managed identities), idempotent sends with
  suppression filtering, MIME building, scheduled sends and retries,
  delivery events, two-scope suppression, Standard-Webhooks-signed outbound
  webhooks, and SES / SMTP / memory transports.
