# Security policy

`@quxkit/mail-kit` builds and sends mail, verifies provider callbacks, and
posts signed webhooks to URLs your tenants choose. Those are the places a
mistake matters, so reports are welcome and taken seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (current) | yes |
| earlier | no |

Fixes land on `main` and ship in the next patch release; there are no
long-lived maintenance branches at this stage.

## Reporting a vulnerability

Please report privately — not in a public issue or pull request.

- **GitHub:** open a private report through
  [Security Advisories](https://github.com/QuxKit/mail-kit/security/advisories/new)
  on the repository.
- **The forge:** if you have access to the maintainers' Gitea, open a
  confidential issue addressed to the repository owner (`brett`).

Include what you found, how to reproduce it, and what you think the impact
is. You will get an acknowledgement within 3 business days and a fix or a
plan within 14. Coordinated disclosure: we ask for up to **90 days** from
acknowledgement before public disclosure, and will credit you in the
changelog unless you prefer otherwise.

## Scope

In scope — anything in this library:

- header injection through any input that reaches a MIME header;
- webhook URL guard bypasses (SSRF): a URL that reaches loopback, private,
  link-local or metadata addresses, or a redirect that does;
- webhook signature or SNS signature verification bypasses;
- DKIM signing/verification errors that let a message verify when it should
  not, or vice versa;
- key/secret handling (DKIM private keys, webhook secrets) at rest or in
  logs;
- tenant isolation: one tenant reading or acting on another's rows through
  this API;
- SQL injection, or any query that trusts an untrusted value.

Out of scope:

- the security of Amazon SES, your SMTP relay, or your DNS provider;
- issues that require a malicious `SqlExecutor`, `MailTransport`, `fetch` or
  `DnsResolver` to be injected by the host — those are trusted seams;
- deliverability outcomes (spam folder placement, provider reputation);
- DNS rebinding between the guard's lookup and the HTTP client's connect —
  documented in `src/ssrf.ts`; hosts whose threat model includes it should
  pin the checked address in the `fetch` they inject.
