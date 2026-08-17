# Contributing

Thanks for looking. mail-kit is a small library with strong opinions; the
easiest contribution to land is one that keeps it that way.

## Setup

```sh
git clone https://github.com/QuxKit/mail-kit.git && cd mail-kit
pnpm install
createdb mail_kit_test              # the store-backed tests run real SQL
pnpm test                           # unit suites + the DB suite
```

Node >= 20.19 and PostgreSQL >= 13. Point at another database with
`MAIL_KIT_TEST_DATABASE_URL=postgres://…`. Without a reachable database the
DB suite is skipped locally; set `REQUIRE_DB=1` (CI does) to make that a
failure instead. The harness rebuilds the `mail` schema from `sql/*.sql` on
every run.

## Scripts

| Script | What |
|---|---|
| `pnpm lint` | Biome (lint + format check) |
| `pnpm format` | Biome, writing |
| `pnpm typecheck` | `tsc --noEmit` |
| `pnpm build` | tsup → `dist/` (ESM + CJS + d.ts) |
| `pnpm test` | every `test/*.test.ts` |
| `pnpm test:coverage` | the same under c8, with thresholds |
| `pnpm check:harness` | the test harness imports without a database |

Run `pnpm lint && pnpm typecheck && pnpm test` before pushing; CI runs the
same set (plus build and coverage) on Node 20 and 22 against Postgres 16.

## How work lands

1. **Open an issue first**, saying what is wrong or missing — the problem,
   not the solution.
2. **Branch from `main`**, named for the issue: `fix/42-thing`,
   `feat/17-thing`, `chore/23-thing`.
3. Commit in logical steps, conventional-commit style subjects
   (`fix(webhooks): …`, `feat: …`, `docs: …`, `test: …`, `style: …`).
   Every behavioural change ships with a test that fails before and passes
   after.
4. **Open a pull request** whose body starts with `Closes #N`. Nothing lands
   on `main` directly.

## Ground rules

- No new runtime dependencies without a discussion in the issue. The
  library currently has none (`pg` is an optional peer).
- Errors are `MailError` with a code from the `MailFailure` union — add to
  the union and to the README's errors section, never throw a bare string.
- Nothing reads `process.env`; configuration is an argument.
- Schema changes are new numbered files under `sql/`, re-runnable, guarded.
- Keep README diagrams ASCII; mermaid lives in `docs/DIAGRAMS.md`.
- Public API changes are additive within a minor version.

## Releasing

Maintainers tag `vX.Y.Z` on `main`; the release workflow verifies, builds
and publishes to npm with provenance. Update `CHANGELOG.md` (move
`[Unreleased]` under the new version) in the same change as the version bump.
