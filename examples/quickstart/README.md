# mail-kit quickstart

Runs the whole loop — domain, webhook, send, delivery event, worker tick —
against a local Postgres, through the memory transport. Nothing leaves the
machine.

```sh
# from the repo root: build the library the example links to
pnpm install && pnpm build

# a database with the schema
createdb mail_kit_example
psql -v ON_ERROR_STOP=1 -d mail_kit_example -f sql/001_mail.sql
psql -v ON_ERROR_STOP=1 -d mail_kit_example -f sql/002_hardening.sql

# run it
cd examples/quickstart
pnpm install
pnpm start                       # DATABASE_URL=postgres://... to point elsewhere
```

`@quxkit/mail-kit` resolves to the repo root via `link:../..`, so rebuild
(`pnpm build` at the root) after changing `src/`.
