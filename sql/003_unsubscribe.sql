-- mail-kit 003: unsubscribe scope. A suppression may be scoped to a list
-- within a tenant, so "unsubscribe from the newsletter" does not also stop
-- the tenant's receipts.
--
--   psql -v ON_ERROR_STOP=1 -f sql/003_unsubscribe.sql
--
-- Re-runnable: every statement is guarded. Apply after 002_hardening.sql.

-- `list_id` NULL is the tenant-wide (or, with tenant_id NULL, global) entry
-- that every send checks; a non-NULL list_id applies only to sends that name
-- the same `listId`. Uniqueness treats both NULLs as values via COALESCE, as
-- the tenant scope already did — one row per (scope, list, address).
ALTER TABLE mail.suppressions ADD COLUMN IF NOT EXISTS list_id text;

DROP INDEX IF EXISTS mail.suppressions_scope_address_idx;
CREATE UNIQUE INDEX IF NOT EXISTS suppressions_scope_list_address_idx
  ON mail.suppressions (COALESCE(tenant_id, ''), COALESCE(list_id, ''), address);
