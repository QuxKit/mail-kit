-- mail-kit 005: per-tenant send quotas.
--
--   psql -v ON_ERROR_STOP=1 -f sql/005_quotas.sql
--
-- Re-runnable: every statement is guarded. Apply after 004_search.sql.

-- Two token buckets per tenant — a minute's worth and a day's worth — that
-- refill continuously (per_minute/60 tokens a second, per_day/86400) up to
-- their capacity, so a tenant may burst to the limit and then run at the
-- rate. `refilled_at` is when the stored token counts were last true; the
-- current count is derived from it on read, so nothing runs on a timer.
--
-- `custom` false means the limits are the host's config default at the time
-- of the check (per_minute/per_day are ignored); `quotas.set` turns it on
-- with explicit limits, NULL meaning "no limit" for that bucket, and
-- `quotas.set(tenantId, null)` turns it off again. Rows are created lazily
-- on the first send that has a limit to enforce.
CREATE TABLE IF NOT EXISTS mail.quotas (
  tenant_id     text             PRIMARY KEY,
  custom        boolean          NOT NULL DEFAULT false,
  per_minute    integer          CHECK (per_minute IS NULL OR per_minute >= 1),
  per_day       integer          CHECK (per_day IS NULL OR per_day >= 1),
  minute_tokens double precision NOT NULL,
  day_tokens    double precision NOT NULL,
  refilled_at   timestamptz      NOT NULL,
  updated_at    timestamptz      NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS quotas_touch_updated_at ON mail.quotas;
CREATE TRIGGER quotas_touch_updated_at
  BEFORE UPDATE ON mail.quotas
  FOR EACH ROW EXECUTE FUNCTION mail.touch_updated_at();
