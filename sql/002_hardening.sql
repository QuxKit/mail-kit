-- mail-kit 002: hardening. Delivery-event de-duplication; what render() needs
-- to reproduce a sent message exactly.
--
--   psql -v ON_ERROR_STOP=1 -f sql/002_hardening.sql
--
-- Re-runnable: every statement is guarded. Apply after 001_mail.sql.

-- A provider redelivers notifications (SNS retries until it gets a 200; a
-- host replays a queue). Without this, every replay re-suppressed the
-- recipient and re-fired the tenant's webhooks. One row per
-- (provider id, message, type, recipient, instant); `record` inserts with
-- ON CONFLICT DO NOTHING and reports the duplicate. The message id is part
-- of the key because a provider id is only unique per transport instance
-- (the memory transport numbers from 1 every time). Partial: an event with
-- no provider id (a transport that has none) is not de-duplicated.
--
-- If this index fails to build on an existing database, duplicates are
-- already present: keep the earliest per key and drop the rest first —
--   DELETE FROM mail.events e USING mail.events d
--    WHERE e.provider_message_id = d.provider_message_id AND e.type = d.type
--      AND COALESCE(e.message_id::text, '') = COALESCE(d.message_id::text, '')
--      AND COALESCE(e.recipient, '') = COALESCE(d.recipient, '')
--      AND e.occurred_at = d.occurred_at AND e.created_at > d.created_at;
CREATE UNIQUE INDEX IF NOT EXISTS events_dedup_idx
  ON mail.events (provider_message_id, COALESCE(message_id::text, ''), type, COALESCE(recipient, ''), occurred_at)
  WHERE provider_message_id IS NOT NULL;

-- What `render` needs to give back exactly the bytes the transport was
-- handed: the multipart boundaries the builder drew, the Date header's
-- instant, and the DKIM-Signature header as signed. Written with the `sent`
-- update; NULL for messages not yet sent (render then builds fresh).
ALTER TABLE mail.messages ADD COLUMN IF NOT EXISTS rendering jsonb;
