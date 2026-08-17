-- mail-kit 002: hardening. Delivery-event de-duplication; what render() needs
-- to reproduce a sent message exactly; webhook secrets sealed at rest.
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

-- Webhook secrets sealed at rest under config.dkimKey (AES-256-GCM, the same
-- key path as DKIM private keys). New rows carry `secret_sealed` and a NULL
-- `secret` when a key is configured; rows from before (or without a key)
-- keep `secret`. Delivery reads whichever is set, so the key can be
-- introduced on a live database. To seal existing rows, recreate the
-- subscriptions (secrets are shown once; a re-seal cannot be done in SQL
-- because the key is not in the database, by design).
ALTER TABLE mail.webhook_subscriptions ADD COLUMN IF NOT EXISTS secret_sealed text;
ALTER TABLE mail.webhook_subscriptions ALTER COLUMN secret DROP NOT NULL;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'webhook_subscriptions_secret_present' AND conrelid = 'mail.webhook_subscriptions'::regclass
  ) THEN
    ALTER TABLE mail.webhook_subscriptions
      ADD CONSTRAINT webhook_subscriptions_secret_present CHECK (secret IS NOT NULL OR secret_sealed IS NOT NULL);
  END IF;
END;
$$;
