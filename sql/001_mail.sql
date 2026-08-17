-- mail-kit schema: sending domains, messages, delivery events, suppression,
-- and outbound webhooks.
--
--   psql -v ON_ERROR_STOP=1 -f sql/001_mail.sql
--
-- Everything lives in a `mail` schema so it cannot collide with a host
-- application's tables and a `search_path` change cannot make either
-- ambiguous — the sibling boundary identity-kit's `identity`, tenant-kit's
-- `tenancy` and billing-kit's `billing` schemas draw.
--
-- Every table carries `tenant_id text`. It is opaque here — tenant-kit's
-- TenantId when tenant-kit is present, any constant otherwise — and it is the
-- column tenant-kit's row-level-security policies key on, so protecting these
-- tables is `tenancy.protect('mail.messages')` and nothing more.
--
-- Re-runnable: every statement is guarded.

CREATE SCHEMA IF NOT EXISTS mail;

DO $$
BEGIN
  IF current_setting('server_version_num')::integer < 130000 THEN
    RAISE EXCEPTION 'mail-kit requires PostgreSQL 13 or newer (gen_random_uuid)';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mail.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- A sending domain. `name` is unique across tenants: a domain is one sending
-- identity at the transport (SES holds one per account) and DNS proves control
-- once. `signing` records who holds the DKIM key — the transport, or mail-kit
-- (`dkim_private_key` is then AES-256-GCM sealed under config.dkimKey; the
-- database never sees the plaintext). `records` is the checklist the host
-- publishes; `last_check` is what DNS said about each, for the dashboard.
CREATE TABLE IF NOT EXISTS mail.domains (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        text        NOT NULL,
  name             text        NOT NULL,
  status           text        NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'verified', 'failed')),
  signing          text        NOT NULL CHECK (signing IN ('transport', 'local')),
  provider_ref     text,
  dkim_selector    text,
  dkim_public_key  text,
  dkim_private_key text,
  return_path_host text,
  records          jsonb       NOT NULL DEFAULT '[]'::jsonb,
  last_check       jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  verified_at      timestamptz,
  last_checked_at  timestamptz,
  CONSTRAINT domains_name_unique UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS domains_tenant_idx ON mail.domains (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS domains_pending_idx ON mail.domains (last_checked_at) WHERE status = 'pending';

DROP TRIGGER IF EXISTS domains_touch_updated_at ON mail.domains;
CREATE TRIGGER domains_touch_updated_at
  BEFORE UPDATE ON mail.domains
  FOR EACH ROW EXECUTE FUNCTION mail.touch_updated_at();

-- A message. `payload` is the normalised send input (recipients, subject,
-- bodies, attachments as base64), kept so a retry rebuilds the same MIME and a
-- dashboard can show what was sent. `content_hash` is what an idempotency key
-- is compared against: same key + same hash → the original row; same key +
-- different hash → conflict. `provider_message_id` is what delivery events
-- key on; it is indexed, not unique, because a memory transport in a test may
-- legitimately repeat one and the transport, not the schema, owns uniqueness.
CREATE TABLE IF NOT EXISTS mail.messages (
  id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             text        NOT NULL,
  domain_id             uuid        REFERENCES mail.domains (id) ON DELETE SET NULL,
  status                text        NOT NULL
                                    CHECK (status IN ('queued', 'scheduled', 'sent', 'delivered', 'delayed',
                                                      'bounced', 'complained', 'failed', 'suppressed', 'canceled')),
  from_address          text        NOT NULL,
  to_addresses          text[]      NOT NULL,
  cc_addresses          text[]      NOT NULL DEFAULT '{}',
  bcc_addresses         text[]      NOT NULL DEFAULT '{}',
  subject               text        NOT NULL,
  message_id            text        NOT NULL,
  provider_message_id   text,
  payload               jsonb       NOT NULL,
  content_hash          text        NOT NULL,
  tags                  jsonb       NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key       text,
  attempts              integer     NOT NULL DEFAULT 0,
  last_error            text,
  next_attempt_at       timestamptz,
  suppressed_recipients text[]      NOT NULL DEFAULT '{}',
  scheduled_at          timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  sent_at               timestamptz,
  CONSTRAINT messages_idempotency_unique UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS messages_tenant_idx ON mail.messages (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messages_provider_id_idx ON mail.messages (provider_message_id);
CREATE INDEX IF NOT EXISTS messages_message_id_idx ON mail.messages (message_id);
-- The worker's queue: what is due. Partial, so it stays small however large the log.
CREATE INDEX IF NOT EXISTS messages_due_idx ON mail.messages (next_attempt_at)
  WHERE status IN ('queued', 'scheduled');

DROP TRIGGER IF EXISTS messages_touch_updated_at ON mail.messages;
CREATE TRIGGER messages_touch_updated_at
  BEFORE UPDATE ON mail.messages
  FOR EACH ROW EXECUTE FUNCTION mail.touch_updated_at();

-- What happened to a message after it left. One row per event; the message's
-- `status` is the current summary, the events are the history. `message_id`
-- is nullable so an event for a message we cannot match (a provider id from
-- before this database existed) is still kept, with the raw payload, rather
-- than dropped on the floor.
CREATE TABLE IF NOT EXISTS mail.events (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id          uuid        REFERENCES mail.messages (id) ON DELETE CASCADE,
  tenant_id           text,
  type                text        NOT NULL,
  recipient           text,
  provider_message_id text,
  occurred_at         timestamptz NOT NULL,
  detail              jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS events_message_idx ON mail.events (message_id, occurred_at);
CREATE INDEX IF NOT EXISTS events_tenant_idx ON mail.events (tenant_id, occurred_at DESC);

-- Addresses not to send to. `tenant_id` NULL is the global list — a complaint
-- from any tenant's send lands there, because the mailbox provider's memory of
-- it is not per-tenant either. Uniqueness treats NULL as a value, via the
-- COALESCE index, so a global entry cannot be duplicated.
CREATE TABLE IF NOT EXISTS mail.suppressions (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  text,
  address    text        NOT NULL,
  reason     text        NOT NULL CHECK (reason IN ('bounce', 'complaint', 'unsubscribe', 'manual')),
  detail     text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS suppressions_scope_address_idx
  ON mail.suppressions (COALESCE(tenant_id, ''), address);
CREATE INDEX IF NOT EXISTS suppressions_address_idx ON mail.suppressions (address);

-- Outbound webhooks. The secret is stored as written because it is what signs
-- every delivery — it is a signing key, not a credential someone presents, so
-- hashing it would leave nothing to sign with. Rotate by creating a new
-- subscription. Deliveries are the queue and the audit trail in one table.
CREATE TABLE IF NOT EXISTS mail.webhook_subscriptions (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  text        NOT NULL,
  url        text        NOT NULL,
  secret     text        NOT NULL,
  events     text[]      NOT NULL,
  enabled    boolean     NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webhook_subscriptions_tenant_idx ON mail.webhook_subscriptions (tenant_id);

CREATE TABLE IF NOT EXISTS mail.webhook_deliveries (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id  uuid        NOT NULL REFERENCES mail.webhook_subscriptions (id) ON DELETE CASCADE,
  tenant_id        text        NOT NULL,
  event_type       text        NOT NULL,
  payload          jsonb       NOT NULL,
  status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
  attempts         integer     NOT NULL DEFAULT 0,
  last_status_code integer,
  last_error       text,
  next_attempt_at  timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  delivered_at     timestamptz
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx ON mail.webhook_deliveries (next_attempt_at)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS webhook_deliveries_tenant_idx ON mail.webhook_deliveries (tenant_id, created_at DESC);
