-- mail-kit 004: message search. The indexes `messages.search` leans on.
--
--   psql -v ON_ERROR_STOP=1 -f sql/004_search.sql
--
-- Re-runnable: every statement is guarded. Apply after 003_unsubscribe.sql.

-- Recipient lookup: `to_addresses @> ARRAY[$1]` — GIN over the text[].
CREATE INDEX IF NOT EXISTS messages_to_addresses_idx ON mail.messages USING gin (to_addresses);

-- Tag lookup: `tags @> '{"kind":"order"}'` — jsonb_path_ops is the smaller,
-- faster GIN for containment, which is the only operator search uses.
CREATE INDEX IF NOT EXISTS messages_tags_idx ON mail.messages USING gin (tags jsonb_path_ops);

-- Keyset paging orders by (created_at DESC, id DESC) within a tenant; the id
-- breaks ties so a page boundary between two rows created in the same
-- microsecond is stable. Supersedes messages_tenant_idx from 001, which is
-- a prefix of this one and is dropped to save the write.
CREATE INDEX IF NOT EXISTS messages_tenant_created_id_idx ON mail.messages (tenant_id, created_at DESC, id DESC);
DROP INDEX IF EXISTS mail.messages_tenant_idx;

-- A "sent between" window. Partial: unsent rows have no sent_at and are
-- excluded by the filter anyway.
CREATE INDEX IF NOT EXISTS messages_tenant_sent_idx ON mail.messages (tenant_id, sent_at DESC)
  WHERE sent_at IS NOT NULL;
