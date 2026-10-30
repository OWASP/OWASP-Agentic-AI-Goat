-- Existing immutable mail receipts retain their originally assigned Message-ID.
ALTER TABLE mcp.mail_intents DROP CONSTRAINT mail_intents_assigned_message_id_check;
ALTER TABLE mcp.mail_intents ADD CONSTRAINT mail_intents_assigned_message_id_check
  CHECK (assigned_message_id ~ '^mcp-[a-f0-9-]{36}@(owasp-ai-goat|dvaia)\.local$');
