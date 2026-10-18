-- SecureShop v2 M4 admin additions — applied against secureshop.db.
--
-- run-all.js applies this file idempotently via extra_schemas +
-- runSchemaIdempotentWithDir(); the runner swallows "duplicate column name"
-- from ALTER TABLE ADD COLUMN so re-runs stay safe.

-- shop_users.banned_at — set by user-management.ban to soft-mark accounts.
-- NULL means active.
ALTER TABLE shop_users ADD COLUMN banned_at DATETIME;
