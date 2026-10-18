-- SecureShop v2 M14 — Role-based Access Control (RBAC) schema.
--
-- Applies to secureshop_agents.db (tool_permissions, system_config additions,
-- agent_trace.policy_violation column). All CREATE TABLE statements are
-- idempotent via IF NOT EXISTS; the ALTER TABLE for policy_violation is
-- swallowed by run-all.js's "duplicate column name" guard.
--
-- Design (see docs/secureshop/ARCHITECTURE.md and docs/secureshop/VULNERABILITIES.md):
--
--   tool_permissions — canonical ACL. One row per (tool_name, role). The
--     supervisor consults this table BEFORE dispatching a tool_use. When
--     system_config.enforce_tool_acl = 'true' the supervisor refuses the
--     call and stamps agent_trace.policy_violation='blocked'. When 'false',
--     the call goes through (LLM06 in action) but the trace is annotated
--     with policy_violation='denied-by-acl' so the AgentLane can render the
--     red PolicyViolationBadge — the marquee teachable moment.
--
--   system_config — key/value bag for supervisor-wide toggles. First key:
--     enforce_tool_acl. Admin can toggle via /api/secureshop/admin/system-config.
--
--   agent_trace.policy_violation — null when the call was allowed, string
--     otherwise. See values above.

CREATE TABLE IF NOT EXISTS tool_permissions (
  tool_name TEXT NOT NULL,       -- '<agent_ns>.<tool>' e.g. 'user-management.set_role'
  role TEXT NOT NULL,            -- 'customer' | 'merchant' | 'admin'
  allowed INTEGER NOT NULL DEFAULT 0,
  reason TEXT,                   -- optional description shown in admin UI
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tool_name, role)
);

CREATE INDEX IF NOT EXISTS idx_tool_permissions_role ON tool_permissions(role);
CREATE INDEX IF NOT EXISTS idx_tool_permissions_tool ON tool_permissions(tool_name);

CREATE TABLE IF NOT EXISTS system_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_by TEXT
);

-- Seed the enforcement toggle to 'false' by default. This preserves the
-- LLM06/LLM04-like "layer B advisory only" teaching surface out of the box;
-- an admin flips it to 'true' via the Access Control page to enable
-- blocking mode.
INSERT OR IGNORE INTO system_config (key, value, updated_by)
  VALUES ('enforce_tool_acl', 'false', 'seed');

-- Additive column on agent_trace. Run-all.js's ALTER-guard swallows the
-- "duplicate column name" error on re-apply.
ALTER TABLE agent_trace ADD COLUMN policy_violation TEXT;
