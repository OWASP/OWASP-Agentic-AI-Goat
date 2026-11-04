-- Enable the SecureShop playground by default on a fresh install. The admin
-- "OWASP AI SecureShop Playground" toggle reads/writes the secureshop_visible
-- system_config key; the student landing page surfaces it via the public
-- feature-flags endpoint, so the row must be is_public=true. Seeded here because
-- 0003_account_flows.sql (checksum-locked) omitted it, which read as disabled.
-- ON CONFLICT DO NOTHING preserves any value an existing install's admin already set.
INSERT INTO identity.system_config(config_key,config_value,config_type,is_public) VALUES
 ('secureshop_visible','true','boolean',true) ON CONFLICT (config_key) DO NOTHING;
