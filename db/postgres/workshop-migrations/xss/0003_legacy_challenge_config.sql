-- Isolated, intentionally mutable classic challenge configuration. Missing row defaults disabled.
CREATE TABLE xss.legacy_challenge_config (
  config_key text PRIMARY KEY,
  config_value text,
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
GRANT SELECT,INSERT,UPDATE,DELETE ON xss.legacy_challenge_config TO dvaia_xss_runtime;
