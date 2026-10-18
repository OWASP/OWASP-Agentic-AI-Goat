CREATE TABLE identity.email_verification_tokens (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
 token_hash text UNIQUE NOT NULL CHECK(token_hash ~ '^[a-f0-9]{64}$'),expires_at timestamptz NOT NULL,used boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE identity.system_config (
 config_key text PRIMARY KEY,config_value text NOT NULL,config_type text NOT NULL DEFAULT 'string',is_public boolean NOT NULL DEFAULT false
);
INSERT INTO identity.system_config(config_key,config_value,config_type) VALUES
 ('allow_registration','true','boolean'),('workshop_signup_random_email_enabled','false','boolean'),('enable_rate_limiting','false','boolean') ON CONFLICT DO NOTHING;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity.email_verification_tokens TO dvaia_identity_runtime;
GRANT SELECT,INSERT,UPDATE ON identity.system_config TO dvaia_identity_runtime;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA identity TO dvaia_identity_runtime;
