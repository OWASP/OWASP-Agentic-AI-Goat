-- Current-origin provenance. All application profile mutations/reset use the origin repository.
ALTER TABLE xss.profiles
  ADD COLUMN name_revision bigint NOT NULL DEFAULT 0 CHECK (name_revision >= 0),
  ADD COLUMN bio_revision bigint NOT NULL DEFAULT 0 CHECK (bio_revision >= 0),
  ADD COLUMN website_revision bigint NOT NULL DEFAULT 0 CHECK (website_revision >= 0);

CREATE TABLE xss.profile_model_origins (
  user_key text NOT NULL REFERENCES xss.profiles(user_key) ON DELETE CASCADE,
  field text NOT NULL CHECK (field IN ('name', 'bio', 'website')),
  platform_user_id integer NOT NULL CHECK (platform_user_id > 0),
  revision bigint NOT NULL CHECK (revision > 0),
  value_sha256 text NOT NULL CHECK (value_sha256 ~ '^[0-9a-f]{64}$'),
  workshop_generation bigint NOT NULL CHECK (workshop_generation >= 0),
  run_id uuid NOT NULL,
  owner_key text NOT NULL,
  durable_generation bigint NOT NULL CHECK (durable_generation >= 0),
  decision_source text NOT NULL CHECK (decision_source = 'model'),
  provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 100),
  model text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
  raw_decision_sha256 text NOT NULL CHECK (raw_decision_sha256 ~ '^[0-9a-f]{64}$'),
  observation_index integer NOT NULL CHECK (observation_index >= 0),
  written_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (user_key, field),
  UNIQUE (user_key, field, revision),
  CHECK (user_key = platform_user_id::text)
);

REVOKE ALL ON xss.profile_model_origins FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON xss.profile_model_origins TO dvaia_xss_runtime;
