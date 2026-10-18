CREATE TABLE workshop_platform.activity_counters (
  user_id integer NOT NULL,
  workshop_key text NOT NULL,
  activity_key text NOT NULL CHECK(activity_key ~ '^[a-z][a-z0-9_-]{0,99}$'),
  activity_count integer NOT NULL DEFAULT 0 CHECK(activity_count >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(user_id,workshop_key,activity_key),
  FOREIGN KEY(user_id,workshop_key)
    REFERENCES workshop_platform.user_state(user_id,workshop_key)
    ON DELETE CASCADE
);

GRANT SELECT,INSERT,UPDATE,DELETE ON workshop_platform.activity_counters TO dvaia_identity_runtime;
