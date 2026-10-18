CREATE SCHEMA session_disclosure;
REVOKE ALL ON SCHEMA session_disclosure FROM PUBLIC;
CREATE TABLE session_disclosure.labs (
  platform_owner_id bigint PRIMARY KEY CHECK(platform_owner_id > 0),
  generation bigint NOT NULL CHECK(generation >= 1),
  lab_session_id uuid NOT NULL UNIQUE,
  lab_cookie text NOT NULL UNIQUE CHECK(lab_cookie ~ '^dvaia_lab_[A-Za-z0-9_-]{43}$'),
  csrf_token text NOT NULL CHECK(csrf_token ~ '^[A-Za-z0-9_-]{32}$'),
  lab_user_id text NOT NULL UNIQUE CHECK(lab_user_id ~ '^lab-[0-9a-f-]{36}$'),
  lab_role text NOT NULL CHECK(lab_role = 'lab_admin'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(updated_at >= created_at)
);
GRANT USAGE ON SCHEMA session_disclosure TO dvaia_session_disclosure_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON session_disclosure.labs TO dvaia_session_disclosure_runtime;
