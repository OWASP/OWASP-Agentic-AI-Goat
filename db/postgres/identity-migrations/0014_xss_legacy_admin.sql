CREATE TABLE workshop_platform.xss_legacy_solution_visibility (
 challenge_id text PRIMARY KEY CHECK(challenge_id IN ('reflected','stored_user','stored_llm','email')),
 solutions_enabled boolean NOT NULL DEFAULT false,
 enabled_by integer REFERENCES identity.users(id) ON DELETE SET NULL,
 enabled_at timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workshop_platform.xss_legacy_solutions (
 challenge_id text PRIMARY KEY CHECK(challenge_id IN ('reflected','stored_user','stored_llm','email')),
 title text NOT NULL,
 difficulty text,
 hints text,
 examples text,
 approach text,
 tips text,
 updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON workshop_platform.xss_legacy_solution_visibility,
 workshop_platform.xss_legacy_solutions FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON workshop_platform.xss_legacy_solution_visibility,
 workshop_platform.xss_legacy_solutions TO dvaia_identity_runtime;
