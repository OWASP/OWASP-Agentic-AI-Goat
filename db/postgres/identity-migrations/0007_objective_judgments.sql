CREATE TABLE workshop_platform.objective_judgments (
 user_id integer NOT NULL REFERENCES identity.users(id), evaluation_id uuid NOT NULL,
 workshop_key text NOT NULL, objective_id text NOT NULL, family text NOT NULL, scenario text NOT NULL,
 rubric_version text NOT NULL, evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$'),
 run_id uuid, generation integer NOT NULL, mode text, canonical_mode text,
 verdict text CHECK(verdict IN ('pass','fail','inconclusive','unavailable')),
 result_json jsonb, result_digest text,
 disposition text NOT NULL DEFAULT 'pending' CHECK(disposition IN ('pending','not_pass','awarded','already_complete','stale_generation','hidden','mode_changed')),
 created_at timestamptz NOT NULL DEFAULT now(), evaluated_at timestamptz,
 PRIMARY KEY(user_id,evaluation_id),
 FOREIGN KEY(workshop_key,objective_id) REFERENCES workshop_platform.objectives(workshop_key,objective_id),
 CHECK((verdict IS NULL AND evaluated_at IS NULL AND result_json IS NULL) OR (verdict IS NOT NULL AND evaluated_at IS NOT NULL AND result_json IS NOT NULL))
);
CREATE INDEX objective_judgments_owner ON workshop_platform.objective_judgments(user_id,created_at DESC);
GRANT SELECT,INSERT,UPDATE ON workshop_platform.objective_judgments TO dvaia_identity_runtime;
