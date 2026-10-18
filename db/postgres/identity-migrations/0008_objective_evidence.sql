CREATE TABLE workshop_platform.objective_evidence (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 user_id integer NOT NULL REFERENCES identity.users(id),
 workshop_key text NOT NULL REFERENCES workshop_platform.exercises(workshop_key),
 scenario text NOT NULL, generation integer NOT NULL,
 run_id uuid NOT NULL, evidence_id text NOT NULL,
 evidence_json jsonb, evidence_digest text NOT NULL,
 omitted boolean NOT NULL DEFAULT false, omission_reason text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
 UNIQUE(user_id,workshop_key,scenario,generation,evidence_id),
 CHECK(evidence_json IS NULL OR octet_length(evidence_json::text)<=32768)
);
CREATE INDEX objective_evidence_scope ON workshop_platform.objective_evidence(user_id,workshop_key,scenario,generation,id DESC);
CREATE INDEX objective_evidence_expiry ON workshop_platform.objective_evidence(expires_at);
GRANT SELECT,INSERT,DELETE ON workshop_platform.objective_evidence TO dvaia_identity_runtime;
GRANT USAGE,SELECT ON SEQUENCE workshop_platform.objective_evidence_id_seq TO dvaia_identity_runtime;
