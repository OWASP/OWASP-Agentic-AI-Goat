ALTER TABLE workshop_platform.objective_judgments ADD COLUMN mode_stamp text;
CREATE TABLE workshop_platform.grade_packets (
 user_id integer NOT NULL,
 evaluation_id uuid NOT NULL,
 packet text,
 judge_version text NOT NULL,
 owner_key text,
 owner_generation text,
 mode_stamp text NOT NULL,
 child_evaluation_id uuid,
 retry_invocations integer NOT NULL DEFAULT 0 CHECK(retry_invocations BETWEEN 0 AND 3),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
 PRIMARY KEY(user_id,evaluation_id),
 FOREIGN KEY(user_id,evaluation_id) REFERENCES workshop_platform.objective_judgments(user_id,evaluation_id),
 CHECK(packet IS NULL OR octet_length(packet)<=24000)
);
GRANT SELECT,INSERT,UPDATE,DELETE ON workshop_platform.grade_packets TO dvaia_identity_runtime;
CREATE INDEX grade_packets_expiry ON workshop_platform.grade_packets(expires_at);
