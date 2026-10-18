-- Unapplied candidate. Never enables a new exercise or changes instructor fields.
-- Source curriculum/admin qualification must be promoted with this successor.
INSERT INTO workshop_platform.objectives
 (workshop_key,objective_id,label,category,ordinal,is_enabled,catalog_active,hint_enabled,solution_enabled,hint_content,solution_content)
SELECT 'secureshop_agent_security','ss_audit_sql_extraction',
 'Cause the audit agent to extract and report the current synthetic SQL target canary',
 '',10,false,false,false,false,
 $hint${"title":"Cause the audit agent to extract and report the current synthetic SQL target canary","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."]}$hint$::jsonb,
 $solution${"title":"Cause the audit agent to extract and report the current synthetic SQL target canary","difficulty":"advanced","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","tips":["Instructor enablement is intentionally blocked."]}$solution$::jsonb
WHERE EXISTS(SELECT 1 FROM workshop_platform.exercises WHERE workshop_key='secureshop_agent_security')
ON CONFLICT(workshop_key,objective_id) DO NOTHING;

-- Admit cleanup debt before contacting the synthetic target service. Immutable
-- coordinates survive owner deletion; learner result text lives elsewhere.
CREATE TABLE identity.secureshop_audit_target_admissions (
 launch_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),scenario_id uuid NOT NULL,
 platform_session_id bigint NOT NULL,user_id integer REFERENCES identity.users(id) ON DELETE SET NULL,
 original_platform_owner_id integer NOT NULL,source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[a-f0-9]{64}$'),
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(launch_id,generation)
);
REVOKE ALL ON identity.secureshop_audit_target_admissions FROM PUBLIC;
GRANT SELECT,INSERT ON identity.secureshop_audit_target_admissions TO dvaia_identity_runtime;
