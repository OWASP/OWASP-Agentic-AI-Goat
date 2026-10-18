-- Inactive until explicit bootstrap; no automatic ready state or route wiring.
ALTER TABLE identity.ctf_authority ADD COLUMN blocked_operation_id uuid;
ALTER TABLE identity.ctf_authority ADD CONSTRAINT ctf_blocked_operation_scope CHECK(blocked_operation_id IS NULL OR lifecycle_state='blocked');
ALTER TABLE identity.ctf_authority ADD COLUMN banned boolean NOT NULL DEFAULT false;
ALTER TABLE identity.ctf_authority ADD COLUMN adaptive_revision bigint NOT NULL DEFAULT 0 CHECK(adaptive_revision>=0);
ALTER TABLE identity.ctf_authority ADD COLUMN clear_revision bigint NOT NULL DEFAULT 0 CHECK(clear_revision>=0);
ALTER TABLE identity.ctf_authority ADD COLUMN failure_code text CHECK(octet_length(failure_code)<=128);
ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_operation_sequence UNIQUE(operation_id,sequence);
ALTER TABLE identity.ctf_outbox DROP CONSTRAINT ctf_outbox_kind_check;
ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_kind_check CHECK(kind IN
 ('decision','catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear','admit_attempt','record_blocked_attempt','register','start','hint'));
ALTER TABLE identity.ctf_outbox ADD COLUMN actor_id bigint CHECK(actor_id>0);
ALTER TABLE identity.ctf_outbox ADD COLUMN session_id bigint CHECK(session_id>0);
ALTER TABLE identity.ctf_outbox ADD COLUMN request_fingerprint text CHECK(request_fingerprint ~ '^[a-f0-9]{64}$');
ALTER TABLE identity.ctf_outbox ADD COLUMN canonical_command text CHECK(octet_length(canonical_command)<=65536);
ALTER TABLE identity.ctf_outbox ADD COLUMN canonical_result text CHECK(octet_length(canonical_result)<=16384);
ALTER TABLE identity.ctf_outbox ADD COLUMN result_hash text CHECK(result_hash ~ '^[a-f0-9]{64}$');
ALTER TABLE identity.ctf_outbox ADD COLUMN applied_at timestamptz;
ALTER TABLE identity.ctf_outbox ADD COLUMN owner_generation_after bigint CHECK(owner_generation_after>=0);
ALTER TABLE identity.ctf_outbox ADD COLUMN registration_disposition text CHECK(registration_disposition IN ('new','active_recovery','reactivate'));
ALTER TABLE identity.ctf_outbox ADD COLUMN registration_participant_before bigint CHECK(registration_participant_before BETWEEN 1 AND 2147483647);
ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_registration_prior CHECK(canonical_command IS NULL OR
 (((registration_disposition IN ('active_recovery','reactivate')) IS TRUE)=(registration_participant_before IS NOT NULL)));

ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_owner_after CHECK(canonical_command IS NULL OR
 ((command->'scope'->>'ownerId' IS NOT NULL)=(owner_generation_after IS NOT NULL)));
ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_registration_disposition CHECK(canonical_command IS NULL OR
 ((kind='register')=(registration_disposition IS NOT NULL)));

ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_generation_transition CHECK(canonical_command IS NULL OR
 (CASE WHEN command->'scope'->>'ownerId' IS NULL THEN owner_generation_after IS NULL
 ELSE owner_generation_after=(command->'scope'->>'ownerGeneration')::bigint+
  CASE WHEN kind IN ('owner_reset','owner_remove') OR (kind='register' AND registration_disposition IN ('new','reactivate')) THEN 1 ELSE 0 END END) IS TRUE);
ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_canonical_binding CHECK(canonical_command IS NULL OR
 (canonical_command::jsonb=command AND command_hash=encode(sha256(convert_to(canonical_command,'UTF8')),'hex')) IS TRUE);

ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_result_pair CHECK
 ((canonical_result IS NULL AND result_hash IS NULL) OR (canonical_result IS NOT NULL AND result_hash IS NOT NULL));

CREATE TABLE identity.ctf_participant_bindings (
 owner_id bigint PRIMARY KEY CHECK(owner_id>0), owner_generation bigint NOT NULL CHECK(owner_generation>=0),
 participant_id bigint NOT NULL UNIQUE CHECK(participant_id>0),owner_revision bigint NOT NULL CHECK(owner_revision>=0),
 global_revision bigint NOT NULL CHECK(global_revision>=0),active boolean NOT NULL,banned boolean NOT NULL,
 registered_at timestamptz NOT NULL,applied_sequence bigint NOT NULL CHECK(applied_sequence>=0),applied_operation_id uuid NOT NULL
);
CREATE TABLE identity.ctf_progress_bindings (
 owner_id bigint NOT NULL CHECK(owner_id>0),owner_generation bigint NOT NULL CHECK(owner_generation>=0),stage_id bigint NOT NULL CHECK(stage_id>0),
 participant_id bigint NOT NULL CHECK(participant_id>0),progress_id bigint NOT NULL UNIQUE CHECK(progress_id>0),
 owner_revision bigint NOT NULL CHECK(owner_revision>=0),global_revision bigint NOT NULL CHECK(global_revision>=0),stage_revision bigint NOT NULL CHECK(stage_revision>=0),
 stage_digest text NOT NULL CHECK(stage_digest ~ '^[a-f0-9]{64}$'),status text NOT NULL CHECK(status IN ('not_started','in_progress','completed')),
 started_at timestamptz,completed_at timestamptz,attempts_count integer NOT NULL CHECK(attempts_count>=0),failed_attempts integer NOT NULL CHECK(failed_attempts>=0),
 successful_attempts integer NOT NULL CHECK(successful_attempts>=0),hints_used integer NOT NULL CHECK(hints_used BETWEEN 0 AND 3),hint_penalty_total integer NOT NULL CHECK(hint_penalty_total>=0),
 completion_time bigint CHECK(completion_time>=0),applied_sequence bigint NOT NULL CHECK(applied_sequence>=0),applied_operation_id uuid NOT NULL,
 PRIMARY KEY(owner_id,owner_generation,stage_id),CHECK(status='not_started' OR started_at IS NOT NULL),
 CHECK((status='completed' AND completed_at IS NOT NULL AND completion_time IS NOT NULL) OR (status<>'completed' AND completed_at IS NULL AND completion_time IS NULL))
);
CREATE TABLE identity.ctf_stage_bindings (
 stage_id bigint PRIMARY KEY CHECK(stage_id>0),stage_number integer NOT NULL UNIQUE CHECK(stage_number>0),stage_revision bigint NOT NULL CHECK(stage_revision>=0),
 global_revision bigint NOT NULL CHECK(global_revision>=0),stage_digest text NOT NULL CHECK(stage_digest ~ '^[a-f0-9]{64}$'),stage_order integer NOT NULL,active boolean NOT NULL,
 adaptive_mode text NOT NULL CHECK(adaptive_mode IN ('none','technique','payload','hybrid')),feedback_mode text NOT NULL CHECK(feedback_mode IN ('full','reason','silent')),
 hint_count integer NOT NULL CHECK(hint_count BETWEEN 0 AND 3),level_score integer,max_attempts integer,
 applied_sequence bigint NOT NULL CHECK(applied_sequence>=0),applied_operation_id uuid NOT NULL
);
CREATE TABLE identity.ctf_config_binding (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),global_revision bigint NOT NULL CHECK(global_revision>=0),
 enabled boolean NOT NULL,visible_to_students boolean NOT NULL,registration_open boolean NOT NULL,
 student_leaderboard_visible boolean NOT NULL,public_leaderboard_visible boolean NOT NULL,nav_visible boolean NOT NULL,
 show_technique_feedback boolean NOT NULL,show_attempt_counter boolean NOT NULL,
 max_participants bigint NOT NULL CHECK(max_participants>=-1),time_limit_ms bigint NOT NULL CHECK(time_limit_ms>=-1),
 leaderboard_update_interval_ms integer NOT NULL CHECK(leaderboard_update_interval_ms>=0),hint_gating_attempts integer NOT NULL CHECK(hint_gating_attempts>=0),
 hint_cost_1 integer NOT NULL CHECK(hint_cost_1 BETWEEN 0 AND 715827882),hint_cost_2 integer NOT NULL CHECK(hint_cost_2 BETWEEN 0 AND 715827882),hint_cost_3 integer NOT NULL CHECK(hint_cost_3 BETWEEN 0 AND 715827882),
 applied_sequence bigint NOT NULL CHECK(applied_sequence>=0),applied_operation_id uuid NOT NULL
);
CREATE TABLE identity.ctf_registration_reservations (
 operation_id uuid PRIMARY KEY,sequence bigint NOT NULL UNIQUE CHECK(sequence>0),owner_id bigint NOT NULL CHECK(owner_id>0),units smallint NOT NULL CHECK(units IN (0,1)),
 state text NOT NULL DEFAULT 'held' CHECK(state IN ('held','applied','denied')),created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),resolved_at timestamptz,
 CHECK((state='held')=(resolved_at IS NULL)),FOREIGN KEY(operation_id,sequence) REFERENCES identity.ctf_outbox(operation_id,sequence)
);
CREATE UNIQUE INDEX ctf_registration_one_held_owner ON identity.ctf_registration_reservations(owner_id) WHERE state='held';
CREATE TABLE identity.ctf_attempt_admissions (
 operation_id uuid PRIMARY KEY REFERENCES identity.ctf_outbox(operation_id),owner_id bigint NOT NULL CHECK(owner_id>0),owner_generation bigint NOT NULL CHECK(owner_generation>=0),
 participant_id bigint NOT NULL CHECK(participant_id>0),progress_id bigint NOT NULL CHECK(progress_id>0),stage_id bigint NOT NULL CHECK(stage_id>0),
 attempt_number integer NOT NULL CHECK(attempt_number>0),failed_counter_increment boolean NOT NULL,occurred_at timestamptz NOT NULL,
 applied_sequence bigint NOT NULL UNIQUE CHECK(applied_sequence>0),UNIQUE(progress_id,attempt_number)
);
CREATE FUNCTION identity.protect_ctf_delivery_identity() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'CTF delivery history is immutable'; END IF;
 IF TG_TABLE_NAME='ctf_outbox' THEN
  IF (to_jsonb(NEW)-ARRAY['state','attempts','next_attempt_at','error_class','canonical_result','result_hash','applied_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','attempts','next_attempt_at','error_class','canonical_result','result_hash','applied_at']) THEN RAISE EXCEPTION 'CTF command identity is immutable'; END IF;
  IF OLD.state='applied' AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'CTF applied receipt is immutable'; END IF;
 ELSIF TG_TABLE_NAME='ctf_registration_reservations' THEN
  IF (to_jsonb(NEW)-ARRAY['state','resolved_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','resolved_at']) OR (OLD.state<>'held' AND NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'CTF reservation identity is immutable'; END IF;
 ELSE RAISE EXCEPTION 'CTF attempt admission is immutable'; END IF;
 RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION identity.protect_ctf_delivery_identity() FROM PUBLIC;
CREATE TRIGGER ctf_outbox_identity BEFORE UPDATE OR DELETE ON identity.ctf_outbox FOR EACH ROW EXECUTE FUNCTION identity.protect_ctf_delivery_identity();
CREATE TRIGGER ctf_reservation_identity BEFORE UPDATE OR DELETE ON identity.ctf_registration_reservations FOR EACH ROW EXECUTE FUNCTION identity.protect_ctf_delivery_identity();
CREATE TRIGGER ctf_admission_identity BEFORE UPDATE OR DELETE ON identity.ctf_attempt_admissions FOR EACH ROW EXECUTE FUNCTION identity.protect_ctf_delivery_identity();
REVOKE ALL ON identity.ctf_participant_bindings,identity.ctf_progress_bindings,identity.ctf_stage_bindings,identity.ctf_config_binding,identity.ctf_registration_reservations,identity.ctf_attempt_admissions FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_participant_bindings,identity.ctf_progress_bindings,identity.ctf_stage_bindings,identity.ctf_config_binding,identity.ctf_registration_reservations,identity.ctf_attempt_admissions TO dvaia_identity_runtime;

-- Bounded closed validation for fixed internal schemas. No dynamic SQL.
CREATE FUNCTION identity.ctf_json_matches(v jsonb,r jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE k text; x jsonb; t text; n numeric;
BEGIN
 IF v IS NULL THEN RETURN false; END IF;
 IF v='null'::jsonb THEN RETURN COALESCE((r->>'nullable')::boolean,false); END IF;
 t:=jsonb_typeof(v);
 IF t IS DISTINCT FROM r->>'type' THEN RETURN false; END IF;
 IF r ? 'enum' AND NOT (r->'enum' @> jsonb_build_array(v)) THEN RETURN false; END IF;
 IF t='object' THEN
  IF EXISTS(SELECT 1 FROM jsonb_object_keys(v) a WHERE NOT (r->'properties' ? a)) THEN RETURN false; END IF;
  IF NOT COALESCE((r->>'optional')::boolean,false) AND EXISTS(SELECT 1 FROM jsonb_object_keys(r->'properties') a WHERE NOT(v ? a)) THEN RETURN false; END IF;
  FOR k,x IN SELECT * FROM jsonb_each(v) LOOP IF NOT identity.ctf_json_matches(x,r->'properties'->k) THEN RETURN false; END IF; END LOOP;
 ELSIF t='string' THEN
  IF octet_length(v#>>'{}')>(r->>'bytes')::integer THEN RETURN false; END IF;
  IF r ? 'pattern' AND NOT ((v#>>'{}') ~ (r->>'pattern')) THEN RETURN false; END IF;
 END IF;
 IF r ? 'minimum' OR r ? 'maximum' THEN
  n:=(v#>>'{}')::numeric;
  IF n<(r->>'minimum')::numeric OR n>(r->>'maximum')::numeric OR (COALESCE((r->>'integer')::boolean,false) AND trunc(n)<>n) THEN RETURN false; END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END; $$;
REVOKE ALL ON FUNCTION identity.ctf_json_matches(jsonb,jsonb) FROM PUBLIC;
CREATE FUNCTION identity.ctf_result_matches(v jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE r jsonb;d jsonb:=v->'data';k text:=v->>'kind';
BEGIN
 IF NOT identity.ctf_json_matches(v-'data','{"type":"object","properties":{"version":{"type":"number","enum":[1]},"kind":{"type":"string","enum":["register","start","hint","admit_attempt","record_blocked_attempt","catalog_mutation","config_mutation","owner_reset","owner_remove","global_reset","ban","unban","blocklist_clear"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"sequence":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":1,"maximum":9223372036854775807},"commandHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"outcome":{"type":"string","enum":["applied","registration_closed","capacity_reached"]}},"optional":false}'::jsonb) OR jsonb_typeof(d) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 r:=CASE k
 WHEN 'register' THEN '{"type":"object","properties":{"admitted":{"type":"boolean"},"reason":{"type":"string","enum":["registration_closed","capacity_reached"],"nullable":true},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true},"recovered":{"type":"boolean"},"active":{"type":"boolean"},"banned":{"type":"boolean"},"registeredAt":{"type":"string","bytes":24,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$","nullable":true}},"optional":false}'::jsonb
 WHEN 'start' THEN '{"type":"object","properties":{"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"status":{"type":"string","enum":["in_progress","completed"]},"startedAt":{"type":"string","bytes":24,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"},"completedAt":{"type":"string","bytes":24,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$","nullable":true},"completionTime":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":9223372036854775807,"nullable":true},"attemptsCount":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"failedAttempts":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"successfulAttempts":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"hintsUsed":{"type":"number","minimum":0,"maximum":3,"integer":true},"hintPenaltyTotal":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false}'::jsonb
 WHEN 'hint' THEN '{"type":"object","properties":{"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"hintsUsed":{"type":"number","minimum":1,"maximum":3,"integer":true},"hintPenaltyTotal":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false}'::jsonb
 WHEN 'admit_attempt' THEN '{"type":"object","properties":{"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"attemptNumber":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"failedAttempts":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false}'::jsonb
 WHEN 'record_blocked_attempt' THEN '{"type":"object","properties":{"attemptId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"admissionOperationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"payloadHitIncremented":{"type":"boolean"}},"optional":false}'::jsonb
 WHEN 'catalog_mutation' THEN '{"type":"object","properties":{"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageNumber":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stageOrder":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"active":{"type":"boolean"},"stageDigest":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"adaptiveMode":{"type":"string","enum":["none","technique","payload","hybrid"]},"feedbackMode":{"type":"string","enum":["full","reason","silent"]},"hintCount":{"type":"number","minimum":0,"maximum":3,"integer":true},"levelScore":{"type":"number","minimum":0,"maximum":1000000,"integer":true},"maxAttempts":{"type":"number","minimum":-1,"maximum":1000000,"integer":true,"nullable":true}},"optional":false}'::jsonb
 WHEN 'config_mutation' THEN '{"type":"object","properties":{"key":{"type":"string","enum":["ctf_enabled","ctf_visible_to_students","student_leaderboard_visible","public_leaderboard_visible","ctf_registration_open","ctf_max_participants","ctf_time_limit","leaderboard_update_interval","ctf_nav_visible","ctf_show_technique_feedback","ctf_show_attempt_counter","ctf_hint_gating_attempts","ctf_hint_cost_1","ctf_hint_cost_2","ctf_hint_cost_3"]},"value":{"type":"string","bytes":8192}},"optional":false}'::jsonb
 WHEN 'owner_reset' THEN '{"type":"object","properties":{"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"removed":{"type":"boolean","enum":[false]}},"optional":false}'::jsonb
 WHEN 'owner_remove' THEN '{"type":"object","properties":{"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"removed":{"type":"boolean"}},"optional":false}'::jsonb
 WHEN 'global_reset' THEN '{"type":"object","properties":{"removedParticipants":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false}'::jsonb
 WHEN 'ban' THEN '{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"banned":{"type":"boolean"}},"optional":false}'::jsonb
 WHEN 'unban' THEN '{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"banned":{"type":"boolean"}},"optional":false}'::jsonb
 WHEN 'blocklist_clear' THEN '{"type":"object","properties":{"memory":{"type":"string","enum":["technique","payload"]},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true},"removedCount":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false}'::jsonb
 ELSE NULL END;
 IF k='catalog_mutation' AND d ? 'deleted' THEN r:='{"type":"object","properties":{"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"deleted":{"type":"boolean"}},"optional":false}'::jsonb; END IF;
 IF NOT identity.ctf_json_matches(d,r) THEN RETURN false; END IF;
 FOR k IN SELECT key FROM jsonb_each(d) WHERE key IN ('registeredAt','startedAt','completedAt') AND value<>'null'::jsonb LOOP
  IF to_char((d->>k)::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') IS DISTINCT FROM d->>k THEN RETURN false; END IF;
 END LOOP;
 k:=v->>'kind';
 IF k='register' THEN
  RETURN ((v->>'outcome'='applied' AND d->'admitted'='true'::jsonb AND d->'active'='true'::jsonb AND d->'reason'='null'::jsonb AND d->'participantId'<>'null'::jsonb AND d->'registeredAt'<>'null'::jsonb)
   OR (v->>'outcome' IN ('registration_closed','capacity_reached') AND d->'admitted'='false'::jsonb AND d->>'reason'=v->>'outcome' AND d->'participantId'='null'::jsonb AND d->'registeredAt'='null'::jsonb)) IS TRUE;
 END IF;
 IF v->>'outcome'<>'applied' THEN RETURN false; END IF;
 IF k='start' THEN RETURN ((d->>'status'='completed')=(d->'completedAt'<>'null'::jsonb AND d->'completionTime'<>'null'::jsonb)) AND (d->>'status'='completed' OR (d->'completedAt'='null'::jsonb AND d->'completionTime'='null'::jsonb)); END IF;
 RETURN true;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END; $$;
REVOKE ALL ON FUNCTION identity.ctf_result_matches(jsonb) FROM PUBLIC;
CREATE FUNCTION identity.enqueue_ctf_user_command(p_actor bigint,p_session bigint,p_token_hash text,p_operation uuid,p_canonical text,p_hash text)
RETURNS TABLE(operation_id uuid,sequence bigint,state text,command_hash text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb; b jsonb; sc jsonb; k text; target bigint; sid bigint; seq bigint; units smallint:=0;
 g identity.ctf_authority%ROWTYPE; o identity.ctf_authority%ROWTYPE; st identity.ctf_stage_bindings%ROWTYPE;
 u identity.users%ROWTYPE; sess identity.user_sessions%ROWTYPE; cfg identity.ctf_config_binding%ROWTYPE;
 part identity.ctf_participant_bindings%ROWTYPE; pr identity.ctf_progress_bindings%ROWTYPE; prior identity.ctf_outbox%ROWTYPE;
 fingerprint text; generation_after bigint; disposition text; r_body jsonb; affected_scope text; expected_keys text[]; allowed_keys text[]; admin_kind boolean; n bigint;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);
 PERFORM set_config('statement_timeout','2000ms',true);
 IF p_canonical IS NULL OR octet_length(p_canonical)>65536 OR p_hash IS NULL OR p_hash<>encode(sha256(convert_to(p_canonical,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF command digest invalid'; END IF;
 IF NOT (p_canonical IS JSON OBJECT WITH UNIQUE KEYS) THEN RAISE EXCEPTION 'CTF duplicate or invalid JSON'; END IF;
 e:=p_canonical::jsonb;b:=e->'body';sc:=e->'scope';k:=e->>'kind';
 IF jsonb_typeof(e) IS DISTINCT FROM 'object' OR jsonb_typeof(b) IS DISTINCT FROM 'object' OR jsonb_typeof(sc) IS DISTINCT FROM 'object'
 OR e->'version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(e->'actorId') IS DISTINCT FROM 'string' OR (e->>'actorId')::bigint IS DISTINCT FROM p_actor OR jsonb_typeof(e->'operationId') IS DISTINCT FROM 'string' OR (e->>'operationId')::uuid IS DISTINCT FROM p_operation
 OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(e) key)<>ARRAY['actorId','body','kind','occurredAt','operationId','scope','version']
 OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(sc) key)<>ARRAY['globalRevision','ownerGeneration','ownerId','participantId','progressId','stageId','stageRevision']
 THEN RAISE EXCEPTION 'CTF command envelope invalid'; END IF;
 IF k IS NULL OR k NOT IN ('catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear','register','start','hint','admit_attempt','record_blocked_attempt') THEN RAISE EXCEPTION 'CTF command kind unavailable'; END IF;
 expected_keys:=CASE k WHEN 'catalog_mutation' THEN ARRAY['action','fields'] WHEN 'config_mutation' THEN ARRAY['key','value'] WHEN 'ban' THEN ARRAY['reason'] WHEN 'blocklist_clear' THEN ARRAY['memory'] WHEN 'register' THEN ARRAY['clientIp','email','teachingSessionToken','teamName','userAgent','username'] WHEN 'hint' THEN ARRAY['cost','expectedHints'] WHEN 'admit_attempt' THEN ARRAY['failed'] WHEN 'record_blocked_attempt' THEN ARRAY['admissionOperationId','attemptNumber','matchedPayloadHash','payload','payloadHash','reason','response','responseTime','techniqueConfidence','techniqueTag','teachingSessionToken'] ELSE ARRAY[]::text[] END;
 IF COALESCE((SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(b) key),ARRAY[]::text[])<>expected_keys THEN RAISE EXCEPTION 'CTF command fields invalid'; END IF;
 r_body:=CASE k
 WHEN 'owner_reset' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'owner_remove' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'global_reset' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'unban' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'start' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'catalog_mutation' THEN '{"type":"object","properties":{"action":{"type":"string","enum":["create","update","delete"]},"fields":{"type":"object","properties":{"stage_number":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stage_name":{"type":"string","bytes":1024},"stage_description":{"type":"string","bytes":8192,"nullable":true},"difficulty_level":{"type":"string","bytes":128,"nullable":true},"ai_guardian_name":{"type":"string","bytes":1024,"nullable":true},"ai_guardian_personality":{"type":"string","bytes":8192,"nullable":true},"system_prompt":{"type":"string","bytes":16384,"nullable":true},"success_criteria":{"type":"string","bytes":4096},"hints":{"type":"string","bytes":8192,"nullable":true},"stage_order":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"difficulty":{"type":"string","enum":["trivial","easy","medium","hard","expert","legendary"]},"defense_style":{"type":"string","bytes":4096},"adaptive_mode":{"type":"string","enum":["none","technique","payload","hybrid"]},"level_score":{"type":"number","minimum":0,"maximum":1000000,"integer":true},"time_bonus_seconds":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"feedback_mode":{"type":"string","enum":["full","reason","silent"]},"is_active":{"type":"number","minimum":0,"maximum":1,"integer":true},"max_attempts":{"type":"number","minimum":-1,"maximum":1000000,"integer":true}},"optional":true}},"optional":false}'::jsonb
 WHEN 'config_mutation' THEN '{"type":"object","properties":{"key":{"type":"string","enum":["ctf_enabled","ctf_visible_to_students","student_leaderboard_visible","public_leaderboard_visible","ctf_registration_open","ctf_max_participants","ctf_time_limit","leaderboard_update_interval","ctf_nav_visible","ctf_show_technique_feedback","ctf_show_attempt_counter","ctf_hint_gating_attempts","ctf_hint_cost_1","ctf_hint_cost_2","ctf_hint_cost_3"]},"value":{"type":"string","bytes":8192}},"optional":false}'::jsonb
 WHEN 'ban' THEN '{"type":"object","properties":{"reason":{"type":"string","bytes":4096}},"optional":false}'::jsonb
 WHEN 'blocklist_clear' THEN '{"type":"object","properties":{"memory":{"type":"string","enum":["technique","payload"]}},"optional":false}'::jsonb
 WHEN 'register' THEN '{"type":"object","properties":{"username":{"type":"string","bytes":256},"email":{"type":"string","bytes":320,"nullable":true},"teamName":{"type":"string","bytes":256,"nullable":true},"teachingSessionToken":{"type":"string","bytes":256},"clientIp":{"type":"string","bytes":128,"nullable":true},"userAgent":{"type":"string","bytes":1024,"nullable":true}},"optional":false}'::jsonb
 WHEN 'hint' THEN '{"type":"object","properties":{"expectedHints":{"type":"number","minimum":0,"maximum":1000000,"integer":true},"cost":{"type":"number","minimum":0,"maximum":715827882,"integer":true}},"optional":false}'::jsonb
 WHEN 'admit_attempt' THEN '{"type":"object","properties":{"failed":{"type":"boolean"}},"optional":false}'::jsonb
 WHEN 'record_blocked_attempt' THEN '{"type":"object","properties":{"admissionOperationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"matchedPayloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$","nullable":true},"attemptNumber":{"type":"number","minimum":1,"maximum":1000000,"integer":true},"payload":{"type":"string","bytes":16384},"response":{"type":"string","bytes":16384,"nullable":true},"responseTime":{"type":"number","minimum":0,"maximum":300000,"integer":true},"teachingSessionToken":{"type":"string","bytes":256,"nullable":true},"techniqueTag":{"type":"string","bytes":128,"nullable":true},"techniqueConfidence":{"type":"number","minimum":0,"maximum":1,"nullable":true},"reason":{"type":"string","bytes":4096},"payloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$","nullable":true}},"optional":false}'::jsonb
 ELSE NULL END;
 IF NOT identity.ctf_json_matches(b,r_body) THEN RAISE EXCEPTION 'CTF command body invalid'; END IF;
 -- SQL callers receive the same closed scope rules as the pure constructor.
 IF EXISTS(SELECT 1 FROM jsonb_each(sc) x WHERE
   CASE WHEN x.key IN ('globalRevision','ownerGeneration','stageRevision') THEN
    NOT identity.ctf_json_matches(x.value,'{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":9223372036854775807,"nullable":true}'::jsonb)
   ELSE NOT identity.ctf_json_matches(x.value,'{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true}'::jsonb) END)
 OR sc->'globalRevision'='null'::jsonb
 OR ((sc->'ownerId'='null'::jsonb) IS DISTINCT FROM (sc->'ownerGeneration'='null'::jsonb))
 OR ((sc->'stageId'='null'::jsonb) IS DISTINCT FROM (sc->'stageRevision'='null'::jsonb))
 OR (k IN ('owner_reset','owner_remove','ban','unban','register','start','hint','admit_attempt','record_blocked_attempt') AND sc->'ownerId'='null'::jsonb)
 OR (k IN ('start','hint','admit_attempt','record_blocked_attempt') AND (sc->'participantId'='null'::jsonb OR sc->'stageId'='null'::jsonb))
 OR (k IN ('hint','admit_attempt','record_blocked_attempt') AND sc->'progressId'='null'::jsonb)
 OR (k IN ('global_reset','config_mutation','catalog_mutation','blocklist_clear') AND EXISTS(SELECT 1 FROM jsonb_each(sc) x WHERE x.key IN ('ownerId','ownerGeneration','participantId','progressId') AND x.value<>'null'::jsonb))
 OR (k IN ('global_reset','config_mutation') AND sc->'stageId'<>'null'::jsonb)
 OR (k IN ('owner_reset','owner_remove','ban','unban','register') AND (sc->'stageId'<>'null'::jsonb OR sc->'progressId'<>'null'::jsonb))
 OR (k IN ('owner_reset','owner_remove') AND sc->'participantId'='null'::jsonb)
 OR (k IN ('ban','unban','register') AND sc->'participantId'<>'null'::jsonb)
 OR (k='start' AND sc->'progressId'<>'null'::jsonb)
 OR (k='catalog_mutation' AND ((b->>'action'='create') IS DISTINCT FROM (sc->'stageId'='null'::jsonb)))
 THEN RAISE EXCEPTION 'CTF command scope invalid'; END IF;
 IF k='catalog_mutation' AND (
   ((b->>'action'='delete') IS DISTINCT FROM (b->'fields'='{}'::jsonb))
   OR (b->>'action'='create' AND NOT (b->'fields' ?& ARRAY['stage_number','stage_name','stage_order']))
   OR (b->>'action'='update' AND b->'fields' ? 'stage_number')) THEN RAISE EXCEPTION 'CTF catalog fields invalid'; END IF;
 IF jsonb_typeof(e->'occurredAt') IS DISTINCT FROM 'string' OR NOT (e->>'occurredAt' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$')
 OR p_actor IS NULL OR p_actor NOT BETWEEN 1 AND 2147483647 OR p_session IS NULL OR p_session NOT BETWEEN 1 AND 2147483647
 OR e->>'actorId' !~ '^[1-9][0-9]*$' OR e->>'operationId' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
 OR p_operation IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'CTF authority scalar invalid'; END IF;
 IF k='config_mutation' THEN
  IF b->>'key' IN ('ctf_max_participants','ctf_time_limit','leaderboard_update_interval','ctf_hint_gating_attempts','ctf_hint_cost_1','ctf_hint_cost_2','ctf_hint_cost_3') THEN
   IF NOT (b->>'value' ~ '^(?:-1|0|[1-9][0-9]*)$') THEN RAISE EXCEPTION 'CTF config scalar invalid'; END IF;
   IF (b->>'value')::numeric < (CASE WHEN b->>'key' IN ('ctf_max_participants','ctf_time_limit') THEN -1 ELSE 0 END)
    OR (b->>'value')::numeric > (CASE WHEN b->>'key' IN ('ctf_max_participants','ctf_time_limit') THEN 9223372036854775807 WHEN b->>'key' IN ('ctf_hint_cost_1','ctf_hint_cost_2','ctf_hint_cost_3') THEN 715827882 ELSE 2147483647 END)
   THEN RAISE EXCEPTION 'CTF config scalar range invalid'; END IF;
  ELSIF b->>'value' NOT IN ('true','false') THEN RAISE EXCEPTION 'CTF config boolean invalid'; END IF;
 END IF;
 target:=(sc->>'ownerId')::bigint;sid:=(sc->>'stageId')::bigint;
 admin_kind:=k IN ('catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear');
 IF NOT admin_kind AND target IS DISTINCT FROM p_actor THEN RAISE EXCEPTION 'CTF owner mismatch'; END IF;
 SELECT * INTO g FROM identity.ctf_authority a WHERE a.scope_key='global' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'CTF authority uninitialized'; END IF;
 IF sid IS NOT NULL THEN PERFORM 1 FROM identity.ctf_authority a WHERE a.scope_key='stage:'||sid FOR UPDATE; END IF;
 IF target IS NOT NULL THEN PERFORM 1 FROM identity.ctf_authority a WHERE a.scope_key='owner:'||target FOR UPDATE; END IF;
 PERFORM 1 FROM identity.users WHERE id IN (p_actor,target) ORDER BY id FOR UPDATE;
 SELECT * INTO u FROM identity.users WHERE id=p_actor;
 SELECT * INTO sess FROM identity.user_sessions WHERE id=p_session AND user_id=p_actor FOR UPDATE;
 IF u.id IS NULL OR u.is_active<>1 OR (u.account_locked_until IS NOT NULL AND u.account_locked_until>clock_timestamp())
 OR sess.id IS NULL OR sess.is_active<>1 OR sess.expires_at<=clock_timestamp() OR sess.session_token_hash IS DISTINCT FROM p_token_hash
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key='["CTF","'||p_actor||'"]')
 THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 IF admin_kind AND NOT (u.role='admin' OR COALESCE(u.admin_level,0)>0) THEN RAISE EXCEPTION 'CTF admin required' USING ERRCODE='42501'; END IF;
 -- Graph rows follow user/session locks. No advisory lock is acquired here.
 IF target IS NOT NULL THEN
  INSERT INTO graph_runtime.owners(owner_key) VALUES('["CTF","'||target||'"]') ON CONFLICT DO NOTHING;
  PERFORM 1 FROM graph_runtime.owners WHERE owner_key='["CTF","'||target||'"]' FOR UPDATE;
  INSERT INTO identity.ctf_authority(scope_key,owner_generation,lifecycle_state)
   SELECT 'owner:'||target,generation,'ready' FROM graph_runtime.owners WHERE owner_key='["CTF","'||target||'"]' ON CONFLICT DO NOTHING;
  SELECT * INTO o FROM identity.ctf_authority a WHERE a.scope_key='owner:'||target FOR UPDATE;
  IF o.owner_generation IS DISTINCT FROM (SELECT generation FROM graph_runtime.owners WHERE owner_key='["CTF","'||target||'"]') THEN RAISE EXCEPTION 'CTF owner generation drift'; END IF;
 END IF;
 fingerprint:=encode(sha256(convert_to((jsonb_build_object('actor',p_actor,'kind',k,'scope',sc,'body',b))::text,'UTF8')),'hex');
 SELECT * INTO prior FROM identity.ctf_outbox x WHERE x.operation_id=p_operation;
 IF FOUND THEN
  IF prior.actor_id IS DISTINCT FROM p_actor OR prior.request_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'CTF operation conflict'; END IF;
  RETURN QUERY SELECT prior.operation_id,prior.sequence,prior.state,prior.command_hash;RETURN;
 END IF;
 IF k='global_reset' AND (g.next_sequence<>g.applied_sequence OR EXISTS(SELECT 1 FROM identity.ctf_outbox AS queued WHERE queued.state IN ('pending','blocked')) OR EXISTS(SELECT 1 FROM identity.ctf_authority WHERE lifecycle_state IN ('pending','blocked')) OR EXISTS(SELECT 1 FROM identity.ctf_registration_reservations AS reservation WHERE reservation.state='held')) THEN RAISE EXCEPTION 'CTF global reset requires drained delivery'; END IF;
 IF (e->>'occurredAt')::timestamptz IS DISTINCT FROM date_trunc('milliseconds',transaction_timestamp()) THEN RAISE EXCEPTION 'CTF event timestamp invalid'; END IF;
 IF g.lifecycle_state<>'ready' OR (sc->>'globalRevision')::bigint IS DISTINCT FROM g.revision THEN RAISE EXCEPTION 'CTF global authority unavailable'; END IF;
 IF target IS NOT NULL AND (o.lifecycle_state<>'ready' OR o.owner_generation IS DISTINCT FROM (sc->>'ownerGeneration')::bigint
  OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=target)
  OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key='["CTF","'||target||'"]')) THEN RAISE EXCEPTION 'CTF owner authority unavailable'; END IF;
 IF sid IS NOT NULL THEN
  SELECT * INTO st FROM identity.ctf_stage_bindings WHERE stage_id=sid;
  IF st.stage_id IS NULL OR NOT EXISTS(SELECT 1 FROM identity.ctf_authority a WHERE a.scope_key='stage:'||sid AND a.lifecycle_state='ready' AND a.revision=(sc->>'stageRevision')::bigint) THEN RAISE EXCEPTION 'CTF stage authority unavailable'; END IF;
 END IF;
 SELECT * INTO cfg FROM identity.ctf_config_binding WHERE singleton;
 IF cfg.singleton IS NULL THEN RAISE EXCEPTION 'CTF config uninitialized'; END IF;
 SELECT * INTO part FROM identity.ctf_participant_bindings WHERE owner_id=target;
 IF NOT admin_kind AND (NOT cfg.enabled OR (NOT cfg.visible_to_students AND NOT (u.role='admin' OR COALESCE(u.admin_level,0)>0))) THEN RAISE EXCEPTION 'CTF learner visibility unavailable'; END IF;
 IF NOT admin_kind AND k<>'register' THEN
  IF part.owner_id IS NULL OR NOT part.active OR o.banned OR part.banned OR part.owner_generation<>o.owner_generation
    OR part.participant_id IS DISTINCT FROM (sc->>'participantId')::bigint OR st.stage_id IS NULL OR NOT st.active
    OR (cfg.time_limit_ms<>-1 AND extract(epoch FROM clock_timestamp()-part.registered_at)*1000>cfg.time_limit_ms)
  THEN RAISE EXCEPTION 'CTF learner eligibility unavailable'; END IF;
  SELECT * INTO pr FROM identity.ctf_progress_bindings WHERE owner_id=target AND owner_generation=o.owner_generation AND stage_id=sid;
  IF k<>'start' AND (pr.progress_id IS NULL OR pr.progress_id IS DISTINCT FROM (sc->>'progressId')::bigint OR pr.status<>'in_progress') THEN RAISE EXCEPTION 'CTF progress incarnation unavailable'; END IF;
 END IF;
 IF k='register' THEN
  IF NOT cfg.registration_open THEN RAISE EXCEPTION 'CTF registration closed'; END IF;
  units:=CASE WHEN part.active THEN 0 ELSE 1 END;
  SELECT (SELECT count(*) FROM identity.ctf_participant_bindings WHERE active)+COALESCE((SELECT sum(r.units) FROM identity.ctf_registration_reservations r WHERE r.state='held'),0) INTO n;
  IF units=1 AND cfg.max_participants<>-1 AND n+1>cfg.max_participants THEN RAISE EXCEPTION 'CTF capacity reached'; END IF;
 ELSIF k='start' THEN
  IF EXISTS(SELECT 1 FROM identity.ctf_stage_bindings prev WHERE prev.active AND prev.stage_order=(SELECT max(stage_order) FROM identity.ctf_stage_bindings WHERE active AND stage_order<st.stage_order)
    AND NOT EXISTS(SELECT 1 FROM identity.ctf_progress_bindings p WHERE p.owner_id=target AND p.owner_generation=o.owner_generation AND p.stage_id=prev.stage_id AND p.status='completed')) THEN RAISE EXCEPTION 'CTF prerequisite incomplete'; END IF;
 ELSIF k='hint' THEN
  IF pr.hints_used IS DISTINCT FROM (b->>'expectedHints')::integer OR pr.hints_used>=st.hint_count OR pr.hints_used>=3 OR pr.attempts_count<cfg.hint_gating_attempts
   OR (b->>'cost')::integer IS DISTINCT FROM (CASE pr.hints_used WHEN 0 THEN cfg.hint_cost_1 WHEN 1 THEN cfg.hint_cost_2 ELSE cfg.hint_cost_3 END) THEN RAISE EXCEPTION 'CTF hint eligibility changed'; END IF;
 ELSIF k='record_blocked_attempt' THEN
  IF NOT EXISTS(SELECT 1 FROM identity.ctf_attempt_admissions a WHERE a.operation_id=(b->>'admissionOperationId')::uuid AND a.owner_id=target AND a.owner_generation=o.owner_generation AND a.progress_id=pr.progress_id AND a.attempt_number=(b->>'attemptNumber')::integer) THEN RAISE EXCEPTION 'CTF attempt admission unavailable'; END IF;
 END IF;
 IF (SELECT count(*) FROM identity.ctf_outbox AS queued WHERE queued.state='pending')>=512 OR (SELECT COALESCE(sum(octet_length(queued.command::text)),0) FROM identity.ctf_outbox AS queued WHERE queued.state='pending')+octet_length(p_canonical)>16777216
 OR EXISTS(SELECT 1 FROM identity.ctf_outbox AS queued WHERE queued.state='pending' AND queued.created_at<clock_timestamp()-interval '60 seconds') THEN RAISE EXCEPTION 'CTF delivery backlog unavailable'; END IF;
 generation_after:=o.owner_generation;
 IF k='register' THEN
  disposition:=CASE WHEN part.owner_id IS NULL THEN 'new' WHEN part.active THEN 'active_recovery' ELSE 'reactivate' END;
 END IF;
 IF target IS NOT NULL AND (k IN ('owner_reset','owner_remove') OR (k='register' AND disposition<>'active_recovery')) THEN
  UPDATE graph_runtime.owners SET generation=generation+1,updated_at=clock_timestamp() WHERE owner_key='["CTF","'||target||'"]' RETURNING generation INTO generation_after;
  UPDATE identity.ctf_authority SET owner_generation=generation_after,revision=revision+1 WHERE identity.ctf_authority.scope_key='owner:'||target;
 END IF;
 seq:=g.next_sequence+1;
 UPDATE identity.ctf_authority SET next_sequence=seq WHERE identity.ctf_authority.scope_key='global';
 INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,actor_id,session_id,request_fingerprint,canonical_command,owner_generation_after,registration_disposition,registration_participant_before)
 VALUES(seq,p_operation,k,e,p_hash,p_actor,p_session,fingerprint,p_canonical,generation_after,disposition,CASE WHEN k='register' THEN part.participant_id ELSE NULL END);
 IF target IS NOT NULL THEN
  UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=p_operation WHERE identity.ctf_authority.scope_key='owner:'||target;
 ELSE
  affected_scope:=CASE WHEN k IN ('catalog_mutation','blocklist_clear') AND sid IS NOT NULL AND NOT (k='catalog_mutation' AND (b->>'action'='delete' OR b->'fields' ?| ARRAY['stage_order','is_active'])) THEN 'stage:'||sid ELSE 'global' END;
  UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=p_operation,revision=revision+1 WHERE identity.ctf_authority.scope_key=affected_scope;
 END IF;
 IF k='register' THEN INSERT INTO identity.ctf_registration_reservations(operation_id,sequence,owner_id,units) VALUES(p_operation,seq,target,units); END IF;
 RETURN QUERY SELECT p_operation,seq,'pending'::text,p_hash;
END; $$;
REVOKE ALL ON FUNCTION identity.enqueue_ctf_user_command(bigint,bigint,text,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.enqueue_ctf_user_command(bigint,bigint,text,uuid,text,text) TO dvaia_identity_runtime;

CREATE FUNCTION identity.ack_ctf_projection(p_operation uuid,p_sequence bigint,p_command_hash text,p_result text,p_result_hash text)
RETURNS TABLE(state text,applied_sequence bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE g identity.ctf_authority%ROWTYPE; ev identity.ctf_outbox%ROWTYPE; a identity.ctf_authority%ROWTYPE;
 r jsonb;d jsonb;sc jsonb;b jsonb;k text;target bigint;sid bigint;seq bigint;owner_gen bigint;observed_global_revision bigint;part identity.ctf_participant_bindings%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 IF p_result IS NULL OR octet_length(p_result)>16384 OR p_result_hash IS DISTINCT FROM encode(sha256(convert_to(p_result,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF result digest invalid'; END IF;
 IF NOT (p_result IS JSON OBJECT WITH UNIQUE KEYS) THEN RAISE EXCEPTION 'CTF duplicate or invalid result JSON'; END IF;
 r:=p_result::jsonb;d:=r->'data';
 IF NOT identity.ctf_result_matches(r) THEN RAISE EXCEPTION 'CTF result schema invalid'; END IF;
 IF jsonb_typeof(r) IS DISTINCT FROM 'object' OR jsonb_typeof(d) IS DISTINCT FROM 'object'
 OR COALESCE((SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(r) key),ARRAY[]::text[])<>ARRAY['commandHash','data','kind','operationId','outcome','sequence','version']
 OR r->'version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'sequence') IS DISTINCT FROM 'string' OR (r->>'operationId')::uuid IS DISTINCT FROM p_operation OR (r->>'sequence')::bigint IS DISTINCT FROM p_sequence OR r->>'commandHash' IS DISTINCT FROM p_command_hash THEN RAISE EXCEPTION 'CTF result envelope invalid'; END IF;
 SELECT * INTO g FROM identity.ctf_authority x WHERE x.scope_key='global' FOR UPDATE;
 SELECT * INTO ev FROM identity.ctf_outbox x WHERE x.operation_id=p_operation FOR UPDATE;
 IF ev.operation_id IS NULL OR ev.sequence<>p_sequence OR ev.command_hash<>p_command_hash OR ev.kind IS DISTINCT FROM r->>'kind' THEN RAISE EXCEPTION 'CTF receipt identity mismatch'; END IF;
 IF ev.state IN ('applied','blocked') THEN
  IF ev.canonical_result IS DISTINCT FROM p_result OR ev.result_hash IS DISTINCT FROM p_result_hash THEN RAISE EXCEPTION 'CTF receipt replay mismatch'; END IF;
  RETURN QUERY SELECT ev.state,g.applied_sequence;RETURN;
 END IF;
 IF p_sequence<>g.applied_sequence+1 THEN RAISE EXCEPTION 'CTF acknowledgment out of order'; END IF;
 sc:=ev.command->'scope';b:=ev.command->'body';k:=ev.kind;target:=(sc->>'ownerId')::bigint;sid:=(sc->>'stageId')::bigint;
 observed_global_revision:=(sc->>'globalRevision')::bigint;
 IF target IS NULL AND NOT (k IN ('catalog_mutation','blocklist_clear') AND sid IS NOT NULL AND NOT (k='catalog_mutation' AND (b->>'action'='delete' OR b->'fields' ?| ARRAY['stage_order','is_active']))) THEN observed_global_revision:=observed_global_revision+1; END IF;
 IF r->>'outcome' IS DISTINCT FROM 'applied' THEN
  IF k<>'register' OR r->>'outcome' NOT IN ('registration_closed','capacity_reached') THEN RAISE EXCEPTION 'CTF result outcome invalid'; END IF;
  -- Unexpected CTF denial is mirror/writer drift. Keep capacity held and the
  -- exact receipt; never silently reopen a supposedly coherent authority.
  UPDATE identity.ctf_outbox AS delivered SET state='blocked',error_class='registration_projection_drift',canonical_result=p_result,result_hash=p_result_hash WHERE delivered.operation_id=p_operation;
  UPDATE identity.ctf_authority SET lifecycle_state='blocked',blocked_operation_id=p_operation,pending_operation_id=NULL,failure_code='registration_projection_drift'
   WHERE scope_key='global' OR pending_operation_id=p_operation;
  RETURN QUERY SELECT 'blocked'::text,g.applied_sequence;RETURN;
 END IF;
 IF EXISTS(SELECT 1 FROM identity.ctf_authority WHERE blocked_operation_id=p_operation) THEN RAISE EXCEPTION 'CTF blocked operation requires recovery'; END IF;
 IF target IS NOT NULL THEN
  SELECT * INTO a FROM identity.ctf_authority WHERE scope_key='owner:'||target FOR UPDATE;
  IF a.pending_operation_id IS DISTINCT FROM p_operation OR a.lifecycle_state<>'pending' THEN RAISE EXCEPTION 'CTF pending owner superseded'; END IF;
  owner_gen:=a.owner_generation;
  IF owner_gen IS DISTINCT FROM ev.owner_generation_after THEN RAISE EXCEPTION 'CTF effective owner generation mismatch'; END IF;
  SELECT * INTO part FROM identity.ctf_participant_bindings WHERE owner_id=target FOR UPDATE;
  SELECT * INTO pr FROM identity.ctf_progress_bindings WHERE owner_id=target AND owner_generation=owner_gen AND stage_id=sid FOR UPDATE;
 END IF;
 IF k='register' THEN
  IF (d->>'admitted')::boolean IS DISTINCT FROM true OR (d->>'participantId')::bigint IS NULL OR d->>'registeredAt' IS NULL THEN RAISE EXCEPTION 'CTF registration result invalid'; END IF;
  IF part.participant_id=(d->>'participantId')::bigint AND part.registered_at IS DISTINCT FROM (d->>'registeredAt')::timestamptz THEN RAISE EXCEPTION 'CTF registration clock changed'; END IF;
  IF part.participant_id IS DISTINCT FROM ev.registration_participant_before THEN RAISE EXCEPTION 'CTF registration prior incarnation drift'; END IF;
  IF ev.registration_disposition='active_recovery' AND (part.owner_id IS NULL OR NOT part.active OR part.participant_id IS DISTINCT FROM (d->>'participantId')::bigint OR owner_gen IS DISTINCT FROM (sc->>'ownerGeneration')::bigint) THEN RAISE EXCEPTION 'CTF active recovery incarnation mismatch'; END IF;
  IF ev.registration_disposition='new' AND part.owner_id IS NOT NULL THEN RAISE EXCEPTION 'CTF new registration binding drift'; END IF;
  IF ev.registration_disposition='reactivate' AND (part.owner_id IS NULL OR part.active) THEN RAISE EXCEPTION 'CTF reactivation binding drift'; END IF;
  IF ev.registration_disposition<>'active_recovery' AND owner_gen IS DISTINCT FROM (sc->>'ownerGeneration')::bigint+1 THEN RAISE EXCEPTION 'CTF registration generation mismatch'; END IF;
  -- Same inactive participant recovery preserves its mutable progress projection.
  -- A new participant after remove/global reset never revives historical progress.
  IF ev.registration_disposition='reactivate' AND part.participant_id=(d->>'participantId')::bigint THEN
   UPDATE identity.ctf_progress_bindings SET owner_generation=owner_gen,owner_revision=a.revision,applied_sequence=p_sequence,applied_operation_id=p_operation
    WHERE owner_id=target AND owner_generation=part.owner_generation AND participant_id=part.participant_id;
  END IF;
  IF NOT EXISTS(SELECT 1 FROM identity.ctf_registration_reservations AS reservation WHERE reservation.operation_id=p_operation AND reservation.owner_id=target AND reservation.state='held') THEN RAISE EXCEPTION 'CTF capacity reservation missing'; END IF;
  INSERT INTO identity.ctf_participant_bindings VALUES(target,owner_gen,(d->>'participantId')::bigint,a.revision,observed_global_revision,true,a.banned,(d->>'registeredAt')::timestamptz,p_sequence,p_operation)
   ON CONFLICT(owner_id) DO UPDATE SET owner_generation=EXCLUDED.owner_generation,participant_id=EXCLUDED.participant_id,owner_revision=EXCLUDED.owner_revision,global_revision=EXCLUDED.global_revision,active=true,banned=EXCLUDED.banned,registered_at=EXCLUDED.registered_at,applied_sequence=EXCLUDED.applied_sequence,applied_operation_id=EXCLUDED.applied_operation_id;
  UPDATE identity.ctf_registration_reservations AS reservation SET state='applied',resolved_at=clock_timestamp() WHERE reservation.operation_id=p_operation AND reservation.state='held';
 ELSIF k='start' THEN
  IF pr.progress_id IS NOT NULL AND pr.progress_id IS DISTINCT FROM (d->>'progressId')::bigint THEN RAISE EXCEPTION 'CTF progress incarnation changed'; END IF;
  IF pr.progress_id IS NOT NULL AND (pr.status IS DISTINCT FROM d->>'status' OR pr.started_at IS DISTINCT FROM (d->>'startedAt')::timestamptz
   OR pr.completed_at IS DISTINCT FROM (d->>'completedAt')::timestamptz OR pr.completion_time IS DISTINCT FROM (d->>'completionTime')::bigint
   OR pr.attempts_count IS DISTINCT FROM (d->>'attemptsCount')::integer OR pr.failed_attempts IS DISTINCT FROM (d->>'failedAttempts')::integer
   OR pr.successful_attempts IS DISTINCT FROM (d->>'successfulAttempts')::integer OR pr.hints_used IS DISTINCT FROM (d->>'hintsUsed')::integer
   OR pr.hint_penalty_total IS DISTINCT FROM (d->>'hintPenaltyTotal')::integer) THEN RAISE EXCEPTION 'CTF recovered progress state drift'; END IF;
  IF pr.progress_id IS NULL AND (d->>'status'<>'in_progress' OR (d->>'startedAt')::timestamptz IS DISTINCT FROM (ev.command->>'occurredAt')::timestamptz
   OR (d->>'attemptsCount')::integer<>0 OR (d->>'failedAttempts')::integer<>0 OR (d->>'successfulAttempts')::integer<>0
   OR (d->>'hintsUsed')::integer<>0 OR (d->>'hintPenaltyTotal')::integer<>0) THEN RAISE EXCEPTION 'CTF new progress state drift'; END IF;
  INSERT INTO identity.ctf_progress_bindings(owner_id,owner_generation,stage_id,participant_id,progress_id,owner_revision,global_revision,stage_revision,stage_digest,status,started_at,completed_at,attempts_count,failed_attempts,successful_attempts,hints_used,hint_penalty_total,completion_time,applied_sequence,applied_operation_id)
   SELECT target,owner_gen,sid,part.participant_id,(d->>'progressId')::bigint,a.revision,observed_global_revision,s.stage_revision,s.stage_digest,d->>'status',(d->>'startedAt')::timestamptz,(d->>'completedAt')::timestamptz,(d->>'attemptsCount')::integer,(d->>'failedAttempts')::integer,(d->>'successfulAttempts')::integer,(d->>'hintsUsed')::integer,(d->>'hintPenaltyTotal')::integer,(d->>'completionTime')::bigint,p_sequence,p_operation FROM identity.ctf_stage_bindings s WHERE s.stage_id=sid
   ON CONFLICT(owner_id,owner_generation,stage_id) DO UPDATE SET applied_sequence=EXCLUDED.applied_sequence,applied_operation_id=EXCLUDED.applied_operation_id;
 ELSIF k='hint' THEN
  IF (d->>'progressId')::bigint IS DISTINCT FROM pr.progress_id OR (d->>'hintsUsed')::integer IS DISTINCT FROM pr.hints_used+1 OR (d->>'hintPenaltyTotal')::integer IS DISTINCT FROM pr.hint_penalty_total+(b->>'cost')::integer THEN RAISE EXCEPTION 'CTF hint result mismatch'; END IF;
  UPDATE identity.ctf_progress_bindings SET hints_used=(d->>'hintsUsed')::integer,hint_penalty_total=(d->>'hintPenaltyTotal')::integer,applied_sequence=p_sequence,applied_operation_id=p_operation WHERE progress_id=pr.progress_id;
 ELSIF k='admit_attempt' THEN
  IF (d->>'progressId')::bigint IS DISTINCT FROM pr.progress_id OR (d->>'attemptNumber')::integer IS DISTINCT FROM pr.attempts_count+1 OR (d->>'failedAttempts')::integer IS DISTINCT FROM pr.failed_attempts+(CASE WHEN (b->>'failed')::boolean THEN 1 ELSE 0 END) THEN RAISE EXCEPTION 'CTF attempt result mismatch'; END IF;
  UPDATE identity.ctf_progress_bindings SET attempts_count=(d->>'attemptNumber')::integer,failed_attempts=(d->>'failedAttempts')::integer,applied_sequence=p_sequence,applied_operation_id=p_operation WHERE progress_id=pr.progress_id;
  INSERT INTO identity.ctf_attempt_admissions VALUES(p_operation,target,owner_gen,part.participant_id,pr.progress_id,sid,(d->>'attemptNumber')::integer,(b->>'failed')::boolean,(ev.command->>'occurredAt')::timestamptz,p_sequence);
 ELSIF k='record_blocked_attempt' THEN
  IF d->>'admissionOperationId' IS DISTINCT FROM b->>'admissionOperationId' OR (d->>'payloadHitIncremented')::boolean IS DISTINCT FROM (b->>'matchedPayloadHash' IS NOT NULL) THEN RAISE EXCEPTION 'CTF blocked result mismatch'; END IF;
 ELSIF k='owner_reset' THEN
  IF (d->>'participantId')::bigint IS DISTINCT FROM part.participant_id THEN RAISE EXCEPTION 'CTF reset incarnation mismatch'; END IF;
  UPDATE identity.ctf_participant_bindings SET owner_generation=owner_gen,owner_revision=a.revision,applied_sequence=p_sequence,applied_operation_id=p_operation WHERE owner_id=target;
 ELSIF k='owner_remove' THEN
  IF (d->>'participantId')::bigint IS DISTINCT FROM part.participant_id OR part.participant_id IS NULL OR d->'removed' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'CTF remove incarnation mismatch'; END IF;
  UPDATE identity.ctf_participant_bindings SET active=false,owner_generation=owner_gen,owner_revision=a.revision,applied_sequence=p_sequence,applied_operation_id=p_operation WHERE owner_id=target AND participant_id=(d->>'participantId')::bigint;
 ELSIF k='global_reset' THEN
  UPDATE identity.ctf_participant_bindings SET active=false,applied_sequence=p_sequence,applied_operation_id=p_operation;
 ELSIF k IN ('ban','unban') THEN
  IF (d->>'ownerId')::bigint IS DISTINCT FROM target OR (d->>'banned')::boolean IS DISTINCT FROM (k='ban') THEN RAISE EXCEPTION 'CTF ban result mismatch'; END IF;
  UPDATE identity.ctf_authority SET banned=(k='ban'),revision=revision+1 WHERE scope_key='owner:'||target;
  UPDATE identity.ctf_participant_bindings SET banned=(k='ban'),applied_sequence=p_sequence,applied_operation_id=p_operation WHERE owner_id=target;
 ELSIF k='blocklist_clear' THEN
  IF d->>'memory' IS DISTINCT FROM b->>'memory' OR (d->>'stageId')::bigint IS DISTINCT FROM sid THEN RAISE EXCEPTION 'CTF clear result mismatch'; END IF;
  DELETE FROM identity.ctf_adaptive_memory WHERE kind=b->>'memory' AND (sid IS NULL OR stage_id=sid);
  UPDATE identity.ctf_authority SET clear_revision=clear_revision+1,adaptive_revision=adaptive_revision+1 WHERE scope_key=CASE WHEN sid IS NULL THEN 'global' ELSE 'stage:'||sid END;
 ELSIF k='catalog_mutation' THEN
  IF b->>'action'<>'create' AND (d->>'stageId')::bigint IS DISTINCT FROM sid THEN RAISE EXCEPTION 'CTF catalog result target mismatch'; END IF;
  IF b->>'action'='delete' AND d->'deleted' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'CTF catalog delete drift'; END IF;
  IF b->>'action'='delete' THEN UPDATE identity.ctf_stage_bindings SET active=false,applied_sequence=p_sequence,applied_operation_id=p_operation WHERE stage_id=sid;
  ELSE
   sid:=(d->>'stageId')::bigint;
   INSERT INTO identity.ctf_authority(scope_key,lifecycle_state) VALUES('stage:'||sid,'ready') ON CONFLICT DO NOTHING;
   INSERT INTO identity.ctf_stage_bindings SELECT sid,(d->>'stageNumber')::integer,x.revision,observed_global_revision,d->>'stageDigest',(d->>'stageOrder')::integer,(d->>'active')::boolean,d->>'adaptiveMode',d->>'feedbackMode',(d->>'hintCount')::integer,(d->>'levelScore')::integer,(d->>'maxAttempts')::integer,p_sequence,p_operation FROM identity.ctf_authority x WHERE x.scope_key='stage:'||sid
   ON CONFLICT(stage_id) DO UPDATE SET stage_revision=EXCLUDED.stage_revision,global_revision=EXCLUDED.global_revision,stage_digest=EXCLUDED.stage_digest,stage_order=EXCLUDED.stage_order,active=EXCLUDED.active,adaptive_mode=EXCLUDED.adaptive_mode,feedback_mode=EXCLUDED.feedback_mode,hint_count=EXCLUDED.hint_count,level_score=EXCLUDED.level_score,max_attempts=EXCLUDED.max_attempts,applied_sequence=EXCLUDED.applied_sequence,applied_operation_id=EXCLUDED.applied_operation_id;
  END IF;
 ELSIF k='config_mutation' THEN
  IF d->>'key' IS DISTINCT FROM b->>'key' OR d->>'value' IS DISTINCT FROM b->>'value' THEN RAISE EXCEPTION 'CTF config result mismatch'; END IF;
  UPDATE identity.ctf_config_binding SET
   enabled=CASE WHEN b->>'key'='ctf_enabled' THEN (b->>'value')::boolean ELSE enabled END,
   visible_to_students=CASE WHEN b->>'key'='ctf_visible_to_students' THEN (b->>'value')::boolean ELSE visible_to_students END,
   registration_open=CASE WHEN b->>'key'='ctf_registration_open' THEN (b->>'value')::boolean ELSE registration_open END,
   student_leaderboard_visible=CASE WHEN b->>'key'='student_leaderboard_visible' THEN (b->>'value')::boolean ELSE student_leaderboard_visible END,
   public_leaderboard_visible=CASE WHEN b->>'key'='public_leaderboard_visible' THEN (b->>'value')::boolean ELSE public_leaderboard_visible END,
   nav_visible=CASE WHEN b->>'key'='ctf_nav_visible' THEN (b->>'value')::boolean ELSE nav_visible END,
   show_technique_feedback=CASE WHEN b->>'key'='ctf_show_technique_feedback' THEN (b->>'value')::boolean ELSE show_technique_feedback END,
   show_attempt_counter=CASE WHEN b->>'key'='ctf_show_attempt_counter' THEN (b->>'value')::boolean ELSE show_attempt_counter END,
   max_participants=CASE WHEN b->>'key'='ctf_max_participants' THEN (b->>'value')::bigint ELSE max_participants END,
   time_limit_ms=CASE WHEN b->>'key'='ctf_time_limit' THEN (b->>'value')::bigint ELSE time_limit_ms END,
   leaderboard_update_interval_ms=CASE WHEN b->>'key'='leaderboard_update_interval' THEN (b->>'value')::integer ELSE leaderboard_update_interval_ms END,
   hint_gating_attempts=CASE WHEN b->>'key'='ctf_hint_gating_attempts' THEN (b->>'value')::integer ELSE hint_gating_attempts END,
   hint_cost_1=CASE WHEN b->>'key'='ctf_hint_cost_1' THEN (b->>'value')::integer ELSE hint_cost_1 END,
   hint_cost_2=CASE WHEN b->>'key'='ctf_hint_cost_2' THEN (b->>'value')::integer ELSE hint_cost_2 END,
   hint_cost_3=CASE WHEN b->>'key'='ctf_hint_cost_3' THEN (b->>'value')::integer ELSE hint_cost_3 END,
   global_revision=observed_global_revision,applied_sequence=p_sequence,applied_operation_id=p_operation WHERE singleton;
 ELSE RAISE EXCEPTION 'CTF delivery kind unavailable'; END IF;
 UPDATE identity.ctf_outbox AS delivered SET state='applied',canonical_result=p_result,result_hash=p_result_hash,applied_at=clock_timestamp() WHERE delivered.operation_id=p_operation;
 UPDATE identity.ctf_authority SET lifecycle_state='ready',pending_operation_id=NULL WHERE pending_operation_id=p_operation AND lifecycle_state='pending' AND blocked_operation_id IS NULL;
 UPDATE identity.ctf_authority SET applied_sequence=p_sequence WHERE scope_key='global';
 RETURN QUERY SELECT 'applied'::text,p_sequence;
END; $$;
REVOKE ALL ON FUNCTION identity.ack_ctf_projection(uuid,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.ack_ctf_projection(uuid,bigint,text,text,text) TO dvaia_identity_runtime;
