CREATE TABLE ctf.projection_receipts (
 sequence bigint PRIMARY KEY CHECK(sequence>0),operation_id uuid NOT NULL UNIQUE,kind text NOT NULL,
 command_hash text NOT NULL CHECK(command_hash ~ '^[a-f0-9]{64}$'),canonical_result text NOT NULL CHECK(octet_length(canonical_result)<=16384),
 result_hash text NOT NULL CHECK(result_hash ~ '^[a-f0-9]{64}$'),applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(kind IN ('catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear','admit_attempt','record_blocked_attempt','register','start','hint'))
);
CREATE FUNCTION ctf.reject_projection_receipt_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'CTF projection receipts are immutable'; END; $$;
REVOKE ALL ON FUNCTION ctf.reject_projection_receipt_mutation() FROM PUBLIC;
CREATE TRIGGER ctf_projection_receipts_immutable BEFORE UPDATE OR DELETE ON ctf.projection_receipts FOR EACH ROW EXECUTE FUNCTION ctf.reject_projection_receipt_mutation();
REVOKE ALL ON ctf.projection_receipts FROM PUBLIC,dvaia_ctf_runtime;
GRANT SELECT,INSERT ON ctf.projection_receipts TO dvaia_ctf_runtime;
GRANT UPDATE(applied_sequence,last_operation_id) ON ctf.projection_cursor TO dvaia_ctf_runtime;
GRANT INSERT,UPDATE ON ctf.projection_scopes TO dvaia_ctf_runtime;
-- initialized remains migration/maintenance-only; no bootstrap activation here.

-- Bounded closed validation for fixed internal schemas. No dynamic SQL.
CREATE FUNCTION ctf.ctf_json_matches(v jsonb,r jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
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
  FOR k,x IN SELECT * FROM jsonb_each(v) LOOP IF NOT ctf.ctf_json_matches(x,r->'properties'->k) THEN RETURN false; END IF; END LOOP;
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
REVOKE ALL ON FUNCTION ctf.ctf_json_matches(jsonb,jsonb) FROM PUBLIC;
CREATE FUNCTION ctf.ctf_result_matches(v jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE r jsonb;d jsonb:=v->'data';k text:=v->>'kind';
BEGIN
 IF NOT ctf.ctf_json_matches(v-'data','{"type":"object","properties":{"version":{"type":"number","enum":[1]},"kind":{"type":"string","enum":["register","start","hint","admit_attempt","record_blocked_attempt","catalog_mutation","config_mutation","owner_reset","owner_remove","global_reset","ban","unban","blocklist_clear"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"sequence":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":1,"maximum":9223372036854775807},"commandHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"outcome":{"type":"string","enum":["applied","registration_closed","capacity_reached"]}},"optional":false}'::jsonb) OR jsonb_typeof(d) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
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
 IF NOT ctf.ctf_json_matches(d,r) THEN RETURN false; END IF;
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
REVOKE ALL ON FUNCTION ctf.ctf_result_matches(jsonb) FROM PUBLIC;
CREATE FUNCTION ctf.valid_projection_result(v text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN v IS JSON OBJECT WITH UNIQUE KEYS THEN ctf.ctf_result_matches(v::jsonb) ELSE false END
$$;
REVOKE ALL ON FUNCTION ctf.valid_projection_result(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctf.valid_projection_result(text),ctf.ctf_result_matches(jsonb),ctf.ctf_json_matches(jsonb,jsonb) TO dvaia_ctf_runtime;
ALTER TABLE ctf.projection_receipts ADD CONSTRAINT ctf_receipt_envelope CHECK(ctf.valid_projection_result(canonical_result));
ALTER TABLE ctf.projection_receipts ADD CONSTRAINT ctf_receipt_binding CHECK(
 ((canonical_result::jsonb->>'operationId')::uuid=operation_id AND
 (canonical_result::jsonb->>'sequence')::bigint=sequence AND canonical_result::jsonb->>'kind'=kind AND
 canonical_result::jsonb->>'commandHash'=command_hash) IS TRUE);
ALTER TABLE ctf.projection_receipts ADD CONSTRAINT ctf_receipt_hash CHECK(result_hash=encode(sha256(convert_to(canonical_result,'UTF8')),'hex'));
