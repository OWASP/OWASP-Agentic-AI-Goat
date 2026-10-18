-- Unmounted forward projection metadata. Never reconstruct missing historical
-- facts from a later mutable catalog. Context and inference claim commit together.
CREATE TABLE identity.ctf_projection_context (
 admission_id uuid PRIMARY KEY REFERENCES identity.ctf_decision_inputs(admission_id),
 stage_snapshot text NOT NULL CHECK(octet_length(stage_snapshot)<=65536),
 stage_digest text NOT NULL CHECK(stage_digest=encode(sha256(convert_to(stage_snapshot,'UTF8')),'hex')),
 stage_name text NOT NULL CHECK(octet_length(stage_name)<=1024),
 adaptive_mode text NOT NULL CHECK(adaptive_mode IN ('none','technique','payload','hybrid')),
 level_score integer CHECK(level_score BETWEEN 0 AND 1000000)
);
CREATE TRIGGER ctf_projection_context_immutable BEFORE UPDATE OR DELETE ON identity.ctf_projection_context FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_projection_context FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_projection_context TO dvaia_identity_runtime;
CREATE FUNCTION identity.claim_ctf_projection_input(p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text,p_stage_snapshot text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb; pairs jsonb;pair jsonb;stage jsonb:='{}'::jsonb;k text;previous_key text;answer jsonb;prior identity.ctf_projection_context%ROWTYPE;
BEGIN
 IF p_document IS NULL OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS) OR octet_length(p_document)>32768
 OR p_stage_snapshot IS NULL OR octet_length(p_stage_snapshot)>65536 OR NOT(p_stage_snapshot IS JSON ARRAY WITH UNIQUE KEYS) THEN RAISE EXCEPTION 'CTF projection context invalid'; END IF;
 e:=p_document::jsonb;pairs:=p_stage_snapshot::jsonb;
 IF encode(sha256(convert_to(p_stage_snapshot,'UTF8')),'hex') IS DISTINCT FROM e->'binding'->>'stageDigest' THEN RAISE EXCEPTION 'CTF stage snapshot digest mismatch'; END IF;
 FOR pair IN SELECT value FROM jsonb_array_elements(pairs) LOOP
  IF jsonb_typeof(pair) IS DISTINCT FROM 'array' OR jsonb_array_length(pair)<>2 OR jsonb_typeof(pair->0) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'CTF stage snapshot pairs invalid'; END IF;
  k:=pair->>0;
  IF NOT(k=ANY(ARRAY['id','stage_number','stage_name','stage_description','difficulty_level','ai_guardian_name','ai_guardian_personality','system_prompt','success_criteria','hints','max_attempts','time_penalty_per_wrong_attempt','is_active','stage_order','difficulty','defense_style','adaptive_mode','level_score','time_bonus_seconds','feedback_mode','created_at']))
  OR (previous_key IS NOT NULL AND k COLLATE "C"<=previous_key COLLATE "C") THEN RAISE EXCEPTION 'CTF stage snapshot keys invalid'; END IF;
  previous_key:=k;stage:=stage||jsonb_build_object(k,pair->1);
 END LOOP;
 IF NOT identity.ctf_json_matches(stage->'stage_name','{"type":"string","bytes":1024}'::jsonb)
 OR NOT identity.ctf_json_matches(stage->'adaptive_mode','{"type":"string","enum":["none","technique","payload","hybrid"]}'::jsonb)
 OR NOT identity.ctf_json_matches(stage->'level_score','{"type":"number","integer":true,"minimum":0,"maximum":1000000,"nullable":true}'::jsonb)
 OR (stage->>'id') IS DISTINCT FROM e->'binding'->>'stageId' OR (stage->>'stage_number') IS DISTINCT FROM e->'binding'->>'stageNumber' THEN RAISE EXCEPTION 'CTF stage snapshot projection fields invalid'; END IF;
 -- Existing function authenticates original admitted session, takes the user
 -- row lock and atomically inserts the durable at-most-once inference claim.
 answer:=identity.capture_ctf_decision_input(p_actor,p_session,p_token_hash,p_document,p_hash);
 SELECT * INTO prior FROM identity.ctf_projection_context pc WHERE pc.admission_id=(e->'binding'->>'admissionId')::uuid;
 IF FOUND THEN
  IF prior.stage_snapshot IS DISTINCT FROM p_stage_snapshot THEN RAISE EXCEPTION 'CTF projection context replay mismatch'; END IF;
 ELSE
  IF answer->'claimed' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'CTF historical input requires explicit recovery'; END IF;
  INSERT INTO identity.ctf_projection_context VALUES((e->'binding'->>'admissionId')::uuid,p_stage_snapshot,e->'binding'->>'stageDigest',stage->>'stage_name',stage->>'adaptive_mode',(stage->>'level_score')::integer);
 END IF;
 RETURN answer;
END; $$;
REVOKE ALL ON FUNCTION identity.claim_ctf_projection_input(integer,integer,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.claim_ctf_projection_input(integer,integer,text,text,text,text) TO dvaia_identity_runtime;
REVOKE EXECUTE ON FUNCTION identity.capture_ctf_decision_input(integer,integer,text,text,text) FROM dvaia_identity_runtime;

CREATE TABLE identity.ctf_decision_projection_facts (
 decision_id uuid PRIMARY KEY,sequence bigint NOT NULL UNIQUE,
 evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[a-f0-9]{64}$'),
 canonical_facts text NOT NULL CHECK(octet_length(canonical_facts)<=16384),
 facts_hash text NOT NULL CHECK(facts_hash=encode(sha256(convert_to(canonical_facts,'UTF8')),'hex')),
 facts jsonb NOT NULL CHECK(facts=canonical_facts::jsonb AND jsonb_typeof(facts)='object'),
 FOREIGN KEY(decision_id,sequence) REFERENCES identity.ctf_decisions(decision_id,sequence)
);
CREATE TRIGGER ctf_projection_facts_immutable BEFORE UPDATE OR DELETE ON identity.ctf_decision_projection_facts FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_decision_projection_facts FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_decision_projection_facts TO dvaia_identity_runtime;
CREATE FUNCTION identity.capture_ctf_projection_facts() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d identity.ctf_decisions%ROWTYPE;p identity.ctf_decision_proposals%ROWTYPE;i identity.ctf_decision_inputs%ROWTYPE;a identity.ctf_attempt_admissions%ROWTYPE;c identity.ctf_projection_context%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;
 matched identity.ctf_adaptive_memory%ROWTYPE;f jsonb;encoded text;
BEGIN
 SELECT * INTO d FROM identity.ctf_decisions dd WHERE dd.decision_id=NEW.decision_id;
 SELECT * INTO p FROM identity.ctf_decision_proposals pp WHERE pp.proposal_id=d.proposal_id;
 SELECT * INTO i FROM identity.ctf_decision_inputs ii WHERE ii.admission_id=p.admission_operation_id;
 SELECT * INTO a FROM identity.ctf_attempt_admissions aa WHERE aa.operation_id=i.admission_id;
 SELECT * INTO c FROM identity.ctf_projection_context cc WHERE cc.admission_id=i.admission_id;
 SELECT * INTO pr FROM identity.ctf_progress_bindings pb WHERE pb.progress_id=d.progress_id;
 IF d.decision_id IS NULL OR c.admission_id IS NULL OR NEW.operation_id IS DISTINCT FROM d.decision_id OR NEW.sequence IS DISTINCT FROM d.sequence OR NEW.actor_id IS DISTINCT FROM d.owner_id OR NEW.session_id IS DISTINCT FROM d.session_id
 OR NEW.canonical_command IS NULL OR NEW.command->>'operationId' IS DISTINCT FROM d.decision_id::text OR NEW.command->>'actorId' IS DISTINCT FROM d.owner_id::text
 OR NEW.command->'body'->>'decisionId' IS DISTINCT FROM d.decision_id::text OR NEW.command->'body'->>'proposalId' IS DISTINCT FROM d.proposal_id::text
 OR NEW.command->'scope'->>'ownerId' IS DISTINCT FROM d.owner_id::text OR NEW.command->'scope'->>'ownerGeneration' IS DISTINCT FROM d.owner_generation::text
 OR NEW.command->'scope'->>'participantId' IS DISTINCT FROM d.participant_id::text OR NEW.command->'scope'->>'progressId' IS DISTINCT FROM d.progress_id::text OR NEW.command->'scope'->>'stageId' IS DISTINCT FROM d.stage_id::text
 OR NEW.command->'scope'->>'globalRevision' IS DISTINCT FROM d.global_revision::text OR NEW.command->'scope'->>'stageRevision' IS DISTINCT FROM d.stage_revision::text
 OR NEW.command->'body'->>'evidenceHash' IS DISTINCT FROM d.evidence_hash OR p.evidence_hash IS DISTINCT FROM d.evidence_hash OR i.run_id IS DISTINCT FROM d.run_id OR i.owner_id IS DISTINCT FROM d.owner_id OR i.session_id IS DISTINCT FROM d.session_id
 OR a.owner_generation IS DISTINCT FROM d.owner_generation OR a.participant_id IS DISTINCT FROM d.participant_id OR a.progress_id IS DISTINCT FROM d.progress_id OR a.stage_id IS DISTINCT FROM d.stage_id OR c.stage_digest IS DISTINCT FROM d.stage_digest
 OR pr.owner_id IS DISTINCT FROM d.owner_id OR pr.owner_generation IS DISTINCT FROM d.owner_generation OR pr.hint_penalty_total IS DISTINCT FROM d.hint_penalty_total THEN RAISE EXCEPTION 'CTF projection facts context unavailable'; END IF;
 -- This trigger executes inside authorization's global/stage/owner locks,
 -- after authoritative memory inserts. Choose a deterministic matched payload
 -- identity, not a guess from verdict. Technique-only blocking has no hit.
 IF d.verdict='blocked' AND c.adaptive_mode IN ('payload','hybrid') THEN
  SELECT * INTO matched FROM identity.ctf_adaptive_memory am WHERE am.kind='payload' AND am.stage_id=d.stage_id
   AND (am.payload_hash=p.evidence->>'payloadHash' OR identity.ctf_ascii_payload_similar(p.evidence->>'normalizedPayload',am.normalized_payload))
   ORDER BY am.memory_id LIMIT 1;
 END IF;
 f:=jsonb_build_object('version',1,'decisionId',d.decision_id,'sequence',d.sequence::text,'stageName',c.stage_name,'adaptiveMode',c.adaptive_mode,'stageScore',c.level_score,
 'attemptNumber',a.attempt_number,'failedCounterIncrement',a.failed_counter_increment,'attemptsCount',pr.attempts_count,'failedAttempts',pr.failed_attempts,'successfulAttempts',pr.successful_attempts,'hintsUsed',pr.hints_used,'hintPenaltyTotal',d.hint_penalty_total,
 'techniqueAdded',EXISTS(SELECT 1 FROM identity.ctf_adaptive_memory am WHERE am.decision_id=d.decision_id AND am.kind='technique'),
 'payloadAdded',EXISTS(SELECT 1 FROM identity.ctf_adaptive_memory am WHERE am.decision_id=d.decision_id AND am.kind='payload'),
 'matchedPayloadHash',matched.payload_hash,'matchedPayloadMemoryId',matched.memory_id,'responseTime',NULL,'techniqueConfidence',NULL,'teachingSessionToken',NULL);
 encoded:=f::text;
 INSERT INTO identity.ctf_decision_projection_facts VALUES(d.decision_id,d.sequence,d.evidence_hash,encoded,encode(sha256(convert_to(encoded,'UTF8')),'hex'),f);
 RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION identity.capture_ctf_projection_facts() FROM PUBLIC;
CREATE TRIGGER ctf_capture_decision_projection_facts AFTER INSERT ON identity.ctf_outbox FOR EACH ROW WHEN(NEW.kind='decision') EXECUTE FUNCTION identity.capture_ctf_projection_facts();

CREATE FUNCTION identity.ctf_decision_receipt_matches(v jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE d jsonb:=v->'data';stamp text;
BEGIN
 IF NOT identity.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[2]},"kind":{"type":"string","enum":["decision"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"sequence":{"type":"string","bytes":19,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":9223372036854775807},"commandHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"outcome":{"type":"string","enum":["applied"]},"data":{"type":"object","properties":{"decisionId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"runId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"admissionId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"evidenceHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"factsHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"attemptId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"accepted":{"type":"boolean"},"verdict":{"type":"string","enum":["pass","fail","inconclusive","unavailable","blocked"]},"status":{"type":"string","enum":["in_progress","completed"]},"attemptsCount":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"failedAttempts":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"successfulAttempts":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"hintPenaltyTotal":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"hintsUsed":{"type":"number","integer":true,"minimum":0,"maximum":3},"completedAt":{"type":"string","bytes":27,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}([0-9]{3})?Z$","nullable":true},"completionTimeMs":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":9223372036854775807,"nullable":true},"techniqueAdded":{"type":"boolean"},"payloadAdded":{"type":"boolean"},"payloadHitIncremented":{"type":"boolean"}}}}}'::jsonb) THEN RETURN false; END IF;
 IF d->>'decisionId' IS DISTINCT FROM v->>'operationId' OR (d->'accepted'='true'::jsonb AND d->>'verdict'<>'pass') THEN RETURN false; END IF;
 IF d->'accepted'='true'::jsonb THEN
  IF d->>'status'<>'completed' OR d->'completedAt'='null'::jsonb OR d->'completionTimeMs'='null'::jsonb THEN RETURN false; END IF;
  stamp:=d->>'completedAt';
  IF to_char(stamp::timestamptz AT TIME ZONE 'UTC',CASE WHEN length(stamp)=27 THEN 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"' ELSE 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"' END) IS DISTINCT FROM stamp THEN RETURN false; END IF;
 ELSE
  IF d->>'status'<>'in_progress' OR d->'completedAt'<>'null'::jsonb OR d->'completionTimeMs'<>'null'::jsonb THEN RETURN false; END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END; $$;
REVOKE ALL ON FUNCTION identity.ctf_decision_receipt_matches(jsonb) FROM PUBLIC;

CREATE FUNCTION identity.ack_ctf_decision_projection(p_operation uuid,p_sequence bigint,p_command_hash text,p_receipt text,p_receipt_hash text)
RETURNS TABLE(operation_id uuid,sequence bigint,state text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE g identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;ev identity.ctf_outbox%ROWTYPE;d identity.ctf_decisions%ROWTYPE;f identity.ctf_decision_projection_facts%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;r jsonb;data jsonb;facts jsonb;
BEGIN
 IF p_receipt IS NULL OR octet_length(p_receipt)>16384 OR NOT(p_receipt IS JSON OBJECT WITH UNIQUE KEYS)
 OR p_receipt_hash IS DISTINCT FROM encode(sha256(convert_to(p_receipt,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF decision receipt bytes invalid'; END IF;
 r:=p_receipt::jsonb;data:=r->'data';
 IF NOT identity.ctf_decision_receipt_matches(r) OR r->>'operationId' IS DISTINCT FROM p_operation::text OR r->>'sequence' IS DISTINCT FROM p_sequence::text OR r->>'commandHash' IS DISTINCT FROM p_command_hash THEN RAISE EXCEPTION 'CTF decision receipt invalid'; END IF;
 SELECT * INTO g FROM identity.ctf_authority aa WHERE aa.scope_key='global' FOR UPDATE;
 SELECT * INTO ev FROM identity.ctf_outbox oo WHERE oo.operation_id=p_operation;
 SELECT * INTO o FROM identity.ctf_authority aa WHERE aa.scope_key='owner:'||ev.actor_id FOR UPDATE;
 SELECT * INTO ev FROM identity.ctf_outbox oo WHERE oo.operation_id=p_operation FOR UPDATE;
 IF ev.kind IS DISTINCT FROM 'decision' OR ev.sequence IS DISTINCT FROM p_sequence OR ev.command_hash IS DISTINCT FROM p_command_hash THEN RAISE EXCEPTION 'CTF decision delivery mismatch'; END IF;
 IF ev.state='applied' THEN
  IF ev.canonical_result IS DISTINCT FROM p_receipt OR ev.result_hash IS DISTINCT FROM p_receipt_hash THEN RAISE EXCEPTION 'CTF decision receipt replay mismatch'; END IF;
  RETURN QUERY SELECT p_operation,p_sequence,'applied'::text;RETURN;
 END IF;
 IF ev.state IS DISTINCT FROM 'pending' OR g.lifecycle_state NOT IN ('ready','pending') OR o.lifecycle_state IS DISTINCT FROM 'pending' OR o.pending_operation_id IS DISTINCT FROM p_operation OR g.applied_sequence+1 IS DISTINCT FROM p_sequence THEN RAISE EXCEPTION 'CTF decision delivery unavailable'; END IF;
 SELECT * INTO d FROM identity.ctf_decisions dd WHERE dd.decision_id=ev.decision_id;
 SELECT * INTO f FROM identity.ctf_decision_projection_facts ff WHERE ff.decision_id=d.decision_id AND ff.sequence=p_sequence;
 SELECT * INTO pr FROM identity.ctf_progress_bindings pp WHERE pp.progress_id=d.progress_id FOR UPDATE;
 facts:=f.facts;
 IF f.decision_id IS NULL OR pr.owner_id IS DISTINCT FROM d.owner_id OR pr.owner_generation IS DISTINCT FROM d.owner_generation OR pr.participant_id IS DISTINCT FROM d.participant_id OR pr.stage_id IS DISTINCT FROM d.stage_id OR pr.status IS DISTINCT FROM 'in_progress'
 OR data->>'decisionId' IS DISTINCT FROM d.decision_id::text OR data->>'runId' IS DISTINCT FROM d.run_id::text OR data->>'admissionId' IS DISTINCT FROM (SELECT pp.admission_operation_id::text FROM identity.ctf_decision_proposals pp WHERE pp.proposal_id=d.proposal_id)
 OR data->>'evidenceHash' IS DISTINCT FROM d.evidence_hash OR data->>'factsHash' IS DISTINCT FROM f.facts_hash
 OR data->>'participantId' IS DISTINCT FROM d.participant_id::text OR data->>'progressId' IS DISTINCT FROM d.progress_id::text OR data->>'stageId' IS DISTINCT FROM d.stage_id::text
 OR (data->>'accepted')::boolean IS DISTINCT FROM d.accepted OR data->>'verdict' IS DISTINCT FROM d.verdict
 OR pr.attempts_count IS DISTINCT FROM (facts->>'attemptsCount')::integer OR pr.failed_attempts IS DISTINCT FROM (facts->>'failedAttempts')::integer OR pr.successful_attempts IS DISTINCT FROM (facts->>'successfulAttempts')::integer OR pr.hints_used IS DISTINCT FROM (facts->>'hintsUsed')::integer OR pr.hint_penalty_total IS DISTINCT FROM d.hint_penalty_total THEN RAISE EXCEPTION 'CTF decision projected identity mismatch'; END IF;
 IF (data->>'attemptsCount')::integer IS DISTINCT FROM pr.attempts_count
 OR (data->>'failedAttempts')::integer IS DISTINCT FROM pr.failed_attempts+(CASE WHEN NOT d.accepted AND NOT (facts->>'failedCounterIncrement')::boolean THEN 1 ELSE 0 END)
 OR (data->>'successfulAttempts')::integer IS DISTINCT FROM pr.successful_attempts+(CASE WHEN d.accepted THEN 1 ELSE 0 END)
 OR (data->>'hintsUsed')::integer IS DISTINCT FROM pr.hints_used OR (data->>'hintPenaltyTotal')::integer IS DISTINCT FROM d.hint_penalty_total
 OR data->'techniqueAdded' IS DISTINCT FROM facts->'techniqueAdded' OR data->'payloadAdded' IS DISTINCT FROM facts->'payloadAdded'
 OR (data->>'payloadHitIncremented')::boolean IS DISTINCT FROM (facts->>'matchedPayloadHash' IS NOT NULL)
 OR (data->>'completionTimeMs')::bigint IS DISTINCT FROM d.completion_time_ms
 OR (d.accepted AND (data->>'completedAt')::timestamptz IS DISTINCT FROM d.authorized_at) THEN RAISE EXCEPTION 'CTF decision projected effects mismatch'; END IF;
 UPDATE identity.ctf_progress_bindings SET status=data->>'status',completed_at=(data->>'completedAt')::timestamptz,completion_time=d.completion_time_ms,failed_attempts=(data->>'failedAttempts')::integer,successful_attempts=(data->>'successfulAttempts')::integer,applied_sequence=p_sequence,applied_operation_id=p_operation WHERE progress_id=d.progress_id;
 UPDATE identity.ctf_outbox oo SET state='applied',canonical_result=p_receipt,result_hash=p_receipt_hash,applied_at=clock_timestamp() WHERE oo.operation_id=p_operation;
 UPDATE identity.ctf_authority aa SET applied_sequence=p_sequence WHERE aa.scope_key='global';
 UPDATE identity.ctf_authority aa SET lifecycle_state='ready',pending_operation_id=NULL WHERE aa.scope_key='owner:'||d.owner_id AND aa.pending_operation_id=p_operation;
 RETURN QUERY SELECT p_operation,p_sequence,'applied'::text;
END; $$;
REVOKE ALL ON FUNCTION identity.ack_ctf_decision_projection(uuid,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.ack_ctf_decision_projection(uuid,bigint,text,text,text) TO dvaia_identity_runtime;
