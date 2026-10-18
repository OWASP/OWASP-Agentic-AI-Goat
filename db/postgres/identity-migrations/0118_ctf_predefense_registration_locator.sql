-- Original registration locator is telemetry only. No prompt or stage duplicate.
CREATE TABLE identity.ctf_predefense_registration_locators (
 run_id uuid PRIMARY KEY REFERENCES identity.ctf_predefense_claims(run_id),
 registration_token text CHECK(octet_length(registration_token)<=256)
);
CREATE TRIGGER ctf_predefense_locator_immutable BEFORE UPDATE OR DELETE ON identity.ctf_predefense_registration_locators FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_predefense_registration_locators FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_predefense_registration_locators TO dvaia_identity_runtime;
CREATE FUNCTION identity.claim_ctf_predefense_with_locator(p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text,p_snapshot text,p_locator text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE answer jsonb; saved text; bound boolean;
BEGIN
 IF octet_length(p_locator)>256 THEN RAISE EXCEPTION 'CTF registration locator invalid'; END IF;
 answer:=identity.claim_ctf_predefense(p_actor,p_session,p_token_hash,p_document,p_hash,p_snapshot);
 IF answer->'claimed'='true'::jsonb THEN
  INSERT INTO identity.ctf_predefense_registration_locators(run_id,registration_token) VALUES((answer->>'runId')::uuid,p_locator);
 END IF;
 SELECT l.registration_token INTO saved FROM identity.ctf_predefense_registration_locators l WHERE l.run_id=(answer->>'runId')::uuid;
 bound:=FOUND;
 -- Historical unbound claims are deliberately not backfilled on recovery.
 RETURN answer||jsonb_build_object('registrationToken',saved,'registrationLocatorBound',bound);
END; $$;
REVOKE ALL ON FUNCTION identity.claim_ctf_predefense_with_locator(integer,integer,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.claim_ctf_predefense_with_locator(integer,integer,text,text,text,text,text) TO dvaia_identity_runtime;
REVOKE EXECUTE ON FUNCTION identity.claim_ctf_predefense(integer,integer,text,text,text,text) FROM dvaia_identity_runtime;

CREATE OR REPLACE FUNCTION identity.prepare_ctf_blocked_predefense(p_actor integer,p_session integer,p_token_hash text,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;done identity.ctf_predefense_consumptions%ROWTYPE;o identity.ctf_predefense_outcomes%ROWTYPE;a identity.ctf_attempt_admissions%ROWTYPE;
 ev identity.ctf_outbox%ROWTYPE;old identity.ctf_outbox%ROWTYPE;b jsonb;body jsonb;doc jsonb;reason text;show_feedback boolean;feedback text;
BEGIN
 SELECT * INTO c FROM identity.ctf_predefense_claims cc WHERE cc.run_id=p_run;
 IF c.run_id IS NULL THEN RAISE EXCEPTION 'CTF pre-defense claim unavailable'; END IF;
 b:=c.input->'binding';PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,false);
 SELECT * INTO done FROM identity.ctf_predefense_consumptions pc WHERE pc.run_id=p_run;
 IF done.run_id IS NULL OR done.final_disposition='continue' THEN RAISE EXCEPTION 'CTF blocked disposition unavailable'; END IF;
 SELECT oo.* INTO old FROM identity.ctf_predefense_blocked_commands bc JOIN identity.ctf_outbox oo ON oo.operation_id=bc.operation_id AND oo.command_hash=bc.command_hash WHERE bc.run_id=p_run;
 IF FOUND THEN
  IF old.operation_id IS DISTINCT FROM c.blocked_operation_id OR old.actor_id IS DISTINCT FROM p_actor OR old.session_id IS DISTINCT FROM p_session OR old.kind IS DISTINCT FROM 'record_blocked_attempt' THEN RAISE EXCEPTION 'CTF blocked replay binding mismatch'; END IF;
  RETURN jsonb_build_object('operationId',old.operation_id,'command',old.command,'canonicalCommand',old.canonical_command,'replayed',true,'currentState',false);
 END IF;
 IF EXISTS(SELECT 1 FROM identity.ctf_outbox oo WHERE oo.operation_id=c.blocked_operation_id) THEN RAISE EXCEPTION 'CTF blocked reserved operation conflict'; END IF;
 SELECT * INTO ev FROM identity.ctf_outbox oo WHERE oo.operation_id=done.operation_id;
 SELECT * INTO a FROM identity.ctf_attempt_admissions aa WHERE aa.operation_id=done.operation_id;
 SELECT * INTO o FROM identity.ctf_predefense_outcomes po WHERE po.run_id=p_run;
 IF ev.state IS DISTINCT FROM 'applied' OR ev.kind IS DISTINCT FROM 'admit_attempt' OR ev.actor_id IS DISTINCT FROM p_actor OR ev.session_id IS DISTINCT FROM p_session OR ev.operation_id IS DISTINCT FROM c.admission_operation_id
 OR a.owner_id IS DISTINCT FROM p_actor OR a.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint OR a.participant_id IS DISTINCT FROM (b->>'participantId')::bigint OR a.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR a.stage_id IS DISTINCT FROM (b->>'stageId')::bigint OR a.failed_counter_increment IS DISTINCT FROM done.failed OR o.run_id IS NULL THEN RAISE EXCEPTION 'CTF blocked admission not acknowledged'; END IF;
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,true);
 SELECT cfg.show_technique_feedback INTO show_feedback FROM identity.ctf_config_binding cfg WHERE cfg.singleton;
 SELECT st.feedback_mode INTO feedback FROM identity.ctf_stage_bindings st WHERE st.stage_id=a.stage_id;
 IF done.final_disposition='category' THEN reason:=CASE WHEN show_feedback THEN 'Technique "'||(c.input->>'techniqueTag')||'" has already been used on this level. Try a different approach.' ELSE 'This approach has been blocked. Try something different.' END;
 ELSIF done.final_disposition='payload' THEN reason:=CASE WHEN show_feedback THEN 'This payload (or a very similar one) has already been used successfully by another participant.' ELSE 'This approach has been blocked by the community shield.' END;
 ELSE reason:=CASE WHEN feedback='silent' THEN 'Your input was blocked by the defense system.' ELSE o.outcome->>'reason' END;
 END IF;
 body:=jsonb_build_object('admissionOperationId',c.admission_operation_id,'matchedPayloadHash',done.matched_payload_hash,'attemptNumber',a.attempt_number,'payload',c.input->>'payload','response',NULL,'responseTime',0,'teachingSessionToken',(SELECT l.registration_token FROM identity.ctf_predefense_registration_locators l WHERE l.run_id=c.run_id),'techniqueTag',c.input->>'techniqueTag','techniqueConfidence',c.input->'techniqueConfidence','reason',reason,'payloadHash',c.input->>'payloadHash');
 doc:=jsonb_build_object('version',1,'kind','record_blocked_attempt','operationId',c.blocked_operation_id,'actorId',p_actor::text,'occurredAt',to_char(date_trunc('milliseconds',transaction_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
 'scope',jsonb_build_object('ownerId',b->>'ownerId','ownerGeneration',b->>'ownerGeneration','globalRevision',b->>'globalRevision','stageRevision',b->>'stageRevision','participantId',b->>'participantId','stageId',b->>'stageId','progressId',b->>'progressId'),'body',body);
 RETURN jsonb_build_object('operationId',c.blocked_operation_id,'command',doc,'canonicalCommand',NULL,'replayed',false,'currentState',false);
END; $$;

CREATE OR REPLACE FUNCTION identity.capture_ctf_projection_facts() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
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
 'matchedPayloadHash',matched.payload_hash,'matchedPayloadMemoryId',matched.memory_id,'responseTime',NULL,'techniqueConfidence',NULL,'teachingSessionToken',(SELECT l.registration_token FROM identity.ctf_predefense_registration_locators l JOIN identity.ctf_predefense_claims pc ON pc.run_id=l.run_id WHERE pc.run_id=d.run_id AND pc.admission_operation_id=i.admission_id AND pc.owner_id=d.owner_id AND pc.session_id=d.session_id));
 encoded:=f::text;
 INSERT INTO identity.ctf_decision_projection_facts VALUES(d.decision_id,d.sequence,d.evidence_hash,encoded,encode(sha256(convert_to(encoded,'UTF8')),'hex'),f);
 RETURN NEW;
END; $$;
