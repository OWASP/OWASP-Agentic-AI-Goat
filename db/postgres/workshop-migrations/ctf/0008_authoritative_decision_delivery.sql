-- Additive unmounted delivery support; legacy rows retain nullable links.
ALTER TABLE ctf.ctf_attempts ADD COLUMN decision_id uuid;
ALTER TABLE ctf.ctf_attempts ADD COLUMN admission_operation_id uuid;
ALTER TABLE ctf.ctf_attempts ADD CONSTRAINT ctf_attempt_authority_pair CHECK((decision_id IS NULL)=(admission_operation_id IS NULL));
CREATE UNIQUE INDEX ctf_attempt_authority_decision ON ctf.ctf_attempts(decision_id) WHERE decision_id IS NOT NULL;
CREATE UNIQUE INDEX ctf_attempt_authority_admission ON ctf.ctf_attempts(admission_operation_id) WHERE admission_operation_id IS NOT NULL;
ALTER TABLE ctf.ctf_progress ADD COLUMN authorized_decision_id uuid;
ALTER TABLE ctf.ctf_progress ADD COLUMN authorized_level_score integer CHECK(authorized_level_score BETWEEN 0 AND 1000000);
ALTER TABLE ctf.ctf_progress ALTER COLUMN completion_time TYPE bigint;
ALTER TABLE ctf.ctf_leaderboard ALTER COLUMN total_completion_time TYPE bigint;
ALTER TABLE ctf.projection_receipts DROP CONSTRAINT projection_receipts_kind_check;
ALTER TABLE ctf.projection_receipts ADD CONSTRAINT projection_receipts_kind_check CHECK(kind IN ('decision','catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear','admit_attempt','record_blocked_attempt','register','start','hint'));

CREATE FUNCTION ctf.ctf_decision_receipt_matches(v jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE d jsonb:=v->'data';stamp text;
BEGIN
 IF NOT ctf.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[2]},"kind":{"type":"string","enum":["decision"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"sequence":{"type":"string","bytes":19,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":9223372036854775807},"commandHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"outcome":{"type":"string","enum":["applied"]},"data":{"type":"object","properties":{"decisionId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"runId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"admissionId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"evidenceHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"factsHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"attemptId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"accepted":{"type":"boolean"},"verdict":{"type":"string","enum":["pass","fail","inconclusive","unavailable","blocked"]},"status":{"type":"string","enum":["in_progress","completed"]},"attemptsCount":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"failedAttempts":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"successfulAttempts":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"hintPenaltyTotal":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"hintsUsed":{"type":"number","integer":true,"minimum":0,"maximum":3},"completedAt":{"type":"string","bytes":27,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}([0-9]{3})?Z$","nullable":true},"completionTimeMs":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":9223372036854775807,"nullable":true},"techniqueAdded":{"type":"boolean"},"payloadAdded":{"type":"boolean"},"payloadHitIncremented":{"type":"boolean"}}}}}'::jsonb) THEN RETURN false; END IF;
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
REVOKE ALL ON FUNCTION ctf.ctf_decision_receipt_matches(jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION ctf.valid_projection_result(v text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN v IS JSON OBJECT WITH UNIQUE KEYS THEN CASE WHEN v::jsonb->>'kind'='decision' THEN ctf.ctf_decision_receipt_matches(v::jsonb) ELSE ctf.ctf_result_matches(v::jsonb) END ELSE false END
$$;
REVOKE ALL ON FUNCTION ctf.valid_projection_result(text),ctf.ctf_decision_receipt_matches(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctf.valid_projection_result(text),ctf.ctf_decision_receipt_matches(jsonb) TO dvaia_ctf_runtime;
CREATE FUNCTION ctf.refresh_authorized_leaderboard(p_authorized_at timestamptz) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO ctf.ctf_leaderboard(participant_id,username,team_name,total_stages_completed,total_completion_time,average_stage_time,total_attempts,success_rate,total_score,last_updated)
 SELECT p.id,p.username,p.team_name,COALESCE(x.cnt,0),COALESCE(x.elapsed,0),COALESCE(x.average,0),COALESCE(a.attempts,0),CASE WHEN COALESCE(a.attempts,0)>0 THEN a.successes::double precision/a.attempts*100 ELSE 0 END,COALESCE(x.score,0),p_authorized_at
 FROM ctf.ctf_participants p LEFT JOIN (SELECT pr.participant_id,COUNT(*) cnt,SUM(pr.completion_time) elapsed,AVG(pr.completion_time) average,SUM(GREATEST(0,(CASE WHEN pr.authorized_decision_id IS NULL THEN s.level_score ELSE pr.authorized_level_score END)-COALESCE(pr.hint_penalty_total,0))) score FROM ctf.ctf_progress pr JOIN ctf.ctf_stages s ON s.id=pr.stage_id WHERE pr.status='completed' GROUP BY pr.participant_id) x ON x.participant_id=p.id
 LEFT JOIN (SELECT participant_id,SUM(attempts_count) attempts,SUM(successful_attempts) successes FROM ctf.ctf_progress GROUP BY participant_id) a ON a.participant_id=p.id WHERE p.is_active=1
 ON CONFLICT(participant_id) DO UPDATE SET username=EXCLUDED.username,team_name=EXCLUDED.team_name,total_stages_completed=EXCLUDED.total_stages_completed,total_completion_time=EXCLUDED.total_completion_time,average_stage_time=EXCLUDED.average_stage_time,total_attempts=EXCLUDED.total_attempts,success_rate=EXCLUDED.success_rate,total_score=EXCLUDED.total_score,last_updated=GREATEST(ctf.ctf_leaderboard.last_updated,EXCLUDED.last_updated);
 WITH ranks AS (SELECT participant_id,rank() OVER(ORDER BY total_stages_completed DESC,total_score DESC,total_completion_time ASC) position FROM ctf.ctf_leaderboard) UPDATE ctf.ctf_leaderboard l SET rank_position=r.position FROM ranks r WHERE r.participant_id=l.participant_id;
END; $$;
REVOKE ALL ON FUNCTION ctf.refresh_authorized_leaderboard(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctf.refresh_authorized_leaderboard(timestamptz) TO dvaia_ctf_runtime;
