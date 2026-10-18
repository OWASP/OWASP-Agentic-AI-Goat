-- Prospective structures only: no proof issuer, replay entry or force-clear API.
-- Existing0001-0003 bytes and historical eligibility are unchanged.
DO $$ BEGIN
 PERFORM 1 FROM dvaia_maintenance.control WHERE singleton FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM dvaia_maintenance.control WHERE singleton AND state='clean') OR
 NOT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=1886610804 AND objid=90 AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
  RAISE EXCEPTION 'Executable recovery schema requires clean control';
 END IF;
END $$;
CREATE TABLE dvaia_maintenance.epoch_execution_admissions (
 epoch bigint PRIMARY KEY REFERENCES dvaia_maintenance.epoch_replay_profiles(epoch),
 operation_id uuid NOT NULL,
 admission_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 profile text NOT NULL CHECK(profile='canonical16-ctf-recovery-v1'),
 launch_policy text NOT NULL CHECK(launch_policy='exclusive-inprocess-no-helpers-v1'),
 source_manifest_sha256 text NOT NULL CHECK(source_manifest_sha256 ~ '^[a-f0-9]{64}$'),
 owner_record_sha256 text NOT NULL CHECK(owner_record_sha256 ~ '^[a-f0-9]{64}$'),
 launcher_policy_sha256 text NOT NULL CHECK(launcher_policy_sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(epoch,operation_id) REFERENCES dvaia_maintenance.epoch_bindings(epoch,operation_id)
);
CREATE TABLE dvaia_maintenance.recovery_abandonment_observations (
 epoch bigint NOT NULL REFERENCES dvaia_maintenance.epoch_execution_admissions(epoch),
 attempt_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 observation_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 prior_state text NOT NULL CHECK(prior_state IN ('claimed','reconciled')),
 prior_owner_sha256 text NOT NULL CHECK(prior_owner_sha256 ~ '^[a-f0-9]{64}$'),
 observer_record jsonb NOT NULL CHECK(jsonb_typeof(observer_record)='object' AND octet_length(observer_record::text)<=32768),
 observer_record_sha256 text NOT NULL CHECK(observer_record_sha256 ~ '^[a-f0-9]{64}$'),
 proof_sha256 text NOT NULL CHECK(proof_sha256 ~ '^[a-f0-9]{64}$'),
 finished_at timestamptz NOT NULL,
 PRIMARY KEY(epoch,attempt_id),
 FOREIGN KEY(epoch,attempt_id) REFERENCES dvaia_maintenance.recovery_attempts(epoch,attempt_id),
 FOREIGN KEY(epoch,operation_id) REFERENCES dvaia_maintenance.epoch_bindings(epoch,operation_id),
 CHECK(observer_record->>'version' IS NOT DISTINCT FROM '2' AND observer_record->>'ancestry' IS NOT DISTINCT FROM 'complete-supported-chain'),
 CHECK(observer_record_sha256=encode(sha256(convert_to(observer_record::text,'UTF8')),'hex'))
);
CREATE TABLE dvaia_maintenance.recovery_finish_claims (
 epoch bigint NOT NULL REFERENCES dvaia_maintenance.epoch_execution_admissions(epoch),
 attempt_id uuid NOT NULL, ordinal integer NOT NULL CHECK(ordinal>0),
 claim_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(), previous_claim_id uuid,
 operation_id uuid NOT NULL,
 publication_id uuid NOT NULL, publication_sha256 text NOT NULL CHECK(publication_sha256 ~ '^[a-f0-9]{64}$'),
 artifact_manifest_sha256 text NOT NULL CHECK(artifact_manifest_sha256 ~ '^[a-f0-9]{64}$'),
 owner_record jsonb NOT NULL CHECK(jsonb_typeof(owner_record)='object' AND octet_length(owner_record::text)<=32768),
 owner_record_sha256 text NOT NULL CHECK(owner_record_sha256 ~ '^[a-f0-9]{64}$'),
 proof_sha256 text NOT NULL CHECK(proof_sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(epoch,attempt_id,ordinal), UNIQUE(epoch,attempt_id,claim_id),
 FOREIGN KEY(epoch,attempt_id) REFERENCES dvaia_maintenance.recovery_attempts(epoch,attempt_id),
 FOREIGN KEY(epoch,operation_id) REFERENCES dvaia_maintenance.epoch_bindings(epoch,operation_id),
 FOREIGN KEY(epoch,attempt_id,previous_claim_id) REFERENCES dvaia_maintenance.recovery_finish_claims(epoch,attempt_id,claim_id),
 CHECK((ordinal=1)=(previous_claim_id IS NULL)),
 CHECK(owner_record->>'version' IS NOT DISTINCT FROM '2' AND owner_record->>'ancestry' IS NOT DISTINCT FROM 'complete-supported-chain'),
 CHECK(owner_record_sha256=encode(sha256(convert_to(owner_record::text,'UTF8')),'hex'))
);
CREATE TABLE dvaia_maintenance.recovery_finish_claim_results (
 epoch bigint PRIMARY KEY REFERENCES dvaia_maintenance.epoch_execution_admissions(epoch),
 attempt_id uuid NOT NULL, claim_id uuid NOT NULL,
 phase text NOT NULL CHECK(phase='finished'),
 finished_at timestamptz NOT NULL,
 FOREIGN KEY(epoch,attempt_id,claim_id) REFERENCES dvaia_maintenance.recovery_finish_claims(epoch,attempt_id,claim_id),
 FOREIGN KEY(epoch,attempt_id,phase) REFERENCES dvaia_maintenance.recovery_phase_receipts(epoch,attempt_id,phase),
 FOREIGN KEY(epoch) REFERENCES dvaia_maintenance.epoch_finish_receipts(epoch)
);
-- An actual common-row write, not only a lock, makes stale REPEATABLE READ
-- writers fail serialization. This also covers a snapshot predating admission:
-- do not condition the barrier on visibility of the prospective admission row.
-- The deferred checker never writes, so control triggers cannot recurse.
CREATE FUNCTION dvaia_maintenance.serialize_execution_write() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 UPDATE dvaia_maintenance.control SET epoch=epoch WHERE singleton;
 IF NOT FOUND THEN RAISE EXCEPTION 'Missing maintenance control'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER aaa_execution_attempt_barrier BEFORE INSERT OR UPDATE ON dvaia_maintenance.recovery_attempts FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.serialize_execution_write();
CREATE TRIGGER aaa_execution_abandonment_barrier BEFORE INSERT ON dvaia_maintenance.recovery_abandonment_observations FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.serialize_execution_write();
CREATE TRIGGER aaa_execution_claim_barrier BEFORE INSERT ON dvaia_maintenance.recovery_finish_claims FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.serialize_execution_write();
CREATE TRIGGER aaa_execution_result_barrier BEFORE INSERT ON dvaia_maintenance.recovery_finish_claim_results FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.serialize_execution_write();
CREATE FUNCTION dvaia_maintenance.guard_execution_admission() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE b dvaia_maintenance.epoch_bindings%ROWTYPE; p dvaia_maintenance.epoch_replay_profiles%ROWTYPE; c dvaia_maintenance.control%ROWTYPE; binding_xid text;
BEGIN
 SELECT * INTO STRICT c FROM dvaia_maintenance.control WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT b FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch;
 SELECT xmin::text INTO STRICT binding_xid FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch;
 SELECT * INTO STRICT p FROM dvaia_maintenance.epoch_replay_profiles WHERE epoch=NEW.epoch;
 IF binding_xid::numeric<>mod(pg_current_xact_id()::text::numeric,4294967296) OR c.state<>'dirty' OR c.epoch<>NEW.epoch OR c.operation_id<>NEW.operation_id OR
 b.operation_id<>NEW.operation_id OR p.operation_id<>NEW.operation_id OR
 NEW.source_manifest_sha256<>p.source_manifest_sha256 OR NEW.owner_record_sha256<>b.owner_record_sha256
 THEN RAISE EXCEPTION 'Invalid prospective execution admission'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guarded_execution_admission BEFORE INSERT ON dvaia_maintenance.epoch_execution_admissions FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.guard_execution_admission();
CREATE FUNCTION dvaia_maintenance.guard_finish_claim() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE c dvaia_maintenance.control%ROWTYPE; a dvaia_maintenance.recovery_attempts%ROWTYPE; prior dvaia_maintenance.recovery_finish_claims%ROWTYPE;
BEGIN
 SELECT * INTO STRICT c FROM dvaia_maintenance.control WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT a FROM dvaia_maintenance.recovery_attempts WHERE epoch=NEW.epoch AND attempt_id=NEW.attempt_id;
 IF c.state<>'dirty' OR c.epoch<>NEW.epoch OR c.operation_id<>NEW.operation_id OR a.state<>'published' OR
 NOT EXISTS(SELECT 1 FROM dvaia_maintenance.epoch_execution_admissions WHERE epoch=NEW.epoch)
 THEN RAISE EXCEPTION 'Finish claim requires prospective published attempt'; END IF;
 IF NEW.ordinal IS NOT NULL OR NEW.previous_claim_id IS NOT NULL THEN RAISE EXCEPTION 'Finish order is internally allocated'; END IF;
 SELECT * INTO prior FROM dvaia_maintenance.recovery_finish_claims WHERE epoch=NEW.epoch AND attempt_id=NEW.attempt_id ORDER BY ordinal DESC LIMIT 1;
 NEW.ordinal:=COALESCE(prior.ordinal,0)+1; NEW.previous_claim_id:=prior.claim_id;
 RETURN NEW;
END $$;
CREATE TRIGGER guarded_finish_claim BEFORE INSERT ON dvaia_maintenance.recovery_finish_claims FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.guard_finish_claim();
CREATE FUNCTION dvaia_maintenance.check_execution_epoch() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE e bigint:=NEW.epoch; admission dvaia_maintenance.epoch_execution_admissions%ROWTYPE; b dvaia_maintenance.epoch_bindings%ROWTYPE; p dvaia_maintenance.epoch_replay_profiles%ROWTYPE; a record; o record; claim record; result record; receipt record; previous uuid; expected_ordinal integer;
BEGIN
 SELECT * INTO admission FROM dvaia_maintenance.epoch_execution_admissions WHERE epoch=e;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF TG_TABLE_NAME='recovery_attempts' AND TG_OP='INSERT' THEN
  IF NEW.state<>'claimed' THEN RAISE EXCEPTION 'Prospective attempt starts claimed'; END IF;
 END IF;
 IF TG_TABLE_NAME='recovery_attempts' AND TG_OP='UPDATE' THEN
  IF NEW.state='failed' AND NOT EXISTS(SELECT 1 FROM dvaia_maintenance.recovery_abandonment_observations WHERE epoch=e AND attempt_id=NEW.attempt_id AND prior_state=OLD.state) THEN RAISE EXCEPTION 'Abandonment prior state mismatch'; END IF;
 END IF;
 PERFORM 1 FROM dvaia_maintenance.control WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT b FROM dvaia_maintenance.epoch_bindings WHERE epoch=e;
 SELECT * INTO STRICT p FROM dvaia_maintenance.epoch_replay_profiles WHERE epoch=e;
 IF admission.operation_id<>b.operation_id OR admission.source_manifest_sha256<>p.source_manifest_sha256 OR admission.owner_record_sha256<>b.owner_record_sha256 OR
 (SELECT count(*) FROM dvaia_maintenance.recovery_attempts WHERE epoch=e AND state IN ('claimed','reconciled','published'))>1
 THEN RAISE EXCEPTION 'Invalid execution epoch'; END IF;
 FOR a IN SELECT * FROM dvaia_maintenance.recovery_attempts WHERE epoch=e LOOP
  IF a.recovery_owner_record->>'version' IS DISTINCT FROM '2' OR a.recovery_owner_record->>'ancestry' IS DISTINCT FROM 'complete-supported-chain' THEN RAISE EXCEPTION 'Unsupported recovery owner'; END IF;
  SELECT * INTO o FROM dvaia_maintenance.recovery_abandonment_observations WHERE epoch=e AND attempt_id=a.attempt_id;
  IF a.state='failed' THEN
   IF o.attempt_id IS NULL OR o.operation_id<>a.original_operation_id OR o.finished_at<>a.finished_at OR o.prior_owner_sha256<>encode(sha256(convert_to(a.recovery_owner_record::text,'UTF8')),'hex') OR
    (SELECT count(*) FROM dvaia_maintenance.recovery_phase_receipts WHERE epoch=e AND attempt_id=a.attempt_id)<>(CASE o.prior_state WHEN 'claimed' THEN 1 ELSE 2 END)
   THEN RAISE EXCEPTION 'Missing or mismatched abandonment'; END IF;
  ELSIF o.attempt_id IS NOT NULL THEN RAISE EXCEPTION 'Orphan abandonment'; END IF;
  previous:=NULL;expected_ordinal:=1;
  FOR claim IN SELECT * FROM dvaia_maintenance.recovery_finish_claims WHERE epoch=e AND attempt_id=a.attempt_id ORDER BY ordinal LOOP
   IF a.state NOT IN ('published','finished') OR claim.ordinal<>expected_ordinal OR claim.previous_claim_id IS DISTINCT FROM previous OR claim.operation_id<>b.operation_id OR
    claim.publication_id<>b.publication_id OR claim.publication_sha256<>b.publication_sha256 OR claim.artifact_manifest_sha256<>p.artifact_manifest_sha256
   THEN RAISE EXCEPTION 'Invalid finish claim chain'; END IF;
   previous:=claim.claim_id;expected_ordinal:=expected_ordinal+1;
  END LOOP;
  SELECT * INTO result FROM dvaia_maintenance.recovery_finish_claim_results WHERE epoch=e AND attempt_id=a.attempt_id;
  IF previous IS NOT NULL AND a.state='finished' THEN
   SELECT * INTO STRICT receipt FROM dvaia_maintenance.epoch_finish_receipts WHERE epoch=e;
   IF result.claim_id IS NULL OR result.claim_id<>previous OR result.finished_at<>a.finished_at OR receipt.recovery_attempt_id<>a.attempt_id OR receipt.finished_at<>result.finished_at OR NOT EXISTS(SELECT 1 FROM dvaia_maintenance.recovery_phase_receipts WHERE epoch=e AND attempt_id=a.attempt_id AND phase='finished' AND created_at=result.finished_at)
   THEN RAISE EXCEPTION 'Missing latest finish claim result'; END IF;
  ELSIF result.claim_id IS NOT NULL THEN RAISE EXCEPTION 'Premature finish claim result'; END IF;
 END LOOP;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER complete_execution_admission AFTER INSERT ON dvaia_maintenance.epoch_execution_admissions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_execution_epoch();
CREATE CONSTRAINT TRIGGER complete_execution_attempt AFTER INSERT OR UPDATE ON dvaia_maintenance.recovery_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_execution_epoch();
CREATE CONSTRAINT TRIGGER complete_execution_abandonment AFTER INSERT ON dvaia_maintenance.recovery_abandonment_observations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_execution_epoch();
CREATE CONSTRAINT TRIGGER complete_execution_claim AFTER INSERT ON dvaia_maintenance.recovery_finish_claims DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_execution_epoch();
CREATE CONSTRAINT TRIGGER complete_execution_result AFTER INSERT ON dvaia_maintenance.recovery_finish_claim_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_execution_epoch();
CREATE CONSTRAINT TRIGGER complete_execution_control AFTER UPDATE ON dvaia_maintenance.control DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_execution_epoch();
CREATE TRIGGER immutable_execution_admission BEFORE UPDATE OR DELETE ON dvaia_maintenance.epoch_execution_admissions FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_execution_abandonment BEFORE UPDATE OR DELETE ON dvaia_maintenance.recovery_abandonment_observations FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_execution_claim BEFORE UPDATE OR DELETE ON dvaia_maintenance.recovery_finish_claims FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_execution_result BEFORE UPDATE OR DELETE ON dvaia_maintenance.recovery_finish_claim_results FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
REVOKE ALL ON dvaia_maintenance.epoch_execution_admissions,dvaia_maintenance.recovery_abandonment_observations,dvaia_maintenance.recovery_finish_claims,dvaia_maintenance.recovery_finish_claim_results FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION dvaia_maintenance.serialize_execution_write(),dvaia_maintenance.guard_execution_admission(),dvaia_maintenance.guard_finish_claim(),dvaia_maintenance.check_execution_epoch() FROM PUBLIC,dvaia_identity_runtime;
