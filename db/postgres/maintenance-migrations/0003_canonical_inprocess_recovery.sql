-- Prospective schema only. No public recovery/proof/force-clear procedure.
-- Existing0001/0002 history is neither adopted nor rewritten.
CREATE TABLE dvaia_maintenance.epoch_replay_profiles (
 epoch bigint PRIMARY KEY,
 operation_id uuid NOT NULL,
 profile text NOT NULL CHECK(profile='canonical16-ctf-inprocess-v1'),
 source_manifest_sha256 text NOT NULL CHECK(source_manifest_sha256 ~ '^[a-f0-9]{64}$'),
 artifact_manifest_sha256 text NOT NULL CHECK(artifact_manifest_sha256 ~ '^[a-f0-9]{64}$'),
 identity_store_id uuid NOT NULL, ctf_store_id uuid NOT NULL,
 bootstrap_id uuid NOT NULL, activation_id uuid NOT NULL,
 writer_policy text NOT NULL CHECK(writer_policy='inprocess-only'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(epoch,operation_id) REFERENCES dvaia_maintenance.epoch_bindings(epoch,operation_id),
 CHECK(identity_store_id<>ctf_store_id AND bootstrap_id<>activation_id)
);
CREATE TABLE dvaia_maintenance.epoch_replay_artifacts (
 epoch bigint NOT NULL REFERENCES dvaia_maintenance.epoch_replay_profiles(epoch),
 kind text NOT NULL CHECK(kind IN ('administrator','ctf-authority','delivery','environment-publication','provisioning')),
 relative_path text NOT NULL,
 schema_version integer NOT NULL,
 binding_sha256 text NOT NULL CHECK(binding_sha256 ~ '^[a-f0-9]{64}$'),
 content_sha256 text, artifact_id uuid,
 PRIMARY KEY(epoch,kind),
 CHECK((kind='ctf-authority' AND schema_version=2 AND relative_path='ctf-authority.json' AND content_sha256 IS NULL AND artifact_id IS NOT NULL) OR
 (kind='environment-publication' AND schema_version=1 AND artifact_id IS NOT NULL AND relative_path='additive-environment-'||artifact_id::text||'.json' AND content_sha256 IS NOT NULL AND content_sha256 ~ '^[a-f0-9]{64}$') OR
 (kind IN ('administrator','delivery','provisioning') AND schema_version=1 AND artifact_id IS NULL AND content_sha256 IS NOT NULL AND content_sha256 ~ '^[a-f0-9]{64}$' AND relative_path=CASE kind WHEN 'delivery' THEN 'ctf-delivery.json' ELSE kind||'.json' END))
);
ALTER TABLE dvaia_maintenance.recovery_attempts ADD CONSTRAINT recovery_epoch_attempt_unique UNIQUE(epoch,attempt_id);
CREATE TABLE dvaia_maintenance.recovery_phase_receipts (
 epoch bigint NOT NULL, attempt_id uuid NOT NULL,
 phase text NOT NULL CHECK(phase IN ('claimed','reconciled','published','finished')),
 operation_id uuid NOT NULL,
 binding_sha256 text NOT NULL CHECK(binding_sha256 ~ '^[a-f0-9]{64}$'),
 proof_sha256 text NOT NULL CHECK(proof_sha256 ~ '^[a-f0-9]{64}$'),
 publication_id uuid, publication_sha256 text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(epoch,attempt_id,phase),
 FOREIGN KEY(epoch,attempt_id) REFERENCES dvaia_maintenance.recovery_attempts(epoch,attempt_id),
 FOREIGN KEY(epoch) REFERENCES dvaia_maintenance.epoch_replay_profiles(epoch),
 CHECK((phase IN ('published','finished') AND publication_id IS NOT NULL AND publication_sha256 IS NOT NULL AND publication_sha256 ~ '^[a-f0-9]{64}$') OR (phase IN ('claimed','reconciled') AND publication_id IS NULL AND publication_sha256 IS NULL))
);
CREATE TABLE dvaia_maintenance.epoch_finish_receipts (
 epoch bigint PRIMARY KEY REFERENCES dvaia_maintenance.epoch_replay_profiles(epoch),
 operation_id uuid NOT NULL,
 recovery_attempt_id uuid,
 FOREIGN KEY(epoch,recovery_attempt_id) REFERENCES dvaia_maintenance.recovery_attempts(epoch,attempt_id),
 profile_binding_sha256 text NOT NULL CHECK(profile_binding_sha256 ~ '^[a-f0-9]{64}$'),
 publication_id uuid NOT NULL,
 publication_sha256 text NOT NULL CHECK(publication_sha256 ~ '^[a-f0-9]{64}$'),
 finished_at timestamptz NOT NULL
);
CREATE TABLE dvaia_maintenance.ctf_journal_lock_intents (
 epoch bigint NOT NULL REFERENCES dvaia_maintenance.epoch_replay_profiles(epoch),
 writer_id uuid NOT NULL, writer_kind text NOT NULL CHECK(writer_kind IN ('original','recovery')),
 original_operation_id uuid NOT NULL,
 recovery_attempt_id uuid,
 nonce uuid NOT NULL UNIQUE,
 binding_sha256 text NOT NULL CHECK(binding_sha256 ~ '^[a-f0-9]{64}$'),
 owner_record_sha256 text NOT NULL CHECK(owner_record_sha256 ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(epoch,writer_id),
 FOREIGN KEY(epoch,original_operation_id) REFERENCES dvaia_maintenance.epoch_bindings(epoch,operation_id),
 FOREIGN KEY(epoch,recovery_attempt_id) REFERENCES dvaia_maintenance.recovery_attempts(epoch,attempt_id),
 CHECK((writer_kind='original' AND recovery_attempt_id IS NULL AND writer_id=original_operation_id) OR (writer_kind='recovery' AND recovery_attempt_id IS NOT NULL AND writer_id=recovery_attempt_id))
);
-- Only closed ASCII names/paths/hex/UUIDs reach this encoder. Field order matches JS.
CREATE FUNCTION dvaia_maintenance.replay_artifact_canonical(p_epoch bigint) RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT '['||string_agg('{"kind":'||to_json(kind)::text||',"relativePath":'||to_json(relative_path)::text||',"schemaVersion":'||schema_version::text||',"bindingSha256":'||to_json(binding_sha256)::text||',"contentSha256":'||COALESCE(to_json(content_sha256)::text,'null')||',"artifactId":'||COALESCE(to_json(artifact_id::text)::text,'null')||'}',',' ORDER BY kind COLLATE "C")||']' FROM dvaia_maintenance.epoch_replay_artifacts WHERE epoch=p_epoch
$$;
CREATE FUNCTION dvaia_maintenance.check_replay_profile() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p dvaia_maintenance.epoch_replay_profiles%ROWTYPE; b dvaia_maintenance.epoch_bindings%ROWTYPE; c dvaia_maintenance.control%ROWTYPE; canonical text; artifact dvaia_maintenance.epoch_replay_artifacts%ROWTYPE;
BEGIN
 SELECT * INTO STRICT p FROM dvaia_maintenance.epoch_replay_profiles WHERE epoch=NEW.epoch;
 SELECT * INTO STRICT b FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch;
 SELECT * INTO STRICT c FROM dvaia_maintenance.control WHERE singleton;
 canonical:=dvaia_maintenance.replay_artifact_canonical(NEW.epoch);
 IF b.profile<>'upgrade-canonical16-v1' OR b.operation_id<>p.operation_id OR b.source_manifest_sha256<>p.source_manifest_sha256 OR
 c.state<>'dirty' OR c.epoch<>p.epoch OR c.operation_id<>p.operation_id OR
 (SELECT count(*) FROM dvaia_maintenance.epoch_stores WHERE epoch=p.epoch)<>16 OR
 (SELECT count(*) FROM dvaia_maintenance.epoch_replay_artifacts WHERE epoch=p.epoch)<>5 OR canonical IS NULL OR octet_length(canonical)>16384 OR
 encode(sha256(convert_to(canonical,'UTF8')),'hex')<>p.artifact_manifest_sha256
 THEN RAISE EXCEPTION 'Invalid replay profile'; END IF;
 SELECT * INTO STRICT artifact FROM dvaia_maintenance.epoch_replay_artifacts WHERE epoch=p.epoch AND kind='environment-publication';
 IF artifact.artifact_id<>b.publication_id OR artifact.content_sha256<>b.publication_sha256 THEN RAISE EXCEPTION 'Invalid publication binding'; END IF;
 SELECT * INTO STRICT artifact FROM dvaia_maintenance.epoch_replay_artifacts WHERE epoch=p.epoch AND kind='ctf-authority';
 IF artifact.artifact_id<>p.activation_id OR artifact.binding_sha256<>encode(sha256(convert_to('{"workspaceId":'||to_json(b.workspace_sha256)::text||',"provisioningSha256":'||to_json((SELECT content_sha256 FROM dvaia_maintenance.epoch_replay_artifacts WHERE epoch=p.epoch AND kind='provisioning'))::text||',"identityStoreId":'||to_json(p.identity_store_id::text)::text||',"ctfStoreId":'||to_json(p.ctf_store_id::text)::text||',"bootstrapId":'||to_json(p.bootstrap_id::text)::text||',"activationId":'||to_json(p.activation_id::text)::text||'}','UTF8')),'hex') THEN RAISE EXCEPTION 'Invalid CTF binding'; END IF;
 IF NOT EXISTS(SELECT 1 FROM dvaia_maintenance.ctf_journal_lock_intents WHERE epoch=p.epoch AND writer_kind='original' AND writer_id=p.operation_id) THEN RAISE EXCEPTION 'Missing original lock intent'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER complete_replay_profile AFTER INSERT ON dvaia_maintenance.epoch_replay_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_profile();
CREATE CONSTRAINT TRIGGER complete_replay_artifacts AFTER INSERT ON dvaia_maintenance.epoch_replay_artifacts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_profile();
CREATE FUNCTION dvaia_maintenance.check_replay_lock_intent() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE b dvaia_maintenance.epoch_bindings%ROWTYPE; a dvaia_maintenance.recovery_attempts%ROWTYPE; expected_binding text;
BEGIN
 SELECT * INTO STRICT b FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch;
 SELECT binding_sha256 INTO STRICT expected_binding FROM dvaia_maintenance.epoch_replay_artifacts WHERE epoch=NEW.epoch AND kind='ctf-authority';
 IF NEW.original_operation_id<>b.operation_id OR NEW.binding_sha256<>expected_binding THEN RAISE EXCEPTION 'Invalid lock binding'; END IF;
 IF NEW.writer_kind='original' THEN
  IF NEW.owner_record_sha256<>b.owner_record_sha256 THEN RAISE EXCEPTION 'Invalid original lock owner'; END IF;
 ELSE
  SELECT * INTO STRICT a FROM dvaia_maintenance.recovery_attempts WHERE epoch=NEW.epoch AND attempt_id=NEW.recovery_attempt_id;
  IF NEW.owner_record_sha256<>encode(sha256(convert_to(a.recovery_owner_record::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'Invalid recovery lock owner'; END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER complete_replay_lock AFTER INSERT ON dvaia_maintenance.ctf_journal_lock_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_lock_intent();
CREATE FUNCTION dvaia_maintenance.check_replay_attempt() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p dvaia_maintenance.epoch_replay_profiles%ROWTYPE; b dvaia_maintenance.epoch_bindings%ROWTYPE; a dvaia_maintenance.recovery_attempts%ROWTYPE; receipt record; required integer; actual integer;
BEGIN
 SELECT * INTO p FROM dvaia_maintenance.epoch_replay_profiles WHERE epoch=NEW.epoch;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO STRICT b FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch;
 SELECT * INTO STRICT a FROM dvaia_maintenance.recovery_attempts WHERE epoch=NEW.epoch AND attempt_id=NEW.attempt_id;
 required:=CASE a.state WHEN 'claimed' THEN 1 WHEN 'reconciled' THEN 2 WHEN 'published' THEN 3 WHEN 'finished' THEN 4 ELSE 0 END;
 SELECT count(*) INTO actual FROM dvaia_maintenance.recovery_phase_receipts WHERE epoch=a.epoch AND attempt_id=a.attempt_id;
 IF NOT EXISTS(SELECT 1 FROM dvaia_maintenance.control WHERE singleton AND epoch=a.epoch AND operation_id=a.original_operation_id AND state=CASE WHEN a.state='finished' THEN 'clean' ELSE 'dirty' END) OR a.original_operation_id<>p.operation_id OR (required>0 AND actual<>required) OR (required=0 AND actual NOT IN (1,2)) OR (a.state IN ('published','finished') AND (a.publication_id<>b.publication_id OR a.publication_sha256<>b.publication_sha256)) OR
 NOT EXISTS(SELECT 1 FROM dvaia_maintenance.ctf_journal_lock_intents WHERE epoch=a.epoch AND writer_id=a.attempt_id AND writer_kind='recovery')
 THEN RAISE EXCEPTION 'Incomplete recovery attempt'; END IF;
 FOR receipt IN SELECT * FROM dvaia_maintenance.recovery_phase_receipts WHERE epoch=a.epoch AND attempt_id=a.attempt_id LOOP
  IF receipt.operation_id<>p.operation_id OR receipt.binding_sha256<>p.artifact_manifest_sha256 OR
   array_position(ARRAY['claimed','reconciled','published','finished'],receipt.phase)>(CASE WHEN required=0 THEN actual ELSE required END) OR
   (receipt.phase='claimed' AND receipt.proof_sha256<>a.proof_digest) OR
   (receipt.phase IN ('published','finished') AND (receipt.publication_id<>b.publication_id OR receipt.publication_sha256<>b.publication_sha256))
  THEN RAISE EXCEPTION 'Invalid recovery receipt'; END IF;
 END LOOP;
 IF a.state='finished' AND NOT EXISTS(SELECT 1 FROM dvaia_maintenance.epoch_finish_receipts WHERE epoch=a.epoch AND recovery_attempt_id=a.attempt_id AND finished_at=a.finished_at) THEN RAISE EXCEPTION 'Missing finish receipt'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER complete_replay_attempt AFTER INSERT OR UPDATE ON dvaia_maintenance.recovery_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_attempt();
CREATE CONSTRAINT TRIGGER complete_replay_phase AFTER INSERT ON dvaia_maintenance.recovery_phase_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_attempt();
CREATE FUNCTION dvaia_maintenance.check_replay_finish() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p dvaia_maintenance.epoch_replay_profiles%ROWTYPE; b dvaia_maintenance.epoch_bindings%ROWTYPE; e dvaia_maintenance.epochs%ROWTYPE; r dvaia_maintenance.epoch_finish_receipts%ROWTYPE; c dvaia_maintenance.control%ROWTYPE;
BEGIN
 SELECT * INTO p FROM dvaia_maintenance.epoch_replay_profiles WHERE epoch=NEW.epoch;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO STRICT e FROM dvaia_maintenance.epochs WHERE epoch=NEW.epoch;
 SELECT * INTO STRICT c FROM dvaia_maintenance.control WHERE singleton;
 IF e.finished_at IS NULL THEN
  IF EXISTS(SELECT 1 FROM dvaia_maintenance.epoch_finish_receipts WHERE epoch=NEW.epoch) OR (c.epoch=NEW.epoch AND c.state='clean') THEN RAISE EXCEPTION 'Premature finish'; END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO STRICT b FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch;
 SELECT * INTO STRICT r FROM dvaia_maintenance.epoch_finish_receipts WHERE epoch=NEW.epoch;
 IF r.operation_id<>p.operation_id OR r.profile_binding_sha256<>p.artifact_manifest_sha256 OR r.publication_id<>b.publication_id OR r.publication_sha256<>b.publication_sha256 OR r.finished_at<>e.finished_at OR c.epoch<>e.epoch OR c.operation_id<>p.operation_id OR c.state<>'clean' OR c.finished_at<>e.finished_at THEN RAISE EXCEPTION 'Invalid final receipt'; END IF;
 IF r.recovery_attempt_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM dvaia_maintenance.recovery_attempts WHERE epoch=r.epoch AND attempt_id=r.recovery_attempt_id AND state='finished' AND finished_at=r.finished_at) THEN RAISE EXCEPTION 'Invalid finishing attempt'; END IF;
 IF r.recovery_attempt_id IS NULL AND EXISTS(SELECT 1 FROM dvaia_maintenance.recovery_attempts WHERE epoch=r.epoch) THEN RAISE EXCEPTION 'Original finish after recovery claim'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER complete_replay_finish AFTER INSERT ON dvaia_maintenance.epoch_finish_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_finish();
CREATE CONSTRAINT TRIGGER complete_replay_epoch_finish AFTER UPDATE ON dvaia_maintenance.epochs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_finish();
CREATE CONSTRAINT TRIGGER complete_replay_control_finish AFTER UPDATE ON dvaia_maintenance.control DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_replay_finish();
-- Reject retroactive extensions even while an old dirty epoch remains current.
CREATE FUNCTION dvaia_maintenance.require_new_replay_binding() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch AND xmin::text::numeric=mod(pg_current_xact_id()::text::numeric,4294967296)) THEN RAISE EXCEPTION 'Replay binding must be admitted atomically'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fresh_replay_binding BEFORE INSERT ON dvaia_maintenance.epoch_replay_profiles FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.require_new_replay_binding();
CREATE TRIGGER immutable_replay_profile BEFORE UPDATE OR DELETE ON dvaia_maintenance.epoch_replay_profiles FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_replay_artifact BEFORE UPDATE OR DELETE ON dvaia_maintenance.epoch_replay_artifacts FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_replay_phase BEFORE UPDATE OR DELETE ON dvaia_maintenance.recovery_phase_receipts FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_replay_finish BEFORE UPDATE OR DELETE ON dvaia_maintenance.epoch_finish_receipts FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_replay_lock BEFORE UPDATE OR DELETE ON dvaia_maintenance.ctf_journal_lock_intents FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
REVOKE ALL ON dvaia_maintenance.epoch_replay_profiles,dvaia_maintenance.epoch_replay_artifacts,dvaia_maintenance.recovery_phase_receipts,dvaia_maintenance.epoch_finish_receipts,dvaia_maintenance.ctf_journal_lock_intents FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION dvaia_maintenance.replay_artifact_canonical(bigint),dvaia_maintenance.check_replay_profile(),dvaia_maintenance.check_replay_lock_intent(),dvaia_maintenance.check_replay_attempt(),dvaia_maintenance.check_replay_finish(),dvaia_maintenance.require_new_replay_binding() FROM PUBLIC,dvaia_identity_runtime;
