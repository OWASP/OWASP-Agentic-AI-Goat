-- Additive recovery journals; no runtime mutation authority or proof procedure.
CREATE TABLE dvaia_maintenance.epoch_bindings (
 epoch bigint PRIMARY KEY REFERENCES dvaia_maintenance.epochs(epoch),
 operation_id uuid NOT NULL UNIQUE,
 UNIQUE(epoch,operation_id),
 profile text NOT NULL CHECK(profile IN ('upgrade-canonical16-v1','unavailable')),
 reason_code text,
 workspace_sha256 text, store_manifest_sha256 text, publication_id uuid,
 publication_sha256 text, source_manifest_sha256 text,
 owner_record jsonb, owner_record_sha256 text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((profile='unavailable' AND reason_code IS NOT NULL AND reason_code ~ '^[A-Z0-9_]{1,80}$' AND workspace_sha256 IS NULL AND store_manifest_sha256 IS NULL AND publication_id IS NULL AND publication_sha256 IS NULL AND source_manifest_sha256 IS NULL AND owner_record IS NULL AND owner_record_sha256 IS NULL) OR
 (profile='upgrade-canonical16-v1' AND reason_code IS NULL AND workspace_sha256 IS NOT NULL AND workspace_sha256 ~ '^[a-f0-9]{64}$' AND store_manifest_sha256 IS NOT NULL AND store_manifest_sha256 ~ '^[a-f0-9]{64}$' AND publication_id IS NOT NULL AND publication_sha256 IS NOT NULL AND publication_sha256 ~ '^[a-f0-9]{64}$' AND source_manifest_sha256 IS NOT NULL AND source_manifest_sha256 ~ '^[a-f0-9]{64}$' AND owner_record IS NOT NULL AND jsonb_typeof(owner_record)='object' AND octet_length(owner_record::text)<=32768 AND owner_record->>'version' IS NOT DISTINCT FROM '2' AND owner_record->>'ancestry' IS NOT DISTINCT FROM 'complete-supported-chain' AND owner_record_sha256 IS NOT NULL AND owner_record_sha256 ~ '^[a-f0-9]{64}$'))
);
CREATE TABLE dvaia_maintenance.epoch_stores (
 epoch bigint NOT NULL REFERENCES dvaia_maintenance.epoch_bindings(epoch),
 ordinal smallint NOT NULL CHECK(ordinal BETWEEN 1 AND 16),
 store_key text NOT NULL,
 cluster_identifier text NOT NULL CHECK(cluster_identifier ~ '^[1-9][0-9]{0,19}$'),
 database_oid oid NOT NULL CHECK(database_oid<>0), database_name text NOT NULL,
 runtime_role text NOT NULL, migration_role text NOT NULL, delivery_role text,
 endpoint_policy_sha256 text NOT NULL CHECK(endpoint_policy_sha256 ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(epoch,ordinal), UNIQUE(epoch,store_key), UNIQUE(epoch,cluster_identifier,database_oid),
 CHECK(store_key=(ARRAY['identity','aria','nova','xss','mcp','csrf','supply_chain','finflow','excessive_agency','ctf','legacy_challenge','sensitive_lookup','secureshop','secureshop_agents','session_disclosure','secureshop_review'])[ordinal]),
 CHECK(database_name='dvaia_'||store_key AND runtime_role='dvaia_'||store_key||'_runtime' AND migration_role='dvaia_'||store_key||'_migration'),
 CHECK(delivery_role IS NULL OR (store_key='ctf' AND delivery_role='dvaia_ctf_delivery'))
);
CREATE TABLE dvaia_maintenance.recovery_attempts (
 attempt_id uuid PRIMARY KEY, epoch bigint NOT NULL REFERENCES dvaia_maintenance.epoch_bindings(epoch),
 original_operation_id uuid NOT NULL,
 FOREIGN KEY(epoch,original_operation_id) REFERENCES dvaia_maintenance.epoch_bindings(epoch,operation_id),
 recovery_owner_record jsonb NOT NULL CHECK(jsonb_typeof(recovery_owner_record)='object' AND octet_length(recovery_owner_record::text)<=32768),
 proof_digest text NOT NULL CHECK(proof_digest ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('claimed','reconciled','published','finished','failed')),
 publication_id uuid, publication_sha256 text,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz,
 CHECK((state IN ('finished','failed'))=(finished_at IS NOT NULL)),
 CHECK((state IN ('published','finished') AND publication_id IS NOT NULL AND publication_sha256 IS NOT NULL AND publication_sha256 ~ '^[a-f0-9]{64}$') OR (state NOT IN ('published','finished') AND publication_id IS NULL AND publication_sha256 IS NULL))
);
CREATE FUNCTION dvaia_maintenance.check_epoch_binding() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE binding dvaia_maintenance.epoch_bindings%ROWTYPE;
BEGIN
 SELECT * INTO binding FROM dvaia_maintenance.epoch_bindings WHERE epoch=NEW.epoch;
 IF binding.operation_id IS DISTINCT FROM (SELECT operation_id FROM dvaia_maintenance.epochs WHERE epoch=NEW.epoch) OR
    (SELECT count(*) FROM dvaia_maintenance.epoch_stores WHERE epoch=NEW.epoch) <> (CASE WHEN binding.profile='upgrade-canonical16-v1' THEN 16 ELSE 0 END)
 THEN RAISE EXCEPTION 'Invalid maintenance epoch binding'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER complete_epoch_binding AFTER INSERT ON dvaia_maintenance.epoch_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_epoch_binding();
CREATE CONSTRAINT TRIGGER complete_epoch_stores AFTER INSERT ON dvaia_maintenance.epoch_stores DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.check_epoch_binding();
CREATE FUNCTION dvaia_maintenance.immutable_recovery_binding() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RAISE EXCEPTION 'Immutable maintenance binding'; END $$;
CREATE TRIGGER immutable_epoch_binding BEFORE UPDATE OR DELETE ON dvaia_maintenance.epoch_bindings FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
CREATE TRIGGER immutable_epoch_store BEFORE UPDATE OR DELETE ON dvaia_maintenance.epoch_stores FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.immutable_recovery_binding();
REVOKE ALL ON dvaia_maintenance.epoch_bindings,dvaia_maintenance.epoch_stores,dvaia_maintenance.recovery_attempts FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION dvaia_maintenance.check_epoch_binding(),dvaia_maintenance.immutable_recovery_binding() FROM PUBLIC,dvaia_identity_runtime;

CREATE FUNCTION dvaia_maintenance.guard_recovery_attempt() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Immutable recovery attempt'; END IF;
 IF ROW(NEW.attempt_id,NEW.epoch,NEW.original_operation_id,NEW.recovery_owner_record,NEW.proof_digest,NEW.started_at) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.epoch,OLD.original_operation_id,OLD.recovery_owner_record,OLD.proof_digest,OLD.started_at) OR
 NOT ((OLD.state='claimed' AND NEW.state='reconciled') OR (OLD.state='reconciled' AND NEW.state='published') OR (OLD.state='published' AND NEW.state='finished') OR (OLD.state IN ('claimed','reconciled') AND NEW.state='failed'))
 THEN RAISE EXCEPTION 'Invalid recovery transition'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guarded_recovery_attempt BEFORE UPDATE OR DELETE ON dvaia_maintenance.recovery_attempts FOR EACH ROW EXECUTE FUNCTION dvaia_maintenance.guard_recovery_attempt();
REVOKE ALL ON FUNCTION dvaia_maintenance.guard_recovery_attempt() FROM PUBLIC,dvaia_identity_runtime;
