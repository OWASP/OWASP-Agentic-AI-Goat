-- PRIVATE QUALIFICATION STAGE. Canonical FinFlow migration 0011.
-- Do not apply outside an owned disposable qualification database.
--
-- Account deletion is distinct from generation reset. Reset retires one
-- generation while preserving its immutable snapshot lineage. Account deletion
-- permanently fences the owner, verifies removal of every historical physical
-- token, then scrubs snapshot_records and customer dataset records to [] while
-- retaining hashes, counts, paths, reads and deletion history. SQL JSON alone
-- is never a physical file-deletion receipt.

CREATE TABLE finflow.customer_datasets (
 owner_id bigint NOT NULL CHECK(owner_id > 0),
 generation bigint NOT NULL CHECK(generation >= 0),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision >= 0),
 records jsonb NOT NULL CHECK(jsonb_typeof(records)='array'),
 deleted boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retired_at timestamptz,
 PRIMARY KEY(owner_id,generation)
);

CREATE TABLE finflow.dataset_deletions (
 operation_id uuid PRIMARY KEY,
 owner_id bigint NOT NULL,
 generation bigint NOT NULL,
 run_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision > 0),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(owner_id,generation) REFERENCES finflow.customer_datasets(owner_id,generation) ON DELETE RESTRICT,
 UNIQUE(owner_id,generation,run_id)
);

CREATE TABLE finflow.backup_artifacts (
 backup_id uuid PRIMARY KEY,
 operation_id uuid NOT NULL UNIQUE,
 owner_id bigint NOT NULL,
 generation bigint NOT NULL,
 run_id uuid NOT NULL,
 file_token uuid NOT NULL UNIQUE,
 virtual_path text NOT NULL,
 dataset_revision bigint NOT NULL CHECK(dataset_revision >= 0),
 snapshot_records jsonb NOT NULL CHECK(jsonb_typeof(snapshot_records)='array'),
 status text NOT NULL CHECK(status IN ('writing','ready','retired')),
 content_sha256 text CHECK(content_sha256 ~ '^[a-f0-9]{64}$'),
 byte_length bigint CHECK(byte_length >= 0),
 record_count integer CHECK(record_count >= 0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 committed_at timestamptz,
 retired_at timestamptz,
 content_scrubbed_at timestamptz,
 FOREIGN KEY(owner_id,generation) REFERENCES finflow.customer_datasets(owner_id,generation) ON DELETE RESTRICT,
 UNIQUE(owner_id,generation,virtual_path),
 CHECK(virtual_path ~ '^/var/app/data/backups/[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.bak$'),
 CHECK(content_scrubbed_at IS NULL OR (status='retired' AND snapshot_records='[]'::jsonb)),
 CHECK((status='writing' AND content_sha256 IS NULL AND byte_length IS NULL AND record_count IS NULL
        AND committed_at IS NULL AND retired_at IS NULL)
    OR (status='ready' AND content_sha256 IS NOT NULL AND byte_length IS NOT NULL AND record_count IS NOT NULL
        AND committed_at IS NOT NULL AND retired_at IS NULL)
    OR (status='retired' AND retired_at IS NOT NULL))
);

CREATE TABLE finflow.backup_reads (
 operation_id uuid PRIMARY KEY,
 owner_id bigint NOT NULL,
 generation bigint NOT NULL,
 run_id uuid NOT NULL,
 backup_id uuid NOT NULL REFERENCES finflow.backup_artifacts(backup_id) ON DELETE RESTRICT,
 requested_path text NOT NULL,
 content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[a-f0-9]{64}$'),
 byte_length bigint NOT NULL CHECK(byte_length >= 0),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(owner_id,generation,run_id,requested_path)
);

CREATE TABLE finflow.resource_retirements (
 operation_id uuid PRIMARY KEY,
 owner_id bigint NOT NULL CHECK(owner_id > 0),
 from_generation bigint NOT NULL CHECK(from_generation >= 0),
 to_generation bigint NOT NULL CHECK(to_generation=from_generation+1),
 status text NOT NULL CHECK(status IN ('pending','completed')),
 file_tokens uuid[] NOT NULL,
 artifact_count integer NOT NULL CHECK(artifact_count >= 0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 UNIQUE(owner_id,from_generation),
 UNIQUE(owner_id,to_generation),
 CHECK((status='pending' AND completed_at IS NULL) OR (status='completed' AND completed_at IS NOT NULL)),
 CHECK(artifact_count=cardinality(file_tokens))
);

CREATE TABLE finflow.owner_resource_deletions (
 job_id uuid PRIMARY KEY,
 owner_id bigint NOT NULL UNIQUE CHECK(owner_id > 0),
 status text NOT NULL CHECK(status IN ('pending','completed')),
 file_tokens uuid[] NOT NULL,
 artifact_count integer NOT NULL CHECK(artifact_count=cardinality(file_tokens) AND artifact_count>=0),
 dataset_count integer NOT NULL CHECK(dataset_count>=0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 CHECK((status='pending' AND completed_at IS NULL) OR (status='completed' AND completed_at IS NOT NULL))
);

CREATE FUNCTION finflow.guard_finflow_resource_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'FinFlow resource lineage is immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER finflow_dataset_deletion_guard BEFORE UPDATE OR DELETE ON finflow.dataset_deletions
 FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_resource_immutable();
CREATE TRIGGER finflow_backup_read_guard BEFORE UPDATE OR DELETE ON finflow.backup_reads
 FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_resource_immutable();

CREATE FUNCTION finflow.guard_finflow_backup_lineage()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE authorized_scrub boolean:=false;
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'FinFlow backup lineage is immutable' USING ERRCODE='23514';
 END IF;
 authorized_scrub:=NEW.status='retired' AND NEW.snapshot_records='[]'::jsonb
   AND OLD.content_scrubbed_at IS NULL AND NEW.content_scrubbed_at IS NOT NULL
   AND EXISTS(SELECT 1 FROM finflow.owner_resource_deletions d
     WHERE d.owner_id=OLD.owner_id AND d.status='pending');
 IF NEW.backup_id IS DISTINCT FROM OLD.backup_id OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
   OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.generation IS DISTINCT FROM OLD.generation
   OR NEW.run_id IS DISTINCT FROM OLD.run_id OR NEW.file_token IS DISTINCT FROM OLD.file_token
   OR NEW.virtual_path IS DISTINCT FROM OLD.virtual_path OR NEW.dataset_revision IS DISTINCT FROM OLD.dataset_revision
   OR NEW.created_at IS DISTINCT FROM OLD.created_at
   OR (NOT authorized_scrub AND (NEW.snapshot_records IS DISTINCT FROM OLD.snapshot_records
      OR NEW.content_scrubbed_at IS DISTINCT FROM OLD.content_scrubbed_at))
   OR (OLD.status='retired' AND NOT authorized_scrub) OR (OLD.status='ready' AND NEW.status<>'retired')
   OR (OLD.status='writing' AND NEW.status NOT IN ('ready','retired'))
   OR (OLD.status IN ('ready','retired') AND (NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
      OR NEW.byte_length IS DISTINCT FROM OLD.byte_length OR NEW.record_count IS DISTINCT FROM OLD.record_count
      OR NEW.committed_at IS DISTINCT FROM OLD.committed_at))
   OR (OLD.status='writing' AND NEW.status='retired' AND
      (NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256 OR NEW.byte_length IS DISTINCT FROM OLD.byte_length
       OR NEW.record_count IS DISTINCT FROM OLD.record_count OR NEW.committed_at IS DISTINCT FROM OLD.committed_at))
   OR (OLD.status='retired' AND NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
  RAISE EXCEPTION 'FinFlow backup lineage is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER finflow_backup_lineage_guard BEFORE UPDATE OR DELETE ON finflow.backup_artifacts
 FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_backup_lineage();

CREATE FUNCTION finflow.guard_finflow_retirement()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.status='completed' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
   OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.from_generation IS DISTINCT FROM OLD.from_generation
   OR NEW.to_generation IS DISTINCT FROM OLD.to_generation OR NEW.file_tokens IS DISTINCT FROM OLD.file_tokens
   OR NEW.artifact_count IS DISTINCT FROM OLD.artifact_count OR NEW.created_at IS DISTINCT FROM OLD.created_at
   OR NEW.status<>'completed' OR NEW.completed_at IS NULL THEN
  RAISE EXCEPTION 'FinFlow resource retirement is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER finflow_resource_retirement_guard BEFORE UPDATE OR DELETE ON finflow.resource_retirements
 FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_retirement();

CREATE FUNCTION finflow.guard_finflow_owner_deletion()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.status='completed' OR NEW.job_id IS DISTINCT FROM OLD.job_id
   OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.file_tokens IS DISTINCT FROM OLD.file_tokens
   OR NEW.artifact_count IS DISTINCT FROM OLD.artifact_count OR NEW.dataset_count IS DISTINCT FROM OLD.dataset_count
   OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.status<>'completed' OR NEW.completed_at IS NULL THEN
  RAISE EXCEPTION 'FinFlow owner deletion receipt is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER finflow_owner_deletion_guard BEFORE UPDATE OR DELETE ON finflow.owner_resource_deletions
 FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_owner_deletion();

CREATE FUNCTION finflow.assert_finflow_generation_active(p_owner_id bigint,p_generation bigint)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF p_owner_id IS NULL OR p_owner_id<=0 OR p_generation IS NULL OR p_generation<0 THEN
  RAISE EXCEPTION 'Invalid FinFlow resource scope' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM finflow.resource_retirements r
   WHERE r.owner_id=p_owner_id AND r.from_generation=p_generation) THEN
  RAISE EXCEPTION 'FinFlow resource generation is retired' USING ERRCODE='55000';
 END IF;
 IF EXISTS(SELECT 1 FROM finflow.owner_resource_deletions d WHERE d.owner_id=p_owner_id) THEN
  RAISE EXCEPTION 'FinFlow resource owner is deleted' USING ERRCODE='55000';
 END IF;
END $$;

CREATE FUNCTION finflow.ensure_customer_dataset(p_owner_id bigint,p_generation bigint,p_initial_records jsonb)
RETURNS finflow.customer_datasets LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE value finflow.customer_datasets%ROWTYPE;
BEGIN
 IF p_initial_records IS NULL OR jsonb_typeof(p_initial_records)<>'array' THEN
  RAISE EXCEPTION 'FinFlow initial dataset must be an array' USING ERRCODE='23514';
 END IF;
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 INSERT INTO finflow.customer_datasets(owner_id,generation,records)
  VALUES(p_owner_id,p_generation,p_initial_records) ON CONFLICT DO NOTHING;
 SELECT d.* INTO STRICT value FROM finflow.customer_datasets d
  WHERE d.owner_id=p_owner_id AND d.generation=p_generation AND d.retired_at IS NULL FOR UPDATE;
 RETURN value;
END $$;

CREATE FUNCTION finflow.read_customer_dataset(p_owner_id bigint,p_generation bigint,p_initial_records jsonb)
RETURNS TABLE(owner_id bigint,generation bigint,revision bigint,records jsonb,deleted boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.customer_datasets%ROWTYPE;
BEGIN
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 value:=finflow.ensure_customer_dataset(p_owner_id,p_generation,p_initial_records);
 RETURN QUERY SELECT value.owner_id,value.generation,value.revision,value.records,value.deleted;
END $$;

CREATE FUNCTION finflow.delete_customer_dataset(
 p_operation_id uuid,p_owner_id bigint,p_generation bigint,p_run_id uuid,p_initial_records jsonb)
RETURNS TABLE(owner_id bigint,generation bigint,operation_id uuid,run_id uuid,revision bigint,deleted boolean,records jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.customer_datasets%ROWTYPE; prior finflow.dataset_deletions%ROWTYPE;
BEGIN
 IF p_operation_id IS NULL OR p_run_id IS NULL OR p_initial_records IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow deletion operation' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 SELECT d.* INTO prior FROM finflow.dataset_deletions d WHERE d.operation_id=p_operation_id;
 IF FOUND THEN
  IF prior.owner_id IS DISTINCT FROM p_owner_id OR prior.generation IS DISTINCT FROM p_generation
    OR prior.run_id IS DISTINCT FROM p_run_id THEN
   RAISE EXCEPTION 'FinFlow deletion operation scope mismatch' USING ERRCODE='23514';
  END IF;
  RETURN QUERY SELECT prior.owner_id,prior.generation,prior.operation_id,prior.run_id,prior.revision,true,'[]'::jsonb; RETURN;
 END IF;
 value:=finflow.ensure_customer_dataset(p_owner_id,p_generation,p_initial_records);
 UPDATE finflow.customer_datasets d SET records='[]'::jsonb,deleted=true,revision=d.revision+1,
   updated_at=clock_timestamp() WHERE d.owner_id=p_owner_id AND d.generation=p_generation RETURNING d.* INTO value;
 INSERT INTO finflow.dataset_deletions(operation_id,owner_id,generation,run_id,revision)
  VALUES(p_operation_id,p_owner_id,p_generation,p_run_id,value.revision);
 RETURN QUERY SELECT p_owner_id,p_generation,p_operation_id,p_run_id,value.revision,true,value.records;
END $$;

CREATE FUNCTION finflow.reserve_customer_backup(
 p_operation_id uuid,p_owner_id bigint,p_generation bigint,p_run_id uuid,p_backup_id uuid,p_file_token uuid,
 p_virtual_path text,p_initial_records jsonb)
RETURNS TABLE(owner_id bigint,generation bigint,operation_id uuid,run_id uuid,backup_id uuid,file_token uuid,
 virtual_path text,dataset_revision bigint,records jsonb,status text,content_sha256 text,byte_length bigint,record_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE dataset finflow.customer_datasets%ROWTYPE; value finflow.backup_artifacts%ROWTYPE;
BEGIN
 IF p_operation_id IS NULL OR p_run_id IS NULL OR p_backup_id IS NULL OR p_file_token IS NULL
   OR p_virtual_path IS NULL OR p_initial_records IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow backup reservation' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 IF p_virtual_path !~ '^/var/app/data/backups/[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.bak$' THEN
  RAISE EXCEPTION 'Invalid FinFlow backup path' USING ERRCODE='23514';
 END IF;
 SELECT b.* INTO value FROM finflow.backup_artifacts b WHERE b.operation_id=p_operation_id FOR UPDATE;
 IF FOUND THEN
  IF value.owner_id IS DISTINCT FROM p_owner_id OR value.generation IS DISTINCT FROM p_generation
    OR value.run_id IS DISTINCT FROM p_run_id OR value.backup_id IS DISTINCT FROM p_backup_id
    OR value.file_token IS DISTINCT FROM p_file_token OR value.virtual_path IS DISTINCT FROM p_virtual_path
    OR value.status='retired' THEN
   RAISE EXCEPTION 'FinFlow backup operation scope mismatch' USING ERRCODE='23514';
  END IF;
 ELSE
  dataset:=finflow.ensure_customer_dataset(p_owner_id,p_generation,p_initial_records);
  INSERT INTO finflow.backup_artifacts(backup_id,operation_id,owner_id,generation,run_id,file_token,
    virtual_path,dataset_revision,snapshot_records,status)
   VALUES(p_backup_id,p_operation_id,p_owner_id,p_generation,p_run_id,p_file_token,
    p_virtual_path,dataset.revision,dataset.records,'writing') RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.owner_id,value.generation,value.operation_id,value.run_id,value.backup_id,value.file_token,
  value.virtual_path,value.dataset_revision,value.snapshot_records,value.status,value.content_sha256,
  value.byte_length,value.record_count;
END $$;

CREATE FUNCTION finflow.commit_customer_backup(
 p_operation_id uuid,p_owner_id bigint,p_generation bigint,p_run_id uuid,p_backup_id uuid,p_file_token uuid,
 p_virtual_path text,p_dataset_revision bigint,p_content_sha256 text,p_byte_length bigint,p_record_count integer)
RETURNS TABLE(owner_id bigint,generation bigint,operation_id uuid,run_id uuid,backup_id uuid,file_token uuid,
 virtual_path text,dataset_revision bigint,records jsonb,status text,content_sha256 text,byte_length bigint,record_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.backup_artifacts%ROWTYPE;
BEGIN
 IF p_operation_id IS NULL OR p_run_id IS NULL OR p_backup_id IS NULL OR p_file_token IS NULL
   OR p_virtual_path IS NULL OR p_dataset_revision IS NULL OR p_content_sha256 IS NULL
   OR p_byte_length IS NULL OR p_record_count IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow backup commit' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 SELECT b.* INTO STRICT value FROM finflow.backup_artifacts b WHERE b.operation_id=p_operation_id FOR UPDATE;
 IF value.owner_id IS DISTINCT FROM p_owner_id OR value.generation IS DISTINCT FROM p_generation
   OR value.run_id IS DISTINCT FROM p_run_id OR value.backup_id IS DISTINCT FROM p_backup_id
   OR value.file_token IS DISTINCT FROM p_file_token OR value.virtual_path IS DISTINCT FROM p_virtual_path
   OR value.dataset_revision IS DISTINCT FROM p_dataset_revision OR p_content_sha256 !~ '^[a-f0-9]{64}$'
   OR p_byte_length<0 OR p_record_count IS DISTINCT FROM jsonb_array_length(value.snapshot_records)
   OR value.status='retired' THEN
  RAISE EXCEPTION 'FinFlow backup commit mismatch' USING ERRCODE='23514';
 END IF;
 IF value.status='writing' THEN
  UPDATE finflow.backup_artifacts b SET status='ready',content_sha256=p_content_sha256,
   byte_length=p_byte_length,record_count=p_record_count,committed_at=clock_timestamp()
   WHERE b.backup_id=value.backup_id RETURNING * INTO value;
 ELSIF value.content_sha256 IS DISTINCT FROM p_content_sha256 OR value.byte_length IS DISTINCT FROM p_byte_length
   OR value.record_count IS DISTINCT FROM p_record_count THEN
  RAISE EXCEPTION 'FinFlow backup commit replay mismatch' USING ERRCODE='23514';
 END IF;
 RETURN QUERY SELECT value.owner_id,value.generation,value.operation_id,value.run_id,value.backup_id,value.file_token,
  value.virtual_path,value.dataset_revision,value.snapshot_records,value.status,value.content_sha256,
  value.byte_length,value.record_count;
END $$;

CREATE FUNCTION finflow.read_customer_backup(p_owner_id bigint,p_generation bigint,p_virtual_path text)
RETURNS TABLE(owner_id bigint,generation bigint,operation_id uuid,run_id uuid,backup_id uuid,file_token uuid,
 virtual_path text,dataset_revision bigint,records jsonb,status text,content_sha256 text,byte_length bigint,record_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_virtual_path IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow backup read path' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 RETURN QUERY SELECT b.owner_id,b.generation,b.operation_id,b.run_id,b.backup_id,b.file_token,b.virtual_path,
  b.dataset_revision,b.snapshot_records,b.status,b.content_sha256,b.byte_length,b.record_count
 FROM finflow.backup_artifacts b WHERE b.owner_id=p_owner_id AND b.generation=p_generation
  AND b.virtual_path=p_virtual_path AND b.status='ready';
END $$;

CREATE FUNCTION finflow.list_customer_backups(p_owner_id bigint,p_generation bigint)
RETURNS TABLE(owner_id bigint,generation bigint,operation_id uuid,run_id uuid,backup_id uuid,file_token uuid,
 virtual_path text,dataset_revision bigint,records jsonb,status text,content_sha256 text,byte_length bigint,record_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_owner_id IS NULL OR p_owner_id<=0 OR p_generation IS NULL OR p_generation<0 THEN
  RAISE EXCEPTION 'Invalid FinFlow backup listing scope' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 RETURN QUERY SELECT b.owner_id,b.generation,b.operation_id,b.run_id,b.backup_id,b.file_token,b.virtual_path,
  b.dataset_revision,b.snapshot_records,b.status,b.content_sha256,b.byte_length,b.record_count
 FROM finflow.backup_artifacts b WHERE b.owner_id=p_owner_id AND b.generation=p_generation
  AND b.status='ready' ORDER BY b.virtual_path;
END $$;

CREATE FUNCTION finflow.record_customer_backup_read(
 p_operation_id uuid,p_owner_id bigint,p_generation bigint,p_run_id uuid,p_backup_id uuid,p_requested_path text,
 p_content_sha256 text,p_byte_length bigint)
RETURNS TABLE(owner_id bigint,generation bigint,operation_id uuid,run_id uuid,backup_id uuid,requested_path text,content_sha256 text,byte_length bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE backup finflow.backup_artifacts%ROWTYPE; value finflow.backup_reads%ROWTYPE;
BEGIN
 IF p_operation_id IS NULL OR p_run_id IS NULL OR p_backup_id IS NULL OR p_requested_path IS NULL
   OR p_content_sha256 IS NULL OR p_byte_length IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow backup read' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 SELECT r.* INTO value FROM finflow.backup_reads r WHERE r.operation_id=p_operation_id;
 IF FOUND THEN
  IF value.owner_id IS DISTINCT FROM p_owner_id OR value.generation IS DISTINCT FROM p_generation
    OR value.run_id IS DISTINCT FROM p_run_id OR value.backup_id IS DISTINCT FROM p_backup_id
    OR value.requested_path IS DISTINCT FROM p_requested_path
    OR value.content_sha256 IS DISTINCT FROM p_content_sha256 OR value.byte_length IS DISTINCT FROM p_byte_length THEN
   RAISE EXCEPTION 'FinFlow backup read scope mismatch' USING ERRCODE='23514';
  END IF;
 ELSE
  SELECT b.* INTO STRICT backup FROM finflow.backup_artifacts b WHERE b.backup_id=p_backup_id FOR UPDATE;
  IF backup.owner_id IS DISTINCT FROM p_owner_id OR backup.generation IS DISTINCT FROM p_generation
    OR backup.status<>'ready' OR backup.virtual_path IS DISTINCT FROM p_requested_path
    OR backup.content_sha256 IS DISTINCT FROM p_content_sha256 OR backup.byte_length IS DISTINCT FROM p_byte_length THEN
   RAISE EXCEPTION 'FinFlow backup readback mismatch' USING ERRCODE='23514';
  END IF;
  INSERT INTO finflow.backup_reads(operation_id,owner_id,generation,run_id,backup_id,requested_path,
    content_sha256,byte_length) VALUES(p_operation_id,p_owner_id,p_generation,p_run_id,p_backup_id,
    p_requested_path,p_content_sha256,p_byte_length) RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.owner_id,value.generation,value.operation_id,value.run_id,value.backup_id,value.requested_path,
  value.content_sha256,value.byte_length;
END $$;

CREATE FUNCTION finflow.begin_resource_retirement(
 p_operation_id uuid,p_owner_id bigint,p_from_generation bigint,p_to_generation bigint)
RETURNS TABLE(operation_id uuid,owner_id bigint,from_generation bigint,to_generation bigint,status text,file_tokens uuid[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.resource_retirements%ROWTYPE; tokens uuid[];
BEGIN
 IF p_operation_id IS NULL OR p_owner_id IS NULL OR p_owner_id<=0 OR p_from_generation IS NULL
   OR p_from_generation<0 OR p_to_generation IS NULL OR p_to_generation IS DISTINCT FROM p_from_generation+1 THEN
  RAISE EXCEPTION 'Invalid FinFlow retirement scope' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 SELECT r.* INTO value FROM finflow.resource_retirements r WHERE r.operation_id=p_operation_id FOR UPDATE;
 IF FOUND THEN
  IF value.owner_id IS DISTINCT FROM p_owner_id OR value.from_generation IS DISTINCT FROM p_from_generation
    OR value.to_generation IS DISTINCT FROM p_to_generation THEN
   RAISE EXCEPTION 'FinFlow retirement scope mismatch' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM finflow.resource_retirements r WHERE r.owner_id=p_owner_id
    AND (r.from_generation=p_from_generation OR r.to_generation=p_to_generation)) THEN
   RAISE EXCEPTION 'Conflicting FinFlow retirement operation' USING ERRCODE='55000';
  END IF;
  SELECT COALESCE(array_agg(b.file_token ORDER BY b.file_token),'{}'::uuid[]) INTO tokens
   FROM finflow.backup_artifacts b WHERE b.owner_id=p_owner_id AND b.generation=p_from_generation
    AND b.status IN ('writing','ready');
  INSERT INTO finflow.resource_retirements(operation_id,owner_id,from_generation,to_generation,status,
    file_tokens,artifact_count) VALUES(p_operation_id,p_owner_id,p_from_generation,p_to_generation,'pending',
    tokens,cardinality(tokens)) RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.operation_id,value.owner_id,value.from_generation,value.to_generation,
  value.status,value.file_tokens;
END $$;

CREATE FUNCTION finflow.complete_resource_retirement(
 p_operation_id uuid,p_owner_id bigint,p_from_generation bigint,p_to_generation bigint,p_file_tokens uuid[])
RETURNS TABLE(operation_id uuid,owner_id bigint,from_generation bigint,to_generation bigint,status text,
 artifact_count integer,completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.resource_retirements%ROWTYPE;
BEGIN
 IF p_operation_id IS NULL OR p_owner_id IS NULL OR p_owner_id<=0 OR p_from_generation IS NULL
   OR p_from_generation<0 OR p_to_generation IS NULL OR p_to_generation IS DISTINCT FROM p_from_generation+1
   OR p_file_tokens IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow retirement completion' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 SELECT r.* INTO STRICT value FROM finflow.resource_retirements r WHERE r.operation_id=p_operation_id FOR UPDATE;
 IF value.owner_id IS DISTINCT FROM p_owner_id OR value.from_generation IS DISTINCT FROM p_from_generation
   OR value.to_generation IS DISTINCT FROM p_to_generation OR value.file_tokens IS DISTINCT FROM p_file_tokens THEN
  RAISE EXCEPTION 'FinFlow retirement completion mismatch' USING ERRCODE='23514';
 END IF;
 IF value.status='pending' THEN
  UPDATE finflow.backup_artifacts b SET status='retired',retired_at=clock_timestamp()
   WHERE b.owner_id=p_owner_id AND b.generation=p_from_generation AND b.status IN ('writing','ready');
  UPDATE finflow.customer_datasets d SET retired_at=clock_timestamp(),updated_at=clock_timestamp()
   WHERE d.owner_id=p_owner_id AND d.generation=p_from_generation AND d.retired_at IS NULL;
  UPDATE finflow.resource_retirements r SET status='completed',completed_at=clock_timestamp()
   WHERE r.operation_id=p_operation_id RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.operation_id,value.owner_id,value.from_generation,value.to_generation,
  value.status,value.artifact_count,value.completed_at;
END $$;

CREATE FUNCTION finflow.read_resource_retirement(
 p_operation_id uuid,p_owner_id bigint,p_from_generation bigint,p_to_generation bigint)
RETURNS TABLE(operation_id uuid,owner_id bigint,from_generation bigint,to_generation bigint,status text,
 artifact_count integer,completed_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path=pg_catalog AS $$
 SELECT r.operation_id,r.owner_id,r.from_generation,r.to_generation,r.status,r.artifact_count,r.completed_at
 FROM finflow.resource_retirements r WHERE r.operation_id=p_operation_id AND r.owner_id=p_owner_id
  AND r.from_generation=p_from_generation AND r.to_generation=p_to_generation
$$;

CREATE FUNCTION finflow.begin_owner_resource_deletion(p_job_id uuid,p_owner_id bigint)
RETURNS TABLE(job_id uuid,owner_id bigint,status text,file_tokens uuid[],artifact_count integer,
 dataset_count integer,completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.owner_resource_deletions%ROWTYPE; tokens uuid[]; datasets integer;
BEGIN
 IF p_job_id IS NULL OR p_owner_id IS NULL OR p_owner_id<=0 THEN
  RAISE EXCEPTION 'Invalid FinFlow owner deletion scope' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 SELECT d.* INTO value FROM finflow.owner_resource_deletions d WHERE d.job_id=p_job_id FOR UPDATE;
 IF FOUND THEN
  IF value.owner_id IS DISTINCT FROM p_owner_id THEN
   RAISE EXCEPTION 'FinFlow owner deletion replay mismatch' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM finflow.owner_resource_deletions d WHERE d.owner_id=p_owner_id) THEN
   RAISE EXCEPTION 'Conflicting FinFlow owner deletion' USING ERRCODE='55000';
  END IF;
  SELECT COALESCE(array_agg(b.file_token ORDER BY b.file_token),'{}'::uuid[]) INTO tokens
   FROM finflow.backup_artifacts b WHERE b.owner_id=p_owner_id;
  SELECT count(*)::integer INTO datasets FROM finflow.customer_datasets d WHERE d.owner_id=p_owner_id;
  INSERT INTO finflow.owner_resource_deletions(job_id,owner_id,status,file_tokens,artifact_count,dataset_count)
   VALUES(p_job_id,p_owner_id,'pending',tokens,cardinality(tokens),datasets) RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.job_id,value.owner_id,value.status,value.file_tokens,value.artifact_count,
  value.dataset_count,value.completed_at;
END $$;

CREATE FUNCTION finflow.complete_owner_resource_deletion(p_job_id uuid,p_owner_id bigint,p_file_tokens uuid[])
RETURNS TABLE(job_id uuid,owner_id bigint,status text,file_tokens uuid[],artifact_count integer,
 dataset_count integer,completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.owner_resource_deletions%ROWTYPE;
BEGIN
 IF p_job_id IS NULL OR p_owner_id IS NULL OR p_owner_id<=0 OR p_file_tokens IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow owner deletion completion' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 SELECT d.* INTO STRICT value FROM finflow.owner_resource_deletions d WHERE d.job_id=p_job_id FOR UPDATE;
 IF value.owner_id IS DISTINCT FROM p_owner_id OR value.file_tokens IS DISTINCT FROM p_file_tokens THEN
  RAISE EXCEPTION 'FinFlow owner deletion completion mismatch' USING ERRCODE='23514';
 END IF;
 IF value.status='pending' THEN
  UPDATE finflow.backup_artifacts b SET status='retired',retired_at=COALESCE(b.retired_at,clock_timestamp()),
   snapshot_records='[]'::jsonb,content_scrubbed_at=clock_timestamp() WHERE b.owner_id=p_owner_id;
  UPDATE finflow.customer_datasets d SET records='[]'::jsonb,deleted=true,
   retired_at=COALESCE(d.retired_at,clock_timestamp()),updated_at=clock_timestamp() WHERE d.owner_id=p_owner_id;
  UPDATE finflow.owner_resource_deletions d SET status='completed',completed_at=clock_timestamp()
   WHERE d.job_id=p_job_id RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.job_id,value.owner_id,value.status,value.file_tokens,value.artifact_count,
  value.dataset_count,value.completed_at;
END $$;

CREATE FUNCTION finflow.read_owner_resource_deletion(p_job_id uuid,p_owner_id bigint)
RETURNS TABLE(job_id uuid,owner_id bigint,status text,file_tokens uuid[],artifact_count integer,
 dataset_count integer,completed_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path=pg_catalog AS $$
 SELECT d.job_id,d.owner_id,d.status,d.file_tokens,d.artifact_count,d.dataset_count,d.completed_at
 FROM finflow.owner_resource_deletions d WHERE d.job_id=p_job_id AND d.owner_id=p_owner_id
$$;

-- This overload replaces the runtime deletion entry point. The legacy bigint
-- form is revoked below so store rows cannot be removed before physical backup
-- cleanup has published its exact completed job receipt.
CREATE FUNCTION finflow.destroy_student_owner(requested_user_id bigint,requested_job_id uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE removed integer:=0; DECLARE n integer;
BEGIN
 IF requested_user_id IS NULL OR requested_user_id<1 OR requested_job_id IS NULL THEN
  RAISE EXCEPTION 'Invalid deletion owner' USING ERRCODE='22023';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM finflow.owner_resource_deletions d
   WHERE d.owner_id=requested_user_id AND d.job_id=requested_job_id AND d.status='completed') THEN
  RAISE EXCEPTION 'FinFlow physical resource cleanup is incomplete' USING ERRCODE='55000';
 END IF;
 DELETE FROM finflow.tool_log WHERE user_id=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM finflow.progress WHERE user_id=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM legacy_sensitive.access_logs WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM legacy_sensitive.judgments WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 DELETE FROM legacy_sensitive.owner_state WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
 RETURN removed;
END $$;

REVOKE ALL ON finflow.customer_datasets,finflow.dataset_deletions,finflow.backup_artifacts,
 finflow.backup_reads,finflow.resource_retirements,finflow.owner_resource_deletions FROM PUBLIC,dvaia_finflow_runtime;
REVOKE ALL ON FUNCTION finflow.guard_finflow_resource_immutable(),finflow.guard_finflow_backup_lineage(),
 finflow.guard_finflow_retirement(),finflow.guard_finflow_owner_deletion(),
 finflow.assert_finflow_generation_active(bigint,bigint),
 finflow.ensure_customer_dataset(bigint,bigint,jsonb),finflow.read_customer_dataset(bigint,bigint,jsonb),
 finflow.delete_customer_dataset(uuid,bigint,bigint,uuid,jsonb),
 finflow.reserve_customer_backup(uuid,bigint,bigint,uuid,uuid,uuid,text,jsonb),
 finflow.commit_customer_backup(uuid,bigint,bigint,uuid,uuid,uuid,text,bigint,text,bigint,integer),
 finflow.read_customer_backup(bigint,bigint,text),
 finflow.list_customer_backups(bigint,bigint),
 finflow.record_customer_backup_read(uuid,bigint,bigint,uuid,uuid,text,text,bigint),
 finflow.begin_resource_retirement(uuid,bigint,bigint,bigint),
 finflow.complete_resource_retirement(uuid,bigint,bigint,bigint,uuid[]),
 finflow.read_resource_retirement(uuid,bigint,bigint,bigint),
 finflow.begin_owner_resource_deletion(uuid,bigint),
 finflow.complete_owner_resource_deletion(uuid,bigint,uuid[]),
 finflow.read_owner_resource_deletion(uuid,bigint),
 finflow.destroy_student_owner(bigint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION finflow.destroy_student_owner(bigint) FROM PUBLIC,dvaia_finflow_runtime;
GRANT EXECUTE ON FUNCTION finflow.read_customer_dataset(bigint,bigint,jsonb),
 finflow.delete_customer_dataset(uuid,bigint,bigint,uuid,jsonb),
 finflow.reserve_customer_backup(uuid,bigint,bigint,uuid,uuid,uuid,text,jsonb),
 finflow.commit_customer_backup(uuid,bigint,bigint,uuid,uuid,uuid,text,bigint,text,bigint,integer),
 finflow.read_customer_backup(bigint,bigint,text),
 finflow.list_customer_backups(bigint,bigint),
 finflow.record_customer_backup_read(uuid,bigint,bigint,uuid,uuid,text,text,bigint),
 finflow.begin_resource_retirement(uuid,bigint,bigint,bigint),
 finflow.complete_resource_retirement(uuid,bigint,bigint,bigint,uuid[]),
 finflow.read_resource_retirement(uuid,bigint,bigint,bigint),
 finflow.begin_owner_resource_deletion(uuid,bigint),
 finflow.complete_owner_resource_deletion(uuid,bigint,uuid[]),
 finflow.read_owner_resource_deletion(uuid,bigint),
 finflow.destroy_student_owner(bigint,uuid) TO dvaia_finflow_runtime;
