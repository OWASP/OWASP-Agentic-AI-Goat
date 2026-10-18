-- Distinct Windows owner schema only. This admits no absence, recovery,
-- termination or runtime mutation authority and preserves historical v2 rows.
DO $$ BEGIN
 PERFORM 1 FROM dvaia_maintenance.control WHERE singleton FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM dvaia_maintenance.control WHERE singleton AND state='clean') OR
 NOT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=1886610804 AND objid=90 AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
  RAISE EXCEPTION 'Windows owner schema requires clean control';
 END IF;
END $$;

CREATE FUNCTION dvaia_maintenance.owner_exact_keys(value jsonb, expected text[]) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' OR expected IS NULL THEN RETURN false; END IF;
 RETURN ARRAY(SELECT jsonb_object_keys(value) ORDER BY 1)=ARRAY(SELECT unnest(expected) ORDER BY 1);
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
CREATE FUNCTION dvaia_maintenance.owner_windows_sid(value text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE parts text[]; i integer;
BEGIN
 IF value IS NULL OR length(value)>184 OR value !~ '^S-1-[0-9]+(-[0-9]+){1,15}$' THEN RETURN false; END IF;
 parts:=string_to_array(value,'-');
 IF parts[3] !~ '^(0|[1-9][0-9]*)$' OR parts[3]::numeric>281474976710655 THEN RETURN false; END IF;
 FOR i IN 4..array_length(parts,1) LOOP
  IF parts[i] !~ '^(0|[1-9][0-9]*)$' OR parts[i]::numeric>4294967295 THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
CREATE FUNCTION dvaia_maintenance.owner_windows_filetime(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE text_value text;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 text_value:=value#>>'{}';
 IF text_value !~ '^[1-9][0-9]{0,19}$' THEN RETURN false; END IF;
 RETURN text_value::numeric<=18446744073709551615;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
CREATE FUNCTION dvaia_maintenance.owner_windows_tuple(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE pid_value numeric; parent_value numeric;
BEGIN
 IF NOT dvaia_maintenance.owner_exact_keys(value,ARRAY['pid','ppid','sid','creationFileTime']) OR
 jsonb_typeof(value->'pid') IS DISTINCT FROM 'number' OR jsonb_typeof(value->'ppid') IS DISTINCT FROM 'number' OR
 jsonb_typeof(value->'sid') IS DISTINCT FROM 'string' OR
 NOT dvaia_maintenance.owner_windows_sid(value->>'sid') OR NOT dvaia_maintenance.owner_windows_filetime(value->'creationFileTime') THEN RETURN false; END IF;
 pid_value:=(value->>'pid')::numeric;parent_value:=(value->>'ppid')::numeric;
 RETURN pid_value=trunc(pid_value) AND pid_value BETWEEN 1 AND 2147483647 AND
 parent_value=trunc(parent_value) AND parent_value BETWEEN 0 AND 2147483647;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
CREATE FUNCTION dvaia_maintenance.supported_owner_record(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE all_processes jsonb; member jsonb; parent jsonb; boundary jsonb; count_owned integer; i integer; seen bigint[]:=ARRAY[]::bigint[]; pid_value bigint; boot numeric;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 -- Preserve the exact previous SQL text-marker acceptance, including v2 fixture
 -- extensions. Existing table object/size/hash constraints remain in force.
 IF value->>'version' IS NOT DISTINCT FROM '2' AND value->>'ancestry' IS NOT DISTINCT FROM 'complete-supported-chain' THEN RETURN true; END IF;
 IF octet_length(value::text)>32768 OR
 NOT dvaia_maintenance.owner_exact_keys(value,ARRAY['version','workspaceSha256','installationId','operationId','platform','hostSha256','bootFileTime','currentSid','ancestors','boundary','ancestry']) OR
 jsonb_typeof(value->'version') IS DISTINCT FROM 'number' OR value->'version' IS DISTINCT FROM '3'::jsonb OR
 value->>'platform' IS DISTINCT FROM 'win32' OR value->>'ancestry' IS DISTINCT FROM 'observed-supported-chain' OR
 jsonb_typeof(value->'workspaceSha256') IS DISTINCT FROM 'string' OR (value->>'workspaceSha256') !~ '^[a-f0-9]{64}$' OR
 jsonb_typeof(value->'hostSha256') IS DISTINCT FROM 'string' OR (value->>'hostSha256') !~ '^[a-f0-9]{64}$' OR
 jsonb_typeof(value->'installationId') IS DISTINCT FROM 'string' OR (value->>'installationId') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
 jsonb_typeof(value->'operationId') IS DISTINCT FROM 'string' OR (value->>'operationId') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
 jsonb_typeof(value->'currentSid') IS DISTINCT FROM 'string' OR NOT dvaia_maintenance.owner_windows_sid(value->>'currentSid') OR
 NOT dvaia_maintenance.owner_windows_filetime(value->'bootFileTime') OR
 jsonb_typeof(value->'ancestors') IS DISTINCT FROM 'array' OR
 NOT dvaia_maintenance.owner_exact_keys(value->'boundary',ARRAY['kind','process']) THEN RETURN false; END IF;
 count_owned:=jsonb_array_length(value->'ancestors');
 IF count_owned NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
 boundary:=value->'boundary';
 IF jsonb_typeof(boundary->'kind') IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 all_processes:=(value->'ancestors')||jsonb_build_array(boundary->'process');
 boot:=(value->>'bootFileTime')::numeric;
 FOR i IN 0..count_owned LOOP
  member:=all_processes->i;
  IF NOT dvaia_maintenance.owner_windows_tuple(member) THEN RETURN false; END IF;
  pid_value:=(member->>'pid')::numeric::bigint;
  IF pid_value=ANY(seen) OR (member->>'creationFileTime')::numeric<boot THEN RETURN false; END IF;
  seen:=array_append(seen,pid_value);
 END LOOP;
 FOR i IN 0..count_owned-1 LOOP
  member:=all_processes->i;parent:=all_processes->(i+1);
  IF member->>'sid' IS DISTINCT FROM value->>'currentSid' OR (member->>'ppid')::numeric<>(parent->>'pid')::numeric OR
  (parent->>'creationFileTime')::numeric>=(member->>'creationFileTime')::numeric THEN RETURN false; END IF;
 END LOOP;
 member:=boundary->'process';
 RETURN (boundary->>'kind'='root' AND (member->>'ppid')::numeric=0 AND member->>'sid'=value->>'currentSid') OR
 (boundary->>'kind'='foreign-sid' AND member->>'sid'<>value->>'currentSid');
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;

-- Find the single historical owner-marker check per table without relying on
-- PostgreSQL's generated constraint names. Unknown/ambiguous schema fails.
DO $$
DECLARE item record; names text[];
BEGIN
 FOR item IN SELECT * FROM (VALUES
 ('epoch_bindings','owner_record'),
 ('recovery_abandonment_observations','observer_record'),
 ('recovery_finish_claims','owner_record')) AS targets(table_name,column_name) LOOP
  SELECT array_agg(c.conname ORDER BY c.conname) INTO names
  FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
  WHERE n.nspname='dvaia_maintenance' AND t.relname=item.table_name AND c.contype='c' AND
  position(item.column_name IN pg_get_constraintdef(c.oid))>0 AND position('version' IN pg_get_constraintdef(c.oid))>0 AND
  position('complete-supported-chain' IN pg_get_constraintdef(c.oid))>0;
  IF cardinality(names) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'Unexpected maintenance owner constraints'; END IF;
  EXECUTE format('ALTER TABLE dvaia_maintenance.%I DROP CONSTRAINT %I',item.table_name,names[1]);
 END LOOP;
END $$;
ALTER TABLE dvaia_maintenance.epoch_bindings ADD CONSTRAINT epoch_bindings_supported_owner CHECK(
 (profile='unavailable' AND reason_code IS NOT NULL AND reason_code ~ '^[A-Z0-9_]{1,80}$' AND workspace_sha256 IS NULL AND store_manifest_sha256 IS NULL AND publication_id IS NULL AND publication_sha256 IS NULL AND source_manifest_sha256 IS NULL AND owner_record IS NULL AND owner_record_sha256 IS NULL) OR
 (profile='upgrade-canonical16-v1' AND reason_code IS NULL AND workspace_sha256 IS NOT NULL AND workspace_sha256 ~ '^[a-f0-9]{64}$' AND store_manifest_sha256 IS NOT NULL AND store_manifest_sha256 ~ '^[a-f0-9]{64}$' AND publication_id IS NOT NULL AND publication_sha256 IS NOT NULL AND publication_sha256 ~ '^[a-f0-9]{64}$' AND source_manifest_sha256 IS NOT NULL AND source_manifest_sha256 ~ '^[a-f0-9]{64}$' AND owner_record IS NOT NULL AND jsonb_typeof(owner_record)='object' AND octet_length(owner_record::text)<=32768 AND dvaia_maintenance.supported_owner_record(owner_record) AND owner_record_sha256 IS NOT NULL AND owner_record_sha256 ~ '^[a-f0-9]{64}$')
);
ALTER TABLE dvaia_maintenance.recovery_abandonment_observations ADD CONSTRAINT recovery_abandonment_supported_observer CHECK(dvaia_maintenance.supported_owner_record(observer_record));
ALTER TABLE dvaia_maintenance.recovery_finish_claims ADD CONSTRAINT recovery_finish_supported_owner CHECK(dvaia_maintenance.supported_owner_record(owner_record));
-- Historical non-prospective attempt rows had only object/size checks. Preserve
-- those rows while denying malformed v3 on every new attempt, not just deferred
-- execution epochs. The existing deferred checker still rejects other versions.
ALTER TABLE dvaia_maintenance.recovery_attempts ADD CONSTRAINT recovery_attempt_windows_owner CHECK(
 recovery_owner_record->>'version' IS DISTINCT FROM '3' OR dvaia_maintenance.supported_owner_record(recovery_owner_record)
);

-- Every other deferred execution invariant is copied unchanged from 0004.
CREATE OR REPLACE FUNCTION dvaia_maintenance.check_execution_epoch() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
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
  IF NOT dvaia_maintenance.supported_owner_record(a.recovery_owner_record) THEN RAISE EXCEPTION 'Unsupported recovery owner'; END IF;
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
REVOKE ALL ON FUNCTION dvaia_maintenance.owner_exact_keys(jsonb,text[]),dvaia_maintenance.owner_windows_sid(text),dvaia_maintenance.owner_windows_filetime(jsonb),dvaia_maintenance.owner_windows_tuple(jsonb),dvaia_maintenance.supported_owner_record(jsonb),dvaia_maintenance.check_execution_epoch() FROM PUBLIC,dvaia_identity_runtime;
