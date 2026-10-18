-- Additive private v3 proof. Existing operation/public receipt rows are unchanged.
CREATE TABLE secureshop_review.bound_system_restart_full_receipts (
 operation_id uuid PRIMARY KEY REFERENCES secureshop_review.bound_system_restart_operations(operation_id) ON DELETE CASCADE,
 target_id uuid NOT NULL REFERENCES secureshop_review.bound_system_restart_targets(target_id),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 receipt_text text NOT NULL CHECK(octet_length(receipt_text) BETWEEN 1 AND 262144),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32
  AND receipt_sha256=sha256(convert_to(receipt_text,'UTF8'))),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON secureshop_review.bound_system_restart_full_receipts FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.bound_system_restart_full_receipts TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.guard_bound_system_restart_full_receipt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_restart_operations%ROWTYPE; body jsonb; witness jsonb;
 expected_keys text[]:=ARRAY['version','targetId','operationId','requestSha256','beforeInstanceId','afterInstanceId',
  'beforeGeneration','afterGeneration','effectSha256','outputSha256','outputBytes','outputText',
  'ownedCommandEffectSha256','ownedCommandEffectFiles','ownedCommandEffectBytes','command','status','isolation',
  'witness','stdoutText','stderrText','stdoutSha256','stderrSha256','stdoutBytes','stderrBytes','drained','exitCode'];
 witness_binding text;
BEGIN
 IF TG_OP='DELETE' THEN
  -- Only the existing guarded owner-deletion path creates this receipt before
  -- deleting operations. Its FK cascade removes this private child atomically.
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_system_restart_owner_deletion_receipts d
    WHERE d.original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'owned restart full receipt is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'owned restart full receipt is immutable' USING ERRCODE='55000'; END IF;
 SELECT * INTO op FROM secureshop_review.bound_system_restart_operations WHERE operation_id=NEW.operation_id FOR SHARE;
 IF NOT FOUND OR op.state<>'completed' OR op.target_id<>NEW.target_id
  OR op.original_platform_owner_id<>NEW.original_platform_owner_id THEN
  RAISE EXCEPTION 'owned restart full receipt binding rejected' USING ERRCODE='55000'; END IF;
 body:=NEW.receipt_text::jsonb;witness:=body->'witness';
 IF jsonb_typeof(body) IS DISTINCT FROM 'object'
  OR ARRAY(SELECT key FROM jsonb_object_keys(body) AS key ORDER BY key)
    IS DISTINCT FROM ARRAY(SELECT key FROM unnest(expected_keys) AS key ORDER BY key)
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['version','targetId','operationId','requestSha256',
    'beforeInstanceId','afterInstanceId','effectSha256','outputSha256','outputText',
    'ownedCommandEffectSha256','command','status','isolation','stdoutText','stderrText',
    'stdoutSha256','stderrSha256']) AS name WHERE jsonb_typeof(body->name) IS DISTINCT FROM 'string')
  OR body->>'version' IS DISTINCT FROM 'secureshop-owned-system-restart-http.v3'
  OR body->>'targetId' IS DISTINCT FROM op.target_id::text
  OR body->>'operationId' IS DISTINCT FROM op.operation_id::text
  OR body->>'requestSha256' IS DISTINCT FROM encode(op.request_sha256,'hex')
  OR body->>'beforeInstanceId' IS DISTINCT FROM op.before_instance_id::text
  OR body->>'afterInstanceId' IS DISTINCT FROM op.after_instance_id::text
  OR body->'beforeGeneration' IS DISTINCT FROM to_jsonb(op.before_generation)
  OR body->'afterGeneration' IS DISTINCT FROM to_jsonb(op.after_generation)
  OR body->>'effectSha256' IS DISTINCT FROM encode(op.effect_sha256,'hex')
  OR body->>'outputSha256' IS DISTINCT FROM encode(op.output_sha256,'hex')
  OR body->'outputBytes' IS DISTINCT FROM to_jsonb(op.output_bytes)
  OR body->>'outputText' IS DISTINCT FROM op.output_text
  OR body->>'command' IS DISTINCT FROM 'systemctl restart '||op.service_name
  OR body->>'status' IS DISTINCT FROM 'completed'
  OR body->>'isolation' IS DISTINCT FROM 'owned-restart-namespace-v1'
  OR body->'drained' IS DISTINCT FROM 'true'::jsonb OR body->'exitCode' IS DISTINCT FROM '0'::jsonb
  OR jsonb_typeof(body->'stdoutText') IS DISTINCT FROM 'string'
  OR jsonb_typeof(body->'stderrText') IS DISTINCT FROM 'string'
  OR body->'stdoutBytes' IS DISTINCT FROM to_jsonb(octet_length(body->>'stdoutText'))
  OR body->'stderrBytes' IS DISTINCT FROM to_jsonb(octet_length(body->>'stderrText'))
  OR octet_length(body->>'stdoutText')+octet_length(body->>'stderrText') NOT BETWEEN 0 AND 16384
  OR body->>'outputText' IS DISTINCT FROM (body->>'stdoutText')||(body->>'stderrText')
  OR body->>'stdoutSha256' IS DISTINCT FROM encode(sha256(convert_to(body->>'stdoutText','UTF8')),'hex')
  OR body->>'stderrSha256' IS DISTINCT FROM encode(sha256(convert_to(body->>'stderrText','UTF8')),'hex')
  OR COALESCE(body->>'ownedCommandEffectSha256','')!~'^[a-f0-9]{64}$'
  OR jsonb_typeof(body->'ownedCommandEffectFiles') IS DISTINCT FROM 'number'
  OR (body->>'ownedCommandEffectFiles')::numeric NOT BETWEEN 1 AND 16
  OR (body->>'ownedCommandEffectFiles')::numeric<>trunc((body->>'ownedCommandEffectFiles')::numeric)
  OR jsonb_typeof(body->'ownedCommandEffectBytes') IS DISTINCT FROM 'number'
  OR (body->>'ownedCommandEffectBytes')::numeric NOT BETWEEN 1 AND 65536
  OR (body->>'ownedCommandEffectBytes')::numeric<>trunc((body->>'ownedCommandEffectBytes')::numeric)
  OR jsonb_typeof(witness) IS DISTINCT FROM 'object'
  OR ARRAY(SELECT key FROM jsonb_object_keys(witness) AS key ORDER BY key)
    IS DISTINCT FROM ARRAY['bindingSha256','hostname','hostnameSha256','version']
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['hostname','hostnameSha256','bindingSha256']) AS name
    WHERE jsonb_typeof(witness->name) IS DISTINCT FROM 'string')
  OR witness->'version' IS DISTINCT FROM '1'::jsonb
  OR COALESCE(witness->>'hostname','')!~'^restart-[a-f0-9]{32}$'
  OR witness->>'hostnameSha256' IS DISTINCT FROM encode(sha256(convert_to(witness->>'hostname','UTF8')),'hex')
 THEN RAISE EXCEPTION 'owned restart full receipt payload rejected' USING ERRCODE='55000'; END IF;
 -- Match the executor's explicit JSON.stringify field order, not JSONB order.
 witness_binding:='{"version":1,"targetId":'||to_json(op.target_id::text)::text||',"operationId":'||to_json(op.operation_id::text)::text
  ||',"requestSha256":'||to_json(encode(op.request_sha256,'hex'))::text||',"hostname":'||to_json(witness->>'hostname')::text||'}';
 IF witness->>'bindingSha256' IS DISTINCT FROM encode(sha256(convert_to(witness_binding,'UTF8')),'hex') THEN
  RAISE EXCEPTION 'owned restart witness binding rejected' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER bound_system_restart_full_receipt_guard BEFORE INSERT OR UPDATE OR DELETE
 ON secureshop_review.bound_system_restart_full_receipts FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.guard_bound_system_restart_full_receipt();
REVOKE ALL ON FUNCTION secureshop_review.guard_bound_system_restart_full_receipt() FROM PUBLIC,dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.complete_bound_system_restart_with_receipt(
 requested_operation uuid,requested_worker uuid,requested_receipt text)
RETURNS SETOF secureshop_review.bound_system_restart_operations
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE body jsonb; op secureshop_review.bound_system_restart_operations%ROWTYPE;
BEGIN
 IF requested_receipt IS NULL OR octet_length(requested_receipt) NOT BETWEEN 1 AND 262144 THEN
  RAISE EXCEPTION 'owned restart full receipt unavailable' USING ERRCODE='22023'; END IF;
 body:=requested_receipt::jsonb;
 IF body->>'version' IS DISTINCT FROM 'secureshop-owned-system-restart-http.v3'
  OR body->>'operationId' IS DISTINCT FROM requested_operation::text THEN
  RAISE EXCEPTION 'owned restart full receipt unavailable' USING ERRCODE='22023'; END IF;
 -- Reuse the existing canonical operation/worker/active-target transition.
 -- Any child validation failure rolls this rotation and completion back.
 SELECT * INTO STRICT op FROM secureshop_review.complete_bound_system_restart(
  requested_operation,requested_worker,(body->>'beforeInstanceId')::uuid,(body->>'afterInstanceId')::uuid,
  (body->>'beforeGeneration')::bigint,(body->>'afterGeneration')::bigint,decode(body->>'effectSha256','hex'),
  decode(body->>'outputSha256','hex'),(body->>'outputBytes')::integer,body->>'outputText');
 INSERT INTO secureshop_review.bound_system_restart_full_receipts
  (operation_id,target_id,original_platform_owner_id,receipt_text,receipt_sha256)
 VALUES(op.operation_id,op.target_id,op.original_platform_owner_id,requested_receipt,sha256(convert_to(requested_receipt,'UTF8')));
 RETURN NEXT op;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.complete_bound_system_restart_with_receipt(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.complete_bound_system_restart_with_receipt(uuid,uuid,text)
 TO dvaia_secureshop_review_runtime;
