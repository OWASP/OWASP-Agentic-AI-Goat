-- Immutable owner-bound upload journal. File bytes remain in the separately
-- owned upload root; these rows retain exact authority and effect digests.
CREATE TABLE secureshop_review.bound_upload_admissions (
 operation_id uuid PRIMARY KEY,
 upload_request_id uuid NOT NULL,
 storage_key uuid NOT NULL UNIQUE,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 launch_id uuid NOT NULL, scenario_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation > 0),
 platform_owner_id integer NOT NULL CHECK(platform_owner_id > 0),
 platform_session_id integer NOT NULL CHECK(platform_session_id > 0),
 scene_id uuid NOT NULL, scene_generation bigint NOT NULL CHECK(scene_generation > 0),
 grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
 shop_user_id integer NOT NULL CHECK(shop_user_id > 0),
 persona_session_id uuid NOT NULL,
 persona_authority_version text NOT NULL CHECK(persona_authority_version ~ '^[1-9][0-9]*$'),
 mode text NOT NULL CHECK(mode IN('vuln','fixed')),
 mode_generation bigint NOT NULL CHECK(mode_generation >= 0),
 mode_stamp bytea NOT NULL CHECK(octet_length(mode_stamp)=32),
 kind text NOT NULL CHECK(kind='avatar'),
 scope_id integer NOT NULL CHECK(scope_id=shop_user_id),
 original_filename text NOT NULL CHECK(octet_length(original_filename) BETWEEN 1 AND 4096),
 declared_mime text NOT NULL CHECK(octet_length(declared_mime) BETWEEN 1 AND 1024),
 is_public boolean NOT NULL,
 byte_count integer NOT NULL CHECK(byte_count BETWEEN 1 AND 20971520),
 body_sha256 bytea NOT NULL CHECK(octet_length(body_sha256)=32),
 binding_sha256 bytea NOT NULL CHECK(octet_length(binding_sha256)=32),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(target_id,generation,shop_user_id,upload_request_id)
);
CREATE TABLE secureshop_review.bound_upload_effects (
 effect_id uuid PRIMARY KEY,
 operation_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.bound_upload_admissions(operation_id),
 outcome text NOT NULL CHECK(outcome IN('completed','denied','unresolved')),
 storage_key uuid,
 original_filename text, cleaned_filename text, declared_mime text,
 byte_count integer, body_sha256 bytea,
 base_virtual_path text, resolved_virtual_path text, stored_virtual_path text,
 is_traversal boolean, denial_code text, quarantine_required boolean NOT NULL,
 effect_sha256 bytea NOT NULL CHECK(octet_length(effect_sha256)=32),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((outcome='completed' AND storage_key IS NOT NULL AND original_filename IS NOT NULL
   AND cleaned_filename IS NOT NULL AND declared_mime IS NOT NULL AND byte_count BETWEEN 1 AND 20971520
   AND octet_length(body_sha256)=32 AND base_virtual_path IS NOT NULL
   AND resolved_virtual_path IS NOT NULL AND stored_virtual_path IS NOT NULL
   AND is_traversal IS NOT NULL AND denial_code IS NULL AND quarantine_required=false)
  OR (outcome='denied' AND storage_key IS NULL AND original_filename IS NULL
   AND cleaned_filename IS NULL AND declared_mime IS NULL AND byte_count IS NULL
   AND body_sha256 IS NULL AND base_virtual_path IS NULL AND resolved_virtual_path IS NULL
   AND stored_virtual_path IS NULL AND is_traversal IS NULL
   AND octet_length(denial_code) BETWEEN 1 AND 128 AND quarantine_required=false)
  OR (outcome='unresolved' AND denial_code IS NULL AND quarantine_required=true AND (
   (storage_key IS NULL AND original_filename IS NULL AND cleaned_filename IS NULL
    AND declared_mime IS NULL AND byte_count IS NULL AND body_sha256 IS NULL
    AND base_virtual_path IS NULL AND resolved_virtual_path IS NULL
    AND stored_virtual_path IS NULL AND is_traversal IS NULL)
   OR (storage_key IS NOT NULL AND original_filename IS NOT NULL AND cleaned_filename IS NOT NULL
    AND declared_mime IS NOT NULL AND byte_count BETWEEN 1 AND 20971520
    AND octet_length(body_sha256)=32 AND base_virtual_path IS NOT NULL
    AND resolved_virtual_path IS NOT NULL AND stored_virtual_path IS NOT NULL
    AND is_traversal IS NOT NULL)))),
 CHECK(original_filename IS NULL OR octet_length(original_filename) BETWEEN 1 AND 4096),
 CHECK(cleaned_filename IS NULL OR octet_length(cleaned_filename) BETWEEN 1 AND 4096),
 CHECK(declared_mime IS NULL OR octet_length(declared_mime) BETWEEN 1 AND 1024),
 CHECK(base_virtual_path IS NULL OR octet_length(base_virtual_path) BETWEEN 1 AND 4096),
 CHECK(resolved_virtual_path IS NULL OR octet_length(resolved_virtual_path) BETWEEN 1 AND 4096),
 CHECK(stored_virtual_path IS NULL OR octet_length(stored_virtual_path) BETWEEN 1 AND 4096)
);
CREATE TABLE secureshop_review.bound_upload_serves (
 serve_id uuid PRIMARY KEY,
 operation_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.bound_upload_admissions(operation_id),
 effect_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.bound_upload_effects(effect_id),
 receipt_path text NOT NULL CHECK(octet_length(receipt_path) BETWEEN 1 AND 4096),
 status integer NOT NULL CHECK(status=200),
 content_type text NOT NULL CHECK(octet_length(content_type) BETWEEN 1 AND 1024),
 content_disposition text NOT NULL CHECK(octet_length(content_disposition) BETWEEN 1 AND 1024),
 nosniff_present boolean NOT NULL,
 response_byte_count integer NOT NULL CHECK(response_byte_count BETWEEN 1 AND 20971520),
 response_sha256 bytea NOT NULL CHECK(octet_length(response_sha256)=32),
 serve_sha256 bytea NOT NULL CHECK(octet_length(serve_sha256)=32),
 served_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_review.bound_upload_reconciliations (
 operation_id uuid PRIMARY KEY REFERENCES secureshop_review.bound_upload_admissions(operation_id),
 effect_id uuid UNIQUE REFERENCES secureshop_review.bound_upload_effects(effect_id),
 action text NOT NULL CHECK(action IN('quarantined','deleted')),
 storage_key uuid NOT NULL,
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_review.bound_upload_cleanup_receipts (
 target_id uuid PRIMARY KEY REFERENCES secureshop_review.product_targets(target_id),
 operation_id uuid NOT NULL UNIQUE,
 launch_id uuid NOT NULL, scenario_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation > 0),
 platform_owner_id integer NOT NULL CHECK(platform_owner_id > 0),
 platform_session_id integer NOT NULL CHECK(platform_session_id > 0),
 deleted_count integer NOT NULL CHECK(deleted_count >= 0),
 quarantined_count integer NOT NULL CHECK(quarantined_count >= 0),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX bound_upload_owner_read ON secureshop_review.bound_upload_admissions
 (target_id,generation,shop_user_id,admitted_at DESC);
CREATE TRIGGER bound_upload_admission_immutable BEFORE UPDATE OR DELETE ON secureshop_review.bound_upload_admissions
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE TRIGGER bound_upload_effect_immutable BEFORE UPDATE OR DELETE ON secureshop_review.bound_upload_effects
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE TRIGGER bound_upload_serve_immutable BEFORE UPDATE OR DELETE ON secureshop_review.bound_upload_serves
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE TRIGGER bound_upload_reconciliation_immutable BEFORE UPDATE OR DELETE ON secureshop_review.bound_upload_reconciliations
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE TRIGGER bound_upload_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_review.bound_upload_cleanup_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();

CREATE FUNCTION secureshop_review.claim_bound_upload_admission(
 op uuid, request_id uuid, selected_storage_key uuid,
 selected_target uuid, selected_launch uuid, selected_scenario uuid, selected_generation bigint,
 selected_owner integer, selected_session integer, selected_scene uuid, selected_scene_generation bigint,
 selected_grant uuid, selected_shop_user integer, selected_persona_session uuid,
 selected_authority_version text, selected_mode text, selected_mode_generation bigint,
 selected_mode_stamp bytea, selected_kind text, selected_scope integer,
 selected_filename text, selected_mime text, selected_public boolean,
 selected_bytes integer, selected_body_sha bytea, selected_binding_sha bytea, selected_request_sha bytea)
RETURNS TABLE(replayed boolean,operation_id uuid,storage_key uuid,request_sha256 bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE prior secureshop_review.bound_upload_admissions%ROWTYPE;
BEGIN
 IF op IS NULL OR request_id IS NULL OR selected_storage_key IS NULL
  OR selected_kind IS DISTINCT FROM 'avatar' OR selected_scope IS DISTINCT FROM selected_shop_user
  OR selected_authority_version !~ '^[1-9][0-9]*$' OR selected_mode NOT IN('vuln','fixed')
  OR selected_mode_generation < 0 OR octet_length(selected_mode_stamp)<>32
  OR octet_length(selected_filename) NOT BETWEEN 1 AND 4096
  OR octet_length(selected_mime) NOT BETWEEN 1 AND 1024
  OR selected_bytes NOT BETWEEN 1 AND 20971520 OR octet_length(selected_body_sha)<>32
  OR octet_length(selected_binding_sha)<>32 OR octet_length(selected_request_sha)<>32 THEN
  RAISE EXCEPTION 'bound upload admission invalid' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('bound-upload-target:'||selected_target::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_review.bound_upload_cleanup_receipts c WHERE c.target_id=selected_target) THEN
  RAISE EXCEPTION 'bound upload target retired' USING ERRCODE='55000';
 END IF;
 IF NOT secureshop_review.assert_scene_execution_grant(selected_grant,selected_scene,
   selected_scene_generation,selected_target,selected_launch,selected_scenario,
   selected_generation,selected_owner,selected_session) THEN
  RAISE EXCEPTION 'bound upload authority unavailable' USING ERRCODE='55000';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('bound-upload:'||selected_target::text||':'||request_id::text,0));
 SELECT * INTO prior FROM secureshop_review.bound_upload_admissions a
  WHERE a.operation_id=op OR (a.target_id=selected_target AND a.generation=selected_generation
   AND a.shop_user_id=selected_shop_user AND a.upload_request_id=request_id) FOR UPDATE;
 IF FOUND THEN
  IF ROW(prior.operation_id,prior.upload_request_id,prior.storage_key,prior.target_id,prior.launch_id,
    prior.scenario_id,prior.generation,prior.platform_owner_id,prior.platform_session_id,
    prior.scene_id,prior.scene_generation,prior.grant_id,prior.shop_user_id,prior.persona_session_id,
    prior.persona_authority_version,prior.mode,prior.mode_generation,prior.mode_stamp,prior.kind,
    prior.scope_id,prior.original_filename,prior.declared_mime,prior.is_public,prior.byte_count,
    prior.body_sha256,prior.binding_sha256,prior.request_sha256)
   IS DISTINCT FROM ROW(op,request_id,selected_storage_key,selected_target,selected_launch,
    selected_scenario,selected_generation,selected_owner,selected_session,selected_scene,
    selected_scene_generation,selected_grant,selected_shop_user,selected_persona_session,
    selected_authority_version,selected_mode,selected_mode_generation,selected_mode_stamp,
    selected_kind,selected_scope,selected_filename,selected_mime,selected_public,selected_bytes,
    selected_body_sha,selected_binding_sha,selected_request_sha) THEN
   RAISE EXCEPTION 'bound upload replay conflict' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT true,prior.operation_id,prior.storage_key,prior.request_sha256; RETURN;
 END IF;
 INSERT INTO secureshop_review.bound_upload_admissions(operation_id,upload_request_id,storage_key,
  target_id,launch_id,scenario_id,generation,platform_owner_id,platform_session_id,scene_id,
  scene_generation,grant_id,shop_user_id,persona_session_id,persona_authority_version,mode,
  mode_generation,mode_stamp,kind,scope_id,original_filename,declared_mime,is_public,byte_count,
  body_sha256,binding_sha256,request_sha256)
 VALUES(op,request_id,selected_storage_key,selected_target,selected_launch,selected_scenario,
  selected_generation,selected_owner,selected_session,selected_scene,selected_scene_generation,
  selected_grant,selected_shop_user,selected_persona_session,selected_authority_version,
  selected_mode,selected_mode_generation,selected_mode_stamp,selected_kind,selected_scope,
  selected_filename,selected_mime,selected_public,selected_bytes,selected_body_sha,
  selected_binding_sha,selected_request_sha);
 RETURN QUERY SELECT false,op,selected_storage_key,selected_request_sha;
END $$;

CREATE FUNCTION secureshop_review.append_bound_upload_effect(
 selected_effect uuid,selected_operation uuid,selected_outcome text,selected_storage_key uuid,
 selected_original_filename text,selected_cleaned_filename text,selected_mime text,
 selected_bytes integer,selected_body_sha bytea,selected_base_path text,selected_resolved_path text,
 selected_stored_path text,selected_traversal boolean,selected_denial text,
 selected_quarantine boolean,selected_effect_sha bytea,selected_binding_sha bytea,selected_request_sha bytea)
RETURNS TABLE(replayed boolean,effect_id uuid,effect_sha256 bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.bound_upload_admissions%ROWTYPE; prior secureshop_review.bound_upload_effects%ROWTYPE;
BEGIN
 SELECT * INTO admission FROM secureshop_review.bound_upload_admissions WHERE operation_id=selected_operation FOR SHARE;
 IF FOUND THEN PERFORM pg_advisory_xact_lock(hashtextextended('bound-upload-target:'||admission.target_id::text,0)); END IF;
 IF NOT FOUND OR NOT secureshop_review.assert_scene_execution_grant(admission.grant_id,admission.scene_id,
  admission.scene_generation,admission.target_id,admission.launch_id,admission.scenario_id,
  admission.generation,admission.platform_owner_id,admission.platform_session_id) THEN
  RAISE EXCEPTION 'bound upload authority unavailable' USING ERRCODE='55000';
 END IF;
 IF admission.binding_sha256 IS DISTINCT FROM selected_binding_sha
  OR admission.request_sha256 IS DISTINCT FROM selected_request_sha
  OR EXISTS(SELECT 1 FROM secureshop_review.bound_upload_cleanup_receipts c WHERE c.target_id=admission.target_id)
  OR EXISTS(SELECT 1 FROM secureshop_review.bound_upload_reconciliations r WHERE r.operation_id=selected_operation)
  OR octet_length(selected_effect_sha)<>32 OR selected_outcome NOT IN('completed','denied','unresolved')
  OR (selected_outcome='completed' AND (selected_storage_key IS DISTINCT FROM admission.storage_key
   OR selected_original_filename IS DISTINCT FROM admission.original_filename
   OR selected_mime IS DISTINCT FROM admission.declared_mime OR selected_bytes IS DISTINCT FROM admission.byte_count
   OR selected_body_sha IS DISTINCT FROM admission.body_sha256 OR selected_quarantine IS DISTINCT FROM false))
  OR (selected_outcome='denied' AND (selected_storage_key IS NOT NULL OR selected_denial IS NULL
   OR selected_quarantine IS DISTINCT FROM false))
  OR (selected_outcome='unresolved' AND (selected_quarantine IS DISTINCT FROM true
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_original_filename IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_cleaned_filename IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_mime IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_bytes IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_body_sha IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_base_path IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_resolved_path IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_stored_path IS NULL))
   OR ((selected_storage_key IS NULL) IS DISTINCT FROM (selected_traversal IS NULL))
   OR (selected_storage_key IS NOT NULL AND (selected_storage_key IS DISTINCT FROM admission.storage_key
    OR selected_original_filename IS DISTINCT FROM admission.original_filename
    OR selected_mime IS DISTINCT FROM admission.declared_mime
    OR selected_bytes IS DISTINCT FROM admission.byte_count
    OR selected_body_sha IS DISTINCT FROM admission.body_sha256)))) THEN
  RAISE EXCEPTION 'bound upload effect invalid' USING ERRCODE='22023';
 END IF;
 SELECT * INTO prior FROM secureshop_review.bound_upload_effects WHERE operation_id=selected_operation FOR UPDATE;
 IF FOUND THEN
  IF ROW(prior.effect_id,prior.outcome,prior.storage_key,prior.original_filename,prior.cleaned_filename,
    prior.declared_mime,prior.byte_count,prior.body_sha256,prior.base_virtual_path,
    prior.resolved_virtual_path,prior.stored_virtual_path,prior.is_traversal,prior.denial_code,
    prior.quarantine_required,prior.effect_sha256)
   IS DISTINCT FROM ROW(selected_effect,selected_outcome,selected_storage_key,selected_original_filename,
    selected_cleaned_filename,selected_mime,selected_bytes,selected_body_sha,selected_base_path,
    selected_resolved_path,selected_stored_path,selected_traversal,selected_denial,
    selected_quarantine,selected_effect_sha) THEN
   RAISE EXCEPTION 'bound upload effect replay conflict' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT true,prior.effect_id,prior.effect_sha256; RETURN;
 END IF;
 INSERT INTO secureshop_review.bound_upload_effects(effect_id,operation_id,outcome,storage_key,
  original_filename,cleaned_filename,declared_mime,byte_count,body_sha256,base_virtual_path,
  resolved_virtual_path,stored_virtual_path,is_traversal,denial_code,quarantine_required,effect_sha256)
 VALUES(selected_effect,selected_operation,selected_outcome,selected_storage_key,
  selected_original_filename,selected_cleaned_filename,selected_mime,selected_bytes,
  selected_body_sha,selected_base_path,selected_resolved_path,selected_stored_path,
  selected_traversal,selected_denial,selected_quarantine,selected_effect_sha);
 RETURN QUERY SELECT false,selected_effect,selected_effect_sha;
END $$;

CREATE FUNCTION secureshop_review.append_bound_upload_serve(
 selected_serve uuid,selected_operation uuid,selected_effect uuid,selected_path text,
 selected_status integer,selected_type text,selected_disposition text,selected_nosniff boolean,
 selected_bytes integer,selected_response_sha bytea,selected_serve_sha bytea,
 selected_binding_sha bytea,selected_request_sha bytea)
RETURNS TABLE(replayed boolean,serve_id uuid,serve_sha256 bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.bound_upload_admissions%ROWTYPE; effect secureshop_review.bound_upload_effects%ROWTYPE; prior secureshop_review.bound_upload_serves%ROWTYPE;
BEGIN
 SELECT * INTO admission FROM secureshop_review.bound_upload_admissions WHERE operation_id=selected_operation FOR SHARE;
 IF FOUND THEN PERFORM pg_advisory_xact_lock(hashtextextended('bound-upload-target:'||admission.target_id::text,0)); END IF;
 SELECT * INTO effect FROM secureshop_review.bound_upload_effects WHERE effect_id=selected_effect AND operation_id=selected_operation FOR SHARE;
 IF admission.operation_id IS NULL OR effect.effect_id IS NULL OR effect.outcome<>'completed'
  OR admission.binding_sha256 IS DISTINCT FROM selected_binding_sha
  OR admission.request_sha256 IS DISTINCT FROM selected_request_sha
  OR selected_status<>200 OR selected_bytes IS DISTINCT FROM effect.byte_count
  OR selected_response_sha IS DISTINCT FROM effect.body_sha256 OR octet_length(selected_serve_sha)<>32
  OR EXISTS(SELECT 1 FROM secureshop_review.bound_upload_cleanup_receipts c WHERE c.target_id=admission.target_id)
  OR NOT secureshop_review.assert_scene_execution_grant(admission.grant_id,admission.scene_id,
   admission.scene_generation,admission.target_id,admission.launch_id,admission.scenario_id,
   admission.generation,admission.platform_owner_id,admission.platform_session_id) THEN
  RAISE EXCEPTION 'bound upload serve unavailable' USING ERRCODE='55000';
 END IF;
 SELECT * INTO prior FROM secureshop_review.bound_upload_serves WHERE operation_id=selected_operation FOR UPDATE;
 IF FOUND THEN
  IF ROW(prior.serve_id,prior.effect_id,prior.receipt_path,prior.status,prior.content_type,
    prior.content_disposition,prior.nosniff_present,prior.response_byte_count,
    prior.response_sha256,prior.serve_sha256)
   IS DISTINCT FROM ROW(selected_serve,selected_effect,selected_path,selected_status,selected_type,
    selected_disposition,selected_nosniff,selected_bytes,selected_response_sha,selected_serve_sha) THEN
   RAISE EXCEPTION 'bound upload serve replay conflict' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT true,prior.serve_id,prior.serve_sha256; RETURN;
 END IF;
 INSERT INTO secureshop_review.bound_upload_serves(serve_id,operation_id,effect_id,receipt_path,
  status,content_type,content_disposition,nosniff_present,response_byte_count,response_sha256,serve_sha256)
 VALUES(selected_serve,selected_operation,selected_effect,selected_path,selected_status,selected_type,
  selected_disposition,selected_nosniff,selected_bytes,selected_response_sha,selected_serve_sha);
 RETURN QUERY SELECT false,selected_serve,selected_serve_sha;
END $$;


CREATE FUNCTION secureshop_review.reconcile_bound_upload(
 selected_operation uuid,selected_effect uuid,selected_action text,
 selected_storage_key uuid,selected_receipt_sha bytea,
 selected_binding_sha bytea,selected_request_sha bytea)
RETURNS TABLE(replayed boolean,operation_id uuid,receipt_sha256 bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.bound_upload_admissions%ROWTYPE; effect secureshop_review.bound_upload_effects%ROWTYPE; prior secureshop_review.bound_upload_reconciliations%ROWTYPE;
BEGIN
 SELECT * INTO admission FROM secureshop_review.bound_upload_admissions WHERE operation_id=selected_operation FOR SHARE;
 IF FOUND THEN PERFORM pg_advisory_xact_lock(hashtextextended('bound-upload-target:'||admission.target_id::text,0)); END IF;
 SELECT * INTO effect FROM secureshop_review.bound_upload_effects WHERE operation_id=selected_operation FOR SHARE;
 IF admission.operation_id IS NULL
  OR (selected_effect IS NULL AND effect.effect_id IS NOT NULL)
  OR (selected_effect IS NOT NULL AND (effect.effect_id IS DISTINCT FROM selected_effect
   OR effect.outcome<>'unresolved' OR effect.quarantine_required IS DISTINCT FROM true))
  OR admission.binding_sha256 IS DISTINCT FROM selected_binding_sha
  OR admission.request_sha256 IS DISTINCT FROM selected_request_sha
  OR selected_storage_key IS DISTINCT FROM admission.storage_key
  OR selected_action NOT IN('quarantined','deleted') OR octet_length(selected_receipt_sha)<>32
  OR EXISTS(SELECT 1 FROM secureshop_review.bound_upload_cleanup_receipts c WHERE c.target_id=admission.target_id) THEN
  RAISE EXCEPTION 'bound upload reconciliation unavailable' USING ERRCODE='55000';
 END IF;
 SELECT * INTO prior FROM secureshop_review.bound_upload_reconciliations WHERE operation_id=selected_operation FOR UPDATE;
 IF FOUND THEN
  IF ROW(prior.effect_id,prior.action,prior.storage_key,prior.receipt_sha256)
   IS DISTINCT FROM ROW(selected_effect,selected_action,selected_storage_key,selected_receipt_sha) THEN
   RAISE EXCEPTION 'bound upload reconciliation replay conflict' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT true,prior.operation_id,prior.receipt_sha256; RETURN;
 END IF;
 INSERT INTO secureshop_review.bound_upload_reconciliations(operation_id,effect_id,action,storage_key,receipt_sha256)
 VALUES(selected_operation,selected_effect,selected_action,selected_storage_key,selected_receipt_sha);
 RETURN QUERY SELECT false,selected_operation,selected_receipt_sha;
END $$;

CREATE FUNCTION secureshop_review.append_bound_upload_cleanup(
 cleanup_operation uuid,selected_target uuid,selected_launch uuid,selected_scenario uuid,
 selected_generation bigint,selected_owner integer,selected_session integer,
 selected_deleted integer,selected_quarantined integer,selected_receipt_sha bytea)
RETURNS TABLE(replayed boolean,operation_id uuid,receipt_sha256 bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; prior secureshop_review.bound_upload_cleanup_receipts%ROWTYPE; expected_deleted integer; expected_quarantined integer;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('bound-upload-target:'||selected_target::text,0));
 SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=selected_target FOR SHARE;
 IF target.target_id IS NULL OR target.lifecycle<>'retired'
  OR ROW(target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id)
   IS DISTINCT FROM ROW(selected_launch,selected_scenario,selected_generation,selected_owner,selected_session)
  OR cleanup_operation IS NULL OR selected_deleted<0 OR selected_quarantined<0
  OR octet_length(selected_receipt_sha)<>32 THEN
  RAISE EXCEPTION 'bound upload cleanup authority unavailable' USING ERRCODE='55000';
 END IF;
 SELECT count(*)::integer INTO expected_deleted FROM secureshop_review.bound_upload_effects e
  JOIN secureshop_review.bound_upload_admissions a USING(operation_id)
  WHERE a.target_id=selected_target AND e.outcome='completed';
 SELECT expected_deleted+count(*)::integer INTO expected_deleted
  FROM secureshop_review.bound_upload_reconciliations r
  JOIN secureshop_review.bound_upload_admissions a USING(operation_id)
  WHERE a.target_id=selected_target AND r.action='deleted';
 SELECT count(*)::integer INTO expected_quarantined FROM secureshop_review.bound_upload_reconciliations r
  JOIN secureshop_review.bound_upload_admissions a USING(operation_id)
  WHERE a.target_id=selected_target AND r.action='quarantined';
 IF selected_deleted<>expected_deleted OR selected_quarantined<>expected_quarantined
  OR EXISTS(SELECT 1 FROM secureshop_review.bound_upload_admissions a
   LEFT JOIN secureshop_review.bound_upload_effects e USING(operation_id)
   LEFT JOIN secureshop_review.bound_upload_reconciliations r USING(operation_id)
   WHERE a.target_id=selected_target AND ((e.effect_id IS NULL AND r.operation_id IS NULL)
    OR (e.outcome='unresolved' AND r.operation_id IS NULL))) THEN
  RAISE EXCEPTION 'bound upload cleanup is incomplete' USING ERRCODE='55000';
 END IF;
 SELECT * INTO prior FROM secureshop_review.bound_upload_cleanup_receipts WHERE target_id=selected_target FOR UPDATE;
 IF FOUND THEN
  IF ROW(prior.operation_id,prior.launch_id,prior.scenario_id,prior.generation,
    prior.platform_owner_id,prior.platform_session_id,prior.deleted_count,
    prior.quarantined_count,prior.receipt_sha256)
   IS DISTINCT FROM ROW(cleanup_operation,selected_launch,selected_scenario,selected_generation,
    selected_owner,selected_session,selected_deleted,selected_quarantined,selected_receipt_sha) THEN
   RAISE EXCEPTION 'bound upload cleanup replay conflict' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT true,prior.operation_id,prior.receipt_sha256; RETURN;
 END IF;
 INSERT INTO secureshop_review.bound_upload_cleanup_receipts(target_id,operation_id,launch_id,
  scenario_id,generation,platform_owner_id,platform_session_id,deleted_count,
  quarantined_count,receipt_sha256)
 VALUES(selected_target,cleanup_operation,selected_launch,selected_scenario,selected_generation,
  selected_owner,selected_session,selected_deleted,selected_quarantined,selected_receipt_sha);
 RETURN QUERY SELECT false,cleanup_operation,selected_receipt_sha;
END $$;

REVOKE ALL ON secureshop_review.bound_upload_admissions,secureshop_review.bound_upload_effects,
 secureshop_review.bound_upload_serves,secureshop_review.bound_upload_reconciliations,
 secureshop_review.bound_upload_cleanup_receipts FROM PUBLIC;
GRANT SELECT ON secureshop_review.bound_upload_admissions,secureshop_review.bound_upload_effects,
 secureshop_review.bound_upload_serves,secureshop_review.bound_upload_reconciliations,
 secureshop_review.bound_upload_cleanup_receipts TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.claim_bound_upload_admission(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,integer,uuid,bigint,uuid,integer,uuid,text,text,bigint,bytea,text,integer,text,text,boolean,integer,bytea,bytea,bytea),
 secureshop_review.append_bound_upload_effect(uuid,uuid,text,uuid,text,text,text,integer,bytea,text,text,text,boolean,text,boolean,bytea,bytea,bytea),
 secureshop_review.append_bound_upload_serve(uuid,uuid,uuid,text,integer,text,text,boolean,integer,bytea,bytea,bytea,bytea),
 secureshop_review.reconcile_bound_upload(uuid,uuid,text,uuid,bytea,bytea,bytea),
 secureshop_review.append_bound_upload_cleanup(uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.claim_bound_upload_admission(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,integer,uuid,bigint,uuid,integer,uuid,text,text,bigint,bytea,text,integer,text,text,boolean,integer,bytea,bytea,bytea),
 secureshop_review.append_bound_upload_effect(uuid,uuid,text,uuid,text,text,text,integer,bytea,text,text,text,boolean,text,boolean,bytea,bytea,bytea),
 secureshop_review.append_bound_upload_serve(uuid,uuid,uuid,text,integer,text,text,boolean,integer,bytea,bytea,bytea,bytea),
 secureshop_review.reconcile_bound_upload(uuid,uuid,text,uuid,bytea,bytea,bytea),
 secureshop_review.append_bound_upload_cleanup(uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,bytea) TO dvaia_secureshop_review_runtime;
