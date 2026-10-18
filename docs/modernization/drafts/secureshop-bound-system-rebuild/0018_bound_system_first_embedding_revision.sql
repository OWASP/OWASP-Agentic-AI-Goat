-- CANDIDATE ONLY: forward extension of canonical 0017. Do not register before
-- disposable fresh/populated/no-op and lifecycle qualification.

ALTER TABLE secureshop_review.bound_system_rebuild_operations
 ADD COLUMN operation_mode text NOT NULL DEFAULT 'selective'
 CHECK(operation_mode IN ('initialize','selective'));
ALTER TABLE secureshop_review.bound_system_rebuild_operations
 ALTER COLUMN operation_mode DROP DEFAULT,
 ALTER COLUMN base_revision_id DROP NOT NULL;
ALTER TABLE secureshop_review.bound_system_rebuild_operations
 ADD CONSTRAINT bound_system_rebuild_mode_shape CHECK(
  (operation_mode='initialize' AND corpus='products' AND expected_head IS NULL AND base_revision_id IS NULL)
  OR (operation_mode='selective' AND base_revision_id IS NOT NULL));

CREATE OR REPLACE FUNCTION secureshop_review.guard_bound_system_rebuild_operation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id)
   OR EXISTS(SELECT 1 FROM secureshop_review.bound_system_rebuild_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN RAISE EXCEPTION 'Bound rebuild owner is deleted' USING ERRCODE='55000'; END IF;
  SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=NEW.target_id FOR SHARE;
  IF NOT FOUND OR target.lifecycle<>'active' OR target.launch_id<>NEW.launch_id OR target.scenario_id<>NEW.scenario_id OR target.generation<>NEW.generation OR target.original_platform_owner_id<>NEW.original_platform_owner_id OR target.original_platform_session_id<>NEW.original_platform_session_id THEN RAISE EXCEPTION 'Active rebuild target required' USING ERRCODE='55000'; END IF;
  IF NEW.operation_mode='selective' AND NOT EXISTS(SELECT 1 FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=NEW.target_id AND c.lifecycle='active') THEN RAISE EXCEPTION 'Active rebuild source required' USING ERRCODE='55000'; END IF;
  IF NEW.operation_mode='initialize' AND EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_revisions r WHERE r.target_id=NEW.target_id AND r.launch_id=NEW.launch_id AND r.scenario_id=NEW.scenario_id AND r.generation=NEW.generation AND r.original_platform_owner_id=NEW.original_platform_owner_id AND r.original_platform_session_id=NEW.original_platform_session_id) THEN RAISE EXCEPTION 'First revision already exists' USING ERRCODE='55000'; END IF;
  IF NEW.state<>'admitted' OR NEW.worker_token IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR NEW.failure_code IS NOT NULL OR NEW.revision_id IS NOT NULL OR NEW.vector_sha256 IS NOT NULL OR NEW.document_count IS NOT NULL THEN RAISE EXCEPTION 'Bound rebuild must begin as an admission' USING ERRCODE='55000'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM secureshop_review.bound_system_rebuild_owner_deletion_receipts r WHERE r.original_platform_owner_id=OLD.original_platform_owner_id) THEN RAISE EXCEPTION 'Bound rebuild operation is immutable' USING ERRCODE='55000'; END IF;
  RETURN OLD;
 END IF;
 IF ROW(NEW.operation_id,NEW.target_id,NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id,NEW.shop_user_id,NEW.persona_session_id,NEW.authority_version,NEW.corpus,NEW.request_sha256,NEW.binding_sha256,NEW.source_set_sha256,NEW.runtime_sha256,NEW.expected_head,NEW.base_revision_id,NEW.operation_mode,NEW.admitted_at)
  IS DISTINCT FROM ROW(OLD.operation_id,OLD.target_id,OLD.launch_id,OLD.scenario_id,OLD.generation,OLD.original_platform_owner_id,OLD.original_platform_session_id,OLD.shop_user_id,OLD.persona_session_id,OLD.authority_version,OLD.corpus,OLD.request_sha256,OLD.binding_sha256,OLD.source_set_sha256,OLD.runtime_sha256,OLD.expected_head,OLD.base_revision_id,OLD.operation_mode,OLD.admitted_at) THEN RAISE EXCEPTION 'Bound rebuild admission is immutable' USING ERRCODE='55000'; END IF;
 IF OLD.state='admitted' AND NEW.state='running' THEN RETURN NEW; END IF;
 IF OLD.state='running' AND NEW.state IN ('completed','failed') AND NEW.worker_token=OLD.worker_token AND NEW.started_at=OLD.started_at THEN
  IF NEW.state='completed' AND NOT EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_revisions r JOIN secureshop_review.product_targets t USING(target_id) WHERE r.revision_id=NEW.operation_id AND r.target_id=NEW.target_id AND r.launch_id=NEW.launch_id AND r.scenario_id=NEW.scenario_id AND r.generation=NEW.generation AND r.original_platform_owner_id=NEW.original_platform_owner_id AND r.original_platform_session_id=NEW.original_platform_session_id AND r.source_set_digest=NEW.source_set_sha256 AND r.runtime_fingerprint=NEW.runtime_sha256 AND r.vector_digest=NEW.vector_sha256 AND r.document_count=NEW.document_count AND t.lifecycle='active') THEN RAISE EXCEPTION 'Bound rebuild completion receipt mismatch' USING ERRCODE='55000'; END IF;
  RETURN NEW;
 END IF;
 IF OLD.state IN ('admitted','running') AND NEW.state='retired' AND EXISTS(SELECT 1 FROM secureshop_review.product_targets t WHERE t.target_id=OLD.target_id AND t.lifecycle='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Bound rebuild lifecycle transition rejected' USING ERRCODE='55000';
END $$;

CREATE FUNCTION secureshop_review.initialize_product_embedding_revision(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,requested_operation uuid,requested_fingerprint bytea,
 requested_source_digest bytea,documents jsonb)
RETURNS TABLE(revision_id uuid,runtime_fingerprint bytea,source_set_digest bytea,vector_digest bytea,document_count integer,replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; admitted secureshop_review.bound_system_rebuild_operations%ROWTYPE; item jsonb; body text; expected_hash bytea; source_count integer;
BEGIN
 SELECT * INTO target FROM secureshop_review.product_targets t WHERE t.target_id=requested_target FOR UPDATE;
 IF NOT FOUND OR target.lifecycle<>'active' OR target.launch_id<>requested_launch OR target.scenario_id<>requested_scenario OR target.generation<>requested_generation OR target.original_platform_owner_id<>requested_owner OR target.original_platform_session_id<>requested_session THEN RAISE EXCEPTION 'embedding target unavailable' USING ERRCODE='55000'; END IF;
 SELECT * INTO admitted FROM secureshop_review.bound_system_rebuild_operations o WHERE o.operation_id=requested_operation FOR UPDATE;
 IF NOT FOUND OR admitted.operation_mode<>'initialize' OR admitted.state<>'running' OR admitted.worker_token IS NULL OR admitted.target_id<>requested_target OR admitted.launch_id<>requested_launch OR admitted.scenario_id<>requested_scenario OR admitted.generation<>requested_generation OR admitted.original_platform_owner_id<>requested_owner OR admitted.original_platform_session_id<>requested_session OR admitted.corpus<>'products' OR admitted.expected_head IS NOT NULL OR admitted.base_revision_id IS NOT NULL OR admitted.runtime_sha256<>requested_fingerprint OR admitted.source_set_sha256<>requested_source_digest THEN RAISE EXCEPTION 'admitted first embedding operation required' USING ERRCODE='55000'; END IF;
 IF EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_revisions WHERE target_id=requested_target)
  OR EXISTS(SELECT 1 FROM secureshop_review.product_target_retrieval_config WHERE target_id=requested_target) THEN RAISE EXCEPTION 'first embedding revision already initialized' USING ERRCODE='55000'; END IF;
 SELECT count(*) INTO source_count FROM secureshop_review.product_target_products WHERE target_id=requested_target;
 IF source_count<1 OR source_count<>jsonb_array_length(documents) THEN RAISE EXCEPTION 'initial embedding source mismatch' USING ERRCODE='55000'; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(documents) LOOP
  IF jsonb_typeof(item)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>6 OR NOT(item ?& ARRAY['sourceKind','sourceId','chunkIndex','text','sourceSha256','embedding']) OR item->>'sourceKind'<>'product' OR item->>'sourceId' !~ '^[1-9][0-9]{0,15}$' OR (item->>'chunkIndex')::integer<>0 THEN RAISE EXCEPTION 'invalid initial embedding document' USING ERRCODE='22023'; END IF;
  SELECT p.name||E'\n'||COALESCE(p.description,''),sha256(convert_to(jsonb_build_object('sourceKind','product','sourceId',p.product_id::text,'chunkIndex',0,'text',p.name||E'\n'||COALESCE(p.description,''))::text,'UTF8')) INTO body,expected_hash FROM secureshop_review.product_target_products p WHERE p.target_id=requested_target AND p.product_id=(item->>'sourceId')::bigint;
  IF body IS NULL OR octet_length(body) NOT BETWEEN 1 AND 32768 OR item->>'text'<>body OR decode(item->>'sourceSha256','hex')<>expected_hash THEN RAISE EXCEPTION 'initial embedding product changed' USING ERRCODE='55000'; END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(documents) d GROUP BY d->>'sourceId' HAVING count(*)>1) THEN RAISE EXCEPTION 'duplicate initial embedding source' USING ERRCODE='22023'; END IF;
 INSERT INTO secureshop_review.product_target_retrieval_config(target_id,embedding_model,embedding_dimension) VALUES(requested_target,'runtime-sha256:'||encode(requested_fingerprint,'hex'),384);
 INSERT INTO secureshop_review.product_target_retrieval_documents(target_id,generation,source_kind,source_id,chunk_index,body,embedding,source_sha256)
 SELECT requested_target,requested_generation,'product',(d->>'sourceId')::bigint,0,d->>'text',ARRAY(SELECT v::text::double precision FROM jsonb_array_elements(d->'embedding') v),decode(d->>'sourceSha256','hex') FROM jsonb_array_elements(documents) d;
 IF secureshop_review.product_embedding_source_digest(requested_target,requested_generation)<>requested_source_digest THEN RAISE EXCEPTION 'initial embedding digest changed' USING ERRCODE='55000'; END IF;
 RETURN QUERY SELECT * FROM secureshop_review.publish_product_embedding_revision(requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,requested_operation,requested_fingerprint,requested_source_digest,NULL,(
  SELECT jsonb_agg(jsonb_build_object('sourceKind',d->>'sourceKind','sourceId',d->>'sourceId','chunkIndex',(d->>'chunkIndex')::integer,'sourceSha256',d->>'sourceSha256','embedding',d->'embedding') ORDER BY d->>'sourceKind' COLLATE "C",(d->>'sourceId')::bigint,(d->>'chunkIndex')::integer) FROM jsonb_array_elements(documents) d));
END $$;
REVOKE ALL ON FUNCTION secureshop_review.initialize_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.initialize_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,jsonb) TO dvaia_secureshop_review_runtime;
