-- CANDIDATE ONLY: immutable agents-store policy snapshot copied into the owned review target.
ALTER TABLE secureshop_review.bound_system_rebuild_operations DROP CONSTRAINT bound_system_rebuild_operations_corpus_check;
ALTER TABLE secureshop_review.bound_system_rebuild_operations ADD CONSTRAINT bound_system_rebuild_operations_corpus_check CHECK(corpus IN('products','reviews','manuals','policies'));
ALTER TABLE secureshop_review.bound_system_rebuild_operations ADD COLUMN policy_version bigint,
 ADD COLUMN policy_snapshot_sha256 bytea,
 ADD CONSTRAINT bound_system_rebuild_policy_shape CHECK(
  (corpus='policies' AND operation_mode='selective' AND policy_version BETWEEN 1 AND 9007199254740991 AND octet_length(policy_snapshot_sha256)=32)
  OR(corpus<>'policies' AND policy_version IS NULL AND policy_snapshot_sha256 IS NULL));
CREATE FUNCTION secureshop_review.guard_bound_policy_rebuild_fields() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN IF NEW.policy_version IS DISTINCT FROM OLD.policy_version OR NEW.policy_snapshot_sha256 IS DISTINCT FROM OLD.policy_snapshot_sha256 THEN RAISE EXCEPTION 'policy rebuild admission is immutable' USING ERRCODE='55000'; END IF;RETURN NEW;END $$;
CREATE TRIGGER bound_policy_rebuild_fields_guard BEFORE UPDATE ON secureshop_review.bound_system_rebuild_operations FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_policy_rebuild_fields();
ALTER TABLE secureshop_review.product_target_retrieval_documents DROP CONSTRAINT product_target_retrieval_documents_source_kind_check;
ALTER TABLE secureshop_review.product_target_retrieval_documents ADD CONSTRAINT product_target_retrieval_documents_source_kind_check CHECK(source_kind IN('product','listing','review','manual','policy'));
CREATE TABLE secureshop_review.bound_system_policy_imports(
 operation_id uuid PRIMARY KEY REFERENCES secureshop_review.bound_system_rebuild_operations(operation_id),
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 policy_version bigint NOT NULL CHECK(policy_version BETWEEN 1 AND 9007199254740991),policy_snapshot_sha256 bytea NOT NULL CHECK(octet_length(policy_snapshot_sha256)=32),
 payload_json jsonb NOT NULL CHECK(jsonb_typeof(payload_json)='object' AND octet_length(payload_json::text)<=1048576),payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),
 imported_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_review.bound_system_policy_import_documents(
 operation_id uuid NOT NULL REFERENCES secureshop_review.bound_system_policy_imports(operation_id),ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 32),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 80),targets_json jsonb NOT NULL CHECK(jsonb_typeof(targets_json)='array'),
 rendered text NOT NULL CHECK(octet_length(rendered)<=65536),rendered_sha256 bytea NOT NULL CHECK(octet_length(rendered_sha256)=32),source_sha256 bytea NOT NULL CHECK(octet_length(source_sha256)=32),
 PRIMARY KEY(operation_id,ordinal),UNIQUE(operation_id,name)
);
CREATE FUNCTION secureshop_review.bound_policy_source_digest(requested_target uuid,requested_generation bigint,policy_documents jsonb)
RETURNS bytea LANGUAGE sql STABLE STRICT SET search_path=pg_catalog AS $$
 WITH desired AS (
  SELECT d.source_kind,d.source_id,d.chunk_index,d.body,d.source_sha256
  FROM secureshop_review.product_target_retrieval_documents d
  WHERE d.target_id=requested_target AND d.generation=requested_generation AND d.source_kind<>'policy'
  UNION ALL
  SELECT 'policy', (p->>'sourceId')::bigint,(p->>'chunkIndex')::integer,p->>'text',decode(p->>'sourceSha256','hex')
  FROM jsonb_array_elements(policy_documents) p
 )
 SELECT sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object('sourceKind',source_kind,'sourceId',source_id::text,
  'chunkIndex',chunk_index,'text',body,'sourceSha256',encode(source_sha256,'hex'))
  ORDER BY source_kind COLLATE "C",source_id,chunk_index),'[]'::jsonb)::text,'UTF8')) FROM desired
$$;
CREATE FUNCTION secureshop_review.guard_bound_system_policy_import() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_rebuild_operations%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'policy import is immutable' USING ERRCODE='55000'; END IF;
 SELECT * INTO op FROM secureshop_review.bound_system_rebuild_operations WHERE operation_id=NEW.operation_id FOR SHARE;
 IF NOT FOUND OR op.state NOT IN('admitted','running') OR op.corpus<>'policies' OR op.operation_mode<>'selective'
  OR op.target_id<>NEW.target_id OR op.generation<>NEW.generation OR op.policy_version<>NEW.policy_version
  OR op.policy_snapshot_sha256<>NEW.policy_snapshot_sha256 THEN RAISE EXCEPTION 'policy import admission mismatch' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION secureshop_review.guard_bound_system_policy_import_document() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE imported secureshop_review.bound_system_policy_imports%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'policy import document is immutable' USING ERRCODE='55000'; END IF;
 SELECT * INTO imported FROM secureshop_review.bound_system_policy_imports WHERE operation_id=NEW.operation_id FOR SHARE;
 IF NOT FOUND OR jsonb_array_length(NEW.targets_json)<1 OR jsonb_array_length(NEW.targets_json)>2
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(NEW.targets_json) value WHERE value NOT IN('customer','summarizer'))
  OR (SELECT count(*) FROM jsonb_array_elements_text(NEW.targets_json))<>(SELECT count(DISTINCT value) FROM jsonb_array_elements_text(NEW.targets_json) value)
  OR NEW.rendered_sha256<>sha256(convert_to(NEW.rendered,'UTF8')) THEN RAISE EXCEPTION 'policy import document mismatch' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER bound_system_policy_import_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.bound_system_policy_imports FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_system_policy_import();
CREATE TRIGGER bound_system_policy_import_document_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.bound_system_policy_import_documents FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_system_policy_import_document();
ALTER TABLE secureshop_review.product_target_embedding_revisions ADD COLUMN policy_version bigint,ADD COLUMN policy_snapshot_sha256 bytea,
 ADD CONSTRAINT product_embedding_policy_shape CHECK((policy_version IS NULL AND policy_snapshot_sha256 IS NULL) OR(policy_version BETWEEN 1 AND 9007199254740991 AND octet_length(policy_snapshot_sha256)=32));
REVOKE ALL ON TABLE secureshop_review.bound_system_policy_imports,secureshop_review.bound_system_policy_import_documents FROM PUBLIC;
GRANT SELECT,INSERT ON TABLE secureshop_review.bound_system_policy_imports,secureshop_review.bound_system_policy_import_documents TO dvaia_secureshop_review_runtime;

-- A policy revision is admitted before any target document changes. The insert
-- hook binds the generic immutable revision row to that admission without a
-- post-publication UPDATE (revision rows are immutable).
CREATE FUNCTION secureshop_review.bind_policy_embedding_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_rebuild_operations%ROWTYPE;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_rebuild_operations WHERE operation_id=NEW.revision_id;
 IF FOUND AND op.corpus='policies' THEN
  IF op.state<>'running' OR op.target_id<>NEW.target_id OR op.runtime_sha256<>NEW.runtime_fingerprint
   OR op.source_set_sha256<>NEW.source_set_digest THEN
   RAISE EXCEPTION 'policy revision admission mismatch' USING ERRCODE='55000';
  END IF;
  NEW.policy_version:=op.policy_version;NEW.policy_snapshot_sha256:=op.policy_snapshot_sha256;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER a_bind_policy_embedding_revision BEFORE INSERT ON secureshop_review.product_target_embedding_revisions
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.bind_policy_embedding_revision();

-- Replace only policy documents and publish the complete new vector set in one
-- transaction. Source triggers may remove the head while rows are replaced;
-- the saved head is restored only inside this target-locked transaction so the
-- existing publisher can enforce its exact CAS and vector validations.
CREATE FUNCTION secureshop_review.publish_bound_policy_embedding_revision(
 requested_operation uuid,requested_worker uuid,documents jsonb)
RETURNS TABLE(revision_id uuid,runtime_fingerprint bytea,source_set_digest bytea,vector_digest bytea,document_count integer,replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_rebuild_operations%ROWTYPE;
 imported secureshop_review.bound_system_policy_imports%ROWTYPE;target secureshop_review.product_targets%ROWTYPE;
 saved_head uuid;current_digest bytea;import_count integer;published record;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_rebuild_operations WHERE operation_id=requested_operation FOR UPDATE;
 IF NOT FOUND OR requested_worker IS NULL OR op.state IS DISTINCT FROM 'running' OR op.worker_token IS DISTINCT FROM requested_worker OR op.corpus IS DISTINCT FROM 'policies' OR op.operation_mode IS DISTINCT FROM 'selective'
  OR jsonb_typeof(documents) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'policy publication admission mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=op.target_id FOR UPDATE;
 IF NOT FOUND OR target.lifecycle<>'active' OR ROW(target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id)
  IS DISTINCT FROM ROW(op.launch_id,op.scenario_id,op.generation,op.original_platform_owner_id,op.original_platform_session_id) THEN
  RAISE EXCEPTION 'policy publication target mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO imported FROM secureshop_review.bound_system_policy_imports WHERE operation_id=requested_operation FOR SHARE;
 IF NOT FOUND OR imported.target_id<>op.target_id OR imported.generation<>op.generation OR imported.policy_version<>op.policy_version
  OR imported.policy_snapshot_sha256<>op.policy_snapshot_sha256 THEN RAISE EXCEPTION 'policy import mismatch' USING ERRCODE='55000'; END IF;
 SELECT count(*) INTO import_count FROM secureshop_review.bound_system_policy_import_documents WHERE operation_id=requested_operation;
 IF import_count<1 OR import_count>32 THEN RAISE EXCEPTION 'policy import empty' USING ERRCODE='22023'; END IF;
 SELECT h.revision_id INTO saved_head FROM secureshop_review.product_target_embedding_heads h WHERE h.target_id=op.target_id FOR UPDATE;
 IF saved_head IS DISTINCT FROM op.expected_head THEN RAISE EXCEPTION 'embedding head changed' USING ERRCODE='55000'; END IF;
 DELETE FROM secureshop_review.product_target_retrieval_documents WHERE target_id=op.target_id AND generation=op.generation AND source_kind='policy';
 INSERT INTO secureshop_review.product_target_retrieval_documents(target_id,generation,source_kind,source_id,chunk_index,body,embedding,source_sha256)
 SELECT op.target_id,op.generation,'policy',d.ordinal,0,d.rendered,
  ARRAY(SELECT v::text::double precision FROM jsonb_array_elements(vector.item->'embedding') v),d.source_sha256
 FROM secureshop_review.bound_system_policy_import_documents d
 JOIN LATERAL (SELECT item FROM jsonb_array_elements(documents) item
  WHERE item->>'sourceKind'='policy' AND item->>'sourceId'=d.ordinal::text AND item->>'chunkIndex'='0'
   AND item->>'sourceSha256'=encode(d.source_sha256,'hex')) vector ON true
 WHERE d.operation_id=requested_operation ORDER BY d.ordinal;
 IF (SELECT count(*) FROM secureshop_review.product_target_retrieval_documents WHERE target_id=op.target_id AND generation=op.generation AND source_kind='policy')<>import_count THEN
  RAISE EXCEPTION 'policy vector payload mismatch' USING ERRCODE='22023'; END IF;
 SELECT secureshop_review.product_embedding_source_digest(op.target_id,op.generation) INTO current_digest;
 IF current_digest<>op.source_set_sha256 THEN RAISE EXCEPTION 'policy source digest changed' USING ERRCODE='55000'; END IF;
 IF saved_head IS NOT NULL THEN INSERT INTO secureshop_review.product_target_embedding_heads(target_id,revision_id) VALUES(op.target_id,saved_head); END IF;
 SELECT * INTO published FROM secureshop_review.publish_product_embedding_revision(op.target_id,op.launch_id,op.scenario_id,op.generation,
  op.original_platform_owner_id,op.original_platform_session_id,op.operation_id,op.runtime_sha256,op.source_set_sha256,saved_head,documents);
 IF published.revision_id<>op.operation_id THEN RAISE EXCEPTION 'policy revision mismatch' USING ERRCODE='55000'; END IF;
 RETURN QUERY SELECT published.revision_id,published.runtime_fingerprint,published.source_set_digest,published.vector_digest,published.document_count,published.replayed;
END $$;

REVOKE ALL ON FUNCTION secureshop_review.bind_policy_embedding_revision(),
 secureshop_review.guard_bound_policy_rebuild_fields(),
 secureshop_review.guard_bound_system_policy_import(),secureshop_review.guard_bound_system_policy_import_document(),
 secureshop_review.bound_policy_source_digest(uuid,bigint,jsonb),
 secureshop_review.publish_bound_policy_embedding_revision(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.bound_policy_source_digest(uuid,bigint,jsonb) TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.publish_bound_policy_embedding_revision(uuid,uuid,jsonb) TO dvaia_secureshop_review_runtime;
REVOKE DELETE ON secureshop_review.product_target_retrieval_documents FROM dvaia_secureshop_review_runtime;
