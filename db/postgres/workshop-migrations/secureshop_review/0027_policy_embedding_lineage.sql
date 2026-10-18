-- Candidate: preserve immutable policy-import lineage through nonpolicy reindex.
-- No caller-supplied policy version, snapshot, or original import is accepted.
CREATE TABLE secureshop_review.policy_embedding_lineage (
 revision_id uuid PRIMARY KEY REFERENCES secureshop_review.product_target_embedding_revisions(revision_id) DEFERRABLE INITIALLY DEFERRED,
 base_revision_id uuid NOT NULL REFERENCES secureshop_review.product_target_embedding_revisions(revision_id),
 import_operation_id uuid NOT NULL REFERENCES secureshop_review.bound_system_policy_imports(operation_id)
);
CREATE TRIGGER policy_embedding_lineage_immutable BEFORE UPDATE OR DELETE ON secureshop_review.policy_embedding_lineage
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
REVOKE ALL ON secureshop_review.policy_embedding_lineage FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.policy_embedding_lineage TO dvaia_secureshop_review_runtime;

CREATE OR REPLACE FUNCTION secureshop_review.bind_policy_embedding_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_rebuild_operations%ROWTYPE;
 imported secureshop_review.bound_system_policy_imports%ROWTYPE;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_rebuild_operations WHERE operation_id=NEW.revision_id;
 IF FOUND AND op.corpus='policies' THEN
  IF op.state IS DISTINCT FROM 'running' OR op.target_id IS DISTINCT FROM NEW.target_id OR op.launch_id IS DISTINCT FROM NEW.launch_id OR op.scenario_id IS DISTINCT FROM NEW.scenario_id OR op.generation IS DISTINCT FROM NEW.generation OR op.original_platform_owner_id IS DISTINCT FROM NEW.original_platform_owner_id OR op.original_platform_session_id IS DISTINCT FROM NEW.original_platform_session_id OR op.runtime_sha256 IS DISTINCT FROM NEW.runtime_fingerprint OR op.source_set_sha256 IS DISTINCT FROM NEW.source_set_digest THEN
   RAISE EXCEPTION 'policy revision admission mismatch' USING ERRCODE='55000';
  END IF;
  NEW.policy_version:=op.policy_version;NEW.policy_snapshot_sha256:=op.policy_snapshot_sha256;
 ELSE
  SELECT i.* INTO imported FROM secureshop_review.policy_embedding_lineage l
   JOIN secureshop_review.bound_system_policy_imports i ON i.operation_id=l.import_operation_id WHERE l.revision_id=NEW.revision_id;
  IF FOUND THEN
   IF imported.target_id IS DISTINCT FROM NEW.target_id OR imported.generation IS DISTINCT FROM NEW.generation THEN RAISE EXCEPTION 'policy lineage scope mismatch' USING ERRCODE='55000'; END IF;
   NEW.policy_version:=imported.policy_version;NEW.policy_snapshot_sha256:=imported.policy_snapshot_sha256;
  ELSIF EXISTS(SELECT 1 FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=NEW.target_id AND d.generation=NEW.generation AND d.source_kind='policy') THEN
   RAISE EXCEPTION 'policy publication requires immutable lineage' USING ERRCODE='55000';
  END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION secureshop_review.publish_embedding_with_policy_lineage(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,requested_operation uuid,requested_fingerprint bytea,
 requested_source_digest bytea,requested_head uuid,documents jsonb)
RETURNS TABLE(revision_id uuid,runtime_fingerprint bytea,source_set_digest bytea,vector_digest bytea,document_count integer,replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE;base secureshop_review.product_target_embedding_revisions%ROWTYPE;
 imported secureshop_review.bound_system_policy_imports%ROWTYPE;origin uuid;head uuid;prior secureshop_review.policy_embedding_lineage%ROWTYPE;
 policy_count integer;
BEGIN
 IF requested_operation IS NULL OR jsonb_typeof(documents) IS DISTINCT FROM 'array' OR jsonb_array_length(documents)>4096 OR octet_length(documents::text)>67108864 THEN RAISE EXCEPTION 'invalid lineage publication' USING ERRCODE='22023'; END IF;
 SELECT * INTO target FROM secureshop_review.product_targets t WHERE t.target_id=requested_target FOR UPDATE;
 IF NOT FOUND OR target.lifecycle IS DISTINCT FROM 'active' OR target.launch_id IS DISTINCT FROM requested_launch OR target.scenario_id IS DISTINCT FROM requested_scenario OR target.generation IS DISTINCT FROM requested_generation OR target.original_platform_owner_id IS DISTINCT FROM requested_owner OR target.original_platform_session_id IS DISTINCT FROM requested_session THEN RAISE EXCEPTION 'policy lineage target unavailable' USING ERRCODE='55000'; END IF;
 PERFORM 1 FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=requested_target AND c.lifecycle='active' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'policy lineage source unavailable' USING ERRCODE='55000'; END IF;
 SELECT h.revision_id INTO head FROM secureshop_review.product_target_embedding_heads h WHERE h.target_id=requested_target FOR UPDATE;
 SELECT * INTO prior FROM secureshop_review.policy_embedding_lineage l WHERE l.revision_id=requested_operation;
 IF FOUND THEN
  SELECT * INTO base FROM secureshop_review.product_target_embedding_revisions r WHERE r.revision_id=prior.base_revision_id;
 ELSE
  IF EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_revisions r WHERE r.revision_id=requested_operation) THEN RAISE EXCEPTION 'policy lineage replay conflict' USING ERRCODE='55000'; END IF;
  IF head IS DISTINCT FROM requested_head THEN RAISE EXCEPTION 'embedding head changed' USING ERRCODE='55000'; END IF;
  SELECT * INTO base FROM secureshop_review.product_target_embedding_revisions r WHERE r.target_id=requested_target AND r.generation=requested_generation
   AND (head IS NULL OR r.revision_id=head) ORDER BY r.created_at DESC,r.revision_id DESC LIMIT 1;
 END IF;
 IF base.revision_id IS NULL OR base.target_id IS DISTINCT FROM requested_target OR base.launch_id IS DISTINCT FROM requested_launch OR base.scenario_id IS DISTINCT FROM requested_scenario OR base.generation IS DISTINCT FROM requested_generation OR base.original_platform_owner_id IS DISTINCT FROM requested_owner OR base.original_platform_session_id IS DISTINCT FROM requested_session OR base.runtime_fingerprint IS DISTINCT FROM requested_fingerprint OR base.policy_version IS NULL THEN RAISE EXCEPTION 'policy lineage base unavailable' USING ERRCODE='55000'; END IF;
 SELECT COALESCE((SELECT l.import_operation_id FROM secureshop_review.policy_embedding_lineage l WHERE l.revision_id=base.revision_id),base.revision_id) INTO origin;
 SELECT * INTO imported FROM secureshop_review.bound_system_policy_imports i WHERE i.operation_id=origin;
 IF NOT FOUND OR imported.target_id IS DISTINCT FROM requested_target OR imported.generation IS DISTINCT FROM requested_generation OR imported.policy_version IS DISTINCT FROM base.policy_version OR imported.policy_snapshot_sha256 IS DISTINCT FROM base.policy_snapshot_sha256 THEN RAISE EXCEPTION 'policy import lineage unavailable' USING ERRCODE='55000'; END IF;
 SELECT count(*) INTO policy_count FROM secureshop_review.bound_system_policy_import_documents i WHERE i.operation_id=origin;
 IF policy_count<1 OR policy_count>32
 OR policy_count<>(SELECT count(*) FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=requested_target AND d.generation=requested_generation AND d.source_kind='policy')
 OR policy_count<>(SELECT count(*) FROM secureshop_review.product_target_embedding_vectors v WHERE v.revision_id=base.revision_id AND v.source_kind='policy')
 OR policy_count<>(SELECT count(*) FROM jsonb_array_elements(documents) d WHERE d->>'sourceKind'='policy')
 THEN RAISE EXCEPTION 'policy lineage cardinality mismatch' USING ERRCODE='55000'; END IF;
 IF EXISTS(SELECT 1 FROM secureshop_review.bound_system_policy_import_documents i
  LEFT JOIN secureshop_review.product_target_retrieval_documents d ON d.target_id=requested_target AND d.generation=requested_generation AND d.source_kind='policy' AND d.source_id=i.ordinal AND d.chunk_index=0
  LEFT JOIN secureshop_review.product_target_embedding_vectors v ON v.revision_id=base.revision_id AND v.source_kind='policy' AND v.source_id=i.ordinal AND v.chunk_index=0
  WHERE i.operation_id=origin AND (d.source_sha256 IS DISTINCT FROM i.source_sha256 OR d.body IS DISTINCT FROM i.rendered OR v.source_sha256 IS DISTINCT FROM i.source_sha256
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(documents) x WHERE x->>'sourceKind'='policy' AND x->>'sourceId'=i.ordinal::text AND x->>'chunkIndex'='0' AND x->>'sourceSha256'=encode(i.source_sha256,'hex')
    AND ARRAY(SELECT z::text::double precision FROM jsonb_array_elements(x->'embedding') z) IS NOT DISTINCT FROM v.embedding)))
 THEN RAISE EXCEPTION 'policy lineage evidence changed' USING ERRCODE='55000'; END IF;
 IF prior.revision_id IS NULL THEN
  INSERT INTO secureshop_review.policy_embedding_lineage VALUES(requested_operation,base.revision_id,origin);
 ELSIF prior.import_operation_id IS DISTINCT FROM origin THEN RAISE EXCEPTION 'policy lineage replay conflict' USING ERRCODE='55000'; END IF;
 RETURN QUERY SELECT * FROM secureshop_review.publish_product_embedding_revision(requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,requested_operation,requested_fingerprint,requested_source_digest,requested_head,documents);
END $$;
REVOKE ALL ON FUNCTION secureshop_review.publish_embedding_with_policy_lineage(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.publish_embedding_with_policy_lineage(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb) TO dvaia_secureshop_review_runtime;
