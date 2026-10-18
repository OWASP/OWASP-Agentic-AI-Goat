-- Retiring the canonical target erases derived vectors atomically. Historical
-- revision digests and a bounded metadata-only cleanup receipt remain immutable.
CREATE TABLE secureshop_review.product_target_embedding_cleanup_receipts (
 target_id uuid PRIMARY KEY REFERENCES secureshop_review.product_targets(target_id),
 launch_id uuid NOT NULL,scenario_id uuid NOT NULL,generation bigint NOT NULL,
 original_platform_owner_id integer NOT NULL,original_platform_session_id integer NOT NULL,
 revision_count integer NOT NULL CHECK(revision_count>=0),
 deleted_vector_count integer NOT NULL CHECK(deleted_vector_count>=0),
 revision_manifest_sha256 bytea NOT NULL CHECK(octet_length(revision_manifest_sha256)=32),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER embedding_cleanup_receipt_immutable BEFORE UPDATE OR DELETE ON secureshop_review.product_target_embedding_cleanup_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE FUNCTION secureshop_review.guard_embedding_vector_privacy_cleanup()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF TG_OP='DELETE' AND current_user='dvaia_secureshop_review_migration' AND EXISTS(
  SELECT 1 FROM secureshop_review.product_target_embedding_revisions r
  JOIN secureshop_review.product_targets t USING(target_id)
  JOIN secureshop_review.product_target_embedding_cleanup_receipts c USING(target_id)
  WHERE r.revision_id=OLD.revision_id AND t.lifecycle='retired'
   AND c.launch_id=t.launch_id AND c.scenario_id=t.scenario_id AND c.generation=t.generation
   AND c.original_platform_owner_id=t.original_platform_owner_id
   AND c.original_platform_session_id=t.original_platform_session_id
 ) THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'embedding vectors are immutable outside canonical retirement' USING ERRCODE='55000';
END $$;
DROP TRIGGER embedding_vectors_immutable ON secureshop_review.product_target_embedding_vectors;
CREATE TRIGGER embedding_vectors_immutable BEFORE UPDATE OR DELETE ON secureshop_review.product_target_embedding_vectors
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_embedding_vector_privacy_cleanup();
REVOKE ALL ON FUNCTION secureshop_review.guard_embedding_vector_privacy_cleanup() FROM PUBLIC;
CREATE FUNCTION secureshop_review.cleanup_retired_product_embeddings(requested_target uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; revisions integer; vectors integer; manifest bytea; receipt bytea;
BEGIN
 SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=requested_target FOR UPDATE;
 IF NOT FOUND OR target.lifecycle<>'retired' THEN RAISE EXCEPTION 'retired embedding target required' USING ERRCODE='55000'; END IF;
 IF EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_cleanup_receipts WHERE target_id=requested_target) THEN
  IF EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_vectors v JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id) WHERE r.target_id=requested_target)
  OR EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_heads WHERE target_id=requested_target) THEN
   RAISE EXCEPTION 'retired embedding cleanup conflicts' USING ERRCODE='55000'; END IF;
  RETURN;
 END IF;
 SELECT count(*),sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object('revisionId',r.revision_id,
   'runtimeFingerprint',encode(r.runtime_fingerprint,'hex'),'sourceSetDigest',encode(r.source_set_digest,'hex'),
   'vectorDigest',encode(r.vector_digest,'hex'),'documentCount',r.document_count) ORDER BY r.revision_id),'[]'::jsonb)::text,'UTF8'))
 INTO revisions,manifest FROM secureshop_review.product_target_embedding_revisions r WHERE r.target_id=requested_target;
 SELECT count(*) INTO vectors FROM secureshop_review.product_target_embedding_vectors v JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id) WHERE r.target_id=requested_target;
 receipt:=sha256(convert_to(jsonb_build_object('version',1,'targetId',requested_target,'launchId',target.launch_id,
  'scenarioId',target.scenario_id,'generation',target.generation,'platformOwnerId',target.original_platform_owner_id,
  'platformSessionId',target.original_platform_session_id,'revisionCount',revisions,'deletedVectorCount',vectors,
  'revisionManifestSha256',encode(manifest,'hex'))::text,'UTF8'));
 INSERT INTO secureshop_review.product_target_embedding_cleanup_receipts(target_id,launch_id,scenario_id,generation,
  original_platform_owner_id,original_platform_session_id,revision_count,deleted_vector_count,revision_manifest_sha256,receipt_sha256)
 VALUES(requested_target,target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,
  target.original_platform_session_id,revisions,vectors,manifest,receipt);
 DELETE FROM secureshop_review.product_target_embedding_heads WHERE target_id=requested_target;
 DELETE FROM secureshop_review.product_target_embedding_vectors v USING secureshop_review.product_target_embedding_revisions r
  WHERE r.revision_id=v.revision_id AND r.target_id=requested_target;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.cleanup_retired_product_embeddings(uuid) FROM PUBLIC,dvaia_secureshop_review_runtime;
CREATE FUNCTION secureshop_review.cleanup_embeddings_on_target_retirement()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF NEW.lifecycle='retired' THEN PERFORM secureshop_review.cleanup_retired_product_embeddings(NEW.target_id); END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.cleanup_embeddings_on_target_retirement() FROM PUBLIC;
CREATE TRIGGER product_embedding_privacy_retirement AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.cleanup_embeddings_on_target_retirement();
REVOKE ALL ON TABLE secureshop_review.product_target_embedding_cleanup_receipts FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON TABLE secureshop_review.product_target_embedding_cleanup_receipts TO dvaia_secureshop_review_runtime;
-- An installation may already contain retired0014 revisions. Never resurrect
-- their sources: apply the same constrained erasure to those tombstoned scopes.
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT target_id FROM secureshop_review.product_targets WHERE lifecycle='retired' ORDER BY target_id LOOP
  PERFORM secureshop_review.cleanup_retired_product_embeddings(item.target_id);
 END LOOP;
END $$;
