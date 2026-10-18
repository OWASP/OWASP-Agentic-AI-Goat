-- Target-owned retrieval state. Product targets are canonical in this store;
-- retrieval rows reference that target so cleanup and retrieval share one lock.
CREATE TABLE secureshop_review.product_target_retrieval_config (
  target_id uuid PRIMARY KEY REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  embedding_model text NOT NULL CHECK (octet_length(embedding_model) BETWEEN 1 AND 256),
  embedding_dimension integer NOT NULL CHECK (embedding_dimension BETWEEN 1 AND 4096),
  lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','retired')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), retired_at timestamptz,
  CHECK ((lifecycle='retired')=(retired_at IS NOT NULL))
);
CREATE TABLE secureshop_review.product_target_retrieval_documents (
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  source_kind text NOT NULL CHECK (source_kind IN ('product','listing','review','manual')),
  source_id bigint NOT NULL CHECK (source_id BETWEEN 1 AND 9007199254740991), chunk_index integer NOT NULL CHECK (chunk_index BETWEEN 0 AND 128),
  body text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 65536), embedding double precision[] NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256)=32), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(target_id,generation,source_kind,source_id,chunk_index)
);
CREATE TABLE secureshop_review.product_target_retrieval_ingest_receipts (
  operation_id uuid PRIMARY KEY, target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  document_digest bytea NOT NULL CHECK (octet_length(document_digest)=32), document_count integer NOT NULL CHECK (document_count BETWEEN 0 AND 4096),
  replaced_count integer NOT NULL CHECK (replaced_count BETWEEN 0 AND 4096),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_review.product_target_retrieval_cleanup_receipts (
  operation_id uuid PRIMARY KEY, target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL, scenario_id uuid NOT NULL, generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1), original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  deleted_document_count integer NOT NULL CHECK (deleted_document_count BETWEEN 0 AND 4096), receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32), completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX product_target_retrieval_documents_search ON secureshop_review.product_target_retrieval_documents(target_id,generation,source_kind);
CREATE FUNCTION secureshop_review.guard_product_retrieval_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF TG_OP IN ('UPDATE','DELETE') THEN RAISE EXCEPTION 'product retrieval evidence is immutable' USING ERRCODE='55000'; END IF; RETURN NEW; END $$;
CREATE TRIGGER product_retrieval_ingest_guard BEFORE UPDATE OR DELETE ON secureshop_review.product_target_retrieval_ingest_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE TRIGGER product_retrieval_cleanup_guard BEFORE UPDATE OR DELETE ON secureshop_review.product_target_retrieval_cleanup_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE FUNCTION secureshop_review.guard_product_retrieval_document() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state text; expected_generation bigint; expected_dimension integer;
BEGIN
  IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'product retrieval documents are immutable' USING ERRCODE='55000'; END IF;
  IF TG_OP='INSERT' THEN
    SELECT t.lifecycle,t.generation,c.embedding_dimension INTO state,expected_generation,expected_dimension
      FROM secureshop_review.product_targets t JOIN secureshop_review.product_target_retrieval_config c USING(target_id)
      WHERE t.target_id=NEW.target_id FOR SHARE;
    IF state IS DISTINCT FROM 'active' OR NEW.generation<>expected_generation OR COALESCE(array_length(NEW.embedding,1),0)<>expected_dimension OR array_ndims(NEW.embedding) IS DISTINCT FROM 1 OR EXISTS (SELECT 1 FROM unnest(NEW.embedding) n WHERE n IS NULL OR n='NaN'::double precision OR abs(n)='Infinity'::double precision) OR NOT EXISTS (SELECT 1 FROM unnest(NEW.embedding) n WHERE n<>0) THEN RAISE EXCEPTION 'product retrieval target is inactive or dimension mismatched' USING ERRCODE='55000'; END IF;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER product_retrieval_document_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.product_target_retrieval_documents FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_document();
REVOKE ALL ON TABLE secureshop_review.product_target_retrieval_config,secureshop_review.product_target_retrieval_documents,secureshop_review.product_target_retrieval_ingest_receipts,secureshop_review.product_target_retrieval_cleanup_receipts FROM PUBLIC;
GRANT SELECT ON secureshop_review.product_target_retrieval_config TO dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.product_target_retrieval_documents TO dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.product_target_retrieval_ingest_receipts,secureshop_review.product_target_retrieval_cleanup_receipts TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.guard_product_retrieval_immutable(),secureshop_review.guard_product_retrieval_document() FROM PUBLIC;

-- Receipt/lifecycle writes are security-definer operations. The runtime role
-- can never forge a receipt or retire a config row by direct DML.
-- PostgreSQL's built-in sha256 avoids extension privileges and search-path resolution.
CREATE FUNCTION secureshop_review.product_retrieval_cleanup_digest(
  op uuid, target uuid, launch uuid, scenario uuid, generation bigint,
  owner_id integer, session_id integer, deleted_count integer)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
  SELECT sha256(convert_to(jsonb_build_object('version',1,'kind','product_retrieval',
    'operationId',op,'targetId',target,'launchId',launch,'scenarioId',scenario,
    'generation',generation,'platformOwnerId',owner_id,'platformSessionId',session_id,
    'deletedDocumentCount',deleted_count)::text,'UTF8'))
$$;
REVOKE ALL ON FUNCTION secureshop_review.product_retrieval_cleanup_digest(uuid,uuid,uuid,uuid,bigint,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.product_retrieval_cleanup_digest(uuid,uuid,uuid,uuid,bigint,integer,integer,integer) TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.validate_product_retrieval_documents(documents jsonb, dimension integer)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item jsonb; element jsonb;
BEGIN
  IF dimension IS NULL OR dimension NOT BETWEEN 1 AND 4096
      OR jsonb_typeof(documents) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'invalid retrieval payload' USING ERRCODE='22023';
  END IF;
  IF jsonb_array_length(documents)>4096 THEN
    RAISE EXCEPTION 'retrieval document limit exceeded' USING ERRCODE='22023';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(documents) LOOP
    IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'retrieval document must be an object' USING ERRCODE='22023';
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(item))<>5
        OR NOT (item ?& ARRAY['sourceKind','sourceId','chunkIndex','text','embedding'])
        OR jsonb_typeof(item->'sourceKind') IS DISTINCT FROM 'string'
        OR item->>'sourceKind' NOT IN ('product','manual','listing','review')
        OR jsonb_typeof(item->'sourceId') IS DISTINCT FROM 'number'
        OR (item->>'sourceId')::numeric NOT BETWEEN 1 AND 9007199254740991
        OR trunc((item->>'sourceId')::numeric)<>(item->>'sourceId')::numeric
        OR jsonb_typeof(item->'chunkIndex') IS DISTINCT FROM 'number'
        OR (item->>'chunkIndex')::numeric NOT BETWEEN 0 AND 128
        OR trunc((item->>'chunkIndex')::numeric)<>(item->>'chunkIndex')::numeric
        OR jsonb_typeof(item->'text') IS DISTINCT FROM 'string'
        OR octet_length(item->>'text') NOT BETWEEN 1 AND 65536
        OR jsonb_typeof(item->'embedding') IS DISTINCT FROM 'array' THEN
      RAISE EXCEPTION 'invalid retrieval document schema' USING ERRCODE='22023';
    END IF;
    IF jsonb_array_length(item->'embedding')<>dimension THEN
      RAISE EXCEPTION 'retrieval embedding dimension mismatch' USING ERRCODE='22023';
    END IF;
    FOR element IN SELECT value FROM jsonb_array_elements(item->'embedding') LOOP
      IF jsonb_typeof(element) IS DISTINCT FROM 'number' THEN
        RAISE EXCEPTION 'retrieval embedding must contain numbers' USING ERRCODE='22023';
      END IF;
      -- Cast also rejects finite JSON numbers outside float8's representable range.
      IF abs(element::text::double precision)='Infinity'::double precision THEN
        RAISE EXCEPTION 'retrieval embedding must be finite' USING ERRCODE='22023';
      END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(item->'embedding') v WHERE v::text::double precision<>0) THEN
      RAISE EXCEPTION 'retrieval embedding cannot be zero' USING ERRCODE='22023';
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(documents) d
      GROUP BY d->>'sourceKind',(d->>'sourceId')::bigint,(d->>'chunkIndex')::integer HAVING count(*)>1) THEN
    RAISE EXCEPTION 'duplicate retrieval document identity' USING ERRCODE='22023';
  END IF;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.validate_product_retrieval_documents(jsonb,integer) FROM PUBLIC;
CREATE FUNCTION secureshop_review.retire_product_target_retrieval(
  requested_operation uuid, requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer)
RETURNS SETOF secureshop_review.product_target_retrieval_cleanup_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; config secureshop_review.product_target_retrieval_config%ROWTYPE;
DECLARE prior secureshop_review.product_target_retrieval_cleanup_receipts%ROWTYPE; count integer; dg bytea; row secureshop_review.product_target_retrieval_cleanup_receipts%ROWTYPE;
BEGIN
  SELECT * INTO target FROM secureshop_review.product_targets t WHERE t.target_id=requested_target AND t.launch_id=requested_launch AND t.scenario_id=requested_scenario AND t.generation=requested_generation AND t.original_platform_owner_id=requested_owner AND t.original_platform_session_id=requested_session FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'retired' THEN RAISE EXCEPTION 'canonical product target must already be retired' USING ERRCODE='55000'; END IF;
  SELECT * INTO prior FROM secureshop_review.product_target_retrieval_cleanup_receipts r WHERE r.target_id=requested_target OR r.operation_id=requested_operation FOR UPDATE;
  IF prior.target_id IS NOT NULL THEN
    IF prior.target_id<>requested_target OR prior.operation_id<>requested_operation THEN RAISE EXCEPTION 'retrieval cleanup replay mismatch' USING ERRCODE='55000'; END IF;
    RETURN NEXT prior; RETURN;
  END IF;
  SELECT * INTO config FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=requested_target FOR UPDATE;
  IF config.target_id IS NULL OR config.lifecycle<>'active' THEN RAISE EXCEPTION 'retrieval config unavailable' USING ERRCODE='55000'; END IF;
  SELECT count(*)::integer INTO count FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=requested_target;
  dg := secureshop_review.product_retrieval_cleanup_digest(requested_operation,requested_target,
    requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,count);
  UPDATE secureshop_review.product_target_retrieval_config SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=requested_target;
  DELETE FROM secureshop_review.product_target_retrieval_documents WHERE target_id=requested_target;
  INSERT INTO secureshop_review.product_target_retrieval_cleanup_receipts(operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,deleted_document_count,receipt_sha256)
    VALUES(requested_operation,requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,count,dg) RETURNING * INTO row;
  RETURN NEXT row;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.retire_product_target_retrieval(uuid,uuid,uuid,uuid,bigint,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.retire_product_target_retrieval(uuid,uuid,uuid,uuid,bigint,integer,integer) TO dvaia_secureshop_review_runtime;
REVOKE UPDATE ON secureshop_review.product_target_retrieval_config FROM dvaia_secureshop_review_runtime;
REVOKE INSERT ON secureshop_review.product_target_retrieval_ingest_receipts,secureshop_review.product_target_retrieval_cleanup_receipts FROM dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.provision_product_retrieval(
  requested_target uuid, requested_launch uuid, requested_scenario uuid, requested_generation bigint, requested_owner integer, requested_session integer, requested_model text, requested_dimension integer, requested_documents jsonb)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; config secureshop_review.product_target_retrieval_config%ROWTYPE; item jsonb; count integer:=0; embedding double precision[];
BEGIN
  SELECT * INTO target FROM secureshop_review.product_targets t WHERE t.target_id=requested_target AND t.launch_id=requested_launch AND t.scenario_id=requested_scenario AND t.generation=requested_generation AND t.original_platform_owner_id=requested_owner AND t.original_platform_session_id=requested_session FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'active' OR requested_model IS NULL OR octet_length(requested_model) NOT BETWEEN 1 AND 256 THEN RAISE EXCEPTION 'retrieval provision target invalid' USING ERRCODE='55000'; END IF;
  PERFORM secureshop_review.validate_product_retrieval_documents(requested_documents,requested_dimension);
  SELECT * INTO config FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=requested_target FOR SHARE;
  IF config.target_id IS NOT NULL THEN
    IF config.lifecycle<>'active' OR config.embedding_model<>requested_model OR config.embedding_dimension<>requested_dimension THEN RAISE EXCEPTION 'retrieval provision config mismatch' USING ERRCODE='55000'; END IF;
    SELECT count(*)::integer INTO count FROM secureshop_review.product_target_retrieval_documents WHERE target_id=requested_target AND generation=requested_generation;
    RETURN count;
  END IF;
  INSERT INTO secureshop_review.product_target_retrieval_config(target_id,embedding_model,embedding_dimension) VALUES(requested_target,requested_model,requested_dimension);
  FOR item IN SELECT value FROM jsonb_array_elements(requested_documents) LOOP
    IF jsonb_typeof(item)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>5 OR NOT (item ? 'sourceKind' AND item ? 'sourceId' AND item ? 'chunkIndex' AND item ? 'text' AND item ? 'embedding') THEN RAISE EXCEPTION 'retrieval document schema invalid' USING ERRCODE='22023'; END IF;
    embedding := ARRAY(SELECT jsonb_array_elements_text(item->'embedding')::double precision);
    INSERT INTO secureshop_review.product_target_retrieval_documents(target_id,generation,source_kind,source_id,chunk_index,body,embedding,source_sha256)
      VALUES(requested_target,requested_generation,item->>'sourceKind',(item->>'sourceId')::bigint,COALESCE((item->>'chunkIndex')::integer,0),item->>'text',embedding,sha256(convert_to(item::text,'UTF8')));
    count:=count+1;
  END LOOP; RETURN count;
END $$;
CREATE FUNCTION secureshop_review.replace_product_retrieval(
  requested_target uuid, requested_launch uuid, requested_scenario uuid, requested_generation bigint, requested_owner integer, requested_session integer, requested_operation uuid, requested_documents jsonb)
RETURNS TABLE(replayed boolean, replaced_count integer, document_count integer, document_digest bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; item jsonb; embedding double precision[]; dg bytea; prior secureshop_review.product_target_retrieval_ingest_receipts%ROWTYPE; old integer:=0; n integer:=0; dimension integer;
BEGIN
  SELECT t.* INTO target FROM secureshop_review.product_targets t JOIN secureshop_review.product_target_retrieval_config c USING(target_id) WHERE t.target_id=requested_target AND t.launch_id=requested_launch AND t.scenario_id=requested_scenario AND t.generation=requested_generation AND t.original_platform_owner_id=requested_owner AND t.original_platform_session_id=requested_session AND t.lifecycle='active' AND c.lifecycle='active' FOR UPDATE;
  IF target.target_id IS NULL OR requested_operation IS NULL THEN RAISE EXCEPTION 'retrieval replacement target invalid' USING ERRCODE='55000'; END IF;
  SELECT c.embedding_dimension INTO dimension FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=requested_target;
  PERFORM secureshop_review.validate_product_retrieval_documents(requested_documents,dimension);
  dg:=sha256(convert_to(requested_documents::text,'UTF8')); SELECT * INTO prior FROM secureshop_review.product_target_retrieval_ingest_receipts WHERE operation_id=requested_operation FOR UPDATE;
  IF prior.operation_id IS NOT NULL THEN IF prior.target_id<>requested_target OR prior.document_digest<>dg THEN RAISE EXCEPTION 'retrieval replay mismatch' USING ERRCODE='55000'; END IF; RETURN QUERY SELECT true,prior.replaced_count,prior.document_count,prior.document_digest; RETURN; END IF;
  SELECT count(*)::integer INTO old FROM secureshop_review.product_target_retrieval_documents WHERE target_id=requested_target AND generation=requested_generation;
  DELETE FROM secureshop_review.product_target_retrieval_documents WHERE target_id=requested_target AND generation=requested_generation;
  FOR item IN SELECT value FROM jsonb_array_elements(requested_documents) LOOP
    IF jsonb_typeof(item)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>5 OR NOT (item ? 'sourceKind' AND item ? 'sourceId' AND item ? 'chunkIndex' AND item ? 'text' AND item ? 'embedding') THEN RAISE EXCEPTION 'retrieval document schema invalid' USING ERRCODE='22023'; END IF;
    embedding:=ARRAY(SELECT jsonb_array_elements_text(item->'embedding')::double precision);
    INSERT INTO secureshop_review.product_target_retrieval_documents(target_id,generation,source_kind,source_id,chunk_index,body,embedding,source_sha256) VALUES(requested_target,requested_generation,item->>'sourceKind',(item->>'sourceId')::bigint,COALESCE((item->>'chunkIndex')::integer,0),item->>'text',embedding,sha256(convert_to(item::text,'UTF8'))); n:=n+1;
  END LOOP;
  INSERT INTO secureshop_review.product_target_retrieval_ingest_receipts(operation_id,target_id,document_digest,document_count,replaced_count) VALUES(requested_operation,requested_target,dg,n,old);
  RETURN QUERY SELECT false,old,n,dg;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.provision_product_retrieval(uuid,uuid,uuid,bigint,integer,integer,text,integer,jsonb),secureshop_review.replace_product_retrieval(uuid,uuid,uuid,bigint,integer,integer,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.provision_product_retrieval(uuid,uuid,uuid,bigint,integer,integer,text,integer,jsonb),secureshop_review.replace_product_retrieval(uuid,uuid,uuid,bigint,integer,integer,uuid,jsonb) TO dvaia_secureshop_review_runtime;
REVOKE INSERT,DELETE ON secureshop_review.product_target_retrieval_documents FROM dvaia_secureshop_review_runtime;
REVOKE INSERT,UPDATE,DELETE ON secureshop_review.product_target_retrieval_config FROM dvaia_secureshop_review_runtime;
