-- CANDIDATE ONLY: not discovered by application initialization.
-- Sources are authoritative; embedding revisions/head publication remain staged.
CREATE SCHEMA workshop_rag;
CREATE TABLE workshop_rag.families(owner_id integer NOT NULL CHECK(owner_id>0),family text NOT NULL CHECK(family IN('RAG','CSRF')),PRIMARY KEY(owner_id,family));
CREATE TABLE workshop_rag.slots(owner_id integer NOT NULL,family text NOT NULL,slot text NOT NULL,
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),selection_version bigint NOT NULL DEFAULT 0 CHECK(selection_version>=0),document_id uuid,
 PRIMARY KEY(owner_id,family,slot),FOREIGN KEY(owner_id,family) REFERENCES workshop_rag.families,
 CHECK((family='RAG' AND slot='current') OR (family='CSRF' AND slot IN('clean','poison'))));
CREATE TABLE workshop_rag.documents(document_id uuid PRIMARY KEY,operation_id uuid NOT NULL UNIQUE,
 owner_id integer NOT NULL,family text NOT NULL,slot text NOT NULL,generation bigint NOT NULL,
 graph_generation bigint NOT NULL,run_id uuid NOT NULL,uploading_session_id bigint NOT NULL,
 ingestion_kind text NOT NULL CHECK(ingestion_kind IN('upload','canonical_clean','poison_upload','legacy_unverified')),
 source_sha256 text NOT NULL,source_bytes integer NOT NULL CHECK(source_bytes BETWEEN 1 AND 1048576),
 chunk_manifest_sha256 text NOT NULL,chunk_pipeline_sha256 text NOT NULL CHECK(chunk_pipeline_sha256~'^[a-f0-9]{64}$'),chunking_version text NOT NULL CHECK(chunking_version='utf8-byte-ranges-v1'),
 chunk_count integer NOT NULL CHECK(chunk_count BETWEEN 1 AND 4096),operation_sha256 text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),retired_at timestamptz,retirement_id uuid,
 CHECK((retired_at IS NULL)=(retirement_id IS NULL)),
 CHECK(source_sha256~'^[a-f0-9]{64}$' AND chunk_manifest_sha256~'^[a-f0-9]{64}$' AND operation_sha256~'^[a-f0-9]{64}$'));
CREATE TABLE workshop_rag.sources(document_id uuid PRIMARY KEY REFERENCES workshop_rag.documents,
 filename text NOT NULL CHECK(octet_length(filename) BETWEEN 1 AND 512),source_text text NOT NULL CHECK(octet_length(source_text) BETWEEN 1 AND 1048576));
CREATE TABLE workshop_rag.chunks(document_id uuid NOT NULL REFERENCES workshop_rag.documents,
 chunk_index integer NOT NULL CHECK(chunk_index>=0),start_byte integer NOT NULL,end_byte integer NOT NULL,
 body text NOT NULL,body_sha256 text NOT NULL CHECK(body_sha256~'^[a-f0-9]{64}$'),
 PRIMARY KEY(document_id,chunk_index),CHECK(start_byte>=0 AND end_byte>start_byte AND octet_length(body)=end_byte-start_byte AND octet_length(body)<=2048));
CREATE TABLE workshop_rag.cleanup_receipts(operation_id uuid PRIMARY KEY,owner_id integer NOT NULL,family text NOT NULL,
 slot text NOT NULL,authority text NOT NULL CHECK(authority IN('reset','student_deletion','document_delete')),authority_id uuid,
 graph_generation bigint,expected_generation bigint,document_count integer NOT NULL,
 manifest_sha256 text NOT NULL CHECK(manifest_sha256~'^[a-f0-9]{64}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX workshop_rag_documents_scope ON workshop_rag.documents(owner_id,family,slot,generation) WHERE retired_at IS NULL;
CREATE FUNCTION workshop_rag.immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Immutable RAG data' USING ERRCODE='55000'; END $$;
CREATE TRIGGER immutable_source BEFORE UPDATE ON workshop_rag.sources FOR EACH ROW EXECUTE FUNCTION workshop_rag.immutable();
CREATE TRIGGER immutable_chunk BEFORE UPDATE ON workshop_rag.chunks FOR EACH ROW EXECUTE FUNCTION workshop_rag.immutable();
CREATE TRIGGER immutable_cleanup BEFORE UPDATE OR DELETE ON workshop_rag.cleanup_receipts FOR EACH ROW EXECUTE FUNCTION workshop_rag.immutable();
CREATE FUNCTION workshop_rag.guard_document() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF current_user<>'dvaia_identity_migration' OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL OR NEW.retirement_id IS NULL
 OR (to_jsonb(OLD)-'retired_at'-'retirement_id') IS DISTINCT FROM (to_jsonb(NEW)-'retired_at'-'retirement_id') THEN
 RAISE EXCEPTION 'Immutable RAG manifest' USING ERRCODE='55000'; END IF;RETURN NEW;END $$;
CREATE TRIGGER immutable_manifest BEFORE UPDATE ON workshop_rag.documents FOR EACH ROW EXECUTE FUNCTION workshop_rag.guard_document();
CREATE TRIGGER retained_manifest BEFORE DELETE ON workshop_rag.documents FOR EACH ROW EXECUTE FUNCTION workshop_rag.immutable();

CREATE FUNCTION workshop_rag.assert_authority(o integer,s bigint,f text,g bigint,r uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k text;actual bigint;
BEGIN
 IF o IS NULL OR s IS NULL OR f IS NULL OR f NOT IN('RAG','CSRF') THEN RAISE EXCEPTION 'Invalid RAG scope' USING ERRCODE='22023';END IF;
 PERFORM 1 FROM identity.users u WHERE id=o AND is_active=1 AND (account_locked_until IS NULL OR account_locked_until<=clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=o) FOR SHARE OF u;
 IF NOT FOUND THEN RAISE EXCEPTION 'RAG owner unavailable' USING ERRCODE='55000';END IF;
 PERFORM 1 FROM identity.user_sessions WHERE id=s AND user_id=o AND is_active=1 AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'RAG session unavailable' USING ERRCODE='55000';END IF;
 IF g IS NOT NULL THEN
  IF r IS NOT NULL AND EXISTS(SELECT 1 FROM workshop_rag.reset_operations WHERE owner_id=o AND family=f AND state<>'completed') THEN RAISE EXCEPTION 'Reset reconciliation required' USING ERRCODE='55000';END IF;
  k='["'||f||'","'||o::text||'"]';SELECT generation INTO actual FROM graph_runtime.owners WHERE owner_key=k FOR SHARE;
  IF actual IS DISTINCT FROM g THEN RAISE EXCEPTION 'RAG graph generation stale' USING ERRCODE='55000';END IF;
  IF r IS NOT NULL THEN
   PERFORM 1 FROM graph_runtime.runs WHERE run_id=r AND owner_key=k AND generation=g AND status='running' FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'RAG admitted run unavailable' USING ERRCODE='55000';END IF;
  END IF;
 ELSIF r IS NOT NULL THEN RAISE EXCEPTION 'Run generation required' USING ERRCODE='22023';END IF;
END $$;
CREATE FUNCTION workshop_rag.lock_slot(o integer,f text,t text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE g bigint;BEGIN
 IF t IS NULL OR NOT((f='RAG' AND t='current')OR(f='CSRF' AND t IN('clean','poison'))) THEN RAISE EXCEPTION 'Invalid RAG slot' USING ERRCODE='22023';END IF;
 INSERT INTO workshop_rag.families VALUES(o,f) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM workshop_rag.families WHERE owner_id=o AND family=f FOR UPDATE;
 INSERT INTO workshop_rag.slots(owner_id,family,slot) VALUES(o,f,t) ON CONFLICT DO NOTHING;
 SELECT generation INTO g FROM workshop_rag.slots WHERE owner_id=o AND family=f AND slot=t FOR UPDATE;RETURN g;END $$;
CREATE FUNCTION workshop_rag.ingest(o integer,s bigint,f text,t text,g bigint,rg bigint,r uuid,d uuid,op uuid,kind text,filename text,source text,parts jsonb,pipeline_hash text)
RETURNS SETOF workshop_rag.documents LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old workshop_rag.documents%ROWTYPE;digest text;manifest text;item jsonb;idx integer:=0;start_at integer;end_at integer;previous integer:=-1;chunk_body text;byte_source bytea;quota record;
BEGIN
 IF g IS NULL OR rg IS NULL OR r IS NULL OR d IS NULL OR op IS NULL THEN RAISE EXCEPTION 'Complete admitted RAG operation required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,r);
 IF workshop_rag.lock_slot(o,f,t)<>rg THEN RAISE EXCEPTION 'RAG resource generation stale' USING ERRCODE='55000';END IF;
 IF pipeline_hash IS NULL OR pipeline_hash!~'^[a-f0-9]{64}$' OR source IS NULL OR octet_length(source) NOT BETWEEN 1 AND 1048576 OR filename IS NULL OR octet_length(filename) NOT BETWEEN 1 AND 512
 OR parts IS NULL OR jsonb_typeof(parts)<>'array' OR jsonb_array_length(parts) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'Invalid RAG document bounds' USING ERRCODE='22023';END IF;
 IF kind IS NULL OR NOT((f='RAG' AND kind IN('upload','legacy_unverified')) OR(f='CSRF' AND t='clean' AND kind='canonical_clean')OR(f='CSRF' AND t='poison' AND kind IN('poison_upload','legacy_unverified'))) THEN RAISE EXCEPTION 'Invalid ingestion provenance' USING ERRCODE='22023';END IF;
 byte_source=convert_to(source,'UTF8');
 manifest=encode(sha256(convert_to(parts::text,'UTF8')),'hex');
 digest=encode(sha256(convert_to(jsonb_build_array(o,f,t,g,rg,r,s,d,kind,filename,source,parts,pipeline_hash)::text,'UTF8')),'hex');
 SELECT * INTO old FROM workshop_rag.documents WHERE operation_id=op;
 IF FOUND THEN IF old.operation_sha256<>digest OR old.retired_at IS NOT NULL THEN RAISE EXCEPTION 'RAG operation replay conflict' USING ERRCODE='55000';END IF;RETURN NEXT old;RETURN;END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(parts) LOOP
  IF jsonb_typeof(item)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR NOT(item?'startByte' AND item?'endByte') THEN RAISE EXCEPTION 'Invalid chunk manifest' USING ERRCODE='22023';END IF;
  start_at=(item->>'startByte')::integer;end_at=(item->>'endByte')::integer;
  IF start_at IS NULL OR end_at IS NULL OR start_at<0 OR start_at<=previous OR end_at<=start_at OR end_at-start_at>2048 OR end_at>octet_length(source) THEN RAISE EXCEPTION 'Invalid chunk range' USING ERRCODE='22023';END IF;
  chunk_body=convert_from(substring(byte_source FROM start_at+1 FOR end_at-start_at),'UTF8');previous=start_at;idx=idx+1;
 END LOOP;
 SELECT count(*) AS docs,COALESCE(sum(source_bytes),0) AS bytes,COALESCE(sum(chunk_count),0) AS chunks INTO quota FROM workshop_rag.documents WHERE owner_id=o AND family=f AND retired_at IS NULL;
 IF quota.docs>=32 OR quota.bytes+octet_length(source)>8388608 OR quota.chunks+idx>4096 THEN RAISE EXCEPTION 'RAG owner quota exceeded' USING ERRCODE='54000';END IF;
 INSERT INTO workshop_rag.documents(document_id,operation_id,owner_id,family,slot,generation,graph_generation,run_id,uploading_session_id,ingestion_kind,source_sha256,source_bytes,chunk_manifest_sha256,chunk_pipeline_sha256,chunking_version,chunk_count,operation_sha256)
 VALUES(d,op,o,f,t,rg,g,r,s,kind,encode(sha256(byte_source),'hex'),octet_length(source),manifest,pipeline_hash,'utf8-byte-ranges-v1',idx,digest);
 INSERT INTO workshop_rag.sources VALUES(d,filename,source);idx=0;
 FOR item IN SELECT value FROM jsonb_array_elements(parts) LOOP start_at=(item->>'startByte')::integer;end_at=(item->>'endByte')::integer;chunk_body=convert_from(substring(byte_source FROM start_at+1 FOR end_at-start_at),'UTF8');
 INSERT INTO workshop_rag.chunks VALUES(d,idx,start_at,end_at,chunk_body,encode(sha256(convert_to(chunk_body,'UTF8')),'hex'));idx=idx+1;END LOOP;
 RETURN QUERY SELECT * FROM workshop_rag.documents WHERE document_id=d;
END $$;
CREATE FUNCTION workshop_rag.select_document(o integer,s bigint,f text,t text,g bigint,rg bigint,r uuid,d uuid,expected uuid,expected_version bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE current uuid;version bigint;BEGIN
 IF g IS NULL OR rg IS NULL OR r IS NULL OR d IS NULL THEN RAISE EXCEPTION 'Complete admitted selection required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,r);IF workshop_rag.lock_slot(o,f,t)<>rg THEN RAISE EXCEPTION 'RAG resource generation stale' USING ERRCODE='55000';END IF;
 SELECT document_id,selection_version INTO current,version FROM workshop_rag.slots WHERE owner_id=o AND family=f AND slot=t;
 IF current IS DISTINCT FROM expected OR version IS DISTINCT FROM expected_version THEN RAISE EXCEPTION 'RAG selection changed' USING ERRCODE='55000';END IF;
 PERFORM 1 FROM workshop_rag.documents WHERE document_id=d AND owner_id=o AND family=f AND slot=t AND generation=rg AND retired_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'RAG document unavailable' USING ERRCODE='55000';END IF;
 UPDATE workshop_rag.slots SET document_id=d,selection_version=selection_version+1 WHERE owner_id=o AND family=f AND slot=t;
END $$;
CREATE FUNCTION workshop_rag.read_slot(o integer,s bigint,f text,t text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE result jsonb;BEGIN
 PERFORM workshop_rag.assert_authority(o,s,f,NULL,NULL);
 PERFORM 1 FROM workshop_rag.families WHERE owner_id=o AND family=f FOR SHARE;
 IF NOT((f='RAG' AND t='current')OR(f='CSRF' AND t IN('clean','poison'))) OR t IS NULL THEN RAISE EXCEPTION 'Invalid slot' USING ERRCODE='22023';END IF;
 SELECT jsonb_build_object('generation',h.generation::text,'selectionVersion',h.selection_version::text,'documentId',h.document_id,'document',CASE WHEN d.document_id IS NULL THEN NULL ELSE to_jsonb(d)||jsonb_build_object('generation',d.generation::text,'graph_generation',d.graph_generation::text,'filename',b.filename,'sourceText',b.source_text,'chunks',COALESCE((SELECT jsonb_agg(to_jsonb(c)-'document_id' ORDER BY chunk_index) FROM workshop_rag.chunks c WHERE c.document_id=d.document_id),'[]'::jsonb)) END)
 INTO result FROM workshop_rag.slots h LEFT JOIN workshop_rag.documents d ON d.document_id=h.document_id AND d.retired_at IS NULL LEFT JOIN workshop_rag.sources b ON b.document_id=d.document_id WHERE h.owner_id=o AND h.family=f AND h.slot=t;
 RETURN COALESCE(result,jsonb_build_object('generation','0','selectionVersion','0','documentId',NULL,'document',NULL));END $$;
CREATE FUNCTION workshop_rag.read_document(o integer,s bigint,f text,t text,d uuid,rg bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE result jsonb;BEGIN
 PERFORM workshop_rag.assert_authority(o,s,f,NULL,NULL);
 PERFORM 1 FROM workshop_rag.families WHERE owner_id=o AND family=f FOR SHARE;
 PERFORM 1 FROM workshop_rag.slots WHERE owner_id=o AND family=f AND slot=t AND generation=rg;
 IF NOT FOUND THEN RAISE EXCEPTION 'RAG resource generation stale' USING ERRCODE='55000';END IF;
 SELECT to_jsonb(m)||jsonb_build_object('generation',m.generation::text,'graph_generation',m.graph_generation::text,'filename',b.filename,'sourceText',b.source_text,'chunks',COALESCE((SELECT jsonb_agg(to_jsonb(c)-'document_id' ORDER BY chunk_index) FROM workshop_rag.chunks c WHERE c.document_id=m.document_id),'[]'::jsonb)) INTO result
 FROM workshop_rag.documents m JOIN workshop_rag.sources b USING(document_id)
 WHERE m.document_id=d AND m.owner_id=o AND m.family=f AND m.slot=t AND m.generation=rg AND m.retired_at IS NULL;
 IF result IS NULL THEN RAISE EXCEPTION 'RAG document unavailable' USING ERRCODE='55000';END IF;RETURN result;END $$;
CREATE FUNCTION workshop_rag.erase_slot(o integer,f text,t text,op uuid,reason text,p_authority_id uuid,g bigint,rg bigint)
RETURNS SETOF workshop_rag.cleanup_receipts LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE old workshop_rag.cleanup_receipts%ROWTYPE;counted integer;digest text;actual_generation bigint;BEGIN
 actual_generation=workshop_rag.lock_slot(o,f,t);
 SELECT * INTO old FROM workshop_rag.cleanup_receipts WHERE operation_id=op;
 IF FOUND THEN IF old.owner_id<>o OR old.family<>f OR old.slot<>t OR old.authority<>reason OR old.authority_id IS DISTINCT FROM p_authority_id OR old.graph_generation IS DISTINCT FROM g OR old.expected_generation IS DISTINCT FROM rg THEN RAISE EXCEPTION 'Cleanup replay conflict' USING ERRCODE='55000';END IF;RETURN NEXT old;RETURN;END IF;
 IF actual_generation<>rg THEN RAISE EXCEPTION 'RAG resource generation stale' USING ERRCODE='55000';END IF;
 SELECT count(*),encode(sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_array(document_id,source_sha256,chunk_manifest_sha256) ORDER BY document_id),'[]'::jsonb)::text,'UTF8')),'hex') INTO counted,digest FROM workshop_rag.documents WHERE owner_id=o AND family=f AND slot=t AND retired_at IS NULL;
 INSERT INTO workshop_rag.cleanup_receipts VALUES(op,o,f,t,reason,p_authority_id,g,rg,counted,digest,clock_timestamp());
 DELETE FROM workshop_rag.embedding_heads WHERE document_id IN(SELECT document_id FROM workshop_rag.documents WHERE owner_id=o AND family=f AND slot=t AND retired_at IS NULL);
 DELETE FROM workshop_rag.embedding_vectors WHERE revision_id IN(SELECT r.revision_id FROM workshop_rag.embedding_revisions r JOIN workshop_rag.documents d USING(document_id) WHERE d.owner_id=o AND d.family=f AND d.slot=t AND d.retired_at IS NULL);
 DELETE FROM workshop_rag.chunks WHERE document_id IN(SELECT document_id FROM workshop_rag.documents WHERE owner_id=o AND family=f AND slot=t AND retired_at IS NULL);
 DELETE FROM workshop_rag.sources WHERE document_id IN(SELECT document_id FROM workshop_rag.documents WHERE owner_id=o AND family=f AND slot=t AND retired_at IS NULL);
 UPDATE workshop_rag.documents SET retired_at=clock_timestamp(),retirement_id=op WHERE owner_id=o AND family=f AND slot=t AND retired_at IS NULL;
 UPDATE workshop_rag.slots SET generation=generation+1,selection_version=selection_version+1,document_id=NULL WHERE owner_id=o AND family=f AND slot=t;
 RETURN QUERY SELECT * FROM workshop_rag.cleanup_receipts WHERE operation_id=op;END $$;
CREATE FUNCTION workshop_rag.retire_slot(o integer,s bigint,f text,t text,g bigint,rg bigint,op uuid)
RETURNS SETOF workshop_rag.cleanup_receipts LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF g IS NULL OR rg IS NULL OR op IS NULL THEN RAISE EXCEPTION 'Reset scope required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,NULL);
 IF EXISTS(SELECT 1 FROM workshop_rag.reset_operations WHERE owner_id=o AND family=f AND state<>'completed') THEN RAISE EXCEPTION 'Reset reconciliation required' USING ERRCODE='55000';END IF;
 RETURN QUERY SELECT * FROM workshop_rag.erase_slot(o,f,t,op,'reset',NULL,g,rg);END $$;
CREATE FUNCTION workshop_rag.delete_owner(o integer,job uuid,lease uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE h record;n integer:=0;BEGIN
 PERFORM 1 FROM identity.users WHERE id=o FOR UPDATE;
 PERFORM 1 FROM identity.student_deletion_jobs WHERE job_id=job AND subject_user_id=o AND state='running' AND lease_token=lease AND lease_expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Current deletion lease required' USING ERRCODE='55000';END IF;
 FOR h IN SELECT * FROM workshop_rag.slots WHERE owner_id=o ORDER BY family,slot LOOP
  IF EXISTS(SELECT 1 FROM workshop_rag.cleanup_receipts WHERE owner_id=o AND family=h.family AND slot=h.slot AND authority='student_deletion' AND authority_id=job) THEN CONTINUE;END IF;
  PERFORM workshop_rag.erase_slot(o,h.family,h.slot,gen_random_uuid(),'student_deletion',job,NULL,h.generation);n=n+1;
 END LOOP;RETURN n;END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA workshop_rag FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA workshop_rag FROM PUBLIC,dvaia_identity_runtime;
GRANT USAGE ON SCHEMA workshop_rag TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION workshop_rag.ingest(integer,bigint,text,text,bigint,bigint,uuid,uuid,uuid,text,text,text,jsonb,text),workshop_rag.select_document(integer,bigint,text,text,bigint,bigint,uuid,uuid,uuid,bigint),workshop_rag.read_slot(integer,bigint,text,text),workshop_rag.read_document(integer,bigint,text,text,uuid,bigint),workshop_rag.retire_slot(integer,bigint,text,text,bigint,bigint,uuid),workshop_rag.delete_owner(integer,uuid,uuid) TO dvaia_identity_runtime;

-- Derived revisions retain only hashes/provenance after source privacy erasure.
CREATE TABLE workshop_rag.embedding_revisions(
 revision_id uuid PRIMARY KEY,document_id uuid NOT NULL REFERENCES workshop_rag.documents,
 owner_id integer NOT NULL,family text NOT NULL,slot text NOT NULL,resource_generation bigint NOT NULL,
 graph_generation bigint NOT NULL,run_id uuid NOT NULL,platform_session_id bigint NOT NULL,
 source_sha256 text NOT NULL,chunk_manifest_sha256 text NOT NULL,chunk_pipeline_sha256 text NOT NULL,
 runtime_fingerprint text NOT NULL CHECK(runtime_fingerprint~'^[a-f0-9]{64}$'),
 expected_head uuid,vector_sha256 text NOT NULL CHECK(vector_sha256~'^[a-f0-9]{64}$'),
 operation_sha256 text NOT NULL CHECK(operation_sha256~'^[a-f0-9]{64}$'),chunk_count integer NOT NULL,
 selects_document boolean NOT NULL,expected_selection uuid,expected_selection_version bigint,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE workshop_rag.embedding_vectors(revision_id uuid NOT NULL REFERENCES workshop_rag.embedding_revisions,
 chunk_index integer NOT NULL,body_sha256 text NOT NULL,embedding double precision[] NOT NULL,
 PRIMARY KEY(revision_id,chunk_index),CHECK(array_ndims(embedding)=1 AND array_length(embedding,1)=384));
CREATE TABLE workshop_rag.embedding_heads(document_id uuid PRIMARY KEY REFERENCES workshop_rag.documents,
 revision_id uuid NOT NULL REFERENCES workshop_rag.embedding_revisions);
CREATE TRIGGER immutable_embedding_revision BEFORE UPDATE OR DELETE ON workshop_rag.embedding_revisions FOR EACH ROW EXECUTE FUNCTION workshop_rag.immutable();
CREATE TRIGGER immutable_embedding_vector BEFORE UPDATE ON workshop_rag.embedding_vectors FOR EACH ROW EXECUTE FUNCTION workshop_rag.immutable();
CREATE FUNCTION workshop_rag.embedding_snapshot(o integer,s bigint,f text,t text,g bigint,rg bigint,r uuid,d uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE doc jsonb;head uuid;BEGIN
 IF g IS NULL OR rg IS NULL OR r IS NULL THEN RAISE EXCEPTION 'Admitted snapshot required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,r);doc=workshop_rag.read_document(o,s,f,t,d,rg);
 SELECT revision_id INTO head FROM workshop_rag.embedding_heads WHERE document_id=d;
 RETURN jsonb_build_object('sourceSha256',doc->>'source_sha256','chunkManifestSha256',doc->>'chunk_manifest_sha256','chunkPipelineSha256',doc->>'chunk_pipeline_sha256','expectedHead',head);END $$;
CREATE FUNCTION workshop_rag.publish_embedding(o integer,s bigint,f text,t text,g bigint,rg bigint,r uuid,d uuid,op uuid,
 source_hash text,manifest_hash text,pipeline_hash text,runtime_hash text,expected_head uuid,vectors jsonb,
 selects boolean,expected_selection uuid,expected_version bigint)
RETURNS SETOF workshop_rag.embedding_revisions LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE doc workshop_rag.documents%ROWTYPE;old workshop_rag.embedding_revisions%ROWTYPE;head uuid;selected uuid;version bigint;v jsonb;values_array double precision[];n integer;total integer:=0;vector_hash text;operation_hash text;
BEGIN
 IF g IS NULL OR rg IS NULL OR r IS NULL OR op IS NULL OR d IS NULL OR selects IS NULL OR runtime_hash IS NULL OR runtime_hash!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Complete embedding publication required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,r);
 IF workshop_rag.lock_slot(o,f,t)<>rg THEN RAISE EXCEPTION 'RAG resource generation stale' USING ERRCODE='55000';END IF;
 SELECT * INTO doc FROM workshop_rag.documents WHERE document_id=d AND owner_id=o AND family=f AND slot=t AND generation=rg AND retired_at IS NULL;
 IF NOT FOUND OR doc.source_sha256 IS DISTINCT FROM source_hash OR doc.chunk_manifest_sha256 IS DISTINCT FROM manifest_hash OR doc.chunk_pipeline_sha256 IS DISTINCT FROM pipeline_hash THEN RAISE EXCEPTION 'Embedding source changed' USING ERRCODE='55000';END IF;
 IF vectors IS NULL OR jsonb_typeof(vectors)<>'array' OR jsonb_array_length(vectors)<>doc.chunk_count OR octet_length(vectors::text)>67108864 THEN RAISE EXCEPTION 'Complete bounded embedding vectors required' USING ERRCODE='22023';END IF;
 vector_hash=encode(sha256(convert_to(vectors::text,'UTF8')),'hex');
 operation_hash=encode(sha256(convert_to(jsonb_build_array(o,s,f,t,g,rg,r,d,source_hash,manifest_hash,pipeline_hash,runtime_hash,expected_head,vector_hash,selects,expected_selection,expected_version)::text,'UTF8')),'hex');
 SELECT revision_id INTO head FROM workshop_rag.embedding_heads WHERE document_id=d;
 SELECT document_id,selection_version INTO selected,version FROM workshop_rag.slots WHERE owner_id=o AND family=f AND slot=t;
 SELECT * INTO old FROM workshop_rag.embedding_revisions WHERE revision_id=op;
 IF FOUND THEN
  IF old.operation_sha256<>operation_hash OR head IS DISTINCT FROM old.revision_id OR (selects AND (selected IS DISTINCT FROM d OR version IS DISTINCT FROM expected_version+1)) THEN RAISE EXCEPTION 'Embedding operation replay conflict' USING ERRCODE='55000';END IF;
  RETURN NEXT old;RETURN;
 END IF;
 IF head IS DISTINCT FROM expected_head THEN RAISE EXCEPTION 'Embedding head changed' USING ERRCODE='55000';END IF;
 IF selects AND (expected_version IS NULL OR selected IS DISTINCT FROM expected_selection OR version<>expected_version) THEN RAISE EXCEPTION 'RAG selection changed' USING ERRCODE='55000';END IF;
 FOR v IN SELECT value FROM jsonb_array_elements(vectors) LOOP
  IF jsonb_typeof(v)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(v))<>3 OR NOT(v?'chunkIndex' AND v?'sourceSha256' AND v?'embedding') OR jsonb_typeof(v->'embedding')<>'array' OR jsonb_array_length(v->'embedding')<>384 THEN RAISE EXCEPTION 'Invalid chunk vector' USING ERRCODE='22023';END IF;
  n=(v->>'chunkIndex')::integer;
  IF n IS DISTINCT FROM total THEN RAISE EXCEPTION 'Ordered complete chunk vectors required' USING ERRCODE='22023';END IF;
  PERFORM 1 FROM workshop_rag.chunks WHERE document_id=d AND chunk_index=n AND body_sha256=v->>'sourceSha256';
  IF NOT FOUND THEN RAISE EXCEPTION 'Chunk source changed' USING ERRCODE='55000';END IF;
  SELECT array_agg(value::double precision ORDER BY ord) INTO values_array FROM jsonb_array_elements_text(v->'embedding') WITH ORDINALITY part(value,ord);
  IF EXISTS(SELECT 1 FROM unnest(values_array) x WHERE x IS NULL OR NOT(x>'-Infinity'::double precision AND x<'Infinity'::double precision)) OR abs((SELECT sum(x*x) FROM unnest(values_array) x)-1)>0.00001 THEN RAISE EXCEPTION 'Normalized finite384 vector required' USING ERRCODE='22023';END IF;
  total=total+1;
 END LOOP;
 IF (SELECT count(*) FROM workshop_rag.embedding_revisions WHERE document_id=d)>=8 OR
 (SELECT count(*) FROM workshop_rag.embedding_vectors v JOIN workshop_rag.embedding_revisions e USING(revision_id) WHERE e.owner_id=o AND e.family=f)+total>16384 THEN RAISE EXCEPTION 'RAG vector quota exceeded' USING ERRCODE='54000';END IF;
 INSERT INTO workshop_rag.embedding_revisions VALUES(op,d,o,f,t,rg,g,r,s,source_hash,manifest_hash,pipeline_hash,runtime_hash,expected_head,vector_hash,operation_hash,total,selects,expected_selection,expected_version,clock_timestamp());
 FOR v IN SELECT value FROM jsonb_array_elements(vectors) LOOP
  SELECT array_agg(value::double precision ORDER BY ord) INTO values_array FROM jsonb_array_elements_text(v->'embedding') WITH ORDINALITY part(value,ord);
  INSERT INTO workshop_rag.embedding_vectors VALUES(op,(v->>'chunkIndex')::integer,v->>'sourceSha256',values_array);
 END LOOP;
 INSERT INTO workshop_rag.embedding_heads VALUES(d,op) ON CONFLICT(document_id) DO UPDATE SET revision_id=EXCLUDED.revision_id;
 IF selects THEN PERFORM workshop_rag.select_document(o,s,f,t,g,rg,r,d,expected_selection,expected_version);END IF;
 RETURN QUERY SELECT * FROM workshop_rag.embedding_revisions WHERE revision_id=op;
END $$;
CREATE FUNCTION workshop_rag.read_embedding(o integer,s bigint,f text,t text,g bigint,rg bigint,r uuid,d uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE doc jsonb;result jsonb;BEGIN
 IF g IS NULL OR rg IS NULL OR r IS NULL THEN RAISE EXCEPTION 'Admitted retrieval required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,r);doc=workshop_rag.read_document(o,s,f,t,d,rg);
 SELECT to_jsonb(revision)||jsonb_build_object('resource_generation',revision.resource_generation::text,'graph_generation',revision.graph_generation::text,'vectors',
 COALESCE((SELECT jsonb_agg(jsonb_build_object('chunkIndex',v.chunk_index,'text',c.body,'sourceSha256',c.body_sha256,'embedding',v.embedding) ORDER BY v.chunk_index)
 FROM workshop_rag.embedding_vectors v JOIN workshop_rag.chunks c ON c.document_id=d AND c.chunk_index=v.chunk_index AND c.body_sha256=v.body_sha256 WHERE v.revision_id=revision.revision_id),'[]'::jsonb))
 INTO result FROM workshop_rag.embedding_heads h JOIN workshop_rag.embedding_revisions revision ON revision.revision_id=h.revision_id
 WHERE h.document_id=d AND revision.document_id=d AND revision.owner_id=o AND revision.family=f AND revision.slot=t AND revision.resource_generation=rg
 AND revision.source_sha256=doc->>'source_sha256' AND revision.chunk_manifest_sha256=doc->>'chunk_manifest_sha256' AND revision.chunk_pipeline_sha256=doc->>'chunk_pipeline_sha256';
 RETURN result;END $$;
REVOKE ALL ON workshop_rag.embedding_revisions,workshop_rag.embedding_vectors,workshop_rag.embedding_heads FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION workshop_rag.embedding_snapshot(integer,bigint,text,text,bigint,bigint,uuid,uuid),workshop_rag.publish_embedding(integer,bigint,text,text,bigint,bigint,uuid,uuid,uuid,text,text,text,text,uuid,jsonb,boolean,uuid,bigint),workshop_rag.read_embedding(integer,bigint,text,text,bigint,bigint,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_rag.embedding_snapshot(integer,bigint,text,text,bigint,bigint,uuid,uuid),workshop_rag.publish_embedding(integer,bigint,text,text,bigint,bigint,uuid,uuid,uuid,text,text,text,text,uuid,jsonb,boolean,uuid,bigint),workshop_rag.read_embedding(integer,bigint,text,text,bigint,bigint,uuid,uuid) TO dvaia_identity_runtime;

-- Successful ingestion retries observe immutable original provenance; they never select again.
CREATE FUNCTION workshop_rag.find_ingest_replay(o integer,s bigint,f text,t text,g bigint,rg bigint,r uuid,d uuid,op uuid,filename_arg text,kind_arg text,source_hash text,pipeline_hash text,parts jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE doc jsonb; original workshop_rag.documents%ROWTYPE; revision workshop_rag.embedding_revisions%ROWTYPE; selected uuid; BEGIN
 IF g IS NULL OR rg IS NULL OR r IS NULL OR d IS NULL OR op IS NULL OR g<0 OR rg<0 THEN RAISE EXCEPTION 'RAG admitted scope required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,r);
 PERFORM 1 FROM workshop_rag.families WHERE owner_id=o AND family=f FOR SHARE;
 SELECT * INTO original FROM workshop_rag.documents WHERE operation_id=op OR document_id=d;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF original.document_id<>d OR original.operation_id<>op OR original.owner_id<>o OR original.family<>f OR original.slot<>t OR original.generation<>rg OR original.retired_at IS NOT NULL THEN RAISE EXCEPTION 'RAG replay scope conflict' USING ERRCODE='55000';END IF;
 doc=workshop_rag.read_document(o,s,f,t,d,rg);
 IF doc->>'filename' IS DISTINCT FROM filename_arg OR original.ingestion_kind IS DISTINCT FROM kind_arg OR original.source_sha256 IS DISTINCT FROM source_hash OR original.chunk_pipeline_sha256 IS DISTINCT FROM pipeline_hash OR
 (SELECT jsonb_agg(jsonb_build_object('startByte',start_byte,'endByte',end_byte) ORDER BY chunk_index) FROM workshop_rag.chunks WHERE document_id=d) IS DISTINCT FROM parts THEN RAISE EXCEPTION 'RAG replay payload conflict' USING ERRCODE='55000';END IF;
 SELECT * INTO revision FROM workshop_rag.embedding_revisions WHERE document_id=d AND selects_document AND run_id=original.run_id AND platform_session_id=original.uploading_session_id ORDER BY created_at,revision_id LIMIT 1;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT document_id INTO selected FROM workshop_rag.slots WHERE owner_id=o AND family=f AND slot=t;
 RETURN jsonb_build_object('document',doc,'revision',to_jsonb(revision)||jsonb_build_object('resource_generation',revision.resource_generation::text,'graph_generation',revision.graph_generation::text),'currentlySelected',selected IS NOT DISTINCT FROM d);END $$;
REVOKE ALL ON FUNCTION workshop_rag.find_ingest_replay(integer,bigint,text,text,bigint,bigint,uuid,uuid,uuid,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_rag.find_ingest_replay(integer,bigint,text,text,bigint,bigint,uuid,uuid,uuid,text,text,text,text,jsonb) TO dvaia_identity_runtime;

-- Canonical reset intent is durable before erasure. Slot snapshots never move on retry.
CREATE TABLE workshop_rag.reset_operations(
 operation_id uuid PRIMARY KEY,owner_id integer NOT NULL,family text NOT NULL,
 actor_owner_id integer NOT NULL,actor_session_id bigint NOT NULL,
 admitted_graph_generation bigint NOT NULL,slot_snapshots jsonb NOT NULL,
 state text NOT NULL CHECK(state IN('pending','erased','completed')),
 lease_token uuid NOT NULL,lease_graph_generation bigint NOT NULL,lease_expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz,
 CHECK((state='completed')=(completed_at IS NOT NULL)));
CREATE UNIQUE INDEX workshop_rag_one_pending_reset ON workshop_rag.reset_operations(owner_id,family) WHERE state<>'completed';
REVOKE ALL ON workshop_rag.reset_operations FROM PUBLIC,dvaia_identity_runtime;
CREATE FUNCTION workshop_rag.assert_reset_actor(actor integer,actor_session bigint,target integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF actor IS NULL OR actor_session IS NULL OR target IS NULL THEN RAISE EXCEPTION 'Verified reset actor required' USING ERRCODE='22023';END IF;
 PERFORM 1 FROM identity.users u JOIN identity.user_sessions s ON s.user_id=u.id
 WHERE u.id=actor AND s.id=actor_session AND u.is_active=1 AND s.is_active=1 AND s.expires_at>clock_timestamp()
 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=actor)
 AND (actor=target OR (u.role IN('admin','super_admin') AND u.admin_level>=1 AND EXISTS(SELECT 1 FROM identity.admin_permissions p WHERE p.admin_id=actor AND p.permission_name='manage_progress' AND p.is_active=1 AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp())))) FOR SHARE OF u,s;
 IF NOT FOUND THEN RAISE EXCEPTION 'Current reset actor unavailable' USING ERRCODE='55000';END IF;
 PERFORM 1 FROM identity.users u WHERE id=target AND is_active=1
 AND (actor=target OR (role='student' AND admin_level=0))
 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=target) FOR SHARE OF u;
 IF NOT FOUND THEN RAISE EXCEPTION 'Reset target unavailable' USING ERRCODE='55000';END IF;
END $$;
CREATE FUNCTION workshop_rag.begin_reset(actor integer,actor_session bigint,o integer,f text,g bigint,op uuid,lease uuid,requested_slots jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old workshop_rag.reset_operations%ROWTYPE;actual bigint;k text;t text;snapshots jsonb:='[]'::jsonb;rg bigint;BEGIN
 IF g IS NULL OR op IS NULL OR lease IS NULL OR f IS NULL OR f NOT IN('RAG','CSRF') OR requested_slots IS NULL OR jsonb_typeof(requested_slots)<>'array' OR jsonb_array_length(requested_slots) NOT BETWEEN 1 AND 2 THEN RAISE EXCEPTION 'Complete reset admission required' USING ERRCODE='22023';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(requested_slots) x WHERE jsonb_typeof(x)<>'string') OR
 (SELECT count(*) FROM jsonb_array_elements(requested_slots))<>(SELECT count(DISTINCT value) FROM jsonb_array_elements(requested_slots)) THEN RAISE EXCEPTION 'Unique reset slots required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_reset_actor(actor,actor_session,o);
 k='["'||f||'","'||o::text||'"]';SELECT generation INTO actual FROM graph_runtime.owners WHERE owner_key=k FOR SHARE;
 IF actual IS DISTINCT FROM g THEN RAISE EXCEPTION 'Reset graph generation stale' USING ERRCODE='55000';END IF;
 -- Acquire the common family lock before reading either the journal or slots.
 FOR t IN SELECT value FROM jsonb_array_elements_text(requested_slots) ORDER BY value LOOP
  rg=workshop_rag.lock_slot(o,f,t);
  snapshots=snapshots||jsonb_build_array(jsonb_build_object('slot',t,'generation',rg::text,'operationId',md5(op::text||':'||t)::uuid));
 END LOOP;
 SELECT * INTO old FROM workshop_rag.reset_operations WHERE operation_id=op FOR UPDATE;
 IF FOUND THEN
  IF old.owner_id<>o OR old.family<>f OR old.actor_owner_id<>actor OR
   (SELECT jsonb_agg(value->>'slot' ORDER BY value->>'slot') FROM jsonb_array_elements(old.slot_snapshots)) IS DISTINCT FROM
   (SELECT jsonb_agg(value ORDER BY value) FROM jsonb_array_elements_text(requested_slots)) THEN RAISE EXCEPTION 'Reset operation replay conflict' USING ERRCODE='55000';END IF;
  IF old.state='completed' THEN RETURN to_jsonb(old);END IF;
  IF old.lease_token<>lease AND old.lease_expires_at>clock_timestamp() AND old.lease_graph_generation>=g THEN RAISE EXCEPTION 'Reset lease busy' USING ERRCODE='55000';END IF;
  UPDATE workshop_rag.reset_operations SET lease_token=lease,lease_graph_generation=g,lease_expires_at=clock_timestamp()+interval '2 minutes' WHERE operation_id=op RETURNING * INTO old;
  RETURN to_jsonb(old);
 END IF;
 IF EXISTS(SELECT 1 FROM workshop_rag.reset_operations WHERE owner_id=o AND family=f AND state<>'completed') THEN RAISE EXCEPTION 'Pending reset must be resumed with its operation ID' USING ERRCODE='55000';END IF;
 INSERT INTO workshop_rag.reset_operations(operation_id,owner_id,family,actor_owner_id,actor_session_id,admitted_graph_generation,slot_snapshots,state,lease_token,lease_graph_generation,lease_expires_at)
 VALUES(op,o,f,actor,actor_session,g,snapshots,'pending',lease,g,clock_timestamp()+interval '2 minutes') RETURNING * INTO old;
 RETURN to_jsonb(old);END $$;
CREATE FUNCTION workshop_rag.apply_reset(actor integer,actor_session bigint,o integer,f text,g bigint,op uuid,lease uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE journal workshop_rag.reset_operations%ROWTYPE;entry jsonb;actual bigint;receipts jsonb:='[]'::jsonb;item workshop_rag.cleanup_receipts%ROWTYPE;BEGIN
 PERFORM workshop_rag.assert_reset_actor(actor,actor_session,o);
 SELECT generation INTO actual FROM graph_runtime.owners WHERE owner_key='["'||f||'","'||o::text||'"]' FOR SHARE;
 IF g IS NULL OR actual IS DISTINCT FROM g THEN RAISE EXCEPTION 'Reset graph generation stale' USING ERRCODE='55000';END IF;
 PERFORM 1 FROM workshop_rag.families WHERE owner_id=o AND family=f FOR UPDATE;
 SELECT * INTO journal FROM workshop_rag.reset_operations WHERE operation_id=op FOR UPDATE;
 IF NOT FOUND OR journal.owner_id<>o OR journal.family<>f OR journal.actor_owner_id<>actor THEN RAISE EXCEPTION 'Reset journal unavailable' USING ERRCODE='55000';END IF;
 IF journal.state<>'completed' AND (journal.lease_token IS DISTINCT FROM lease OR journal.lease_graph_generation IS DISTINCT FROM g OR journal.lease_expires_at<=clock_timestamp()) THEN RAISE EXCEPTION 'Current reset lease required' USING ERRCODE='55000';END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(journal.slot_snapshots) LOOP
  IF journal.state<>'pending' THEN
   SELECT * INTO item FROM workshop_rag.cleanup_receipts WHERE operation_id=(entry->>'operationId')::uuid;
   IF NOT FOUND THEN RAISE EXCEPTION 'Reset receipt unavailable' USING ERRCODE='55000';END IF;
  ELSE
   SELECT * INTO item FROM workshop_rag.erase_slot(o,f,entry->>'slot',(entry->>'operationId')::uuid,'reset',op,g,(entry->>'generation')::bigint);
  END IF;
  receipts=receipts||jsonb_build_array(to_jsonb(item));
 END LOOP;
 IF journal.state='pending' THEN UPDATE workshop_rag.reset_operations SET state='erased' WHERE operation_id=op;END IF;
 RETURN jsonb_build_object('operationId',op,'replayed',journal.state='completed','receipts',receipts);END $$;
REVOKE ALL ON FUNCTION workshop_rag.assert_reset_actor(integer,bigint,integer),workshop_rag.begin_reset(integer,bigint,integer,text,bigint,uuid,uuid,jsonb),workshop_rag.apply_reset(integer,bigint,integer,text,bigint,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_rag.begin_reset(integer,bigint,integer,text,bigint,uuid,uuid,jsonb),workshop_rag.apply_reset(integer,bigint,integer,text,bigint,uuid,uuid) TO dvaia_identity_runtime;

CREATE FUNCTION workshop_rag.retire_document(o integer,s bigint,f text,t text,g bigint,rg bigint,d uuid,op uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE doc workshop_rag.documents%ROWTYPE;prior workshop_rag.cleanup_receipts%ROWTYPE;BEGIN
 IF g IS NULL OR rg IS NULL OR d IS NULL OR op IS NULL THEN RAISE EXCEPTION 'Complete document retirement required' USING ERRCODE='22023';END IF;
 PERFORM workshop_rag.assert_authority(o,s,f,g,NULL);
 IF EXISTS(SELECT 1 FROM workshop_rag.reset_operations WHERE owner_id=o AND family=f AND state<>'completed') THEN RAISE EXCEPTION 'Reset reconciliation required' USING ERRCODE='55000';END IF;
 IF workshop_rag.lock_slot(o,f,t)<>rg THEN RAISE EXCEPTION 'Resource generation stale' USING ERRCODE='55000';END IF;
 SELECT * INTO prior FROM workshop_rag.cleanup_receipts WHERE operation_id=op;
 IF FOUND THEN IF prior.owner_id<>o OR prior.family<>f OR prior.slot<>t OR prior.authority<>'document_delete' OR prior.authority_id<>d THEN RAISE EXCEPTION 'Retirement replay conflict' USING ERRCODE='55000';END IF;RETURN jsonb_build_object('deleted',true,'replayed',true,'operationId',op);END IF;
 SELECT * INTO doc FROM workshop_rag.documents WHERE document_id=d AND owner_id=o AND family=f AND slot=t AND generation=rg;
 IF NOT FOUND OR doc.retired_at IS NOT NULL THEN RETURN jsonb_build_object('deleted',false,'replayed',false,'operationId',op);END IF;
 INSERT INTO workshop_rag.cleanup_receipts VALUES(op,o,f,t,'document_delete',d,g,rg,1,encode(sha256(convert_to(jsonb_build_array(d,doc.source_sha256,doc.chunk_manifest_sha256)::text,'UTF8')),'hex'),clock_timestamp());
 DELETE FROM workshop_rag.embedding_heads WHERE document_id=d;
 DELETE FROM workshop_rag.embedding_vectors WHERE revision_id IN(SELECT revision_id FROM workshop_rag.embedding_revisions WHERE document_id=d);
 DELETE FROM workshop_rag.chunks WHERE document_id=d;DELETE FROM workshop_rag.sources WHERE document_id=d;
 UPDATE workshop_rag.documents SET retired_at=clock_timestamp(),retirement_id=op WHERE document_id=d;
 UPDATE workshop_rag.slots SET document_id=NULL,selection_version=selection_version+1 WHERE owner_id=o AND family=f AND slot=t AND document_id=d;
 RETURN jsonb_build_object('deleted',true,'replayed',false,'operationId',op);END $$;
REVOKE ALL ON FUNCTION workshop_rag.retire_document(integer,bigint,text,text,bigint,bigint,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_rag.retire_document(integer,bigint,text,text,bigint,bigint,uuid,uuid) TO dvaia_identity_runtime;

CREATE FUNCTION workshop_rag.finish_reset(actor integer,actor_session bigint,o integer,f text,g bigint,op uuid,lease uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE journal workshop_rag.reset_operations%ROWTYPE;actual bigint;BEGIN
 PERFORM workshop_rag.assert_reset_actor(actor,actor_session,o);
 SELECT generation INTO actual FROM graph_runtime.owners WHERE owner_key='["'||f||'","'||o::text||'"]' FOR SHARE;
 IF g IS NULL OR actual IS DISTINCT FROM g THEN RAISE EXCEPTION 'Reset graph generation stale' USING ERRCODE='55000';END IF;
 PERFORM 1 FROM workshop_rag.families WHERE owner_id=o AND family=f FOR UPDATE;
 SELECT * INTO journal FROM workshop_rag.reset_operations WHERE operation_id=op FOR UPDATE;
 IF NOT FOUND OR journal.owner_id<>o OR journal.family<>f OR journal.actor_owner_id<>actor THEN RAISE EXCEPTION 'Reset journal unavailable' USING ERRCODE='55000';END IF;
 IF journal.state='completed' THEN RETURN;END IF;
 IF journal.state<>'erased' OR journal.lease_token IS DISTINCT FROM lease OR journal.lease_graph_generation IS DISTINCT FROM g OR journal.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'Current erased reset lease required' USING ERRCODE='55000';END IF;
 UPDATE workshop_rag.reset_operations SET state='completed',completed_at=clock_timestamp() WHERE operation_id=op;
END $$;
REVOKE ALL ON FUNCTION workshop_rag.finish_reset(integer,bigint,integer,text,bigint,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_rag.finish_reset(integer,bigint,integer,text,bigint,uuid,uuid) TO dvaia_identity_runtime;
