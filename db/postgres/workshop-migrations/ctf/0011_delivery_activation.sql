CREATE TABLE ctf.delivery_activations (
 activation_id uuid PRIMARY KEY,identity_store_id uuid NOT NULL,ctf_store_id uuid NOT NULL,
 bootstrap_operation_id uuid NOT NULL,source_revision bigint NOT NULL CHECK(source_revision>=0),
 manifest_sha256 text NOT NULL CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$'),protocol_version integer NOT NULL CHECK(protocol_version=1),
 authority_sha256 text NOT NULL CHECK(authority_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TRIGGER ctf_delivery_activation_immutable BEFORE UPDATE OR DELETE ON ctf.delivery_activations
 FOR EACH ROW EXECUTE FUNCTION ctf.reject_projection_receipt_mutation();
CREATE TABLE ctf.delivery_control(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),activation_id uuid REFERENCES ctf.delivery_activations(activation_id));
INSERT INTO ctf.delivery_control(singleton) VALUES(true);
REVOKE ALL ON ctf.delivery_activations,ctf.delivery_control FROM PUBLIC,dvaia_ctf_runtime;
GRANT SELECT ON ctf.delivery_activations,ctf.delivery_control TO dvaia_ctf_runtime;
CREATE FUNCTION ctf.delivery_checkpoint_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM ctf.delivery_control d JOIN ctf.delivery_activations a USING(activation_id) CROSS JOIN ctf.bootstrap_control b
 WHERE d.singleton AND b.singleton AND b.state='prepared' AND a.protocol_version=1 AND a.ctf_store_id=b.store_id
 AND a.identity_store_id=b.identity_store_id AND a.bootstrap_operation_id=b.operation_id AND a.source_revision=b.revision AND a.manifest_sha256=b.manifest_sha256)
$$;
REVOKE ALL ON FUNCTION ctf.delivery_checkpoint_ready() FROM PUBLIC,dvaia_ctf_runtime;
CREATE OR REPLACE FUNCTION ctf.guard_bootstrap_source() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s text;
BEGIN
 PERFORM pg_advisory_xact_lock(1886610804,44);
 SELECT state INTO s FROM ctf.bootstrap_control WHERE singleton FOR UPDATE;
 IF session_user='dvaia_ctf_delivery' THEN
  IF NOT ctf.delivery_checkpoint_ready() THEN RAISE EXCEPTION 'CTF delivery checkpoint unavailable' USING ERRCODE='55000';END IF;
  -- Ordered delivery changes live state, not the historical bootstrap snapshot.
  RETURN NULL;
 END IF;
 IF s IS DISTINCT FROM 'open' AND session_user<>'dvaia_ctf_migration' THEN RAISE EXCEPTION 'CTF bootstrap writer fence' USING ERRCODE='55000';END IF;
 UPDATE ctf.delivery_control SET activation_id=NULL WHERE singleton;
 UPDATE ctf.bootstrap_control SET revision=revision+1,state=CASE WHEN state='prepared' THEN 'fenced' ELSE state END,manifest_sha256=NULL WHERE singleton;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION ctf.guard_bootstrap_source() FROM PUBLIC,dvaia_ctf_runtime;
-- Migration-only bounded pages: history size does not require one large JSON value.
CREATE TABLE ctf.delivery_scope_transfer(activation_id uuid PRIMARY KEY,next_page integer NOT NULL DEFAULT 0 CHECK(next_page>=0),last_scope text,chain_sha256 text NOT NULL DEFAULT repeat('0',64) CHECK(chain_sha256 ~ '^[a-f0-9]{64}$'));
CREATE TABLE ctf.delivery_scope_pages(activation_id uuid NOT NULL REFERENCES ctf.delivery_scope_transfer,page_number integer NOT NULL CHECK(page_number>=0),canonical_rows text NOT NULL CHECK(octet_length(canonical_rows)<=262144),page_sha256 text NOT NULL CHECK(page_sha256=encode(sha256(convert_to(canonical_rows,'UTF8')),'hex')),chain_sha256 text NOT NULL CHECK(chain_sha256 ~ '^[a-f0-9]{64}$'),PRIMARY KEY(activation_id,page_number));
CREATE TABLE ctf.delivery_scope_rows(activation_id uuid NOT NULL REFERENCES ctf.delivery_scope_transfer,scope_key text NOT NULL CHECK(scope_key='global' OR scope_key ~ '^(stage|owner):[1-9][0-9]*$'),revision bigint NOT NULL CHECK(revision>=0),owner_generation bigint CHECK(owner_generation>=0),PRIMARY KEY(activation_id,scope_key),CHECK((scope_key LIKE 'owner:%')=(owner_generation IS NOT NULL)));
CREATE TRIGGER ctf_scope_page_immutable BEFORE UPDATE OR DELETE ON ctf.delivery_scope_pages FOR EACH ROW EXECUTE FUNCTION ctf.reject_projection_receipt_mutation();
CREATE TRIGGER ctf_scope_row_immutable BEFORE UPDATE OR DELETE ON ctf.delivery_scope_rows FOR EACH ROW EXECUTE FUNCTION ctf.reject_projection_receipt_mutation();
REVOKE ALL ON ctf.delivery_scope_transfer,ctf.delivery_scope_pages,ctf.delivery_scope_rows FROM PUBLIC,dvaia_ctf_runtime;
CREATE FUNCTION ctf.stage_ctf_delivery_scopes(p_activation uuid,p_page integer,p_rows text,p_hash text) RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE t ctf.delivery_scope_transfer%ROWTYPE;sc jsonb;last_key text;prior text;chain text;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 IF p_activation IS NULL OR p_page IS NULL OR p_page<0 OR p_rows IS NULL OR octet_length(p_rows)>262144 OR NOT(p_rows IS JSON ARRAY WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_rows,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF activation page invalid';END IF;
 IF jsonb_array_length(p_rows::jsonb) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'CTF activation page size invalid';END IF;
 INSERT INTO ctf.delivery_scope_transfer(activation_id) VALUES(p_activation) ON CONFLICT DO NOTHING;
 SELECT * INTO t FROM ctf.delivery_scope_transfer WHERE activation_id=p_activation FOR UPDATE;
 SELECT canonical_rows,chain_sha256 INTO prior,chain FROM ctf.delivery_scope_pages WHERE activation_id=p_activation AND page_number=p_page;
 IF FOUND THEN IF prior IS DISTINCT FROM p_rows THEN RAISE EXCEPTION 'CTF activation page replay conflict';END IF;RETURN chain;END IF;
 IF p_page<>t.next_page OR EXISTS(SELECT 1 FROM ctf.delivery_activations WHERE activation_id=p_activation) THEN RAISE EXCEPTION 'CTF activation page order invalid';END IF;
 last_key:=t.last_scope;
 FOR sc IN SELECT value FROM jsonb_array_elements(p_rows::jsonb) LOOP
  IF NOT ctf.ctf_json_matches(sc,'{"type":"object","properties":{"scope_key":{"type":"string","bytes":64,"pattern":"^(global|(stage|owner):[1-9][0-9]*)$"},"revision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"owner_generation":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807","nullable":true}},"optional":false}'::jsonb)
  OR ((sc->>'scope_key' LIKE 'owner:%') IS DISTINCT FROM (sc->>'owner_generation' IS NOT NULL)) OR (last_key IS NOT NULL AND (sc->>'scope_key') COLLATE "C"<=last_key COLLATE "C") THEN RAISE EXCEPTION 'CTF activation scope invalid';END IF;
  INSERT INTO ctf.delivery_scope_rows VALUES(p_activation,sc->>'scope_key',(sc->>'revision')::bigint,(sc->>'owner_generation')::bigint);
  last_key:=sc->>'scope_key';
 END LOOP;
 chain:=encode(sha256(convert_to(t.chain_sha256||p_hash,'UTF8')),'hex');
 INSERT INTO ctf.delivery_scope_pages VALUES(p_activation,p_page,p_rows,p_hash,chain);
 UPDATE ctf.delivery_scope_transfer SET next_page=next_page+1,last_scope=last_key,chain_sha256=chain WHERE activation_id=p_activation;
 RETURN chain;
END $$;
REVOKE ALL ON FUNCTION ctf.stage_ctf_delivery_scopes(uuid,integer,text,text) FROM PUBLIC,dvaia_ctf_runtime;
CREATE FUNCTION ctf.activate_delivery(p_activation uuid,p_identity uuid,p_ctf uuid,p_bootstrap uuid,p_revision bigint,p_manifest text,p_authority_hash text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE b ctf.bootstrap_control%ROWTYPE;tab text;seq text;sc jsonb;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 PERFORM pg_advisory_xact_lock(1886610804,44);
 SELECT * INTO b FROM ctf.bootstrap_control WHERE singleton FOR UPDATE;
 IF p_activation IS NULL OR b.state IS DISTINCT FROM 'prepared' OR b.store_id IS DISTINCT FROM p_ctf OR b.identity_store_id IS DISTINCT FROM p_identity
 OR b.operation_id IS DISTINCT FROM p_bootstrap OR b.revision IS DISTINCT FROM p_revision OR b.manifest_sha256 IS DISTINCT FROM p_manifest
 OR NOT EXISTS(SELECT 1 FROM ctf.projection_cursor WHERE singleton AND applied_sequence=0 AND last_operation_id IS NULL)
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='dvaia_ctf_delivery' AND rolcanlogin AND NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member OR r.oid=m.roleid WHERE r.rolname='dvaia_ctf_delivery') THEN RAISE EXCEPTION 'CTF activation unavailable';END IF;
 PERFORM 1 FROM ctf.delivery_scope_transfer WHERE activation_id=p_activation FOR SHARE;
 IF NOT EXISTS(SELECT 1 FROM ctf.delivery_scope_transfer WHERE activation_id=p_activation AND next_page>0 AND chain_sha256=p_authority_hash)
 OR EXISTS(WITH expected(k) AS (SELECT 'global' UNION SELECT 'stage:'||id FROM ctf.ctf_stages UNION SELECT 'owner:'||user_id FROM ctf.ctf_participants UNION SELECT 'owner:'||user_id FROM ctf.ctf_bans),provided(k) AS(SELECT scope_key FROM ctf.delivery_scope_rows WHERE activation_id=p_activation) (SELECT k FROM expected EXCEPT SELECT k FROM provided) UNION ALL (SELECT k FROM provided EXCEPT SELECT k FROM expected))
 OR EXISTS(SELECT 1 FROM ctf.projection_receipts) THEN RAISE EXCEPTION 'CTF activation scope mismatch';END IF;
 INSERT INTO ctf.delivery_activations VALUES(p_activation,p_identity,p_ctf,p_bootstrap,p_revision,p_manifest,1,p_authority_hash) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM ctf.delivery_activations WHERE activation_id=p_activation AND identity_store_id=p_identity AND ctf_store_id=p_ctf AND bootstrap_operation_id=p_bootstrap AND source_revision=p_revision AND manifest_sha256=p_manifest AND protocol_version=1 AND authority_sha256=p_authority_hash) THEN RAISE EXCEPTION 'CTF activation conflict';END IF;
 INSERT INTO ctf.projection_scopes(scope_key,revision,owner_generation,applied_operation_id) SELECT scope_key,revision,owner_generation,p_bootstrap FROM ctf.delivery_scope_rows WHERE activation_id=p_activation ON CONFLICT DO NOTHING;
 IF EXISTS(SELECT 1 FROM ctf.projection_scopes s FULL JOIN (SELECT * FROM ctf.delivery_scope_rows WHERE activation_id=p_activation) r USING(scope_key) WHERE s.scope_key IS NULL OR r.scope_key IS NULL OR s.revision IS DISTINCT FROM r.revision OR s.owner_generation IS DISTINCT FROM r.owner_generation OR s.applied_operation_id IS DISTINCT FROM p_bootstrap) THEN RAISE EXCEPTION 'CTF activation scope conflict';END IF;
 UPDATE ctf.projection_cursor SET initialized=true WHERE singleton;
 GRANT USAGE ON SCHEMA ctf TO dvaia_ctf_delivery;
 FOREACH tab IN ARRAY ARRAY['ctf_config','ctf_stages','ctf_participants','ctf_progress','ctf_attempts','ctf_leaderboard','ctf_events','ctf_sessions','ctf_technique_blocklist','ctf_payload_blocklist','ctf_bans','ctf_judgments','stage_default_fields'] LOOP
  EXECUTE format('REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON ctf.%I FROM dvaia_ctf_runtime',tab);
  EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON ctf.%I TO dvaia_ctf_delivery',tab);
  seq:=NULL;
  IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('ctf.'||tab) AND attname='id' AND NOT attisdropped) THEN seq:=pg_get_serial_sequence('ctf.'||tab,'id');END IF;
  IF seq IS NOT NULL THEN EXECUTE format('REVOKE USAGE ON SEQUENCE %s FROM dvaia_ctf_runtime',seq);EXECUTE format('GRANT USAGE,SELECT ON SEQUENCE %s TO dvaia_ctf_delivery',seq);END IF;
 END LOOP;
 REVOKE UPDATE(applied_sequence,last_operation_id) ON ctf.projection_cursor FROM dvaia_ctf_runtime;
 REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON ctf.projection_cursor,ctf.projection_scopes,ctf.projection_receipts FROM dvaia_ctf_runtime;
 GRANT SELECT ON ctf.bootstrap_control,ctf.delivery_control,ctf.delivery_activations,ctf.import_provenance TO dvaia_ctf_delivery;
 GRANT SELECT,UPDATE ON ctf.projection_cursor TO dvaia_ctf_delivery;
 GRANT SELECT,INSERT,UPDATE ON ctf.projection_scopes TO dvaia_ctf_delivery;
 GRANT SELECT,INSERT ON ctf.projection_receipts TO dvaia_ctf_delivery;
 REVOKE EXECUTE ON FUNCTION ctf.mark_stage_default_fields_custom(integer,text[]),ctf.refresh_authorized_leaderboard(timestamptz) FROM dvaia_ctf_runtime;
 GRANT EXECUTE ON FUNCTION ctf.mark_stage_default_fields_custom(integer,text[]),ctf.refresh_authorized_leaderboard(timestamptz),ctf.delivery_checkpoint_ready(),ctf.valid_projection_result(text),ctf.ctf_json_matches(jsonb,jsonb),ctf.ctf_result_matches(jsonb),ctf.ctf_decision_receipt_matches(jsonb),ctf.ctf_deletion_receipt_matches(jsonb) TO dvaia_ctf_delivery;
 UPDATE ctf.delivery_control SET activation_id=p_activation WHERE singleton;
END $$;
REVOKE ALL ON FUNCTION ctf.activate_delivery(uuid,uuid,uuid,uuid,bigint,text,text) FROM PUBLIC,dvaia_ctf_runtime;

CREATE FUNCTION ctf.resume_delivery(p_activation uuid,p_transfer uuid,p_authority_hash text,p_sequence bigint,p_operation uuid,p_command_hash text,p_result_hash text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE a ctf.delivery_activations%ROWTYPE;b ctf.bootstrap_control%ROWTYPE;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 PERFORM pg_advisory_xact_lock(1886610804,44);
 SELECT * INTO b FROM ctf.bootstrap_control WHERE singleton FOR UPDATE;
 SELECT * INTO a FROM ctf.delivery_activations WHERE activation_id=p_activation;
 IF a.activation_id IS NULL OR b.state IS DISTINCT FROM 'prepared' OR b.store_id IS DISTINCT FROM a.ctf_store_id OR b.identity_store_id IS DISTINCT FROM a.identity_store_id OR b.operation_id IS DISTINCT FROM a.bootstrap_operation_id OR b.revision IS DISTINCT FROM a.source_revision OR b.manifest_sha256 IS DISTINCT FROM a.manifest_sha256 THEN RAISE EXCEPTION 'CTF resume checkpoint invalid';END IF;
 PERFORM 1 FROM ctf.projection_cursor WHERE singleton FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM ctf.projection_cursor WHERE singleton AND initialized AND applied_sequence=p_sequence AND last_operation_id IS NOT DISTINCT FROM p_operation) THEN RAISE EXCEPTION 'CTF resume cursor invalid';END IF;
 IF p_sequence=0 THEN
  IF p_operation IS NOT NULL OR p_command_hash IS NOT NULL OR p_result_hash IS NOT NULL THEN RAISE EXCEPTION 'CTF resume head invalid';END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM ctf.projection_receipts WHERE sequence=p_sequence AND operation_id=p_operation AND command_hash=p_command_hash AND result_hash=p_result_hash) THEN RAISE EXCEPTION 'CTF resume head invalid';END IF;
 PERFORM 1 FROM ctf.delivery_scope_transfer WHERE activation_id=p_transfer FOR SHARE;
 IF NOT EXISTS(SELECT 1 FROM ctf.delivery_scope_transfer WHERE activation_id=p_transfer AND next_page>0 AND chain_sha256=p_authority_hash)
 OR EXISTS(SELECT 1 FROM ctf.projection_scopes s FULL JOIN (SELECT * FROM ctf.delivery_scope_rows WHERE activation_id=p_transfer) r USING(scope_key) WHERE s.scope_key IS NULL OR r.scope_key IS NULL OR s.revision IS DISTINCT FROM r.revision OR s.owner_generation IS DISTINCT FROM r.owner_generation) THEN RAISE EXCEPTION 'CTF resume scope drift';END IF;
 UPDATE ctf.delivery_control SET activation_id=p_activation WHERE singleton;
END $$;
REVOKE ALL ON FUNCTION ctf.resume_delivery(uuid,uuid,text,bigint,uuid,text,text) FROM PUBLIC,dvaia_ctf_runtime;
