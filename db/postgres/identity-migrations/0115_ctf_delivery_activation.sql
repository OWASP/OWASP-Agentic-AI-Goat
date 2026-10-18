-- Operator-only paired activation. PREPARED alone remains unavailable.
CREATE TABLE identity.ctf_delivery_activations (
 activation_id uuid PRIMARY KEY, identity_store_id uuid NOT NULL, ctf_store_id uuid NOT NULL,
 bootstrap_operation_id uuid NOT NULL REFERENCES identity.ctf_bootstrap_sessions(operation_id),
 source_revision bigint NOT NULL CHECK(source_revision>=0),
 manifest_sha256 text NOT NULL CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$'),
 protocol_version integer NOT NULL CHECK(protocol_version=1),
 authority_sha256 text NOT NULL CHECK(authority_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TRIGGER ctf_delivery_activation_immutable BEFORE UPDATE OR DELETE ON identity.ctf_delivery_activations
 FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
CREATE TABLE identity.ctf_delivery_control (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 activation_id uuid REFERENCES identity.ctf_delivery_activations(activation_id)
);
INSERT INTO identity.ctf_delivery_control(singleton) VALUES(true);
REVOKE ALL ON identity.ctf_delivery_activations,identity.ctf_delivery_control FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_delivery_activations,identity.ctf_delivery_control TO dvaia_identity_runtime;
-- Migration-only bounded pages: history size does not require one large JSON value.
CREATE TABLE identity.ctf_delivery_scope_transfer(activation_id uuid PRIMARY KEY,next_page integer NOT NULL DEFAULT 0 CHECK(next_page>=0),last_scope text,chain_sha256 text NOT NULL DEFAULT repeat('0',64) CHECK(chain_sha256 ~ '^[a-f0-9]{64}$'));
CREATE TABLE identity.ctf_delivery_scope_pages(activation_id uuid NOT NULL REFERENCES identity.ctf_delivery_scope_transfer,page_number integer NOT NULL CHECK(page_number>=0),canonical_rows text NOT NULL CHECK(octet_length(canonical_rows)<=262144),page_sha256 text NOT NULL CHECK(page_sha256=encode(sha256(convert_to(canonical_rows,'UTF8')),'hex')),chain_sha256 text NOT NULL CHECK(chain_sha256 ~ '^[a-f0-9]{64}$'),PRIMARY KEY(activation_id,page_number));
CREATE TABLE identity.ctf_delivery_scope_rows(activation_id uuid NOT NULL REFERENCES identity.ctf_delivery_scope_transfer,scope_key text NOT NULL CHECK(scope_key='global' OR scope_key ~ '^(stage|owner):[1-9][0-9]*$'),revision bigint NOT NULL CHECK(revision>=0),owner_generation bigint CHECK(owner_generation>=0),PRIMARY KEY(activation_id,scope_key),CHECK((scope_key LIKE 'owner:%')=(owner_generation IS NOT NULL)));
CREATE TRIGGER ctf_scope_page_immutable BEFORE UPDATE OR DELETE ON identity.ctf_delivery_scope_pages FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
CREATE TRIGGER ctf_scope_row_immutable BEFORE UPDATE OR DELETE ON identity.ctf_delivery_scope_rows FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_delivery_scope_transfer,identity.ctf_delivery_scope_pages,identity.ctf_delivery_scope_rows FROM PUBLIC,dvaia_identity_runtime;
CREATE FUNCTION identity.stage_ctf_delivery_scopes(p_activation uuid,p_page integer,p_rows text,p_hash text) RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE t identity.ctf_delivery_scope_transfer%ROWTYPE;sc jsonb;last_key text;prior text;chain text;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 IF p_activation IS NULL OR p_page IS NULL OR p_page<0 OR p_rows IS NULL OR octet_length(p_rows)>262144 OR NOT(p_rows IS JSON ARRAY WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_rows,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF activation page invalid';END IF;
 IF jsonb_array_length(p_rows::jsonb) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'CTF activation page size invalid';END IF;
 INSERT INTO identity.ctf_delivery_scope_transfer(activation_id) VALUES(p_activation) ON CONFLICT DO NOTHING;
 SELECT * INTO t FROM identity.ctf_delivery_scope_transfer WHERE activation_id=p_activation FOR UPDATE;
 SELECT canonical_rows,chain_sha256 INTO prior,chain FROM identity.ctf_delivery_scope_pages WHERE activation_id=p_activation AND page_number=p_page;
 IF FOUND THEN IF prior IS DISTINCT FROM p_rows THEN RAISE EXCEPTION 'CTF activation page replay conflict';END IF;RETURN chain;END IF;
 IF p_page<>t.next_page OR EXISTS(SELECT 1 FROM identity.ctf_delivery_activations WHERE activation_id=p_activation) THEN RAISE EXCEPTION 'CTF activation page order invalid';END IF;
 last_key:=t.last_scope;
 FOR sc IN SELECT value FROM jsonb_array_elements(p_rows::jsonb) LOOP
  IF NOT identity.ctf_json_matches(sc,'{"type":"object","properties":{"scope_key":{"type":"string","bytes":64,"pattern":"^(global|(stage|owner):[1-9][0-9]*)$"},"revision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"owner_generation":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807","nullable":true}},"optional":false}'::jsonb)
  OR ((sc->>'scope_key' LIKE 'owner:%') IS DISTINCT FROM (sc->>'owner_generation' IS NOT NULL)) OR (last_key IS NOT NULL AND (sc->>'scope_key') COLLATE "C"<=last_key COLLATE "C") THEN RAISE EXCEPTION 'CTF activation scope invalid';END IF;
  INSERT INTO identity.ctf_delivery_scope_rows VALUES(p_activation,sc->>'scope_key',(sc->>'revision')::bigint,(sc->>'owner_generation')::bigint);
  last_key:=sc->>'scope_key';
 END LOOP;
 chain:=encode(sha256(convert_to(t.chain_sha256||p_hash,'UTF8')),'hex');
 INSERT INTO identity.ctf_delivery_scope_pages VALUES(p_activation,p_page,p_rows,p_hash,chain);
 UPDATE identity.ctf_delivery_scope_transfer SET next_page=next_page+1,last_scope=last_key,chain_sha256=chain WHERE activation_id=p_activation;
 RETURN chain;
END $$;
REVOKE ALL ON FUNCTION identity.stage_ctf_delivery_scopes(uuid,integer,text,text) FROM PUBLIC,dvaia_identity_runtime;
CREATE FUNCTION identity.activate_ctf_delivery(p_activation uuid,p_identity uuid,p_ctf uuid,p_bootstrap uuid,p_revision bigint,p_manifest text,p_authority_hash text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE v_global identity.ctf_authority%ROWTYPE; v_bootstrap identity.ctf_bootstrap_sessions%ROWTYPE; expected jsonb;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 SELECT * INTO v_global FROM identity.ctf_authority WHERE scope_key='global' FOR UPDATE;
 SELECT * INTO v_bootstrap FROM identity.ctf_bootstrap_sessions WHERE operation_id=p_bootstrap FOR SHARE;
 IF p_activation IS NULL OR p_identity IS DISTINCT FROM (SELECT store_id FROM identity.ctf_bootstrap_store WHERE singleton)
 OR v_bootstrap.state IS DISTINCT FROM 'prepared' OR v_bootstrap.source_store_id IS DISTINCT FROM p_ctf OR v_bootstrap.source_revision IS DISTINCT FROM p_revision OR v_bootstrap.manifest_sha256 IS DISTINCT FROM p_manifest
 OR v_global.lifecycle_state NOT IN ('uninitialized','ready') OR v_global.next_sequence IS DISTINCT FROM v_global.applied_sequence
 OR EXISTS(SELECT 1 FROM identity.ctf_authority WHERE lifecycle_state IN ('pending','blocked')) THEN RAISE EXCEPTION 'CTF activation unavailable';END IF;
 IF NOT EXISTS(SELECT 1 FROM identity.ctf_delivery_scope_transfer WHERE activation_id=p_activation AND next_page>0 AND chain_sha256=p_authority_hash) THEN RAISE EXCEPTION 'CTF activation scope digest invalid';END IF;
 PERFORM 1 FROM identity.ctf_delivery_scope_transfer WHERE activation_id=p_activation FOR SHARE;
 PERFORM 1 FROM identity.ctf_authority ORDER BY scope_key COLLATE "C" FOR UPDATE;
 IF EXISTS(SELECT 1 FROM identity.ctf_authority a FULL JOIN (SELECT * FROM identity.ctf_delivery_scope_rows WHERE activation_id=p_activation) r USING(scope_key) WHERE a.scope_key IS NULL OR r.scope_key IS NULL OR a.revision IS DISTINCT FROM r.revision OR a.owner_generation IS DISTINCT FROM r.owner_generation)
 OR EXISTS(SELECT 1 FROM identity.ctf_authority WHERE lifecycle_state NOT IN ('uninitialized','ready'))
 OR EXISTS(SELECT 1 FROM identity.ctf_outbox) OR EXISTS(SELECT 1 FROM identity.ctf_decisions)
 OR NOT EXISTS(SELECT 1 FROM identity.ctf_config_binding WHERE singleton AND applied_operation_id=p_bootstrap) THEN RAISE EXCEPTION 'CTF activation authority drift';END IF;
 -- Lock current users before graph owners, matching deletion/admission ordering.
 PERFORM 1 FROM identity.users u WHERE u.id IN(SELECT substring(scope_key from 7)::integer FROM identity.ctf_authority WHERE scope_key LIKE 'owner:%') ORDER BY u.id FOR UPDATE;
 PERFORM 1 FROM graph_runtime.owners graph_owner WHERE graph_owner.owner_key IN(SELECT '["CTF","'||substring(scope_key from 7)||'"]' FROM identity.ctf_authority WHERE scope_key LIKE 'owner:%') ORDER BY graph_owner.owner_key FOR SHARE;
 IF EXISTS(SELECT 1 FROM identity.ctf_authority a LEFT JOIN identity.users u ON u.id=CASE WHEN a.scope_key LIKE 'owner:%' THEN substring(a.scope_key from 7)::integer END LEFT JOIN graph_runtime.owners o ON o.owner_key='["CTF","'||u.id||'"]' WHERE a.scope_key LIKE 'owner:%' AND (u.id IS NULL OR o.generation IS DISTINCT FROM a.owner_generation OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs j WHERE j.subject_user_id=u.id) OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks x WHERE x.owner_key=o.owner_key))) THEN RAISE EXCEPTION 'CTF activation owner drift';END IF;
 INSERT INTO identity.ctf_delivery_activations VALUES(p_activation,p_identity,p_ctf,p_bootstrap,p_revision,p_manifest,1,p_authority_hash) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM identity.ctf_delivery_activations WHERE activation_id=p_activation AND identity_store_id=p_identity AND ctf_store_id=p_ctf AND bootstrap_operation_id=p_bootstrap AND source_revision=p_revision AND manifest_sha256=p_manifest AND protocol_version=1 AND authority_sha256=p_authority_hash) THEN RAISE EXCEPTION 'CTF activation conflict';END IF;
 UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE lifecycle_state='uninitialized';
 UPDATE identity.ctf_delivery_control SET activation_id=p_activation WHERE singleton;
END $$;
REVOKE ALL ON FUNCTION identity.activate_ctf_delivery(uuid,uuid,uuid,uuid,bigint,text,text) FROM PUBLIC,dvaia_identity_runtime;
CREATE OR REPLACE FUNCTION identity.ctf_publication_bootstrap_ready() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM identity.ctf_delivery_control c JOIN identity.ctf_delivery_activations a USING(activation_id)
 JOIN identity.ctf_bootstrap_sessions b ON b.operation_id=a.bootstrap_operation_id
 JOIN identity.ctf_bootstrap_store s ON s.singleton
 WHERE c.singleton AND a.protocol_version=1 AND a.identity_store_id=s.store_id AND b.state='prepared'
 AND b.source_store_id=a.ctf_store_id AND b.source_revision=a.source_revision AND b.manifest_sha256=a.manifest_sha256)
$$;
REVOKE ALL ON FUNCTION identity.ctf_publication_bootstrap_ready() FROM PUBLIC,dvaia_identity_runtime;

-- Resume an unchanged prepared checkpoint after traffic without resetting history.
CREATE FUNCTION identity.resume_ctf_delivery(p_activation uuid,p_transfer uuid,p_authority_hash text,p_sequence bigint,p_operation uuid,p_command_hash text,p_result_hash text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE v_global identity.ctf_authority%ROWTYPE;v_activation identity.ctf_delivery_activations%ROWTYPE;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 SELECT * INTO v_global FROM identity.ctf_authority WHERE scope_key='global' FOR UPDATE;
 SELECT * INTO v_activation FROM identity.ctf_delivery_activations WHERE activation_id=p_activation;
 IF v_activation.activation_id IS NULL OR NOT EXISTS(SELECT 1 FROM identity.ctf_bootstrap_sessions b CROSS JOIN identity.ctf_bootstrap_store s WHERE s.singleton AND s.store_id=v_activation.identity_store_id AND b.operation_id=v_activation.bootstrap_operation_id AND b.state='prepared' AND b.source_store_id=v_activation.ctf_store_id AND b.source_revision=v_activation.source_revision AND b.manifest_sha256=v_activation.manifest_sha256)
 OR v_global.lifecycle_state IS DISTINCT FROM 'ready' OR v_global.next_sequence IS DISTINCT FROM p_sequence OR v_global.applied_sequence IS DISTINCT FROM p_sequence
 OR EXISTS(SELECT 1 FROM identity.ctf_outbox WHERE state IN ('pending','blocked')) THEN RAISE EXCEPTION 'CTF resume unavailable';END IF;
 IF p_sequence=0 THEN
  IF p_operation IS NOT NULL OR p_command_hash IS NOT NULL OR p_result_hash IS NOT NULL THEN RAISE EXCEPTION 'CTF resume head invalid';END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM identity.ctf_outbox WHERE sequence=p_sequence AND operation_id=p_operation AND state='applied' AND command_hash=p_command_hash AND result_hash=p_result_hash) THEN RAISE EXCEPTION 'CTF resume head invalid';END IF;
 PERFORM 1 FROM identity.ctf_delivery_scope_transfer WHERE activation_id=p_transfer FOR SHARE;
 IF NOT EXISTS(SELECT 1 FROM identity.ctf_delivery_scope_transfer WHERE activation_id=p_transfer AND next_page>0 AND chain_sha256=p_authority_hash) THEN RAISE EXCEPTION 'CTF resume scope digest invalid';END IF;
 PERFORM 1 FROM identity.ctf_authority ORDER BY scope_key COLLATE "C" FOR UPDATE;
 IF EXISTS(SELECT 1 FROM identity.ctf_authority authority_row FULL JOIN (SELECT * FROM identity.ctf_delivery_scope_rows WHERE activation_id=p_transfer) r USING(scope_key) WHERE authority_row.scope_key IS NULL OR r.scope_key IS NULL OR authority_row.revision IS DISTINCT FROM r.revision OR authority_row.owner_generation IS DISTINCT FROM r.owner_generation)
 OR EXISTS(SELECT 1 FROM identity.ctf_authority authority_row WHERE authority_row.lifecycle_state<>'ready' AND NOT(authority_row.scope_key LIKE 'owner:%' AND authority_row.lifecycle_state='blocked' AND authority_row.failure_code='student_deleted' AND EXISTS(
  SELECT 1 FROM identity.ctf_outbox e JOIN identity.ctf_deletion_commands dc ON dc.operation_id=e.operation_id AND dc.sequence=e.sequence
  WHERE e.operation_id=authority_row.blocked_operation_id AND e.kind='student_delete' AND e.state='applied'
  AND identity.ctf_deletion_command_matches(e.command)
  AND authority_row.scope_key='owner:'||dc.subject_id AND e.command->>'subjectId'=dc.subject_id::text
  AND e.command->>'jobId'=dc.job_id::text AND e.command->>'generationAfter'=authority_row.owner_generation::text)))
 THEN RAISE EXCEPTION 'CTF resume authority drift';END IF;
 PERFORM 1 FROM identity.users u WHERE u.id IN(SELECT substring(scope_key from 7)::integer FROM identity.ctf_authority WHERE scope_key LIKE 'owner:%' AND lifecycle_state='ready') ORDER BY u.id FOR UPDATE;
 PERFORM 1 FROM graph_runtime.owners o WHERE o.owner_key IN(SELECT '["CTF","'||substring(scope_key from 7)||'"]' FROM identity.ctf_authority WHERE scope_key LIKE 'owner:%' AND lifecycle_state='ready') ORDER BY o.owner_key FOR SHARE;
 IF EXISTS(SELECT 1 FROM identity.ctf_authority authority_row LEFT JOIN identity.users u ON u.id=CASE WHEN authority_row.scope_key LIKE 'owner:%' THEN substring(authority_row.scope_key from 7)::integer END LEFT JOIN graph_runtime.owners o ON o.owner_key='["CTF","'||u.id||'"]' WHERE authority_row.scope_key LIKE 'owner:%' AND authority_row.lifecycle_state='ready' AND (u.id IS NULL OR o.generation IS DISTINCT FROM authority_row.owner_generation OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs j WHERE j.subject_user_id=u.id) OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks x WHERE x.owner_key=o.owner_key))) THEN RAISE EXCEPTION 'CTF resume owner drift';END IF;
 UPDATE identity.ctf_delivery_control SET activation_id=p_activation WHERE singleton;
END $$;
REVOKE ALL ON FUNCTION identity.resume_ctf_delivery(uuid,uuid,text,bigint,uuid,text,text) FROM PUBLIC,dvaia_identity_runtime;
