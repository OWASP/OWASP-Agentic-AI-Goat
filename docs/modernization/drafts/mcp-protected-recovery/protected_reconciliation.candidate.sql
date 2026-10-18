-- UNNUMBERED CANDIDATE: apply only in explicitly owned qualification databases.
CREATE TABLE workshop_conversations.mcp_protected_intents (
 operation_id uuid PRIMARY KEY,
 user_id integer NOT NULL CHECK(user_id>0), platform_session_id bigint NOT NULL CHECK(platform_session_id>0),
 owner_key text NOT NULL, generation bigint NOT NULL CHECK(generation>=0), run_id uuid NOT NULL,
 target_id uuid NOT NULL, ledger_effect_key text NOT NULL CHECK(octet_length(ledger_effect_key) BETWEEN 1 AND 1024),
 sdk_effect_key text NOT NULL CHECK(octet_length(sdk_effect_key) BETWEEN 1 AND 512),
 origin text NOT NULL CHECK(origin IN ('model','manual','controlled')),
 decision_digest text CHECK(decision_digest ~ '^[a-f0-9]{64}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[a-f0-9]{64}$'),
 request_canonical text NOT NULL CHECK(octet_length(request_canonical)<=8192),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((origin='model')=(decision_digest IS NOT NULL)),
 UNIQUE(owner_key,generation,ledger_effect_key), UNIQUE(run_id,sdk_effect_key)
);
CREATE TABLE workshop_conversations.mcp_protected_reconciliations (
 reconciliation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 operation_id uuid NOT NULL REFERENCES workshop_conversations.mcp_protected_intents(operation_id),
 outcome text NOT NULL CHECK(outcome IN ('completed','uncertain','absent')),
 receipt_digest text CHECK(receipt_digest ~ '^[a-f0-9]{64}$'),
 record_digest text NOT NULL CHECK(record_digest ~ '^[a-f0-9]{64}$'),
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((outcome='completed')=(receipt_digest IS NOT NULL))
);
CREATE UNIQUE INDEX mcp_protected_reconciliation_exact ON workshop_conversations.mcp_protected_reconciliations(operation_id,outcome,COALESCE(receipt_digest,''));
CREATE FUNCTION workshop_conversations.mcp_protected_current(p_owner integer,p_session bigint,p_generation bigint,p_run uuid,p_effect text,p_status text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE k text:='["MCP","'||p_owner::text||'"]';g bigint;s text;
BEGIN
 PERFORM 1 FROM identity.users WHERE id=p_owner AND is_active=1 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROTECTED_OWNER_UNAVAILABLE';END IF;
 PERFORM 1 FROM identity.user_sessions WHERE id=p_session AND user_id=p_owner AND is_active=1 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROTECTED_SESSION_UNAVAILABLE';END IF;
 SELECT generation INTO g FROM graph_runtime.owners WHERE owner_key=k FOR SHARE;
 IF g IS DISTINCT FROM p_generation THEN RAISE EXCEPTION 'PROTECTED_GENERATION_STALE';END IF;
 PERFORM 1 FROM graph_runtime.runs WHERE run_id=p_run AND owner_key=k AND generation=g AND (p_status<>'started' OR status='running') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROTECTED_RUN_UNAVAILABLE';END IF;
 SELECT status INTO s FROM graph_runtime.effects WHERE run_id=p_run AND owner_key=k AND generation=g AND effect_key=p_effect FOR SHARE;
 IF s IS DISTINCT FROM p_status THEN RAISE EXCEPTION 'PROTECTED_EFFECT_UNAVAILABLE';END IF;
END $$;
CREATE FUNCTION workshop_conversations.admit_mcp_protected(p_owner integer,p_session bigint,p_generation bigint,p_run uuid,p_target uuid,p_effect text,p_sdk text,p_origin text,p_decision text,p_request text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r jsonb:=p_request::jsonb;i workshop_conversations.mcp_protected_intents;d text:=encode(sha256(convert_to(p_request,'UTF8')),'hex');op uuid;
BEGIN
 IF octet_length(p_request)>8192 OR jsonb_typeof(r) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(r))<>5
 OR (r ?& ARRAY['operationId','runId','binding','operation','arguments']) IS NOT TRUE
 OR r->>'runId' IS DISTINCT FROM p_run::text OR r->'binding' IS DISTINCT FROM jsonb_build_object('targetId',p_target,'platformOwnerId',p_owner,'platformSessionId',p_session,'generation',p_generation)
 OR jsonb_typeof(r->'arguments') IS DISTINCT FROM 'object' OR right(p_effect,length(p_sdk)+1) IS DISTINCT FROM ':'||p_sdk OR length(p_sdk)<1
 OR p_origin NOT IN ('model','manual','controlled') OR ((p_origin='model')<>(p_decision IS NOT NULL)) THEN RAISE EXCEPTION 'PROTECTED_INTENT_INVALID';END IF;
 op:=(r->>'operationId')::uuid;
 IF op IS NULL OR r->>'operation' NOT IN ('read_configuration','rotate_keys','set_audit_logging') THEN RAISE EXCEPTION 'PROTECTED_INTENT_INVALID';END IF;
 IF ((r->>'operation'='read_configuration' AND r->'arguments'='{}'::jsonb)
 OR (r->>'operation'='rotate_keys' AND (SELECT count(*) FROM jsonb_object_keys(r->'arguments'))=2 AND r->'arguments'->>'labRole' IN ('privileged','unprivileged') AND jsonb_typeof(r->'arguments'->'enforceAuthorization')='boolean')
 OR (r->>'operation'='set_audit_logging' AND (SELECT count(*) FROM jsonb_object_keys(r->'arguments'))=1 AND r->'arguments'->>'action' IN ('enable','disable','clear'))) IS NOT TRUE THEN RAISE EXCEPTION 'PROTECTED_INTENT_INVALID';END IF;
 PERFORM workshop_conversations.mcp_protected_current(p_owner,p_session,p_generation,p_run,p_effect,'started');
 INSERT INTO workshop_conversations.mcp_protected_intents(operation_id,user_id,platform_session_id,owner_key,generation,run_id,target_id,ledger_effect_key,sdk_effect_key,origin,decision_digest,request_digest,request_canonical)
 VALUES(op,p_owner,p_session,'["MCP","'||p_owner::text||'"]',p_generation,p_run,p_target,p_effect,p_sdk,p_origin,p_decision,d,p_request) ON CONFLICT(operation_id) DO NOTHING;
 SELECT * INTO i FROM workshop_conversations.mcp_protected_intents WHERE operation_id=op FOR UPDATE;
 IF ROW(i.user_id,i.platform_session_id,i.generation,i.run_id,i.target_id,i.ledger_effect_key,i.sdk_effect_key,i.origin,i.decision_digest,i.request_digest,i.request_canonical)
 IS DISTINCT FROM ROW(p_owner,p_session,p_generation,p_run,p_target,p_effect,p_sdk,p_origin,p_decision,d,p_request) THEN RAISE EXCEPTION 'PROTECTED_INTENT_CONFLICT';END IF;
 RETURN to_jsonb(i);
END $$;
CREATE FUNCTION workshop_conversations.append_mcp_protected_reconciliation(p_operation uuid,p_owner integer,p_session bigint,p_outcome text,p_receipt text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE i workshop_conversations.mcp_protected_intents;v workshop_conversations.mcp_protected_reconciliations;d text;
BEGIN
 SELECT * INTO i FROM workshop_conversations.mcp_protected_intents WHERE operation_id=p_operation FOR UPDATE;
 IF NOT FOUND OR i.user_id<>p_owner OR i.platform_session_id<>p_session THEN RAISE EXCEPTION 'PROTECTED_INTENT_UNAVAILABLE';END IF;
 PERFORM workshop_conversations.mcp_protected_current(p_owner,p_session,i.generation,i.run_id,i.ledger_effect_key,'uncertain');
 IF p_outcome NOT IN ('completed','uncertain','absent') OR ((p_outcome='completed')<>(p_receipt IS NOT NULL)) OR (p_receipt IS NOT NULL AND p_receipt !~ '^[a-f0-9]{64}$') THEN RAISE EXCEPTION 'PROTECTED_RECONCILIATION_INVALID';END IF;
 IF p_outcome='completed' AND EXISTS(SELECT 1 FROM workshop_conversations.mcp_protected_reconciliations WHERE operation_id=p_operation AND outcome='completed' AND receipt_digest<>p_receipt) THEN RAISE EXCEPTION 'PROTECTED_RECONCILIATION_CONFLICT';END IF;
 d:=encode(sha256(convert_to(jsonb_build_array(p_operation,i.request_digest,p_outcome,p_receipt)::text,'UTF8')),'hex');
 INSERT INTO workshop_conversations.mcp_protected_reconciliations(operation_id,outcome,receipt_digest,record_digest) VALUES(p_operation,p_outcome,p_receipt,d) ON CONFLICT DO NOTHING;
 SELECT * INTO v FROM workshop_conversations.mcp_protected_reconciliations WHERE operation_id=p_operation AND outcome=p_outcome AND receipt_digest IS NOT DISTINCT FROM p_receipt;
 RETURN to_jsonb(v);
END $$;
REVOKE ALL ON workshop_conversations.mcp_protected_intents,workshop_conversations.mcp_protected_reconciliations FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION workshop_conversations.mcp_protected_current(integer,bigint,bigint,uuid,text,text),workshop_conversations.admit_mcp_protected(integer,bigint,bigint,uuid,uuid,text,text,text,text,text),workshop_conversations.append_mcp_protected_reconciliation(uuid,integer,bigint,text,text) FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON workshop_conversations.mcp_protected_intents,workshop_conversations.mcp_protected_reconciliations TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION workshop_conversations.admit_mcp_protected(integer,bigint,bigint,uuid,uuid,text,text,text,text,text),workshop_conversations.append_mcp_protected_reconciliation(uuid,integer,bigint,text,text) TO dvaia_identity_runtime;
