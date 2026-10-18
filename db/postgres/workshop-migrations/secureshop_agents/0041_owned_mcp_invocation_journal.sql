-- Unwired invocation foundation. Existing registry actions and immutable0035/36 stay unchanged.
CREATE TABLE secureshop_agents.owned_mcp_invocation_journal (
 invocation_id uuid PRIMARY KEY,
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 persona_id integer NOT NULL CHECK(persona_id>0), persona_session_id uuid NOT NULL, authority_version bigint NOT NULL CHECK(authority_version>0),
 entry_id uuid NOT NULL, registry_version bigint NOT NULL CHECK(registry_version>0),
 run_id uuid NOT NULL, effect_key text NOT NULL CHECK(octet_length(effect_key) BETWEEN 1 AND 256),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 manager_instance_id uuid NOT NULL, runtime_sha256 bytea NOT NULL CHECK(octet_length(runtime_sha256)=32),
 worker_token uuid NOT NULL,
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN ('admitted','completed','failed_before_effect','uncertain')),
 request_json jsonb, receipt_json jsonb, receipt_sha256 bytea,
 drained boolean NOT NULL DEFAULT false, redacted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,run_id,effect_key),
 CHECK(request_json IS NULL OR (jsonb_typeof(request_json)='object' AND octet_length(request_json::text)<=196608)),
 CHECK(receipt_json IS NULL OR (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=196608)),
 CHECK(receipt_sha256 IS NULL OR octet_length(receipt_sha256)=32),
 CHECK(redacted_at IS NULL OR (request_json IS NULL AND receipt_json IS NULL))
);
CREATE TABLE secureshop_agents.owned_mcp_invocation_fences (
 fence_id uuid NOT NULL, manager_instance_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('retirement','owner_deletion')),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0), platform_launch_id uuid, platform_scenario_id uuid,
 platform_launch_generation bigint, original_platform_session_id integer,
 receipt_json jsonb NOT NULL CHECK(jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=65536),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(fence_id,manager_instance_id),
 CHECK((kind='owner_deletion' AND platform_launch_id IS NULL AND platform_scenario_id IS NULL AND platform_launch_generation IS NULL AND original_platform_session_id IS NULL)
 OR (kind='retirement' AND platform_launch_id IS NOT NULL AND platform_scenario_id IS NOT NULL AND platform_launch_generation IS NOT NULL AND platform_launch_generation>0 AND original_platform_session_id IS NOT NULL AND original_platform_session_id>0))
);

CREATE FUNCTION secureshop_agents.admit_owned_mcp_invocation(v jsonb, worker uuid)
RETURNS SETOF secureshop_agents.owned_mcp_invocation_journal LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE b jsonb:=v->'request'->'binding'; s jsonb:=v->'personaSession'; e secureshop_agents.bound_mcp_registry_entries%ROWTYPE;
 prior secureshop_agents.owned_mcp_invocation_journal%ROWTYPE; l uuid:=(b->>'launchId')::uuid; g bigint:=(b->>'generation')::bigint;
 o integer:=(b->>'platformOwnerId')::integer; ps integer:=(b->>'platformSessionId')::integer; sc uuid:=(b->>'scenarioId')::uuid;
BEGIN
 IF v IS NULL OR jsonb_typeof(v) IS DISTINCT FROM 'object' OR octet_length(v::text)>196608 OR v->'request'->>'version' IS DISTINCT FROM 'owned-mcp-invocation-v1'
 OR b->>'role' IS DISTINCT FROM 'admin' OR v->>'requestSha256' !~ '^[0-9a-f]{64}$' OR v->>'runtimeSha256' !~ '^[0-9a-f]{64}$'
 OR worker IS NULL OR v->>'effectKey' IS NULL THEN RAISE EXCEPTION 'Invalid invocation admission' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||o::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||l::text,0));
 PERFORM secureshop_agents.assert_owned_mcp_registry_actor_current(l,sc,g,o,ps,(b->>'shopUserId')::integer,(s->>'sessionId')::uuid,(s->>'authorityVersion')::bigint);
 SELECT * INTO prior FROM secureshop_agents.owned_mcp_invocation_journal WHERE invocation_id=(v->>'invocationId')::uuid;
 IF FOUND THEN
  IF prior.request_sha256 IS DISTINCT FROM decode(v->>'requestSha256','hex') OR prior.request_json IS DISTINCT FROM v THEN
   RAISE EXCEPTION 'Invocation identity conflict' USING ERRCODE='55000'; END IF;
  RETURN NEXT prior; RETURN;
 END IF;
 SELECT * INTO e FROM secureshop_agents.bound_mcp_registry_entries WHERE platform_launch_id=l AND platform_scenario_id=sc
 AND platform_launch_generation=g AND original_platform_owner_id=o AND original_platform_session_id=ps
 AND entry_id=(v->'request'->>'entryId')::uuid AND lifecycle='active' FOR UPDATE;
 IF NOT FOUND OR e.current_version IS DISTINCT FROM (v->'request'->>'registryVersion')::bigint
 OR e.schema_sha256 IS DISTINCT FROM decode(v->'request'->>'schemaSha256','hex')
 OR NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_revisions r WHERE r.platform_launch_id=l
  AND r.platform_scenario_id=sc AND r.platform_launch_generation=g AND r.original_platform_owner_id=o AND r.original_platform_session_id=ps
  AND r.entry_id=e.entry_id AND r.name=e.name AND r.registry_version=e.current_version AND r.schema_sha256=e.schema_sha256
  AND r.transport=e.transport AND r.endpoint_text=e.endpoint_text AND r.redacted_at IS NULL AND r.action IN ('register','import')
  AND r.tools_json=v->'snapshot'->'tools')
 OR EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_invocation_fences f WHERE f.original_platform_owner_id=o
  AND (f.kind='owner_deletion' OR (f.platform_launch_id=l AND f.platform_launch_generation=g))) THEN
  RAISE EXCEPTION 'Invocation authority changed' USING ERRCODE='55000'; END IF;
 IF (SELECT count(*) FROM secureshop_agents.owned_mcp_invocation_journal WHERE platform_launch_id=l AND platform_launch_generation=g)>=256 THEN
  RAISE EXCEPTION 'Invocation quota' USING ERRCODE='55000'; END IF;
 INSERT INTO secureshop_agents.owned_mcp_invocation_journal(invocation_id,platform_launch_id,platform_scenario_id,platform_launch_generation,
 original_platform_owner_id,original_platform_session_id,persona_id,persona_session_id,authority_version,entry_id,registry_version,
 run_id,effect_key,request_sha256,manager_instance_id,runtime_sha256,worker_token,request_json)
 VALUES((v->>'invocationId')::uuid,l,sc,g,o,ps,(b->>'shopUserId')::integer,(s->>'sessionId')::uuid,(s->>'authorityVersion')::bigint,
 e.entry_id,e.current_version,(v->'request'->>'runId')::uuid,v->>'effectKey',decode(v->>'requestSha256','hex'),
 (v->>'managerInstanceId')::uuid,decode(v->>'runtimeSha256','hex'),worker,v) RETURNING * INTO prior;
 RETURN NEXT prior;
END $$;

CREATE FUNCTION secureshop_agents.settle_owned_mcp_invocation(id uuid, worker uuid, outcome text, receipt jsonb)
RETURNS SETOF secureshop_agents.owned_mcp_invocation_journal LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE r secureshop_agents.owned_mcp_invocation_journal%ROWTYPE; h bytea;
BEGIN
 SELECT * INTO r FROM secureshop_agents.owned_mcp_invocation_journal WHERE invocation_id=id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Invocation unavailable' USING ERRCODE='55000'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||r.original_platform_owner_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||r.platform_launch_id::text,0));
 SELECT * INTO r FROM secureshop_agents.owned_mcp_invocation_journal WHERE invocation_id=id FOR UPDATE;
 IF r.worker_token IS DISTINCT FROM worker OR r.redacted_at IS NOT NULL OR outcome NOT IN ('completed','failed_before_effect','uncertain')
 OR receipt->>'invocationId' IS DISTINCT FROM id::text OR receipt->>'requestSha256' IS DISTINCT FROM encode(r.request_sha256,'hex')
 OR receipt->>'managerInstanceId' IS DISTINCT FROM r.manager_instance_id::text OR receipt->>'runtimeSha256' IS DISTINCT FROM encode(r.runtime_sha256,'hex')
 OR (r.drained AND receipt->'drained' IS DISTINCT FROM 'true'::jsonb)
 OR receipt->>'state' IS DISTINCT FROM outcome OR jsonb_typeof(receipt->'drained') IS DISTINCT FROM 'boolean'
 OR (outcome IN ('completed','failed_before_effect') AND receipt->'drained' IS DISTINCT FROM 'true'::jsonb)
 THEN RAISE EXCEPTION 'Invocation receipt mismatch' USING ERRCODE='55000'; END IF;
 h:=sha256(convert_to(receipt::text,'UTF8'));
 IF r.state IN ('completed','failed_before_effect') THEN
  IF r.state IS DISTINCT FROM outcome OR r.receipt_sha256 IS DISTINCT FROM h THEN RAISE EXCEPTION 'Invocation terminal conflict' USING ERRCODE='55000'; END IF;
  RETURN NEXT r; RETURN;
 END IF;
 UPDATE secureshop_agents.owned_mcp_invocation_journal SET state=outcome,receipt_json=receipt,receipt_sha256=h,
 drained=(receipt->>'drained')::boolean,updated_at=clock_timestamp() WHERE invocation_id=id RETURNING * INTO r;
 RETURN NEXT r;
END $$;

CREATE FUNCTION secureshop_agents.record_owned_mcp_invocation_fence(v jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE o integer:=(v->>'platformOwnerId')::integer; l uuid:=(v->>'launchId')::uuid; g bigint:=(v->>'generation')::bigint;
 mid uuid:=(v->>'managerInstanceId')::uuid; fid uuid:=(v->>'fenceId')::uuid; k text:=v->>'kind'; h bytea;
BEGIN
 IF k NOT IN ('retirement','owner_deletion') OR v->'retired' IS DISTINCT FROM 'true'::jsonb OR v->'drained' IS DISTINCT FROM 'true'::jsonb
 OR jsonb_typeof(v->'invocationIds') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invocation fence invalid' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||o::text,0));
 IF l IS NOT NULL THEN PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||l::text,0)); END IF;
 IF EXISTS((SELECT invocation_id::text FROM secureshop_agents.owned_mcp_invocation_journal WHERE original_platform_owner_id=o AND manager_instance_id=mid
  AND (k='owner_deletion' OR (platform_launch_id=l AND platform_scenario_id=(v->>'scenarioId')::uuid AND platform_launch_generation=g AND original_platform_session_id=(v->>'platformSessionId')::integer)))
  EXCEPT SELECT jsonb_array_elements_text(v->'invocationIds'))
 OR EXISTS((SELECT jsonb_array_elements_text(v->'invocationIds')) EXCEPT
  SELECT invocation_id::text FROM secureshop_agents.owned_mcp_invocation_journal WHERE original_platform_owner_id=o AND manager_instance_id=mid
  AND (k='owner_deletion' OR (platform_launch_id=l AND platform_scenario_id=(v->>'scenarioId')::uuid AND platform_launch_generation=g AND original_platform_session_id=(v->>'platformSessionId')::integer)))
 THEN RAISE EXCEPTION 'Invocation fence set mismatch' USING ERRCODE='55000'; END IF;
 h:=sha256(convert_to(v::text,'UTF8'));
 IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_invocation_fences WHERE fence_id=fid AND manager_instance_id=mid AND receipt_sha256<>h) THEN
  RAISE EXCEPTION 'Invocation fence conflict' USING ERRCODE='55000'; END IF;
 INSERT INTO secureshop_agents.owned_mcp_invocation_fences(fence_id,manager_instance_id,kind,original_platform_owner_id,
 platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_session_id,receipt_json,receipt_sha256)
 VALUES(fid,mid,k,o,l,(v->>'scenarioId')::uuid,g,(v->>'platformSessionId')::integer,v,h) ON CONFLICT DO NOTHING;
 UPDATE secureshop_agents.owned_mcp_invocation_journal SET drained=true,state=CASE WHEN state='admitted' THEN 'uncertain' ELSE state END,updated_at=clock_timestamp()
 WHERE original_platform_owner_id=o AND manager_instance_id=mid AND redacted_at IS NULL AND invocation_id::text IN (SELECT jsonb_array_elements_text(v->'invocationIds'));
END $$;

CREATE FUNCTION secureshop_agents.guard_owned_mcp_invocation_cleanup() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE o integer; l uuid; g bigint; fid uuid; k text;
BEGIN
 IF TG_TABLE_NAME='bound_mcp_registry_entries' THEN
  o:=OLD.original_platform_owner_id;l:=OLD.platform_launch_id;g:=OLD.platform_launch_generation;
  IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_invocation_journal WHERE original_platform_owner_id=o AND platform_launch_id=l
   AND platform_launch_generation=g AND entry_id=OLD.entry_id AND NOT drained) THEN
   RAISE EXCEPTION 'Invocation drain required' USING ERRCODE='55000'; END IF;
  IF TG_OP='UPDATE' THEN RETURN NEW; ELSE RETURN OLD; END IF;
 END IF;
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN o:=NEW.original_platform_owner_id;l:=NEW.platform_launch_id;g:=NEW.from_generation;fid:=NEW.reset_id;k:='retirement';
 ELSE o:=NEW.original_platform_owner_id;fid:=NEW.deletion_job_id;k:='owner_deletion'; END IF;
 -- Retirement already holds the launch lock. Never acquire owner after launch.
 IF l IS NULL THEN PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||o::text,0));
 ELSE PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||l::text,0)); END IF;
 IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_invocation_journal i WHERE i.original_platform_owner_id=o AND (l IS NULL OR (i.platform_launch_id=l AND i.platform_launch_generation=g))
  AND (NOT i.drained OR NOT EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_invocation_fences f WHERE f.fence_id=fid AND f.kind=k AND f.manager_instance_id=i.manager_instance_id
   AND f.original_platform_owner_id=o AND (l IS NULL OR (f.platform_launch_id=l AND f.platform_launch_generation=g))))) THEN
  RAISE EXCEPTION 'Invocation tombstone required' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_mcp_invocation_entry_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_mcp_registry_entries
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_invocation_cleanup();
CREATE TRIGGER owned_mcp_invocation_retirement_guard BEFORE INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_invocation_cleanup();
CREATE TRIGGER owned_mcp_invocation_deletion_guard BEFORE INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_invocation_cleanup();

CREATE FUNCTION secureshop_agents.cleanup_owned_mcp_invocations() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
  UPDATE secureshop_agents.owned_mcp_invocation_journal SET request_json=NULL,receipt_json=NULL,redacted_at=clock_timestamp(),updated_at=clock_timestamp()
   WHERE platform_launch_id=NEW.platform_launch_id AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=NEW.from_generation
   AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id AND redacted_at IS NULL;
 ELSE DELETE FROM secureshop_agents.owned_mcp_invocation_journal WHERE original_platform_owner_id=NEW.original_platform_owner_id; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_mcp_invocation_retirement_cleanup AFTER INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_owned_mcp_invocations();
CREATE TRIGGER owned_mcp_invocation_deletion_cleanup AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_owned_mcp_invocations();
REVOKE ALL ON secureshop_agents.owned_mcp_invocation_journal,secureshop_agents.owned_mcp_invocation_fences FROM PUBLIC,dvaia_secureshop_agents_runtime;
-- Runtime is trusted service SQL authority; tokens correlate private workers,
-- not signatures against a compromised runtime role. Do not expose them in reads.
GRANT SELECT(invocation_id,platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
 original_platform_session_id,persona_id,persona_session_id,authority_version,entry_id,registry_version,run_id,effect_key,
 request_sha256,manager_instance_id,runtime_sha256,state,request_json,receipt_json,receipt_sha256,drained,redacted_at,created_at,updated_at)
 ON secureshop_agents.owned_mcp_invocation_journal TO dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.owned_mcp_invocation_fences TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.admit_owned_mcp_invocation(jsonb,uuid),secureshop_agents.settle_owned_mcp_invocation(uuid,uuid,text,jsonb),secureshop_agents.record_owned_mcp_invocation_fence(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.admit_owned_mcp_invocation(jsonb,uuid),secureshop_agents.settle_owned_mcp_invocation(uuid,uuid,text,jsonb),secureshop_agents.record_owned_mcp_invocation_fence(jsonb) TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_owned_mcp_invocation_cleanup(),secureshop_agents.cleanup_owned_mcp_invocations() FROM PUBLIC,dvaia_secureshop_agents_runtime;

CREATE FUNCTION secureshop_agents.guard_owned_mcp_invocation_immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog AS $$ BEGIN
 IF TG_TABLE_NAME='owned_mcp_invocation_fences' THEN
  RAISE EXCEPTION 'Invocation fence immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Invocation deletion authority required' USING ERRCODE='55000';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','request_json','receipt_json','receipt_sha256','drained','redacted_at','updated_at'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','request_json','receipt_json','receipt_sha256','drained','redacted_at','updated_at'])
  OR (OLD.drained AND NOT NEW.drained) THEN RAISE EXCEPTION 'Invocation identity immutable' USING ERRCODE='55000'; END IF;
 IF NEW.redacted_at IS NOT NULL THEN
  IF OLD.redacted_at IS NULL AND NEW.request_json IS NULL AND NEW.receipt_json IS NULL
   AND NEW.receipt_sha256 IS NOT DISTINCT FROM OLD.receipt_sha256 AND NEW.state=OLD.state AND NEW.drained=OLD.drained
   AND EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id
    AND platform_scenario_id=OLD.platform_scenario_id AND from_generation=OLD.platform_launch_generation
    AND original_platform_owner_id=OLD.original_platform_owner_id AND original_platform_session_id=OLD.original_platform_session_id) THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'Invocation redaction authority required' USING ERRCODE='55000';
 END IF;
 IF OLD.redacted_at IS NOT NULL OR NEW.request_json IS DISTINCT FROM OLD.request_json
  OR (OLD.state IN ('completed','failed_before_effect') AND (NEW.state IS DISTINCT FROM OLD.state OR NEW.receipt_json IS DISTINCT FROM OLD.receipt_json OR NEW.receipt_sha256 IS DISTINCT FROM OLD.receipt_sha256))
  OR (OLD.state<>'admitted' AND NEW.state='admitted') THEN RAISE EXCEPTION 'Invocation transition invalid' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_mcp_invocation_identity BEFORE UPDATE OR DELETE ON secureshop_agents.owned_mcp_invocation_journal
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_invocation_immutable();
CREATE TRIGGER owned_mcp_invocation_fence_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.owned_mcp_invocation_fences
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_invocation_immutable();
REVOKE ALL ON FUNCTION secureshop_agents.guard_owned_mcp_invocation_immutable() FROM PUBLIC,dvaia_secureshop_agents_runtime;
