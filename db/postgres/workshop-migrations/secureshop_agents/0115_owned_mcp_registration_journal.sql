-- Original model-selected registration lineage, distinct from invocation of an
-- already registered tool. Admission commits before any isolated shell starts.
CREATE TABLE secureshop_agents.owned_mcp_registration_journal (
 operation_id uuid PRIMARY KEY, platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 persona_id integer NOT NULL CHECK(persona_id>0), persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL CHECK(authority_version>0), run_id uuid NOT NULL,
 effect_key text NOT NULL CHECK(octet_length(effect_key) BETWEEN 1 AND 256),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 args_sha256 bytea NOT NULL CHECK(octet_length(args_sha256)=32),
 instance_id uuid NOT NULL, runtime_sha256 bytea NOT NULL CHECK(octet_length(runtime_sha256)=32),
 worker_token uuid NOT NULL, state text NOT NULL DEFAULT 'admitted'
 CHECK(state IN ('admitted','completed','failed_before_effect','uncertain')),
 drained boolean NOT NULL DEFAULT false, request_json jsonb, receipt_json jsonb, receipt_sha256 bytea,
 redacted_at timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,run_id,effect_key),
 CHECK(request_json IS NULL OR (jsonb_typeof(request_json)='object' AND octet_length(request_json::text)<=98304)),
 CHECK(receipt_json IS NULL OR (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=262144)),
 CHECK(receipt_sha256 IS NULL OR octet_length(receipt_sha256)=32),
 CHECK(redacted_at IS NULL OR (request_json IS NULL AND receipt_json IS NULL))
);
CREATE TABLE secureshop_agents.owned_mcp_registration_fences (
 fence_id uuid NOT NULL, instance_id uuid NOT NULL, original_platform_owner_id integer NOT NULL,
 kind text NOT NULL CHECK(kind IN ('retirement','owner_deletion')), platform_launch_id uuid,
 platform_scenario_id uuid, platform_launch_generation bigint, original_platform_session_id integer,
 receipt_json jsonb NOT NULL, receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 PRIMARY KEY(fence_id,instance_id),
 CHECK(jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=65536)
);
CREATE TABLE secureshop_agents.owned_mcp_registration_drains (
 operation_id uuid PRIMARY KEY REFERENCES secureshop_agents.owned_mcp_registration_journal(operation_id),
 receipt_json jsonb NOT NULL, receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 CHECK(jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=4096)
);
CREATE FUNCTION secureshop_agents.record_owned_mcp_registration_drain(v jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE r secureshop_agents.owned_mcp_registration_journal%ROWTYPE; h bytea;
BEGIN
 SELECT * INTO r FROM secureshop_agents.owned_mcp_registration_journal WHERE operation_id=(v->>'operationId')::uuid FOR UPDATE;
 IF NOT FOUND OR v->'version' IS DISTINCT FROM '1'::jsonb OR v->'drained' IS DISTINCT FROM 'true'::jsonb
 OR v->>'state' IS NULL OR v->>'state' NOT IN ('completed','retired')
 OR v->>'instanceId' IS DISTINCT FROM r.instance_id::text
 OR v->>'requestSha256' IS DISTINCT FROM encode(r.request_sha256,'hex')
 THEN RAISE EXCEPTION 'Registration drain proof mismatch' USING ERRCODE='55000'; END IF;
 h:=sha256(convert_to(v::text,'UTF8'));
 IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_registration_drains WHERE operation_id=r.operation_id AND receipt_sha256<>h)
 THEN RAISE EXCEPTION 'Registration drain conflict' USING ERRCODE='55000'; END IF;
 INSERT INTO secureshop_agents.owned_mcp_registration_drains VALUES(r.operation_id,v,h) ON CONFLICT DO NOTHING;
 UPDATE secureshop_agents.owned_mcp_registration_journal SET drained=true,
 state=CASE WHEN state='admitted' THEN 'uncertain' ELSE state END,updated_at=clock_timestamp() WHERE operation_id=r.operation_id;
END $$;

CREATE FUNCTION secureshop_agents.admit_owned_mcp_registration(v jsonb,worker uuid)
RETURNS SETOF secureshop_agents.owned_mcp_registration_journal LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE b jsonb:=v->'scope'; p jsonb:=v->'persona'; s jsonb:=v->'personaSession'; q jsonb:=v->'request';
 l uuid:=(b->>'launchId')::uuid; sc uuid:=(b->>'scenarioId')::uuid; g bigint:=(b->>'generation')::bigint;
 o integer:=(b->>'platformOwnerId')::integer; ps integer:=(b->>'platformSessionId')::integer;
 r secureshop_agents.owned_mcp_registration_journal%ROWTYPE;
BEGIN
 IF v IS NULL OR jsonb_typeof(v) IS DISTINCT FROM 'object' OR v->'version' IS DISTINCT FROM '1'::jsonb
 OR octet_length(v::text)>98304 OR p->>'role' IS DISTINCT FROM 'admin' OR worker IS NULL
 OR v->>'tool' IS DISTINCT FROM 'mcp-registry.register' OR v->>'mode' IS DISTINCT FROM 'vuln'
 OR q->>'action' IS DISTINCT FROM 'register' OR q->>'transport' IS DISTINCT FROM 'stdio'
 OR v->'args'->>'transport' IS DISTINCT FROM 'stdio' OR v->'args'->>'name' IS DISTINCT FROM q->>'name'
 OR v->'args'->>'stdio_cmd' IS DISTINCT FROM q->>'stdio_cmd'
 OR v->>'requestSha256' IS NULL OR v->>'requestSha256' !~ '^[0-9a-f]{64}$'
 OR v->>'argsSha256' IS NULL OR v->>'argsSha256' !~ '^[0-9a-f]{64}$'
 OR v->>'runtimeDigest' IS NULL OR v->>'runtimeDigest' !~ '^[0-9a-f]{64}$'
 OR v->>'effectKey' IS NULL OR v->>'callId' IS NULL
 OR decode(v->>'requestSha256','hex') IS DISTINCT FROM secureshop_agents.owned_mcp_registry_request_digest(q)
 THEN RAISE EXCEPTION 'Invalid original registration admission' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||o::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||l::text,0));
 PERFORM secureshop_agents.assert_owned_mcp_registry_actor_current(l,sc,g,o,ps,(p->>'id')::integer,(s->>'sessionId')::uuid,(s->>'authorityVersion')::bigint);
 IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_registration_fences f WHERE f.original_platform_owner_id=o
 AND (f.kind='owner_deletion' OR (f.platform_launch_id=l AND f.platform_launch_generation=g)))
 THEN RAISE EXCEPTION 'Registration generation retired' USING ERRCODE='55000'; END IF;
 -- Even identical re-admission is not authority to dispatch again.
 IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_registration_journal WHERE operation_id=(q->>'operationId')::uuid)
 THEN RAISE EXCEPTION 'Registration already admitted' USING ERRCODE='55000'; END IF;
 IF (SELECT count(*) FROM secureshop_agents.owned_mcp_registration_journal WHERE platform_launch_id=l AND platform_launch_generation=g)>=256
 THEN RAISE EXCEPTION 'Registration quota exceeded' USING ERRCODE='55000'; END IF;
 INSERT INTO secureshop_agents.owned_mcp_registration_journal(operation_id,platform_launch_id,platform_scenario_id,platform_launch_generation,
 original_platform_owner_id,original_platform_session_id,persona_id,persona_session_id,authority_version,run_id,effect_key,
 request_sha256,args_sha256,instance_id,runtime_sha256,worker_token,request_json)
 VALUES((q->>'operationId')::uuid,l,sc,g,o,ps,(p->>'id')::integer,(s->>'sessionId')::uuid,(s->>'authorityVersion')::bigint,
 (v->>'runId')::uuid,v->>'effectKey',decode(v->>'requestSha256','hex'),decode(v->>'argsSha256','hex'),
 (v->>'instanceId')::uuid,decode(v->>'runtimeDigest','hex'),worker,v) RETURNING * INTO r;
 RETURN NEXT r;
END $$;

CREATE FUNCTION secureshop_agents.settle_owned_mcp_registration(id uuid,worker uuid,v jsonb)
RETURNS SETOF secureshop_agents.owned_mcp_registration_journal LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE r secureshop_agents.owned_mcp_registration_journal%ROWTYPE; h bytea; p jsonb:=v->'proof';
BEGIN
 SELECT * INTO r FROM secureshop_agents.owned_mcp_registration_journal WHERE operation_id=id FOR UPDATE;
 IF NOT FOUND OR r.worker_token IS DISTINCT FROM worker OR r.redacted_at IS NOT NULL
 OR v->>'state' IS NULL OR v->>'state' NOT IN ('completed','failed_before_effect','uncertain')
 OR v->>'operationId' IS DISTINCT FROM id::text OR p->>'operationId' IS DISTINCT FROM id::text
 OR v->>'instanceId' IS DISTINCT FROM r.instance_id::text OR p->>'instanceId' IS DISTINCT FROM r.instance_id::text
 OR v->>'requestSha256' IS DISTINCT FROM encode(r.request_sha256,'hex') OR p->>'requestSha256' IS DISTINCT FROM encode(r.request_sha256,'hex')
 OR v->>'runtimeDigest' IS DISTINCT FROM encode(r.runtime_sha256,'hex')
 OR jsonb_typeof(v->'drained') IS DISTINCT FROM 'boolean' OR p->'drained' IS DISTINCT FROM v->'drained'
 OR (r.drained AND v->'drained' IS DISTINCT FROM 'true'::jsonb)
 OR (v->>'state'='completed' AND (v->'drained' IS DISTINCT FROM 'true'::jsonb OR p->>'state' IS DISTINCT FROM 'completed' OR jsonb_typeof(p->'changes') IS DISTINCT FROM 'array'))
 OR (v->>'state'='failed_before_effect' AND (v->'drained' IS DISTINCT FROM 'true'::jsonb OR p->>'state' IS DISTINCT FROM 'not_dispatched'))
 THEN RAISE EXCEPTION 'Registration settlement mismatch' USING ERRCODE='55000'; END IF;
 h:=sha256(convert_to(v::text,'UTF8'));
 IF r.state IN ('completed','failed_before_effect') THEN
  IF r.state IS DISTINCT FROM v->>'state' OR r.receipt_sha256 IS DISTINCT FROM h
  THEN RAISE EXCEPTION 'Registration terminal conflict' USING ERRCODE='55000'; END IF;
  RETURN NEXT r; RETURN;
 END IF;
 UPDATE secureshop_agents.owned_mcp_registration_journal SET state=v->>'state',drained=(v->>'drained')::boolean,
 receipt_json=v,receipt_sha256=h,updated_at=clock_timestamp() WHERE operation_id=id RETURNING * INTO r;
 RETURN NEXT r;
END $$;

CREATE FUNCTION secureshop_agents.record_owned_mcp_registration_fence(v jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE o integer:=(v->>'platformOwnerId')::integer; l uuid:=(v->>'launchId')::uuid; sc uuid:=(v->>'scenarioId')::uuid;
 g bigint:=(v->>'generation')::bigint; ps integer:=(v->>'platformSessionId')::integer;
 i uuid:=(v->>'instanceId')::uuid; f uuid:=(v->>'fenceId')::uuid; k text:=v->>'kind'; h bytea; expected jsonb;
BEGIN
 IF k IS NULL OR k NOT IN ('retirement','owner_deletion') OR v->'drained' IS DISTINCT FROM 'true'::jsonb
 OR v->'retired' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(v->'operationIds') IS DISTINCT FROM 'array'
 OR (k='retirement' AND (l IS NULL OR sc IS NULL OR g IS NULL OR ps IS NULL))
 OR (k='owner_deletion' AND (l IS NOT NULL OR sc IS NOT NULL OR g IS NOT NULL OR ps IS NOT NULL))
 THEN RAISE EXCEPTION 'Invalid registration fence' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||o::text,0));
 IF l IS NOT NULL THEN PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||l::text,0)); END IF;
 SELECT COALESCE(jsonb_agg(operation_id::text ORDER BY operation_id),'[]'::jsonb) INTO expected
 FROM secureshop_agents.owned_mcp_registration_journal WHERE original_platform_owner_id=o AND instance_id=i
 AND (k='owner_deletion' OR (platform_launch_id=l AND platform_scenario_id=sc AND platform_launch_generation=g AND original_platform_session_id=ps));
 IF expected IS DISTINCT FROM v->'operationIds' THEN RAISE EXCEPTION 'Registration fence set mismatch' USING ERRCODE='55000'; END IF;
 h:=sha256(convert_to(v::text,'UTF8'));
 IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_registration_fences WHERE fence_id=f AND instance_id=i AND receipt_sha256<>h)
 THEN RAISE EXCEPTION 'Registration fence conflict' USING ERRCODE='55000'; END IF;
 INSERT INTO secureshop_agents.owned_mcp_registration_fences VALUES(f,i,o,k,l,sc,g,ps,v,h) ON CONFLICT DO NOTHING;
 UPDATE secureshop_agents.owned_mcp_registration_journal SET drained=true,
 state=CASE WHEN state='admitted' THEN 'uncertain' ELSE state END,updated_at=clock_timestamp()
 WHERE original_platform_owner_id=o AND instance_id=i AND operation_id::text IN (SELECT jsonb_array_elements_text(expected));
END $$;

CREATE FUNCTION secureshop_agents.guard_owned_mcp_registration_retirement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE o integer:=NEW.original_platform_owner_id; l uuid; g bigint; f uuid; k text;
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN l:=NEW.platform_launch_id;g:=NEW.from_generation;f:=NEW.reset_id;k:='retirement';
 ELSE f:=NEW.deletion_job_id;k:='owner_deletion'; END IF;
 IF EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_registration_journal r WHERE r.original_platform_owner_id=o
 AND (l IS NULL OR (r.platform_launch_id=l AND r.platform_launch_generation=g))
 AND (NOT r.drained OR NOT EXISTS(SELECT 1 FROM secureshop_agents.owned_mcp_registration_fences x
 WHERE x.fence_id=f AND x.instance_id=r.instance_id AND x.original_platform_owner_id=o AND x.kind=k)))
 THEN RAISE EXCEPTION 'Registration drain and fence required' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_mcp_registration_retirement_guard BEFORE INSERT ON secureshop_agents.conversation_generation_retirements
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_registration_retirement();
CREATE TRIGGER owned_mcp_registration_deletion_guard BEFORE INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_registration_retirement();
CREATE FUNCTION secureshop_agents.redact_owned_mcp_registrations() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
 UPDATE secureshop_agents.owned_mcp_registration_journal SET request_json=NULL,receipt_json=NULL,redacted_at=clock_timestamp()
 WHERE original_platform_owner_id=NEW.original_platform_owner_id AND platform_launch_id=NEW.platform_launch_id AND platform_launch_generation=NEW.from_generation;
 ELSE
 UPDATE secureshop_agents.owned_mcp_registration_journal SET request_json=NULL,receipt_json=NULL,redacted_at=clock_timestamp()
 WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER owned_mcp_registration_retirement_redact AFTER INSERT ON secureshop_agents.conversation_generation_retirements
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.redact_owned_mcp_registrations();
CREATE TRIGGER owned_mcp_registration_deletion_redact AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.redact_owned_mcp_registrations();
REVOKE ALL ON secureshop_agents.owned_mcp_registration_journal,secureshop_agents.owned_mcp_registration_fences,secureshop_agents.owned_mcp_registration_drains FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.owned_mcp_registration_journal,secureshop_agents.owned_mcp_registration_fences,secureshop_agents.owned_mcp_registration_drains TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.admit_owned_mcp_registration(jsonb,uuid),secureshop_agents.settle_owned_mcp_registration(uuid,uuid,jsonb),secureshop_agents.record_owned_mcp_registration_fence(jsonb),secureshop_agents.record_owned_mcp_registration_drain(jsonb),secureshop_agents.guard_owned_mcp_registration_retirement(),secureshop_agents.redact_owned_mcp_registrations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.admit_owned_mcp_registration(jsonb,uuid),secureshop_agents.settle_owned_mcp_registration(uuid,uuid,jsonb),secureshop_agents.record_owned_mcp_registration_fence(jsonb),secureshop_agents.record_owned_mcp_registration_drain(jsonb) TO dvaia_secureshop_agents_runtime;
