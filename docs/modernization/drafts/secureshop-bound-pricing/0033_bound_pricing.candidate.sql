-- UNREGISTERED pricing candidate0033. Native fresh/populated/no-op qualification required.
-- Immutable admission precedes external IO. Terminal unknown/completed never re-admits.
CREATE TABLE secureshop_agents.bound_pricing_admissions (
 platform_launch_id uuid NOT NULL,
 platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 operation_id uuid NOT NULL,
 run_id uuid NOT NULL,
 target_id uuid UNIQUE,
 target_snapshot_json jsonb CHECK(target_snapshot_json IS NULL OR (jsonb_typeof(target_snapshot_json)='object' AND octet_length(target_snapshot_json::text)<=131072)),
 persona_id integer NOT NULL CHECK(persona_id>0),
 persona_session_id uuid NOT NULL,
 persona_role text NOT NULL CHECK(persona_role IN ('customer','merchant')),
 authority_version bigint NOT NULL CHECK(authority_version>0),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 binding_sha256 bytea NOT NULL CHECK(octet_length(binding_sha256)=32),
 request_json jsonb CHECK(request_json IS NULL OR (jsonb_typeof(request_json)='object' AND octet_length(request_json::text)<=131072)),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id)
);
CREATE TABLE secureshop_agents.bound_pricing_outcomes (
 platform_launch_id uuid NOT NULL,
 platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 operation_id uuid NOT NULL,
 run_id uuid NOT NULL,
 persona_id integer NOT NULL CHECK(persona_id>0),
 persona_session_id uuid NOT NULL,
 persona_role text NOT NULL CHECK(persona_role IN ('customer','merchant')),
 authority_version bigint NOT NULL CHECK(authority_version>0),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 binding_sha256 bytea NOT NULL CHECK(octet_length(binding_sha256)=32),
 state text NOT NULL CHECK(state IN ('completed','unknown','not_executed')),
 receipt_json jsonb CHECK(receipt_json IS NULL OR (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=524288)),
 receipt_sha256 bytea CHECK(receipt_sha256 IS NULL OR octet_length(receipt_sha256)=32),
 CONSTRAINT pricing_outcome_shape CHECK((state IN ('unknown','not_executed') AND receipt_json IS NULL AND receipt_sha256 IS NULL) OR (state='completed' AND receipt_sha256 IS NOT NULL)),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id),
 FOREIGN KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id) REFERENCES secureshop_agents.bound_pricing_admissions(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id)
);
CREATE FUNCTION secureshop_agents.guard_pricing_record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE retired boolean;
BEGIN
 retired:=EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id AND platform_scenario_id=OLD.platform_scenario_id AND from_generation=OLD.platform_launch_generation AND original_platform_owner_id=OLD.original_platform_owner_id AND original_platform_session_id=OLD.original_platform_session_id)
 OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id);
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
 ELSIF retired THEN
  IF TG_TABLE_NAME='bound_pricing_admissions' THEN
   IF NEW.request_json IS NULL AND NEW.target_id IS NULL AND NEW.target_snapshot_json IS NULL AND (to_jsonb(NEW)-'request_json'-'target_id'-'target_snapshot_json')=(to_jsonb(OLD)-'request_json'-'target_id'-'target_snapshot_json') THEN RETURN NEW; END IF;
  ELSIF TG_TABLE_NAME='bound_pricing_outcomes' THEN
   IF NEW.receipt_json IS NULL AND (to_jsonb(NEW)-'receipt_json')=(to_jsonb(OLD)-'receipt_json') THEN RETURN NEW; END IF;
  END IF;
 END IF;
 RAISE EXCEPTION 'Pricing evidence immutable' USING ERRCODE='55000';
END $$;
CREATE FUNCTION secureshop_agents.guard_pricing_actor() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
  JOIN secureshop_agents.bound_persona_templates t ON t.shop_user_id=s.shop_user_id
  LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
  WHERE s.platform_launch_id=NEW.platform_launch_id AND s.platform_scenario_id=NEW.platform_scenario_id AND s.platform_launch_generation=NEW.platform_launch_generation AND s.original_platform_owner_id=NEW.original_platform_owner_id AND s.original_platform_session_id=NEW.original_platform_session_id
  AND s.shop_user_id=NEW.persona_id AND s.session_id=NEW.persona_session_id AND s.role=NEW.persona_role
  AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND st.banned_at IS NULL
  AND COALESCE(st.effective_role,t.role)=NEW.persona_role AND COALESCE(st.authority_version,1)=NEW.authority_version
  AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
   WHERE c.platform_launch_id=NEW.platform_launch_id AND c.platform_scenario_id=NEW.platform_scenario_id AND c.platform_launch_generation=NEW.platform_launch_generation AND c.original_platform_owner_id=NEW.original_platform_owner_id AND c.original_platform_session_id=NEW.original_platform_session_id AND c.shop_user_id=NEW.persona_id),1)) THEN
  RAISE EXCEPTION 'Pricing persona unavailable' USING ERRCODE='55000'; END IF;

 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(':','secureshop-pricing',NEW.platform_launch_id::text,NEW.platform_scenario_id::text,NEW.platform_launch_generation::text,NEW.original_platform_owner_id::text,NEW.original_platform_session_id::text),0));
 IF TG_TABLE_NAME='bound_pricing_admissions' THEN
  IF NEW.target_id IS NULL OR NEW.request_json IS NULL OR NEW.target_snapshot_json IS NULL OR (SELECT count(*) FROM secureshop_agents.bound_pricing_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id)>=128 THEN RAISE EXCEPTION 'Pricing admission quota' USING ERRCODE='55000'; END IF;
  IF (SELECT count(*) FROM secureshop_agents.bound_pricing_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.persona_session_id=NEW.persona_session_id AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_outcomes o WHERE (o.platform_launch_id,o.platform_scenario_id,o.platform_launch_generation,o.original_platform_owner_id,o.original_platform_session_id,o.operation_id)=(a.platform_launch_id,a.platform_scenario_id,a.platform_launch_generation,a.original_platform_owner_id,a.original_platform_session_id,a.operation_id)))>=8 THEN RAISE EXCEPTION 'Pricing pending quota' USING ERRCODE='55000'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.request_json))<>4 OR jsonb_typeof(NEW.request_json->'message') IS DISTINCT FROM 'string' OR NEW.request_json->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR octet_length(NEW.request_json->>'message') NOT BETWEEN 1 AND 8192 OR jsonb_typeof(NEW.request_json->'productId') IS DISTINCT FROM 'number' OR NOT (NEW.request_json->>'productId' ~ '^[1-9][0-9]{0,9}$') OR (NEW.request_json->>'productId')::numeric>2147483647 OR (CASE NEW.persona_role WHEN 'customer' THEN 'price-advisor' ELSE 'pricing-strategy' END) IS DISTINCT FROM NEW.request_json->>'task' THEN RAISE EXCEPTION 'Pricing request mismatch' USING ERRCODE='55000'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.operation_id=NEW.operation_id AND a.run_id=NEW.run_id AND a.persona_id=NEW.persona_id AND a.persona_session_id=NEW.persona_session_id AND a.persona_role=NEW.persona_role AND a.authority_version=NEW.authority_version AND a.request_sha256=NEW.request_sha256 AND a.binding_sha256=NEW.binding_sha256 AND a.request_json IS NOT NULL AND a.target_id IS NOT NULL AND (NEW.state<>'completed' OR (NEW.receipt_json->>'targetId'=a.target_id::text AND NEW.receipt_json->>'version'='secureshop-pricing-execution.v1' AND NEW.receipt_json->>'operationId'=a.operation_id::text AND NEW.receipt_json->>'runId'=a.run_id::text AND NEW.receipt_json->>'requestSha256'=encode(a.request_sha256,'hex')))) OR (NEW.state='completed' AND NEW.receipt_json IS NULL) THEN RAISE EXCEPTION 'Pricing admission mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER a_pricing_admissions_insert BEFORE INSERT ON secureshop_agents.bound_pricing_admissions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER b_pricing_admissions_actor BEFORE INSERT ON secureshop_agents.bound_pricing_admissions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_pricing_actor();
CREATE TRIGGER pricing_admissions_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_pricing_admissions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_pricing_record();
CREATE TRIGGER a_pricing_outcomes_insert BEFORE INSERT ON secureshop_agents.bound_pricing_outcomes FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER b_pricing_outcomes_actor BEFORE INSERT ON secureshop_agents.bound_pricing_outcomes FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_pricing_actor();
CREATE TRIGGER pricing_outcomes_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_pricing_outcomes FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_pricing_record();
CREATE TABLE secureshop_agents.bound_pricing_cleanup_receipts (
 cleanup_id uuid PRIMARY KEY, cleanup_kind text NOT NULL CHECK(cleanup_kind IN ('retirement','owner_deletion')),
 original_platform_owner_id integer NOT NULL, platform_launch_id uuid, platform_launch_generation bigint,
 admission_count integer NOT NULL, outcome_count integer NOT NULL, receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32));
CREATE TRIGGER pricing_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_pricing_cleanup_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_owner_deletion_receipt();
CREATE FUNCTION secureshop_agents.cleanup_pricing_records() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer; m integer; id uuid; kind text; l uuid; g bigint;
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
 id:=NEW.reset_id;kind:='retirement';l:=NEW.platform_launch_id;g:=NEW.from_generation;
 UPDATE secureshop_agents.bound_pricing_admissions SET request_json=NULL,target_id=NULL,target_snapshot_json=NULL WHERE platform_launch_id=l AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;GET DIAGNOSTICS n=ROW_COUNT;
 UPDATE secureshop_agents.bound_pricing_outcomes SET receipt_json=NULL WHERE platform_launch_id=l AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;GET DIAGNOSTICS m=ROW_COUNT;
 ELSE
 id:=NEW.deletion_job_id;kind:='owner_deletion';
 DELETE FROM secureshop_agents.bound_pricing_outcomes WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS m=ROW_COUNT;
 DELETE FROM secureshop_agents.bound_pricing_admissions WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS n=ROW_COUNT;
 END IF;
 INSERT INTO secureshop_agents.bound_pricing_cleanup_receipts VALUES(id,kind,NEW.original_platform_owner_id,l,g,n,m,sha256(convert_to(jsonb_build_array(id,kind,NEW.original_platform_owner_id,l,g,n,m)::text,'UTF8')));
 RETURN NEW;
END $$;
CREATE TRIGGER pricing_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_pricing_records();
CREATE TRIGGER pricing_owner_delete AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_pricing_records();
REVOKE ALL ON secureshop_agents.bound_pricing_admissions,secureshop_agents.bound_pricing_outcomes,secureshop_agents.bound_pricing_cleanup_receipts FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_pricing_admissions,secureshop_agents.bound_pricing_outcomes TO dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_pricing_cleanup_receipts TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_pricing_actor(),secureshop_agents.guard_pricing_record(),secureshop_agents.cleanup_pricing_records() FROM PUBLIC,dvaia_secureshop_agents_runtime;
-- Retirement redacts payloads only; immutable digests/coordinates remain until owned deletion.

-- Preserve every existing purpose through qualified Analytics0032 (no further
-- purpose changes in0032). Pricing0033 remains unregistered pending native proof.
ALTER TABLE secureshop_agents.agent_sessions DROP CONSTRAINT agent_sessions_conversation_purpose_shape;
ALTER TABLE secureshop_agents.agent_sessions ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
 conversation_purpose IN ('general','mcp_rogue_registration','mcp_rug_pull','persona_inbox','controlled_ssrf','review_moderation','secureshop_refund_request','secureshop_product_assist','secureshop_product_manual_ingest','secureshop_audit_summary','secureshop_audit_sql','secureshop_analytics','secureshop_price_advisor','secureshop_pricing_strategy')
 AND (authority_mode='launch_bound' OR conversation_purpose='general')
);
