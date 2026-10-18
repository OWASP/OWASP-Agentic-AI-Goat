-- DRAFT ONLY. Launch-owned MCP trust exercise storage. It deliberately does
-- not reuse the legacy global MCP registry/cache/history teaching sink.
CREATE TABLE secureshop_agents.bound_mcp_targets (
  target_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id>=1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id>=1),
  server_identity text NOT NULL CHECK (octet_length(server_identity) BETWEEN 1 AND 128),
  trust_scenario text NOT NULL CHECK (trust_scenario IN ('rogue_registration','rug_pull')),
  lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','retired')),
  current_schema_version integer NOT NULL DEFAULT 0 CHECK (current_schema_version BETWEEN 0 AND 16),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  UNIQUE(launch_id,generation,trust_scenario),
  CHECK ((lifecycle='retired')=(retired_at IS NOT NULL))
);

CREATE TABLE secureshop_agents.bound_mcp_schema_versions (
  target_id uuid NOT NULL REFERENCES secureshop_agents.bound_mcp_targets(target_id) ON DELETE RESTRICT,
  version integer NOT NULL CHECK (version BETWEEN 1 AND 16),
  schema_sha256 bytea NOT NULL CHECK (octet_length(schema_sha256)=32),
  discovery_receipt_sha256 bytea NOT NULL CHECK (octet_length(discovery_receipt_sha256)=32),
  discovered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(target_id,version),
  UNIQUE(target_id,schema_sha256)
);

CREATE TABLE secureshop_agents.bound_mcp_tool_payloads (
  target_id uuid NOT NULL,
  version integer NOT NULL,
  tools_json jsonb NOT NULL CHECK (jsonb_typeof(tools_json)='array'),
  PRIMARY KEY(target_id,version),
  FOREIGN KEY(target_id,version) REFERENCES secureshop_agents.bound_mcp_schema_versions(target_id,version)
    ON DELETE RESTRICT
);

CREATE TABLE secureshop_agents.bound_mcp_invocations (
  invocation_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE,
  target_id uuid NOT NULL,
  schema_version integer NOT NULL,
  schema_sha256 bytea NOT NULL CHECK (octet_length(schema_sha256)=32),
  run_id uuid NOT NULL,
  request_id uuid NOT NULL,
  call_id text NOT NULL CHECK (octet_length(call_id) BETWEEN 1 AND 128),
  tool_name text NOT NULL CHECK (octet_length(tool_name) BETWEEN 1 AND 128),
  arguments_sha256 bytea NOT NULL CHECK (octet_length(arguments_sha256)=32),
  remote_receipt_sha256 bytea NOT NULL CHECK (octet_length(remote_receipt_sha256)=32),
  trust_policy_sha256 bytea NOT NULL CHECK (octet_length(trust_policy_sha256)=32),
  approved boolean NOT NULL,
  server_approved boolean NOT NULL,
  schema_approved boolean NOT NULL,
  trust_scenario text NOT NULL CHECK (trust_scenario IN ('rogue_registration','rug_pull')),
  behavior_class text NOT NULL CHECK (behavior_class IN ('public_forecast_lookup','protected_record_export')),
  result_sha256 bytea NOT NULL CHECK (octet_length(result_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(target_id,schema_version) REFERENCES secureshop_agents.bound_mcp_schema_versions(target_id,version),
  UNIQUE(target_id,run_id,call_id),
  CHECK (approved=(server_approved AND schema_approved))
);

CREATE TABLE secureshop_agents.bound_mcp_cleanup_receipts (
  operation_id uuid NOT NULL,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_agents.bound_mcp_targets(target_id),
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL,
  original_platform_owner_id integer NOT NULL,
  original_platform_session_id integer NOT NULL,
  deleted_payload_count integer NOT NULL CHECK (deleted_payload_count BETWEEN 0 AND 16),
  retained_invocation_count integer NOT NULL CHECK (retained_invocation_count BETWEEN 0 AND 4096),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(operation_id,target_id)
);

CREATE FUNCTION secureshop_agents.guard_bound_mcp_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  RAISE EXCEPTION 'Bound MCP evidence is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_mcp_schema_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_mcp_schema_versions
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_mcp_immutable();
CREATE TRIGGER bound_mcp_invocation_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_mcp_invocations
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_mcp_immutable();
CREATE TRIGGER bound_mcp_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_mcp_cleanup_receipts
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_mcp_immutable();

-- Only the reset composition receives EXECUTE on this function. It locks the
-- target, tombstones it, removes model-visible tool payloads, and retains the
-- schema/invocation digests needed to audit accepted historical credit.
CREATE FUNCTION secureshop_agents.retire_bound_mcp_target(requested_operation uuid,requested_target uuid,
  requested_launch uuid,requested_scenario uuid,requested_generation bigint,requested_owner integer,
  requested_session integer,requested_receipt_sha256 bytea)
RETURNS SETOF secureshop_agents.bound_mcp_cleanup_receipts LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.bound_mcp_targets%ROWTYPE;
DECLARE prior secureshop_agents.bound_mcp_cleanup_receipts%ROWTYPE;
DECLARE payloads integer;DECLARE invocations integer;
BEGIN
  SELECT * INTO target FROM secureshop_agents.bound_mcp_targets t WHERE t.target_id=requested_target
    AND t.launch_id=requested_launch AND t.scenario_id=requested_scenario AND t.generation=requested_generation
    AND t.original_platform_owner_id=requested_owner AND t.original_platform_session_id=requested_session FOR UPDATE;
  IF target.target_id IS NULL THEN RAISE EXCEPTION 'Bound MCP target unavailable' USING ERRCODE='55000'; END IF;
  -- One launch reset legitimately retires the rogue and rug-pull targets with
  -- the same operation. Serialize that operation and reject reuse in another
  -- launch scope while retaining one immutable receipt per target.
  PERFORM pg_advisory_xact_lock(hashtextextended('bound-mcp-cleanup-operation:'||requested_operation::text,0));
  IF EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_cleanup_receipts r
    WHERE r.operation_id=requested_operation AND (r.launch_id<>requested_launch OR r.scenario_id<>requested_scenario
      OR r.generation<>requested_generation OR r.original_platform_owner_id<>requested_owner
      OR r.original_platform_session_id<>requested_session))
  THEN RAISE EXCEPTION 'Bound MCP cleanup operation scope mismatch' USING ERRCODE='55000'; END IF;
  SELECT * INTO prior FROM secureshop_agents.bound_mcp_cleanup_receipts r WHERE r.target_id=requested_target;
  IF prior.target_id IS NOT NULL THEN
    IF prior.target_id<>requested_target OR prior.operation_id<>requested_operation
      OR prior.launch_id<>requested_launch OR prior.scenario_id<>requested_scenario
      OR prior.generation<>requested_generation OR prior.original_platform_owner_id<>requested_owner
      OR prior.original_platform_session_id<>requested_session OR prior.receipt_sha256<>requested_receipt_sha256
      OR target.lifecycle<>'retired' OR EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_tool_payloads p WHERE p.target_id=requested_target)
    THEN RAISE EXCEPTION 'Bound MCP cleanup replay mismatch' USING ERRCODE='55000'; END IF;
    RETURN NEXT prior;RETURN;
  END IF;
  IF target.lifecycle<>'active' OR octet_length(requested_receipt_sha256)<>32 THEN
    RAISE EXCEPTION 'Bound MCP cleanup invalid' USING ERRCODE='55000';
  END IF;
  SELECT count(*) INTO payloads FROM secureshop_agents.bound_mcp_tool_payloads p WHERE p.target_id=requested_target;
  SELECT count(*) INTO invocations FROM secureshop_agents.bound_mcp_invocations i WHERE i.target_id=requested_target;
  DELETE FROM secureshop_agents.bound_mcp_tool_payloads p WHERE p.target_id=requested_target;
  UPDATE secureshop_agents.bound_mcp_targets SET lifecycle='retired',retired_at=clock_timestamp()
    WHERE target_id=requested_target;
  INSERT INTO secureshop_agents.bound_mcp_cleanup_receipts(operation_id,target_id,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id,deleted_payload_count,retained_invocation_count,receipt_sha256)
  VALUES(requested_operation,requested_target,requested_launch,requested_scenario,requested_generation,
    requested_owner,requested_session,payloads,invocations,requested_receipt_sha256) RETURNING * INTO prior;
  RETURN NEXT prior;
END $$;

REVOKE ALL ON secureshop_agents.bound_mcp_targets,secureshop_agents.bound_mcp_schema_versions,
  secureshop_agents.bound_mcp_tool_payloads,secureshop_agents.bound_mcp_invocations,
  secureshop_agents.bound_mcp_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.retire_bound_mcp_target(uuid,uuid,uuid,uuid,bigint,integer,integer,bytea),
  secureshop_agents.guard_bound_mcp_immutable() FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.bound_mcp_targets,secureshop_agents.bound_mcp_schema_versions,
  secureshop_agents.bound_mcp_tool_payloads,secureshop_agents.bound_mcp_invocations
  TO dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_mcp_cleanup_receipts TO dvaia_secureshop_agents_runtime;
GRANT UPDATE(current_schema_version) ON secureshop_agents.bound_mcp_targets TO dvaia_secureshop_agents_runtime;
GRANT EXECUTE ON FUNCTION secureshop_agents.retire_bound_mcp_target(uuid,uuid,uuid,uuid,bigint,integer,integer,bytea)
  TO dvaia_secureshop_agents_runtime;
