-- DRAFT ONLY. Unnumbered, unregistered and default-off.
-- Stores authority and immutable receipts; owned public/private payload bytes remain on disk.
CREATE TABLE secureshop_agents.bound_ssrf_targets (
  target_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','retired')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  UNIQUE (launch_id,generation),
  CHECK ((lifecycle='retired')=(retired_at IS NOT NULL))
);

CREATE TABLE secureshop_agents.bound_ssrf_requests (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL REFERENCES secureshop_agents.bound_ssrf_targets(target_id) ON DELETE RESTRICT,
  request_id uuid NOT NULL,
  resource_kind text NOT NULL CHECK (resource_kind IN ('public-policy','private-policy')),
  nonce uuid,
  issued_url text CHECK (issued_url IS NULL OR octet_length(issued_url) BETWEEN 1 AND 512),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (target_id,request_id),
  CHECK ((nonce IS NULL)=(issued_url IS NULL))
);

CREATE TABLE secureshop_agents.bound_ssrf_invocations (
  operation_id uuid PRIMARY KEY REFERENCES secureshop_agents.bound_ssrf_requests(operation_id) ON DELETE RESTRICT,
  target_id uuid NOT NULL REFERENCES secureshop_agents.bound_ssrf_targets(target_id) ON DELETE RESTRICT,
  run_id uuid NOT NULL,
  request_id uuid NOT NULL,
  session_id text NOT NULL CHECK (octet_length(session_id) BETWEEN 1 AND 256),
  call_id text NOT NULL CHECK (octet_length(call_id) BETWEEN 1 AND 128),
  arguments_sha256 bytea NOT NULL CHECK (octet_length(arguments_sha256)=32),
  result_sha256 bytea NOT NULL CHECK (octet_length(result_sha256)=32),
  response_sha256 bytea NOT NULL CHECK (octet_length(response_sha256)=32),
  egress_receipt_sha256 bytea NOT NULL CHECK (octet_length(egress_receipt_sha256)=32),
  egress_policy_sha256 bytea NOT NULL CHECK (octet_length(egress_policy_sha256)=32),
  request_method text NOT NULL CHECK (request_method='GET'),
  request_path text NOT NULL CHECK (octet_length(request_path) BETWEEN 1 AND 256),
  response_status integer NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  resource_kind text NOT NULL CHECK (resource_kind IN ('public-policy','private-policy')),
  policy_decision text NOT NULL CHECK (policy_decision IN ('allowed','denied')),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (target_id,request_id),
  CHECK ((resource_kind='public-policy')=(policy_decision='allowed'))
);

CREATE TABLE secureshop_agents.bound_ssrf_cleanup_receipts (
  operation_id uuid NOT NULL,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_agents.bound_ssrf_targets(target_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL,
  original_platform_owner_id integer NOT NULL,
  original_platform_session_id integer NOT NULL,
  retained_request_count integer NOT NULL CHECK (retained_request_count >= 0),
  retained_invocation_count integer NOT NULL CHECK (retained_invocation_count >= 0),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (operation_id,target_id)
);

CREATE FUNCTION secureshop_agents.guard_bound_ssrf_request() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Bound SSRF request is immutable' USING ERRCODE='55000'; END IF;
  IF NEW.operation_id<>OLD.operation_id OR NEW.target_id<>OLD.target_id
    OR NEW.request_id<>OLD.request_id OR NEW.resource_kind<>OLD.resource_kind OR NEW.created_at<>OLD.created_at
    OR OLD.nonce IS NOT NULL OR NEW.nonce IS NULL OR NEW.issued_url IS NULL
  THEN RAISE EXCEPTION 'Bound SSRF request is immutable' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER bound_ssrf_requests_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_ssrf_requests
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_ssrf_request();
CREATE FUNCTION secureshop_agents.guard_bound_ssrf_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Bound SSRF audit rows are immutable' USING ERRCODE='55000'; END $$;
CREATE TRIGGER bound_ssrf_invocations_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_ssrf_invocations
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_ssrf_immutable();
CREATE TRIGGER bound_ssrf_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_ssrf_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_ssrf_immutable();

CREATE FUNCTION secureshop_agents.retire_bound_ssrf_target(requested_operation uuid,requested_target uuid,
  requested_launch uuid,requested_scenario uuid,requested_generation bigint,requested_owner integer,
  requested_session integer,requested_receipt bytea)
RETURNS SETOF secureshop_agents.bound_ssrf_cleanup_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.bound_ssrf_targets%ROWTYPE; prior secureshop_agents.bound_ssrf_cleanup_receipts%ROWTYPE;
  operation_prior secureshop_agents.bound_ssrf_cleanup_receipts%ROWTYPE;
  requests integer; invocations integer;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(requested_target::text,0));
  SELECT * INTO target FROM secureshop_agents.bound_ssrf_targets WHERE target_id=requested_target FOR UPDATE;
  IF target.target_id IS NULL OR target.launch_id<>requested_launch OR target.scenario_id<>requested_scenario
    OR target.generation<>requested_generation OR target.original_platform_owner_id<>requested_owner
    OR target.original_platform_session_id<>requested_session THEN
    RAISE EXCEPTION 'Bound SSRF cleanup scope mismatch' USING ERRCODE='55000';
  END IF;
  SELECT * INTO operation_prior FROM secureshop_agents.bound_ssrf_cleanup_receipts
    WHERE operation_id=requested_operation ORDER BY target_id LIMIT 1;
  IF operation_prior.target_id IS NOT NULL AND (operation_prior.launch_id<>requested_launch
    OR operation_prior.scenario_id<>requested_scenario OR operation_prior.generation<>requested_generation
    OR operation_prior.original_platform_owner_id<>requested_owner
    OR operation_prior.original_platform_session_id<>requested_session) THEN
    RAISE EXCEPTION 'Bound SSRF cleanup operation scope mismatch' USING ERRCODE='55000';
  END IF;
  SELECT * INTO prior FROM secureshop_agents.bound_ssrf_cleanup_receipts WHERE target_id=requested_target;
  IF prior.target_id IS NOT NULL THEN
    IF prior.operation_id<>requested_operation OR prior.launch_id<>requested_launch OR prior.scenario_id<>requested_scenario
      OR prior.generation<>requested_generation OR prior.original_platform_owner_id<>requested_owner
      OR prior.original_platform_session_id<>requested_session OR prior.receipt_sha256<>requested_receipt
      OR target.lifecycle<>'retired' THEN RAISE EXCEPTION 'Bound SSRF cleanup replay mismatch' USING ERRCODE='55000'; END IF;
    RETURN NEXT prior; RETURN;
  END IF;
  IF target.lifecycle<>'active' OR octet_length(requested_receipt)<>32 THEN
    RAISE EXCEPTION 'Bound SSRF cleanup invalid' USING ERRCODE='55000';
  END IF;
  SELECT count(*) INTO requests FROM secureshop_agents.bound_ssrf_requests WHERE target_id=requested_target;
  SELECT count(*) INTO invocations FROM secureshop_agents.bound_ssrf_invocations WHERE target_id=requested_target;
  UPDATE secureshop_agents.bound_ssrf_targets SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=requested_target;
  INSERT INTO secureshop_agents.bound_ssrf_cleanup_receipts(operation_id,target_id,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id,retained_request_count,retained_invocation_count,receipt_sha256)
  VALUES(requested_operation,requested_target,requested_launch,requested_scenario,requested_generation,
    requested_owner,requested_session,requests,invocations,requested_receipt) RETURNING * INTO prior;
  RETURN NEXT prior;
END $$;

REVOKE ALL ON secureshop_agents.bound_ssrf_targets,secureshop_agents.bound_ssrf_requests,
  secureshop_agents.bound_ssrf_invocations,secureshop_agents.bound_ssrf_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.retire_bound_ssrf_target(uuid,uuid,uuid,uuid,bigint,integer,integer,bytea),
  secureshop_agents.guard_bound_ssrf_request(),secureshop_agents.guard_bound_ssrf_immutable() FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.bound_ssrf_targets,secureshop_agents.bound_ssrf_requests,
  secureshop_agents.bound_ssrf_invocations TO dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_ssrf_cleanup_receipts TO dvaia_secureshop_agents_runtime;
GRANT UPDATE(nonce,issued_url) ON secureshop_agents.bound_ssrf_requests TO dvaia_secureshop_agents_runtime;
GRANT EXECUTE ON FUNCTION secureshop_agents.retire_bound_ssrf_target(uuid,uuid,uuid,uuid,bigint,integer,integer,bytea)
  TO dvaia_secureshop_agents_runtime;
