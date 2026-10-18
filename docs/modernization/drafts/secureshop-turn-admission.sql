-- DRAFT: not auto-applied. Qualify against fresh/populated agents databases
-- before assigning the next forward-only migration number.
CREATE TABLE secureshop_agents.turn_requests (
  session_id text NOT NULL REFERENCES secureshop_agents.agent_sessions(id),
  request_id uuid NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
  request_version smallint NOT NULL DEFAULT 1 CHECK (request_version=1),
  claim_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'started' CHECK (status IN ('started','completed','uncertain')),
  result_json jsonb,
  CHECK (result_json IS NULL OR octet_length(result_json::text) <= 262144),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_at timestamptz,
  PRIMARY KEY(session_id,request_id),
  CHECK ((status='started' AND result_json IS NULL AND finished_at IS NULL)
    OR (status='completed' AND result_json IS NOT NULL AND jsonb_typeof(result_json)='object' AND finished_at IS NOT NULL)
    OR (status='uncertain' AND result_json IS NULL AND finished_at IS NOT NULL))
);

CREATE FUNCTION secureshop_agents.guard_turn_request() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Turn request history cannot be deleted';
  END IF;
  IF TG_OP='INSERT' THEN
    -- Hold a shared row lock through insertion so an active conversation cannot
    -- be abandoned between its admission check and the durable turn claim.
    PERFORM 1 FROM secureshop_agents.agent_sessions
      WHERE id=NEW.session_id AND authority_mode='launch_bound' AND binding_state='active'
      FOR SHARE;
    IF NEW.status <> 'started' OR NOT FOUND THEN
      RAISE EXCEPTION 'Turn requires an active bound conversation';
    END IF;
  ELSE
    IF ROW(NEW.session_id,NEW.request_id,NEW.request_hash,NEW.request_version,NEW.claim_id,NEW.created_at)
      IS DISTINCT FROM ROW(OLD.session_id,OLD.request_id,OLD.request_hash,OLD.request_version,OLD.claim_id,OLD.created_at)
      OR OLD.status <> 'started' OR NEW.status NOT IN ('completed','uncertain') THEN
      RAISE EXCEPTION 'Turn identity and terminal state are immutable';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER turn_request_guard BEFORE INSERT OR UPDATE OR DELETE
ON secureshop_agents.turn_requests FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_turn_request();
REVOKE ALL ON FUNCTION secureshop_agents.guard_turn_request() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_agents.turn_requests TO dvaia_secureshop_agents_runtime;
