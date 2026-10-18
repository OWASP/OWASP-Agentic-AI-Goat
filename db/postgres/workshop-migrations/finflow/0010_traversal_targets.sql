-- Durable, owner-bound controlled traversal targets. Retired bindings are immutable history.
CREATE TABLE finflow.traversal_targets (
  owner_key text NOT NULL,
  generation bigint NOT NULL CHECK (generation >= 0),
  target_token uuid NOT NULL UNIQUE,
  state text NOT NULL CHECK (state IN ('provisioning','active','cleanup_debt','retired')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  retired_at timestamptz,
  cleanup_error_code text CHECK (cleanup_error_code IS NULL OR cleanup_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  PRIMARY KEY (owner_key, generation)
);
CREATE FUNCTION finflow.guard_traversal_target_immutability()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF OLD.state = 'retired' THEN
    RAISE EXCEPTION 'Retired FinFlow traversal target is immutable' USING ERRCODE='23514';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  IF NEW.owner_key <> OLD.owner_key OR NEW.generation <> OLD.generation
      OR NEW.target_token <> OLD.target_token OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'FinFlow traversal target binding is immutable' USING ERRCODE='23514';
  END IF;
  IF NOT ((OLD.state = 'provisioning' AND NEW.state IN ('provisioning','active','cleanup_debt'))
      OR (OLD.state = 'active' AND NEW.state IN ('active','cleanup_debt'))
      OR (OLD.state = 'cleanup_debt' AND NEW.state IN ('cleanup_debt','retired'))) THEN
    RAISE EXCEPTION 'Invalid FinFlow traversal target transition' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER finflow_traversal_target_immutability BEFORE UPDATE OR DELETE
  ON finflow.traversal_targets FOR EACH ROW
  EXECUTE FUNCTION finflow.guard_traversal_target_immutability();
REVOKE ALL ON finflow.traversal_targets FROM PUBLIC;
REVOKE ALL ON FUNCTION finflow.guard_traversal_target_immutability() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON finflow.traversal_targets TO dvaia_finflow_runtime;
