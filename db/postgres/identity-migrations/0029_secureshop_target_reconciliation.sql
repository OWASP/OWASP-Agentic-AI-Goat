-- Draft identity migration. Do not register in startup migrations yet.
-- History proves only that a private target receipt was verified before the
-- active reservation was removed. It does not complete a reset or deletion.
CREATE TABLE identity.secureshop_target_cleanup_history (
  target_id uuid PRIMARY KEY,
  target_kind text NOT NULL CHECK (target_kind IN ('files','reviews')),
  launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  scenario_id uuid NOT NULL,
  from_generation bigint NOT NULL CHECK (from_generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  operation_id uuid NOT NULL REFERENCES identity.secureshop_launch_resets(reset_id) ON DELETE RESTRICT,
  target_receipt_version integer NOT NULL CHECK (target_receipt_version = 1),
  target_receipt_sha256 bytea NOT NULL CHECK (octet_length(target_receipt_sha256) = 32),
  target_completed_at timestamptz NOT NULL,
  resolved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (operation_id,target_kind)
);

CREATE FUNCTION identity.validate_secureshop_target_cleanup_history()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
DECLARE reset_authority identity.secureshop_launch_resets%ROWTYPE;
DECLARE reservation identity.secureshop_target_reservations%ROWTYPE;
BEGIN
  -- Match the authority repository's global order: launch, reset journal, then
  -- target reservation. These locks make the insert decision stable until the
  -- history row and reservation retirement commit together.
  SELECT * INTO authority FROM identity.secureshop_launches
    WHERE launch_id=NEW.launch_id FOR UPDATE;
  SELECT * INTO reset_authority FROM identity.secureshop_launch_resets
    WHERE reset_id=NEW.operation_id FOR UPDATE;
  SELECT * INTO reservation FROM identity.secureshop_target_reservations
    WHERE target_id=NEW.target_id FOR UPDATE;
  IF reservation.target_id IS NULL OR authority.launch_id IS NULL
     OR reset_authority.reset_id IS NULL
     OR reservation.launch_id <> NEW.launch_id
     OR reservation.generation <> NEW.from_generation
     OR reservation.target_kind <> NEW.target_kind
     OR reservation.original_platform_owner_id <> NEW.original_platform_owner_id
     OR reset_authority.launch_id <> NEW.launch_id
     OR reset_authority.from_generation <> NEW.from_generation
     OR authority.scenario_id <> NEW.scenario_id
     OR authority.original_platform_owner_id <> NEW.original_platform_owner_id
     OR authority.original_platform_session_id <> NEW.original_platform_session_id THEN
    RAISE EXCEPTION 'SecureShop cleanup history binding is invalid';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION identity.guard_secureshop_target_cleanup_history()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'SecureShop cleanup history is immutable' USING ERRCODE='55000';
END $$;

CREATE FUNCTION identity.resolve_secureshop_target_reservation(p_target_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
DECLARE removed integer;
BEGIN
  DELETE FROM identity.secureshop_target_reservations r
  USING identity.secureshop_target_cleanup_history h,
        identity.secureshop_launches l
  WHERE r.target_id=p_target_id AND h.target_id=r.target_id
    AND l.launch_id=r.launch_id AND h.launch_id=r.launch_id
    AND h.target_kind=r.target_kind AND h.from_generation=r.generation
    AND h.original_platform_owner_id=r.original_platform_owner_id
    AND h.scenario_id=l.scenario_id
    AND h.original_platform_session_id=l.original_platform_session_id;
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed=1;
END $$;

CREATE TRIGGER secureshop_target_cleanup_history_validate
BEFORE INSERT ON identity.secureshop_target_cleanup_history
FOR EACH ROW EXECUTE FUNCTION identity.validate_secureshop_target_cleanup_history();
CREATE TRIGGER secureshop_target_cleanup_history_immutable
BEFORE UPDATE OR DELETE ON identity.secureshop_target_cleanup_history
FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_target_cleanup_history();

REVOKE ALL ON TABLE identity.secureshop_target_cleanup_history FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.validate_secureshop_target_cleanup_history() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_target_cleanup_history() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.resolve_secureshop_target_reservation(uuid) FROM PUBLIC;
GRANT SELECT,INSERT ON TABLE identity.secureshop_target_cleanup_history TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_target_cleanup_history() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.guard_secureshop_target_cleanup_history() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.resolve_secureshop_target_reservation(uuid) TO dvaia_identity_runtime;
