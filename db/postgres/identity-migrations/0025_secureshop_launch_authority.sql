-- Durable SecureShop launch authority. No live route is enabled by this schema.
-- Authority lifecycle is separate from external target cleanup and grading.
CREATE TABLE identity.secureshop_launches (
  launch_id uuid PRIMARY KEY,
  platform_session_id integer UNIQUE
    REFERENCES identity.user_sessions(id) ON DELETE SET NULL,
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  handle_hash bytea NOT NULL UNIQUE CHECK (octet_length(handle_hash) = 32),
  scenario_id uuid NOT NULL UNIQUE,
  generation bigint NOT NULL DEFAULT 1
    CHECK (generation BETWEEN 1 AND 9007199254740991),
  credential_version bigint NOT NULL DEFAULT 1
    CHECK (credential_version BETWEEN 1 AND 9007199254740991),
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'resetting', 'revoked')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  revoke_reason text,
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CHECK (expires_at > created_at)
);

CREATE INDEX secureshop_launch_expiry
  ON identity.secureshop_launches (expires_at)
  WHERE status IN ('active', 'resetting');

CREATE TABLE identity.secureshop_launch_resets (
  reset_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL
    REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  from_generation bigint NOT NULL CHECK (from_generation >= 1),
  to_generation bigint NOT NULL
    CHECK (to_generation = from_generation + 1
      AND to_generation <= 9007199254740991),
  idempotency_hash bytea NOT NULL CHECK (octet_length(idempotency_hash) = 32),
  status text NOT NULL DEFAULT 'fenced'
    CHECK (status IN ('fenced', 'committed', 'aborted')),
  -- Authority commit/abort does not prove external target cleanup. A future
  -- receipt-verifying reconciler is the only component allowed to clear this.
  reconciliation_required boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  committed_at timestamptz,
  aborted_at timestamptz,
  abort_reason text,
  UNIQUE (launch_id, to_generation),
  UNIQUE (launch_id, idempotency_hash),
  CHECK ((status = 'committed') = (committed_at IS NOT NULL)),
  CHECK ((status = 'aborted') = (aborted_at IS NOT NULL))
);

CREATE INDEX secureshop_launch_reset_pending
  ON identity.secureshop_launch_resets (updated_at)
  WHERE reconciliation_required;

-- The copied identifiers are nonsecret cleanup/audit coordinates. They are
-- checked against the live trusted session at insertion, immutable afterward,
-- and must never be used by resolution or effect authorization.
CREATE FUNCTION identity.validate_secureshop_launch_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actual_owner integer;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.platform_session_id IS NULL
       OR NEW.original_platform_session_id <> NEW.platform_session_id THEN
      RAISE EXCEPTION 'SecureShop launch cleanup identity is invalid';
    END IF;
    SELECT s.user_id INTO actual_owner FROM identity.user_sessions s
      WHERE s.id = NEW.platform_session_id;
    IF actual_owner IS NULL OR NEW.original_platform_owner_id <> actual_owner THEN
      RAISE EXCEPTION 'SecureShop launch cleanup identity is invalid';
    END IF;
  ELSIF NEW.launch_id IS DISTINCT FROM OLD.launch_id
     OR NEW.original_platform_session_id IS DISTINCT FROM OLD.original_platform_session_id
     OR NEW.original_platform_owner_id IS DISTINCT FROM OLD.original_platform_owner_id
     OR NEW.scenario_id IS DISTINCT FROM OLD.scenario_id
     OR NOT (NEW.platform_session_id IS NOT DISTINCT FROM OLD.platform_session_id
       OR (OLD.platform_session_id IS NOT NULL AND NEW.platform_session_id IS NULL)) THEN
    RAISE EXCEPTION 'SecureShop launch cleanup identity is immutable';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER secureshop_launch_identity_guard
BEFORE INSERT OR UPDATE ON identity.secureshop_launches
FOR EACH ROW EXECUTE FUNCTION identity.validate_secureshop_launch_identity();

-- Session deletion retains a nonsecret launch/scenario/generation tombstone.
-- Session revocation fences the launch and any reset journal before callers can
-- observe the inactive session. Expiry remains fail-closed in every lookup and
-- is materialized here when the existing cleanup path deletes the session.
CREATE FUNCTION identity.fence_secureshop_launch_on_session_end()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected_launch uuid;
BEGIN
  IF TG_OP = 'DELETE' OR (OLD.is_active = 1 AND NEW.is_active = 0) THEN
    UPDATE identity.secureshop_launches
       SET status = 'revoked', revoked_at = COALESCE(revoked_at, clock_timestamp()),
           revoke_reason = COALESCE(revoke_reason,
             CASE WHEN TG_OP = 'DELETE' THEN 'platform_session_deleted' ELSE 'platform_session_revoked' END),
           updated_at = clock_timestamp()
     WHERE platform_session_id = OLD.id AND status <> 'revoked'
     RETURNING launch_id INTO affected_launch;
    IF affected_launch IS NOT NULL THEN
      UPDATE identity.secureshop_launch_resets
         SET status = 'aborted', aborted_at = clock_timestamp(),
             abort_reason = 'platform_session_unavailable', updated_at = clock_timestamp()
       WHERE launch_id = affected_launch AND status = 'fenced';
    END IF;
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;

CREATE TRIGGER secureshop_launch_session_fence
BEFORE UPDATE OF is_active OR DELETE ON identity.user_sessions
FOR EACH ROW EXECUTE FUNCTION identity.fence_secureshop_launch_on_session_end();

CREATE FUNCTION identity.fence_secureshop_launch_on_user_end()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR (OLD.is_active = 1 AND NEW.is_active = 0) THEN
    -- Match repository lock order: user (held by the triggering statement),
    -- every session in stable order, launches, then reset journals.
    PERFORM s.id FROM identity.user_sessions s
      WHERE s.user_id = OLD.id ORDER BY s.id FOR UPDATE OF s;
    UPDATE identity.secureshop_launches l
       SET status = 'revoked', revoked_at = COALESCE(l.revoked_at, clock_timestamp()),
           revoke_reason = COALESCE(l.revoke_reason, 'platform_owner_unavailable'),
           updated_at = clock_timestamp()
     FROM identity.user_sessions s
     WHERE l.platform_session_id = s.id AND s.user_id = OLD.id AND l.status <> 'revoked';
    UPDATE identity.secureshop_launch_resets
       SET status = 'aborted', aborted_at = clock_timestamp(),
           abort_reason = 'platform_owner_unavailable', updated_at = clock_timestamp()
     WHERE status = 'fenced' AND launch_id IN (
       SELECT l.launch_id FROM identity.secureshop_launches l
       JOIN identity.user_sessions s ON s.id = l.platform_session_id
       WHERE s.user_id = OLD.id
     );
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;

CREATE TRIGGER secureshop_launch_user_fence
BEFORE UPDATE OF is_active OR DELETE ON identity.users
FOR EACH ROW EXECUTE FUNCTION identity.fence_secureshop_launch_on_user_end();

REVOKE ALL ON FUNCTION identity.fence_secureshop_launch_on_session_end() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.fence_secureshop_launch_on_user_end() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.validate_secureshop_launch_identity() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.fence_secureshop_launch_on_session_end() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.fence_secureshop_launch_on_user_end() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_launch_identity() TO dvaia_identity_runtime;

GRANT SELECT, INSERT, UPDATE ON
  identity.secureshop_launches,
  identity.secureshop_launch_resets
TO dvaia_identity_runtime;
