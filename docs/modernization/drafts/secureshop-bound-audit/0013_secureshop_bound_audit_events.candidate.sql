-- CANDIDATE ONLY: proposed secureshop_review/0013 migration.
--
-- This store-local journal is distinct from agent traces and the legacy global
-- audit table. Writers must append it in the same transaction as the effect
-- named by source_kind/source_id. The application supplies only server-resolved
-- launch, owner, session, and authenticated shop-persona coordinates.

CREATE TABLE secureshop_review.bound_audit_owner_deletion_receipts (
  deletion_job_id uuid PRIMARY KEY,
  original_platform_owner_id integer NOT NULL UNIQUE
    CHECK (original_platform_owner_id >= 1),
  deleted_event_count bigint NOT NULL CHECK (deleted_event_count >= 0),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE secureshop_review.bound_audit_events (
  event_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL
    CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL
    CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL
    CHECK (original_platform_session_id >= 1),
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  shop_role text NOT NULL CHECK (shop_role IN ('customer','merchant','admin')),
  actor text NOT NULL CHECK (octet_length(actor) >= 1),
  action text NOT NULL CHECK (octet_length(action) >= 1),
  target text CHECK (target IS NULL OR octet_length(target) >= 1),
  -- Keep the exact training input bytes. Cast only while reading if a consumer
  -- needs structured JSON; do not normalize this column to json/jsonb.
  params_json text NOT NULL CHECK (params_json IS JSON),
  outcome text NOT NULL CHECK (outcome IN ('completed','denied','failed')),
  source_kind text NOT NULL CHECK (octet_length(source_kind) >= 1),
  source_id text NOT NULL CHECK (octet_length(source_id) >= 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Every source query applies all trusted scope predicates. The event UUID is
-- the deterministic final tie-breaker used before the federated store key.
CREATE INDEX bound_audit_events_admin_scope_order
  ON secureshop_review.bound_audit_events
  (launch_id, scenario_id, generation, original_platform_owner_id,
   original_platform_session_id, created_at DESC, event_id DESC);

CREATE FUNCTION secureshop_review.bound_audit_owner_receipt_digest(
  requested_job uuid, requested_owner integer, removed bigint)
RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
  SELECT sha256(convert_to(concat_ws(chr(31),
    'secureshop-bound-audit-owner-deletion-v1', requested_job::text,
    requested_owner::text, removed::text), 'UTF8'))
$$;

-- INSERT takes the same owner lock as deletion. Whichever operation gets the
-- lock first completes before the other: a preceding append is removed, while
-- an append after the durable receipt is rejected. UPDATE is never valid.
-- DELETE is available only to the receipt-backed cleanup function below; the
-- runtime role has no table DELETE privilege.
CREATE FUNCTION secureshop_review.guard_bound_audit_event()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, secureshop_review
AS $$
DECLARE owner_id integer;
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'secureshop-bound-audit-owner:' || NEW.original_platform_owner_id::text, 0));
    IF EXISTS (
      SELECT 1
      FROM secureshop_review.bound_audit_owner_deletion_receipts receipt
      WHERE receipt.original_platform_owner_id = NEW.original_platform_owner_id
    ) THEN
      RAISE EXCEPTION 'Bound audit owner is deleted' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'Bound audit event is immutable' USING ERRCODE = '55000';
  END IF;

  owner_id := OLD.original_platform_owner_id;
  IF NOT EXISTS (
    SELECT 1
    FROM secureshop_review.bound_audit_owner_deletion_receipts receipt
    WHERE receipt.original_platform_owner_id = owner_id
  ) THEN
    RAISE EXCEPTION 'Bound audit event is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END
$$;

CREATE TRIGGER bound_audit_event_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.bound_audit_events
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_audit_event();

CREATE FUNCTION secureshop_review.guard_bound_audit_owner_deletion_receipt()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'Bound audit owner deletion receipt is immutable'
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER bound_audit_owner_deletion_receipt_guard
BEFORE UPDATE OR DELETE
ON secureshop_review.bound_audit_owner_deletion_receipts
FOR EACH ROW
EXECUTE FUNCTION secureshop_review.guard_bound_audit_owner_deletion_receipt();

-- Account deletion only. Launch reset intentionally retains prior-generation
-- audit events. The durable identity deletion job UUID is the idempotency key.
-- Promotion must compose this call into the existing `secureshop` deletion step
-- and verify the returned receipt before acknowledging that step; this draft
-- alone does not provide cross-database deletion-job authority.
CREATE FUNCTION secureshop_review.destroy_bound_audit_owner(
  requested_owner integer, requested_deletion_job uuid)
RETURNS SETOF secureshop_review.bound_audit_owner_deletion_receipts
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, secureshop_review
AS $$
DECLARE
  operation_prior secureshop_review.bound_audit_owner_deletion_receipts%ROWTYPE;
  owner_prior secureshop_review.bound_audit_owner_deletion_receipts%ROWTYPE;
  removed bigint;
  deleted bigint;
  digest bytea;
BEGIN
  IF requested_owner IS NULL OR requested_owner < 1
      OR requested_deletion_job IS NULL THEN
    RAISE EXCEPTION 'Valid bound audit deletion scope required'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    'secureshop-bound-audit-owner:' || requested_owner::text, 0));

  SELECT * INTO operation_prior
  FROM secureshop_review.bound_audit_owner_deletion_receipts receipt
  WHERE receipt.deletion_job_id = requested_deletion_job
  FOR UPDATE;
  SELECT * INTO owner_prior
  FROM secureshop_review.bound_audit_owner_deletion_receipts receipt
  WHERE receipt.original_platform_owner_id = requested_owner
  FOR UPDATE;

  IF operation_prior.deletion_job_id IS NOT NULL
      OR owner_prior.deletion_job_id IS NOT NULL THEN
    IF operation_prior.deletion_job_id IS NULL
        OR owner_prior.deletion_job_id IS NULL
        OR operation_prior.deletion_job_id <> owner_prior.deletion_job_id
        OR owner_prior.deletion_job_id <> requested_deletion_job
        OR owner_prior.original_platform_owner_id <> requested_owner
        OR owner_prior.receipt_sha256 <>
          secureshop_review.bound_audit_owner_receipt_digest(
            owner_prior.deletion_job_id,
            owner_prior.original_platform_owner_id,
            owner_prior.deleted_event_count)
        OR EXISTS (
          SELECT 1 FROM secureshop_review.bound_audit_events event
          WHERE event.original_platform_owner_id = requested_owner
        ) THEN
      RAISE EXCEPTION 'Bound audit owner deletion replay mismatch'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEXT owner_prior;
    RETURN;
  END IF;

  SELECT count(*)::bigint INTO removed
  FROM secureshop_review.bound_audit_events event
  WHERE event.original_platform_owner_id = requested_owner;
  digest := secureshop_review.bound_audit_owner_receipt_digest(
    requested_deletion_job, requested_owner, removed);

  INSERT INTO secureshop_review.bound_audit_owner_deletion_receipts(
    deletion_job_id, original_platform_owner_id, deleted_event_count,
    receipt_sha256)
  VALUES(requested_deletion_job, requested_owner, removed, digest)
  RETURNING * INTO owner_prior;

  DELETE FROM secureshop_review.bound_audit_events event
  WHERE event.original_platform_owner_id = requested_owner;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  IF deleted <> removed THEN
    RAISE EXCEPTION 'Bound audit owner deletion count mismatch'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEXT owner_prior;
END
$$;

REVOKE ALL ON TABLE secureshop_review.bound_audit_events,
  secureshop_review.bound_audit_owner_deletion_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION
  secureshop_review.bound_audit_owner_receipt_digest(uuid,integer,bigint),
  secureshop_review.guard_bound_audit_event(),
  secureshop_review.guard_bound_audit_owner_deletion_receipt(),
  secureshop_review.destroy_bound_audit_owner(integer,uuid) FROM PUBLIC;

GRANT SELECT ON TABLE secureshop_review.bound_audit_events,
  secureshop_review.bound_audit_owner_deletion_receipts
  TO dvaia_secureshop_review_runtime;
GRANT INSERT(event_id,launch_id,scenario_id,generation,
  original_platform_owner_id,original_platform_session_id,
  shop_user_id,shop_role,actor,action,target,params_json,outcome,
  source_kind,source_id)
  ON secureshop_review.bound_audit_events
  TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION
  secureshop_review.destroy_bound_audit_owner(integer,uuid)
  TO dvaia_secureshop_review_runtime;

