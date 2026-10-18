-- Draft additive migration. Apply only after secureshop-review-binding.sql.
-- A receipt proves deletion inside the dedicated review target database. It
-- does not resolve the identity reservation or complete a launch reset.
CREATE TABLE secureshop_review.review_cleanup_receipts (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL UNIQUE
    REFERENCES secureshop_review.review_targets(target_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  deleted_review_count integer NOT NULL CHECK (deleted_review_count BETWEEN 0 AND 256),
  seed_count integer NOT NULL CHECK (seed_count BETWEEN 0 AND 256),
  seed_sha256 bytea NOT NULL CHECK (octet_length(seed_sha256) = 32),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (deleted_review_count = seed_count)
);

CREATE FUNCTION secureshop_review.guard_cleanup_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'review cleanup receipts are immutable' USING ERRCODE='55000';
END $$;

CREATE TRIGGER review_cleanup_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_review.review_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_cleanup_receipt();

CREATE FUNCTION secureshop_review.require_active_review_target()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_lifecycle text;
BEGIN
  SELECT lifecycle INTO target_lifecycle
    FROM secureshop_review.review_targets WHERE target_id=NEW.target_id FOR SHARE;
  IF target_lifecycle IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'review target is not active' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER review_insert_requires_active_target
BEFORE INSERT ON secureshop_review.reviews
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_review_target();

REVOKE ALL ON TABLE secureshop_review.review_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.guard_cleanup_receipt() FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.require_active_review_target() FROM PUBLIC;
-- UPDATE is needed by SELECT ... FOR UPDATE; the trigger rejects every update.
GRANT SELECT,INSERT,UPDATE ON TABLE secureshop_review.review_cleanup_receipts
  TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_cleanup_receipt()
  TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.require_active_review_target()
  TO dvaia_secureshop_review_runtime;
