-- Draft only: owner-bound SecureShop review lab. Do not register in startup yet.
-- This belongs in a dedicated database whose runtime role is not reachable by
-- the intentionally vulnerable SecureShop commerce analytics SQL tool.
CREATE SCHEMA IF NOT EXISTS secureshop_review AUTHORIZATION dvaia_secureshop_review_migration;
REVOKE ALL ON SCHEMA secureshop_review FROM PUBLIC;
GRANT USAGE ON SCHEMA secureshop_review TO dvaia_secureshop_review_runtime;

CREATE TABLE secureshop_review.review_targets (
  target_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','retired')),
  seed_count integer NOT NULL CHECK (seed_count BETWEEN 0 AND 256),
  seed_sha256 bytea NOT NULL CHECK (octet_length(seed_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  UNIQUE (launch_id,generation),
  CHECK ((lifecycle='retired') = (retired_at IS NOT NULL))
);

CREATE TABLE secureshop_review.reviews (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  target_id uuid NOT NULL REFERENCES secureshop_review.review_targets(target_id) ON DELETE CASCADE,
  product_id integer NOT NULL CHECK (product_id >= 1),
  author_id integer NOT NULL CHECK (author_id >= 1),
  body text NOT NULL CHECK (octet_length(body) <= 65536),
  rating integer NOT NULL CHECK (rating BETWEEN 1 AND 5),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  moderator_kind text CHECK (moderator_kind IN ('auto','manual')),
  moderator_notes text CHECK (moderator_notes IS NULL OR octet_length(moderator_notes) <= 16384),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  moderated_at timestamptz,
  CHECK ((status='pending' AND moderator_kind IS NULL AND moderator_notes IS NULL AND moderated_at IS NULL)
      OR (status IN ('approved','rejected') AND moderator_kind IS NOT NULL AND moderated_at IS NOT NULL))
);

CREATE INDEX review_pending_by_target ON secureshop_review.reviews(target_id,id) WHERE status='pending';

CREATE FUNCTION secureshop_review.guard_target_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_id IS DISTINCT FROM OLD.target_id
     OR NEW.launch_id IS DISTINCT FROM OLD.launch_id
     OR NEW.scenario_id IS DISTINCT FROM OLD.scenario_id
     OR NEW.generation IS DISTINCT FROM OLD.generation
     OR NEW.original_platform_owner_id IS DISTINCT FROM OLD.original_platform_owner_id
     OR NEW.original_platform_session_id IS DISTINCT FROM OLD.original_platform_session_id
     OR NEW.seed_count IS DISTINCT FROM OLD.seed_count
     OR NEW.seed_sha256 IS DISTINCT FROM OLD.seed_sha256
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR OLD.lifecycle='retired' OR (OLD.lifecycle='active' AND NEW.lifecycle NOT IN ('active','retired')) THEN
    RAISE EXCEPTION 'review target identity or lifecycle is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER review_target_guard BEFORE UPDATE ON secureshop_review.review_targets
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_target_identity();

CREATE FUNCTION secureshop_review.guard_review_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.target_id IS DISTINCT FROM OLD.target_id
     OR NEW.product_id IS DISTINCT FROM OLD.product_id OR NEW.author_id IS DISTINCT FROM OLD.author_id
     OR NEW.body IS DISTINCT FROM OLD.body OR NEW.rating IS DISTINCT FROM OLD.rating
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR OLD.status <> 'pending'
     OR NEW.status NOT IN ('approved','rejected') THEN
    RAISE EXCEPTION 'review identity or decision is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER review_decision_guard BEFORE UPDATE ON secureshop_review.reviews
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_review_identity();

REVOKE ALL ON ALL TABLES IN SCHEMA secureshop_review FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA secureshop_review FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA secureshop_review FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA secureshop_review TO dvaia_secureshop_review_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA secureshop_review TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA secureshop_review TO dvaia_secureshop_review_runtime;
