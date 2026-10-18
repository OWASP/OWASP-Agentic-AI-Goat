-- Retain every review target and its immutable launch/generation binding.
-- Older review reservations occupy slot one; new sessions may reserve their
-- own review snapshots without resetting or rebinding previous evidence.
ALTER TABLE identity.secureshop_target_reservations
  ADD COLUMN review_owner_slot smallint;
UPDATE identity.secureshop_target_reservations
  SET review_owner_slot=1 WHERE target_kind='reviews';
ALTER TABLE identity.secureshop_target_reservations
  ADD CONSTRAINT secureshop_review_owner_slot_valid CHECK (
    (target_kind='reviews' AND review_owner_slot IS NOT NULL AND review_owner_slot BETWEEN 1 AND 256)
    OR (target_kind<>'reviews' AND review_owner_slot IS NULL)
  );

DROP INDEX identity.secureshop_nonproduct_owner_target;
CREATE UNIQUE INDEX secureshop_nonproduct_owner_target
  ON identity.secureshop_target_reservations(original_platform_owner_id,target_kind)
  WHERE target_kind NOT IN ('products','reviews');
CREATE UNIQUE INDEX secureshop_review_owner_slot
  ON identity.secureshop_target_reservations(original_platform_owner_id,review_owner_slot)
  WHERE target_kind='reviews';

CREATE OR REPLACE FUNCTION identity.validate_secureshop_target_reservation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
BEGIN
  IF NEW.target_kind IN ('products','reviews') THEN
    -- Same owner-before-launch lock order as the admission/reset repositories.
    PERFORM 1 FROM identity.users WHERE id=NEW.original_platform_owner_id FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SecureShop target reservation owner is unavailable';
    END IF;
  END IF;
  SELECT * INTO authority FROM identity.secureshop_launches
    WHERE launch_id=NEW.launch_id FOR KEY SHARE;
  IF NOT FOUND OR authority.original_platform_owner_id <> NEW.original_platform_owner_id
     OR authority.generation <> NEW.generation OR authority.status <> 'active'
     OR authority.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'SecureShop target reservation binding is invalid';
  END IF;
  IF NEW.target_kind='products' THEN
    SELECT slot INTO NEW.product_owner_slot FROM generate_series(1,256) AS slots(slot)
      WHERE NOT EXISTS (
        SELECT 1 FROM identity.secureshop_target_reservations r
        WHERE r.original_platform_owner_id=NEW.original_platform_owner_id
          AND r.target_kind='products' AND r.product_owner_slot=slots.slot
      ) ORDER BY slot LIMIT 1;
    IF NEW.product_owner_slot IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained shop session limit reached';
    END IF;
  ELSIF NEW.target_kind='reviews' THEN
    SELECT slot INTO NEW.review_owner_slot FROM generate_series(1,256) AS slots(slot)
      WHERE NOT EXISTS (
        SELECT 1 FROM identity.secureshop_target_reservations r
        WHERE r.original_platform_owner_id=NEW.original_platform_owner_id
          AND r.target_kind='reviews' AND r.review_owner_slot=slots.slot
      ) ORDER BY slot LIMIT 1;
    IF NEW.review_owner_slot IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained review session limit reached';
    END IF;
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION identity.validate_secureshop_target_reservation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_target_reservation() TO dvaia_identity_runtime;
