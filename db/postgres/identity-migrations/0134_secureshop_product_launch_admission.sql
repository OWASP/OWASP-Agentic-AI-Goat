-- Preserve every retained target and its immutable launch/generation binding.
-- Product snapshots may coexist across sessions. Other target kinds keep their
-- existing one-outstanding-target-per-owner admission rule.
ALTER TABLE identity.secureshop_target_reservations
  ADD COLUMN product_owner_slot smallint;
UPDATE identity.secureshop_target_reservations
  SET product_owner_slot=1 WHERE target_kind='products';
ALTER TABLE identity.secureshop_target_reservations
  ADD CONSTRAINT secureshop_product_owner_slot_valid CHECK (
    (target_kind='products' AND product_owner_slot IS NOT NULL AND product_owner_slot BETWEEN 1 AND 256)
    OR (target_kind<>'products' AND product_owner_slot IS NULL)
  );

DO $$
DECLARE constraint_name text;
BEGIN
  SELECT c.conname INTO STRICT constraint_name
    FROM pg_constraint c
    WHERE c.conrelid='identity.secureshop_target_reservations'::regclass AND c.contype='u'
      AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
           FROM unnest(c.conkey) WITH ORDINALITY k(attnum,ordinality)
           JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum)
          = ARRAY['original_platform_owner_id','target_kind'];
  EXECUTE format('ALTER TABLE identity.secureshop_target_reservations DROP CONSTRAINT %I',constraint_name);
END $$;

CREATE UNIQUE INDEX secureshop_nonproduct_owner_target
  ON identity.secureshop_target_reservations(original_platform_owner_id,target_kind)
  WHERE target_kind<>'products';
-- Uniqueness makes the cap hold even for concurrent inserts with old snapshots.
CREATE UNIQUE INDEX secureshop_product_owner_slot
  ON identity.secureshop_target_reservations(original_platform_owner_id,product_owner_slot)
  WHERE target_kind='products';

CREATE OR REPLACE FUNCTION identity.validate_secureshop_target_reservation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
BEGIN
  IF NEW.target_kind='products' THEN
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
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION identity.validate_secureshop_target_reservation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_target_reservation() TO dvaia_identity_runtime;

-- An aborted reset on a revoked launch cannot have admitted effects in its new
-- generation. A committed reset is insufficient: the new generation may have
-- run more conversations before a later logout. Flags are receipt-gated by the
-- existing target, conversation and progress cleanup authorities.
CREATE FUNCTION identity.secureshop_launch_is_retired(requested_launch_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,identity AS $$
  SELECT EXISTS (
    SELECT 1 FROM identity.secureshop_launches l
    JOIN identity.secureshop_launch_resets r ON r.launch_id=l.launch_id
      AND r.to_generation=l.generation AND r.status='aborted'
    WHERE l.launch_id=requested_launch_id AND l.status='revoked'
      AND NOT r.reconciliation_required AND NOT r.conversation_reconciliation_required
      AND NOT r.progress_reconciliation_required
      AND NOT EXISTS (SELECT 1 FROM identity.secureshop_target_reservations t WHERE t.launch_id=l.launch_id)
      AND NOT EXISTS (SELECT 1 FROM identity.secureshop_launch_resets debt WHERE debt.launch_id=l.launch_id
        AND (debt.reconciliation_required OR debt.conversation_reconciliation_required OR debt.progress_reconciliation_required))
  );
$$;
REVOKE ALL ON FUNCTION identity.secureshop_launch_is_retired(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.secureshop_launch_is_retired(uuid) TO dvaia_identity_runtime;

-- Owner reset/deletion bounds unresolved/active launches at 256. Retired launch
-- tombstones and immutable evidence remain, but consume no resource slot.
-- Keep historical unresolved overflow intact and block only future admission.
-- A separate relation avoids rewriting launch rows during an in-progress reset.
CREATE TABLE identity.secureshop_launch_capacity (
  launch_id uuid PRIMARY KEY REFERENCES identity.secureshop_launches(launch_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id >= 1),
  owner_slot smallint NOT NULL CHECK(owner_slot BETWEEN 1 AND 256),
  UNIQUE(original_platform_owner_id,owner_slot)
);
INSERT INTO identity.secureshop_launch_capacity(launch_id,original_platform_owner_id,owner_slot)
  SELECT launch_id,original_platform_owner_id,slot::smallint FROM (
    SELECT launch_id,original_platform_owner_id,
      row_number() OVER(PARTITION BY original_platform_owner_id ORDER BY created_at,launch_id) AS slot
    FROM identity.secureshop_launches WHERE NOT identity.secureshop_launch_is_retired(launch_id)
  ) retained WHERE slot<=256;

CREATE FUNCTION identity.admit_secureshop_launch_capacity()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
DECLARE available_slot smallint;
BEGIN
  PERFORM 1 FROM identity.users WHERE id=NEW.original_platform_owner_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SecureShop launch owner is unavailable';
  END IF;
  IF (SELECT count(*) FROM identity.secureshop_launches l
      WHERE l.original_platform_owner_id=NEW.original_platform_owner_id
        AND NOT identity.secureshop_launch_is_retired(l.launch_id)) >= 256 THEN
    RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained session limit reached';
  END IF;
  DELETE FROM identity.secureshop_launch_capacity c
    WHERE c.original_platform_owner_id=NEW.original_platform_owner_id
      AND identity.secureshop_launch_is_retired(c.launch_id);
  SELECT slot INTO available_slot FROM generate_series(1,256) AS slots(slot)
    WHERE NOT EXISTS (
      SELECT 1 FROM identity.secureshop_launch_capacity c
      WHERE c.original_platform_owner_id=NEW.original_platform_owner_id AND c.owner_slot=slots.slot
    ) ORDER BY slot LIMIT 1;
  IF available_slot IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained session limit reached';
  END IF;
  INSERT INTO identity.secureshop_launch_capacity(launch_id,original_platform_owner_id,owner_slot)
    VALUES(NEW.launch_id,NEW.original_platform_owner_id,available_slot);
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_launch_capacity_guard BEFORE INSERT ON identity.secureshop_launches
  FOR EACH ROW EXECUTE FUNCTION identity.admit_secureshop_launch_capacity();
REVOKE ALL ON identity.secureshop_launch_capacity FROM PUBLIC;
REVOKE ALL ON identity.secureshop_launch_capacity FROM dvaia_identity_runtime;
GRANT SELECT ON identity.secureshop_launch_capacity TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.admit_secureshop_launch_capacity() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.admit_secureshop_launch_capacity() TO dvaia_identity_runtime;
