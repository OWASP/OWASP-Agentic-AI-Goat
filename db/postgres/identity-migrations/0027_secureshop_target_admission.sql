-- Preserve the already-applied reservation schema; strengthen admission with
-- retained owner identity and a database-level outstanding-target ceiling.
ALTER TABLE identity.secureshop_target_reservations ADD COLUMN original_platform_owner_id integer;
UPDATE identity.secureshop_target_reservations r SET original_platform_owner_id=l.original_platform_owner_id
  FROM identity.secureshop_launches l WHERE l.launch_id=r.launch_id;
ALTER TABLE identity.secureshop_target_reservations
  ALTER COLUMN original_platform_owner_id SET NOT NULL,
  ADD CHECK (original_platform_owner_id >= 1),
  ADD UNIQUE (original_platform_owner_id, target_kind);

CREATE FUNCTION identity.validate_secureshop_target_reservation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
BEGIN
  SELECT * INTO authority FROM identity.secureshop_launches
    WHERE launch_id=NEW.launch_id FOR KEY SHARE;
  IF NOT FOUND OR authority.original_platform_owner_id <> NEW.original_platform_owner_id
     OR authority.generation <> NEW.generation OR authority.status <> 'active'
     OR authority.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'SecureShop target reservation binding is invalid';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER secureshop_target_reservation_guard
BEFORE INSERT ON identity.secureshop_target_reservations
FOR EACH ROW EXECUTE FUNCTION identity.validate_secureshop_target_reservation();

REVOKE ALL ON FUNCTION identity.validate_secureshop_target_reservation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_target_reservation() TO dvaia_identity_runtime;

