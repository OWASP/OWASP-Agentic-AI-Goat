-- Forward-only files admission: retain every old reservation and cleanup
-- identity, while independent shop principals may coexist in one tenant.
-- The old owner-kind uniqueness means each historical files row owns slot one.
ALTER TABLE identity.secureshop_target_reservations
  ADD COLUMN files_owner_slot smallint,
  ADD COLUMN files_tenant_id uuid,
  ADD COLUMN files_principal_id uuid;
UPDATE identity.secureshop_target_reservations SET files_owner_slot=1 WHERE target_kind='files';
UPDATE identity.secureshop_target_reservations r
  SET files_tenant_id=e.tenant_id,files_principal_id=e.principal_id
  FROM identity.secureshop_launches l
  JOIN identity.secureshop_authority_sessions s
    ON s.id=l.original_platform_session_id AND s.user_id=l.original_platform_owner_id AND s.realm='shop'
  JOIN secureshop_auth.execution_sessions e
    ON e.session_id=s.shop_execution_session_id AND e.session_id=s.id
  JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id AND t.owner_id=s.user_id
  WHERE r.launch_id=l.launch_id AND r.original_platform_owner_id=l.original_platform_owner_id
    AND r.target_kind='files';
-- Platform and unclassifiable historical shop rows deliberately retain NULL
-- scope. The trigger blocks future shop admission beside unclassifiable debt.
ALTER TABLE identity.secureshop_target_reservations
  ADD CONSTRAINT secureshop_files_admission_fields CHECK (
    (target_kind='files' AND files_owner_slot IS NOT NULL AND files_owner_slot BETWEEN 1 AND 256
      AND ((files_tenant_id IS NULL AND files_principal_id IS NULL)
        OR (files_tenant_id IS NOT NULL AND files_principal_id IS NOT NULL)))
    OR (target_kind<>'files' AND files_owner_slot IS NULL
      AND files_tenant_id IS NULL AND files_principal_id IS NULL)
  ),
  ADD CONSTRAINT secureshop_files_principal_membership FOREIGN KEY(files_tenant_id,files_principal_id)
    REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id);

DROP INDEX identity.secureshop_nonproduct_owner_target;
CREATE UNIQUE INDEX secureshop_nonproduct_owner_target
  ON identity.secureshop_target_reservations(original_platform_owner_id,target_kind)
  WHERE target_kind NOT IN ('products','reviews','files');
-- Unique slots preserve the aggregate ceiling under concurrent old snapshots.
CREATE UNIQUE INDEX secureshop_files_owner_slot
  ON identity.secureshop_target_reservations(original_platform_owner_id,files_owner_slot)
  WHERE target_kind='files';
-- NULL is a single protected platform/historical partition, never free space.
CREATE UNIQUE INDEX secureshop_files_owner_principal
  ON identity.secureshop_target_reservations(original_platform_owner_id,files_principal_id)
  NULLS NOT DISTINCT WHERE target_kind='files';

CREATE OR REPLACE FUNCTION identity.validate_secureshop_target_reservation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE; owner_realm text;
BEGIN
  IF NEW.target_kind IN ('products','reviews','files') THEN
    -- Same owner-before-launch lock order as the admission/reset repositories.
    SELECT realm INTO owner_realm FROM identity.secureshop_authority_owners
      WHERE id=NEW.original_platform_owner_id FOR UPDATE;
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
  ELSIF NEW.target_kind='files' THEN
    -- Ignore supplied scope/slot values. Immutable launch birth authority is
    -- the sole source of this principal partition, even after session renewal.
    NEW.files_tenant_id := NULL;
    NEW.files_principal_id := NULL;
    IF owner_realm='shop' THEN
      SELECT e.tenant_id,e.principal_id INTO NEW.files_tenant_id,NEW.files_principal_id
        FROM identity.secureshop_authority_sessions s
        JOIN secureshop_auth.execution_sessions e
          ON e.session_id=s.shop_execution_session_id AND e.session_id=s.id
        JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id AND t.owner_id=s.user_id
        WHERE s.id=authority.original_platform_session_id AND s.realm='shop'
          AND s.user_id=NEW.original_platform_owner_id;
      IF NOT FOUND OR NEW.files_tenant_id IS NULL OR NEW.files_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='SecureShop files principal authority unavailable';
      END IF;
      -- Historical unclassified debt cannot be discounted to gain capacity.
      IF EXISTS (SELECT 1 FROM identity.secureshop_target_reservations r
        WHERE r.original_platform_owner_id=NEW.original_platform_owner_id AND r.target_kind='files'
          AND (r.files_tenant_id IS DISTINCT FROM NEW.files_tenant_id OR r.files_principal_id IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='SecureShop files cleanup scope unavailable';
      END IF;
      SELECT slot INTO NEW.files_owner_slot FROM generate_series(1,256) AS slots(slot)
        WHERE NOT EXISTS (SELECT 1 FROM identity.secureshop_target_reservations r
          WHERE r.original_platform_owner_id=NEW.original_platform_owner_id
            AND r.target_kind='files' AND r.files_owner_slot=slots.slot)
        ORDER BY slot LIMIT 1;
      IF NEW.files_owner_slot IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained files target limit reached';
      END IF;
    ELSIF owner_realm='platform' THEN
      -- Preserve the platform workshop's one unresolved target per owner.
      NEW.files_owner_slot := 1;
    ELSE
      RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='SecureShop files owner realm unavailable';
    END IF;
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION identity.validate_secureshop_target_reservation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_target_reservation() TO dvaia_identity_runtime;
