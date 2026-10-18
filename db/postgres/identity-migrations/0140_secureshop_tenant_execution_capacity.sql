-- A storefront execution lease is not the durable shop it accesses. Expired
-- and revoked tenant executions retain their immutable history and any cleanup
-- debt, but do not consume a concurrent-session slot. Product/review resource
-- reservation limits and legacy receipt-based owner retirement are unchanged.
CREATE FUNCTION identity.secureshop_launch_consumes_capacity(requested_launch_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,identity AS $$
  SELECT CASE WHEN owner.shop_tenant_id IS NOT NULL THEN
    l.status='active' AND l.expires_at>clock_timestamp() AND owner.is_active=1
      AND session.is_active=1 AND session.expires_at>clock_timestamp()
    ELSE NOT identity.secureshop_launch_is_retired(l.launch_id) END
  FROM identity.secureshop_launches l
  JOIN identity.secureshop_authority_owners owner ON owner.id=l.original_platform_owner_id
  LEFT JOIN identity.secureshop_authority_sessions session ON session.id=l.platform_session_id
  WHERE l.launch_id=requested_launch_id;
$$;
REVOKE ALL ON FUNCTION identity.secureshop_launch_consumes_capacity(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.secureshop_launch_consumes_capacity(uuid) TO dvaia_identity_runtime;

CREATE OR REPLACE FUNCTION identity.admit_secureshop_launch_capacity()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
DECLARE available_slot smallint;
BEGIN
  PERFORM 1 FROM identity.secureshop_authority_owners WHERE id=NEW.original_platform_owner_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SecureShop launch owner is unavailable';
  END IF;
  IF (SELECT count(*) FROM identity.secureshop_launches l
      WHERE l.original_platform_owner_id=NEW.original_platform_owner_id
        AND identity.secureshop_launch_consumes_capacity(l.launch_id)) >= 256 THEN
    RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained session limit reached';
  END IF;
  DELETE FROM identity.secureshop_launch_capacity c
    WHERE c.original_platform_owner_id=NEW.original_platform_owner_id
      AND NOT identity.secureshop_launch_consumes_capacity(c.launch_id);
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
