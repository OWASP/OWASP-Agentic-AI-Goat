-- External SMTP evidence is not lab mail. Retain claims/quota accounting across
-- practice reset; never cascade it from scene or launch cleanup.
CREATE TABLE secureshop_auth.external_mail_operations (
 operation_id uuid PRIMARY KEY,
 -- Historical identity, not a lifecycle FK: account deletion must not delete
 -- dispatch evidence or be prevented by this independent retained ledger.
 principal_id uuid NOT NULL,
 auth_session_id integer NOT NULL,
 scope_key text NOT NULL CHECK(scope_key ~ '^[a-f0-9]{64}$'),
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object'),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 preview jsonb NOT NULL CHECK(jsonb_typeof(preview)='object' AND octet_length(preview::text)<=2048),
 sender_key text NOT NULL CHECK(sender_key ~ '^[a-f0-9]{64}$'),
 state text NOT NULL DEFAULT 'prepared' CHECK(state IN
   ('prepared','cancelled','dispatching','smtp_accepted','rejected_before_dispatch','unknown')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 claimed_at timestamptz,
 settled_at timestamptz,
 smtp jsonb CHECK(smtp IS NULL OR (jsonb_typeof(smtp)='object'
   AND smtp->'smtpAccepted'='true'::jsonb AND smtp->'deliveryConfirmed'='false'::jsonb
   AND octet_length(smtp::text)<=2048)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 minutes'),
 CHECK((state='smtp_accepted')=(smtp IS NOT NULL)),
 CHECK((state IN ('dispatching','smtp_accepted','unknown')) IS NOT TRUE OR claimed_at IS NOT NULL)
);
CREATE INDEX external_mail_owner_quota ON secureshop_auth.external_mail_operations(principal_id,claimed_at);
CREATE INDEX external_mail_sender_quota ON secureshop_auth.external_mail_operations(sender_key,claimed_at);
CREATE FUNCTION secureshop_auth.guard_external_mail_operation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'External mail evidence is retained'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'prepared' OR NEW.claimed_at IS NOT NULL OR NEW.settled_at IS NOT NULL OR NEW.smtp IS NOT NULL THEN
   RAISE EXCEPTION 'External mail must be prepared first'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','claimed_at','settled_at','smtp']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['state','claimed_at','settled_at','smtp']) THEN
  RAISE EXCEPTION 'External mail draft is immutable'; END IF;
 IF NOT ((OLD.state='prepared' AND NEW.state IN ('cancelled','dispatching'))
     OR (OLD.state='dispatching' AND NEW.state IN ('smtp_accepted','unknown','rejected_before_dispatch'))) THEN
  RAISE EXCEPTION 'External mail transition unavailable'; END IF;
 IF OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at THEN
  RAISE EXCEPTION 'External mail dispatch claim is immutable'; END IF;
 IF NEW.state='dispatching' AND (NEW.claimed_at IS NULL OR NEW.settled_at IS NOT NULL)
    OR NEW.state<>'dispatching' AND NEW.settled_at IS NULL THEN
  RAISE EXCEPTION 'External mail transition evidence required'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER external_mail_operation_guard BEFORE INSERT OR UPDATE OR DELETE
 ON secureshop_auth.external_mail_operations FOR EACH ROW
 EXECUTE FUNCTION secureshop_auth.guard_external_mail_operation();
REVOKE ALL ON secureshop_auth.external_mail_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_auth.guard_external_mail_operation() FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_auth.external_mail_operations TO dvaia_identity_runtime;
GRANT UPDATE(state,claimed_at,settled_at,smtp) ON secureshop_auth.external_mail_operations TO dvaia_identity_runtime;

-- Runtime has SELECT-only canonical mode access. A narrowly scoped read lock
-- preserves that grant boundary; it does not update mode or create authority.
CREATE FUNCTION secureshop_auth.lock_external_mail_mode(requested_session integer,
 requested_tenant uuid,requested_principal uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_auth.execution_authority_state e
   WHERE e.session_id=requested_session AND e.tenant_id=requested_tenant
     AND e.principal_id=requested_principal AND e.is_active=1 AND e.expires_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'External mail execution unavailable' USING ERRCODE='28000';
 END IF;
 PERFORM 1 FROM secureshop_auth.tenant_modes m
   WHERE m.tenant_id=requested_tenant AND m.principal_id=requested_principal FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'External mail mode unavailable' USING ERRCODE='28000'; END IF;
END $$;
REVOKE ALL ON FUNCTION secureshop_auth.lock_external_mail_mode(integer,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_auth.lock_external_mail_mode(integer,uuid,uuid) TO dvaia_identity_runtime;
