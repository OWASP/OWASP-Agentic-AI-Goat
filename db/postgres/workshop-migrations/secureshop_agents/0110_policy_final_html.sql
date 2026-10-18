-- Add a separately admitted policy-source flow; preserve all C32 rows and receipts.
ALTER TABLE secureshop_agents.bound_ssrf_requests
  DROP CONSTRAINT bound_ssrf_requests_resource_kind_check,
  ADD CONSTRAINT bound_ssrf_requests_resource_kind_check CHECK(resource_kind IN ('public-policy','private-policy','html-policy')),
  ADD COLUMN policy_html text,
  ADD CONSTRAINT bound_ssrf_policy_html_check CHECK (
    (resource_kind='html-policy' AND policy_html IS NOT NULL AND octet_length(policy_html) BETWEEN 1 AND 8192)
    OR (resource_kind<>'html-policy' AND policy_html IS NULL));
ALTER TABLE secureshop_agents.bound_ssrf_invocations
  DROP CONSTRAINT bound_ssrf_invocations_resource_kind_check,
  DROP CONSTRAINT bound_ssrf_invocations_check,
  ADD CONSTRAINT bound_ssrf_invocations_resource_kind_check CHECK(resource_kind IN ('public-policy','private-policy','html-policy')),
  ADD CONSTRAINT bound_ssrf_invocations_check CHECK ((resource_kind IN ('public-policy','html-policy'))=(policy_decision='allowed'));
CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_ssrf_request() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Bound SSRF request is immutable' USING ERRCODE='55000'; END IF;
  IF NEW.operation_id<>OLD.operation_id OR NEW.target_id<>OLD.target_id
    OR NEW.request_id<>OLD.request_id OR NEW.resource_kind<>OLD.resource_kind OR NEW.created_at<>OLD.created_at
    OR NEW.policy_html IS DISTINCT FROM OLD.policy_html
    OR OLD.nonce IS NOT NULL OR NEW.nonce IS NULL OR NEW.issued_url IS NULL
  THEN RAISE EXCEPTION 'Bound SSRF request is immutable' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
