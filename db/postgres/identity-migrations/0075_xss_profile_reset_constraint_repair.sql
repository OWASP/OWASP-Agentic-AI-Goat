-- Forward repair for 0074: replace every generated CHECK on the two journal
-- relations with the complete 0072+0074 invariant set under stable names.
-- Dropping by catalog identity avoids relying on PostgreSQL's generated suffixes.
DO $$
DECLARE item record;
BEGIN
  FOR item IN SELECT conname FROM pg_constraint
    WHERE conrelid='identity.xss_profile_reset_operations'::regclass AND contype='c'
  LOOP
    EXECUTE format('ALTER TABLE identity.xss_profile_reset_operations DROP CONSTRAINT %I',item.conname);
  END LOOP;
  FOR item IN SELECT conname FROM pg_constraint
    WHERE conrelid='identity.xss_profile_reset_steps'::regclass AND contype='c'
  LOOP
    EXECUTE format('ALTER TABLE identity.xss_profile_reset_steps DROP CONSTRAINT %I',item.conname);
  END LOOP;
END $$;

ALTER TABLE identity.xss_profile_reset_operations
  ADD CONSTRAINT xss_profile_reset_operations_graph_parent_nonnegative
    CHECK(graph_parent_generation>=0),
  ADD CONSTRAINT xss_profile_reset_operations_workshop_nonnegative
    CHECK(workshop_generation>=0),
  ADD CONSTRAINT xss_profile_reset_operations_stored_user_from_range
    CHECK(stored_user_from>=0 AND stored_user_from<9223372036854775807),
  ADD CONSTRAINT xss_profile_reset_operations_stored_llm_from_range
    CHECK(stored_llm_from>=0 AND stored_llm_from<9223372036854775807),
  ADD CONSTRAINT xss_profile_reset_operations_status
    CHECK(status IN ('pending','running','failed','completed','superseded')),
  ADD CONSTRAINT xss_profile_reset_operations_failure_code_format
    CHECK(failure_code IS NULL OR failure_code~'^[A-Z][A-Z0-9_]{0,63}$'),
  ADD CONSTRAINT xss_profile_reset_operations_owner_positive CHECK(owner_id>0),
  ADD CONSTRAINT xss_profile_reset_operations_owner_key
    CHECK(owner_key=('['||'"XSS"'||','||'"'||owner_id::text||'"'||']')),
  ADD CONSTRAINT xss_profile_reset_operations_stored_user_transition
    CHECK(stored_user_to=stored_user_from+1),
  ADD CONSTRAINT xss_profile_reset_operations_stored_llm_transition
    CHECK(stored_llm_to=stored_llm_from+1),
  ADD CONSTRAINT xss_profile_reset_operations_lease_pair
    CHECK((lease_token IS NULL)=(lease_expires_at IS NULL)),
  ADD CONSTRAINT xss_profile_reset_operations_running_lease
    CHECK((status='running')=(lease_token IS NOT NULL)),
  ADD CONSTRAINT xss_profile_reset_operations_terminal_time
    CHECK((status IN ('completed','superseded'))=(completed_at IS NOT NULL)),
  ADD CONSTRAINT xss_profile_reset_operations_failure_state
    CHECK(status IN ('failed','superseded') OR failure_code IS NULL),
  ADD CONSTRAINT xss_profile_reset_operations_reconciliation CHECK(
    (status='superseded')=(reconciliation_kind IS NOT NULL)
    AND (reconciliation_kind IS NULL)=(reconciliation_sha256 IS NULL)
    AND (reconciliation_kind IS NULL)=(reconciled_graph_parent_generation IS NULL)
    AND (reconciliation_kind IS NULL)=(reconciled_workshop_generation IS NULL)
    AND (reconciliation_kind IS NULL OR reconciliation_kind IN ('retired_no_effect','committed'))
    AND (reconciliation_sha256 IS NULL OR reconciliation_sha256~'^[0-9a-f]{64}$')
    AND (reconciled_graph_parent_generation IS NULL OR reconciled_graph_parent_generation>=0)
    AND (reconciled_workshop_generation IS NULL OR reconciled_workshop_generation>=0)
    AND (status<>'superseded' OR (failure_code IS NOT NULL
      AND failure_code='PARENT_RESET_SUPERSEDED'))
  );

ALTER TABLE identity.xss_profile_reset_steps
  ADD CONSTRAINT xss_profile_reset_steps_key CHECK(step_key='xss_store'),
  ADD CONSTRAINT xss_profile_reset_steps_ordinal CHECK(ordinal=0),
  ADD CONSTRAINT xss_profile_reset_steps_status
    CHECK(status IN ('pending','failed','completed','superseded')),
  ADD CONSTRAINT xss_profile_reset_steps_attempts CHECK(attempts>=0),
  ADD CONSTRAINT xss_profile_reset_steps_receipt_digest_format
    CHECK(receipt_sha256 IS NULL OR receipt_sha256~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT xss_profile_reset_steps_failure_code_format
    CHECK(failure_code IS NULL OR failure_code~'^[A-Z][A-Z0-9_]{0,63}$'),
  ADD CONSTRAINT xss_profile_reset_steps_terminal_time
    CHECK((status IN ('completed','superseded'))=(completed_at IS NOT NULL)),
  ADD CONSTRAINT xss_profile_reset_steps_receipt_pair
    CHECK((receipt IS NULL)=(receipt_sha256 IS NULL)),
  ADD CONSTRAINT xss_profile_reset_steps_terminal_receipt
    CHECK((status IN ('completed','superseded'))=(receipt IS NOT NULL)),
  ADD CONSTRAINT xss_profile_reset_steps_failure_state
    CHECK(status IN ('failed','superseded') OR failure_code IS NULL),
  ADD CONSTRAINT xss_profile_reset_steps_superseded
    CHECK(status<>'superseded' OR (failure_code IS NOT NULL
      AND failure_code='PARENT_RESET_SUPERSEDED'));
