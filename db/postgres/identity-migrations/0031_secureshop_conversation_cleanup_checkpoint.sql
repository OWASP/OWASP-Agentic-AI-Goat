-- DRAFT: not auto-applied. Identity-side checkpoint for a privately verified
-- SecureShop agents conversation-generation retirement receipt. This gate is
-- independent of external target reconciliation and canonical progress reset.
ALTER TABLE identity.secureshop_launch_resets
  ADD COLUMN conversation_reconciliation_required boolean NOT NULL DEFAULT true;

-- Upgrade note: retained committed rows intentionally acquire debt=true but
-- their launches are not retroactively moved out of active state. A later
-- commit/replay admission is gated until the private receipt is checkpointed.
-- This checkpoint proves only bound-conversation retirement. It does not clear
-- target reconciliation_required and does not claim canonical progress reset.

CREATE INDEX secureshop_launch_reset_conversation_pending
  ON identity.secureshop_launch_resets(updated_at)
  WHERE conversation_reconciliation_required;

CREATE TABLE identity.secureshop_conversation_cleanup_history (
  reset_id uuid PRIMARY KEY
    REFERENCES identity.secureshop_launch_resets(reset_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL
    REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  scenario_id uuid NOT NULL,
  from_generation bigint NOT NULL CHECK (from_generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  receipt_version integer NOT NULL CHECK (receipt_version = 1),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
  session_count integer NOT NULL CHECK (session_count BETWEEN 0 AND 256),
  -- A launch may retain 256 conversations and each conversation may retain
  -- 256 admitted turns. The receipt reports the bounded aggregate.
  uncertain_turn_count integer NOT NULL CHECK (uncertain_turn_count BETWEEN 0 AND 65536),
  session_set_sha256 bytea NOT NULL CHECK (octet_length(session_set_sha256) = 32),
  target_completed_at timestamptz NOT NULL,
  verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (launch_id,from_generation)
);

CREATE FUNCTION identity.validate_secureshop_conversation_cleanup_history()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
DECLARE reset_authority identity.secureshop_launch_resets%ROWTYPE;
BEGIN
  -- Match launch repository ordering so finalize and commit cannot deadlock:
  -- launch first, then the exact reset journal.
  SELECT * INTO authority FROM identity.secureshop_launches
    WHERE launch_id=NEW.launch_id FOR UPDATE;
  SELECT * INTO reset_authority FROM identity.secureshop_launch_resets
    WHERE reset_id=NEW.reset_id FOR UPDATE;
  IF authority.launch_id IS NULL OR reset_authority.reset_id IS NULL
     OR reset_authority.launch_id <> NEW.launch_id
     OR reset_authority.from_generation <> NEW.from_generation
     OR authority.scenario_id <> NEW.scenario_id
     OR authority.original_platform_owner_id <> NEW.original_platform_owner_id
     OR authority.original_platform_session_id <> NEW.original_platform_session_id THEN
    RAISE EXCEPTION 'SecureShop conversation cleanup history binding is invalid';
  END IF;
  -- The runtime role cannot choose an authoritative verification timestamp,
  -- and a receipt cannot predate its reset or claim future completion.
  NEW.verified_at := clock_timestamp();
  IF NEW.target_completed_at < reset_authority.created_at
     OR NEW.target_completed_at > NEW.verified_at THEN
    RAISE EXCEPTION 'SecureShop conversation cleanup receipt timestamp is invalid';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION identity.guard_secureshop_conversation_cleanup_history()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'SecureShop conversation cleanup history is immutable' USING ERRCODE='55000';
END $$;

CREATE FUNCTION identity.guard_secureshop_conversation_cleanup_gate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
BEGIN
  IF NEW.conversation_reconciliation_required IS DISTINCT FROM OLD.conversation_reconciliation_required THEN
    IF OLD.conversation_reconciliation_required IS NOT TRUE
       OR NEW.conversation_reconciliation_required IS NOT FALSE
       OR NOT EXISTS (
         SELECT 1 FROM identity.secureshop_conversation_cleanup_history h
         WHERE h.reset_id=OLD.reset_id AND h.launch_id=OLD.launch_id
           AND h.from_generation=OLD.from_generation
       ) THEN
      RAISE EXCEPTION 'SecureShop conversation cleanup gate requires verified history' USING ERRCODE='55000';
    END IF;
  END IF;
  IF OLD.status <> 'committed' AND NEW.status='committed'
     AND NEW.conversation_reconciliation_required THEN
    RAISE EXCEPTION 'SecureShop conversation cleanup remains required' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER secureshop_conversation_cleanup_history_validate
BEFORE INSERT ON identity.secureshop_conversation_cleanup_history
FOR EACH ROW EXECUTE FUNCTION identity.validate_secureshop_conversation_cleanup_history();
CREATE TRIGGER secureshop_conversation_cleanup_history_immutable
BEFORE UPDATE OR DELETE ON identity.secureshop_conversation_cleanup_history
FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_conversation_cleanup_history();
CREATE TRIGGER secureshop_conversation_cleanup_gate
BEFORE UPDATE OF status,conversation_reconciliation_required
ON identity.secureshop_launch_resets
FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_conversation_cleanup_gate();

REVOKE ALL ON TABLE identity.secureshop_conversation_cleanup_history FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.validate_secureshop_conversation_cleanup_history() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_conversation_cleanup_history() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_conversation_cleanup_gate() FROM PUBLIC;
GRANT SELECT,INSERT ON TABLE identity.secureshop_conversation_cleanup_history TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_conversation_cleanup_history() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.guard_secureshop_conversation_cleanup_history() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.guard_secureshop_conversation_cleanup_gate() TO dvaia_identity_runtime;
