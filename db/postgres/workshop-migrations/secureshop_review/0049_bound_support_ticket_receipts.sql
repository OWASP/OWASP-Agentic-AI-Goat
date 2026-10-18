-- Bound customer support tickets are independent of the legacy shared
-- secureshop.support_tickets teaching sink. Source authority is durable and
-- immutable; an administrator's current scene grant is resolved only at read.
CREATE TABLE secureshop_review.product_target_support_tickets (
  ticket_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE,
  proposal_id uuid NOT NULL UNIQUE,
  proposal_tool_key text NOT NULL CHECK (proposal_tool_key='support.ticket_prepare'),
  proposal_invocation_step integer NOT NULL CHECK (proposal_invocation_step BETWEEN 1 AND 4),
  proposal_call_id text NOT NULL CHECK (octet_length(proposal_call_id) BETWEEN 1 AND 128),
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  source_launch_id uuid NOT NULL,
  source_scenario_id uuid NOT NULL,
  source_generation bigint NOT NULL CHECK (source_generation > 0),
  source_platform_owner_id integer NOT NULL CHECK (source_platform_owner_id > 0),
  source_platform_session_id integer NOT NULL CHECK (source_platform_session_id > 0),
  source_scene_id uuid NOT NULL,
  source_scene_generation bigint NOT NULL CHECK (source_scene_generation > 0),
  source_grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
  birth_launch_id uuid NOT NULL,
  birth_scenario_id uuid NOT NULL,
  birth_generation bigint NOT NULL CHECK (birth_generation > 0),
  birth_platform_owner_id integer NOT NULL CHECK (birth_platform_owner_id > 0),
  birth_platform_session_id integer NOT NULL CHECK (birth_platform_session_id > 0),
  shop_user_id integer NOT NULL CHECK (shop_user_id > 0),
  persona_session_id uuid NOT NULL,
  authority_version text NOT NULL CHECK (authority_version ~ '^[1-9][0-9]*$'),
  turn_session_id uuid NOT NULL,
  turn_request_id uuid NOT NULL,
  turn_run_id uuid NOT NULL,
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256)=32),
  subject text NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 256),
  body text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 4096),
  subject_sha256 bytea NOT NULL CHECK (octet_length(subject_sha256)=32),
  body_sha256 bytea NOT NULL CHECK (octet_length(body_sha256)=32),
  source_mode_snapshot jsonb NOT NULL CHECK (jsonb_typeof(source_mode_snapshot)='object'),
  status text NOT NULL DEFAULT 'open' CHECK (status='open'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (operation_id=proposal_id),
  CHECK (source_platform_owner_id=birth_platform_owner_id)
);
CREATE INDEX product_target_support_tickets_source_read
  ON secureshop_review.product_target_support_tickets
  (target_id,shop_user_id,persona_session_id,operation_id);
CREATE INDEX product_target_support_tickets_admin_page
  ON secureshop_review.product_target_support_tickets(target_id,created_at DESC,ticket_id DESC);

CREATE TABLE secureshop_review.product_target_support_ticket_receipts (
  operation_id uuid PRIMARY KEY REFERENCES secureshop_review.product_target_support_tickets(operation_id) ON DELETE RESTRICT,
  ticket_id bigint NOT NULL UNIQUE REFERENCES secureshop_review.product_target_support_tickets(ticket_id) ON DELETE RESTRICT,
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  receipt_json jsonb NOT NULL CHECK (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=32768),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Retiring a target removes it from all active ticket views while keeping the
-- immutable ticket and receipt rows available for reset/audit history.
CREATE TABLE secureshop_review.product_target_support_ticket_retirements (
  ticket_id bigint PRIMARY KEY REFERENCES secureshop_review.product_target_support_tickets(ticket_id) ON DELETE RESTRICT,
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  birth_launch_id uuid NOT NULL,
  birth_scenario_id uuid NOT NULL,
  birth_generation bigint NOT NULL CHECK (birth_generation > 0),
  birth_platform_owner_id integer NOT NULL CHECK (birth_platform_owner_id > 0),
  birth_platform_session_id integer NOT NULL CHECK (birth_platform_session_id > 0),
  retired_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX product_target_support_ticket_retirements_target
  ON secureshop_review.product_target_support_ticket_retirements(target_id);

CREATE FUNCTION secureshop_review.guard_support_ticket_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  IF NEW.subject_sha256<>sha256(convert_to(NEW.subject,'UTF8'))
    OR NEW.body_sha256<>sha256(convert_to(NEW.body,'UTF8')) THEN
    RAISE EXCEPTION 'support ticket body digest mismatch' USING ERRCODE='55000';
  END IF;
  PERFORM 1
  FROM secureshop_review.product_targets p
  JOIN secureshop_review.scene_execution_grants g ON g.grant_id=NEW.source_grant_id
  WHERE p.target_id=NEW.target_id AND p.lifecycle='active'
    AND p.launch_id=NEW.birth_launch_id AND p.scenario_id=NEW.birth_scenario_id
    AND p.generation=NEW.birth_generation
    AND p.original_platform_owner_id=NEW.birth_platform_owner_id
    AND p.original_platform_session_id=NEW.birth_platform_session_id
    AND g.target_id=NEW.target_id
    AND g.scene_id=NEW.source_scene_id AND g.scene_generation=NEW.source_scene_generation
    AND g.launch_id=NEW.source_launch_id AND g.scenario_id=NEW.source_scenario_id
    AND g.generation=NEW.source_generation
    AND g.original_platform_owner_id=NEW.source_platform_owner_id
    AND g.original_platform_session_id=NEW.source_platform_session_id
    AND g.created_at<=NEW.created_at;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'support ticket source grant unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER support_ticket_source_guard
BEFORE INSERT ON secureshop_review.product_target_support_tickets
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_support_ticket_insert();

CREATE FUNCTION secureshop_review.guard_support_ticket_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  RAISE EXCEPTION 'support ticket receipt is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER support_ticket_immutable
BEFORE UPDATE OR DELETE ON secureshop_review.product_target_support_tickets
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_support_ticket_immutable();
CREATE TRIGGER support_ticket_receipt_immutable
BEFORE UPDATE OR DELETE ON secureshop_review.product_target_support_ticket_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_support_ticket_immutable();
CREATE TRIGGER support_ticket_retirement_immutable
BEFORE UPDATE OR DELETE ON secureshop_review.product_target_support_ticket_retirements
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_support_ticket_immutable();

CREATE FUNCTION secureshop_review.retire_product_target_support_tickets() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  IF OLD.lifecycle='active' AND NEW.lifecycle='retired' THEN
    INSERT INTO secureshop_review.product_target_support_ticket_retirements
      (ticket_id,target_id,birth_launch_id,birth_scenario_id,birth_generation,
       birth_platform_owner_id,birth_platform_session_id,retired_at)
    SELECT t.ticket_id,t.target_id,t.birth_launch_id,t.birth_scenario_id,t.birth_generation,
      t.birth_platform_owner_id,t.birth_platform_session_id,NEW.retired_at
    FROM secureshop_review.product_target_support_tickets t
    WHERE t.target_id=NEW.target_id
    ON CONFLICT(ticket_id) DO NOTHING;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER retire_product_target_support_tickets
AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
FOR EACH ROW EXECUTE FUNCTION secureshop_review.retire_product_target_support_tickets();

REVOKE ALL ON TABLE secureshop_review.product_target_support_tickets,
  secureshop_review.product_target_support_ticket_receipts,
  secureshop_review.product_target_support_ticket_retirements FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.guard_support_ticket_insert(),
  secureshop_review.guard_support_ticket_immutable(),
  secureshop_review.retire_product_target_support_tickets() FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT ON secureshop_review.product_target_support_tickets,
  secureshop_review.product_target_support_ticket_receipts TO dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.product_target_support_ticket_retirements
  TO dvaia_secureshop_review_runtime;
GRANT USAGE,SELECT ON SEQUENCE secureshop_review.product_target_support_tickets_ticket_id_seq
  TO dvaia_secureshop_review_runtime;
