-- A customer chat turn captures one owned practice before model admission.
-- These rows remain as historical evidence when a generation is retired.
ALTER TABLE secureshop_agents.agent_sessions DROP CONSTRAINT agent_sessions_conversation_purpose_shape;
ALTER TABLE secureshop_agents.agent_sessions ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
 conversation_purpose IN ('general','mcp_rogue_registration','mcp_rug_pull','persona_inbox','controlled_ssrf','review_moderation','secureshop_refund_request','secureshop_product_assist','secureshop_product_manual_ingest','secureshop_audit_summary','secureshop_audit_sql','secureshop_analytics','secureshop_price_advisor','secureshop_pricing_strategy','secureshop_listing_rewrite','secureshop_listing_import','secureshop_listing_template','secureshop_mail_reply','secureshop_inventory','secureshop_customer_chat')
 AND (authority_mode='launch_bound' OR conversation_purpose='general')
);

CREATE TABLE secureshop_agents.customer_chat_turn_bindings (
 session_id text NOT NULL REFERENCES secureshop_agents.agent_sessions(id),
 request_id uuid NOT NULL,
 launch_id uuid NOT NULL,
 scenario_id uuid NOT NULL,
 generation bigint NOT NULL CHECK (generation > 0),
 owner_id integer NOT NULL CHECK (owner_id > 0),
 execution_session_id integer NOT NULL CHECK (execution_session_id > 0),
 persona_id integer NOT NULL CHECK (persona_id > 0),
 persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL CHECK (authority_version > 0),
 scene_id uuid NOT NULL,
 scene_generation bigint NOT NULL CHECK (scene_generation > 0),
 grant_id uuid NOT NULL,
 target_id uuid NOT NULL,
 envelope_sha256 text NOT NULL CHECK (envelope_sha256 ~ '^[a-f0-9]{64}$'),
 request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (session_id, request_id)
);
CREATE UNIQUE INDEX customer_chat_request_owner_unique
ON secureshop_agents.customer_chat_turn_bindings(owner_id,persona_id,request_id);
CREATE FUNCTION secureshop_agents.guard_customer_chat_turn_binding() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Customer chat binding is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER customer_chat_turn_binding_guard BEFORE UPDATE OR DELETE
ON secureshop_agents.customer_chat_turn_bindings FOR EACH ROW
EXECUTE FUNCTION secureshop_agents.guard_customer_chat_turn_binding();
REVOKE ALL ON FUNCTION secureshop_agents.guard_customer_chat_turn_binding() FROM PUBLIC;
GRANT SELECT, INSERT ON secureshop_agents.customer_chat_turn_bindings TO dvaia_secureshop_agents_runtime;
