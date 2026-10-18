-- One reviewed ACL catalog successor. Existing policy and admission evidence is never rewritten.
CREATE TABLE secureshop_agents.bound_tool_registry_upgrades (
 platform_launch_id uuid NOT NULL,
 platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id bigint NOT NULL CHECK(original_platform_session_id>0),
 predecessor_version bigint NOT NULL CHECK(predecessor_version>0),
 successor_version bigint NOT NULL CHECK(successor_version=predecessor_version+1),
 predecessor_sha256 bytea NOT NULL CHECK(octet_length(predecessor_sha256)=32),
 successor_sha256 bytea NOT NULL CHECK(octet_length(successor_sha256)=32),
 enforcement_enabled boolean NOT NULL,
 overrides_before jsonb NOT NULL CHECK(jsonb_typeof(overrides_before)='array' AND octet_length(overrides_before::text)<=32768),
 overrides_sha256 bytea NOT NULL CHECK(octet_length(overrides_sha256)=32),
 added_denials jsonb NOT NULL CHECK(jsonb_typeof(added_denials)='array' AND jsonb_array_length(added_denials)=15),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
);

CREATE TABLE secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts (
 deletion_job_id uuid PRIMARY KEY,
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 deleted_upgrade_count bigint NOT NULL CHECK(deleted_upgrade_count>=0),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE current_head secureshop_agents.bound_tool_policy_heads%ROWTYPE;
 old_overrides jsonb;
 expected_denials jsonb;
BEGIN
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
   WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Tool registry upgrade evidence immutable' USING ERRCODE='55000';
 ELSIF TG_OP='UPDATE' THEN
  RAISE EXCEPTION 'Tool registry upgrade evidence immutable' USING ERRCODE='55000';
 END IF;
 SELECT * INTO current_head FROM secureshop_agents.bound_tool_policy_heads
  WHERE platform_launch_id=NEW.platform_launch_id AND platform_scenario_id=NEW.platform_scenario_id
   AND platform_launch_generation=NEW.platform_launch_generation
   AND original_platform_owner_id=NEW.original_platform_owner_id
   AND original_platform_session_id=NEW.original_platform_session_id FOR UPDATE;
 IF NOT FOUND OR current_head.policy_version<>NEW.predecessor_version
  OR current_head.enforcement_enabled<>NEW.enforcement_enabled
  OR current_head.registry_sha256<>NEW.predecessor_sha256
  OR encode(NEW.predecessor_sha256,'hex')<>'a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64'
  OR encode(NEW.successor_sha256,'hex')<>'93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed'
  OR NEW.overrides_sha256<>sha256(convert_to(NEW.overrides_before::text,'UTF8')) THEN
  RAISE EXCEPTION 'Unknown tool registry predecessor' USING ERRCODE='55000'; END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('toolKey',tool_key,'role',role,'allowed',allowed)
  ORDER BY tool_key,role),'[]'::jsonb) INTO old_overrides
  FROM secureshop_agents.bound_tool_policy_overrides
  WHERE platform_launch_id=NEW.platform_launch_id AND platform_scenario_id=NEW.platform_scenario_id
   AND platform_launch_generation=NEW.platform_launch_generation
   AND original_platform_owner_id=NEW.original_platform_owner_id
   AND original_platform_session_id=NEW.original_platform_session_id;
 SELECT jsonb_agg(jsonb_build_object('toolKey',split_part(k,':',1),'role',split_part(k,':',2)) ORDER BY k)
  INTO expected_denials FROM unnest(ARRAY[
   'account.addresses:customer','admin.audit_recent:admin','admin.users_search:admin',
   'cart.add:customer','cart.remove:customer','cart.update:customer','catalog.details:customer',
   'checkout.prepare:customer','merchant.catalog_search:merchant','merchant.overview:merchant',
   'merchant.top_products:merchant','orders.details:customer','orders.list:customer',
   'payment.create_method:customer','payment.methods:customer']) k;
 IF NEW.overrides_before<>old_overrides OR NEW.added_denials<>expected_denials
  OR EXISTS(SELECT 1 FROM jsonb_to_recordset(NEW.added_denials) AS denied("toolKey" text,role text)
   WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.overrides_before) prior
    WHERE prior->>'toolKey'=denied."toolKey" AND prior->>'role'=denied.role)) THEN
  RAISE EXCEPTION 'Tool registry upgrade snapshot mismatch' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION secureshop_agents.guard_bound_tool_registry_head() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE upgrade secureshop_agents.bound_tool_registry_upgrades%ROWTYPE;
BEGIN
 IF NEW.registry_sha256=OLD.registry_sha256 THEN RETURN NEW; END IF;
 SELECT * INTO upgrade FROM secureshop_agents.bound_tool_registry_upgrades
  WHERE platform_launch_id=OLD.platform_launch_id AND platform_scenario_id=OLD.platform_scenario_id
   AND platform_launch_generation=OLD.platform_launch_generation
   AND original_platform_owner_id=OLD.original_platform_owner_id
   AND original_platform_session_id=OLD.original_platform_session_id;
 IF NOT FOUND OR OLD.registry_sha256<>upgrade.predecessor_sha256
  OR NEW.registry_sha256<>upgrade.successor_sha256
  OR OLD.policy_version<>upgrade.predecessor_version
  OR NEW.policy_version<>upgrade.successor_version
  OR OLD.enforcement_enabled<>NEW.enforcement_enabled
  OR EXISTS(SELECT 1 FROM jsonb_to_recordset(upgrade.added_denials) AS denied("toolKey" text,role text)
   WHERE NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_tool_policy_overrides o
    WHERE o.platform_launch_id=OLD.platform_launch_id AND o.platform_scenario_id=OLD.platform_scenario_id
     AND o.platform_launch_generation=OLD.platform_launch_generation
     AND o.original_platform_owner_id=OLD.original_platform_owner_id
     AND o.original_platform_session_id=OLD.original_platform_session_id
     AND o.tool_key=denied."toolKey" AND o.role=denied.role AND o.allowed=false)) THEN
  RAISE EXCEPTION 'Tool registry upgrade incomplete' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade_commit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_tool_policy_heads h
  WHERE h.platform_launch_id=NEW.platform_launch_id AND h.platform_scenario_id=NEW.platform_scenario_id
   AND h.platform_launch_generation=NEW.platform_launch_generation
   AND h.original_platform_owner_id=NEW.original_platform_owner_id
   AND h.original_platform_session_id=NEW.original_platform_session_id
   AND h.policy_version=NEW.successor_version AND h.registry_sha256=NEW.successor_sha256
   AND h.enforcement_enabled=NEW.enforcement_enabled) THEN
  RAISE EXCEPTION 'Tool registry upgrade not committed' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION secureshop_agents.cleanup_bound_tool_registry_upgrades() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE deleted_count bigint;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
 DELETE FROM secureshop_agents.bound_tool_registry_upgrades
  WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 GET DIAGNOSTICS deleted_count=ROW_COUNT;
 INSERT INTO secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts
  (deletion_job_id,original_platform_owner_id,deleted_upgrade_count,receipt_sha256)
 VALUES(NEW.deletion_job_id,NEW.original_platform_owner_id,deleted_count,
  sha256(convert_to(jsonb_build_array('tool-registry-upgrade-cleanup-v1',NEW.deletion_job_id,
   NEW.original_platform_owner_id,deleted_count)::text,'UTF8')));
 RETURN NEW;
END $$;

CREATE TRIGGER a_bound_tool_registry_upgrade_fence BEFORE INSERT ON secureshop_agents.bound_tool_registry_upgrades
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_write();
CREATE TRIGGER b_bound_tool_registry_upgrade_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.bound_tool_registry_upgrades
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade();
CREATE CONSTRAINT TRIGGER c_bound_tool_registry_upgrade_commit AFTER INSERT ON secureshop_agents.bound_tool_registry_upgrades
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade_commit();
CREATE TRIGGER b_bound_tool_registry_head_guard BEFORE UPDATE ON secureshop_agents.bound_tool_policy_heads
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_registry_head();
CREATE TRIGGER z_bound_tool_registry_upgrade_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_owner_deletion_receipt();
CREATE TRIGGER cleanup_bound_tool_registry_upgrade_owner AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_bound_tool_registry_upgrades();

INSERT INTO secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts
 (deletion_job_id,original_platform_owner_id,deleted_upgrade_count,receipt_sha256)
 SELECT deletion_job_id,original_platform_owner_id,0,
  sha256(convert_to(jsonb_build_array('tool-registry-upgrade-cleanup-v1',deletion_job_id,
   original_platform_owner_id,0)::text,'UTF8'))
 FROM secureshop_agents.bound_audit_owner_deletion_receipts;

REVOKE ALL ON secureshop_agents.bound_tool_registry_upgrades FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_tool_registry_upgrades TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_head() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade_commit() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.cleanup_bound_tool_registry_upgrades() FROM PUBLIC,dvaia_secureshop_agents_runtime;
