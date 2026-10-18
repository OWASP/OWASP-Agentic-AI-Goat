-- Add only the no-effect customer address-form handoff. Preserve every prior
-- registry edge, instructor override, enforcement state and immutable receipt.
ALTER TABLE secureshop_agents.bound_tool_registry_upgrades
 DROP CONSTRAINT bound_tool_registry_upgrades_added_denials_check,
 ADD CONSTRAINT bound_tool_registry_upgrades_added_denials_check
  CHECK(jsonb_typeof(added_denials)='array' AND jsonb_array_length(added_denials) IN (1,2,3,4,5,6,15,16,18,19,20,21)),
 DROP CONSTRAINT bound_tool_registry_successor_v6,
 ADD CONSTRAINT bound_tool_registry_successor_v7 CHECK(
  (encode(predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(successor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND jsonb_array_length(added_denials)=15)
  OR (encode(predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(successor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND jsonb_array_length(added_denials)=16)
  OR (encode(predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(successor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND jsonb_array_length(added_denials)=1)
  OR (encode(predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(successor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND jsonb_array_length(added_denials)=18)
  OR (encode(predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(successor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND jsonb_array_length(added_denials)=3)
  OR (encode(predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(successor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND jsonb_array_length(added_denials)=2)
  OR (encode(predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND jsonb_array_length(added_denials)=19)
  OR (encode(predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND jsonb_array_length(added_denials)=4)
  OR (encode(predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND jsonb_array_length(added_denials)=3)
  OR (encode(predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND jsonb_array_length(added_denials)=1)
  OR (encode(predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND jsonb_array_length(added_denials)=20)
  OR (encode(predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND jsonb_array_length(added_denials)=5)
  OR (encode(predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND jsonb_array_length(added_denials)=4)
  OR (encode(predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND jsonb_array_length(added_denials)=2)
  OR (encode(predecessor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND encode(successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND jsonb_array_length(added_denials)=1)
  OR (encode(predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND jsonb_array_length(added_denials)=21)
  OR (encode(predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND jsonb_array_length(added_denials)=6)
  OR (encode(predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND jsonb_array_length(added_denials)=5)
  OR (encode(predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND jsonb_array_length(added_denials)=3)
  OR (encode(predecessor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND encode(successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND jsonb_array_length(added_denials)=2)
  OR (encode(predecessor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND encode(successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND jsonb_array_length(added_denials)=1));

CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() RETURNS trigger
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
  OR NOT ((encode(NEW.predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(NEW.successor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed')
   OR (encode(NEW.predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(NEW.successor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427')
   OR (encode(NEW.predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(NEW.successor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427')
   OR (encode(NEW.predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(NEW.successor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1')
   OR (encode(NEW.predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(NEW.successor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1')
   OR (encode(NEW.predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(NEW.successor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1')
   OR (encode(NEW.predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(NEW.successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26')
   OR (encode(NEW.predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(NEW.successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26')
   OR (encode(NEW.predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(NEW.successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26')
   OR (encode(NEW.predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(NEW.successor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26')
   OR (encode(NEW.predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(NEW.successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b')
   OR (encode(NEW.predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(NEW.successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b')
   OR (encode(NEW.predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(NEW.successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b')
   OR (encode(NEW.predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(NEW.successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b')
   OR (encode(NEW.predecessor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND encode(NEW.successor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b')
   OR (encode(NEW.predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(NEW.successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
   OR (encode(NEW.predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(NEW.successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
   OR (encode(NEW.predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(NEW.successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
   OR (encode(NEW.predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(NEW.successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
   OR (encode(NEW.predecessor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND encode(NEW.successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
   OR (encode(NEW.predecessor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND encode(NEW.successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0'))
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
 IF encode(NEW.predecessor_sha256,'hex') IN ('93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed','a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427','640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1','4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26','f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b') THEN
  expected_denials='[]'::jsonb;
 END IF;
 IF encode(NEW.successor_sha256,'hex') IN ('a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427','640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1','4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26','f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b','2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
  AND encode(NEW.predecessor_sha256,'hex') NOT IN ('a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427','640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1','4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26','f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b') THEN
  expected_denials=expected_denials || '[{"toolKey":"merchant.inventory_prepare","role":"merchant"}]'::jsonb;
 END IF;
 IF encode(NEW.successor_sha256,'hex') IN ('640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1','4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26','f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b','2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
  AND encode(NEW.predecessor_sha256,'hex')NOT IN ('640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1','4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26','f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b') THEN
  expected_denials=expected_denials || '[{"toolKey":"merchant.pricing_suggest_prepare","role":"merchant"},{"toolKey":"merchant.pricing_experiment_prepare","role":"merchant"}]'::jsonb;
 END IF;
 IF encode(NEW.successor_sha256,'hex') IN ('4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26','f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b','2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
  AND encode(NEW.predecessor_sha256,'hex') NOT IN ('4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26','f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b') THEN
  expected_denials=expected_denials || '[{"toolKey":"merchant.listing_edit_prepare","role":"merchant"}]'::jsonb;
 END IF;
 IF encode(NEW.successor_sha256,'hex') IN ('f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b','2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0')
  AND encode(NEW.predecessor_sha256,'hex')<>'f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' THEN
  expected_denials=expected_denials || '[{"toolKey":"merchant.listing_create_prepare","role":"merchant"}]'::jsonb;
 END IF;
 IF encode(NEW.successor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' THEN
  expected_denials=expected_denials || '[{"toolKey":"account.address_setup","role":"customer"}]'::jsonb;
 END IF;
 SELECT jsonb_agg(value ORDER BY value->>'toolKey',value->>'role') INTO expected_denials
  FROM jsonb_array_elements(expected_denials);
 IF NEW.overrides_before<>old_overrides OR NEW.added_denials<>expected_denials
  OR EXISTS(SELECT 1 FROM jsonb_to_recordset(NEW.added_denials) AS denied("toolKey" text,role text)
   WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.overrides_before) prior
    WHERE prior->>'toolKey'=denied."toolKey" AND prior->>'role'=denied.role)) THEN
  RAISE EXCEPTION 'Tool registry upgrade snapshot mismatch' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;

-- Existing head/deferred completion guards, receipt key and counted cleanup remain unchanged.
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() FROM PUBLIC,dvaia_secureshop_agents_runtime;
