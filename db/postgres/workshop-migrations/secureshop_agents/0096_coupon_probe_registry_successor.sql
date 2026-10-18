-- Forward-only v28 ACL registry successor. Only the customer-only coupon probe
-- workflow is added; historical registry transitions and snapshots remain intact.
DO $$
DECLARE
  guard_source text;
  constraint_def text;
  old_hash constant text := 'f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c';
  new_hash constant text := '1678d1c76c1e5565c6d09e62dc9e80e3d5d7bb3bfb0fa7a405b1f0579f586c72';
  old_guard_hash constant text := '9f33be5293a6a7c0d91d499b20f790a7ce5aa932c16717f6ebfe295d1f69defc';
  branch text := E' IF encode(NEW.successor_sha256,''hex'')=''1678d1c76c1e5565c6d09e62dc9e80e3d5d7bb3bfb0fa7a405b1f0579f586c72'' THEN\n  expected_denials=CASE encode(NEW.predecessor_sha256,''hex'')\n   WHEN ''f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c'' THEN ''[{"toolKey":"cart.apply_coupon","role":"customer"}]''::jsonb\n   ELSE NULL END;\n  IF expected_denials IS NULL THEN RAISE EXCEPTION ''Unknown coupon probe registry predecessor'' USING ERRCODE=''55000''; END IF;\n  SELECT jsonb_agg(value ORDER BY (value->>''toolKey'') COLLATE "C",(value->>''role'') COLLATE "C") INTO expected_denials\n   FROM jsonb_array_elements(expected_denials);\n  IF NEW.overrides_before<>old_overrides OR NEW.added_denials<>expected_denials\n   OR EXISTS(SELECT 1 FROM jsonb_to_recordset(NEW.added_denials) AS denied("toolKey" text,role text)\n    WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.overrides_before) prior\n     WHERE prior->>''toolKey''=denied."toolKey" AND prior->>''role''=denied.role)) THEN\n   RAISE EXCEPTION ''Tool registry upgrade snapshot mismatch'' USING ERRCODE=''55000'';\n  END IF;\n  RETURN NEW;\n END IF;\n';
  edge text := E'  OR (encode(predecessor_sha256,''hex'')=''f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c'' AND encode(successor_sha256,''hex'')=''1678d1c76c1e5565c6d09e62dc9e80e3d5d7bb3bfb0fa7a405b1f0579f586c72'' AND jsonb_array_length(added_denials)=1)';
BEGIN
  SELECT p.prosrc INTO guard_source
    FROM pg_proc p WHERE p.oid='secureshop_agents.guard_bound_tool_registry_upgrade()'::regprocedure;
  IF guard_source IS NULL OR encode(sha256(convert_to(guard_source,'UTF8')),'hex')<>old_guard_hash
    OR position(' IF encode(NEW.successor_sha256,''hex'')=''f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c'' THEN' IN guard_source)=0 THEN
    RAISE EXCEPTION 'Expected v27 coupon probe registry guard is unavailable' USING ERRCODE='55000';
  END IF;
  guard_source := replace(guard_source,
    ' IF encode(NEW.successor_sha256,''hex'')=''f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c'' THEN',
    branch || ' IF encode(NEW.successor_sha256,''hex'')=''f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c'' THEN');
  EXECUTE format('CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS %L',guard_source);

  SELECT pg_get_constraintdef(c.oid) INTO constraint_def
    FROM pg_constraint c WHERE c.conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass
      AND c.conname='bound_tool_registry_successor_v27' AND c.contype='c' AND c.convalidated;
  IF constraint_def IS NULL THEN RAISE EXCEPTION 'Expected v27 registry successor constraint is unavailable' USING ERRCODE='55000'; END IF;
  constraint_def := regexp_replace(constraint_def,E'\\)\\s*$',edge||E'\n)');
  EXECUTE 'ALTER TABLE secureshop_agents.bound_tool_registry_upgrades ADD CONSTRAINT bound_tool_registry_successor_v28 '||constraint_def;
  ALTER TABLE secureshop_agents.bound_tool_registry_upgrades DROP CONSTRAINT bound_tool_registry_successor_v27;
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade()
 FROM PUBLIC,dvaia_secureshop_agents_runtime;
