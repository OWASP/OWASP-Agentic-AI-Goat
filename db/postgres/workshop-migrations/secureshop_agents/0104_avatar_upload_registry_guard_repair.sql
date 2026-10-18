-- Forward-only repair for the v31 avatar-upload registry guard. Migration 0103
-- installed the v31 CASE without the ELSE that makes older successor branches
-- mutually exclusive, so a valid v30-to-v31 receipt reached the older chain and
-- failed the shared snapshot comparison. Preserve every edge, constraint and ACL.
DO $$
DECLARE
 guard_source text;
 old_guard_sha256 constant text := 'ebd90aa7e547b3040bf946d5c25484aa615d799bd3a89ed69ac93bc1d142e6af';
 repaired_guard_sha256 constant text := '29c18a399a6273f8fde1c1c6c23355369a410f4beab42a8a52c2a2aa2115c2cf';
 broken_anchor constant text := E'  END;\n IF encode(NEW.successor_sha256,''hex'')=''e747a55517a50d484901bcc78a98747c98773042cb2bff6396a7654722a470ef'' THEN';
 repaired_anchor constant text := E'  END;\n ELSE\n IF encode(NEW.successor_sha256,''hex'')=''e747a55517a50d484901bcc78a98747c98773042cb2bff6396a7654722a470ef'' THEN';
BEGIN
 SELECT p.prosrc INTO guard_source FROM pg_proc p
  WHERE p.oid='secureshop_agents.guard_bound_tool_registry_upgrade()'::regprocedure;
 IF guard_source IS NULL
  OR encode(sha256(convert_to(guard_source,'UTF8')),'hex')<>old_guard_sha256
  OR position(broken_anchor IN guard_source)=0 THEN
  RAISE EXCEPTION 'Expected v31 avatar-upload registry guard is unavailable' USING ERRCODE='55000';
 END IF;
 guard_source:=replace(guard_source,broken_anchor,repaired_anchor);
 IF encode(sha256(convert_to(guard_source,'UTF8')),'hex')<>repaired_guard_sha256 THEN
  RAISE EXCEPTION 'Avatar-upload registry guard repair checksum mismatch' USING ERRCODE='55000';
 END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS %L',guard_source);
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade()
 FROM PUBLIC,dvaia_secureshop_agents_runtime;
