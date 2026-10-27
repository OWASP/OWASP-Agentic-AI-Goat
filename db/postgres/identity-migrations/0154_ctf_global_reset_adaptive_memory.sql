-- A successful, ordered Full CTF Reset clears the authoritative adaptive
-- memory as well as the physical CTF blocklist projection. Do not backfill:
-- historical receipts and all non-reset operations retain their prior effect.
-- The original ACK function is from 0105 and has not been replaced by the
-- intervening migrations. Refuse an unreviewed body instead of patching it.
DO $migration$
DECLARE
 original text;
 old_branch text := $old$
 ELSIF k='global_reset' THEN
  UPDATE identity.ctf_participant_bindings SET active=false,applied_sequence=p_sequence,applied_operation_id=p_operation;
 ELSIF k IN ('ban','unban') THEN$old$;
 new_branch text := $new$
 ELSIF k='global_reset' THEN
  UPDATE identity.ctf_participant_bindings SET active=false,applied_sequence=p_sequence,applied_operation_id=p_operation;
  DELETE FROM identity.ctf_adaptive_memory;
 ELSIF k IN ('ban','unban') THEN$new$;
BEGIN
 SELECT p.prosrc INTO original FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid='identity.ack_ctf_projection(uuid,bigint,text,text,text)'::pg_catalog.regprocedure
   AND p.prosecdef AND l.lanname='plpgsql'
   AND p.proconfig=ARRAY['search_path=pg_catalog'];
 IF original IS NULL OR encode(sha256(convert_to(original,'UTF8')),'hex')
    <> 'ed13ddf23f9fe18fe7932295d97eb5f093bb485ac3cf7eeaa87d2d0662d54e1e'
    OR strpos(original,old_branch)=0
    OR strpos(substr(original,strpos(original,old_branch)+length(old_branch)),old_branch)>0 THEN
  RAISE EXCEPTION 'CTF reset ACK predecessor unavailable' USING ERRCODE='55000';
 END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION identity.ack_ctf_projection(
  p_operation uuid,p_sequence bigint,p_command_hash text,p_result text,p_result_hash text)
  RETURNS TABLE(state text,applied_sequence bigint) LANGUAGE plpgsql SECURITY DEFINER
  SET search_path=pg_catalog AS %L',replace(original,old_branch,new_branch));
END $migration$;
REVOKE ALL ON FUNCTION identity.ack_ctf_projection(uuid,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.ack_ctf_projection(uuid,bigint,text,text,text) TO dvaia_identity_runtime;
