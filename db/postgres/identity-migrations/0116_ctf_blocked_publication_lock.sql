-- Read-side authenticated lock acquisition only. Never grants runtime table UPDATE.
CREATE FUNCTION identity.lock_ctf_blocked_publication(p_run uuid,p_actor integer,p_session integer,p_token_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;
BEGIN
 SELECT * INTO c FROM identity.ctf_predefense_claims WHERE run_id=p_run;
 IF c.run_id IS NULL OR c.owner_id IS DISTINCT FROM p_actor OR c.session_id IS DISTINCT FROM p_session THEN
  RAISE EXCEPTION 'CTF blocked publication unavailable' USING ERRCODE='42501';
 END IF;
 -- Qualified helper authenticates original live session and locks scopes,
 -- user/session, graph owner/run in that order. Stored claim supplies all scope.
 -- false does not confer current authority: caller must still validate current
 -- state, both immutable receipts and activation before returning a response.
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,c.input->'binding',false);
END $$;
REVOKE ALL ON FUNCTION identity.lock_ctf_blocked_publication(uuid,integer,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.lock_ctf_blocked_publication(uuid,integer,integer,text) TO dvaia_identity_runtime;
