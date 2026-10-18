-- Optional immutable presentation diagnostics; never completion authority.
CREATE TABLE identity.ctf_response_diagnostics (
 proposal_id uuid PRIMARY KEY REFERENCES identity.ctf_decision_proposals(proposal_id),
 admission_id uuid NOT NULL REFERENCES identity.ctf_decision_inputs(admission_id),
 input_hash text NOT NULL CHECK(input_hash~'^[a-f0-9]{64}$'),
 evidence_hash text NOT NULL CHECK(evidence_hash~'^[a-f0-9]{64}$'),
 canonical_diagnostics text NOT NULL CHECK(octet_length(canonical_diagnostics)<=2048),
 diagnostics_hash text NOT NULL CHECK(diagnostics_hash=encode(sha256(convert_to(canonical_diagnostics,'UTF8')),'hex'))
);
CREATE TRIGGER ctf_response_diagnostics_immutable BEFORE UPDATE OR DELETE ON identity.ctf_response_diagnostics FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_response_diagnostics FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_response_diagnostics TO dvaia_identity_runtime;
CREATE FUNCTION identity.stage_ctf_response_diagnostics(p_proposal uuid,p_actor integer,p_session integer,p_token_hash text,p_evidence text,p_evidence_hash text,p_diagnostics text,p_diagnostics_hash text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb;d jsonb;c identity.ctf_predefense_claims%ROWTYPE;i identity.ctf_decision_inputs%ROWTYPE;prior identity.ctf_response_diagnostics%ROWTYPE;expected text;
BEGIN
 IF p_evidence IS NULL OR octet_length(p_evidence)>65536 OR NOT(p_evidence IS JSON OBJECT WITH UNIQUE KEYS)
 OR p_evidence_hash IS DISTINCT FROM encode(sha256(convert_to(p_evidence,'UTF8')),'hex')
 OR p_diagnostics IS NULL OR octet_length(p_diagnostics)>2048 OR NOT(p_diagnostics IS JSON OBJECT WITH UNIQUE KEYS)
 OR p_diagnostics_hash IS DISTINCT FROM encode(sha256(convert_to(p_diagnostics,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF diagnostic bytes invalid'; END IF;
 e:=p_evidence::jsonb;d:=p_diagnostics::jsonb;
 IF identity.ctf_decision_document_matches(e) IS NOT TRUE OR identity.ctf_json_matches(d,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"responseTimeMs":{"type":"number","integer":true,"minimum":0,"maximum":300000,"nullable":true},"timingScope":{"type":"string","enum":["guardian_generation","guardian_failure_elapsed"]},"guardianUnavailable":{"type":"boolean"},"reviewerObserved":{"type":"boolean"},"visibleResponseSha256":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}}'::jsonb) IS NOT TRUE THEN RAISE EXCEPTION 'CTF diagnostic schema invalid'; END IF;
 IF (d->>'guardianUnavailable')::boolean IS DISTINCT FROM (d->>'timingScope'='guardian_failure_elapsed')
 OR d->>'visibleResponseSha256' IS DISTINCT FROM encode(sha256(convert_to(e->>'visibleResponse','UTF8')),'hex')
 OR (NOT (d->>'guardianUnavailable')::boolean AND e->'guardian'='null'::jsonb)
 OR ((d->>'guardianUnavailable')::boolean AND (e->'judgment'->>'verdict' IS DISTINCT FROM 'unavailable' OR e->'observedSecret' IS DISTINCT FROM 'false'::jsonb OR e->'guardian' IS DISTINCT FROM 'null'::jsonb)) THEN RAISE EXCEPTION 'CTF diagnostic evidence mismatch'; END IF;
 -- Fixed scalar-only canonical encoding; no generic jsonb text serialization.
 expected:='{"guardianUnavailable":'||(d->>'guardianUnavailable')||',"responseTimeMs":'||CASE WHEN d->'responseTimeMs'='null'::jsonb THEN 'null' ELSE ((d->>'responseTimeMs')::numeric)::integer::text END||',"reviewerObserved":'||(d->>'reviewerObserved')||',"timingScope":'||to_json(d->>'timingScope')::text||',"version":1,"visibleResponseSha256":'||to_json(d->>'visibleResponseSha256')::text||'}';
 IF p_diagnostics IS DISTINCT FROM expected THEN RAISE EXCEPTION 'CTF diagnostic canonical bytes invalid'; END IF;
 SELECT * INTO i FROM identity.ctf_decision_inputs di WHERE di.admission_id=(e->'binding'->>'admissionId')::uuid;
 SELECT * INTO c FROM identity.ctf_predefense_claims pc WHERE pc.run_id=i.run_id AND pc.admission_operation_id=i.admission_id;
 IF i.admission_id IS NULL OR c.run_id IS NULL OR i.owner_id IS DISTINCT FROM p_actor OR i.session_id IS DISTINCT FROM p_session THEN RAISE EXCEPTION 'CTF diagnostic original claim unavailable'; END IF;
 -- Same lock order as canonical pre-defense/publication. Serializes first insert
 -- with original staging's user lock, including legacy direct staging callers.
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,c.input->'binding',false);
 SELECT * INTO prior FROM identity.ctf_response_diagnostics rd WHERE rd.proposal_id=p_proposal;
 IF FOUND THEN
  IF prior.admission_id IS DISTINCT FROM i.admission_id OR prior.input_hash IS DISTINCT FROM i.input_hash OR prior.evidence_hash IS DISTINCT FROM p_evidence_hash OR prior.canonical_diagnostics IS DISTINCT FROM p_diagnostics OR prior.diagnostics_hash IS DISTINCT FROM p_diagnostics_hash THEN RAISE EXCEPTION 'CTF diagnostic replay conflict'; END IF;
  PERFORM identity.stage_ctf_server_proposal(p_proposal,p_actor,p_session,p_token_hash,p_evidence,p_evidence_hash);
  RETURN p_proposal;
 END IF;
 IF EXISTS(SELECT 1 FROM identity.ctf_decision_proposals pp WHERE pp.proposal_id=p_proposal OR pp.run_id=i.run_id OR pp.admission_operation_id=i.admission_id) THEN RAISE EXCEPTION 'CTF historical diagnostics unavailable'; END IF;
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,c.input->'binding',true);
 PERFORM identity.stage_ctf_server_proposal(p_proposal,p_actor,p_session,p_token_hash,p_evidence,p_evidence_hash);
 INSERT INTO identity.ctf_response_diagnostics VALUES(p_proposal,i.admission_id,i.input_hash,p_evidence_hash,p_diagnostics,p_diagnostics_hash);
 RETURN p_proposal;
END; $$;
REVOKE ALL ON FUNCTION identity.stage_ctf_response_diagnostics(uuid,integer,integer,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.stage_ctf_response_diagnostics(uuid,integer,integer,text,text,text,text,text) TO dvaia_identity_runtime;
