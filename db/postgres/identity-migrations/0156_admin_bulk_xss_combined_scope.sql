-- Admit the unified XSS admin card as one immutable, two-family student cohort.
-- All other workshop scopes remain single-family; canonical child keys are unchanged.
CREATE OR REPLACE FUNCTION identity.begin_bulk_reset(op uuid,a integer,s bigint,kind text,keys text[]) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior identity.bulk_reset_operations%ROWTYPE; normalized text[]; BEGIN
 PERFORM identity.assert_bulk_reset_actor(a,s);
 SELECT array_agg(DISTINCT k ORDER BY k) INTO normalized FROM unnest(keys) k;
 IF op IS NULL OR kind IS NULL OR keys IS NULL OR array_position(keys,NULL) IS NOT NULL OR kind NOT IN ('workshop','all') OR normalized IS NULL OR cardinality(normalized)>64
 OR (kind='workshop' AND cardinality(normalized)<>1 AND normalized<>ARRAY['xss_email_builder','xss_workshop']::text[]) OR EXISTS(SELECT 1 FROM unnest(normalized) k WHERE k IS NULL OR k !~ '^[a-z][a-z0-9_]{0,95}$')
 THEN RAISE EXCEPTION 'Invalid reset request' USING ERRCODE='22023';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('bulk-reset:'||op::text,0));
 SELECT * INTO prior FROM identity.bulk_reset_operations WHERE operation_id=op;
 IF FOUND THEN
 IF prior.actor_id<>a OR prior.request_kind<>kind OR (kind='workshop' AND prior.workshop_keys<>normalized) THEN RAISE EXCEPTION 'Reset request conflict' USING ERRCODE='22023';END IF;
 ELSE
 INSERT INTO identity.bulk_reset_operations VALUES(op,a,s,kind,normalized,clock_timestamp());
 INSERT INTO identity.bulk_reset_children(operation_id,ordinal,owner_id,workshop_key,child_operation_id)
 SELECT op,row_number() OVER(ORDER BY k,u.id)::integer,u.id,k,gen_random_uuid()
 FROM unnest(normalized) k CROSS JOIN identity.users u WHERE u.role='student' AND u.admin_level=0
 AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id);
 END IF;
 RETURN identity.bulk_reset_snapshot(op);
END $$;
REVOKE ALL ON FUNCTION identity.begin_bulk_reset(uuid,integer,bigint,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.begin_bulk_reset(uuid,integer,bigint,text,text[]) TO dvaia_identity_runtime;

-- Match the combined scope before LIMIT so unrelated operations cannot hide recovery.
CREATE OR REPLACE FUNCTION identity.list_bulk_resets_for_scope(a integer,s bigint,kind text,k text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;BEGIN
 PERFORM identity.assert_bulk_reset_actor(a,s);
 IF kind IS NULL OR kind NOT IN ('all','workshop') OR (kind='all' AND k IS NOT NULL)
 OR (kind='workshop' AND (k IS NULL OR k !~ '^[a-z][a-z0-9_]{0,95}$'))
 THEN RAISE EXCEPTION 'Invalid reset recovery scope' USING ERRCODE='22023';END IF;
 SELECT COALESCE(jsonb_agg(identity.bulk_reset_snapshot(operation_id)),'[]'::jsonb) INTO result
 FROM (SELECT p.operation_id FROM identity.bulk_reset_operations p
 WHERE p.actor_id=a AND p.request_kind=kind AND (kind='all' OR p.workshop_keys=CASE WHEN k='xss_combined' THEN ARRAY['xss_email_builder','xss_workshop']::text[] ELSE ARRAY[k] END)
 AND EXISTS(SELECT 1 FROM identity.bulk_reset_children c WHERE c.operation_id=p.operation_id AND c.state NOT IN ('completed','deleted'))
 ORDER BY p.created_at,p.operation_id LIMIT 1) pending;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION identity.list_bulk_resets_for_scope(integer,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.list_bulk_resets_for_scope(integer,bigint,text,text) TO dvaia_identity_runtime;

-- Builder resets retain owned cross-store receipts for safe interrupted-child replay.
-- Permit only explicitly replay-capable Legacy file/SSI owner resets to reconcile retained child IDs.
CREATE OR REPLACE FUNCTION identity.claim_bulk_reset_child(op uuid,a integer,s bigint,n integer,token uuid,replay_safe boolean) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p identity.bulk_reset_operations%ROWTYPE;c identity.bulk_reset_children%ROWTYPE; BEGIN
 PERFORM identity.assert_bulk_reset_actor(a,s);
 IF NOT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted
 AND classid=842184::oid AND objid=((hashtext(op::text)::bigint+4294967296)%4294967296)::oid AND objsubid=2)
 THEN RAISE EXCEPTION 'Reset operation lease required' USING ERRCODE='55000';END IF;
 SELECT * INTO p FROM identity.bulk_reset_operations WHERE operation_id=op FOR UPDATE;
 IF NOT FOUND OR p.actor_id<>a OR token IS NULL THEN RAISE EXCEPTION 'Reset actor conflict' USING ERRCODE='22023';END IF;
 SELECT * INTO c FROM identity.bulk_reset_children WHERE operation_id=op AND ordinal=n FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Reset child missing' USING ERRCODE='22023';END IF;
 IF c.state IN ('completed','deleted') THEN RETURN jsonb_build_object('state',c.state);END IF;
 IF c.state<>'pending' AND (replay_safe IS DISTINCT FROM true OR c.workshop_key NOT IN ('indirect_prompt_injection','csrf_workshop','xss_workshop','xss_email_builder','secureshop_agent_security','legacy_sensitive_file_ssi')) THEN RAISE EXCEPTION 'Reset child outcome uncertain' USING ERRCODE='55000';END IF;
 IF EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=c.owner_id)
 OR NOT EXISTS(SELECT 1 FROM identity.users WHERE id=c.owner_id) THEN
 UPDATE identity.bulk_reset_children SET state='deleted',finished_at=clock_timestamp() WHERE operation_id=op AND ordinal=n;
 RETURN jsonb_build_object('state','deleted');END IF;
 UPDATE identity.bulk_reset_children SET state='started',lease_token=token,started_at=clock_timestamp() WHERE operation_id=op AND ordinal=n;
 RETURN jsonb_build_object('state','started','leaseToken',token);
END $$;
