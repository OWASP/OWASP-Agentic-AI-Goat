-- Permit only explicitly replay-capable SecureShop owner resets to reconcile retained child IDs.
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
 IF c.state<>'pending' AND (replay_safe IS DISTINCT FROM true OR c.workshop_key NOT IN ('indirect_prompt_injection','csrf_workshop','xss_workshop','secureshop_agent_security')) THEN RAISE EXCEPTION 'Reset child outcome uncertain' USING ERRCODE='55000';END IF;
 IF EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=c.owner_id)
 OR NOT EXISTS(SELECT 1 FROM identity.users WHERE id=c.owner_id) THEN
 UPDATE identity.bulk_reset_children SET state='deleted',finished_at=clock_timestamp() WHERE operation_id=op AND ordinal=n;
 RETURN jsonb_build_object('state','deleted');END IF;
 UPDATE identity.bulk_reset_children SET state='started',lease_token=token,started_at=clock_timestamp() WHERE operation_id=op AND ordinal=n;
 RETURN jsonb_build_object('state','started','leaseToken',token);
END $$;
