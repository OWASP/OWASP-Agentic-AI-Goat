-- Candidate only: do not activate until native qualification and recovery UI integration.
CREATE TABLE identity.bulk_reset_operations (
 operation_id uuid PRIMARY KEY, actor_id integer NOT NULL, original_session_id bigint NOT NULL,
 request_kind text NOT NULL CHECK(request_kind IN ('workshop','all')), workshop_keys text[] NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE identity.bulk_reset_children (
 operation_id uuid NOT NULL REFERENCES identity.bulk_reset_operations(operation_id), ordinal integer NOT NULL,
 owner_id integer NOT NULL, workshop_key text NOT NULL, child_operation_id uuid NOT NULL UNIQUE,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','started','completed','deleted','uncertain')),
 lease_token uuid, started_at timestamptz, finished_at timestamptz, failure_code text,
 PRIMARY KEY(operation_id,ordinal), UNIQUE(operation_id,owner_id,workshop_key),
 CHECK((state IN ('completed','deleted'))=(finished_at IS NOT NULL)));
REVOKE ALL ON identity.bulk_reset_operations,identity.bulk_reset_children FROM PUBLIC,dvaia_identity_runtime;
CREATE FUNCTION identity.assert_bulk_reset_actor(a integer,s bigint) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF a IS NULL OR s IS NULL THEN RAISE EXCEPTION 'Reset authority required' USING ERRCODE='22023';END IF;
 PERFORM 1 FROM identity.users u JOIN identity.user_sessions us ON us.user_id=u.id
 WHERE u.id=a AND us.id=s AND u.role IN ('admin','super_admin') AND u.admin_level>=1
 AND u.is_active=1 AND us.is_active=1 AND us.expires_at>clock_timestamp()
 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
 AND EXISTS(SELECT 1 FROM identity.admin_permissions p WHERE p.admin_id=a AND p.permission_name='manage_progress' AND p.is_active=1 AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp())) FOR SHARE OF u,us;
 IF NOT FOUND THEN RAISE EXCEPTION 'Reset authority unavailable' USING ERRCODE='42501'; END IF;
END $$;
CREATE FUNCTION identity.bulk_reset_snapshot(op uuid) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('operationId',p.operation_id,'actorId',p.actor_id,'originalSessionId',p.original_session_id::text,
 'requestKind',p.request_kind,'workshopKeys',p.workshop_keys,'children',COALESCE((SELECT jsonb_agg(jsonb_build_object(
 'ordinal',c.ordinal,'ownerId',c.owner_id,'workshopKey',c.workshop_key,'childOperationId',c.child_operation_id,
 'state',c.state,'failureCode',c.failure_code) ORDER BY c.ordinal) FROM identity.bulk_reset_children c WHERE c.operation_id=p.operation_id),'[]'::jsonb))
 FROM identity.bulk_reset_operations p WHERE p.operation_id=op
$$;
CREATE FUNCTION identity.begin_bulk_reset(op uuid,a integer,s bigint,kind text,keys text[]) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior identity.bulk_reset_operations%ROWTYPE; normalized text[]; BEGIN
 PERFORM identity.assert_bulk_reset_actor(a,s);
 SELECT array_agg(DISTINCT k ORDER BY k) INTO normalized FROM unnest(keys) k;
 IF op IS NULL OR kind IS NULL OR keys IS NULL OR array_position(keys,NULL) IS NOT NULL OR kind NOT IN ('workshop','all') OR normalized IS NULL OR cardinality(normalized)>64
 OR (kind='workshop' AND cardinality(normalized)<>1) OR EXISTS(SELECT 1 FROM unnest(normalized) k WHERE k IS NULL OR k !~ '^[a-z][a-z0-9_]{0,95}$')
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
CREATE FUNCTION identity.claim_bulk_reset_child(op uuid,a integer,s bigint,n integer,token uuid,replay_safe boolean) RETURNS jsonb
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
 IF c.state<>'pending' AND (replay_safe IS DISTINCT FROM true OR c.workshop_key NOT IN ('indirect_prompt_injection','csrf_workshop')) THEN RAISE EXCEPTION 'Reset child outcome uncertain' USING ERRCODE='55000';END IF;
 IF EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=c.owner_id)
 OR NOT EXISTS(SELECT 1 FROM identity.users WHERE id=c.owner_id) THEN
 UPDATE identity.bulk_reset_children SET state='deleted',finished_at=clock_timestamp() WHERE operation_id=op AND ordinal=n;
 RETURN jsonb_build_object('state','deleted');END IF;
 UPDATE identity.bulk_reset_children SET state='started',lease_token=token,started_at=clock_timestamp() WHERE operation_id=op AND ordinal=n;
 RETURN jsonb_build_object('state','started','leaseToken',token);
END $$;
CREATE FUNCTION identity.finish_bulk_reset_child(op uuid,a integer,s bigint,n integer,token uuid,ok boolean,code text) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 PERFORM identity.assert_bulk_reset_actor(a,s);
 IF NOT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted
 AND classid=842184::oid AND objid=((hashtext(op::text)::bigint+4294967296)%4294967296)::oid AND objsubid=2)
 THEN RAISE EXCEPTION 'Reset operation lease required' USING ERRCODE='55000';END IF;
 PERFORM 1 FROM identity.bulk_reset_operations WHERE operation_id=op AND actor_id=a FOR UPDATE;
 IF NOT FOUND OR ok IS NULL THEN RAISE EXCEPTION 'Reset actor conflict' USING ERRCODE='22023';END IF;
 UPDATE identity.bulk_reset_children SET state=CASE WHEN ok THEN 'completed' ELSE 'uncertain' END,
 finished_at=CASE WHEN ok THEN clock_timestamp() ELSE NULL END,failure_code=CASE WHEN ok THEN NULL ELSE 'RESET_PARTIAL_FAILURE' END
 WHERE operation_id=op AND ordinal=n AND lease_token=token AND state='started';
 IF NOT FOUND THEN RAISE EXCEPTION 'Reset lease stale' USING ERRCODE='55000';END IF;
END $$;
CREATE FUNCTION identity.list_bulk_resets(a integer,s bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;BEGIN PERFORM identity.assert_bulk_reset_actor(a,s);
 SELECT COALESCE(jsonb_agg(identity.bulk_reset_snapshot(operation_id) ORDER BY created_at),'[]'::jsonb) INTO result
 FROM (SELECT p.* FROM identity.bulk_reset_operations p WHERE actor_id=a AND EXISTS(SELECT 1 FROM identity.bulk_reset_children c WHERE c.operation_id=p.operation_id AND state NOT IN ('completed','deleted')) ORDER BY created_at LIMIT 100) pending;
 RETURN result;END $$;
REVOKE ALL ON FUNCTION identity.assert_bulk_reset_actor(integer,bigint),identity.bulk_reset_snapshot(uuid),identity.begin_bulk_reset(uuid,integer,bigint,text,text[]),identity.claim_bulk_reset_child(uuid,integer,bigint,integer,uuid,boolean),identity.finish_bulk_reset_child(uuid,integer,bigint,integer,uuid,boolean,text),identity.list_bulk_resets(integer,bigint) FROM PUBLIC,dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.begin_bulk_reset(uuid,integer,bigint,text,text[]),identity.claim_bulk_reset_child(uuid,integer,bigint,integer,uuid,boolean),identity.finish_bulk_reset_child(uuid,integer,bigint,integer,uuid,boolean,text),identity.list_bulk_resets(integer,bigint) TO dvaia_identity_runtime;
