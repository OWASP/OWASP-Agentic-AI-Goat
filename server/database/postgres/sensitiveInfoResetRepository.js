'use strict';

const { randomUUID } = require('node:crypto');
const { withTransaction } = require('./index');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const STEPS = Object.freeze(['legacy_store', 'finflow_store']);
function failure(code) { return Object.assign(new Error(code), { code }); }
function owner(value) { const id = Number(value); if (!Number.isSafeInteger(id) || id < 1 || id > 2147483647) throw new TypeError('Valid owner required'); return id; }
function operation(value) { if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('Valid reset operation required'); return value.toLowerCase(); }
function step(value) { if (!STEPS.includes(value)) throw new TypeError('Valid reset step required'); return value; }

function createSensitiveInfoResetRepository(pool) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function') throw new TypeError('PostgreSQL pool required');
  const read = async operationId => {
    operationId = operation(operationId);
    const state = (await pool.query(`SELECT operation_id,owner_id,from_generation,to_generation,status,COALESCE((to_jsonb(r)->>'plan_version')::integer,1) AS plan_version
      FROM identity.sensitive_info_resets r WHERE operation_id=$1`, [operationId])).rows[0];
    if (!state) throw failure('SENSITIVE_INFO_RESET_UNAVAILABLE');
    return Object.freeze({ operationId: state.operation_id, ownerId: Number(state.owner_id),
      fromGeneration: Number(state.from_generation), toGeneration: Number(state.to_generation), status: state.status, planVersion: Number(state.plan_version) });
  };
  return Object.freeze({
    async assertReady() {
      const row = (await pool.query(`SELECT
        to_regclass('identity.sensitive_info_resets') IS NOT NULL AS operations,
        to_regclass('identity.sensitive_info_reset_steps') IS NOT NULL AS steps,
        to_regclass('identity.sensitive_info_reset_authority') IS NOT NULL AS authority,
        to_regprocedure('identity.begin_sensitive_info_reset(integer,uuid)') IS NOT NULL AS begin,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='sensitive_info_reset_judgment_guard' AND NOT tgisinternal) AS judgment_guard,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='sensitive_info_reset_completion_guard' AND NOT tgisinternal) AS completion_guard,
        EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='sensitive_info_reset_run_guard' AND NOT tgisinternal) AS run_guard,
        has_function_privilege(current_user,'identity.begin_sensitive_info_reset(integer,uuid)','EXECUTE') AS runtime_begin,
        NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE p.oid='identity.begin_sensitive_info_reset(integer,uuid)'::regprocedure
            AND a.grantee=0 AND a.privilege_type='EXECUTE') AS no_public_execute`)).rows[0];
      if (!row || Object.values(row).some(value => value !== true)) throw failure('RESET_STORAGE_NOT_READY');
      return true;
    },
    async begin({ ownerId, operationId = randomUUID() } = {}) {
      operationId = operation(operationId);
      const row = (await pool.query('SELECT * FROM identity.begin_sensitive_info_reset($1,$2)',
        [owner(ownerId), operationId])).rows[0];
      if (!row) throw failure('SENSITIVE_INFO_RESET_UNAVAILABLE');
      return Object.freeze({ ...await read(row.operation_id), replayed: row.operation_id !== operationId });
    },
    read,
    async listRecoverable({ limit = 20 } = {}) {
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new TypeError('Invalid recovery limit');
      return (await pool.query(`SELECT operation_id FROM identity.sensitive_info_resets
        WHERE status IN ('pending','failed') OR (status='running' AND lease_expires_at<=clock_timestamp())
        ORDER BY updated_at,operation_id LIMIT $1`, [limit])).rows.map(row => row.operation_id);
    },
    async claim(operationId, leaseMs = 30000) {
      operationId = operation(operationId);
      if (!Number.isInteger(leaseMs) || leaseMs < 1000 || leaseMs > 300000) throw new TypeError('Invalid lease duration');
      const leaseToken = randomUUID();
      const row = (await pool.query(`UPDATE identity.sensitive_info_resets
        SET status='running',lease_token=$2,lease_expires_at=clock_timestamp()+($3*interval '1 millisecond'),
          failure_code=NULL,updated_at=clock_timestamp()
        WHERE operation_id=$1 AND (status IN ('pending','failed') OR
          (status='running' AND lease_expires_at<=clock_timestamp()))
        RETURNING owner_id,from_generation,to_generation`, [operationId, leaseToken, leaseMs])).rows[0];
      return row ? Object.freeze({ operationId, leaseToken, ownerId: Number(row.owner_id),
        fromGeneration: Number(row.from_generation), toGeneration: Number(row.to_generation) }) : null;
    },
    async nextStep({ operationId, leaseToken }) {
      operationId = operation(operationId); leaseToken = operation(leaseToken);
      const rows = (await pool.query(`SELECT s.step_key,s.status,COALESCE((to_jsonb(r)->>'plan_version')::integer,1) AS plan_version FROM identity.sensitive_info_reset_steps s
        JOIN identity.sensitive_info_resets r USING(operation_id)
        WHERE s.operation_id=$1 AND r.status='running' AND r.lease_token=$2
          AND r.lease_expires_at>clock_timestamp() ORDER BY s.ordinal`, [operationId,leaseToken])).rows;
      const expected=rows[0]?.plan_version===2?['finflow_store']:STEPS;
      if (rows.length !== expected.length || rows.some((row,index) => row.step_key !== expected[index])) throw failure('SENSITIVE_INFO_RESET_SCOPE_MISMATCH');
      return rows.find(row => row.status !== 'completed')?.step_key || null;
    },
    async acknowledge({ operationId, leaseToken, stepKey }) {
      operationId = operation(operationId); leaseToken = operation(leaseToken); stepKey = step(stepKey);
      return withTransaction(pool,async client=>{const result = await client.query(`UPDATE identity.sensitive_info_reset_steps s
        SET status='completed',attempts=attempts+1,failure_code=NULL,completed_at=clock_timestamp()
        FROM identity.sensitive_info_resets r WHERE s.operation_id=$1 AND s.step_key=$3
          AND r.operation_id=s.operation_id AND r.status='running' AND r.lease_token=$2
          AND r.lease_expires_at>clock_timestamp() AND s.status<>'completed'
          AND NOT EXISTS(SELECT 1 FROM identity.sensitive_info_reset_steps prior
            WHERE prior.operation_id=s.operation_id AND prior.ordinal<s.ordinal AND prior.status<>'completed')`,
      [operationId,leaseToken,stepKey]);
      if (!result.rowCount) {
        const current = (await client.query('SELECT status FROM identity.sensitive_info_reset_steps WHERE operation_id=$1 AND step_key=$2', [operationId,stepKey])).rows[0];
        if (current?.status !== 'completed') throw failure('SENSITIVE_INFO_RESET_STEP_OUT_OF_ORDER');
      }
      return { completed: true };
      });
    },
    async fail({ operationId, leaseToken, stepKey, code = 'CLEANUP_FAILED' }) {
      operationId = operation(operationId); leaseToken = operation(leaseToken); stepKey = step(stepKey);
      if (typeof code !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/.test(code)) code = 'CLEANUP_FAILED';
      return withTransaction(pool,async client=>{const stepResult = await client.query(`UPDATE identity.sensitive_info_reset_steps s SET status='failed',attempts=attempts+1,failure_code=$4,completed_at=NULL
        FROM identity.sensitive_info_resets r WHERE s.operation_id=$1 AND s.step_key=$3 AND s.status<>'completed'
          AND r.operation_id=s.operation_id AND r.status='running' AND r.lease_token=$2 AND r.lease_expires_at>clock_timestamp()`,
      [operationId,leaseToken,stepKey,code]);
      if (!stepResult.rowCount) throw failure('STALE_SENSITIVE_INFO_RESET_LEASE');
      const result = await client.query(`UPDATE identity.sensitive_info_resets SET status='failed',failure_code=$3,
        lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
        WHERE operation_id=$1 AND status='running' AND lease_token=$2`, [operationId,leaseToken,code]);
      if (!result.rowCount) throw failure('STALE_SENSITIVE_INFO_RESET_LEASE');
      return { status:'failed' };
      });
    },
    async complete({ operationId, leaseToken }) {
      operationId = operation(operationId); leaseToken = operation(leaseToken);
      return withTransaction(pool,async client=>{const result = await client.query(`UPDATE identity.sensitive_info_resets r
        SET status='completed',completed_at=clock_timestamp(),updated_at=clock_timestamp(),lease_token=NULL,lease_expires_at=NULL
        WHERE operation_id=$1 AND status='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp()
          AND NOT EXISTS(SELECT 1 FROM identity.sensitive_info_reset_steps s
            WHERE s.operation_id=r.operation_id AND s.status<>'completed') RETURNING owner_id,from_generation,to_generation,COALESCE((to_jsonb(r)->>'plan_version')::integer,1) AS plan_version`,
      [operationId,leaseToken]);
      if (!result.rowCount) throw failure('SENSITIVE_INFO_RESET_INCOMPLETE');
      return Object.freeze({operationId,ownerId:Number(result.rows[0].owner_id),
        fromGeneration:Number(result.rows[0].from_generation),toGeneration:Number(result.rows[0].to_generation),status:'completed',planVersion:Number(result.rows[0].plan_version)});
      });
    },
  });
}

module.exports = { STEPS, createSensitiveInfoResetRepository };
