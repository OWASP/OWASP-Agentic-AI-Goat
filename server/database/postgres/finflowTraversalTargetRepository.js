'use strict';

const { randomUUID } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');

const TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLEANUP_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;

function failure(code, message = code) {
  return Object.assign(new Error(message), { code });
}

function executionScope(execution) {
  if (!execution || typeof execution.ownerKey !== 'string' || execution.ownerKey.length === 0
      || execution.ownerKey.length > 240 || typeof execution.runId !== 'string' || !execution.runId
      || execution.durableGeneration === undefined
      || !/^\d+$/.test(String(execution.durableGeneration))) {
    throw failure('TRAVERSAL_TARGET_AUTH_REQUIRED');
  }
  return Object.freeze({ ownerKey: execution.ownerKey,
    generation: String(execution.durableGeneration) });
}

function ownerKey(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 240) {
    throw new TypeError('Valid traversal owner key required');
  }
  return value;
}

function targetBinding(target) {
  if (!target || typeof target.ownerKey !== 'string' || !/^\d+$/.test(String(target.generation))
      || !TOKEN.test(target.targetToken || '')) throw failure('TRAVERSAL_TARGET_BINDING_MISMATCH');
  return Object.freeze({ ownerKey: target.ownerKey, generation: String(target.generation),
    targetToken: target.targetToken.toLowerCase() });
}

function project(row) {
  return row ? Object.freeze({ ownerKey: row.ownerKey, generation: String(row.generation),
    targetToken: row.targetToken, state: row.state,
    cleanupErrorCode: row.cleanupErrorCode || null }) : null;
}

function createFinflowTraversalTargetRepository({ pool, token = () => randomUUID() } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function') {
    throw new TypeError('FinFlow traversal target pool required');
  }

  const lockStorage = new AsyncLocalStorage();
  const lockKey = scope => `${scope.ownerKey}:${scope.generation}`;
  const query = (scope, sql, params) => {
    const held = lockStorage.getStore();
    if (held) {
      if (held.key !== lockKey(scope)) throw failure('TRAVERSAL_TARGET_LOCK_ORDER_INVALID');
      return held.client.query(sql, params);
    }
    return pool.query(sql, params);
  };
  const unlockedQuery = (sql, params) => {
    if (lockStorage.getStore()) throw failure('TRAVERSAL_TARGET_LOCK_ORDER_INVALID');
    return pool.query(sql, params);
  };

  async function getByBinding(scope) {
    const result = await query(scope, `SELECT owner_key AS "ownerKey",generation::text AS generation,
      target_token::text AS "targetToken",state,cleanup_error_code AS "cleanupErrorCode"
      FROM finflow.traversal_targets WHERE owner_key=$1 AND generation=$2`,
    [scope.ownerKey, scope.generation]);
    return project(result.rows[0]);
  }

  return Object.freeze({
    async assertReady() {
      const row = (await unlockedQuery(`WITH target AS (
        SELECT to_regclass('finflow.traversal_targets') AS oid
      ) SELECT
        target.oid IS NOT NULL AS relation,
        COALESCE(EXISTS(SELECT 1 FROM pg_trigger
          WHERE tgrelid=target.oid AND tgname='finflow_traversal_target_immutability'
            AND NOT tgisinternal),false) AS immutability,
        CASE WHEN target.oid IS NULL THEN false
          ELSE has_table_privilege(current_user,target.oid,'SELECT') END AS runtime_select,
        CASE WHEN target.oid IS NULL THEN false
          ELSE has_table_privilege(current_user,target.oid,'INSERT') END AS runtime_insert,
        CASE WHEN target.oid IS NULL THEN false
          ELSE has_table_privilege(current_user,target.oid,'UPDATE') END AS runtime_update,
        CASE WHEN target.oid IS NULL THEN false
          ELSE NOT has_table_privilege(current_user,target.oid,'DELETE') END AS no_runtime_delete
        FROM target`)).rows[0];
      if (!row || Object.values(row).some(value => value !== true)) {
        throw failure('TRAVERSAL_TARGET_STORAGE_NOT_READY');
      }
      return true;
    },

    async get(execution) {
      return getByBinding(executionScope(execution));
    },

    async getTarget(target) {
      return getByBinding(targetBinding(target));
    },

    async withTargetLock(scopeLike, work) {
      if (typeof work !== 'function') throw new TypeError('Traversal target operation required');
      const scope = scopeLike?.runId ? executionScope(scopeLike) : targetBinding(scopeLike);
      const key = lockKey(scope);
      const held = lockStorage.getStore();
      if (held) {
        if (held.key !== key) throw failure('TRAVERSAL_TARGET_LOCK_ORDER_INVALID');
        return work();
      }
      await scopeLike?.check?.();
      const client = await pool.connect();
      let acquired = false;
      try {
        await client.query('SELECT pg_advisory_lock(hashtextextended($1,0))',
          [`finflow-traversal:${scope.ownerKey}:${scope.generation}`]);
        acquired = true;
        await scopeLike?.check?.();
        return await lockStorage.run({ client, key }, work);
      } finally {
        try {
          if (acquired) await client.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',
            [`finflow-traversal:${scope.ownerKey}:${scope.generation}`]);
          client.release();
        } catch (_) { client.release(true); }
      }
    },

    async reserve(execution) {
      const scope = executionScope(execution);
      await execution.check?.();
      const targetToken = String(token()).toLowerCase();
      if (!TOKEN.test(targetToken)) throw failure('TRAVERSAL_TARGET_TOKEN_INVALID');
      const inserted = await query(scope, `INSERT INTO finflow.traversal_targets
        (owner_key,generation,target_token,state) VALUES($1,$2,$3,'provisioning')
        ON CONFLICT(owner_key,generation) DO NOTHING
        RETURNING owner_key AS "ownerKey",generation::text AS generation,
          target_token::text AS "targetToken",state,cleanup_error_code AS "cleanupErrorCode"`,
      [scope.ownerKey, scope.generation, targetToken]);
      const row = project(inserted.rows[0]) || await getByBinding(scope);
      if (!row) throw failure('TRAVERSAL_TARGET_RESERVATION_FAILED');
      if (row.state === 'retired') throw failure('TRAVERSAL_TARGET_RETIRED');
      if (row.state === 'cleanup_debt') throw failure('TRAVERSAL_TARGET_CLEANUP_DEBT');
      if (!['provisioning', 'active'].includes(row.state)) {
        throw failure('TRAVERSAL_TARGET_STATE_INVALID');
      }
      return row;
    },

    async activate(execution, target) {
      const scope = executionScope(execution);
      const binding = targetBinding(target);
      if (binding.ownerKey !== scope.ownerKey || binding.generation !== scope.generation) {
        throw failure('TRAVERSAL_TARGET_BINDING_MISMATCH');
      }
      await execution.check?.();
      const updated = await query(scope, `UPDATE finflow.traversal_targets
        SET state='active',activated_at=COALESCE(activated_at,clock_timestamp()),cleanup_error_code=NULL
        WHERE owner_key=$1 AND generation=$2 AND target_token=$3 AND state='provisioning'
        RETURNING owner_key AS "ownerKey",generation::text AS generation,
          target_token::text AS "targetToken",state,cleanup_error_code AS "cleanupErrorCode"`,
      [scope.ownerKey, scope.generation, binding.targetToken]);
      if (updated.rowCount === 1) return project(updated.rows[0]);
      const current = await getByBinding(scope);
      if (current?.targetToken === binding.targetToken && current.state === 'active') return current;
      throw failure(current?.state === 'retired'
        ? 'TRAVERSAL_TARGET_RETIRED' : 'TRAVERSAL_TARGET_ACTIVATION_FAILED');
    },

    async listOwner(value) {
      value = ownerKey(value);
      const result = await unlockedQuery(`SELECT owner_key AS "ownerKey",generation::text AS generation,
        target_token::text AS "targetToken",state,cleanup_error_code AS "cleanupErrorCode"
        FROM finflow.traversal_targets WHERE owner_key=$1 ORDER BY generation,target_token`, [value]);
      return Object.freeze(result.rows.map(project));
    },

    async markCleanupDebt(target, code = 'CONTROLLED_TRAVERSAL_CLEANUP_FAILED') {
      const binding = targetBinding(target);
      if (!CLEANUP_CODE.test(code)) code = 'CONTROLLED_TRAVERSAL_CLEANUP_FAILED';
      const updated = await query(binding, `UPDATE finflow.traversal_targets
        SET state='cleanup_debt',cleanup_error_code=$4
        WHERE owner_key=$1 AND generation=$2 AND target_token=$3
          AND state IN ('provisioning','active','cleanup_debt')
        RETURNING owner_key AS "ownerKey",generation::text AS generation,
          target_token::text AS "targetToken",state,cleanup_error_code AS "cleanupErrorCode"`,
      [binding.ownerKey, binding.generation, binding.targetToken, code]);
      if (updated.rowCount === 1) return project(updated.rows[0]);
      const current = await getByBinding(binding);
      if (current?.targetToken === binding.targetToken && current.state === 'retired') return current;
      throw failure('TRAVERSAL_TARGET_CLEANUP_STATE_FAILED');
    },

    async retire(target) {
      const binding = targetBinding(target);
      const updated = await query(binding, `UPDATE finflow.traversal_targets
        SET state='retired',retired_at=COALESCE(retired_at,clock_timestamp()),cleanup_error_code=NULL
        WHERE owner_key=$1 AND generation=$2 AND target_token=$3 AND state='cleanup_debt'
        RETURNING state`, [binding.ownerKey, binding.generation, binding.targetToken]);
      if (updated.rowCount === 1) return true;
      const current = await getByBinding(binding);
      if (current?.targetToken === binding.targetToken && current.state === 'retired') return true;
      throw failure('TRAVERSAL_TARGET_RETIRE_FAILED');
    },
  });
}

module.exports = { createFinflowTraversalTargetRepository };
