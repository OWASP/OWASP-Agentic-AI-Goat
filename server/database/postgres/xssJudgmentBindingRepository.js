'use strict';

const { canonicalDurableGeneration } = require('../../agent-runtime/durableGeneration');
const { error } = require('./workshopPlatformSupport');

function stale(cause) {
  const failure = error('STALE_GENERATION', 'XSS child judgment authority is no longer current');
  if (cause) failure.cause = cause;
  return failure;
}
function binding(row) {
  if (!row) return null;
  return Object.freeze({
    runId: row.runId,
    ownerId: Number(row.ownerId),
    ownerKey: row.ownerKey,
    scopeKey: row.scopeKey,
    parentGeneration: canonicalDurableGeneration(row.parentGeneration),
    childGeneration: canonicalDurableGeneration(row.childGeneration),
  });
}
async function query(client, sql, values) {
  try { return await client.query(sql, values); }
  catch (cause) {
    if (['23503', '23505', '23514', '55000'].includes(cause?.code)) throw stale(cause);
    throw cause;
  }
}
const columns = `run_id AS "runId",owner_id AS "ownerId",owner_key AS "ownerKey",
  scope_key AS "scopeKey",parent_generation::text AS "parentGeneration",
  child_generation::text AS "childGeneration"`;

function exact(actual, expected) {
  if (!actual || ['runId','ownerId','ownerKey','scopeKey','parentGeneration','childGeneration']
    .some(key => actual[key] !== expected[key])) throw stale();
  return actual;
}

function createXssJudgmentBindingRepository() {
  return Object.freeze({
    async lockRunPrefix(client, value) {
      const result = await query(client, `SELECT ${columns}
        FROM identity.lock_xss_judgment_run_prefix($1,$2,$3,$4,$5,$6)`,
      [value.runId,value.ownerId,value.ownerKey,value.scopeKey,
        value.parentGeneration,value.childGeneration]);
      if (result.rowCount !== 1) throw stale();
      return exact(binding(result.rows[0]), value);
    },
    async lockEvaluationPrefix(client, { userId, evaluationId }) {
      const result = await query(client, `SELECT ${columns}
        FROM identity.lock_xss_judgment_prefix($1,$2)`, [userId,evaluationId]);
      if (result.rowCount > 1) throw stale();
      return result.rowCount ? binding(result.rows[0]) : null;
    },
    async assertRunIsUnscoped(client, { runId }) {
      if (runId == null) return;
      let result;
      try {
        result = await client.query(
          'SELECT identity.assert_xss_run_unscoped_for_judgment($1) AS unscoped', [runId]);
      } catch (cause) {
        if (cause?.code === '55000') {
          const conflict = error('JUDGMENT_SCOPE_MISMATCH', 'Protected XSS run requires exact child scope');
          conflict.cause = cause; throw conflict;
        }
        throw cause;
      }
      if (result.rows[0]?.unscoped !== true) {
        throw error('JUDGMENT_SCOPE_MISMATCH', 'Protected XSS run requires exact child scope');
      }
    },
    async bindEvaluationAfterWorkshopLock(client, { userId, evaluationId, workshopGeneration, value }) {
      const result = await query(client, `SELECT ${columns}
        FROM identity.bind_xss_judgment_scope($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [userId,evaluationId,value.runId,value.ownerId,value.ownerKey,value.scopeKey,
        value.parentGeneration,value.childGeneration,workshopGeneration]);
      if (result.rowCount !== 1) throw stale();
      return exact(binding(result.rows[0]), value);
    },
    async assertChildAfterWorkshopLock(client, { userId, evaluationId, workshopGeneration, value }) {
      const result = await query(client, `SELECT ${columns}
        FROM identity.assert_xss_judgment_child_current($1,$2,$3)`,
      [userId,evaluationId,workshopGeneration]);
      if (result.rowCount !== 1) throw stale();
      return exact(binding(result.rows[0]), value);
    },
  });
}

module.exports = { createXssJudgmentBindingRepository };
