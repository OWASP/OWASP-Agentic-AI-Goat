'use strict';

const { canonicalDurableGeneration } = require('../../agent-runtime/durableGeneration');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SCOPES = new Set(['reflected', 'stored_user', 'stored_llm', 'email']);

function stale(message = 'XSS scope authority is no longer current') {
  const error = new Error(message);
  error.name = 'AbortError';
  error.code = 'XSS_SCOPE_STALE';
  return error;
}

function coordinates(context) {
  if (!context || typeof context !== 'object' || Array.isArray(context)) {
    throw new TypeError('XSS scope context is required');
  }
  const userId = context.scope?.userId;
  if (!Number.isSafeInteger(userId) || userId < 1 || userId > 2147483647) {
    throw new TypeError('Authenticated XSS user ID is required');
  }
  const scopeKey = context.scope?.scopeKey;
  if (!SCOPES.has(scopeKey)) throw new TypeError('Closed XSS scope is required');
  const ownerKey = JSON.stringify(['XSS', String(userId)]);
  if (context.ownerKey !== ownerKey) throw new TypeError('XSS owner scope mismatch');
  if (typeof context.runId !== 'string' || !UUID.test(context.runId)) {
    throw new TypeError('XSS run ID is invalid');
  }
  return Object.freeze({
    runId: context.runId.toLowerCase(), ownerId: userId, ownerKey, scopeKey,
    parentGeneration: canonicalDurableGeneration(context.durableGeneration),
  });
}

function suppliedBinding(context, expected) {
  const value = context.scopeBinding;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw stale();
  if (!Number.isSafeInteger(value.ownerId) || value.ownerId < 1 || value.ownerId > 2147483647) throw stale();
  let parentGeneration;
  let childGeneration;
  try {
    parentGeneration = canonicalDurableGeneration(value.parentGeneration);
    childGeneration = canonicalDurableGeneration(value.childGeneration);
  } catch {
    throw stale();
  }
  const binding = {
    runId:value.runId, ownerId:value.ownerId, ownerKey:value.ownerKey,
    scopeKey:value.scopeKey, parentGeneration, childGeneration,
  };
  for (const key of ['runId', 'ownerId', 'ownerKey', 'scopeKey', 'parentGeneration']) {
    if (binding[key] !== expected[key]) throw stale();
  }
  return Object.freeze(binding);
}

function rowBinding(row) {
  return Object.freeze({
    runId:row.runId, ownerId:Number(row.ownerId), ownerKey:row.ownerKey,
    scopeKey:row.scopeKey,
    parentGeneration:canonicalDurableGeneration(row.parentGeneration),
    childGeneration:canonicalDurableGeneration(row.childGeneration),
  });
}

async function authorityQuery(client, sql, values) {
  try {
    return await client.query(sql, values);
  } catch (error) {
    if (['23503', '23505', '23514', '55000'].includes(error?.code)) {
      const unavailable = stale(); unavailable.cause = error; throw unavailable;
    }
    throw error;
  }
}

function createXssScopeAuthorityRepository() {
  return Object.freeze({
    async bindRun(client, context) {
      if (!client || typeof client.query !== 'function') throw new TypeError('Caller transaction client is required');
      const value = coordinates(context);
      const inserted = await authorityQuery(client, `SELECT run_id AS "runId",owner_id AS "ownerId",
          owner_key AS "ownerKey",scope_key AS "scopeKey",
          parent_generation::text AS "parentGeneration",
          child_generation::text AS "childGeneration"
        FROM identity.bind_xss_run_scope($1,$2,$3,$4,$5)`,
      [value.runId, value.ownerId, value.ownerKey, value.scopeKey, value.parentGeneration]);
      if (inserted.rowCount !== 1) throw stale();
      return rowBinding(inserted.rows[0]);
    },

    async assertRunCurrent(client, context) {
      if (!client || typeof client.query !== 'function') throw new TypeError('Caller transaction client is required');
      const value = coordinates(context);
      const binding = suppliedBinding(context, value);
      const result = await authorityQuery(client, `SELECT run_id AS "runId",owner_id AS "ownerId",
          owner_key AS "ownerKey",scope_key AS "scopeKey",
          parent_generation::text AS "parentGeneration",
          child_generation::text AS "childGeneration"
        FROM identity.assert_xss_run_scope_current($1,$2,$3,$4,$5,$6)`,
      [binding.runId, binding.ownerId, binding.ownerKey, binding.scopeKey,
        binding.parentGeneration, binding.childGeneration]);
      if (result.rowCount !== 1) throw stale();
      const current = rowBinding(result.rows[0]);
      for (const key of ['runId', 'ownerId', 'ownerKey', 'scopeKey', 'parentGeneration', 'childGeneration']) {
        if (current[key] !== binding[key]) throw stale();
      }
      return current;
    },
  });
}

module.exports = { SCOPES, createXssScopeAuthorityRepository };
