'use strict';

const { withTransaction } = require('./index');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROUTES = new Set([
  'prompt_injection',
  'chain_of_thought',
  'context_stuffing',
  'multi_turn_jailbreak',
]);
const PG_BIGINT_MAX = 9223372036854775807n;

function invalid(message) {
  return Object.assign(new TypeError(message), { code: 'BAD_REQUEST' });
}

function ownerId(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw invalid('Valid legacy AI history owner required');
  }
  return value;
}

function positiveBigint(value, label) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 1) throw invalid(`Valid ${label} required`);
    value = String(value);
  } else if (typeof value === 'bigint') {
    value = value.toString();
  }
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)
      || BigInt(value) > PG_BIGINT_MAX) throw invalid(`Valid ${label} required`);
  return value;
}

function generation(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw invalid('Valid history generation required');
    value = String(value);
  } else if (typeof value === 'bigint') {
    value = value.toString();
  }
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)
      || BigInt(value) > PG_BIGINT_MAX) throw invalid('Valid history generation required');
  return value;
}

function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw invalid(`Valid ${label} required`);
  return value.toLowerCase();
}

function content(value, label, maxBytes) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > maxBytes) {
    throw invalid(`Valid ${label} required`);
  }
  return value;
}

function sourceRoute(value) {
  if (!ROUTES.has(value)) throw invalid('Valid legacy AI source route required');
  return value;
}

function limit(value = 100) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 200) {
    throw invalid('History limit must be between 1 and 200');
  }
  return value;
}

function cursor({ beforeCursor = null, ...unsupported } = {}) {
  if (Object.keys(unsupported).length) throw invalid('Opaque history cursor required');
  if (beforeCursor == null) return null;
  if (typeof beforeCursor !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(beforeCursor)) {
    throw invalid('Valid opaque history cursor required');
  }
  const [timestamp, requestId] = beforeCursor.split('|');
  return `${timestamp}|${requestId.toLowerCase()}`;
}

function row(value) {
  if (!value) return null;
  return Object.freeze({
    requestId: value.request_id,
    ownerId: Number(value.owner_id),
    generation: String(value.generation),
    sourceRoute: value.source_route,
    prompt: value.prompt,
    response: value.response,
    modelUsed: value.model_used,
    createdAt: value.created_at,
    cursor: value.cursor_token,
    replayed: value.replayed === true,
  });
}

function resetReceipt(value) {
  if (!value) return null;
  return Object.freeze({
    resetRequestId: value.reset_request_id,
    ownerId: Number(value.owner_id),
    fromGeneration: String(value.from_generation),
    toGeneration: String(value.to_generation),
    removedCount: Number(value.removed_count),
    createdAt: value.created_at,
    replayed: value.replayed === true,
  });
}

function deletionReceipt(value) {
  if (!value) return null;
  return Object.freeze({
    jobId: value.job_id,
    ownerId: Number(value.owner_id),
    historyRemoved: Number(value.history_removed),
    resetReceiptsRemoved: Number(value.reset_receipts_removed),
    ownerStateRemoved: Number(value.owner_state_removed),
    archiveRemoved: Number(value.archive_removed),
    createdAt: value.created_at,
    replayed: value.replayed === true,
  });
}

function requirePool(pool) {
  if (!pool || typeof pool.connect !== 'function' || typeof pool.query !== 'function') {
    throw new TypeError('PostgreSQL identity pool required');
  }
  return pool;
}

// Draft-only repository. Do not mount until the unregistered schema, cutover,
// privilege boundary, and populated-upgrade path are qualified and promoted.
function createLegacyAiHistoryRepository(pool) {
  requirePool(pool);
  const query = work => withTransaction(pool, work);
  return Object.freeze({
    async admit({ ownerId: owner, sessionId } = {}) {
      const values = [ownerId(owner), positiveBigint(sessionId, 'platform session')];
      const result = await query(client => client.query(
        'SELECT * FROM legacy_ai_private.admit_history($1,$2)', values));
      const admitted = result.rows[0];
      if (!admitted || Number(admitted.owner_id) !== values[0]
          || String(admitted.session_id) !== values[1]) {
        throw Object.assign(new Error('History admission authority mismatch'), { code: '55000' });
      }
      return Object.freeze({ ownerId: values[0], sessionId: values[1],
        generation: generation(admitted.generation) });
    },

    async append({ ownerId: owner, sessionId, generation: expectedGeneration, requestId,
      sourceRoute: route, prompt, response, modelUsed } = {}) {
      const values = [
        ownerId(owner),
        positiveBigint(sessionId, 'platform session'),
        generation(expectedGeneration),
        uuid(requestId, 'history request ID'),
        sourceRoute(route),
        content(prompt, 'history prompt', 65536),
        content(response, 'history response', 262144),
        content(modelUsed, 'history model', 256),
      ];
      const result = await query(client => client.query(
        'SELECT * FROM legacy_ai_private.append_history($1,$2,$3,$4,$5,$6,$7,$8)', values));
      return row(result.rows[0]);
    },

    async listOwn({ ownerId: owner, sessionId, limit: requestedLimit = 100, ...requestedCursor } = {}) {
      const beforeCursor = cursor(requestedCursor);
      const values = [ownerId(owner), positiveBigint(sessionId, 'platform session'),
        limit(requestedLimit), beforeCursor];
      const result = await query(client => client.query(
        'SELECT * FROM legacy_ai_private.list_own_history($1,$2,$3,$4)', values));
      return Object.freeze(result.rows.map(row));
    },

    async listAdmin({ adminId, sessionId, limit: requestedLimit = 100, ...requestedCursor } = {}) {
      const beforeCursor = cursor(requestedCursor);
      const values = [ownerId(adminId), positiveBigint(sessionId, 'platform session'),
        limit(requestedLimit), beforeCursor];
      const result = await query(client => client.query(
        'SELECT * FROM legacy_ai_private.list_admin_history($1,$2,$3,$4)', values));
      return Object.freeze(result.rows.map(row));
    },

    async reset({ ownerId: owner, sessionId, generation: expectedGeneration, resetRequestId } = {}) {
      const values = [ownerId(owner), positiveBigint(sessionId, 'platform session'),
        generation(expectedGeneration), uuid(resetRequestId, 'history reset request ID')];
      const result = await query(client => client.query(
        'SELECT * FROM legacy_ai_private.reset_history($1,$2,$3,$4)', values));
      return resetReceipt(result.rows[0]);
    },

    async cleanupForStudentDeletion({ ownerId: owner, jobId, leaseToken } = {}) {
      const values = [uuid(jobId, 'student deletion job ID'), uuid(leaseToken, 'student deletion lease token'), ownerId(owner)];
      const result = await query(client => client.query(
        'SELECT * FROM legacy_ai_private.cleanup_history_for_student_deletion($1,$2,$3)', values));
      return deletionReceipt(result.rows[0]);
    },
  });
}

module.exports = { createLegacyAiHistoryRepository };
