'use strict';

const crypto = require('node:crypto');

const hex64 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const positive = value => Number.isSafeInteger(Number(value)) && Number(value) > 0;
const invalid = (code, message) => Object.assign(new Error(message), { code });

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  const encoded = JSON.stringify(value);return encoded === undefined ? 'null' : encoded;
}

function requestFingerprint(input) {
  const body = stableJson(input);
  if (Buffer.byteLength(body) > 131072) throw invalid('CODEBOT_REQUEST_TOO_LARGE', 'CodeBot request context is too large');
  return crypto.createHash('sha256').update(body).digest('hex');
}

function validateClaim(value) {
  if (!value || typeof value.ownerKey !== 'string' || !value.ownerKey || !hex64(value.requestKey)
      || !hex64(value.fingerprint) || !positive(value.userId) || !positive(value.platformSessionId)
      || !Number.isSafeInteger(Number(value.generation)) || Number(value.generation) < 0
      || typeof value.runId !== 'string' || !value.runId) {
    throw invalid('CODEBOT_REQUEST_INVALID', 'Exact CodeBot request authority is required');
  }
}

function createCodeBotRequestJournal(pool) {
  if (typeof pool?.query !== 'function') throw new TypeError('CodeBot request journal pool is required');
  async function readExisting(value) {
    const row = (await pool.query(`SELECT request_fingerprint_sha256 AS fingerprint,user_id AS "userId",
        platform_session_id AS "platformSessionId",generation::text,run_id AS "runId",status,response_json AS response
      FROM graph_runtime.codebot_requests WHERE owner_key=$1 AND request_key_sha256=$2`, [value.ownerKey,value.requestKey])).rows[0];
    if (!row) return null;
    if (row.fingerprint !== value.fingerprint) throw invalid('CODEBOT_REQUEST_FINGERPRINT_CONFLICT', 'Idempotency-Key was already used for a different CodeBot request');
    if (Number(row.userId) !== Number(value.userId) || Number(row.platformSessionId) !== Number(value.platformSessionId)) {
      throw invalid('CODEBOT_REQUEST_SESSION_CONFLICT', 'Idempotency-Key belongs to another platform session');
    }
    if (String(row.generation) !== String(value.generation)) throw invalid('CODEBOT_REQUEST_GENERATION_CONFLICT', 'Idempotency-Key belongs to an earlier CodeBot generation');
    if (row.status !== 'completed' || !row.response) throw invalid('CODEBOT_REQUEST_INCOMPLETE', 'The prior CodeBot request did not complete and will not be replayed');
    return Object.freeze({ replayed: true, response: Object.freeze(structuredClone(row.response)) });
  }
  return Object.freeze({
    async assertReady() {
      const row = (await pool.query(`SELECT relation_ready,
        CASE WHEN relation_ready THEN has_table_privilege(current_user,relation_oid,'SELECT') ELSE false END AS can_select,
        CASE WHEN relation_ready THEN has_table_privilege(current_user,relation_oid,'INSERT') ELSE false END AS can_insert,
        CASE WHEN relation_ready THEN has_column_privilege(current_user,relation_oid,'status','UPDATE') ELSE false END AS can_update_status,
        CASE WHEN relation_ready THEN has_column_privilege(current_user,relation_oid,'response_json','UPDATE') ELSE false END AS can_update_response
        FROM (SELECT to_regclass('graph_runtime.codebot_requests') AS relation_oid,
          to_regclass('graph_runtime.codebot_requests') IS NOT NULL AS relation_ready) readiness`)).rows[0];
      if (!row?.relation_ready || !row.can_select || !row.can_insert || !row.can_update_status || !row.can_update_response) {
        throw invalid('CODEBOT_REQUEST_JOURNAL_UNAVAILABLE', 'CodeBot request replay storage is unavailable');
      }
      return true;
    },
    async replay(value) {
      validateClaim(value);
      return readExisting(value);
    },
    async claim(value) {
      validateClaim(value);
      const inserted = await pool.query(`INSERT INTO graph_runtime.codebot_requests(
          owner_key,request_key_sha256,request_fingerprint_sha256,user_id,platform_session_id,generation,run_id,status)
        SELECT $1,$2,$3,$4,$5,$6,$7,'started'
        FROM graph_runtime.runs active_run JOIN identity.user_sessions session ON session.id=$5 AND session.user_id=$4
        WHERE active_run.run_id=$7 AND active_run.owner_key=$1 AND active_run.generation=$6 AND active_run.status='running'
          AND session.is_active=1 AND session.expires_at>clock_timestamp()
        ON CONFLICT(owner_key,request_key_sha256) DO NOTHING
        RETURNING run_id`, [value.ownerKey,value.requestKey,value.fingerprint,Number(value.userId),Number(value.platformSessionId),Number(value.generation),value.runId]);
      if (inserted.rowCount === 1) return Object.freeze({ replayed: false });
      const existing = await readExisting(value);
      if (!existing) throw invalid('CODEBOT_REQUEST_ADMISSION_REJECTED', 'CodeBot request admission is unavailable');
      return existing;
    },
    async complete(value, response) {
      validateClaim(value);
      const encoded = JSON.stringify(response);
      if (!response || typeof response !== 'object' || Array.isArray(response) || Buffer.byteLength(encoded) > 262144) {
        throw invalid('CODEBOT_RESPONSE_INVALID', 'CodeBot response is unavailable for replay');
      }
      const result = await pool.query(`UPDATE graph_runtime.codebot_requests
        SET status='completed',response_json=$8::jsonb,updated_at=clock_timestamp()
        WHERE owner_key=$1 AND request_key_sha256=$2 AND request_fingerprint_sha256=$3
          AND user_id=$4 AND platform_session_id=$5 AND generation=$6 AND run_id=$7 AND status='started'`,
      [value.ownerKey,value.requestKey,value.fingerprint,Number(value.userId),Number(value.platformSessionId),Number(value.generation),value.runId,encoded]);
      if (result.rowCount !== 1) throw invalid('CODEBOT_REQUEST_COMPLETION_REJECTED', 'CodeBot request result could not be committed');
      return true;
    },
    async markUncertain(value) {
      validateClaim(value);
      await pool.query(`UPDATE graph_runtime.codebot_requests SET status='uncertain',updated_at=clock_timestamp()
        WHERE owner_key=$1 AND request_key_sha256=$2 AND request_fingerprint_sha256=$3
          AND user_id=$4 AND platform_session_id=$5 AND generation=$6 AND run_id=$7 AND status='started'`,
      [value.ownerKey,value.requestKey,value.fingerprint,Number(value.userId),Number(value.platformSessionId),Number(value.generation),value.runId]);
    },
  });
}

let configured;
function getConfiguredCodeBotRequestJournal() {
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') return null;
  if (!configured) configured = createCodeBotRequestJournal(require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().pool);
  return configured;
}

module.exports = { createCodeBotRequestJournal, getConfiguredCodeBotRequestJournal, requestFingerprint, stableJson };
