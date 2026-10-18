'use strict';

const {
  createHash
} = require('node:crypto');
const {
  ownerTransaction,
  userId,
  key,
  error
} = require('./workshopPlatformSupport');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function boundedEvidence(evidence, maxBytes) {
  let bytes = 0;
  const seen = new Set();
  function visit(value, depth) {
    if (depth > 12) throw Error('depth_limit');
    if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number' && Number.isFinite(value)) {
      const size = typeof value === 'string' ? Buffer.byteLength(value) : 8;
      bytes += size;
      if (bytes > maxBytes) throw Error('byte_limit');
      return value;
    }
    if (typeof value !== 'object' || seen.has(value) || !Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw Error('unsupported_json');
    seen.add(value);
    const out = Array.isArray(value) ? [] : Object.create(null);
    for (const field of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, field);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw Error('unsupported_json');
      // These are transport/provider fields, never a tool outcome evidence contract.
      if (/^(authorization|proxy-authorization|headers|requestHeaders|processEnv|providerCredentials|apiKey|api_key|accessToken|refreshToken)$/i.test(field)) throw Error('forbidden_transport_field');
      bytes += Buffer.byteLength(field) + 4;
      if (bytes > maxBytes) throw Error('byte_limit');
      out[field] = visit(descriptor.value, depth + 1);
    }
    seen.delete(value);
    return out;
  }
  try {
    const safe = visit(evidence, 0);
    const json = JSON.stringify(safe);
    if (Buffer.byteLength(json) > maxBytes) throw Error('byte_limit');
    return {
      json,
      digest: createHash('sha256').update(json).digest('hex'),
      omitted: false,
      reason: null
    };
  } catch (cause) {
    const reason = ['depth_limit', 'byte_limit', 'forbidden_transport_field'].includes(cause.message) ? cause.message : 'unsupported_json';
    // Do not serialize oversized/forbidden input just to hash it. Omission IDs remain immutable tombstones.
    return {
      json: null,
      digest: createHash('sha256').update(`omitted:${reason}`).digest('hex'),
      omitted: true,
      reason
    };
  }
}
function createObjectiveEvidenceRepository(pool, {
  maxEntries = 20,
  maxBytes = 16000,
  retentionSeconds = 86400
} = {}) {
  for (const [value, min, max] of [[maxEntries, 1, 100], [maxBytes, 256, 16000], [retentionSeconds, 60, 2592000]]) if (!Number.isInteger(value) || value < min || value > max) throw new TypeError('Invalid evidence retention configuration');
  function scope(input) {
    userId(input.userId);
    key(input.workshopKey);
    key(input.scenario);
    if (!Number.isInteger(input.generation) || input.generation < 0) throw error('BAD_REQUEST', 'Canonical generation required');
  }
  const dto = row => ({
    evidenceID: row.evidence_id,
    runId: row.run_id,
    generation: row.generation,
    evidence: row.evidence_json,
    omitted: row.omitted,
    omissionReason: row.omission_reason,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  });
  async function prune(client, uid, w, scenario, generation) {
    await client.query('DELETE FROM workshop_platform.objective_evidence WHERE user_id=$1 AND workshop_key=$2 AND (expires_at<=clock_timestamp() OR generation<>$3)', [uid, w, generation]);
    await client.query('DELETE FROM workshop_platform.objective_evidence WHERE id IN (SELECT id FROM workshop_platform.objective_evidence WHERE user_id=$1 AND workshop_key=$2 AND scenario=$3 AND generation=$4 ORDER BY id DESC OFFSET $5)', [uid, w, scenario, generation, maxEntries]);
  }
  return {
    append(input) {
      scope(input);
      key(input.evidenceID);
      if (!UUID.test(input.runId || '')) throw error('BAD_REQUEST', 'Execution run UUID required');
      const value = boundedEvidence(input.evidence, maxBytes);
      return ownerTransaction(pool, input.userId, input.workshopKey, input.generation, async (client, w, _state, uid) => {
        const old = (await client.query('SELECT * FROM workshop_platform.objective_evidence WHERE user_id=$1 AND workshop_key=$2 AND scenario=$3 AND generation=$4 AND evidence_id=$5', [uid, w.workshop_key, input.scenario, input.generation, input.evidenceID])).rows[0];
        if (old) {
          if (old.run_id !== input.runId.toLowerCase() || old.evidence_digest !== value.digest) throw error('IDEMPOTENCY_CONFLICT', 'Evidence ID already has a different outcome');
          return dto(old);
        }
        const row = (await client.query('INSERT INTO workshop_platform.objective_evidence(user_id,workshop_key,scenario,generation,run_id,evidence_id,evidence_json,evidence_digest,omitted,omission_reason,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,clock_timestamp()+$11*interval \'1 second\') RETURNING *', [uid, w.workshop_key, input.scenario, input.generation, input.runId, input.evidenceID, value.json, value.digest, value.omitted, value.reason, retentionSeconds])).rows[0];
        await prune(client, uid, w.workshop_key, input.scenario, input.generation);
        return dto(row);
      });
    },
    list(input) {
      scope(input);
      const limit = input.limit ?? maxEntries;
      if (!Number.isInteger(limit) || limit < 1 || limit > maxEntries) throw error('BAD_REQUEST', 'Invalid evidence page size');
      return ownerTransaction(pool, input.userId, input.workshopKey, input.generation, async (client, w, _state, uid) => {
        await prune(client, uid, w.workshop_key, input.scenario, input.generation);
        const rows = (await client.query('SELECT * FROM (SELECT * FROM workshop_platform.objective_evidence WHERE user_id=$1 AND workshop_key=$2 AND scenario=$3 AND generation=$4 AND expires_at>clock_timestamp() ORDER BY id DESC LIMIT $5) evidence ORDER BY id', [uid, w.workshop_key, input.scenario, input.generation, limit])).rows;
        return rows.map(dto);
      });
    },
    async purgeExpired({
      limit = 1000
    } = {}) {
      if (!Number.isInteger(limit) || limit < 1 || limit > 10000) throw error('BAD_REQUEST', 'Invalid purge limit');
      await pool.query('UPDATE workshop_platform.grade_packets SET packet=NULL WHERE (user_id,evaluation_id) IN (SELECT user_id,evaluation_id FROM workshop_platform.grade_packets WHERE expires_at<=clock_timestamp() AND packet IS NOT NULL ORDER BY expires_at LIMIT $1)',[limit]);
      return (await pool.query('DELETE FROM workshop_platform.objective_evidence WHERE id IN (SELECT id FROM workshop_platform.objective_evidence WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1)', [limit])).rowCount;
    }
  };
}
module.exports = {
  createObjectiveEvidenceRepository
};
