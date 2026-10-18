'use strict';
// Inert comparison API. No method authorizes, repairs, enqueues or delivers.
const MAX_ROWS = 256, MAX_BYTES = 262144;
function decimal(value, positive = false) {
  const text = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(text) || BigInt(text) > 9223372036854775807n
    || (positive && text === '0') || (typeof value === 'number' && !Number.isSafeInteger(value))) throw new TypeError('Invalid bigint identity');
  return text;
}
function uuid(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)) throw new TypeError('Invalid UUID');
  return value;
}
function scope(value) {
  if (value === 'global') return value;
  const match = /^(stage|owner):([1-9][0-9]*)$/.exec(value);
  if (!match) throw new TypeError('Invalid scope');
  decimal(match[2], true); return value;
}
function createCtfAuthorityRepository(identityPool, ctfPool) {
  if (typeof identityPool?.query !== 'function' || typeof ctfPool?.query !== 'function') throw new TypeError('Both read pools required');
  return Object.freeze({
    async readScopeSnapshot(keys) {
      if (!Array.isArray(keys) || keys.length < 1 || keys.length > 3 || new Set(keys).size !== keys.length) throw new TypeError('One to three distinct scopes required');
      keys.forEach(scope);
      const rows = (await identityPool.query(`SELECT scope_key,revision::text,owner_generation::text,
        lifecycle_state,pending_operation_id,next_sequence::text,applied_sequence::text
        FROM identity.ctf_authority WHERE scope_key=ANY($1::text[]) ORDER BY scope_key`, [keys])).rows;
      return { available: rows.length === keys.length && rows.every(row => row.lifecycle_state === 'ready'), rows };
    },
    async readDecisionByRun(runId) {
      return (await identityPool.query(`SELECT decision_id,run_id,owner_id::text,session_id::text,
        owner_generation::text,global_revision::text,stage_revision::text,participant_id::text,
        progress_id::text,stage_id::text,stage_digest,evidence_hash,verdict,accepted,sequence::text,authorized_at
        FROM identity.ctf_decisions WHERE run_id=$1`, [uuid(runId)])).rows[0] || null;
    },
    async readAppliedProjectionStatus() {
      const row = (await ctfPool.query(`SELECT applied_sequence::text,last_operation_id,initialized
        FROM ctf.projection_cursor WHERE singleton=TRUE`)).rows[0];
      return row ? { available: row.initialized === true, ...row } : { available: false };
    },
    async readAdaptiveSnapshot({ stageId, stageRevision, clearRevision, limit = MAX_ROWS, maxBytes = MAX_BYTES }) {
      if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ROWS || !Number.isInteger(maxBytes)
        || maxBytes < 1 || maxBytes > MAX_BYTES) throw new TypeError('Invalid adaptive bounds');
      const rows = (await identityPool.query(`SELECT memory_id,kind,stage_id::text,stage_revision::text,
        clear_revision::text,owner_id::text,owner_generation::text,technique_tag,payload_hash,
        normalized_payload,decision_id,legacy_source FROM identity.ctf_adaptive_memory
        WHERE stage_id=$1 AND stage_revision=$2 AND clear_revision=$3 ORDER BY memory_id LIMIT $4`,
      [decimal(stageId, true), decimal(stageRevision), decimal(clearRevision), limit + 1])).rows;
      if (rows.length > limit || Buffer.byteLength(JSON.stringify(rows), 'utf8') > maxBytes) {
        return { available: false, complete: false, reason: 'adaptive_snapshot_limit', rows: null };
      }
      // Complete means complete for this single SQL snapshot, not authorization
      // freshness. Later admission must validate its own adaptive revision.
      return { available: true, complete: true, rows };
    },
    async compareLegacyProjection(runId) {
      const id = uuid(runId);
      const projection = (await ctfPool.query(`SELECT run_id,decision_id,authority_version,accepted,
        participant_id::text,progress_id::text,stage_id::text,stage_digest
        FROM ctf.ctf_judgments WHERE run_id=$1`, [id])).rows[0];
      const decision = await this.readDecisionByRun(id);
      if (!projection) return { classification: decision ? 'pending_projection' : 'absent' };
      if (!projection.decision_id && !projection.authority_version) return { classification: decision ? 'unlinked_decision' : 'legacy', legacyAccepted: Number(projection.accepted) === 1 };
      if (!decision) return { classification: 'missing_authority' };
      const matches = projection.authority_version === 'identity-ctf-v1'
        && projection.decision_id === decision.decision_id
        && Number(projection.accepted) === Number(decision.accepted)
        && ['participant_id','progress_id','stage_id','stage_digest'].every(key => String(projection[key]) === String(decision[key]));
      return { classification: matches ? 'linked_comparison_match' : 'mismatch' };
    },
  });
}
module.exports = { createCtfAuthorityRepository };
