'use strict';

const { withTransaction } = require('./index');
const { buildReceipt } = require('./secureshopConversationLifecycleRepository');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[a-f0-9]{64}$/;
const STATUSES = new Set(['fenced', 'committed', 'aborted']);

function failure(code, message = 'Conversation cleanup checkpoint unavailable') {
  return Object.assign(new Error(message), { code });
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function integer(value, label, max) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) {
    throw failure('INVALID_CONVERSATION_RECEIPT', `${label} is invalid`);
  }
  return value;
}
function iso(value) {
  if (!(value instanceof Date) && typeof value !== 'string') throw failure('INVALID_CONVERSATION_RECEIPT');
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw failure('INVALID_CONVERSATION_RECEIPT');
  const canonical = parsed.toISOString();
  if (typeof value === 'string' && value !== canonical) throw failure('INVALID_CONVERSATION_RECEIPT');
  return canonical;
}
function operation(value, resetId) {
  const binding = value?.binding;
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || value.resetId !== resetId
      || !STATUSES.has(value.status) || !binding || Object.getPrototypeOf(binding) !== Object.prototype) {
    throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
  }
  const generation = Number(binding.generation);
  const ownerId = Number(binding.platformOwnerId);
  const sessionId = Number(binding.platformSessionId);
  if (!Number.isSafeInteger(generation) || generation < 1
      || !Number.isInteger(ownerId) || ownerId < 1 || ownerId > 2147483647
      || !Number.isInteger(sessionId) || sessionId < 1 || sessionId > 2147483647) {
    throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
  }
  return Object.freeze({ resetId, status: value.status, launchId: uuid(binding.launchId, 'launchId'),
    scenarioId: uuid(binding.scenarioId, 'scenarioId'), fromGeneration: generation,
    platformOwnerId: ownerId, platformSessionId: sessionId });
}
function receipt(value, expected) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || value.version !== 1
      || value.status !== 'completed' || value.resetId !== expected.resetId
      || value.launchId !== expected.launchId || value.scenarioId !== expected.scenarioId
      || value.fromGeneration !== expected.fromGeneration
      || value.platformOwnerId !== expected.platformOwnerId
      || value.platformSessionId !== expected.platformSessionId
      || typeof value.receiptSha256 !== 'string' || !SHA256.test(value.receiptSha256)
      || typeof value.sessionSetSha256 !== 'string' || !SHA256.test(value.sessionSetSha256)) {
    throw failure('INVALID_CONVERSATION_RECEIPT');
  }
  const normalized = Object.freeze({ ...expected, version: 1, status: 'completed',
    receiptSha256: value.receiptSha256,
    sessionCount: integer(value.sessionCount, 'sessionCount', 256),
    uncertainTurnCount: integer(value.uncertainTurnCount, 'uncertainTurnCount', 65536),
    sessionSetSha256: value.sessionSetSha256, completedAt: iso(value.completedAt) });
  const canonical = buildReceipt({ resetId: normalized.resetId, launchId: normalized.launchId,
    scenarioId: normalized.scenarioId, generation: normalized.fromGeneration,
    platformOwnerId: normalized.platformOwnerId, platformSessionId: normalized.platformSessionId },
  { completedAt: normalized.completedAt, sessionCount: normalized.sessionCount,
    uncertainTurnCount: normalized.uncertainTurnCount,
    sessionSetSha256: normalized.sessionSetSha256 });
  if (canonical.receiptSha256 !== normalized.receiptSha256) {
    throw failure('INVALID_CONVERSATION_RECEIPT');
  }
  return normalized;
}
function matches(row, value) {
  return row.reset_id === value.resetId && row.launch_id === value.launchId
    && row.scenario_id === value.scenarioId && Number(row.from_generation) === value.fromGeneration
    && Number(row.original_platform_owner_id) === value.platformOwnerId
    && Number(row.original_platform_session_id) === value.platformSessionId
    && Number(row.receipt_version) === value.version
    && Buffer.isBuffer(row.receipt_sha256) && row.receipt_sha256.toString('hex') === value.receiptSha256
    && Number(row.session_count) === value.sessionCount
    && Number(row.uncertain_turn_count) === value.uncertainTurnCount
    && Buffer.isBuffer(row.session_set_sha256) && row.session_set_sha256.toString('hex') === value.sessionSetSha256
    && new Date(row.target_completed_at).toISOString() === value.completedAt;
}
function project(row) {
  return Object.freeze({ resetId: row.reset_id, launchId: row.launch_id,
    scenarioId: row.scenario_id, fromGeneration: Number(row.from_generation),
    platformOwnerId: Number(row.original_platform_owner_id),
    platformSessionId: Number(row.original_platform_session_id), version: Number(row.receipt_version),
    receiptSha256: row.receipt_sha256.toString('hex'), sessionCount: Number(row.session_count),
    uncertainTurnCount: Number(row.uncertain_turn_count),
    sessionSetSha256: row.session_set_sha256.toString('hex'),
    completedAt: new Date(row.target_completed_at).toISOString(), verifiedAt: row.verified_at });
}

/** Private cross-database checkpoint; callers never supply a receipt DTO. */
function createSecureShopConversationCleanupCheckpointRepository(pool, dependencies = {}) {
  if (typeof pool?.connect !== 'function' || typeof pool?.query !== 'function'
      || typeof dependencies.getOperation !== 'function'
      || typeof dependencies.readRetirementReceipt !== 'function') {
    throw failure('INVALID_CONFIGURATION');
  }
  const getOperation = dependencies.getOperation;
  const readRetirementReceipt = dependencies.readRetirementReceipt;
  return Object.freeze({
    async finalize(value) {
      const resetId = uuid(value, 'resetId');
      const expected = operation(await getOperation(resetId), resetId);
      const verified = receipt(await readRetirementReceipt(resetId), expected);
      return withTransaction(pool, async client => {
        // Match launch reset operations: launch first, then reset journal.
        const launch = (await client.query(`SELECT launch_id,scenario_id,original_platform_owner_id,
            original_platform_session_id FROM identity.secureshop_launches
          WHERE launch_id=$1 FOR UPDATE`, [expected.launchId])).rows[0];
        const reset = (await client.query(`SELECT * FROM identity.secureshop_launch_resets
          WHERE reset_id=$1 AND launch_id=$2 FOR UPDATE`, [resetId, expected.launchId])).rows[0];
        if (!launch || !reset || launch.scenario_id !== expected.scenarioId
            || Number(launch.original_platform_owner_id) !== expected.platformOwnerId
            || Number(launch.original_platform_session_id) !== expected.platformSessionId
            || Number(reset.from_generation) !== expected.fromGeneration
            || !STATUSES.has(reset.status)) {
          throw failure('CONVERSATION_CHECKPOINT_MISMATCH');
        }
        const existing = (await client.query(`SELECT * FROM identity.secureshop_conversation_cleanup_history
          WHERE reset_id=$1 OR (launch_id=$2 AND from_generation=$3)`,
        [resetId, expected.launchId, expected.fromGeneration])).rows;
        let row;
        let replayed = false;
        if (existing.length) {
          if (existing.length !== 1 || !matches(existing[0], verified)) {
            throw failure('CONVERSATION_CHECKPOINT_MISMATCH');
          }
          row = existing[0];
          replayed = true;
        } else {
          row = (await client.query(`INSERT INTO identity.secureshop_conversation_cleanup_history
            (reset_id,launch_id,scenario_id,from_generation,original_platform_owner_id,
             original_platform_session_id,receipt_version,receipt_sha256,session_count,
             uncertain_turn_count,session_set_sha256,target_completed_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
          [verified.resetId, verified.launchId, verified.scenarioId, verified.fromGeneration,
            verified.platformOwnerId, verified.platformSessionId, verified.version,
            Buffer.from(verified.receiptSha256, 'hex'), verified.sessionCount,
            verified.uncertainTurnCount, Buffer.from(verified.sessionSetSha256, 'hex'),
            verified.completedAt])).rows[0];
        }
        if (reset.conversation_reconciliation_required) {
          const changed = await client.query(`UPDATE identity.secureshop_launch_resets
            SET conversation_reconciliation_required=false,updated_at=clock_timestamp()
            WHERE reset_id=$1 AND conversation_reconciliation_required`, [resetId]);
          if (changed.rowCount !== 1) throw failure('CONVERSATION_CHECKPOINT_MISMATCH');
        }
        return Object.freeze({ resetId, replayed, checkpoint: project(row) });
      });
    },
  });
}

module.exports = { createSecureShopConversationCleanupCheckpointRepository };
