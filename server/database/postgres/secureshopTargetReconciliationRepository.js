'use strict';

const { withTransaction } = require('./index');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[a-f0-9]{64}$/;
const KINDS = new Set(['files', 'mcp_rogue', 'mcp_rug_pull', 'persona_inbox', 'products', 'reviews', 'controlled_ssrf']);

function failure(code, message) {
  return Object.assign(new Error(message), { code });
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function positive(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 9007199254740991) {
    throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  }
  return value;
}
function platformId(value, label) {
  positive(value, label);
  if (value > 2147483647) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value;
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function normalizeScope(input) {
  if (!plain(input)) throw failure('INVALID_ARGUMENT', 'target reconciliation scope is invalid');
  if (!KINDS.has(input.targetKind)) throw failure('INVALID_ARGUMENT', 'targetKind is invalid');
  return Object.freeze({
    targetId: uuid(input.targetId, 'targetId'), targetKind: input.targetKind,
    launchId: uuid(input.launchId, 'launchId'), scenarioId: uuid(input.scenarioId, 'scenarioId'),
    fromGeneration: positive(input.fromGeneration, 'fromGeneration'),
    platformOwnerId: platformId(input.platformOwnerId, 'platformOwnerId'),
    platformSessionId: platformId(input.platformSessionId, 'platformSessionId'),
  });
}
function authority(scope, operationId) {
  return Object.freeze({ ...scope, operationId });
}
function sameBinding(row, scope, operationId) {
  return row.target_id === scope.targetId && row.target_kind === scope.targetKind
    && row.launch_id === scope.launchId && row.scenario_id === scope.scenarioId
    && Number(row.from_generation) === scope.fromGeneration
    && Number(row.original_platform_owner_id) === scope.platformOwnerId
    && Number(row.original_platform_session_id) === scope.platformSessionId
    && row.operation_id === operationId;
}
function publicHistory(row) {
  return Object.freeze({
    targetId: row.target_id, targetKind: row.target_kind, launchId: row.launch_id,
    scenarioId: row.scenario_id, fromGeneration: Number(row.from_generation),
    platformOwnerId: Number(row.original_platform_owner_id),
    platformSessionId: Number(row.original_platform_session_id), operationId: row.operation_id,
    targetReceiptVersion: Number(row.target_receipt_version),
    targetReceiptSha256: row.target_receipt_sha256.toString('hex'),
    targetCompletedAt: row.target_completed_at, resolvedAt: row.resolved_at,
  });
}
function validateReceipt(receipt, scope, operationId) {
  if (!plain(receipt) || receipt.operationId !== operationId || receipt.targetId !== scope.targetId
      || receipt.kind !== scope.targetKind || receipt.launchId !== scope.launchId
      || receipt.scenarioId !== scope.scenarioId || receipt.generation !== scope.fromGeneration
      || receipt.platformOwnerId !== scope.platformOwnerId
      || receipt.platformSessionId !== scope.platformSessionId
      || receipt.version !== 1
      || typeof receipt.receiptSha256 !== 'string' || !SHA256.test(receipt.receiptSha256)) {
    throw failure('TARGET_RECEIPT_MISMATCH', 'target cleanup receipt does not match the reservation');
  }
  if (!(receipt.completedAt instanceof Date)
      && (typeof receipt.completedAt !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.completedAt))) {
    throw failure('TARGET_RECEIPT_MISMATCH', 'target cleanup receipt is invalid');
  }
  const completedAt = new Date(receipt.completedAt);
  if (!Number.isFinite(completedAt.getTime())) {
    throw failure('TARGET_RECEIPT_MISMATCH', 'target cleanup receipt is invalid');
  }
  if (typeof receipt.completedAt === 'string' && completedAt.toISOString() !== receipt.completedAt) {
    throw failure('TARGET_RECEIPT_MISMATCH', 'target cleanup receipt is invalid');
  }
  return Object.freeze({ version: receipt.version,
    receiptSha256: Buffer.from(receipt.receiptSha256, 'hex'), completedAt });
}
async function lockReconciliation(client, scope, operationId) {
  const keys = [`operation:${scope.targetKind}:${operationId}`, `target:${scope.targetId}`].sort();
  for (const key of keys) {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [key]);
  }
}

function createSecureShopTargetReconciliationRepository(pool, dependencies = {}) {
  if (!pool || typeof pool.connect !== 'function' || typeof pool.query !== 'function'
      || typeof dependencies.checkAuthority !== 'function'
      || typeof dependencies.readCleanupReceipt !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'target reconciliation dependencies are invalid');
  }
  const checkAuthority = dependencies.checkAuthority;
  const readCleanupReceipt = dependencies.readCleanupReceipt;
  return Object.freeze({
    async reconcile(inputScope, { operationId } = {}) {
      const scope = normalizeScope(inputScope);
      const operation = uuid(operationId, 'operationId');
      const trusted = authority(scope, operation);
      await checkAuthority(trusted);
      return withTransaction(pool, async client => {
        await lockReconciliation(client, scope, operation);
        // History is immutable. The transaction-scoped operation/target advisory
        // locks above serialize repository replays without granting UPDATE solely
        // to obtain a row lock on this audit table.
        const historyRows = (await client.query(`SELECT * FROM identity.secureshop_target_cleanup_history
          WHERE target_id=$1`, [scope.targetId])).rows;
        if (historyRows.length) {
          if (historyRows.length !== 1 || !sameBinding(historyRows[0], scope, operation)
              || !Buffer.isBuffer(historyRows[0].target_receipt_sha256)
              || historyRows[0].target_receipt_sha256.length !== 32) {
            throw failure('TARGET_RECONCILIATION_MISMATCH', 'target reconciliation does not match history');
          }
          const receipt = validateReceipt(await readCleanupReceipt(trusted), scope, operation);
          if (Number(historyRows[0].target_receipt_version) !== receipt.version
              || !historyRows[0].target_receipt_sha256.equals(receipt.receiptSha256)
              || new Date(historyRows[0].target_completed_at).getTime() !== receipt.completedAt.getTime()) {
            throw failure('TARGET_RECONCILIATION_MISMATCH', 'target receipt no longer matches history');
          }
          await checkAuthority(trusted);
          return Object.freeze({ replayed: true, history: publicHistory(historyRows[0]) });
        }

        const row = (await client.query(`SELECT r.target_id,r.target_kind,r.launch_id,r.generation,
            r.original_platform_owner_id,l.scenario_id,l.original_platform_session_id
          FROM identity.secureshop_target_reservations r
          JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
          WHERE r.target_id=$1 FOR UPDATE OF l`, [scope.targetId])).rows[0];
        if (!row || row.target_kind !== scope.targetKind || row.launch_id !== scope.launchId
            || row.scenario_id !== scope.scenarioId || Number(row.generation) !== scope.fromGeneration
            || Number(row.original_platform_owner_id) !== scope.platformOwnerId
            || Number(row.original_platform_session_id) !== scope.platformSessionId) {
          throw failure('TARGET_RESERVATION_MISMATCH', 'target reservation does not match');
        }
        await checkAuthority(trusted);
        const receipt = validateReceipt(await readCleanupReceipt(trusted), scope, operation);
        await checkAuthority(trusted);
        const inserted = (await client.query(`INSERT INTO identity.secureshop_target_cleanup_history
          (target_id,target_kind,launch_id,scenario_id,from_generation,original_platform_owner_id,
           original_platform_session_id,operation_id,target_receipt_version,target_receipt_sha256,target_completed_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [scope.targetId, scope.targetKind, scope.launchId, scope.scenarioId, scope.fromGeneration,
          scope.platformOwnerId, scope.platformSessionId, operation, receipt.version,
          receipt.receiptSha256, receipt.completedAt])).rows[0];
        const removed = (await client.query(
          'SELECT identity.resolve_secureshop_target_reservation($1) AS resolved', [scope.targetId]
        )).rows[0];
        if (removed?.resolved !== true) throw failure('TARGET_RESERVATION_MISMATCH', 'target reservation changed');
        await checkAuthority(trusted);
        return Object.freeze({ replayed: false, history: publicHistory(inserted) });
      });
    },
  });
}

module.exports = { createSecureShopTargetReconciliationRepository,
  SECURESHOP_RECONCILIATION_TARGET_KINDS:Object.freeze([...KINDS]) };
