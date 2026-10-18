'use strict';

const crypto = require('node:crypto');
const { withTransaction } = require('./index');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KINDS = new Set(['files', 'mcp_rogue', 'mcp_rug_pull', 'persona_inbox', 'products', 'reviews', 'controlled_ssrf']);
const SHA256 = /^[a-f0-9]{64}$/;

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function number(value, label, max = 9007199254740991) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value;
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function completedAt(value) {
  if (!(value instanceof Date)
      && (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))) {
    throw failure('INVALID_ARGUMENT', 'targetCompletedAt is invalid');
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())
      || (typeof value === 'string' && parsed.toISOString() !== value)) {
    throw failure('INVALID_ARGUMENT', 'targetCompletedAt is invalid');
  }
  return parsed;
}
function verifiedTarget(input, operationId) {
  if (!plain(input) || input.operationId !== operationId || !KINDS.has(input.targetKind)
      || input.targetReceiptVersion !== 1 || typeof input.targetReceiptSha256 !== 'string'
      || !SHA256.test(input.targetReceiptSha256)) {
    throw failure('INVALID_ARGUMENT', 'verified target receipt is invalid');
  }
  return Object.freeze({ targetId: uuid(input.targetId, 'targetId'), targetKind: input.targetKind,
    launchId: uuid(input.launchId, 'launchId'), scenarioId: uuid(input.scenarioId, 'scenarioId'),
    fromGeneration: number(input.fromGeneration, 'fromGeneration'),
    platformOwnerId: number(input.platformOwnerId, 'platformOwnerId', 2147483647),
    platformSessionId: number(input.platformSessionId, 'platformSessionId', 2147483647),
    operationId, targetReceiptVersion: 1,
    targetReceiptSha256: Buffer.from(input.targetReceiptSha256, 'hex'),
    targetCompletedAt: completedAt(input.targetCompletedAt) });
}
function normalizeVerifiedTargets(values, operationId) {
  // Products and reviews each have 256 owner slots; the other five kinds have
  // at most one reservation per launch/generation. Retired scene claims may
  // add those two complete slot sets to a single canonical reset.
  if (!Array.isArray(values) || values.length > KINDS.size + 2 * 255
      || Object.keys(values).length !== values.length) {
    throw failure('INVALID_ARGUMENT', 'verified target receipts are invalid');
  }
  const normalized = values.map(value => verifiedTarget(value, operationId))
    .sort((a, b) => a.targetKind < b.targetKind ? -1
      : a.targetKind > b.targetKind ? 1 : a.targetId < b.targetId ? -1 : a.targetId > b.targetId ? 1 : 0);
  if (new Set(normalized.map(item => `${item.targetKind}:${item.targetId}`)).size !== normalized.length) {
    throw failure('INVALID_ARGUMENT', 'verified target receipts are invalid');
  }
  return normalized;
}
function historyMatches(row, item) {
  return row.target_id === item.targetId && row.target_kind === item.targetKind
    && row.launch_id === item.launchId && row.scenario_id === item.scenarioId
    && Number(row.from_generation) === item.fromGeneration
    && Number(row.original_platform_owner_id) === item.platformOwnerId
    && Number(row.original_platform_session_id) === item.platformSessionId
    && row.operation_id === item.operationId
    && Number(row.target_receipt_version) === item.targetReceiptVersion
    && Buffer.isBuffer(row.target_receipt_sha256) && row.target_receipt_sha256.length === 32
    && crypto.timingSafeEqual(row.target_receipt_sha256, item.targetReceiptSha256)
    && new Date(row.target_completed_at).getTime() === item.targetCompletedAt.getTime();
}
function target(row) {
  return Object.freeze({ targetId: row.target_id, targetKind: row.target_kind,
    launchId: row.launch_id, scenarioId: row.scenario_id,
    fromGeneration: Number(row.from_generation),
    platformOwnerId: Number(row.original_platform_owner_id),
    platformSessionId: Number(row.original_platform_session_id) });
}
// A reset that used a retired scene cannot finish while its single canonical
// inbox cleanup claimant still has the birth reservation. No second receipt is
// created for a later launch that happened to use the same scene.
const mappedMailDebt = `EXISTS (
  SELECT 1 FROM identity.secureshop_scenes scene
  JOIN identity.secureshop_mail_scenes mail ON mail.scene_id=scene.scene_id
  JOIN identity.secureshop_target_reservations r ON r.target_id=mail.target_id
    AND r.target_kind='persona_inbox'
  WHERE scene.status='retired' AND (scene.birth_launch_id=o.launch_id OR EXISTS (
    SELECT 1 FROM identity.secureshop_scene_execution_grants grant_row
    WHERE grant_row.scene_id=scene.scene_id AND grant_row.launch_id=o.launch_id
      AND grant_row.generation=o.from_generation))
)`;
const mappedSceneDebt = `EXISTS (
  SELECT 1 FROM identity.secureshop_scenes scene
  JOIN identity.secureshop_target_reservations r
    ON r.target_id=scene.product_target_id AND r.target_kind='products'
  WHERE scene.status='retired' AND (scene.birth_launch_id=o.launch_id OR EXISTS (
    SELECT 1 FROM identity.secureshop_scene_execution_grants grant_row
    WHERE grant_row.scene_id=scene.scene_id AND grant_row.launch_id=o.launch_id
      AND grant_row.generation=o.from_generation))
) OR EXISTS (
  SELECT 1 FROM identity.secureshop_scenes scene
  JOIN identity.secureshop_scene_review_targets review ON review.scene_id=scene.scene_id
  JOIN identity.secureshop_target_reservations r
    ON r.target_id=review.target_id AND r.target_kind='reviews'
  WHERE scene.status='retired' AND (scene.birth_launch_id=o.launch_id OR EXISTS (
    SELECT 1 FROM identity.secureshop_scene_execution_grants grant_row
    WHERE grant_row.scene_id=scene.scene_id AND grant_row.launch_id=o.launch_id
      AND grant_row.generation=o.from_generation))
)`;

/** Cleanup authority comes from immutable reset/target bindings or the one claimed retired mail scene. */
function createSecureShopResetCleanupAuthorityRepository(pool) {
  if (!pool || typeof pool.query !== 'function') throw failure('INVALID_CONFIGURATION', 'identity pool is required');
  async function checkTarget(input) {
      const operationId = uuid(input?.operationId, 'operationId');
      const targetId = uuid(input?.targetId, 'targetId');
      if (!KINDS.has(input?.targetKind)) throw failure('INVALID_ARGUMENT', 'targetKind is invalid');
      const fromGeneration = number(input.fromGeneration, 'fromGeneration');
      const platformOwnerId = number(input.platformOwnerId, 'platformOwnerId', 2147483647);
      const platformSessionId = number(input.platformSessionId, 'platformSessionId', 2147483647);
      const row = (await pool.query(`SELECT o.status AS reset_status
        FROM identity.secureshop_launch_resets o
        JOIN identity.secureshop_launches l ON l.launch_id=o.launch_id
        WHERE o.reset_id=$1 AND (
          (l.launch_id=$2 AND l.scenario_id=$3
          AND o.from_generation=$4 AND l.original_platform_owner_id=$5
          AND l.original_platform_session_id=$6
          AND NOT ($8='persona_inbox' AND EXISTS (
            SELECT 1 FROM identity.secureshop_mail_scenes m WHERE m.target_id=$7))
          AND NOT ($8='products' AND EXISTS (
            SELECT 1 FROM identity.secureshop_scenes scene WHERE scene.product_target_id=$7))
          AND NOT ($8='reviews' AND EXISTS (
            SELECT 1 FROM identity.secureshop_scene_review_targets scene WHERE scene.target_id=$7))
          AND (EXISTS (SELECT 1 FROM identity.secureshop_target_reservations r
            WHERE r.target_id=$7 AND r.launch_id=l.launch_id AND r.generation=o.from_generation
              AND r.target_kind=$8 AND r.original_platform_owner_id=l.original_platform_owner_id)
            OR EXISTS (SELECT 1 FROM identity.secureshop_target_cleanup_history h
              WHERE h.target_id=$7 AND h.operation_id=o.reset_id AND h.launch_id=l.launch_id
                AND h.scenario_id=l.scenario_id AND h.from_generation=o.from_generation
                AND h.target_kind=$8 AND h.original_platform_owner_id=l.original_platform_owner_id
                AND h.original_platform_session_id=l.original_platform_session_id)))
          OR ($8='persona_inbox' AND identity.mail_scene_reset_cleanup_authorized(
            o.reset_id,$7,$2,$3,$4,$5,$6))
          OR ($8 IN ('products','reviews') AND identity.scene_target_reset_cleanup_authorized(
            o.reset_id,$7,$8,$2,$3,$4,$5,$6)))`,
      [operationId, uuid(input.launchId, 'launchId'), uuid(input.scenarioId, 'scenarioId'),
        fromGeneration, platformOwnerId, platformSessionId, targetId, input.targetKind])).rows[0];
      if (!row) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED', 'reset cleanup authority is unavailable');
      return Object.freeze({ status: row.reset_status });
  }
  return Object.freeze({
    checkTarget,
    async getOperation(resetId) {
      const operationId = uuid(resetId, 'resetId');
      const row = (await pool.query(`SELECT o.status,o.from_generation,o.to_generation,l.launch_id,l.scenario_id,
          l.generation AS current_generation,l.original_platform_owner_id,l.original_platform_session_id
        FROM identity.secureshop_launch_resets o
        JOIN identity.secureshop_launches l ON l.launch_id=o.launch_id
        WHERE o.reset_id=$1`, [operationId])).rows[0];
      if (!row || !['fenced', 'committed', 'aborted'].includes(row.status)
          || Number(row.current_generation) <= Number(row.from_generation)) {
        throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED', 'reset cleanup authority is unavailable');
      }
      number(Number(row.current_generation), 'currentGeneration');
      return Object.freeze({ resetId: operationId, status: row.status,
        toGeneration: number(Number(row.to_generation), 'toGeneration'),
        binding: Object.freeze({ launchId: uuid(row.launch_id, 'launchId'),
          scenarioId: uuid(row.scenario_id, 'scenarioId'),
          generation: number(Number(row.from_generation), 'fromGeneration'),
          platformOwnerId: number(Number(row.original_platform_owner_id), 'platformOwnerId', 2147483647),
          platformSessionId: number(Number(row.original_platform_session_id), 'platformSessionId', 2147483647) }) });
    },
    async checkReviewTarget(input) {
      if (input?.fromGeneration !== undefined && input.fromGeneration !== input.generation) {
        throw failure('INVALID_ARGUMENT', 'review cleanup generation is invalid');
      }
      return checkTarget({ ...input, targetKind: 'reviews', fromGeneration: input?.generation });
    },

    async checkProductTarget(input) {
      if (input?.fromGeneration !== undefined && input.fromGeneration !== input.generation) {
        throw failure('INVALID_ARGUMENT', 'product cleanup generation is invalid');
      }
      return checkTarget({ ...input, targetKind: 'products', fromGeneration: input?.generation });
    },

    async listTargets(resetId) {
      const operationId = uuid(resetId, 'resetId');
      const operation = (await pool.query(`SELECT o.status,l.launch_id,l.scenario_id,o.from_generation,
          l.original_platform_owner_id,l.original_platform_session_id
        FROM identity.secureshop_launch_resets o
        JOIN identity.secureshop_launches l ON l.launch_id=o.launch_id
        WHERE o.reset_id=$1`, [operationId])).rows[0];
      if (!operation) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED', 'reset cleanup authority is unavailable');
      const rows = (await pool.query(`SELECT r.target_id,r.target_kind,r.launch_id,l.scenario_id,
          r.generation AS from_generation,r.original_platform_owner_id,l.original_platform_session_id
        FROM identity.secureshop_target_reservations r
        JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
        WHERE r.launch_id=$1 AND r.generation=$2
          AND (r.target_kind<>'persona_inbox' OR NOT EXISTS (
            SELECT 1 FROM identity.secureshop_mail_scenes m WHERE m.target_id=r.target_id)
            OR identity.mail_scene_reset_cleanup_authorized(
              $3,r.target_id,r.launch_id,l.scenario_id,r.generation,
              r.original_platform_owner_id,l.original_platform_session_id))
          AND (r.target_kind<>'products' OR NOT EXISTS (
            SELECT 1 FROM identity.secureshop_scenes scene WHERE scene.product_target_id=r.target_id)
            OR identity.scene_target_reset_cleanup_authorized(
              $3,r.target_id,r.target_kind,r.launch_id,l.scenario_id,r.generation,
              r.original_platform_owner_id,l.original_platform_session_id))
          AND (r.target_kind<>'reviews' OR NOT EXISTS (
            SELECT 1 FROM identity.secureshop_scene_review_targets scene WHERE scene.target_id=r.target_id)
            OR identity.scene_target_reset_cleanup_authorized(
              $3,r.target_id,r.target_kind,r.launch_id,l.scenario_id,r.generation,
              r.original_platform_owner_id,l.original_platform_session_id))
        UNION ALL
        SELECT h.target_id,h.target_kind,h.launch_id,h.scenario_id,h.from_generation,
          h.original_platform_owner_id,h.original_platform_session_id
        FROM identity.secureshop_target_cleanup_history h
        WHERE h.operation_id=$3
        UNION ALL
        SELECT r.target_id,r.target_kind,r.launch_id,birth.scenario_id,
          r.generation AS from_generation,r.original_platform_owner_id,
          birth.original_platform_session_id
        FROM identity.secureshop_mail_scene_retirements claim
        JOIN identity.secureshop_mail_scenes m ON m.scene_id=claim.scene_id
          AND m.target_id=claim.target_id
        JOIN identity.secureshop_target_reservations r ON r.target_id=m.target_id
          AND r.target_kind='persona_inbox'
        JOIN identity.secureshop_launches birth ON birth.launch_id=r.launch_id
        JOIN identity.secureshop_launch_resets o ON o.launch_id=claim.retiring_launch_id
          AND o.from_generation=claim.from_generation AND o.to_generation=claim.to_generation
        WHERE o.reset_id=$3 AND identity.mail_scene_reset_cleanup_authorized(
          o.reset_id,r.target_id,r.launch_id,birth.scenario_id,r.generation,
          r.original_platform_owner_id,birth.original_platform_session_id)
        UNION ALL
        SELECT r.target_id,r.target_kind,r.launch_id,birth.scenario_id,
          r.generation AS from_generation,r.original_platform_owner_id,
          birth.original_platform_session_id
        FROM identity.secureshop_scene_target_retirements claim
        JOIN identity.secureshop_target_reservations r ON r.target_id=claim.target_id
          AND r.target_kind=claim.target_kind
        JOIN identity.secureshop_launches birth ON birth.launch_id=r.launch_id
        JOIN identity.secureshop_launch_resets o ON o.launch_id=claim.retiring_launch_id
          AND o.from_generation=claim.from_generation AND o.to_generation=claim.to_generation
        WHERE o.reset_id=$3 AND identity.scene_target_reset_cleanup_authorized(
          o.reset_id,r.target_id,r.target_kind,r.launch_id,birth.scenario_id,r.generation,
          r.original_platform_owner_id,birth.original_platform_session_id)`,
      [operation.launch_id, operation.from_generation, operationId])).rows;
      const unique = new Map();
      for (const row of rows) {
        const item = target(row);
        const prior = unique.get(item.targetId);
        if (prior && JSON.stringify(prior) !== JSON.stringify(item)) {
          throw failure('RESET_CLEANUP_BINDING_MISMATCH', 'reset cleanup target history is inconsistent');
        }
        unique.set(item.targetId, item);
      }
      return Object.freeze({ resetId: operationId, status: operation.status,
        targets: Object.freeze([...unique.values()].sort((a, b) => a.targetId < b.targetId ? -1 : a.targetId > b.targetId ? 1 : 0)) });
    },

    async assertResolved(resetId) {
      const operationId = uuid(resetId, 'resetId');
      const row = (await pool.query(`SELECT o.status,NOT EXISTS(
          SELECT 1 FROM identity.secureshop_target_reservations r
          WHERE r.launch_id=o.launch_id AND r.generation<=o.from_generation
        ) AND NOT ${mappedMailDebt} AND NOT (${mappedSceneDebt}) AS resolved
        FROM identity.secureshop_launch_resets o WHERE o.reset_id=$1`, [operationId])).rows[0];
      if (!row || row.resolved !== true) throw failure('CLEANUP_REQUIRED', 'reset target cleanup remains unresolved');
      return Object.freeze({ status: row.status, resolved: true });
    },

    /**
     * Clear only the external-target reconciliation flag. The caller must
     * supply the exact private receipts it just reverified; this method does
     * not complete progress, conversations, or the reset lifecycle itself.
     */
    async finalizeReconciliation(resetId, verifiedTargets) {
      const operationId = uuid(resetId, 'resetId');
      const verified = normalizeVerifiedTargets(verifiedTargets, operationId);
      return withTransaction(pool, async client => {
        const located = (await client.query(
          'SELECT launch_id FROM identity.secureshop_launch_resets WHERE reset_id=$1', [operationId]
        )).rows[0];
        if (!located) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED', 'reset cleanup authority is unavailable');
        // Match launch repository order: launch first, reset journal second.
        const launch = (await client.query(
          `SELECT launch_id,scenario_id,original_platform_owner_id,original_platform_session_id
           FROM identity.secureshop_launches WHERE launch_id=$1 FOR UPDATE`,
          [located.launch_id]
        )).rows[0];
        const operation = (await client.query(
          `SELECT * FROM identity.secureshop_launch_resets
           WHERE reset_id=$1 AND launch_id=$2 FOR UPDATE`, [operationId, located.launch_id]
        )).rows[0];
        if (!launch || !operation) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED', 'reset cleanup authority is unavailable');
        const debt = (await client.query(`SELECT EXISTS(
          SELECT 1 FROM identity.secureshop_target_reservations r
          WHERE r.launch_id=o.launch_id AND r.generation<=o.from_generation
          ) OR ${mappedMailDebt} OR (${mappedSceneDebt}) AS pending
          FROM identity.secureshop_launch_resets o WHERE o.reset_id=$1`, [operationId])).rows[0];
        if (!debt || debt.pending) throw failure('CLEANUP_REQUIRED', 'reset target cleanup remains unresolved');
        const rows = (await client.query(`SELECT * FROM identity.secureshop_target_cleanup_history
          WHERE operation_id=$1 ORDER BY target_kind,target_id`, [operationId])).rows;
        let bindingMismatch = false;
        for (const item of verified) {
          const mapped = item.targetKind === 'persona_inbox' && (await client.query(
            `SELECT EXISTS(SELECT 1 FROM identity.secureshop_mail_scenes WHERE target_id=$1) AS mapped`,
            [item.targetId])).rows[0]?.mapped === true;
          if (mapped) {
            const allowed = (await client.query(`SELECT identity.mail_scene_reset_cleanup_authorized(
              $1,$2,$3,$4,$5,$6,$7) AS allowed`, [operationId,item.targetId,item.launchId,
              item.scenarioId,item.fromGeneration,item.platformOwnerId,item.platformSessionId])).rows[0]?.allowed;
            if (allowed !== true) bindingMismatch = true;
          } else if (item.targetKind === 'products' || item.targetKind === 'reviews') {
            const mappedScene = (await client.query(`SELECT
              (EXISTS(SELECT 1 FROM identity.secureshop_scenes WHERE product_target_id=$1)
                OR EXISTS(SELECT 1 FROM identity.secureshop_scene_review_targets WHERE target_id=$1)) AS mapped`,
            [item.targetId])).rows[0]?.mapped === true;
            if (mappedScene) {
              const allowed = (await client.query(`SELECT identity.scene_target_reset_cleanup_authorized(
                $1,$2,$3,$4,$5,$6,$7,$8) AS allowed`, [operationId,item.targetId,item.targetKind,
                item.launchId,item.scenarioId,item.fromGeneration,item.platformOwnerId,
                item.platformSessionId])).rows[0]?.allowed;
              if (allowed !== true) bindingMismatch = true;
            } else if (item.launchId !== launch.launch_id || item.scenarioId !== launch.scenario_id
              || item.fromGeneration !== Number(operation.from_generation)
              || item.platformOwnerId !== Number(launch.original_platform_owner_id)
              || item.platformSessionId !== Number(launch.original_platform_session_id)) {
              bindingMismatch = true;
            }
          } else if (item.launchId !== launch.launch_id || item.scenarioId !== launch.scenario_id
            || item.fromGeneration !== Number(operation.from_generation)
            || item.platformOwnerId !== Number(launch.original_platform_owner_id)
            || item.platformSessionId !== Number(launch.original_platform_session_id)) {
            bindingMismatch = true;
          }
        }
        if (bindingMismatch || rows.length !== verified.length
            || rows.some((row, index) => !historyMatches(row, verified[index]))) {
          throw failure('TARGET_RECONCILIATION_MISMATCH', 'verified target receipts do not match cleanup history');
        }
        if (operation.reconciliation_required) {
          await client.query(`UPDATE identity.secureshop_launch_resets
            SET reconciliation_required=false,updated_at=clock_timestamp() WHERE reset_id=$1`, [operationId]);
        }
        return Object.freeze({ resetId: operationId, status: operation.status,
          reconciled: true, replayed: operation.reconciliation_required !== true });
      });
    },
  });
}

module.exports = { createSecureShopResetCleanupAuthorityRepository,
  SECURESHOP_RESET_TARGET_KINDS:Object.freeze([...KINDS]) };
