'use strict';

const { withTransaction } = require('../database/postgres');
const { assertSecureShopStandaloneAuthPrincipal,
  assertSecureShopStandalonePrincipal } = require('./secureshopStandaloneAuth');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function failure(code) { return Object.assign(new Error('Shared shop practice reset unavailable'), { code }); }
function validId(value) { return typeof value === 'string' && UUID.test(value); }
function scopeChanged() { return failure('SHOP_RESET_SCOPE_CHANGED'); }

function createSecureShopStandaloneReset({ identityPool, authService, launches, scenes,
  resetCoordinator, preflight } = {}) {
  if (typeof identityPool?.query !== 'function' || typeof identityPool?.connect !== 'function'
      || typeof authService?.establishTenantContext !== 'function'
      || typeof launches?.readActiveMetadata !== 'function'
      || typeof scenes?.readExisting !== 'function'
      || typeof resetCoordinator?.reset !== 'function'
      || typeof resetCoordinator?.resumeExisting !== 'function'
      || typeof resetCoordinator?.recover !== 'function'
      || typeof preflight?.preview !== 'function') throw new TypeError('Shared shop reset dependencies required');

  async function principal(base) {
    assertSecureShopStandaloneAuthPrincipal(base);
    if (base.role !== 'admin') throw failure('SHOP_ADMIN_REQUIRED');
    const execution = assertSecureShopStandalonePrincipal(await authService.establishTenantContext(base));
    if (execution.role !== 'admin' || execution.principalId !== base.principalId
        || execution.principalOwnerId !== base.ownerId || execution.authSessionId !== base.sessionId
        || execution.shopUserId !== base.shopUserId) throw failure('SHOP_ADMIN_REQUIRED');
    return execution;
  }

  // The private identity transaction protects the canonical principal identity,
  // current credential and session versions, and active tenant-admin membership
  // only until the reset journal's durable begin. Cleanup proceeds from that
  // journal after this lease ends.
  async function withAdminLease(base, execution, work) {
    return withTransaction(identityPool, async client => {
      await client.query("SET LOCAL lock_timeout='3000ms'");
      const row = (await client.query(`SELECT p.principal_id
        FROM secureshop_auth.principals p
        JOIN secureshop_auth.sessions s ON s.principal_id=p.principal_id
        JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id
        JOIN secureshop_auth.tenants t ON t.tenant_id=m.tenant_id
        JOIN secureshop_auth.execution_sessions e ON e.auth_session_id=s.session_id
          AND e.tenant_id=m.tenant_id AND e.principal_id=p.principal_id
        WHERE p.principal_id=$1 AND p.owner_id=$2 AND p.shop_user_id=$3
          AND s.session_id=$4 AND e.session_id=$5 AND t.tenant_id=$6 AND t.owner_id=$7
          AND m.role='admin' AND m.shop_user_id=p.shop_user_id
          AND m.is_active=true AND t.is_active=true
          AND p.is_active=true AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
          AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp()
          AND s.credential_version=p.credential_version AND s.authority_version=p.authority_version
          AND e.membership_version=m.membership_version
          AND p.credential_version::text=$8 AND p.authority_version::text=$9
          AND m.membership_version::text=$10
        FOR SHARE OF p,s,m,t,e`, [base.principalId,base.ownerId,base.shopUserId,
        base.sessionId,execution.sessionId,execution.tenantId,execution.ownerId,
        base.credentialVersion,base.authorityVersion,execution.membershipVersion])).rows[0];
      if (!row) throw failure('SHOP_ADMIN_REQUIRED');
      return work();
    });
  }

  async function currentScope(execution) {
    const scope = await launches.readActiveMetadata({ platformOwnerId: execution.ownerId,
      platformSessionId: execution.sessionId });
    if (!scope || scope.platformOwnerId !== execution.ownerId
        || scope.platformSessionId !== execution.sessionId || !validId(scope.launchId)
        || !Number.isSafeInteger(scope.generation) || scope.generation < 1) {
      throw failure('SHOP_RESET_UNAVAILABLE');
    }
    return scope;
  }
  async function resetScope(execution, launchId) {
    const row = (await identityPool.query(`SELECT launch_id,generation,status
      FROM identity.secureshop_launches
      WHERE launch_id=$1 AND platform_session_id=$2 AND original_platform_session_id=$2
        AND original_platform_owner_id=$3 AND status IN ('active','resetting')
        AND expires_at>clock_timestamp()`,
    [launchId,execution.sessionId,execution.ownerId])).rows[0];
    if (!row || !validId(row.launch_id) || !Number.isSafeInteger(Number(row.generation))
        || Number(row.generation) < 1) throw scopeChanged();
    return Object.freeze({ launchId: row.launch_id, generation: Number(row.generation), status: row.status });
  }
  async function selectedScene(ownerId) {
    const rows = (await identityPool.query(`SELECT scene_id,status FROM identity.secureshop_scenes
      WHERE original_platform_owner_id=$1 AND status='active' ORDER BY scene_id LIMIT 2`, [ownerId])).rows;
    if (rows.length !== 1 || !validId(rows[0].scene_id)) throw failure('SHOP_RESET_UNAVAILABLE');
    return rows[0].scene_id;
  }
  function recoveryRow(row) {
    if (!row || !validId(row.reset_id) || !validId(row.launch_id) || !validId(row.scene_id)
        || !['fenced','committed','aborted'].includes(row.status)
        || !Number.isSafeInteger(Number(row.from_generation)) || Number(row.from_generation) < 1
        || Number(row.to_generation) !== Number(row.from_generation) + 1
        || !Number.isSafeInteger(Number(row.original_execution_session_id))
        || !Number.isSafeInteger(Number(row.current_generation))
        || typeof row.launch_live !== 'boolean'
        || Number(row.scene_claim_count) !== 1
        || [row.reconciliation_required,row.conversation_reconciliation_required,
          row.progress_reconciliation_required].some(value => typeof value !== 'boolean')) {
      throw failure('SHOP_RESET_UNAVAILABLE');
    }
    return Object.freeze({ resetId: row.reset_id, launchId: row.launch_id,
      fromGeneration: Number(row.from_generation), toGeneration: Number(row.to_generation),
      status: row.status, sceneId: row.scene_id,
      cleanupComplete: !row.reconciliation_required && !row.conversation_reconciliation_required
        && !row.progress_reconciliation_required,
      originalExecutionSessionId: Number(row.original_execution_session_id),
      launchStatus: row.launch_status, currentGeneration: Number(row.current_generation),
      launchLive: row.launch_live });
  }
  async function readRecovery(execution, resetId) {
    const result = await identityPool.query(`SELECT o.reset_id,o.status,o.from_generation,o.to_generation,
        o.reconciliation_required,o.conversation_reconciliation_required,o.progress_reconciliation_required,
        l.launch_id,l.status AS launch_status,l.generation AS current_generation,
        (l.expires_at>clock_timestamp()) AS launch_live,
        l.original_platform_session_id AS original_execution_session_id,
        claim.scene_id,claim.scene_claim_count
      FROM identity.secureshop_launch_resets o
      JOIN identity.secureshop_launches l ON l.launch_id=o.launch_id
      JOIN secureshop_auth.execution_sessions original
        ON original.session_id=l.original_platform_session_id
      LEFT JOIN (SELECT retiring_launch_id,from_generation,min(scene_id::text)::uuid AS scene_id,
          count(*)::int AS scene_claim_count
        FROM identity.secureshop_scene_target_retirements WHERE target_kind='products'
        GROUP BY retiring_launch_id,from_generation) claim
        ON claim.retiring_launch_id=o.launch_id AND claim.from_generation=o.from_generation
      WHERE original.principal_id=$1 AND original.tenant_id=$2
        AND l.original_platform_owner_id=$3
        ${resetId ? 'AND o.reset_id=$4' : ''}
      ORDER BY ${resetId ? 'o.created_at DESC' : `
        (o.status='fenced' OR o.reconciliation_required OR o.conversation_reconciliation_required
          OR o.progress_reconciliation_required) DESC,o.created_at DESC`},o.reset_id DESC LIMIT 1`,
    resetId ? [execution.principalId,execution.tenantId,execution.ownerId,resetId]
      : [execution.principalId,execution.tenantId,execution.ownerId]);
    if (!result.rows[0]) return null;
    return recoveryRow(result.rows[0]);
  }
  async function originalCanActivate(base, execution, row) {
    if (row.originalExecutionSessionId !== execution.sessionId || row.status === 'aborted') return false;
    return withAdminLease(base, execution, async () => {
      const fresh = await readRecovery(execution, row.resetId);
      if (!fresh || fresh.launchId !== row.launchId || fresh.sceneId !== row.sceneId
          || fresh.fromGeneration !== row.fromGeneration
          || fresh.originalExecutionSessionId !== execution.sessionId) throw scopeChanged();
      return ['active','resetting'].includes(fresh.launchStatus) && fresh.status !== 'aborted'
        && fresh.launchLive && fresh.currentGeneration === fresh.toGeneration;
    });
  }
  function mapError(error) {
    if (['SHOP_ADMIN_REQUIRED','SHOP_RESET_SCOPE_CHANGED','SHOP_RESET_CONFLICT',
      'SHOP_RESET_UNAVAILABLE','SHOP_RESET_NOT_FOUND','INVALID_ARGUMENT'].includes(error?.code)) throw error;
    if (['STALE_GENERATION','STALE_LAUNCH','LAUNCH_UNAVAILABLE','SHOP_SCENE_STALE',
      'SHOP_SCENE_SELECTION_REQUIRED'].includes(error?.code)) throw scopeChanged();
    if (error?.code === 'IDEMPOTENCY_CONFLICT') throw failure('SHOP_RESET_CONFLICT');
    throw failure('SHOP_RESET_UNAVAILABLE');
  }

  return Object.freeze({
    async readiness(base) {
      try {
        const execution = await principal(base);
        return await withAdminLease(base, execution, async () => {
          const scope = await currentScope(execution);
          const sceneId = await selectedScene(execution.ownerId);
          // Login and scene listing do not grant access to a retained target.
          // Bind only the existing selected practice for this admin execution;
          // reset readiness must not depend on an unrelated catalog read.
          const existing = await scenes.readExisting(scope);
          if (!existing?.scene || existing.scene.sceneId !== sceneId) throw scopeChanged();
          const granted = createLaunchScope(executionScope(existing));
          const expected = createLaunchScope(scope);
          if (Object.keys(expected).some(key => granted[key] !== expected[key])) throw scopeChanged();
          const proof = await preflight.preview({ ownerId: execution.ownerId,
            launchId: scope.launchId, generation: scope.generation, sceneId });
          if (proof?.available !== true || proof.sceneId !== sceneId) throw failure('SHOP_RESET_UNAVAILABLE');
          return Object.freeze({ available: true, scope: 'shared_practice',
            launchId: scope.launchId, generation: scope.generation,
            scene: Object.freeze({ id: sceneId, label: 'Shop practice 1' }) });
        });
      } catch (error) { mapError(error); }
    },
    async reset(base, input) {
      try {
        if (!input || Object.keys(input).sort().join(',')
            !== 'confirmation,expectedGeneration,idempotencyKey,launchId,sceneId'
            || !validId(input.launchId) || !validId(input.idempotencyKey) || !validId(input.sceneId)
            || !Number.isSafeInteger(input.expectedGeneration) || input.expectedGeneration < 1
            || input.confirmation !== 'RESET_SHARED_PRACTICE') throw failure('INVALID_ARGUMENT');
        const execution = await principal(base);
        const current = await resetScope(execution, input.launchId);
        if (current.launchId !== input.launchId
            || ![input.expectedGeneration,input.expectedGeneration+1].includes(current.generation)) throw scopeChanged();
        const scene = (await identityPool.query(`SELECT scene_id,status FROM identity.secureshop_scenes
          WHERE scene_id=$1 AND original_platform_owner_id=$2`, [input.sceneId,execution.ownerId])).rows[0];
        if (!scene || !['active','retired'].includes(scene.status)) throw scopeChanged();
        if (current.generation === input.expectedGeneration) {
          if (current.status !== 'active') throw scopeChanged();
          const selected = await selectedScene(execution.ownerId);
          if (selected !== scene.scene_id || scene.status !== 'active') throw scopeChanged();
        }
        const result = await resetCoordinator.reset({ launchId: current.launchId,
          platformSessionId: execution.sessionId, platformOwnerId: execution.ownerId,
          expectedGeneration: input.expectedGeneration, idempotencyKey: input.idempotencyKey },
        { expectedSceneId: scene.scene_id, withAdmission: begin => withAdminLease(base, execution, async () => {
          const live = await resetScope(execution, input.launchId);
          if (live.launchId !== current.launchId || live.generation !== current.generation) throw scopeChanged();
          await begin();
        }) });
        if (!validId(result?.resetId) || result.status !== 'committed'
            || result.fromGeneration !== input.expectedGeneration
            || result.toGeneration !== input.expectedGeneration+1
            || result.binding?.launchId !== current.launchId
            || result.binding?.generation !== input.expectedGeneration+1) {
          throw failure('SHOP_RESET_UNAVAILABLE');
        }
        return Object.freeze({ resetId: result.resetId, status: 'committed', cleanupComplete: true });
      } catch (error) { mapError(error); }
    },
    async readRecovery(base) {
      try {
        const execution = await principal(base);
        return withAdminLease(base, execution, async () => {
          const row = await readRecovery(execution);
          return Object.freeze({ pending: row ? Object.freeze({ resetId: row.resetId,
            launchId: row.launchId, fromGeneration: row.fromGeneration,
            toGeneration: row.toGeneration, status: row.status,
            scene: Object.freeze({ id: row.sceneId, label: 'Shop practice' }),
            cleanupComplete: row.cleanupComplete,
            sameExecution: row.originalExecutionSessionId === execution.sessionId }) : null });
        });
      } catch (error) { mapError(error); }
    },
    async recover(base, input) {
      try {
        if (!input || Object.keys(input).sort().join(',') !== 'resetId'
            || !validId(input.resetId)) throw failure('INVALID_ARGUMENT');
        const execution = await principal(base);
        const row = await withAdminLease(base, execution, () => readRecovery(execution, input.resetId));
        if (!row) throw failure('SHOP_RESET_NOT_FOUND');
        let originalLive = await originalCanActivate(base, execution, row);
        if (originalLive) {
          try {
            const resumed = await resetCoordinator.resumeExisting(row.resetId, {
              launchId: row.launchId, platformOwnerId: execution.ownerId,
              platformSessionId: execution.sessionId,
              withAdmission: admit => withAdminLease(base, execution, async () => {
                const exact = await readRecovery(execution, row.resetId);
                if (!exact || exact.launchId !== row.launchId || exact.sceneId !== row.sceneId
                    || exact.fromGeneration !== row.fromGeneration
                    || exact.originalExecutionSessionId !== execution.sessionId) throw scopeChanged();
                await admit();
              }),
            });
            if (resumed?.resetId !== row.resetId || resumed.status !== 'committed'
                || resumed.activated !== true || resumed.binding?.launchId !== row.launchId
                || resumed.binding?.generation !== row.toGeneration) throw failure('SHOP_RESET_UNAVAILABLE');
            return Object.freeze({ resetId: row.resetId, status: 'committed',
              cleanupComplete: true, activated: true });
          } catch (error) {
            if (!['LAUNCH_UNAVAILABLE','STALE_GENERATION',
              'RESET_CLEANUP_AUTHORITY_REQUIRED'].includes(error?.code)) throw error;
            originalLive = await originalCanActivate(base, execution, row);
            if (originalLive) throw error;
          }
        }
        const cleaned = await resetCoordinator.recover(row.resetId);
        if (cleaned?.resetId !== row.resetId || cleaned.resolved !== true
            || cleaned.activated !== false || !['fenced','committed','aborted'].includes(cleaned.status)) {
          throw failure('SHOP_RESET_UNAVAILABLE');
        }
        return Object.freeze({ resetId: row.resetId, status: cleaned.status,
          cleanupComplete: true, activated: false });
      } catch (error) { mapError(error); }
    },
  });
}

module.exports = { createSecureShopStandaloneReset };
