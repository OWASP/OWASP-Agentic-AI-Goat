'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function failure(code) { return Object.assign(new Error('SecureShop reset is incomplete'), { code }); }
function operationId(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT');
  return value.toLowerCase();
}

// Aggregate application composition. The target-only coordinator is an
// internal stage, never sufficient to declare a launch reset complete.
function createSecureShopLaunchResetCoordinator({ launches, cleanupAuthority,
  conversationLifecycle, conversationCheckpoint, targetCoordinator, progressCheckpoint, auditSqlLifecycle,
  analyticsLifecycle, sceneResetPreflight } = {}) {
  if ([launches?.beginReset, launches?.commitReset, cleanupAuthority?.getOperation,
    conversationLifecycle?.retireGeneration, conversationCheckpoint?.finalize,
    targetCoordinator?.recover, progressCheckpoint?.finalize].some(fn => typeof fn !== 'function')) {
    throw failure('INVALID_CONFIGURATION');
  }
  if(analyticsLifecycle!==undefined&&typeof analyticsLifecycle?.retireGeneration!=='function')throw failure('INVALID_CONFIGURATION');
  if(auditSqlLifecycle!==undefined&&typeof auditSqlLifecycle?.retireGeneration!=='function')throw failure('INVALID_CONFIGURATION');
  async function clean(value, signal) {
    const resetId = operationId(value);
    const check = () => signal?.throwIfAborted();
    check();
    const authority = await cleanupAuthority.getOperation(resetId);
    if (authority?.resetId !== resetId) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
    if (sceneResetPreflight) await sceneResetPreflight.withOwnerLease(
      authority.binding.platformOwnerId, lease => lease.reconcileRetired(resetId));
    check();
    // Each stage owns a durable checkpoint. Retrying the same reset must resume
    // those stages rather than synthesize a new generation or replay effects.
    await conversationLifecycle.retireGeneration(resetId, { signal });
    check();
    if(auditSqlLifecycle){const audit=await auditSqlLifecycle.retireGeneration(resetId,{signal});if(audit?.resetId!==resetId||audit.retired!==true)throw failure('AUDIT_SQL_CLEANUP_INCOMPLETE');}
    if(analyticsLifecycle){const analytics=await analyticsLifecycle.retireGeneration(resetId,{signal});if(analytics?.resetId!==resetId||analytics.retired!==true)throw failure('ANALYTICS_CLEANUP_INCOMPLETE');}
    const conversation = await conversationCheckpoint.finalize(resetId);
    if (conversation?.resetId !== resetId) throw failure('CONVERSATION_CHECKPOINT_MISMATCH');
    check();
    const targets = await targetCoordinator.recover(resetId);
    if (targets?.resetId !== resetId || targets.resolved !== true || targets.activated !== false) {
      throw failure('TARGET_CLEANUP_INCOMPLETE');
    }
    check();
    const progress = await progressCheckpoint.finalize(resetId);
    if (progress?.resetId !== resetId) throw failure('PROGRESS_CHECKPOINT_MISMATCH');
    check();
    return Object.freeze({ resetId, targets: targets.targets });
  }
  return Object.freeze({
    async reset({ launchId, platformSessionId, platformOwnerId, expectedGeneration,
      idempotencyKey, signal } = {}, { withAdmission, expectedSceneId } = {}) {
      signal?.throwIfAborted();
      if (withAdmission !== undefined && typeof withAdmission !== 'function') throw failure('INVALID_CONFIGURATION');
      let began = false;
      let started;
      let pendingBegin;
      const begin = async () => {
        if (began) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
        began = true;
        pendingBegin = sceneResetPreflight ? sceneResetPreflight.withOwnerLease(platformOwnerId, async lease => {
          const replay = expectedSceneId === undefined ? { exists:false }
            : await lease.readExactResetIntent({ launchId, generation: expectedGeneration,
              idempotencyKey, sceneId: expectedSceneId });
          if (!replay.exists) await lease.preflightLaunches(
            [{ launchId, generation: expectedGeneration }], { expectedSceneId });
          return launches.beginReset({ launchId, platformSessionId, platformOwnerId,
            expectedGeneration, idempotencyKey });
        }) : launches.beginReset({ launchId, platformSessionId, platformOwnerId,
          expectedGeneration, idempotencyKey });
        started = await pendingBegin;
        return started;
      };
      if (withAdmission) await withAdmission(begin);
      else await begin();
      if (pendingBegin) started = await pendingBegin;
      if (!started?.resetId) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
      const cleaned = await clean(started.resetId, signal);
      signal?.throwIfAborted();
      // A committed idempotency-key replay still verifies every durable cleanup
      // stage, but must not attempt a second generation transition.
      const binding = started.status === 'committed' ? started.binding
        : await launches.commitReset({ resetId: cleaned.resetId, launchId,
          platformSessionId, platformOwnerId, expectedGeneration: started.toGeneration });
      if (!binding || binding.generation !== started.toGeneration
          || binding.launchId !== launchId) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
      signal?.throwIfAborted();
      return Object.freeze({ resetId: cleaned.resetId, status: 'committed', binding,
        fromGeneration: started.fromGeneration, toGeneration: started.toGeneration,
        targets: cleaned.targets });
    },
    // Resume an existing durable journal for the same still-live execution.
    // Admission checks the immutable tuple; this path never begins a reset.
    async resumeExisting(resetId, { launchId, platformOwnerId, platformSessionId,
      withAdmission, signal } = {}) {
      const id = operationId(resetId);
      if (withAdmission !== undefined && typeof withAdmission !== 'function') throw failure('INVALID_CONFIGURATION');
      let admitted;
      let calls = 0;
      const admit = async () => {
        if (++calls !== 1) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
        const operation = await cleanupAuthority.getOperation(id);
        const birth = operation?.binding;
        if (operation?.resetId !== id || !['fenced','committed'].includes(operation.status)
            || birth?.launchId !== launchId || birth?.platformOwnerId !== platformOwnerId
            || birth?.platformSessionId !== platformSessionId
            || !Number.isSafeInteger(operation.toGeneration)
            || operation.toGeneration !== birth.generation + 1) {
          throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
        }
        admitted = operation;
        return operation;
      };
      if (withAdmission) await withAdmission(admit);
      else await admit();
      if (!admitted || calls !== 1) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
      const cleaned = await clean(id, signal);
      signal?.throwIfAborted();
      const binding = admitted.status === 'committed'
        ? await launches.readActiveMetadata({ platformOwnerId, platformSessionId })
        : await launches.commitReset({ resetId:id, launchId, platformOwnerId,
          platformSessionId, expectedGeneration:admitted.toGeneration });
      if (binding?.launchId !== launchId || binding?.generation !== admitted.toGeneration)
        throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
      return Object.freeze({ resetId:id, status:'committed', activated:true, binding,
        fromGeneration:admitted.binding.generation,toGeneration:admitted.toGeneration,
        targets:cleaned.targets });
    },
    // Only an existing reset journal supplies cleanup intent after logout or
    // revocation. This path never calls commitReset or restores launch access.
    async recover(resetId, { signal } = {}) {
      const cleaned = await clean(resetId, signal);
      const authority = await cleanupAuthority.getOperation(cleaned.resetId);
      signal?.throwIfAborted();
      if (authority?.resetId !== cleaned.resetId) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
      return Object.freeze({ resetId: cleaned.resetId, status: authority.status,
        resolved: true, activated: false, targets: cleaned.targets });
    },
  });
}

module.exports = { createSecureShopLaunchResetCoordinator };
