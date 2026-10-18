'use strict';

function failure(code, message) { return Object.assign(new Error(message), { code }); }

function createSecureShopReviewResetCoordinator({ launches, cleanupAuthority, reviewRepository, reconciler,
  fileCleanup, productCleanup, personaInboxCleanup, mcpTrustCleanup, ssrfCleanup } = {}) {
  if (!launches || typeof launches.beginReset !== 'function' || typeof launches.commitReset !== 'function'
      || !cleanupAuthority || typeof cleanupAuthority.listTargets !== 'function'
      || typeof cleanupAuthority.assertResolved !== 'function'
      || typeof cleanupAuthority.finalizeReconciliation !== 'function'
      || !reviewRepository || typeof reviewRepository.cleanup !== 'function'
      || !reconciler || typeof reconciler.reconcile !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'review reset coordinator dependencies are invalid');
  }
  async function cleanup(resetId) {
    const operation = await cleanupAuthority.listTargets(resetId);
    const handlers = Object.freeze({
      reviews: (item) => reviewRepository.cleanup(Object.freeze({ targetId: item.targetId,
        launchId: item.launchId, scenarioId: item.scenarioId, generation: item.fromGeneration,
        platformOwnerId: item.platformOwnerId, platformSessionId: item.platformSessionId }),
      { operationId: resetId }),
      files: typeof fileCleanup?.cleanup === 'function'
        ? (item) => fileCleanup.cleanup(item, { operationId: resetId }) : null,
      products: typeof productCleanup?.cleanup === 'function'
        ? (item) => productCleanup.cleanup(Object.freeze({ targetId: item.targetId,
          launchId: item.launchId, scenarioId: item.scenarioId, generation: item.fromGeneration,
          platformOwnerId: item.platformOwnerId, platformSessionId: item.platformSessionId }),
        { operationId: resetId }) : null,
      persona_inbox: typeof personaInboxCleanup?.cleanup === 'function'
        ? (item) => personaInboxCleanup.cleanup(Object.freeze({ targetId: item.targetId,
          launchId: item.launchId, scenarioId: item.scenarioId, generation: item.fromGeneration,
          platformOwnerId: item.platformOwnerId, platformSessionId: item.platformSessionId }),
        { operationId: resetId }) : null,
      mcp_rogue: typeof mcpTrustCleanup?.cleanup === 'function'
        ? (item) => mcpTrustCleanup.cleanup(item,{operationId:resetId}) : null,
      mcp_rug_pull: typeof mcpTrustCleanup?.cleanup === 'function'
        ? (item) => mcpTrustCleanup.cleanup(item,{operationId:resetId}) : null,
      controlled_ssrf: typeof ssrfCleanup?.cleanup === 'function'
        ? (item) => ssrfCleanup.cleanup(item,{operationId:resetId}) : null,
    });
    const unsupported = operation.targets.filter(item => !Object.hasOwn(handlers, item.targetKind)
      || typeof handlers[item.targetKind] !== 'function');
    if (unsupported.length) {
      throw failure('UNSUPPORTED_TARGET_CLEANUP', 'reset includes a target without a cleanup adapter');
    }
    const results = [];
    for (const item of operation.targets) {
      await handlers[item.targetKind](item);
      results.push(await reconciler.reconcile(item, { operationId: resetId }));
    }
    const resolved = await cleanupAuthority.assertResolved(resetId);
    // Each reconciliation result was produced only after a private target
    // receipt reread. Finalization compares this exact aggregate with durable
    // identity history and clears only the external-target cleanup flag.
    const verifiedTargets = results.map(result => result.history);
    const finalized = await cleanupAuthority.finalizeReconciliation(resetId, verifiedTargets);
    return Object.freeze({ operation, results: Object.freeze(results), resolved, finalized });
  }
  return Object.freeze({
    async reset({ launchId, platformSessionId, platformOwnerId, expectedGeneration, idempotencyKey }) {
      const started = await launches.beginReset({ launchId, platformSessionId, platformOwnerId,
        expectedGeneration, idempotencyKey });
      const cleaned = await cleanup(started.resetId);
      const binding = await launches.commitReset({ resetId: started.resetId, launchId,
        platformSessionId, platformOwnerId, expectedGeneration: started.toGeneration });
      return Object.freeze({ resetId: started.resetId, fromGeneration: started.fromGeneration,
        toGeneration: started.toGeneration, status: 'committed', binding,
        targets: cleaned.operation.targets.length });
    },

    // Internal recovery for a durable reset whose session/launch later became
    // unavailable. It resolves target debt but never reactivates the launch.
    async recover(resetId) {
      const cleaned = await cleanup(resetId);
      return Object.freeze({ resetId: cleaned.operation.resetId, status: cleaned.resolved.status,
        resolved: true, activated: false, targets: cleaned.operation.targets.length });
    },
  });
}

module.exports = { createSecureShopReviewResetCoordinator };
