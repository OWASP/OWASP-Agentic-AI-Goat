'use strict';

const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

// Qualifies the real launch-reset aggregate for an audit parent fixture.  The
// caller supplies the already-issued launch, bound turns and product adapter;
// this helper only composes the durable cleanup authorities around them.
async function qualifyAuditReset({ identity, agents, review, launches, scope, products, coordinator, turns, beforeReset }) {
  if (!identity || !agents || !launches || !scope || !products || !coordinator || !turns) {
    throw new TypeError('Audit reset qualification dependencies are required');
  }

  const authority = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository')
    .createSecureShopResetCleanupAuthorityRepository(identity);
  // Rebuild the product adapter with the reset authority. Some parent
  // compositions deliberately inject a fail-closed checkCleanup; using that
  // adapter here would make a real product target impossible to reconcile.
  const reviewPool = review || (typeof products.query === 'function' && typeof products.connect === 'function' ? products : null);
  if (!reviewPool) throw new TypeError('Review pool is required for audit reset qualification');
  const productRepository = require('../../server/database/postgres/secureshopBoundProductRepository')
    .createSecureShopBoundProductRepository(reviewPool, {
      checkCurrent: value => launches.assertCurrent(value),
      checkCleanup: value => authority.checkProductTarget(value),
    });
  const lifecycleRows = require('../../server/database/postgres/secureshopConversationLifecycleRepository')
    .createSecureShopConversationLifecycleRepository({ pool: agents });
  const lifecycle = require('../../server/services/secureshopConversationLifecycle')
    .createSecureShopConversationLifecycle({ repository: lifecycleRows, turns, cleanupAuthority: authority });
  const checkpoint = require('../../server/database/postgres/secureshopConversationCleanupCheckpointRepository')
    .createSecureShopConversationCleanupCheckpointRepository(identity, {
      getOperation: resetId => authority.getOperation(resetId),
      readRetirementReceipt: resetId => lifecycle.readReceipt(resetId),
    });
  const progressCheckpoint = require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository')
    .createSecureShopProgressCleanupCheckpointRepository(identity);
  const reconciler = require('../../server/database/postgres/secureshopTargetReconciliationRepository')
    .createSecureShopTargetReconciliationRepository(identity, {
      checkAuthority: input => authority.checkTarget(input),
      readCleanupReceipt: input => {
        if (input.targetKind !== 'products') {
          throw Object.assign(new Error('Unexpected audit reset target'), { code: 'UNSUPPORTED_TARGET_CLEANUP' });
        }
        return productRepository.readCleanupReceipt({
          targetId: input.targetId,
          launchId: input.launchId,
          scenarioId: input.scenarioId,
          generation: input.fromGeneration,
          platformOwnerId: input.platformOwnerId,
          platformSessionId: input.platformSessionId,
        }, { operationId: input.operationId });
      },
    });
  const reviewReset = require('../../server/services/secureshopReviewResetCoordinator')
    .createSecureShopReviewResetCoordinator({
      launches,
      cleanupAuthority: authority,
      // The qualification reserves only a product target. An unexpected
      // review target must fail closed rather than be silently accepted.
      reviewRepository: { async cleanup() { throw new Error('unexpected review target'); } },
      productCleanup: productRepository,
      reconciler,
    });
  let failProgressOnce=true;
  const resetCoordinator = require('../../server/services/secureshopLaunchResetCoordinator')
    .createSecureShopLaunchResetCoordinator({
      launches,
      cleanupAuthority: authority,
      conversationLifecycle: lifecycle,
      conversationCheckpoint: checkpoint,
      targetCoordinator: reviewReset,
      progressCheckpoint:{async finalize(resetId){
        if(failProgressOnce){failProgressOnce=false;throw Object.assign(new Error('Qualification outage before progress checkpoint'),{code:'QUALIFICATION_PROGRESS_OUTAGE'});}
        return progressCheckpoint.finalize(resetId);
      }},
    });

  const judgmentsBefore=(await identity.query('SELECT row_to_json(j) AS receipt FROM workshop_platform.objective_judgments j WHERE user_id=$1 ORDER BY evaluation_id',[scope.platformOwnerId])).rows;
  const siblingSnapshot=async()=>({
    judgments:(await identity.query('SELECT row_to_json(j) AS row FROM workshop_platform.objective_judgments j WHERE user_id<>$1 ORDER BY user_id,evaluation_id',[scope.platformOwnerId])).rows,
    auditRuns:(await agents.query('SELECT row_to_json(r) AS row FROM secureshop_agents.bound_audit_runs r WHERE original_platform_owner_id<>$1 ORDER BY run_id',[scope.platformOwnerId])).rows,
  });
  const siblingsBefore=await siblingSnapshot();
  const input={
    launchId: scope.launchId,
    platformSessionId: scope.platformSessionId,
    platformOwnerId: scope.platformOwnerId,
    expectedGeneration: scope.generation,
    idempotencyKey: randomUUID(),
  };
  const race = beforeReset === undefined ? null : await beforeReset();
  if (race && typeof race.assertRejected !== 'function') throw new TypeError('Audit reset race qualification is invalid');
  try {
    await assert.rejects(resetCoordinator.reset(input),{code:'QUALIFICATION_PROGRESS_OUTAGE'});
    if (race) await race.assertRejected();
  } finally { if (race) await race.close(); }
  await assert.rejects(launches.assertCurrent(scope),{code:'STALE_LAUNCH'});
  const interrupted=(await identity.query('SELECT generation,status FROM identity.secureshop_launches WHERE launch_id=$1',[scope.launchId])).rows[0];
  assert.equal(Number(interrupted.generation),scope.generation+1);assert.equal(interrupted.status,'resetting');
  const reset=await resetCoordinator.reset(input);
  assert.deepEqual(await resetCoordinator.reset(input),reset,'same reset request must recover and replay without another generation');
  assert.deepEqual(await siblingSnapshot(),siblingsBefore,'reset must preserve sibling judgment and audit publications');
  assert.equal(reset.status, 'committed');
  assert.equal(reset.fromGeneration, scope.generation);
  assert.equal(reset.toGeneration, scope.generation + 1);
  assert.equal(reset.targets, 1);
  await assert.rejects(launches.assertCurrent(scope), { code: 'STALE_LAUNCH' });
  const targets = await authority.listTargets(reset.resetId);
  assert.equal(targets.targets.length, 1);
  assert.equal(targets.targets[0].targetKind, 'products');
  const remaining = (await reviewPool.query(
    'SELECT count(*)::integer AS count FROM secureshop_review.product_target_products WHERE target_id=$1',
    [targets.targets[0].targetId],
  )).rows[0].count;
  assert.equal(remaining, 0);
  assert.equal((await reviewPool.query('SELECT lifecycle FROM secureshop_review.product_targets WHERE target_id=$1',[targets.targets[0].targetId])).rows[0].lifecycle,'retired');
  assert.deepEqual((await identity.query('SELECT row_to_json(j) AS receipt FROM workshop_platform.objective_judgments j WHERE user_id=$1 ORDER BY evaluation_id',[scope.platformOwnerId])).rows,judgmentsBefore);
  assert.equal((await identity.query("SELECT count(*)::integer AS count FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='secureshop_agent_security'",[scope.platformOwnerId])).rows[0].count,0);
  assert.equal((await identity.query('SELECT count(*)::integer AS count FROM identity.secureshop_progress_cleanup_history WHERE reset_id=$1',[reset.resetId])).rows[0].count,1);
  return Object.freeze({
    resetId: reset.resetId,
    status: reset.status,
    fromGeneration: reset.fromGeneration,
    toGeneration: reset.toGeneration,
    targets: reset.targets,
    launchResetCoordinator:resetCoordinator,
  });
}

module.exports = { qualifyAuditReset };
