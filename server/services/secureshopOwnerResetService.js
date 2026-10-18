'use strict';
function createSecureShopOwnerResetService({ repository, launchResetCoordinator, launches,
  sceneResetPreflight } = {}) {
  if (typeof repository?.assertReady !== 'function' || typeof repository?.begin !== 'function'
      || typeof repository?.read !== 'function' || typeof repository?.complete !== 'function'
      || typeof launchResetCoordinator?.recover !== 'function'
      || typeof launches?.commitReset !== 'function') throw new TypeError('SecureShop owner reset dependencies required');
  return Object.freeze({
    async assertReady() { await repository.assertReady(); return true; },
    async resetOwner(ownerId, {operationId} = {}) {
      const execute = async () => {
      const operation = await repository.begin({ ownerId, ...(operationId!==undefined?{operationId}:{}) });
      if(operation.status==='completed')return Object.freeze({operationId:operation.operationId,completed:true,launchCount:operation.launches.length});
      for (const item of operation.launches) {
        const recovered = await launchResetCoordinator.recover(item.resetId);
        if (recovered?.resetId !== item.resetId || recovered.resolved !== true || recovered.activated !== false) {
          throw new Error('SecureShop owner reset cleanup is incomplete');
        }
        if (item.reactivate && !['aborted','committed'].includes(recovered.status)) await launches.commitReset({ resetId: item.resetId,
          launchId: item.launchId, platformSessionId: item.platformSessionId,
          platformOwnerId: ownerId, expectedGeneration: item.toGeneration });
      }
      const replay = await repository.read({ ownerId, operationId: operation.operationId });
      if (replay.launches.length !== operation.launches.length
          || replay.launches.some((item,index) => item.resetId !== operation.launches[index].resetId)) {
        throw new Error('SecureShop owner reset mapping changed');
      }
      return repository.complete({ ownerId, operationId: operation.operationId });
      };
      return sceneResetPreflight ? sceneResetPreflight.withOwnerLease(ownerId, async lease => {
        await lease.preflightLaunches(await lease.listOwnerLaunches());
        return execute();
      }) : execute();
    },
  });
}
function getSecureShopOwnerResetService() {
  const pool = require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
  const launches = require('../database/postgres/secureshopLaunchRepository')
    .createSecureShopLaunchRepository(pool);
  const repository = require('../database/postgres/secureshopOwnerResetRepository')
    .createSecureShopOwnerResetRepository(pool);
  const launchResetCoordinator = require('./secureshopBoundReviewComposition')
    .getSecureShopLaunchResetCoordinator();
  return createSecureShopOwnerResetService({ repository, launchResetCoordinator, launches });
}
module.exports = { createSecureShopOwnerResetService, getSecureShopOwnerResetService };
