'use strict';

// Startup-only preparation. No route installation, fallback core or retained singleton.
function databaseName(value) {
  try {
    if (typeof value !== 'string' || !value) throw Error();
    const url = new URL(value);
    const name = decodeURIComponent(url.pathname.slice(1));
    if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname
        || !name || name.includes('/') || name.includes('\0')) throw Error();
    return name;
  } catch { throw new TypeError('Canonical grading database configuration is invalid'); }
}
async function prepareSecureShopStartupGrading(options = {}, dependencies = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Explicit startup grading options required');
  }
  const env = dependencies.env || process.env;
  if (env.PLATFORM_DATABASE_ENGINE !== 'postgres') throw new TypeError('PostgreSQL grading startup required');
  const expectedIdentityDatabase = databaseName(env.IDENTITY_DATABASE_URL);
  const expectedAgentsDatabase = databaseName(env.SECURESHOP_AGENTS_DATABASE_URL);
  if (expectedIdentityDatabase === expectedAgentsDatabase) throw new TypeError('Distinct grading databases required');
  for (const key of ['mcpTrustFeature', 'ssrfFeature']) {
    if (options[key] !== undefined && typeof options[key] !== 'boolean') throw new TypeError('Boolean cleanup feature required');
  }
  const cleanupOptions = Object.freeze(Object.fromEntries(
    ['files', 'mcpTrustFeature', 'mcpTrustFixtureRoot', 'ssrfFeature', 'ssrfFixtureRoot', 'systemRestartClient']
      .map(key => [key, key === 'mcpTrustFeature' || key === 'ssrfFeature' ? options[key] === true : options[key]])));
  const judge = options.judge, coordinatorFactory = options.coordinatorFactory;
  const getStores = dependencies.getPlatformStores || require('./postgresPlatformStores').getPostgresPlatformStores;
  const getAgents = dependencies.getAgentsPool || require('../database/postgres/secureshopPools').getAgentsPool;
  const getCleanup = dependencies.getCleanupComposition || require('./secureshopCleanupComposition').getSecureShopCleanupComposition;
  const createBootstrap = dependencies.createBootstrap || require('./secureshopGradingBootstrap').createSecureShopGradingBootstrap;
  const stores = getStores(), agentsPool = getAgents();
  if (typeof stores?.pool?.query !== 'function' || typeof stores.pool.connect !== 'function'
      || typeof stores.progress?.getGeneration !== 'function'
      || typeof agentsPool?.query !== 'function' || typeof agentsPool.connect !== 'function'
      || stores.pool === agentsPool) throw new TypeError('Initialized grading stores required');
  const resetComposition = await getCleanup(cleanupOptions);
  return createBootstrap({ identityPool: stores.pool, agentsPool, progress: stores.progress,
    resetComposition, expectedIdentityDatabase, expectedAgentsDatabase,
    ...(judge === undefined ? {} : { judge }),
    ...(coordinatorFactory === undefined ? {} : { coordinatorFactory }) });
}
module.exports = { prepareSecureShopStartupGrading };
