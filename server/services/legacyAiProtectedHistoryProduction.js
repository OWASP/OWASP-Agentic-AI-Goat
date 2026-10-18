'use strict';

const WRITE_PATHS = new Set(['/prompt-injection', '/chain-of-thought', '/context-stuffing', '/multi-turn-jailbreak']);
const READ_PATHS = new Set(['/history', '/history/admin']);

function unavailable() {
  return Object.assign(new Error('Protected legacy AI history is unavailable'), {
    code: 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE',
  });
}

function createLegacyAiProtectedHistoryProduction({
  env = process.env,
  getIdentityAdapter = () => require('./postgresIdentityAdapter').getPostgresIdentityAdapter(),
  createInference = options => require('./legacyAiExperimentConfiguredInference').createLegacyAiExperimentConfiguredInference(options),
  createComposition = options => require('./legacyAiProtectedHistoryComposition').createLegacyAiProtectedHistoryComposition(options),
  createExperimentAccess = key => require('../middleware/workshopMode').checkVulnerabilityAccess(key),
} = {}) {
  if (!env || typeof env !== 'object'
      || [getIdentityAdapter, createInference, createComposition, createExperimentAccess].some(value => typeof value !== 'function')) {
    throw new TypeError('Protected history production dependencies required');
  }
  // Engine selection is fixed at boot; later provider settings remain reloadable.
  const enabled = env.PLATFORM_DATABASE_ENGINE === 'postgres';
  let router;
  let initialization;
  function initialize() {
    if (!initialization) initialization = (async () => {
      if (!enabled) return Object.freeze({ enabled: false, ready: false });
      try {
        const url = new URL(env.IDENTITY_DATABASE_URL);
        const expectedDatabase = decodeURIComponent(url.pathname.slice(1));
        if (!['postgres:', 'postgresql:'].includes(url.protocol) || !expectedDatabase
            || expectedDatabase.includes('/') || Buffer.byteLength(expectedDatabase) > 63) throw unavailable();
        const identityAdapter = getIdentityAdapter();
        const composition = await createComposition({
          identityAdapter,
          identityPool: identityAdapter?.pool,
          expectedDatabase,
          infer: createInference({ getEnvironment: () => env }),
          experimentAccess: createExperimentAccess('prompt_injection'),
        });
        if (composition?.readiness?.ready !== true || typeof composition.router !== 'function') throw unavailable();
        router = composition.router;
        return Object.freeze({ enabled: true, ready: true });
      } catch {
        // Connection strings and provider credentials never escape startup errors.
        throw unavailable();
      }
    })();
    return initialization;
  }
  function middleware(req, res, next) {
    if (!enabled) return next();
    const path = (typeof req.path === 'string' ? req.path : '').toLowerCase().replace(/\/+$/, '');
    const targeted = (req.method === 'POST' && WRITE_PATHS.has(path))
      || (['GET', 'HEAD'].includes(req.method) && READ_PATHS.has(path));
    if (!targeted) return next();
    if (!router) return res.status(503).json({ error: 'Protected history unavailable' });
    // Never allow a targeted request to fall through into historical handlers.
    return router(req, res, () => {
      if (!res.headersSent) res.status(503).json({ error: 'Protected history unavailable' });
    });
  }
  return Object.freeze({ initialize, middleware });
}

module.exports = { createLegacyAiProtectedHistoryProduction };
