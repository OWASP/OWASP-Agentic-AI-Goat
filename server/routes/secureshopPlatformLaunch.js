'use strict';

const express = require('express');
const { rateLimit } = require('express-rate-limit');

function metadata(binding) {
  return binding && { launchId: binding.launchId, generation: binding.generation,
    credentialVersion: binding.credentialVersion, expiresAt: binding.expiresAt };
}

// Launch authority stays in the platform parent. Aggregate reset is available
// only when explicitly composed; the shop gateway separately authorizes tools.
function createSecureShopLaunchRouter({ enabled = false, engine, authenticateToken,
  repository, audit, resetCoordinator, progress, modeService = require('../services/workshopModeService'), ttlMs = 30 * 60 * 1000, now = Date.now } = {}) {
  const router = express.Router();
  if (!enabled || engine !== 'postgres') return router;
  if (typeof authenticateToken !== 'function' || typeof audit !== 'function' || !repository) throw new TypeError('Launch dependencies required');
  if (resetCoordinator !== undefined && typeof resetCoordinator?.reset !== 'function') throw new TypeError('Aggregate launch reset required');
  const preparationOnly = resetCoordinator === undefined;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 3600000) throw new TypeError('Invalid launch lifetime');
  router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  router.use(authenticateToken);
  router.use((req, res, next) => {
    if (!Number.isSafeInteger(req.user?.id) || req.user.id < 1
      || !Number.isSafeInteger(req.identitySession?.id) || req.identitySession.id < 1) {
      return res.status(401).json({ error: 'Authenticated platform session required' });
    }
    next();
  });
  // Separate session buckets avoid penalizing a classroom behind one NAT.
  // This process-local guard is not a distributed admission guarantee.
  router.use(rateLimit({ windowMs: 60000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false,
    keyGenerator: req => `${req.user.id}:${req.identitySession.id}`,
    message: { error: 'Too many launch requests' } }));

  function route(keys, action, { auditMutation = true } = {}) {
    return async (req, res) => {
      const body = req.body === undefined ? {} : req.body;
      if ((req.method !== 'GET' && !req.is('application/json'))
        || Object.keys(req.query).length || !body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).some(key => !keys.includes(key))
        || keys.some(key => !Object.hasOwn(body, key))) {
        return res.status(400).json({ error: 'Invalid launch request' });
      }
      const scope = { platformOwnerId: req.user.id, platformSessionId: req.identitySession.id };
      try {
        if (req.method !== 'GET' && auditMutation) {
          // An attempt receipt is deliberately not an effect/completion receipt.
          // Fail before mutation if the audit store is unavailable.
          await audit({ userId: scope.platformOwnerId, actionType: 'secureshop_launch_attempt',
            details: { method: req.method, operation: req.route.path, platformSessionId: scope.platformSessionId } });
        }
        return await action(req, res, scope, body);
      } catch (error) {
        if (error.code === 'LAUNCH_CAPACITY') {
          return res.status(409).json({ code: 'LAUNCH_CAPACITY',
            error: 'SecureShop retained session limit reached. Ask your administrator to review retained sessions before opening another.' });
        }
        const status = ['INVALID_ARGUMENT', 'INVALID_EXPIRY'].includes(error.code) ? 400
          : ['LAUNCH_EXISTS', 'LAUNCH_SESSION_TERMINAL', 'STALE_HANDLE', 'STALE_GENERATION'].includes(error.code) ? 409
          : ['OWNER_MISMATCH', 'SESSION_UNAVAILABLE', 'LAUNCH_UNAVAILABLE'].includes(error.code) ? 409 : 503;
        return res.status(status).json({ error: status === 503 ? 'Launch store unavailable' : 'Launch request could not be completed',
          ...(error.code === 'LAUNCH_SESSION_TERMINAL' ? { code: 'LAUNCH_SESSION_TERMINAL' } : {}) });
      }
    };
  }

  function modeProjection(mode) {
    if (!['vuln','fixed'].includes(mode)) throw new Error('Canonical SecureShop mode unavailable');
    const {POLICIES}=require('../services/secureshopFeatureModeAuthority');
    return {success:true,version:1,mode,effectiveMode:mode,defaultMode:'vuln',
      allowedModes:['vuln','fixed'],selectableModes:['vuln','fixed'],
      scope:{kind:'owner',id:'secureshop_agent_security'},
      features:Object.entries(POLICIES).map(([featureId,policyVersion])=>({featureId,policyVersion,
        scope:{kind:'launch_feature',id:featureId}}))};
  }
  router.get('/mode',route([],async(_req,res,scope)=>{
    const mode=await modeService.getMode({userId:scope.platformOwnerId,workshopKey:'secureshop_agent_security'});
    res.json(modeProjection(mode));
  },{auditMutation:false}));
  router.post('/mode',route(['mode'],async(_req,res,scope,body)=>{
    if(!['vuln','fixed'].includes(body.mode))return res.status(400).json({error:'A supported SecureShop mode is required'});
    // Canonical revision invalidates already captured feature tokens. Existing
    // effects/artifacts stay intact; subsequent dispatch/publication rechecks it.
    await modeService.setMode({userId:scope.platformOwnerId,workshopKey:'secureshop_agent_security',mode:body.mode});
    const current=await modeService.getMode({userId:scope.platformOwnerId,workshopKey:'secureshop_agent_security'});
    res.json(modeProjection(current));
  }));

  if (resetCoordinator && typeof progress?.recordHeartbeat === 'function') {
    router.post('/heartbeat', route(['bearer', 'expectedGeneration'], async (req, res, scope, body) => {
      const binding = await repository.resolve({ ...scope, bearer: body.bearer });
      if (!binding || !Number.isSafeInteger(body.expectedGeneration) || binding.generation !== body.expectedGeneration) {
        return res.status(409).json({ error: 'Launch heartbeat is no longer current' });
      }
      const result = await progress.recordHeartbeat({userId:scope.platformOwnerId,
        workshopKey:'secureshop_agent_security',instanceScope:binding});
      res.json({success:true,...result});
    }, {auditMutation:false}));
  }
  router.get('/', route([], async (req, res, scope) => {
    res.json({ preparationOnly, launch: metadata(await repository.readActiveMetadata(scope)) });
  }));
  router.post('/', route([], async (req, res, scope) => {
    const result = await repository.issueOrRenew({ ...scope, expiresAt: new Date(now() + ttlMs).toISOString() });
    res.status(201).json({ preparationOnly, launch: metadata(result.binding), bearer: result.bearer });
  }));
  router.patch('/', route(['bearer'], async (req, res, scope, body) => {
    const result = await repository.issueOrRenew({ ...scope, expectedBearer: body.bearer,
      expiresAt: new Date(now() + ttlMs).toISOString() });
    res.json({ preparationOnly, launch: metadata(result.binding), bearer: result.bearer });
  }));
  router.post('/recover', route(['launchId', 'expectedCredentialVersion'], async (req, res, scope, body) => {
    const result = await repository.recoverCredential({ ...scope, ...body });
    res.json({ preparationOnly, launch: metadata(result.binding), bearer: result.bearer });
  }));
  // Only the full conversation/target/progress composition may expose reset.
  // A preparation-only server must not acknowledge a target-only cleanup.
  if (resetCoordinator) router.post('/reset', route(['launchId', 'expectedGeneration', 'idempotencyKey'], async (req, res, scope, body) => {
    const controller = new AbortController();
    const abort = () => controller.abort();
    const close = () => { if (!res.writableEnded) abort(); };
    req.once('aborted', abort);
    res.once('close', close);
    try {
      const result = await resetCoordinator.reset({ ...body, ...scope, signal: controller.signal });
      if (result?.status !== 'committed' || result.binding?.launchId !== body.launchId
          || result.binding.platformOwnerId !== scope.platformOwnerId
          || result.binding.platformSessionId !== scope.platformSessionId
          || result.fromGeneration !== body.expectedGeneration
          || result.toGeneration !== body.expectedGeneration + 1
          || result.binding.generation !== result.toGeneration) {
        throw Object.assign(new Error('Aggregate reset receipt mismatch'), { code: 'RESET_INCOMPLETE' });
      }
      if (!controller.signal.aborted) res.json({ resetId: result.resetId,
        cleanupComplete: true, launch: metadata(result.binding) });
    } finally {
      req.removeListener('aborted', abort);
      res.removeListener('close', close);
    }
  }));
  router.delete('/', route(['launchId', 'expectedGeneration'], async (req, res, scope, body) => {
    await repository.revoke({ ...scope, ...body, reason: 'platform_launch_revoked' });
    res.json({ revoked: true, preparationOnly, cleanupComplete: false });
  }));
  return router;
}

module.exports = { createSecureShopLaunchRouter };
