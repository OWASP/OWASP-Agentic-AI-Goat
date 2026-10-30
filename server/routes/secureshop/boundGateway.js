'use strict';

const express = require('express');
const multer = require('multer');
const { PRODUCT_RETRIEVAL_MODES } = require('../../services/secureshopProductExecutionConfig');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable }
  = require('../../middleware/secureshopLaunch');

const HEADER = 'x-owasp-ai-goat-secureshop-launch';
const API_KEY_HEADER = 'x-api-key';
const ROLES = new Set(['customer', 'merchant', 'admin']);
const PRODUCT_FIELDS = Object.freeze(['id', 'name', 'description', 'description_html', 'price',
  'category', 'image_url', 'images', 'stock_quantity', 'status', 'created_at', 'updated_at',
  'avg_rating', 'review_count', 'retailer_id', 'template_source']);
const PRODUCT_SUMMARY_FIELDS = Object.freeze(['product_id', 'name', 'price', 'category',
  'stock_quantity', 'description', 'description_html', 'summary', 'provider', 'model', 'modeCapability']);
const RELATED_PRODUCT_FIELDS = Object.freeze(['id', 'name', 'description', 'price', 'category',
  'image_url', 'images', 'stock_quantity', 'avg_rating', 'review_count']);
const REVIEW_FIELDS = Object.freeze(['id', 'body', 'rating', 'status', 'moderator_kind',
  'created_at', 'author_name']);
const USER_FIELDS = Object.freeze(['id', 'username', 'email', 'role', 'full_name', 'phone']);
const CART_FIELDS = Object.freeze(['id','product_id','quantity','name','price','image_url']);
const ORDER_FIELDS = Object.freeze(['id','user_id','total_amount','status','payment_method','payment_status','shipping_address','order_date','updated_at','subtotal_amount','discount_amount','coupon_code','coupon_percent']);
const ORDER_ITEM_FIELDS = Object.freeze(['id','product_id','quantity','price','name','discount_amount','total_amount']);
const ADDRESS_FIELDS = Object.freeze(['id','label','line1','line2','city','state','zip','phone',
  'is_default','created_at']);
const SESSION_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function invalidConfiguration() {
  return new TypeError('Bound SecureShop gateway dependencies required');
}
function headerOccurrences(req, name = HEADER) {
  let count = 0;
  for (let index = 0; index < (req.rawHeaders || []).length; index += 2) {
    if (String(req.rawHeaders[index]).toLowerCase() === name) count += 1;
  }
  return count;
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function project(value, fields) {
  if (!plain(value)) throw new Error('Invalid bound catalog projection');
  const output = {};
  for (const field of fields) if (Object.hasOwn(value, field)) output[field] = value[field];
  return output;
}
function resourceId(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) return 0;
  const number = Number(value);
  return Number.isSafeInteger(number) && number <= 2147483647 ? number : 0;
}
function positive(value, fallback, maximum) {
  if (value === undefined) return fallback;
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) return 0;
  const number = Number(value);
  return Number.isSafeInteger(number) && number <= maximum ? number : 0;
}
function nonnegative(value, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) return -1;
  const number = Number(value);
  return Number.isSafeInteger(number) && number <= 2147483647 ? number : -1;
}
function catalogPrice(value) {
  if (value === undefined) return null;
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,5})(?:\.[0-9]{1,2})?$/.test(value)) return NaN;
  const amount = Number(value);
  return amount <= 100000 ? amount : NaN;
}
function exactQuery(req, allowed) {
  return Object.keys(req.query).every(key => allowed.includes(key)
    && typeof req.query[key] === 'string');
}
function publicError(error) {
  if (error?.code === 'UPLOAD_RECOVERY_SCOPE_STALE') return [409, 'Upload recovery scope changed. Reopen SecureShop to continue.', false];
  if (error?.code === 'SHOP_SCENE_SELECTION_REQUIRED') return [409, 'Choose an existing shop practice to continue', false];
  if (error?.code === 'SHOP_SCENE_STALE') return [409, 'Shop practice has changed. Reopen SecureShop to continue.', false];
  if (error?.code === 'PRODUCT_TARGET_CAPACITY') return [409,
    'SecureShop retained shop limit reached. Ask your administrator to review retained sessions before opening another.', false];
  if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE']
    .includes(error?.code)) return [401, 'SecureShop launch unavailable', true];
  if (error?.code === 'OWNER_MISMATCH') return [401, 'SecureShop launch unavailable', false];
  if (error?.code === 'CONVERSATION_UNAVAILABLE') return [404, 'Conversation unavailable', false];
  if (error?.code === 'SHOP_AUTH_INVALID') return [401, 'Shop authentication required', false];
  if (error?.code === 'SHOP_CREDENTIALS_INVALID') return [401, 'Invalid shop credentials', false];
  if (error?.code === 'SHOP_PASSWORD_MISMATCH') return [403, 'Current shop password is incorrect', false];
  if (error?.code === 'SHOP_PASSWORD_INVALID') return [400, 'Invalid shop password', false];
  if (error?.code === 'SHOP_API_KEY_INVALID') return [401, 'Invalid shop API key', false];
  if (error?.code === 'SHOP_PERSONA_CAPACITY') return [409, 'Shop session capacity reached', false];
  if (error?.code === 'CHECKOUT_RECEIPT_NOT_FOUND') return [404, 'Checkout outcome is not confirmed', false];
  if (['COMMERCE_CHOICE_DENIED','COMMERCE_CHOICE_STALE','COMMERCE_ADDRESS_STALE','COMMERCE_ADDRESS_CAPACITY','COMMERCE_PROPOSAL_NOT_FOUND','CART_EMPTY','INSUFFICIENT_STOCK'].includes(error?.code)) return [409,'Shopping selection changed. Read current choices before continuing.',false];
  if (error?.code === 'COMMERCE_OPERATION_CONFLICT') return [409, 'Commerce operation conflicts with this request', false];
  if (error?.code === 'AUDIT_FIXED_COUNT_LIMIT') return [400, 'Fixed audit summaries accept at most 100 events', false];
  if (error?.code === 'INVALID_ARGUMENT') return [400, 'Invalid bound SecureShop request', false];
  return [503, 'Bound SecureShop operation unavailable', false];
}
function exactBody(req, allowed, required = allowed) {
  return req.is('application/json') && plain(req.body)
    && Object.keys(req.body).every(key => allowed.includes(key))
    && required.every(key => Object.hasOwn(req.body, key));
}
function readBearer(req) {
  const match = /^Bearer ([^\s]+)$/.exec(req.get('authorization') || '');
  return match ? match[1] : null;
}
function requestUuid(value) {
  return typeof value === 'string' && SESSION_UUID.test(value) ? value.toLowerCase() : null;
}
function positiveBody(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? value : 0;
  if (typeof value === 'string' && /^[1-9][0-9]*$/.test(value)) {
    const number = Number(value);
    return Number.isSafeInteger(number) && number > 0 ? number : 0;
  }
  return 0;
}

const PRODUCT_REQUEST_ABORTED = Symbol('product-request-aborted');
async function runProductRequest(req, res, operation) {
  const controller = new AbortController();
  const inherited = req.signal;
  const inheritedSignal = inherited && typeof inherited.addEventListener === 'function'
    && typeof inherited.removeEventListener === 'function' ? inherited : null;
  const abort = reason => {
    if (!res.writableEnded && !controller.signal.aborted) {
      controller.abort(reason instanceof Error ? reason
        : new DOMException('Client disconnected', 'AbortError'));
    }
  };
  const requestAborted = () => abort(new DOMException('Client disconnected', 'AbortError'));
  const responseClosed = () => {
    if (!res.writableEnded) abort(new DOMException('Client disconnected', 'AbortError'));
  };
  const inheritedAborted = () => abort(inheritedSignal.reason);
  req.once('aborted', requestAborted);
  res.once('close', responseClosed);
  inheritedSignal?.addEventListener('abort', inheritedAborted, { once: true });
  if (req.aborted || res.destroyed) requestAborted();
  else if (inheritedSignal?.aborted) inheritedAborted();
  try {
    controller.signal.throwIfAborted();
    const result = await operation(controller.signal);
    controller.signal.throwIfAborted();
    return result;
  } catch (error) {
    if (controller.signal.aborted) return PRODUCT_REQUEST_ABORTED;
    throw error;
  } finally {
    req.off('aborted', requestAborted);
    res.off('close', responseClosed);
    inheritedSignal?.removeEventListener('abort', inheritedAborted);
  }
}

function productNotFound(error) {
  return error?.code === 'NOT_FOUND' || error?.code === 'PRODUCT_NOT_FOUND';
}

function lowerRequestUuid(value) {
  const normalized = requestUuid(value);
  return normalized !== null && normalized === value ? normalized : null;
}

function projectSummaryResult(result, { productId, sessionId, requestId } = {}) {
  if (!plain(result) || result.product_id !== productId || typeof result.name !== 'string'
      || !['number','string'].includes(typeof result.price)
      || !Number.isInteger(result.stock_quantity) || result.stock_quantity < 0
      || typeof result.summary !== 'string' || !result.summary.trim()
      || typeof result.provider !== 'string' || !result.provider || typeof result.model !== 'string' || !result.model
      || ['description','description_html','category'].some(key => result[key] !== null && result[key] !== undefined && typeof result[key] !== 'string')
      || (sessionId !== undefined && (result.sessionId !== sessionId || result.requestId !== requestId)))
    throw new Error('Invalid bound product summary');
  return project(result, sessionId === undefined ? PRODUCT_SUMMARY_FIELDS : [...PRODUCT_SUMMARY_FIELDS,'sessionId','requestId']);
}

function projectSimilarResult(result, { productId, sessionId, requestId } = {}) {
  if (!plain(result) || !Array.isArray(result.results)
      || !Number.isSafeInteger(result.count) || result.count !== result.results.length
      || !PRODUCT_RETRIEVAL_MODES.includes(result.mode) || !plain(result.seed)
      || result.seed.id !== productId || typeof result.seed.name !== 'string'
      || !Array.isArray(result.retrieved_context)
      || typeof result.recommendation !== 'string' || !result.recommendation.trim()
      || typeof result.provider !== 'string' || !result.provider
      || typeof result.model !== 'string' || !result.model
      || (sessionId !== undefined && result.sessionId !== sessionId)
      || (requestId !== undefined && result.requestId !== requestId)) {
    throw new Error('Invalid bound similar-products result');
  }
  return { results: result.results.map(row => project(row, RELATED_PRODUCT_FIELDS)),
    count: result.count, mode: result.mode, recommendation: result.recommendation,
    seed: project(result.seed, ['id', 'name']), retrieved_context: result.retrieved_context,
    provider: result.provider, model: result.model,
    ...(result.modeCapability ? { modeCapability: result.modeCapability } : {}),
    ...(sessionId === undefined ? {} : { sessionId }),
    ...(requestId === undefined ? {} : { requestId }) };
}

// Mount at /api/secureshop before every legacy SecureShop router. No launch
// header exits this router unchanged. Once the header is present, this router
// owns the request and its terminal handler prevents any legacy fall-through.
function createSecureShopBoundGateway({ launches, authenticatePersona, personaAuth, standaloneAuth,
  reviewsRouter, browserRouter, personaInboxRouter, mcpTrustRouter, ssrfRouter, catalog, commerce,
  account, admin, personaObservations, userAdministration, accessControl, promptPolicies, promptPolicyTaskTargets = [], systemConfigRouter, systemDiagnosticRouter, systemRebuildRouter, systemRestartRouter, analyticsRouter, pricingRouter, listingsRouter, mailRouter, inventoryRouter, ownedMcpRegistryRouter, adminChatRouter,
  refundRouter, customerChatRouter, agencyRoleRouter, idorLessonRouter, checkoutAuditLessonRouter, couponAgentRouter, couponProbeRouter, avatarUploadRouter, fileSummaryRouter, filePathSummaryRouter, productSearchRouter, orderStatusRouter, ticketAgentRouter, searchEchoRouter, manualRagRouter, productSummaryRouter, merchantAssistantRouter, adminAssistantRouter,
  productAssist, productManualIngestion, accountAvatar, auditSummary, auditUnbounded, auditSearch,
  auditAgentReady = false, auditTimingReady = false, scenes } = {}) {
  if (typeof launches?.resolveCapability !== 'function'
    || typeof authenticatePersona !== 'function'
    || typeof personaAuth?.login !== 'function' || typeof personaAuth?.renew !== 'function'
    || typeof personaAuth?.logout !== 'function' || typeof personaAuth?.listSessions !== 'function'
    || typeof personaAuth?.revokeOwnedSession !== 'function'
    || typeof personaAuth?.changePassword !== 'function'
    || typeof personaAuth?.listApiKey !== 'function'
    || typeof personaAuth?.rotateApiKey !== 'function'
    || typeof personaAuth?.authenticateApiKey !== 'function'
    || typeof reviewsRouter !== 'function'
    || typeof browserRouter !== 'function'
    || (personaInboxRouter !== undefined && typeof personaInboxRouter !== 'function')
    || (ssrfRouter !== undefined && typeof ssrfRouter !== 'function')
    || (mcpTrustRouter !== undefined && typeof mcpTrustRouter !== 'function')
    || (systemConfigRouter !== undefined && typeof systemConfigRouter !== 'function')
    || (systemDiagnosticRouter !== undefined && typeof systemDiagnosticRouter !== 'function')
    || (systemRebuildRouter !== undefined && typeof systemRebuildRouter !== 'function')
    || (systemRestartRouter !== undefined && typeof systemRestartRouter !== 'function')
    || (analyticsRouter !== undefined && typeof analyticsRouter !== 'function')
    || (pricingRouter !== undefined && typeof pricingRouter !== 'function')
    || (adminChatRouter !== undefined && typeof adminChatRouter !== 'function')
    || (ownedMcpRegistryRouter !== undefined && typeof ownedMcpRegistryRouter !== 'function')
    || (listingsRouter !== undefined && typeof listingsRouter !== 'function')
    || (inventoryRouter !== undefined && typeof inventoryRouter !== 'function')
    || (mailRouter !== undefined && typeof mailRouter !== 'function')
    || (refundRouter !== undefined && typeof refundRouter !== 'function')
    || (customerChatRouter !== undefined && typeof customerChatRouter !== 'function')
    || (agencyRoleRouter !== undefined && typeof agencyRoleRouter !== 'function')
    || (idorLessonRouter !== undefined && typeof idorLessonRouter !== 'function')
    || (checkoutAuditLessonRouter !== undefined && typeof checkoutAuditLessonRouter !== 'function')
    || (fileSummaryRouter !== undefined && typeof fileSummaryRouter !== 'function')
    || (filePathSummaryRouter !== undefined && typeof filePathSummaryRouter !== 'function')
    || (couponAgentRouter !== undefined && typeof couponAgentRouter !== 'function')
    || (couponProbeRouter !== undefined && typeof couponProbeRouter !== 'function')
    || (productSearchRouter !== undefined && typeof productSearchRouter !== 'function')
    || (orderStatusRouter !== undefined && typeof orderStatusRouter !== 'function')
    || (ticketAgentRouter !== undefined && typeof ticketAgentRouter !== 'function')
    || (searchEchoRouter !== undefined && typeof searchEchoRouter !== 'function')
    || (manualRagRouter !== undefined && typeof manualRagRouter !== 'function')
    || (productSummaryRouter !== undefined && typeof productSummaryRouter !== 'function')
    || (merchantAssistantRouter !== undefined && typeof merchantAssistantRouter !== 'function')
    || (adminAssistantRouter !== undefined && typeof adminAssistantRouter !== 'function')
    || (admin !== undefined && typeof admin?.users !== 'function')
    || (productManualIngestion !== undefined && typeof productManualIngestion?.upload !== 'function')
    || (accountAvatar !== undefined && (typeof accountAvatar?.upload !== 'function'
      || typeof accountAvatar?.read !== 'function'))
    || (productAssist !== undefined && (typeof productAssist?.summary !== 'function'
      || typeof productAssist?.similar !== 'function'))
    || (auditSummary !== undefined && (typeof auditSummary?.createSession !== 'function'
      || typeof auditSummary?.run !== 'function'))
    || (auditUnbounded !== undefined && (typeof auditUnbounded?.createSession !== 'function'
      || typeof auditUnbounded?.run !== 'function'))
    || typeof auditAgentReady !== 'boolean'
    || typeof auditTimingReady !== 'boolean'
    || (auditAgentReady && (typeof auditSearch?.createAgentSession !== 'function'
      || typeof auditSearch?.runAgent !== 'function'))
    || (auditTimingReady && (typeof auditSearch?.createTimingSession !== 'function'
      || typeof auditSearch?.runTimingAgent !== 'function'))
    || ['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct',
      'updateMerchantProduct', 'archiveMerchantProduct', 'categories']
      .some(name => typeof catalog?.[name] !== 'function')
    || ['cart','add','update','remove','summary','checkout','orders','order']
      .some(name => typeof commerce?.[name] !== 'function')
    || ['profile','updateProfile','addresses','createAddress','updateAddress','deleteAddress']
      .some(name => typeof account?.[name] !== 'function')) throw invalidConfiguration();

  const router = express.Router();
  if (scenes !== undefined && ['list','select'].some(key => typeof scenes?.[key] !== 'function')) throw invalidConfiguration();
  const requireLaunch = requireSecureShopLaunch({ launches });
  router.use((req, res, next) => {
    if (headerOccurrences(req) === 0) return next('router');
    return requireLaunch(req, res, next);
  });

  const persona = requiredRole => [authenticatePersona, (req, res, next) => {
    if (!plain(req.ssUser) || !Number.isSafeInteger(req.ssUser.id) || req.ssUser.id < 1
      || !ROLES.has(req.ssUser.role) || (requiredRole && req.ssUser.role !== requiredRole)) {
      return res.status(403).json({ error: 'Shop persona unavailable' });
    }
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: req.ssUser.role });
    return next();
  }];
  const apiPersona = requiredRole => async (req, res, next) => {
    if (headerOccurrences(req, API_KEY_HEADER) !== 1 || req.get('authorization')) {
      return res.status(401).json({ error: 'Invalid shop API key' });
    }
    try {
      const value = await personaAuth.authenticateApiKey({ scope: req.ssLaunch,
        presentedKey: req.get(API_KEY_HEADER) });
      if (!plain(value?.user) || !Number.isSafeInteger(value.user.id) || value.user.id < 1
          || !ROLES.has(value.user.role) || (requiredRole && value.user.role !== requiredRole)) {
        return res.status(403).json({ error: 'Shop persona unavailable' });
      }
      req.boundPersona = Object.freeze({ id: value.user.id, role: value.user.role });
      req.ssApiKeyVersion = value.apiKeyVersion;
      if(typeof personaAuth.captureApiKeyAuthority==='function') {
        const fence=await personaAuth.captureApiKeyAuthority({scope:req.ssLaunch,presentedKey:req.get(API_KEY_HEADER)});
        req.ssApiAuthority=require('../../services/secureshopBoundPersonaAuth').resolveBoundApiKeyAuthority(fence,{scope:req.ssLaunch,persona:req.boundPersona});
        if(fence.binding.apiKeyVersion!==value.apiKeyVersion)throw Object.assign(Error('API credential changed'),{code:'SHOP_API_KEY_INVALID'});
      }
      return next();
    } catch (error) {
      const [status, message, launchUnavailable] = publicError(error);
      if (launchUnavailable) markSecureShopLaunchUnavailable(res);
      return res.status(status).json({ error: message });
    }
  };
  const handle = operation => async (req, res) => {
    try { await operation(req, res); }
    catch (error) {
      const [status, message, launchUnavailable] = publicError(error);
      if (!res.headersSent) {
        if (launchUnavailable) markSecureShopLaunchUnavailable(res);
        res.status(status).json({ error: message, ...(['SHOP_SCENE_SELECTION_REQUIRED','SHOP_SCENE_STALE'].includes(error?.code) ? { code: error.code } : {}) });
      }
    }
  };
  const registerUnavailable = (routes, message = 'Bound SecureShop operation unavailable') => {
    const fail = (_req, res) => res.status(503).json({ error: message });
    for (const [method, path] of routes) router[method](path, fail);
  };
  const context = req => Object.freeze({ scope: req.ssLaunch, persona: req.boundPersona });
  if (scenes) {
    router.get('/v2/scenes', handle(async (req, res) => {
      res.set('Cache-Control', 'no-store');
      if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid shop practice request' });
      res.json({ scenes: await scenes.list(req.ssLaunch) });
    }));
    router.post('/v2/scenes/select', handle(async (req, res) => {
      res.set('Cache-Control', 'no-store');
      if (!exactQuery(req, []) || !exactBody(req, ['sceneId']) || !requestUuid(req.body.sceneId)) {
        return res.status(400).json({ error: 'Invalid shop practice request' });
      }
      res.json(await scenes.select(req.ssLaunch, req.body.sceneId));
    }));
  }
  const adminContext = req => Object.freeze({ ...context(req), ...(req.ssPersonaSession
    ? { personaSession: Object.freeze({ sessionId: req.ssPersonaSession.sessionId,
      authorityVersion: req.ssPersonaSession.authorityVersion }) } : {}) });
  const commerceContext = req => ({ ...context(req), ...(req.ssApiAuthority
    ? { apiAuthority: req.ssApiAuthority } : { personaSession: req.ssPersonaSession }) });
  if(userAdministration) router.use(require('./boundUserAdministration').createBoundUserAdministrationRouter({service:userAdministration,authenticatePersona}));
  else registerUnavailable([
    ['post', '/admin/users/lookup'],
    ['get', '/admin/users/:id/reset-readiness'],
    ['post', '/admin/users/:id/reset-password'],
    ['get', '/admin/users/:id/password-resets/:operationId'],
    ['post', '/admin/users/:id/password-resets/:operationId/reveal'],
    ['post', '/admin/users/:id/password-resets/:operationId/acknowledge'],
    ['get', '/admin/users/operations/:operationId'],
    ['post', '/admin/users/:id/role'],
    ['post', '/admin/users/:id/ban'],
  ]);
  if(accessControl !== undefined) router.use(require('./boundAccessControl').createBoundAccessControlRouter({service:accessControl,authenticatePersona}));
  else registerUnavailable([
    ['get', '/admin/access-control'],
    ['get', '/admin/access-control/operations/:operationId'],
    ['post', '/admin/access-control/permission'],
    ['post', '/admin/access-control/enforcement'],
  ]);
  router.get('/admin/policies/readiness', ...persona('admin'), handle(async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid policy readiness request' });
    if (promptPolicies === undefined) return res.json({ ready: false });
    if (typeof promptPolicies.readiness !== 'function') throw invalidConfiguration();
    const readiness = await promptPolicies.readiness(Object.freeze({
      scope: req.ssLaunch,
      persona: Object.freeze({ id: req.ssUser.id, role: req.ssUser.role }),
      personaSession: Object.freeze({ sessionId: req.ssPersonaSession.sessionId,
        authorityVersion: req.ssPersonaSession.authorityVersion }),
    }));
    if (readiness?.ready !== true) throw invalidConfiguration();
    // Health is awaited outside authentication. Re-authenticate before releasing
    // a positive result so a concurrent logout/role change cannot retain it.
    await launches.assertCurrent(req.ssLaunch);
    return authenticatePersona(req, res, () => {
      if (req.ssUser?.role !== 'admin') return res.status(403).json({ error: 'Shop persona unavailable' });
      return res.json({ ready: true });
    });
  }));
  if(promptPolicies !== undefined) router.use(require('./boundPromptPolicies').createBoundPromptPoliciesRouter({service:promptPolicies,authenticatePersona,supportedTaskTargets:promptPolicyTaskTargets}));
  else registerUnavailable([
    ['get', '/admin/policies'],
    ['get', '/admin/policies/operations/:operationId'],
    ['post', '/admin/policies'],
    ['post', '/admin/policies/:name/render'],
    ['post', '/admin/policies/:name'],
    ['delete', '/admin/policies/:name'],
  ]);
  if(systemConfigRouter !== undefined) router.use(systemConfigRouter);
  else registerUnavailable([
    ['get', '/admin/system/config-read'], ['post', '/admin/system/config-read'],
    ['get', '/admin/system/config-operations/:operationId'],
  ]);
  if(systemDiagnosticRouter !== undefined) router.use(systemDiagnosticRouter);
  else registerUnavailable([
    ['get', '/admin/system/diagnostic'], ['post', '/admin/system/diagnostic'],
    ['get', '/admin/system/diagnostic-operations/:operationId'],
  ]);
  if(systemRebuildRouter !== undefined) router.use(systemRebuildRouter);
  else registerUnavailable([
    ['get', '/admin/system/rebuild-index'], ['post', '/admin/system/rebuild-index'],
    ['get', '/admin/system/rebuild-index/operations/:operationId'],
  ]);
  if(systemRestartRouter !== undefined) router.use(systemRestartRouter);
  else registerUnavailable([
    ['get', '/admin/system/restart'], ['post', '/admin/system/restart'],
    ['get', '/admin/system/restart-operations/:operationId'],
  ]);
  if(analyticsRouter !== undefined) router.use('/merchant/analytics',analyticsRouter);
  else registerUnavailable([
    ['get', '/merchant/analytics'], ['post', '/merchant/analytics/query'],
    ['get', '/merchant/analytics/requests/:requestId'], ['get', '/merchant/analytics/history'],
    ['get', '/merchant/analytics/top-products'],
  ]);
  if(pricingRouter !== undefined) router.use(pricingRouter);
  else registerUnavailable([
    ['get', '/merchant/pricing/history'], ['get', '/merchant/pricing/run'],
    ['post', '/merchant/pricing/run'], ['get', '/merchant/pricing/operations/:operationId'],
    ['get', '/pricing/advisor/history'], ['get', '/pricing/advisor/run'],
    ['post', '/pricing/advisor/run'], ['get', '/pricing/advisor/operations/:operationId'],
  ]);
  if(ownedMcpRegistryRouter !== undefined) router.use(ownedMcpRegistryRouter);
  else registerUnavailable([
    ['post', '/admin/mcp/register'], ['post', '/admin/mcp/import-manifest'],
    ['delete', '/admin/mcp/:name'], ['get', '/admin/mcp/operations/:operationId'],
  ]);
  if(adminChatRouter !== undefined) router.use(adminChatRouter);
  else registerUnavailable([
    ['post', '/agents/admin/session'], ['get', '/agents/admin/chat/requests/:sessionId/:requestId'],
    ['post', '/agents/admin/chat'],
  ]);
  if(merchantAssistantRouter !== undefined) router.use(merchantAssistantRouter);
  else registerUnavailable([
    ['post', '/agents/merchant/chat'],
    ['post', '/agents/merchant/assistant/session'], ['post', '/agents/merchant/assistant/chat'],
    ['get', '/agents/merchant/assistant/operations/:sessionId/:requestId'],
    ['post', '/agents/merchant/assistant/review/confirm'],
    ['post', '/agents/merchant/assistant/mail/confirm'],
    ['get', '/agents/merchant/assistant/mail/operations/:sessionId/:requestId/:operationId'],
    ['post', '/agents/merchant/assistant/inventory/confirm'],
    ['post', '/agents/merchant/assistant/pricing/confirm'],
    ['post', '/agents/merchant/assistant/listing/confirm'],
    ['get', '/agents/merchant/assistant/listing/operations/:operationId'],
    ['post', '/agents/merchant/assistant/listing-create/confirm'],
    ['get', '/agents/merchant/assistant/listing-create/operations/:operationId'],
    ['post', '/agents/merchant/assistant/listing-create/assess'],
    ['get', '/agents/merchant/assistant/listing-create/assessment/:operationId'],
  ]);
  if(adminAssistantRouter !== undefined) router.use(adminAssistantRouter);
  else registerUnavailable([
    ['post', '/agents/admin/assistant/session'], ['post', '/agents/admin/assistant/chat'],
    ['get', '/agents/admin/assistant/operations/:sessionId/:requestId'],
    ['get', '/agents/admin/assistant/audit/operations/:sessionId/:requestId/:operationId'],
    ['get', '/agents/admin/assistant/audit/job/operations/:sessionId/:requestId/:proposalId'],
    ['get', '/agents/admin/assistant/system/config/operations/:sessionId/:requestId/:operationId'],
    ['post', '/agents/admin/assistant/system/config/assessment-retry'],
    ['post', '/agents/admin/assistant/policy/instruction/assessment-retry'],
    ['post', '/agents/admin/assistant/user/confirm'], ['post', '/agents/admin/assistant/policies/confirm'],
    ['post', '/agents/admin/assistant/system/diagnostic/confirm'],
    ['get', '/agents/admin/assistant/system/diagnostic/confirm/:sessionId/:requestId/:proposalId'],
    ['post', '/agents/admin/assistant/system/restart/confirm'], ['post', '/agents/admin/assistant/acl/confirm'],
    ['post', '/agents/admin/assistant/audit/job/run'], ['post', '/agents/admin/assistant/mcp/confirm'],
  ]);
  if(listingsRouter !== undefined) router.use(listingsRouter);
  else registerUnavailable([
    ['get', '/merchant/listings/readiness'],
    ['post', '/merchant/listings/assist-write'], ['post', '/merchant/listings/import-bulk'],
    ['post', '/merchant/listings/rewrite-save'],
    ['get', '/merchant/listings/rewrite-saves/:saveOperationId'],
    ['post', '/merchant/listings/browser-attempt'], ['post', '/merchant/listings/browser-retry'],
    ['get', '/merchant/listings/operations/:operationId'],
    ['post', '/merchant/listings/operations/:operationId/resume'],
    ['get', '/merchant/listings/template-readiness'],
    ['post', '/merchant/listings/template-render'],
    ['get', '/merchant/listings/template-operations/:operationId'],
  ]);
  if(inventoryRouter !== undefined) router.use(inventoryRouter);
  else registerUnavailable([
    ['get', '/merchant/inventory/readiness'], ['post', '/merchant/inventory/run'],
    ['post', '/merchant/inventory/judge-retry'], ['get', '/merchant/inventory/operations/:requestId'],
    ['get', '/merchant/inventory/history'], ['get', '/merchant/inventory/history/:requestId'],
  ]);
  if(mailRouter !== undefined) router.use(mailRouter);
  else registerUnavailable([
    ['get', '/email/readiness'], ['get', '/email/inbox/:userId'], ['post', '/email/send'],
    ['post', '/email/auto-reply/:threadId'],
    ['post', '/email/operations/autoReply/:requestId/keep-unresolved'],
    ['post', '/email/reply-assessment'], ['post', '/email/disclosure'],
    ['post', '/email/disclosure-assessment'], ['post', '/email/header-assessment'],
    ['post', '/email/browser-assessment'], ['post', '/email/html-injection-assessment'],
    ['get', '/email/html-injection-assessment/:requestId/:sourceSessionId/:sourceRequestId/:sendOperationId/:messageId'],
    ['get', '/email/operations/:action/:requestId'],
  ]);

  if (accountAvatar) {
    const parseAvatar = multer({ storage: multer.memoryStorage(), preservePath: true,
      limits: { fileSize: 20 * 1024 * 1024, files: 1, fields: 5, parts: 6,
        fieldSize: 4096, fieldNameSize: 32 } }).single('file');
    const avatarResult = (res, value, persona, requestId) => {
      const required = ['ok','kind','scope_id','requestId','status','operationId','filename',
        'mime','size_bytes','public','is_traversal','replayed'];
      if (!plain(value) || Object.keys(value).sort().join(',') !== required.concat(
        value.status === 'denied' ? ['denialCode'] : []).sort().join(',')
          || typeof value.ok !== 'boolean' || value.ok !== (value.status === 'completed')
          || value.kind !== 'avatar' || value.scope_id !== String(persona.id)
          || value.requestId !== requestId || !['completed','denied','uncertain'].includes(value.status)
          || value.operationId !== null && !SESSION_UUID.test(value.operationId)
          || value.status !== 'uncertain' && value.operationId === null
          || typeof value.filename !== 'string' || typeof value.mime !== 'string'
          || !Number.isSafeInteger(value.size_bytes) || value.size_bytes < 0
          || value.size_bytes > 20 * 1024 * 1024 || typeof value.public !== 'boolean'
          || typeof value.is_traversal !== 'boolean' || typeof value.replayed !== 'boolean'
          || value.status === 'denied' && (typeof value.denialCode !== 'string'
            || !value.denialCode || value.denialCode.length > 128))
        throw new Error('Invalid bound avatar result');
      res.set('Cache-Control', 'no-store').json(value);
    };
    router.post('/uploads/avatar', ...persona(), handle(async (req, res) => {
      if (!exactQuery(req, []) || !req.is('multipart/form-data'))
        return res.status(400).json({ error: 'Invalid avatar upload' });
      let value;
      try {
        value = await runProductRequest(req, res, async signal => {
          await new Promise((resolve, reject) => parseAvatar(req, res,
            error => error ? reject(error) : resolve()));
          signal.throwIfAborted();
          const body = req.body;
          if (!plain(body) || Object.keys(body).sort().join(',') !== 'kind,mime,public,requestId,scope_id'
              || body.kind !== 'avatar' || typeof body.requestId !== 'string'
              || !SESSION_UUID.test(body.requestId)
              || String(req.boundPersona.id) !== body.scope_id
              || typeof body.mime !== 'string' || !body.mime || Buffer.byteLength(body.mime) > 1024
              || /[\0\r\n]/.test(body.mime) || !['true','false'].includes(body.public)
              || !req.file || !Buffer.isBuffer(req.file.buffer) || !req.file.buffer.length
              || typeof req.file.originalname !== 'string' || !req.file.originalname
              || Buffer.byteLength(req.file.originalname) > 4096)
            throw Object.assign(new Error('Invalid avatar upload'), { code: 'INVALID_ARGUMENT' });
          return accountAvatar.upload({ ...context(req), personaSession: req.ssPersonaSession,
            requestId: body.requestId, scopeId: req.boundPersona.id, bytes: req.file.buffer,
            filename: req.file.originalname, mime: body.mime, public: body.public === 'true', signal });
        });
      } catch (error) {
        if (error instanceof multer.MulterError) return res.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 400)
          .json({ error: 'Invalid or oversized avatar upload' });
        throw error;
      }
      if (value !== PRODUCT_REQUEST_ABORTED) avatarResult(res, value, req.boundPersona, req.body.requestId);
    }));
    router.get('/uploads/avatar/operations/:requestId', ...persona(), handle(async (req, res) => {
      if (!exactQuery(req, []) || !SESSION_UUID.test(req.params.requestId || ''))
        return res.status(400).json({ error: 'Invalid avatar operation' });
      const value = await runProductRequest(req, res, signal => accountAvatar.read({ ...context(req),
        personaSession: req.ssPersonaSession, requestId: req.params.requestId, signal }));
      if (value !== PRODUCT_REQUEST_ABORTED) avatarResult(res, value, req.boundPersona, req.params.requestId);
    }));
  } else registerUnavailable([
    ['post', '/uploads/avatar'], ['get', '/uploads/avatar/operations/:requestId']
  ]);

  if (productManualIngestion) {
    const manualRecovery = require('../../services/secureshopManualUploadRecoveryContract');
    router.get('/uploads/product-manual/receipt', (_req, res, next) => {
      res.set('Cache-Control', 'no-store'); next();
    }, ...persona('merchant'), handle(async (req, res) => {
      const fields = ['productId', 'sha256', 'sizeBytes', 'filename', 'mime', 'public', 'recoveryScopeKey'];
      if (!exactQuery(req, fields) || fields.slice(0, 6).some(key => !Object.hasOwn(req.query, key))
          || !resourceId(req.query.productId) || !resourceId(req.query.sizeBytes)
          || !['true', 'false'].includes(req.query.public)) throw Object.assign(new Error('Invalid manual receipt request'), {code:'INVALID_ARGUMENT'});
      const descriptor = manualRecovery.normalizeManualUploadDescriptor({productId:resourceId(req.query.productId),
        sha256:req.query.sha256, sizeBytes:resourceId(req.query.sizeBytes), filename:req.query.filename,
        mime:req.query.mime, isPublic:req.query.public === 'true'});
      const recoveryScopeKey = req.query.recoveryScopeKey === undefined ? undefined
        : manualRecovery.validateManualUploadRecoveryKey(req.query.recoveryScopeKey);
      if (typeof productManualIngestion.readReceipt !== 'function') throw new Error('Manual receipt recovery unavailable');
      const result = await productManualIngestion.readReceipt({...context(req),
        personaSession:req.ssPersonaSession, descriptor,
        ...(recoveryScopeKey === undefined ? {} : {recoveryScopeKey})});
      if (result?.version !== 1 || result.kind !== 'product_manual' || !requestUuid(result.operationId)
          || !['indexed', 'not_found'].includes(result.state)
          || (result.state === 'not_found' ? result.receipt !== null : !plain(result.receipt))) throw new Error('Invalid manual receipt result');
      manualRecovery.validateManualUploadRecoveryKey(result.recoveryScopeKey);
      res.json({...project(result, ['version','kind','operationId','recoveryScopeKey','state']),
        receipt:result.receipt === null ? null : project(result.receipt,
          ['productId','sha256','sizeBytes','filename','mime','isPublic','chunkCount','chunkIds','completedAt'])});
    }));
    const parseManual = multer({ storage: multer.memoryStorage(), preservePath: true,
      limits: { fileSize: 20 * 1024 * 1024, files: 1, fields: 5, parts: 6,
        fieldSize: 256, fieldNameSize: 32 },
    }).single('file');
    router.post('/uploads', ...persona('merchant'), handle(async (req, res) => {
      if (!exactQuery(req, []) || !req.is('multipart/form-data')) {
        return res.status(400).json({ error: 'Invalid product manual upload' });
      }
      let result;
      try {
        result = await runProductRequest(req, res, async signal => {
          await new Promise((resolve, reject) => parseManual(req, res,
            error => error ? reject(error) : resolve()));
          signal.throwIfAborted();
          const body = req.body;
          if (!plain(body) || ![4,5].includes(Object.keys(body).length)
              || Object.keys(body).some(key => !['kind','scope_id','mime','public','recoveryScopeKey'].includes(key))
              || !['kind', 'scope_id', 'mime', 'public'].every(key => typeof body[key] === 'string')
              || body.kind !== 'product_manual' || !resourceId(body.scope_id)
              || !['true', 'false'].includes(body.public) || !body.mime || Buffer.byteLength(body.mime) > 128
              || /[\x00-\x1f\x7f]/.test(body.mime)
              || !req.file || !Buffer.isBuffer(req.file.buffer) || !req.file.buffer.length
              || typeof req.file.originalname !== 'string' || !req.file.originalname.trim()
              || Buffer.byteLength(req.file.originalname) > 255
              || /[\x00-\x1f\x7f]/.test(req.file.originalname)) {
            throw Object.assign(new Error('Invalid manual upload'), { code: 'INVALID_ARGUMENT' });
          }
          const recoveryScopeKey = body.recoveryScopeKey === undefined ? undefined
            : manualRecovery.validateManualUploadRecoveryKey(body.recoveryScopeKey);
          return productManualIngestion.upload({ ...context(req), ...(req.ssPersonaSession ? {personaSession:req.ssPersonaSession} : {}), productId: resourceId(body.scope_id),
            bytes: req.file.buffer, filename: req.file.originalname, mime: body.mime,
            isPublic: body.public === 'true', signal,
            ...(recoveryScopeKey === undefined ? {} : {recoveryScopeKey}) });
        });
      } catch (error) {
        if (error instanceof multer.MulterError) {
          return res.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 400)
            .json({ error: 'Invalid or oversized product manual upload' });
        }
        throw error;
      }
      if (result === PRODUCT_REQUEST_ABORTED) return;
      if (!plain(result) || result.ok !== true || result.kind !== 'product_manual'
          || result.scope_id !== resourceId(req.body.scope_id)
          || result.indexed_corpus !== 'manuals' || !Array.isArray(result.chunk_ids)
          || result.chunk_count !== result.chunk_ids.length || result.chunk_count < 1
          || result.chunk_count > 129 || result.is_traversal !== false
          || typeof result.provider !== 'string' || !result.provider
          || typeof result.model !== 'string' || !result.model) throw new Error('Invalid manual ingestion result');
      res.json(project(result, ['ok', 'kind', 'scope_id', 'filename', 'cleaned_filename',
        'relative_path', 'mime', 'size_bytes', 'is_traversal', 'extracted_bytes', 'chunk_count',
        'chunk_ids', 'extractor', 'extractor_error', 'indexed_corpus', 'operationId',
        'replayed', 'provider', 'model']));
    }));
  } else {
    router.get('/uploads/product-manual/receipt', (_req, res) => res.set('Cache-Control','no-store')
      .status(503).json({error:'Bound SecureShop operation unavailable'}));
    registerUnavailable([['post', '/uploads']]);
  }

  router.post('/v2/auth/login', handle(async (req, res) => {
    if (!exactQuery(req, []) || !exactBody(req, ['username', 'password'])
      || typeof req.body.username !== 'string' || typeof req.body.password !== 'string') {
      return res.status(400).json({ error: 'Invalid shop login request' });
    }
    const cookie = require('../secureshopStandaloneAuth').readShopCookie(req);
    if (standaloneAuth && cookie) {
      if (typeof standaloneAuth.withReauthenticatedExecution !== 'function'
        || typeof personaAuth.establishAdditionalSession !== 'function') throw Object.assign(new Error('Shop authentication unavailable'), {code:'SHOP_AUTH_INVALID'});
      const result = await standaloneAuth.withReauthenticatedExecution({ token: cookie,
        username: req.body.username, password: req.body.password }, shopPrincipal =>
          personaAuth.establishAdditionalSession({ scope: req.ssLaunch, shopPrincipal,
            token: readBearer(req), ip: typeof req.ip === 'string' ? req.ip : null,
            userAgent: req.get('user-agent') || null }));
      return res.json(result);
    }
    const result = await personaAuth.login({ scope: req.ssLaunch,
      username: req.body.username, password: req.body.password,
      ip: typeof req.ip === 'string' ? req.ip : null,
      userAgent: req.get('user-agent') || null });
    res.json(result);
  }));

  router.post('/v2/auth/logout', handle(async (req, res) => {
    if (!exactQuery(req, [])
      || (req.body !== undefined && !exactBody(req, [], []))) {
      return res.status(400).json({ error: 'Invalid shop logout request' });
    }
    await personaAuth.logout({ scope: req.ssLaunch, token: readBearer(req) });
    res.json({ ok: true, next: 'login' });
  }));

  router.patch('/v2/auth/renew', handle(async (req, res) => {
    if (!exactQuery(req, []) || (req.body !== undefined && !exactBody(req, [], []))) {
      return res.status(400).json({ error: 'Invalid shop renewal request' });
    }
    res.json(await personaAuth.renew({ scope: req.ssLaunch, token: readBearer(req) }));
  }));
  registerUnavailable([
    ['post', '/v2/auth/register'], ['post', '/v2/auth/switch-role'],
  ]);

  // The review router performs its own launch/persona checks as a second
  // current-generation fence. It may handle only its closed review paths.
  router.use(browserRouter);
  router.use(reviewsRouter);
  if (personaInboxRouter) router.use(personaInboxRouter);
  else {
    router.get('/v2/persona-inbox/readiness', ...persona(), (_req, res) => res.json({ ready: false }));
    registerUnavailable([
      ['post', '/v2/persona-inbox/read'], ['post', '/v2/persona-inbox/enforce'],
    ], 'Persona inbox exercise unavailable');
  }
  if(mcpTrustRouter)router.use(mcpTrustRouter);
  else {
    router.get('/v2/mcp-trust/readiness',...persona('admin'),(_req,res)=>res.json({ready:false}));
    registerUnavailable([
      ['post', '/v2/mcp-trust/discover'], ['post', '/v2/mcp-trust/rotate'],
      ['post', '/v2/mcp-trust/run'],
    ], 'MCP trust exercise unavailable');
  }

  if(ssrfRouter)router.use(ssrfRouter);
  else {
    router.get('/v2/controlled-ssrf/readiness',...persona(),(_req,res)=>res.json({ready:false}));
    registerUnavailable([['post', '/v2/controlled-ssrf/run']], 'Controlled SSRF exercise unavailable');
  }

  if (refundRouter) router.use(refundRouter);
  else registerUnavailable([
    ['post', '/agents/customer/refund/session'], ['post', '/agents/customer/refund/chat'],
    ['get', '/agents/customer/refund/operations/:sessionId/:requestId'],
  ]);
  if (customerChatRouter) router.use(customerChatRouter);
  else {
    const unavailableChat=(_req,res)=>res.status(503).json({error:'Bound SecureShop operation unavailable'});
    router.post('/agents/customer/session',unavailableChat);
    router.post('/agents/customer/chat',unavailableChat);
    router.get('/agents/customer/operations/:sessionId/:requestId',unavailableChat);
    router.post('/agents/customer/profile/confirm',unavailableChat);
  }
  if (idorLessonRouter) router.use(idorLessonRouter);
  else registerUnavailable([
    ['post','/agents/customer/idor/prepare'], ['get','/agents/customer/idor/cards'],
    ['post','/agents/customer/idor/session'], ['post','/agents/customer/idor/chat'],
    ['get','/agents/customer/idor/operations/:sessionId/:requestId'],
    ['get','/agents/customer/idor/assessments/:sessionId/:requestId'],
    ['post','/agents/customer/idor/assessment-retry'],
  ]);
  if (checkoutAuditLessonRouter) router.use(checkoutAuditLessonRouter);
  else registerUnavailable([
    ['post','/agents/customer/checkout-audit/session'],
    ['post','/agents/customer/checkout-audit/practice-token'],
    ['post','/agents/customer/checkout-audit/chat'],
    ['get','/agents/customer/checkout-audit/operations/:sessionId/:requestId'],
  ]);
  if (ticketAgentRouter) router.use(ticketAgentRouter);
  else registerUnavailable([
    ['post','/agents/customer/tickets/confirm'],
    ['get','/agents/customer/tickets/confirm/:sessionId/:requestId/:proposalId'],
    ['get','/admin/tickets'], ['get','/admin/tickets/:ticketId'],
  ]);
  // A partially composed ticket feature must not route assessment requests to
  // legacy handlers. A ready assessment router consumes these paths above.
  registerUnavailable([
    ['post','/admin/tickets/:ticketId/assessment'],
    ['get','/admin/tickets/:ticketId/assessment/:requestId'],
  ]);
  if (searchEchoRouter) router.use(searchEchoRouter);
  if (manualRagRouter) router.use(manualRagRouter);
  if (productSummaryRouter) router.use(productSummaryRouter);
  if (agencyRoleRouter) router.use(agencyRoleRouter);
  registerUnavailable([
    ['post','/agents/customer/search-echo/assess'],
    ['get','/agents/customer/sessions/:sessionId/requests/:requestId/search-echo/:step/assessment'],
  ]);
  if (couponProbeRouter) router.use(couponProbeRouter);
  else {
   router.get('/customer/coupon-probe/capabilities', ...persona('customer'), (req, res) => {
    if (Object.keys(req.query || {}).length) return res.status(400).json({ error: 'Invalid coupon probe request' });
    res.set('Cache-Control', 'no-store');
    return res.json({ ready: false });
   });
   registerUnavailable([
    ['post','/customer/coupon-probe/session'],
    ['post','/customer/coupon-probe/run'],
    ['get','/customer/coupon-probe/operations/:sessionId/:requestId'],
    ['post','/customer/coupon-probe/assess'],
    ['get','/customer/coupon-probe/assess/:sessionId/:requestId'],
  ]);
  }
  if (avatarUploadRouter) router.use(avatarUploadRouter);
  if (fileSummaryRouter) router.use(fileSummaryRouter);
  if (filePathSummaryRouter) router.use(filePathSummaryRouter);
  if (productSearchRouter) router.use(productSearchRouter);
  else {
   router.get('/customer/product-search/capabilities', ...persona('customer'), (req, res) => {
    if (Object.keys(req.query || {}).length) return res.status(400).json({ error: 'Invalid product search request' });
    res.set('Cache-Control', 'no-store');
    return res.json({ ready: false });
   });
   registerUnavailable([
    ['post','/customer/product-search/session'],
    ['post','/customer/product-search/run'],
    ['get','/customer/product-search/operations/:sessionId/:requestId'],
    ['post','/customer/product-search/assess'],
    ['get','/customer/product-search/assess/:sessionId/:requestId'],
  ]);
  }
  if (orderStatusRouter) router.use(orderStatusRouter);
  else {
   router.get('/customer/order-status/capabilities', ...persona('customer'), (req, res) => {
    if (Object.keys(req.query || {}).length) return res.status(400).json({ error: 'Invalid order status request' });
    res.set('Cache-Control', 'no-store');
    return res.json({ ready: false });
   });
   registerUnavailable([
    ['post','/customer/order-status/session'],
    ['post','/customer/order-status/run'],
    ['get','/customer/order-status/operations/:sessionId/:requestId'],
    ['post','/customer/order-status/assess'],
    ['get','/customer/order-status/assess/:sessionId/:requestId'],
  ]);
  }
  if (couponAgentRouter) router.use(couponAgentRouter);
  else registerUnavailable([
    ['post','/agents/customer/coupons/confirm'],
    ['get','/agents/customer/coupons/confirm/:sessionId/:requestId/:proposalId'],
    ['post','/agents/customer/coupons/assessment-retry'],
    ['get','/agents/customer/coupons/assessment/:sessionId/:requestId/:proposalId'],
  ]);

  // Product summary/recommendation adapters are optional until their graph
  // composition is ready. Never fall through to the legacy customer router:
  // an absent target-bound adapter remains an honest 503.
  if (productAssist) {
    router.post('/products/:id/summary', ...persona('customer'), handle(async (req, res) => {
      res.set('Cache-Control', 'no-store');
      const productId = resourceId(req.params.id);
      const saved = plain(req.body) && Object.hasOwn(req.body, 'sessionId');
      if (!productId || !exactQuery(req, []) || (saved
          ? !exactBody(req, ['sessionId','requestId']) || !lowerRequestUuid(req.body.sessionId) || !lowerRequestUuid(req.body.requestId)
          : req.body !== undefined && !exactBody(req, [], [])))
        return res.status(400).json({ error: 'Invalid product summary request' });
      if (saved && typeof productAssist.runSummary !== 'function') return res.status(503).json({ error: 'Product summary unavailable' });
      const identity = saved ? { sessionId:req.body.sessionId, requestId:req.body.requestId } : {};
      let result;
      try {
        result = await runProductRequest(req, res, signal =>
          productAssist[saved ? 'runSummary' : 'summary']({ ...context(req),
            ...(req.ssPersonaSession ? { personaSession:req.ssPersonaSession } : {}), productId, ...identity, signal }));
      } catch (error) {
        if (productNotFound(error)) return res.status(404).json({ error:'not found' });
        throw error;
      }
      if (result === PRODUCT_REQUEST_ABORTED) return;
      res.json(projectSummaryResult(result, { productId, ...identity }));
    }));
    if (typeof productAssist.createSummarySession === 'function') {
      router.post('/products/:id/summary/session', ...persona('customer'), handle(async (req, res) => {
        res.set('Cache-Control', 'no-store');
        const productId = resourceId(req.params.id);
        if (!productId || !exactQuery(req, []) || (req.body !== undefined && !exactBody(req, [], [])))
          return res.status(400).json({ error:'Invalid product summary session request' });
        const value = await runProductRequest(req, res, signal => productAssist.createSummarySession({ ...context(req),
          ...(req.ssPersonaSession ? {personaSession:req.ssPersonaSession} : {}), productId, signal }));
        if (value === PRODUCT_REQUEST_ABORTED) return;
        const sessionId = lowerRequestUuid(value?.sessionId);
        if (!sessionId || !/^[a-f0-9]{64}$/.test(value?.recoveryKey || '')) throw new Error('Invalid bound product summary session');
        res.json({ sessionId, recoveryKey:value.recoveryKey });
      }));
    } else registerUnavailable([['post','/products/:id/summary/session']]);
    if (typeof productAssist.readSummary === 'function') {
      router.get('/products/:id/summary/sessions/:sessionId/requests/:requestId', ...persona('customer'), handle(async (req, res) => {
        res.set('Cache-Control', 'no-store');
        const productId = resourceId(req.params.id), sessionId = lowerRequestUuid(req.params.sessionId), requestId = lowerRequestUuid(req.params.requestId);
        if (!productId || !sessionId || !requestId || !exactQuery(req, []) || req.body !== undefined)
          return res.status(400).json({ error:'Invalid saved product summary request' });
        const value = await runProductRequest(req, res, signal => productAssist.readSummary({ ...context(req),
          ...(req.ssPersonaSession ? {personaSession:req.ssPersonaSession} : {}), productId, sessionId, requestId, signal }));
        if (value === PRODUCT_REQUEST_ABORTED) return;
        if (!plain(value)) throw new Error('Invalid saved product summary');
        if (value.status === 'completed') return res.json({ status:'completed', result:projectSummaryResult(value.result, { productId, sessionId, requestId }) });
        if (value.sessionId !== sessionId || value.requestId !== requestId) throw new Error('Invalid saved product summary');
        if (value.status === 'pending') return res.status(202).json({ status:'pending',sessionId,requestId });
        if (value.status === 'not_found') return res.status(404).json({ status:'not_found',sessionId,requestId });
        throw new Error('Invalid saved product summary');
      }));
    } else registerUnavailable([['get','/products/:id/summary/sessions/:sessionId/requests/:requestId']]);
    if(typeof productAssist.question==='function')router.post('/products/:id/question',...persona('customer'),handle(async(req,res)=>{
      const productId=resourceId(req.params.id),body=req.body;
      if(!productId||!exactQuery(req,[])||!req.is('application/json')||!plain(body)||Object.keys(body).some(k=>!['message','sessionId','requestId'].includes(k))
        ||typeof body.message!=='string'||!body.message.trim()||!body.message.isWellFormed()||body.message.includes('\0')||Buffer.byteLength(body.message)>8192
        ||body.sessionId!==undefined&&!SESSION_UUID.test(body.sessionId)||body.requestId!==undefined&&!SESSION_UUID.test(body.requestId))return res.status(400).json({error:'Invalid product question'});
      const selected={message:body.message,...(body.sessionId===undefined?{}:{sessionId:body.sessionId}),...(body.requestId===undefined?{}:{requestId:body.requestId})};
      const result=await runProductRequest(req,res,signal=>productAssist.question({...context(req),...(req.ssPersonaSession?{personaSession:req.ssPersonaSession}:{}),productId,...selected,signal}));
      if(result===PRODUCT_REQUEST_ABORTED)return;
      if(!plain(result)||result.product_id!==productId||typeof result.answer!=='string'||!result.answer.trim()||!SESSION_UUID.test(result.sessionId)||!SESSION_UUID.test(result.requestId)
        ||selected.requestId!==undefined&&result.requestId!==selected.requestId||selected.sessionId!==undefined&&result.sessionId!==selected.sessionId)throw Error('Invalid bound product answer');
      res.json(project(result,['product_id','answer','sessionId','requestId','provider','model','modeCapability']));
    }));
    router.get('/products/:id/similar', ...persona('customer'), handle(async (req, res) => {
      const productId = resourceId(req.params.id);
      if (!productId || !exactQuery(req, [])) {
        return res.status(400).json({ error: 'Invalid similar-products request' });
      }
      let result;
      try {
        result = await runProductRequest(req, res, signal =>
          productAssist.similar({ ...context(req), ...(req.ssPersonaSession?{personaSession:req.ssPersonaSession}:{}), productId, signal }));
      } catch (error) {
        if (productNotFound(error)) return res.status(404).json({ error: 'not found' });
        throw error;
      }
      if (result === PRODUCT_REQUEST_ABORTED) return;
      res.json(projectSimilarResult(result, { productId }));
    }));
    const similarContext = req => ({ ...context(req),
      ...(req.ssPersonaSession ? { personaSession: req.ssPersonaSession } : {}) });
    if (typeof productAssist.createSimilarSession === 'function') {
      router.post('/products/:id/similar/session', ...persona('customer'), handle(async (req, res) => {
        res.set('Cache-Control', 'no-store');
        const productId = resourceId(req.params.id);
        if (!productId || !exactQuery(req, [])
            || (req.body !== undefined && !exactBody(req, [], []))) {
          return res.status(400).json({ error: 'Invalid similar-products session request' });
        }
        const value = await runProductRequest(req, res, signal =>
          productAssist.createSimilarSession({ ...similarContext(req), productId, signal }));
        if (value === PRODUCT_REQUEST_ABORTED) return;
        const sessionId = lowerRequestUuid(value?.sessionId);
        if (!sessionId) throw new Error('Invalid bound similar-products session');
        res.json({ sessionId });
      }));
    } else registerUnavailable([['post', '/products/:id/similar/session']]);
    if (typeof productAssist.runSimilar === 'function') {
      router.post('/products/:id/similar', ...persona('customer'), handle(async (req, res) => {
        res.set('Cache-Control', 'no-store');
        const productId = resourceId(req.params.id);
        if (!productId || !exactQuery(req, [])
            || !exactBody(req, ['sessionId', 'requestId'])
            || !lowerRequestUuid(req.body.sessionId) || !lowerRequestUuid(req.body.requestId)) {
          return res.status(400).json({ error: 'Invalid similar-products run request' });
        }
        const { sessionId, requestId } = req.body;
        const value = await runProductRequest(req, res, signal => productAssist.runSimilar({
          ...similarContext(req), productId, sessionId, requestId, signal }));
        if (value === PRODUCT_REQUEST_ABORTED) return;
        res.json(projectSimilarResult(value, { productId, sessionId, requestId }));
      }));
    } else registerUnavailable([['post', '/products/:id/similar']]);
    if (typeof productAssist.readSimilar === 'function') {
      router.get('/products/:id/similar/sessions/:sessionId/requests/:requestId',
        ...persona('customer'), handle(async (req, res) => {
          res.set('Cache-Control', 'no-store');
          const productId = resourceId(req.params.id);
          const sessionId = lowerRequestUuid(req.params.sessionId);
          const requestId = lowerRequestUuid(req.params.requestId);
          if (!productId || !sessionId || !requestId || !exactQuery(req, [])
              || req.body !== undefined) {
            return res.status(400).json({ error: 'Invalid similar-products read request' });
          }
          const value = await runProductRequest(req, res, signal => productAssist.readSimilar({
            ...similarContext(req), productId, sessionId, requestId, signal }));
          if (value === PRODUCT_REQUEST_ABORTED) return;
          if (!plain(value)) throw new Error('Invalid bound similar-products read');
          if (value.status === 'completed') {
            return res.json({ status: 'completed', result: projectSimilarResult(value.result,
              { productId, sessionId, requestId }) });
          }
          if (value.sessionId !== sessionId || value.requestId !== requestId) {
            throw new Error('Invalid bound similar-products read');
          }
          if (value.status === 'pending') {
            return res.status(202).json({ status: 'pending', sessionId, requestId });
          }
          if (value.status === 'not_found') {
            return res.status(404).json({ status: 'not_found', sessionId, requestId });
          }
          throw new Error('Invalid bound similar-products read');
        }));
    } else registerUnavailable([
      ['get', '/products/:id/similar/sessions/:sessionId/requests/:requestId'],
    ]);
  } else registerUnavailable([
    ['post', '/products/:id/summary'], ['post', '/products/:id/summary/session'],
    ['get', '/products/:id/summary/sessions/:sessionId/requests/:requestId'], ['post', '/products/:id/question'],
    ['get', '/products/:id/similar'], ['post', '/products/:id/similar/session'],
    ['post', '/products/:id/similar'],
    ['get', '/products/:id/similar/sessions/:sessionId/requests/:requestId'],
  ]);

  const auditCapability = (ready, reason) => ready ? { ready: true } : { ready: false, reason };
  const auditCapabilities = Object.freeze({
    manualSearch: auditCapability(typeof auditSearch?.search === 'function', 'Owned audit search is unavailable'),
    agentSearch: auditCapability(auditAgentReady && typeof auditSearch?.createAgentSession === 'function'
      && typeof auditSearch?.runAgent === 'function', 'Owned audit agent is unavailable'),
    timingAgent: auditCapability(auditTimingReady && typeof auditSearch?.createTimingSession === 'function'
      && typeof auditSearch?.runTimingAgent === 'function', 'Owned audit timing agent is unavailable'),
    summary: auditCapability(typeof auditSummary?.createSession === 'function'
      && typeof auditSummary?.run === 'function', 'Audit summary is unavailable'),
    unbounded: auditCapability(typeof auditUnbounded?.createSession === 'function'
      && typeof auditUnbounded?.run === 'function', 'Audit unbounded summary is unavailable'),
  });
  router.get('/admin/audit/capabilities', ...persona('admin'), (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid audit capabilities request' });
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, capabilities: auditCapabilities });
  });

  // The durable audit summary is optional until its run-storage schema and
  // model qualification gates are active. Keep disabled paths terminal so
  // requests cannot fall through to the legacy audit tool.
  const auditSummarySession = (service, unavailable) => async (req, res) => {
    if (!exactQuery(req, []) || !exactBody(req, [], [])) {
      return res.status(400).json({ error: 'Invalid audit summary session request' });
    }
    if (!service) return res.status(503).json({ error: unavailable });
    const result = await service.createSession({ ...context(req),
      ...(req.ssPersonaSession ? { personaSession: Object.freeze({ sessionId: req.ssPersonaSession.sessionId,
        authorityVersion: req.ssPersonaSession.authorityVersion }) } : {}) });
    const sessionId = requestUuid(result?.sessionId);
    if (!sessionId) throw new Error('Invalid audit summary session');
    res.json({ ok: true, sessionId });
  };
  const auditSummaryRun = (service, unavailable) => async (req, res) => {
    if (!exactQuery(req, []) || !exactBody(req, ['session_id', 'request_id', 'limit'])) {
      return res.status(400).json({ error: 'Invalid audit summary request' });
    }
    const sessionId = requestUuid(req.body.session_id);
    const requestId = requestUuid(req.body.request_id);
    const requestedCount = positiveBody(req.body.limit);
    if (!sessionId || !requestId || !requestedCount) {
      return res.status(400).json({ error: 'Invalid audit summary request' });
    }
    if (!service) return res.status(503).json({ error: unavailable });
    const result = await runProductRequest(req, res, signal => service.run({
      ...context(req), ...(req.ssPersonaSession ? { personaSession: Object.freeze({ sessionId: req.ssPersonaSession.sessionId,
        authorityVersion: req.ssPersonaSession.authorityVersion }) } : {}),
      sessionId, requestId, requestedCount, signal,
    }));
    if (result === PRODUCT_REQUEST_ABORTED) return;
    if (!plain(result) || !requestUuid(result.runId) || typeof result.summary !== 'string'
      || !result.summary.trim() || typeof result.provider !== 'string' || !result.provider
      || typeof result.model !== 'string' || !result.model
      || !Number.isSafeInteger(result.requestedCount) || result.requestedCount !== requestedCount
      || !Number.isSafeInteger(result.rowCount) || result.rowCount < 0
      || result.rowCount > result.requestedCount || typeof result.objectiveCredit !== 'boolean'
      || typeof result.replayed !== 'boolean'
      || !plain(result.assessment)||typeof result.assessment.completed!=='boolean'
      || !plain(result.assessment.judgment)||!['pass','fail','inconclusive','unavailable'].includes(result.assessment.judgment.verdict)
      || result.objectiveCredit!==result.assessment.completed
      || (result.objectiveCredit&&result.assessment.judgment.verdict!=='pass')) {
      throw new Error('Invalid bound audit summary result');
    }
    res.json(project(result, ['runId', 'summary', 'provider', 'model', 'requestedCount',
      'rowCount', 'objectiveCredit', 'replayed', 'assessment', 'modeCapability']));
  };
  router.post('/admin/audit/bound-session', ...persona('admin'), handle(auditSummarySession(auditSummary, 'Audit summary unavailable')));
  router.post('/admin/audit/bound-summary', ...persona('admin'), handle(auditSummaryRun(auditSummary, 'Audit summary unavailable')));
  router.post('/admin/audit/unbounded-session', ...persona('admin'), handle(auditSummarySession(auditUnbounded, 'Audit unbounded summary unavailable')));
  router.post('/admin/audit/unbounded-summary', ...persona('admin'), handle(auditSummaryRun(auditUnbounded, 'Audit unbounded summary unavailable')));

  const ownedAuditSearch = handle(async (req, res) => {
    if (!auditSearch || typeof auditSearch.search !== 'function') return res.status(503).json({ error: 'Owned audit search unavailable' });
    if (!plain(req.body) || Object.keys(req.body).some(key => !['username','operationId'].includes(key))
      || typeof req.body.username !== 'string' || Buffer.byteLength(req.body.username) > 8192
      || typeof req.body.operationId !== 'string' || !SESSION_UUID.test(req.body.operationId)) return res.status(400).json({ error: 'Invalid audit search operation' });
    const result = await runProductRequest(req, res, signal => auditSearch.search({ ...context(req),
      token: readBearer(req), operationId: req.body.operationId, username: req.body.username, signal }));
    if (result === PRODUCT_REQUEST_ABORTED) return;
    if (result) res.json(result);
  });
  router.post('/admin/audit/search', ...persona('admin'), ownedAuditSearch);
  router.post('/admin/audit/search-by-user', ...persona('admin'), ownedAuditSearch);
  const auditAgentSession=(method,ready,unavailable)=>handle(async(req,res)=>{
    if(!ready||typeof auditSearch?.[method]!=='function')return res.status(503).json({error:unavailable});if(!plain(req.body)||Object.keys(req.body).length)return res.status(400).json({error:'Invalid audit session'});res.json(await auditSearch[method]({...context(req),...(req.ssPersonaSession?{personaSession:Object.freeze({sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion})}:{})}));
  });
  const auditAgentRun=(method,ready,unavailable)=>handle(async(req,res)=>{
    if(!ready||typeof auditSearch?.[method]!=='function')return res.status(503).json({error:unavailable});
    if(!plain(req.body)||Object.keys(req.body).sort().join(',')!=='message,requestId,sessionId'||!SESSION_UUID.test(req.body.sessionId)||!SESSION_UUID.test(req.body.requestId)||typeof req.body.message!=='string'||!req.body.message.trim()||Buffer.byteLength(req.body.message)>12000)return res.status(400).json({error:'Invalid audit agent operation'});
    const result=await runProductRequest(req,res,signal=>auditSearch[method]({...context(req),...req.body,...(req.ssPersonaSession?{personaSession:Object.freeze({sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion})}:{}),signal}));
    if (result === PRODUCT_REQUEST_ABORTED) return;
    if(result)res.json(result);
  });
  router.post('/admin/audit/agent-session', ...persona('admin'), auditAgentSession('createAgentSession',true,'Owned audit agent unavailable'));
  router.post('/admin/audit/agent-search', ...persona('admin'), auditAgentRun('runAgent',true,'Owned audit agent unavailable'));
  router.post('/admin/audit/timing-session', ...persona('admin'), auditAgentSession('createTimingSession',auditTimingReady,'Owned audit timing agent unavailable'));
  router.post('/admin/audit/timing-run', ...persona('admin'), auditAgentRun('runTimingAgent',auditTimingReady,'Owned audit timing agent unavailable'));


  for (const [url,method] of [['/admin/agent-host/health','runtimeHealth'],['/admin/mcp/servers','mcpServers'],['/admin/mcp/schema-history','mcpHistory'],['/admin/db-sizes','dbSizes']]) {
    if (typeof admin?.[method] === 'function') router.get(url, ...persona('admin'), handle(async(req,res)=> {
      if (Object.keys(req.query).length) return res.status(400).json({error:'Unexpected bound read query'});
      try { res.json({ok:true,...await admin[method](adminContext(req))}); }
      catch(error) { if(error?.statusCode===503) return res.status(503).json({error:error.message,code:error.code}); throw error; }
    }));
    else registerUnavailable([['get', url]]);
  }

  if (typeof admin?.mcpTools === 'function') router.get('/admin/mcp/servers/:name/tools', ...persona('admin'), handle(async(req,res)=>{
    if(Object.keys(req.query).length)return res.status(400).json({error:'Unexpected bound read query'});
    try{res.json({ok:true,...await admin.mcpTools({...adminContext(req),name:req.params.name})});}
    catch(error){if([400,404,503].includes(error?.statusCode))return res.status(error.statusCode).json({error:error.message,code:error.code});throw error;}
  }));
  else registerUnavailable([['get', '/admin/mcp/servers/:name/tools']]);

  if (typeof admin?.audit === 'function') {
    router.get('/admin/audit', ...persona('admin'), handle(async (req, res) => {
      const limit = positive(req.query.limit, 200, 10000);
      if (!exactQuery(req, ['limit', 'actor', 'action', 'target', 'q', 'from', 'to', 'cursor']) || !limit) {
        return res.status(400).json({ error: 'Invalid audit request' });
      }
      const query = { ...req.query, limit };
      require('../../database/postgres/secureshopBoundAuditRepository').auditQuery(query);
      res.json({ ok: true, ...await admin.audit({ ...adminContext(req), query }) });
    }));
  } else registerUnavailable([['get', '/admin/audit']]);
  if (typeof admin?.providers === 'function') {
    router.get('/admin/provider-state', ...persona('admin'), handle(async (req, res) => {
      if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid provider-state request' });
      const providers = await admin.providers(adminContext(req));
      res.json({ ok: true, count: providers.length, providers });
    }));
  } else registerUnavailable([['get', '/admin/provider-state']]);
  if (typeof admin?.latestTrace === 'function') {
    router.get('/agents/admin/trace/latest', ...persona('admin'), handle(async (req, res) => {
      const limit = positive(req.query.limit, 20, 200);
      if (!exactQuery(req, ['limit']) || !limit) return res.status(400).json({ error: 'Invalid trace request' });
      const rows = await admin.latestTrace({ ...adminContext(req), limit });
      res.json({ ok: true, count: rows.length, rows });
    }));
  } else registerUnavailable([['get', '/agents/admin/trace/latest']]);
  if (typeof personaObservations?.latestTrace === 'function') {
    for (const role of ['customer', 'merchant']) {
      router.get(`/agents/${role}/trace/latest`, ...persona(role), handle(async (req, res) => {
        const limit = positive(req.query.limit, 20, 50);
        if (!exactQuery(req, ['limit']) || !limit) return res.status(400).json({ error: 'Invalid trace request' });
        const rows = await personaObservations.latestTrace({ ...commerceContext(req), limit });
        res.json({ ok: true, count: rows.length, rows, basis: 'persisted_launch_persona_trace' });
      }));
    }
  } else registerUnavailable([
    ['get', '/agents/customer/trace/latest'], ['get', '/agents/merchant/trace/latest'],
  ]);
  if (typeof admin?.kpis === 'function') {
    router.get('/admin/overview/kpis', ...persona('admin'), handle(async (req, res) => {
      if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid admin overview request' });
      res.json({ ok: true, ...await admin.kpis(adminContext(req)) });
    }));
  } else registerUnavailable([['get', '/admin/overview/kpis']]);
  if (admin) {
    router.get('/admin/users', ...persona('admin'), handle(async (req, res) => {
      const page = positive(req.query.page, 1, 2147483647);
      const pageSize = positive(req.query.pageSize, 25, 100);
      if (!exactQuery(req, ['page', 'pageSize', 'search', 'role', 'banned']) || !page || !pageSize) {
        return res.status(400).json({ error: 'Invalid admin users request' });
      }
      const result = await admin.users({ ...adminContext(req), query: {
        page, pageSize, search: req.query.search ?? '', role: req.query.role ?? '',
        banned: req.query.banned ?? '',
      } });
      res.json({ ok: true, ...result });
    }));
  } else if (!userAdministration) registerUnavailable([['get', '/admin/users']]);

  router.get('/products', ...persona(), handle(async (req, res) => {
    const allowed = ['search', 'q', 'category', 'sort', 'minRating', 'maxPrice', 'page', 'limit', 'offset'];
    const limit = positive(req.query.limit, 24, 100);
    const minRating = req.query.minRating === undefined ? null : positive(req.query.minRating, 0, 5);
    const maxPrice = catalogPrice(req.query.maxPrice);
    let offset = nonnegative(req.query.offset, 0);
    let page = positive(req.query.page, 1, 2147483647);
    if (!exactQuery(req, allowed) || !limit || offset < 0 || !page
        || minRating === 0 || Number.isNaN(maxPrice)) {
      return res.status(400).json({ error: 'Invalid catalog request' });
    }
    // The customer UI sends an offset; other clients may send a page. Resolve
    // the omitted representation before enforcing the catalog's single range.
    if (req.query.page === undefined) page = offset / limit + 1;
    if (req.query.offset === undefined) offset = (page - 1) * limit;
    if (!Number.isSafeInteger(page) || page > 2147483647 || !Number.isSafeInteger(offset)
        || offset > 2147483647 || offset !== (page - 1) * limit) {
      return res.status(400).json({ error: 'Invalid catalog request' });
    }
    const result = await catalog.listProducts({ ...context(req), query: Object.freeze({
      search: req.query.search ?? req.query.q ?? null, category: req.query.category ?? null,
      minRating, maxPrice,
      sort: req.query.sort ?? '', page, limit, offset,
    }) });
    if (!plain(result) || !Array.isArray(result.products)) throw new Error('Invalid bound catalog projection');
    const products = result.products.map(row => project(row, PRODUCT_FIELDS));
    res.json({ products, count: Number.isSafeInteger(result.count) ? result.count : products.length,
      total: Number.isSafeInteger(result.total) ? result.total : products.length });
  }));

  router.get('/products/:id', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid catalog request' });
    const productId = resourceId(req.params.id);
    if (!productId) return res.status(400).json({ error: 'Invalid catalog request' });
    const result = await catalog.getProduct({ ...context(req), productId });
    if (result === null) return res.status(404).json({ error: 'not found' });
    if (!plain(result) || !plain(result.product)
      || (result.reviews !== undefined && !Array.isArray(result.reviews))) {
      throw new Error('Invalid bound catalog projection');
    }
    res.json({ product: project(result.product, PRODUCT_FIELDS),
      ...(result.reviews === undefined ? {} : {
        reviews: result.reviews.map(row => project(row, REVIEW_FIELDS)),
      }) });
  }));

  router.get('/categories', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid catalog request' });
    const result = await catalog.categories({ ...context(req) });
    if (!plain(result) || !Array.isArray(result.categories)) {
      throw new Error('Invalid bound catalog projection');
    }
    res.json({ categories: result.categories.slice() });
  }));

  const merchantContext=req=>({...context(req),...(req.ssPersonaSession?{personaSession:Object.freeze({sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion})}:{})});
  const manualListing = require('../../services/secureshopManualListingContract');
  router.get('/merchant/listings/manual/readiness', ...persona('merchant'), handle(async (req, res) => {
    if (!exactQuery(req, []) || req.body !== undefined && !exactBody(req, [], []))
      return res.status(400).json({ error: 'Invalid manual listing readiness request' });
    res.json(await catalog.manualListingReadiness(merchantContext(req)));
  }));
  for (const kind of ['create', 'edit']) {
    const suffix = kind === 'create' ? 'Create' : 'Edit';
    router.post(`/merchant/listings/manual/${kind}/preview`, ...persona('merchant'), handle(async (req, res) => {
      const keys = kind === 'create' ? ['listing'] : ['productId', 'listing'];
      if (!exactQuery(req, []) || !exactBody(req, keys))
        return res.status(400).json({ error: 'Invalid manual listing preview request' });
      manualListing.boundManualListingRequest(req.body);
      const listing = manualListing.normalizeManualListing(req.body.listing);
      res.json(await catalog[`previewManualMerchantListing${suffix}`]({ ...merchantContext(req), listing,
        ...(kind === 'edit' ? { productId: req.body.productId } : {}) }));
    }));
    router.post(`/merchant/listings/manual/${kind}/confirm`, ...persona('merchant'), handle(async (req, res) => {
      if (!exactQuery(req, []) || !exactBody(req, ['operationId', 'preview']) || !requestUuid(req.body.operationId))
        return res.status(400).json({ error: 'Invalid manual listing confirmation request' });
      manualListing.boundManualListingRequest(req.body);
      const preview = manualListing.validateManualListingPreview(req.body.preview, kind);
      res.json(await catalog[`confirmManualMerchantListing${suffix}`]({ ...merchantContext(req),
        operationId: req.body.operationId, preview }));
    }));
    router.get(`/merchant/listings/manual/${kind}/operations/:operationId`, ...persona('merchant'), handle(async (req, res) => {
      if (!exactQuery(req, []) || !requestUuid(req.params.operationId)
          || req.body !== undefined && !exactBody(req, [], []))
        return res.status(400).json({ error: 'Invalid manual listing outcome request' });
      res.json(await catalog[`readManualMerchantListing${suffix}`]({ ...merchantContext(req), operationId: req.params.operationId }));
    }));
  }
  router.get('/merchant/products', ...persona('merchant'), handle(async (req, res) => {
    const allowed = ['retailer_id', 'page', 'per_page', 'sort', 'search', 'status', 'category'];
    const page = positive(req.query.page, 1, 2147483647);
    const perPage = positive(req.query.per_page, 20, 100);
    const retailerId = req.query.retailer_id === undefined
      ? null : positive(req.query.retailer_id, 0, 2147483647);
    if (!exactQuery(req, allowed) || !page || !perPage || retailerId === 0) {
      return res.status(400).json({ error: 'Invalid catalog request' });
    }
    const result = await catalog.listMerchantProducts({ ...merchantContext(req), query: Object.freeze({
      retailerId, page, perPage, sort: req.query.sort ?? 'updated_desc',
      search: req.query.search ?? null, status: req.query.status ?? null,
      category: req.query.category ?? null,
    }) });
    if (!plain(result) || !Array.isArray(result.products)) throw new Error('Invalid bound catalog projection');
    const products = result.products.map(row => project(row, PRODUCT_FIELDS));
    const total = Number.isSafeInteger(result.total) ? result.total : products.length;
    res.json({ products, count: Number.isSafeInteger(result.count) ? result.count : products.length,
      total, page, per_page: perPage, pages: Math.max(1, Math.ceil(total / perPage)),
      categories: Array.isArray(result.categories) ? result.categories.slice() : [] });
  }));

  router.post('/merchant/products', ...persona('merchant'), handle(async (req, res) => {
    const allowed = ['title', 'description', 'price', 'images', 'category', 'template_source', 'retailer_id'];
    if (!exactQuery(req, []) || !exactBody(req, allowed)
        || typeof req.body.title !== 'string' || typeof req.body.description !== 'string'
        || typeof req.body.price !== 'number' || !Number.isFinite(req.body.price)
        || !Array.isArray(req.body.images) || Object.keys(req.body.images).length !== req.body.images.length
        || req.body.images.some(value => typeof value !== 'string')
        || (req.body.category !== null && typeof req.body.category !== 'string')
        || (req.body.template_source !== null && typeof req.body.template_source !== 'string')
        || !Number.isSafeInteger(req.body.retailer_id) || req.body.retailer_id < 1) {
      return res.status(400).json({ error: 'Invalid merchant listing request' });
    }
    const result = await catalog.createMerchantProduct({ ...merchantContext(req), listing: Object.freeze({
      name: req.body.title, description: req.body.description, price: req.body.price,
      images: req.body.images.slice(), category: req.body.category,
      templateSource: req.body.template_source,
    }) });
    res.json({ ok: true, product_id: result.productId });
  }));

  router.put('/merchant/products/:id', ...persona('merchant'), handle(async (req, res) => {
    const productId = resourceId(req.params.id); const allowed = ['name', 'description', 'price',
      'category', 'template_source', 'image_url'];
    if (!productId || !exactQuery(req, []) || !exactBody(req, ['patch'])
        || !plain(req.body.patch) || Object.keys(req.body.patch).length === 0
        || Object.keys(req.body.patch).some(key => !allowed.includes(key))
        || (Object.hasOwn(req.body.patch, 'name') && typeof req.body.patch.name !== 'string')
        || (Object.hasOwn(req.body.patch, 'description') && req.body.patch.description !== null
          && typeof req.body.patch.description !== 'string')
        || (Object.hasOwn(req.body.patch, 'price') && (typeof req.body.patch.price !== 'number'
          || !Number.isFinite(req.body.patch.price)))
        || ['category', 'template_source', 'image_url'].some(key => Object.hasOwn(req.body.patch, key)
          && req.body.patch[key] !== null && typeof req.body.patch[key] !== 'string')) {
      return res.status(400).json({ error: 'Invalid merchant listing request' });
    }
    const patch = {};
    for (const key of Object.keys(req.body.patch)) {
      patch[key === 'template_source' ? 'templateSource' : key === 'image_url' ? 'imageUrl' : key]
        = req.body.patch[key];
    }
    const result = await catalog.updateMerchantProduct({ ...merchantContext(req), productId,
      patch: Object.freeze(patch) });
    if (result === null) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true, product_id: result.productId });
  }));

  router.delete('/merchant/products/:id', ...persona('merchant'), handle(async (req, res) => {
    const productId = resourceId(req.params.id);
    if (!productId || !exactQuery(req, [])
        || (req.body !== undefined && !exactBody(req, [], []))) {
      return res.status(400).json({ error: 'Invalid merchant listing request' });
    }
    if (!(await catalog.archiveMerchantProduct({ ...merchantContext(req), productId }))) {
      return res.status(404).json({ error: 'not found' });
    }
    res.json({ ok: true });
  }));

  for (const [path, key] of [['kpis', 'kpis'], ['sales-chart', 'salesChart']]) {
    router.get(`/merchant/overview/${path}`, ...persona('merchant'), handle(async (req, res) => {
      const days = path === 'kpis' ? 30 : positive(req.query.days, 30, 365);
      if (!exactQuery(req, path === 'kpis' ? ['retailer_id'] : ['retailer_id', 'days']) || !days || days < 7
          || (req.query.retailer_id !== undefined && resourceId(req.query.retailer_id) !== req.ssUser.id)) {
        return res.status(400).json({ error: 'Invalid merchant reporting request' });
      }
      if (typeof commerce.merchantOverview !== 'function') return res.status(503).json({ error: 'Merchant reporting unavailable' });
      const result = await commerce.merchantOverview({ ...commerceContext(req), days });
      res.json(result[key]);
    }));
  }
  router.get('/merchant/overview/top-products', ...persona('merchant'), handle(async (req, res) => {
    const days = positive(req.query.days, 30, 365), limit = positive(req.query.limit, 8, 50);
    if (!exactQuery(req, ['days','limit']) || !days || days < 7 || !limit) {
      return res.status(400).json({ error: 'Invalid merchant reporting request' });
    }
    if (typeof commerce.merchantTopProducts !== 'function') return res.status(503).json({ error: 'Merchant reporting unavailable' });
    const result = await commerce.merchantTopProducts({ ...commerceContext(req), days, limit });
    res.set('Cache-Control', 'no-store');
    res.json(result);
  }));

  router.get('/recommended', ...persona('customer'), handle(async (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid recommendations request' });
    if (typeof commerce.recommendations !== 'function') return res.status(503).json({ error: 'Bound recommendations unavailable' });
    const result = await commerce.recommendations(commerceContext(req));
    if (!plain(result) || !Array.isArray(result.feed) || result.feed.length > 6
        || result.provenance?.algorithm !== 'local-category-affinity-v1'
        || result.provenance?.modelUsed !== false) throw new Error('Invalid recommendations projection');
    res.set('Cache-Control', 'no-store');
    res.json({ feed: result.feed.map(row => ({ ...project(row, PRODUCT_FIELDS),
      recommendation_reason: row.recommendation_reason })), provenance: result.provenance });
  }));

  const conversationDomain = typeof commerce.conversational==='function'
    ? require('../../services/secureshopConversationalCommerce').createConversationalCommerce({commerce}) : null;
  router.get('/customer/commerce/profile-form',...persona('customer'),handle(async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(!exactQuery(req,[]))return res.status(400).json({error:'Invalid conversational commerce request'});
    if(!conversationDomain||req.ssApiAuthority)return res.status(503).json({error:'Conversational commerce unavailable'});
    res.json(await conversationDomain.profileForm({...commerceContext(req),args:{}}));
  }));
  router.get('/customer/commerce/address-form',...persona('customer'),handle(async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(!exactQuery(req,['action','choiceId'])||!Object.hasOwn(req.query,'action')
      ||(req.query.action==='create'&&Object.hasOwn(req.query,'choiceId'))
      ||(req.query.action==='update'&&!Object.hasOwn(req.query,'choiceId')))
      return res.status(400).json({error:'Invalid conversational commerce request'});
    if(!conversationDomain||req.ssApiAuthority)return res.status(503).json({error:'Conversational commerce unavailable'});
    res.json(await conversationDomain.addressForm({...commerceContext(req),args:{action:req.query.action,
      choiceId:req.query.choiceId??null}}));
  }));
  for(const [method,path,verb,keys] of [
    ['addressChoices','/customer/commerce/addresses','get',[]],
    ['saveAddress','/customer/commerce/addresses','post',['operationId','action','choiceId','expectedSnapshotSha256','defaultSetSha256','fields']],
    ['saveProfile','/customer/commerce/profile','post',['operationId','expectedSnapshotSha256','fields']],
    ['paymentMethods','/customer/commerce/payment-methods','get',[]],
    ['createPaymentMethod','/customer/commerce/payment-methods','post',['operationId','scenario']],
    ['prepareCheckout','/customer/commerce/checkout/prepare','post',['operationId','addressChoiceId','paymentChoiceId']],
    ['confirmCheckout','/customer/commerce/checkout/confirm','post',['proposalId']],
    ['confirmCart','/customer/commerce/cart/confirm','post',['proposalId']],
    ['readOperation','/customer/commerce/operations/:operationId','get',[]],
  ]) router[verb](path,...persona('customer'),handle(async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(!exactQuery(req,[])||(verb==='post'&&!exactBody(req,keys)))return res.status(400).json({error:'Invalid conversational commerce request'});
    if(!conversationDomain||req.ssApiAuthority)return res.status(503).json({error:'Conversational commerce unavailable'});
    const args=method==='readOperation'?{operationId:req.params.operationId}:verb==='post'?req.body:{};
    res.json(await conversationDomain[method]({...commerceContext(req),args}));
  }));

  router.get('/cart', ...persona('customer'), handle(async (req,res)=>{
    if(!exactQuery(req,[]))return res.status(400).json({error:'Invalid cart request'});
    const result=await commerce.cart(commerceContext(req));
    if(!plain(result)||!Array.isArray(result.items)||!Number.isFinite(result.subtotal))throw new Error('Invalid bound cart projection');
    res.json({items:result.items.map(row=>project(row,CART_FIELDS)),subtotal:result.subtotal,couponAvailable:commerce.couponAvailable===true,...(/^[a-f0-9]{64}$/.test(result.couponScopeKey||'')?{couponScopeKey:result.couponScopeKey}:{}),...(Object.hasOwn(result,'coupon')?{coupon:result.coupon,discount:result.discount,total:result.total}: {})});
  }));
  router.post('/cart/apply-coupon',...persona('customer'),handle(async(req,res)=>{
    if(!exactQuery(req,[])||!exactBody(req,['code','operationId'])||typeof req.body.code!=='string'||Buffer.byteLength(req.body.code)>1024||!require('../../services/secureshopCouponContract').UUID.test(req.body.operationId||''))return res.status(400).json({error:'Invalid coupon request'});
    if(typeof commerce.applyCoupon!=='function')return res.status(503).json({error:'Bound coupon unavailable'});
    const result=await commerce.applyCoupon({...commerceContext(req),code:req.body.code,operationId:req.body.operationId});res.status(result.ok?200:404).json(result);
  }));
  router.post('/cart', ...persona('customer'), handle(async(req,res)=>{
    if(!exactQuery(req,[])||!exactBody(req,['product_id','quantity']))return res.status(400).json({error:'Invalid cart request'});
    const {product_id:productId,quantity}=req.body;
    if(!Number.isSafeInteger(productId)||productId<1||!Number.isSafeInteger(quantity)||quantity<1||quantity>99)return res.status(400).json({error:'Invalid cart request'});
    const result=await commerce.add({...commerceContext(req),productId,quantity});res.json({ok:true,cart_item_id:result.id});
  }));
  router.patch('/cart/:id',...persona('customer'),handle(async(req,res)=>{
    const cartItemId=resourceId(req.params.id),quantity=req.body?.quantity;
    if(!cartItemId||!exactQuery(req,[])||!exactBody(req,['quantity'])||!Number.isSafeInteger(quantity)||quantity<1||quantity>99)return res.status(400).json({error:'Invalid cart request'});
    res.json({ok:true,changes:await commerce.update({...commerceContext(req),cartItemId,quantity})});
  }));
  router.delete('/cart/:id',...persona('customer'),handle(async(req,res)=>{
    const cartItemId=resourceId(req.params.id);if(!cartItemId||!exactQuery(req,[])||(req.body!==undefined&&!exactBody(req,[],[])))return res.status(400).json({error:'Invalid cart request'});
    res.json({ok:true,changes:await commerce.remove({...commerceContext(req),cartItemId})});
  }));
  router.post('/orders/summary',...persona('customer'),handle(async(req,res)=>{
    if(!exactQuery(req,[])||(req.body!==undefined&&!exactBody(req,[],[])))return res.status(400).json({error:'Invalid order request'});
    const result=await commerce.summary(commerceContext(req));const items=result.items.map(row=>project(row,CART_FIELDS));
    res.json({ok:true,items,total:result.total??result.subtotal,...(Object.hasOwn(result,'coupon')?{coupon:result.coupon,discount:result.discount}:{}),summary:{item_count:items.reduce((sum,row)=>sum+row.quantity,0),subtotal:result.subtotal,...(Object.hasOwn(result,'discount')?{discount:result.discount}: {})}});
  }));
  router.post('/orders',...persona('customer'),handle(async(req,res)=>{
    if(!exactQuery(req,[])||!exactBody(req,['shipping_address','payment_method','operationId'])||!require('../../services/secureshopCouponContract').UUID.test(req.body.operationId||''))return res.status(400).json({error:'Invalid order request'});
    const result=await commerce.checkout({...commerceContext(req),shippingAddress:req.body.shipping_address,paymentMethod:req.body.payment_method,operationId:req.body.operationId});
    res.json({ok:true,order_id:result.orderId,total:result.total,...(result.discount===undefined?{}:{discount:result.discount,subtotal:result.subtotal})});
  }));
  router.get('/orders',...persona('customer'),handle(async(req,res)=>{
    if(!exactQuery(req,[]))return res.status(400).json({error:'Invalid order request'});
    res.json({orders:(await commerce.orders(commerceContext(req))).map(row=>project(row,ORDER_FIELDS))});
  }));
  router.get('/orders/operations',...persona('customer'),handle(async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(!exactQuery(req,[]))return res.status(400).json({error:'Invalid checkout history request'});
    if(typeof commerce.checkoutHistory!=='function')return res.status(503).json({error:'Checkout history unavailable'});
    res.json(await commerce.checkoutHistory(commerceContext(req)));
  }));
  router.get('/orders/operations/:operationId',...persona('customer'),handle(async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(!exactQuery(req,[])||!require('../../services/secureshopCouponContract').UUID.test(req.params.operationId))return res.status(400).json({error:'Invalid checkout reference'});
    if(typeof commerce.checkoutReceipt!=='function')return res.status(503).json({error:'Checkout history unavailable'});
    res.json(await commerce.checkoutReceipt({...commerceContext(req),operationId:req.params.operationId.toLowerCase()}));
  }));
  router.get('/orders/:id',...persona('customer'),handle(async(req,res)=>{
    const orderId=resourceId(req.params.id);if(!orderId||!exactQuery(req,[]))return res.status(400).json({error:'Invalid order request'});
    const result=await commerce.order({...commerceContext(req),orderId});if(!result)return res.status(404).json({error:'not found'});
    res.json({order:project(result.order,ORDER_FIELDS),items:result.items.map(row=>project(row,ORDER_ITEM_FIELDS))});
  }));

  const accountContext=req=>({...context(req),...(req.ssApiAuthority?{apiAuthority:req.ssApiAuthority}:req.ssPersonaSession?{personaSession:Object.freeze({sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion})}:{})});
  router.get('/v2/auth/users/me', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid account request' });
    res.json({ ok: true, user: project(await account.profile(accountContext(req)), USER_FIELDS) });
  }));
  router.put('/v2/auth/users/me', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, []) || !exactBody(req, ['full_name', 'email', 'phone'])
        || (req.body.full_name !== null && typeof req.body.full_name !== 'string')
        || typeof req.body.email !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(req.body.email)
        || (req.body.phone !== null && typeof req.body.phone !== 'string')) {
      return res.status(400).json({ error: 'Invalid account request' });
    }
    const user = await account.updateProfile({ ...accountContext(req), fullName: req.body.full_name,
      email: req.body.email, phone: req.body.phone });
    res.json({ ok: true, user: project(user, USER_FIELDS) });
  }));

  function exactAddress(req) {
    const allowed = ['label', 'line1', 'line2', 'city', 'state', 'zip', 'phone', 'is_default'];
    if (!exactBody(req, allowed) || typeof req.body.line1 !== 'string'
        || typeof req.body.is_default !== 'boolean') return null;
    for (const key of ['label', 'line2', 'city', 'state', 'zip', 'phone']) {
      if (req.body[key] !== null && typeof req.body[key] !== 'string') return null;
    }
    return Object.freeze({ label: req.body.label, line1: req.body.line1, line2: req.body.line2,
      city: req.body.city, state: req.body.state, zip: req.body.zip, phone: req.body.phone,
      isDefault: req.body.is_default });
  }
  router.get('/v2/auth/users/me/addresses', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid address request' });
    res.json({ addresses: (await account.addresses(accountContext(req))).map(row => project(row, ADDRESS_FIELDS)) });
  }));
  router.post('/v2/auth/users/me/addresses', ...persona(), handle(async (req, res) => {
    const address = exactAddress(req);
    if (!exactQuery(req, []) || !address) return res.status(400).json({ error: 'Invalid address request' });
    const row = await account.createAddress({ ...accountContext(req), address });
    res.json({ ok: true, id: row.id });
  }));
  router.put('/v2/auth/users/me/addresses/:id', ...persona(), handle(async (req, res) => {
    const addressId = resourceId(req.params.id); const address = exactAddress(req);
    if (!addressId || !exactQuery(req, []) || !address) {
      return res.status(400).json({ error: 'Invalid address request' });
    }
    const row = await account.updateAddress({ ...accountContext(req), addressId, address });
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true });
  }));
  router.delete('/v2/auth/users/me/addresses/:id', ...persona(), handle(async (req, res) => {
    const addressId = resourceId(req.params.id);
    if (!addressId || !exactQuery(req, []) || (req.body !== undefined && !exactBody(req, [], []))) {
      return res.status(400).json({ error: 'Invalid address request' });
    }
    res.json({ ok: (await account.deleteAddress({ ...accountContext(req), addressId })) === 1 });
  }));

  router.get('/v2/auth/users/me/sessions', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid session request' });
    const sessions = await personaAuth.listSessions({ ...context(req), authorityVersion:req.ssPersonaSession?.authorityVersion,
      shopPersona: req.boundPersona, currentSessionId: req.ssPersonaSession?.sessionId });
    res.json({ sessions });
  }));
  router.post('/v2/auth/users/me/sessions/:id/revoke', ...persona(), handle(async (req, res) => {
    if (!SESSION_UUID.test(req.params.id) || !exactQuery(req, [])
        || (req.body !== undefined && !exactBody(req, [], []))) {
      return res.status(400).json({ error: 'Invalid session request' });
    }
    const ok = await personaAuth.revokeOwnedSession({ ...context(req), authorityVersion:req.ssPersonaSession?.authorityVersion,
      shopPersona: req.boundPersona, currentSessionId: req.ssPersonaSession?.sessionId,
      sessionId: req.params.id });
    res.json({ ok });
  }));

  router.post('/v2/auth/users/me/password', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, []) || !exactBody(req, ['current_password', 'new_password'])
        || typeof req.body.current_password !== 'string'
        || typeof req.body.new_password !== 'string') {
      return res.status(400).json({ error: 'Invalid password request' });
    }
    res.json(await personaAuth.changePassword({ ...context(req), shopPersona: req.boundPersona,
      currentSessionId: req.ssPersonaSession?.sessionId,
      currentPassword: req.body.current_password, newPassword: req.body.new_password }));
  }));

  router.get('/v2/auth/users/me/api-keys', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, [])) return res.status(400).json({ error: 'Invalid API key request' });
    res.json(await personaAuth.listApiKey({ ...context(req), authorityVersion:req.ssPersonaSession?.authorityVersion, shopPersona: req.boundPersona, currentSessionId:req.ssPersonaSession?.sessionId }));
  }));
  router.post('/v2/auth/users/me/api-keys/rotate', ...persona(), handle(async (req, res) => {
    if (!exactQuery(req, []) || (req.body !== undefined && !exactBody(req, [], []))) {
      return res.status(400).json({ error: 'Invalid API key request' });
    }
    res.json(await personaAuth.rotateApiKey({ ...context(req), shopPersona: req.boundPersona, currentSessionId: req.ssPersonaSession?.sessionId }));
  }));

  // The host launch capability remains the parent authority. The API key is a
  // child shop-persona credential and is resolved only inside req.ssLaunch.
  router.get('/v2/api/orders', apiPersona('customer'), handle(async (req, res) => {
    if (!exactQuery(req, []) || req.body !== undefined) {
      return res.status(400).json({ error: 'Invalid API order request' });
    }
    res.json({ orders: (await commerce.orders(commerceContext(req))).map(row => project(row, ORDER_FIELDS)) });
  }));
  router.get('/v2/api/orders/:id', apiPersona('customer'), handle(async (req, res) => {
    const orderId = resourceId(req.params.id);
    if (!orderId || !exactQuery(req, []) || req.body !== undefined) {
      return res.status(400).json({ error: 'Invalid API order request' });
    }
    const result = await commerce.order({ ...commerceContext(req), orderId });
    if (!result) return res.status(404).json({ error: 'not found' });
    res.json({ order: project(result.order, ORDER_FIELDS),
      items: result.items.map(row => project(row, ORDER_ITEM_FIELDS)) });
  }));

  // AuthContext hydration composes the immutable persona with this target's
  // profile and launch-local credential overlays. Registration remains unavailable.
  router.get('/v2/auth/whoami', ...persona(), handle(async (req, res) => {
    res.json({ ok: true, user: project(await account.profile(accountContext(req)), USER_FIELDS),
      expiresAt: req.ssPersonaSession?.expiresAt });
  }));

  router.use((_req, res) => res.status(404).json({ error: 'Bound SecureShop route not found' }));
  return router;
}

module.exports = { createSecureShopBoundGateway };
