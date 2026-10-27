'use strict';

const express = require('express');
const { rateLimit } = require('express-rate-limit');

const COOKIE = 'dvaia_shop_session';
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function projectBootstrap(value) {
  const launch = value?.launch, persona = value?.persona, user = persona?.user;
  const future = expiry => typeof expiry === 'string' && Date.parse(expiry) > Date.now();
  if (!exactKeys(value, ['launch', 'bearer', 'persona'])
    || !exactKeys(launch, ['launchId', 'generation', 'credentialVersion', 'expiresAt'])
    || !UUID.test(launch.launchId) || !Number.isSafeInteger(launch.generation) || launch.generation < 1
    || !Number.isSafeInteger(launch.credentialVersion) || launch.credentialVersion < 1
    || !future(launch.expiresAt) || !TOKEN.test(value.bearer)
    || !exactKeys(persona, ['token', 'user', 'expiresAt']) || !future(persona.expiresAt)
    || Date.parse(persona.expiresAt) > Date.parse(launch.expiresAt)
    || typeof persona.token !== 'string' || persona.token.length > 8192
    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(persona.token)
    || !exactKeys(user, ['id', 'username', 'email', 'role', 'full_name', 'phone'])
    || !Number.isSafeInteger(user.id) || user.id < 1 || !ROLES.has(user.role)
    || typeof user.username !== 'string' || typeof user.email !== 'string'
    || !(user.full_name === null || typeof user.full_name === 'string')
    || !(user.phone === null || typeof user.phone === 'string')) throw new Error('Invalid shop bootstrap');
  return { launch: { launchId: launch.launchId, generation: launch.generation,
    credentialVersion: launch.credentialVersion, expiresAt: launch.expiresAt }, bearer: value.bearer,
  persona: { token: persona.token, expiresAt: persona.expiresAt,
    user: { id: user.id, username: user.username, email: user.email, role: user.role,
      full_name: user.full_name, phone: user.phone } } };
}

function projectCartImport(value, requestId) {
  if (value?.requestId !== requestId || typeof value.imported !== 'boolean' || typeof value.replayed !== 'boolean') {
    throw new Error('Invalid cart import result');
  }
  if (value.imported) {
    if (!exactKeys(value, ['requestId', 'imported', 'replayed', 'items', 'subtotal'])
      || !Number.isFinite(value.subtotal) || value.subtotal < 0 || !Array.isArray(value.items) || value.items.length > 50
      || value.items.some(item => !exactKeys(item, ['productId', 'quantity', 'price', 'name'])
        || !Number.isSafeInteger(item.productId) || item.productId < 1
        || !Number.isSafeInteger(item.quantity) || item.quantity < 1 || item.quantity > 99
        || !Number.isFinite(item.price) || item.price < 0 || typeof item.name !== 'string' || Buffer.byteLength(item.name, 'utf8') > 4096)) {
      throw new Error('Invalid cart import success');
    }
  } else if (!exactKeys(value, ['requestId', 'imported', 'replayed', 'issues']) || value.replayed
    || !Array.isArray(value.issues) || !value.issues.length || value.issues.length > 50
    || value.issues.some(item => !Number.isSafeInteger(item.productId) || item.productId < 1
      || !['UNAVAILABLE', 'INSUFFICIENT_STOCK', 'CART_QUANTITY_LIMIT'].includes(item.code)
      || !Object.keys(item).every(key => ['productId', 'code', 'availableQuantity'].includes(key))
      || (item.availableQuantity !== undefined && (!Number.isSafeInteger(item.availableQuantity) || item.availableQuantity < 0)))) {
    throw new Error('Invalid cart import rejection');
  }
  return value;
}

// This cookie is a shop-only capability. Never consult a workshop bearer,
// identity cookie, or caller-supplied owner/session identifier here.
function readShopCookie(req) {
  const values = String(req.headers.cookie || '').split(';')
    .map(part => part.trim()).filter(part => part.startsWith(`${COOKIE}=`));
  if (values.length !== 1) return null;
  const token = values[0].slice(COOKIE.length + 1);
  return TOKEN.test(token) ? token : null;
}

function publicUser(user) {
  if (!user || typeof user.principalId !== 'string' || !ROLES.has(user.role)
    || typeof user.username !== 'string') throw new Error('Invalid shop identity projection');
  return { id: user.shopUserId ?? user.id, principalId: user.principalId,
    username: user.username, email: user.email, role: user.role };
}

function createSecureShopStandaloneAuthRouter({ service, bootstrap, cartImport, mode, assessmentObjectives, assessmentRecovery, assessmentProgress, registeredAdminReset, reset, practices, externalMail, allowedOrigins,
  secureCookies = false, loginLimit = 30 } = {}) {
  if (!service || ['login', 'register', 'authenticate', 'renew', 'logout', 'changePassword']
    .some(method => typeof service[method] !== 'function')
    || typeof bootstrap !== 'function' || !Array.isArray(allowedOrigins) || !allowedOrigins.length
    || !Number.isSafeInteger(loginLimit) || loginLimit < 1) throw new TypeError('Shop auth dependencies required');
  const origins = new Set(allowedOrigins.map(value => {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== value) throw new TypeError('Exact shop origin required');
    return value;
  }));
  const router = express.Router();
  if (externalMail) router.use('/external-mail', require('./secureshopExternalMail')
    .createExternalMailRouter({...externalMail,authService:service,allowedOrigins}));
  const cookieOptions = { httpOnly: true, sameSite: 'strict', secure: secureCookies, path: '/api/secureshop' };
  router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  router.use((req, res, next) => {
    if (req.method === 'GET') return next();
    if (!origins.has(req.get('Origin'))) return res.status(403).json({ error: 'Shop request origin denied' });
    if (!req.is('application/json')) return res.status(415).json({ error: 'JSON required' });
    next();
  });
  const limit = rateLimit({ windowMs: 15 * 60 * 1000, limit: loginLimit,
    standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'Too many shop authentication requests' } });
  const wrap = action => async (req, res) => {
    try { await action(req, res); } catch (error) {
      const errors = {
        INVALID_ARGUMENT: [400, 'Invalid shop request'],
        SHOP_CREDENTIALS_INVALID: [401, 'Invalid shop credentials'],
        SHOP_AUTH_INVALID: [401, 'Shop authentication required'],
        SHOP_LAUNCH_EXPIRED: [409, 'Shop launch expired; renew the shop session to continue'],
        SHOP_ACCOUNT_EXISTS: [409, 'Shop account already exists'],
        CART_IMPORT_CONFLICT: [409, 'Cart import request conflicts with an earlier request'],
        SHOP_MODE_CONFLICT: [409, 'Shop mode changed; reload its current value'],
        SHOP_ADMIN_REQUIRED: [403, 'Shop administrator required'],
        SHOP_OBJECTIVE_CONFLICT: [409, 'Objective configuration changed; reload its current value'],
        SHOP_OBJECTIVE_UNQUALIFIED: [409, 'This objective is not qualified for enablement'],
        SHOP_ASSESSMENT_NOT_FOUND: [404, 'Shop assessment not found'],
        REGISTERED_RESET_FORBIDDEN: [403, 'This account cannot be reset by this administrator'],
        REGISTERED_RESET_REVISION_CONFLICT: [409, 'Account changed; refresh before resetting'],
        REGISTERED_RESET_CONFLICT: [409, 'Reset request conflicts with an earlier request'],
        REGISTERED_RESET_OPERATION_NOT_FOUND: [404, 'Reset operation not found'],
        SHOP_RESET_SCOPE_CHANGED: [409, 'Shop practice changed; refresh reset readiness'],
        SHOP_RESET_CONFLICT: [409, 'Reset request conflicts with an earlier request'],
        SHOP_RESET_NOT_FOUND: [404, 'Shop reset operation not found'],
        SHOP_RESET_UNAVAILABLE: [503, 'Shop practice reset unavailable'],
        SHOP_PRACTICE_CAPACITY: [409, 'Practice capacity reached; retained practices remain available'],
        SHOP_PRACTICE_CONFLICT: [409, 'Practice admission changed; check its saved status'],
        SHOP_PRACTICE_NOT_FOUND: [404, 'Practice admission not found'],
      };
      const retryConflict = ['SHOP_ASSESSMENT_STALE', 'STALE_GENERATION', 'MODE_CHANGED', 'OBJECTIVE_DISABLED',
        'JUDGE_VERSION_CHANGED', 'RETRY_NOT_ALLOWED', 'RETRY_EXHAUSTED', 'EVIDENCE_EXPIRED'].includes(error.code);
      const [status, message] = errors[error.code] || (retryConflict
        ? [409, 'Assessment cannot be retried in its current state; refresh the assessment list']
        : [503, 'Shop service unavailable']);
      res.status(status).json({ error: message,
        ...(error.code === 'SHOP_LAUNCH_EXPIRED' ? { code: 'SHOP_LAUNCH_EXPIRED' } : {}),
        ...(['SHOP_PRACTICE_CAPACITY','SHOP_PRACTICE_CONFLICT'].includes(error.code)
          && UUID.test(req.body?.operationId || '') ? { code: error.code, operationId: req.body.operationId.toLowerCase() } : {}) });
    }
  };
  function body(req, keys) {
    const value = req.body;
    if (Object.keys(req.query).length || !value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
      throw Object.assign(new Error('Invalid request'), { code: 'INVALID_ARGUMENT' });
    }
    return value;
  }
  function setSession(res, result) {
    const expires = new Date(result?.expiresAt);
    const user = publicUser(result?.user);
    if (!TOKEN.test(result?.token || '') || !Number.isFinite(expires.getTime()) || expires <= new Date()) {
      throw new Error('Invalid shop session');
    }
    res.cookie(COOKIE, result.token, { ...cookieOptions, expires });
    res.json({ authenticated: true, user, expiresAt: expires.toISOString() });
  }
  async function authenticated(req) {
    const token = readShopCookie(req);
    const user = token && await service.authenticate(token);
    if (!user) throw Object.assign(new Error('No shop session'), { code: 'SHOP_AUTH_INVALID' });
    return { token, user };
  }
  router.post('/login', limit, wrap(async (req, res) => {
    setSession(res, await service.login(body(req, ['username', 'password'])));
  }));
  router.post('/register', limit, wrap(async (req, res) => {
    const input = body(req, ['username', 'email', 'password', 'role']);
    if (!['customer', 'merchant'].includes(input.role)) throw Object.assign(new Error('Role denied'), { code: 'INVALID_ARGUMENT' });
    setSession(res, await service.register(input));
  }));
  router.get('/session', wrap(async (req, res) => {
    if (Object.keys(req.query).length) throw Object.assign(new Error('Invalid query'), { code: 'INVALID_ARGUMENT' });
    const token = readShopCookie(req);
    const user = token && await service.authenticate(token);
    res.json({ authenticated: Boolean(user), user: user ? publicUser(user) : null });
  }));
  function projectPractice(value, operationId) {
    if (!exactKeys(value, ['operationId','status','sceneId','canResume'])
      || value.operationId !== operationId.toLowerCase()
      || !['unconfirmed','pending','published','retained_unfinished'].includes(value.status)
      || value.canResume !== (value.status === 'pending')
      || (value.status === 'published' ? !UUID.test(value.sceneId || '') : value.sceneId !== null)) {
      throw new Error('Invalid practice result');
    }
    return value;
  }
  router.post('/practices', wrap(async (req, res) => {
    const { operationId } = body(req, ['operationId']);
    if (typeof operationId !== 'string' || !UUID.test(operationId)) throw Object.assign(new Error('Invalid request'), { code: 'INVALID_ARGUMENT' });
    const { user } = await authenticated(req);
    if (typeof practices?.create !== 'function') throw new Error('Practice admission unavailable');
    res.json(projectPractice(await practices.create(user, operationId), operationId));
  }));
  router.get('/practices/:operationId', wrap(async (req, res) => {
    const { operationId } = req.params;
    if (Object.keys(req.query).length || !UUID.test(operationId)) throw Object.assign(new Error('Invalid request'), { code: 'INVALID_ARGUMENT' });
    const { user } = await authenticated(req);
    if (typeof practices?.read !== 'function') throw new Error('Practice admission unavailable');
    res.json(projectPractice(await practices.read(user, operationId), operationId));
  }));
  router.post('/renew', limit, wrap(async (req, res) => {
    body(req, []);
    const { token } = await authenticated(req);
    setSession(res, await service.renew(token));
  }));
  router.post('/logout', wrap(async (req, res) => {
    body(req, []);
    const token = readShopCookie(req);
    if (token) await service.logout(token);
    res.clearCookie(COOKIE, cookieOptions);
    res.json({ authenticated: false });
  }));
  router.post('/password', limit, wrap(async (req, res) => {
    const input = body(req, ['currentPassword', 'newPassword']);
    const { token } = await authenticated(req);
    const result = await service.changePassword(token, input);
    if (result?.ok !== true) throw new Error('Shop password change unconfirmed');
    res.clearCookie(COOKIE, cookieOptions);
    res.json({ authenticated: false, passwordChanged: true });
  }));
  function projectMode(value) {
    if (!exactKeys(value, ['mode', 'revision']) || !['vuln', 'fixed'].includes(value.mode)
      || typeof value.revision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value.revision) || BigInt(value.revision) > 9223372036854775807n) {
      throw new Error('Invalid shop mode result');
    }
    return value;
  }
  router.get('/mode', wrap(async (req, res) => {
    if (Object.keys(req.query).length) throw Object.assign(new Error('Invalid query'), { code: 'INVALID_ARGUMENT' });
    const { user } = await authenticated(req);
    if (typeof mode?.get !== 'function') throw new Error('Shop mode unavailable');
    res.json(projectMode(await mode.get(user)));
  }));
  router.post('/mode', wrap(async (req, res) => {
    const input = body(req, ['mode', 'expectedRevision']);
    if (!['vuln', 'fixed'].includes(input.mode) || typeof input.expectedRevision !== 'string'
      || !/^[1-9][0-9]{0,18}$/.test(input.expectedRevision) || BigInt(input.expectedRevision) > 9223372036854775807n) {
      throw Object.assign(new Error('Invalid shop mode'), { code: 'INVALID_ARGUMENT' });
    }
    const { user } = await authenticated(req);
    if (typeof mode?.set !== 'function') throw new Error('Shop mode unavailable');
    res.json(projectMode(await mode.set(user, input)));
  }));
  const objectiveIdValid = value => typeof value === 'string' && /^ss_[a-z0-9_]{1,100}$/.test(value);
  const revisionValid = value => typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value)
    && BigInt(value) <= 9223372036854775807n;
  function projectObjective(value, withLabel = false) {
    const keys = ['objectiveId', 'enabled', 'qualification', 'revision', ...(withLabel ? ['label'] : [])];
    if (!exactKeys(value, keys) || !objectiveIdValid(value.objectiveId) || typeof value.enabled !== 'boolean'
      || !['pending', 'native-model', 'native-browser-judge'].includes(value.qualification)
      || !revisionValid(value.revision) || (withLabel && (typeof value.label !== 'string'
        || !value.label.length || Buffer.byteLength(value.label, 'utf8') > 4096))) throw new Error('Invalid objective projection');
    return value;
  }
  async function shopAdmin(req) {
    const { user } = await authenticated(req);
    if (user.role !== 'admin') throw Object.assign(new Error('Shop administrator required'), { code: 'SHOP_ADMIN_REQUIRED' });
    return user;
  }
  const invalidProgressQuery = () => Object.assign(new Error('Invalid progress query'), { code: 'INVALID_ARGUMENT' });
  router.get('/progress', wrap(async (req, res) => {
    if (Object.keys(req.query).length) throw invalidProgressQuery();
    const { user } = await authenticated(req);
    if (typeof assessmentProgress?.readSelf !== 'function') throw new Error('Shop progress unavailable');
    res.json(await assessmentProgress.readSelf(user));
  }));
  router.get('/admin/progress/learners', wrap(async (req, res) => {
    if (Object.keys(req.query).some(key => !['limit', 'cursor'].includes(key))) throw invalidProgressQuery();
    const integer = (value, fallback) => {
      if (value === undefined) return fallback;
      if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,9})$/.test(value)) throw invalidProgressQuery();
      const number = Number(value);
      if (!Number.isSafeInteger(number)) throw invalidProgressQuery();
      return number;
    };
    const limit = integer(req.query.limit, 25), cursor = integer(req.query.cursor, null);
    if (limit < 1 || limit > 50 || (cursor !== null && cursor > 2147483647)) throw invalidProgressQuery();
    const user = await shopAdmin(req);
    if (typeof assessmentProgress?.listLearners !== 'function') throw new Error('Shop progress unavailable');
    res.json(await assessmentProgress.listLearners(user, { limit, cursor }));
  }));
  router.get('/admin/progress/:principalId', wrap(async (req, res) => {
    if (Object.keys(req.query).length || !UUID.test(req.params.principalId)) throw invalidProgressQuery();
    const user = await shopAdmin(req);
    if (typeof assessmentProgress?.readLearner !== 'function') throw new Error('Shop progress unavailable');
    res.json(await assessmentProgress.readLearner(user, { targetPrincipalId: req.params.principalId.toLowerCase() }));
  }));
  router.get('/assessment-objectives', wrap(async (req, res) => {
    if (Object.keys(req.query).length) throw Object.assign(new Error('Invalid query'), { code: 'INVALID_ARGUMENT' });
    const user = await shopAdmin(req);
    if (typeof assessmentObjectives?.list !== 'function') throw new Error('Objective catalog unavailable');
    const value = await assessmentObjectives.list(user);
    if (!exactKeys(value, ['objectives']) || !Array.isArray(value.objectives) || value.objectives.length > 256
      || new Set(value.objectives.map(row => row?.objectiveId)).size !== value.objectives.length) throw new Error('Invalid objective list');
    res.json({ objectives: value.objectives.map(row => projectObjective(row, true)) });
  }));
  router.post('/assessment-objectives', wrap(async (req, res) => {
    const input = body(req, ['objectiveId', 'enabled', 'expectedRevision']);
    if (!objectiveIdValid(input.objectiveId) || typeof input.enabled !== 'boolean' || !revisionValid(input.expectedRevision)) {
      throw Object.assign(new Error('Invalid objective configuration'), { code: 'INVALID_ARGUMENT' });
    }
    const user = await shopAdmin(req);
    if (typeof assessmentObjectives?.set !== 'function') throw new Error('Objective catalog unavailable');
    const result = projectObjective(await assessmentObjectives.set(user, input));
    if (result.objectiveId !== input.objectiveId || result.enabled !== input.enabled) throw new Error('Objective update unconfirmed');
    res.json(result);
  }));
  const verdictValid = value => ['pass', 'fail', 'inconclusive', 'unavailable'].includes(value);
  const dispositionValid = value => ['not_pass', 'awarded', 'already_complete', 'stale_generation',
    'mode_changed', 'hidden', 'grading_unqualified'].includes(value);
  const isoValid = value => typeof value === 'string' && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value;
  router.get('/assessments', wrap(async (req, res) => {
    if (Object.keys(req.query).length) throw Object.assign(new Error('Invalid query'), { code: 'INVALID_ARGUMENT' });
    const { user } = await authenticated(req);
    if (typeof assessmentRecovery?.list !== 'function') throw new Error('Assessment recovery unavailable');
    const value = await assessmentRecovery.list(user);
    if (!exactKeys(value, ['judgments']) || !Array.isArray(value.judgments) || value.judgments.length > 20
      || new Set(value.judgments.map(row => row?.evaluationId)).size !== value.judgments.length
      || value.judgments.some(row => !exactKeys(row, ['evaluationId', 'objectiveId', 'verdict', 'disposition',
        'createdAt', 'evaluatedAt', 'canRetry', 'childEvaluationId']) || !UUID.test(row.evaluationId)
        || !objectiveIdValid(row.objectiveId) || !(row.verdict === null || verdictValid(row.verdict))
        || !(row.disposition === null || dispositionValid(row.disposition)) || !isoValid(row.createdAt)
        || !(row.evaluatedAt === null || isoValid(row.evaluatedAt)) || typeof row.canRetry !== 'boolean'
        || !(row.childEvaluationId === null || UUID.test(row.childEvaluationId)))) throw new Error('Invalid recovery projection');
    res.json(value);
  }));
  router.post('/assessments/retry', limit, wrap(async (req, res) => {
    const input = body(req, ['evaluationId']);
    if (typeof input.evaluationId !== 'string' || !UUID.test(input.evaluationId)) {
      throw Object.assign(new Error('Invalid evaluation identifier'), { code: 'INVALID_ARGUMENT' });
    }
    const { user } = await authenticated(req);
    if (typeof assessmentRecovery?.retry !== 'function') throw new Error('Assessment recovery unavailable');
    const evaluationId = input.evaluationId.toLowerCase();
    const result = await assessmentRecovery.retry(user, { evaluationId });
    if (!exactKeys(result, ['evaluationId', 'childEvaluationId', 'verdict', 'disposition', 'completed', 'replayed'])
      || result.evaluationId !== evaluationId || !UUID.test(result.childEvaluationId)
      || !verdictValid(result.verdict) || !dispositionValid(result.disposition)
      || typeof result.completed !== 'boolean' || typeof result.replayed !== 'boolean'
      || (result.completed && result.verdict !== 'pass')
      || result.completed !== ['awarded', 'already_complete'].includes(result.disposition)) throw new Error('Invalid recovery result');
    res.json(result);
  }));
  router.post('/cart-import', wrap(async (req, res) => {
    const input = body(req, ['requestId', 'items']);
    if (!UUID.test(input.requestId) || !Array.isArray(input.items) || !input.items.length || input.items.length > 50
      || input.items.some(item => !exactKeys(item, ['productId', 'quantity'])
        || !Number.isSafeInteger(item.productId) || item.productId < 1 || item.productId > 2147483647
        || !Number.isSafeInteger(item.quantity) || item.quantity < 1 || item.quantity > 99)
      || new Set(input.items.map(item => item.productId)).size !== input.items.length) {
      throw Object.assign(new Error('Invalid cart import'), { code: 'INVALID_ARGUMENT' });
    }
    const { user } = await authenticated(req);
    if (typeof cartImport !== 'function') throw new Error('Cart import unavailable');
    const canonical = { ...input, requestId: input.requestId.toLowerCase() };
    res.json(projectCartImport(await cartImport(user, canonical), canonical.requestId));
  }));
  router.post('/bootstrap', wrap(async (req, res) => {
    body(req, []);
    const { user } = await authenticated(req);
    res.json(projectBootstrap(await bootstrap(user)));
  }));
  const resetScene = value => exactKeys(value, ['id', 'label']) && UUID.test(value.id)
    && typeof value.label === 'string' && value.label.length > 0
    && Buffer.byteLength(value.label, 'utf8') <= 256;
  router.get('/reset-readiness', wrap(async (req, res) => {
    if (Object.keys(req.query).length) throw Object.assign(new Error('Invalid query'), { code: 'INVALID_ARGUMENT' });
    const user = await shopAdmin(req);
    if (typeof reset?.readiness !== 'function') throw Object.assign(new Error('Reset unavailable'), { code: 'SHOP_RESET_UNAVAILABLE' });
    const value = await reset.readiness(user);
    if (!exactKeys(value, ['available', 'scope', 'launchId', 'generation', 'scene'])
      || typeof value.available !== 'boolean' || value.scope !== 'shared_practice'
      || !UUID.test(value.launchId) || !Number.isSafeInteger(value.generation) || value.generation < 1
      || !resetScene(value.scene)) throw new Error('Invalid shop reset readiness');
    res.json(value);
  }));
  router.post('/reset', limit, wrap(async (req, res) => {
    const input = body(req, ['launchId', 'expectedGeneration', 'idempotencyKey', 'sceneId', 'confirmation']);
    if (!UUID.test(input.launchId) || !UUID.test(input.idempotencyKey) || !UUID.test(input.sceneId)
      || !Number.isSafeInteger(input.expectedGeneration) || input.expectedGeneration < 1
      || input.confirmation !== 'RESET_SHARED_PRACTICE') {
      throw Object.assign(new Error('Invalid reset request'), { code: 'INVALID_ARGUMENT' });
    }
    const user = await shopAdmin(req);
    if (typeof reset?.reset !== 'function') throw Object.assign(new Error('Reset unavailable'), { code: 'SHOP_RESET_UNAVAILABLE' });
    const canonical = Object.freeze({ launchId: input.launchId.toLowerCase(),
      expectedGeneration: input.expectedGeneration, idempotencyKey: input.idempotencyKey.toLowerCase(),
      sceneId: input.sceneId.toLowerCase(), confirmation: input.confirmation });
    const value = await reset.reset(user, canonical);
    if (!exactKeys(value, ['resetId', 'status', 'cleanupComplete']) || !UUID.test(value.resetId)
      || value.status !== 'committed' || value.cleanupComplete !== true) throw new Error('Invalid shop reset result');
    res.json(value);
  }));
  router.get('/reset-recovery', wrap(async (req, res) => {
    if (Object.keys(req.query).length) throw Object.assign(new Error('Invalid query'), { code: 'INVALID_ARGUMENT' });
    const user = await shopAdmin(req);
    if (typeof reset?.readRecovery !== 'function') throw Object.assign(new Error('Reset recovery unavailable'), { code: 'SHOP_RESET_UNAVAILABLE' });
    const value = await reset.readRecovery(user);
    const pending = value?.pending;
    if (!exactKeys(value, ['pending']) || !(pending === null || (
      exactKeys(pending, ['resetId', 'launchId', 'fromGeneration', 'toGeneration',
        'status', 'scene', 'cleanupComplete', 'sameExecution'])
      && UUID.test(pending.resetId) && UUID.test(pending.launchId)
      && Number.isSafeInteger(pending.fromGeneration) && pending.fromGeneration > 0
      && pending.toGeneration === pending.fromGeneration + 1
      && ['fenced', 'committed', 'aborted'].includes(pending.status)
      && resetScene(pending.scene) && typeof pending.cleanupComplete === 'boolean'
      && typeof pending.sameExecution === 'boolean'))) throw new Error('Invalid reset recovery status');
    res.json(value);
  }));
  router.post('/reset-recovery', limit, wrap(async (req, res) => {
    const input = body(req, ['resetId']);
    if (!UUID.test(input.resetId)) throw Object.assign(new Error('Invalid reset recovery'), { code: 'INVALID_ARGUMENT' });
    const user = await shopAdmin(req);
    if (typeof reset?.recover !== 'function') throw Object.assign(new Error('Reset recovery unavailable'), { code: 'SHOP_RESET_UNAVAILABLE' });
    const value = await reset.recover(user, Object.freeze({ resetId: input.resetId.toLowerCase() }));
    if (!exactKeys(value, ['resetId', 'status', 'cleanupComplete', 'activated'])
      || value.resetId !== input.resetId.toLowerCase()
      || !['fenced', 'committed', 'aborted'].includes(value.status)
      || value.cleanupComplete !== true || typeof value.activated !== 'boolean'
      || (value.activated && value.status !== 'committed')) throw new Error('Invalid reset recovery result');
    res.json(value);
  }));
  require('./secureshopRegisteredAdminReset').installRegisteredAdminResetRoutes(router, {
    service: registeredAdminReset, authenticated, body, wrap, limit,
  });
  return router;
}

module.exports = { createSecureShopStandaloneAuthRouter, readShopCookie, projectBootstrap };
