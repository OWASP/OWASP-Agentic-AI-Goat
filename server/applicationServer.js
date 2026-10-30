'use strict';
// Stateful construction is loaded only after entry owns its shared database lease.
async function startApplicationServer({app,lifecycle,signal,assertHeld}) {
const {closeApplicationOwnedResources,settleApplicationCleanup}=require('./services/applicationLifecycle');
let sessionManager,teachingSessionProduction,authRoutes,server,evidenceMaintenance;
let secureShopReady=Promise.resolve();
let ctfAuthorityRouter=null;
let constructionComplete=false;
const startupTasks=[];
const track=promise=>{startupTasks.push(promise);return promise;};
const initializeTask=work=>Promise.resolve().then(()=>{assertActive();return work();});
const assertActive=()=>{signal.throwIfAborted();assertHeld();if(lifecycle.stopping)throw Error('APPLICATION_STOPPING');};
const checked=async promise=>{const value=await promise;assertActive();return value;};
const loaded=name=>{try{return require.cache[require.resolve(name)]?.exports||{};}catch{return {};}};
lifecycle.register(async () => {
  await settleApplicationCleanup([
    () => sessionManager?.stopCleanupTask(),
    // Rejection means initialization ended; it does not mean work is still
    // running. Wait for every task, then explicitly close its allocated owner.
    () => Promise.allSettled(startupTasks),
    () => authRoutes?.close?.(),
    () => loaded('./routes/csrfWorkshop').closeBrowser?.(),
    () => new Promise(resolve => {
      if (!server?.listening) return resolve();
      server.close(resolve);
      server.closeIdleConnections?.();
    }),
    () => teachingSessionProduction?.close?.(),
    () => loaded('./routes/xssWorkshop').closeBrowser?.(),
    () => loaded('./services/xssMailProvider').close?.(),
    () => evidenceMaintenance?.stop(),
    () => secureShopReady,
    async () => {
      app.locals.secureshopBoundGateway = null;
      app.locals.secureshopBoundLaunchRouter = null;
      app.locals.secureshopBoundReadiness = null;
      app.locals.secureshopStandaloneAuthRouter = null;
      app.locals.secureshopPublicCatalog = null;
      const uploadAssets = app.locals.secureshopUploadAssets;
      app.locals.secureshopUploadAssets = null;
      const shop = app.locals.secureshopV2;
      await settleApplicationCleanup([
        () => uploadAssets?.stop?.(),
        () => closeApplicationOwnedResources({
        closeStudentDeletion: () => loaded('./services/studentDeletionProduction')
          .closeProductionStudentDeletionComposition?.(),
        closeCtfRuntime: () => { ctfAuthorityRouter=null; return loaded('./services/ctfAuthorityProduction').closeProductionCtfAuthority?.(); },
        closeSensitiveInfoReset: () => loaded('./services/sensitiveInfoResetComposition')
          .closeSensitiveInfoResetComposition?.(),
        closeSecureShopBoundReview: () => loaded('./services/secureshopBoundReviewComposition')
          .closeSecureShopBoundReviewComposition?.(),
        closeOwnedAudit: () => loaded('./services/secureshopOwnedAuditProduction').closeOwnedAuditProduction?.(),
        closeSecureShop: () => shop
          ? loaded('./services/secureshop').settleSecureShopCleanup([
            () => shop.pool.close(), () => shop.agentHost.stop(),
          ]) : undefined,
        closeSessionDisclosure: () => loaded('./services/sessionDisclosureLab').closeSessionDisclosureLab?.(),
        closeSecureShopReviewDb: () => loaded('./database/postgres/secureshopReviewDb').closeSecureShopReviewDb?.(),
        closePostgresPools: () => loaded('./database/postgres').closePostgresPools?.(),
        }),
      ]);
    },
    () => { if (!constructionComplete) throw Error('APPLICATION_PARTIAL_IMPORT_UNDRAINED'); },
  ]);
});

assertActive();
// Load private configuration before any internal module captures authentication
// state. Supported application startup rejects missing, short, or public sample
// signing keys before framework, database, or provider initialization.
const proxyTrust = require('./services/applicationProxyTrust').applicationProxyTrust();
require('./middleware/eventGate').assertEventGateConfiguration(process.env);
process.env.OWASP_AI_GOAT_APP_DATA_ROOT = require('../scripts/application-data-root')
  .ensureApplicationDataRoot({ workspace: require('node:path').resolve(__dirname, '..'), environment: process.env });
Object.assign(process.env, require('./services/mcp/ownedManagedConfiguration').loadOwnedManagedConfiguration());
Object.assign(process.env, require('./services/secureshopSystemManagedEnvironment').loadWithQualified());
Object.assign(process.env, require('./services/secureshopPricingManagedConfiguration').environment());
Object.assign(process.env, require('./services/secureshopCouponManagedConfiguration').environment());
Object.assign(process.env, require('./services/secureshopPolicyRendererManagedEnvironment').load({
  root: require('node:path').resolve(__dirname, '..'), home: require('node:os').homedir(), environment: process.env,
}));
const { assertApplicationDatabaseEngine } = require('./services/applicationDatabaseEngine');
assertApplicationDatabaseEngine();
require('./services/platformSigningConfiguration').assertPlatformSigningConfiguration(process.env);
const platformDataLifecyclePolicy = require('./services/platformDataLifecycleActivation');
platformDataLifecyclePolicy.assertPlatformDataLifecycleConfiguration(process.env);
// Keep the prompt-policy feature dependency-free when its flag is absent. A
// present flag is validated before SecureShop branching so a requested feature
// cannot be ignored merely because another bound prerequisite is disabled.
const promptPolicyActivation = Object.prototype.hasOwnProperty.call(process.env, 'SS_BOUND_PROMPT_POLICIES_ENABLED')
  ? require('./services/secureshopPromptPolicyActivation') : null;
promptPolicyActivation?.activationPolicy(process.env);
const systemConfigActivation = Object.prototype.hasOwnProperty.call(process.env, 'SS_BOUND_SYSTEM_CONFIG_ENABLED')
  ? require('./services/secureshopSystemConfigActivation') : null;
systemConfigActivation?.activationPolicy(process.env);
const systemDiagnosticActivation = Object.prototype.hasOwnProperty.call(process.env, 'SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED')
  ? require('./services/secureshopSystemDiagnosticActivation') : null;
systemDiagnosticActivation?.activationPolicy(process.env);
const systemRestartActivation = Object.prototype.hasOwnProperty.call(process.env, 'SS_BOUND_SYSTEM_RESTART_ENABLED')
  ? require('./services/secureshopSystemRestartActivation') : null;
systemRestartActivation?.activationPolicy(process.env);
const pricingActivation = Object.prototype.hasOwnProperty.call(process.env, 'SS_BOUND_PRICING_ENABLED')
  ? require('./services/secureshopPricingActivation') : null;
pricingActivation?.activationPolicy(process.env);
const systemRebuildActivation = Object.prototype.hasOwnProperty.call(process.env, 'SS_BOUND_SYSTEM_REBUILD_ENABLED')
  ? require('./services/secureshopSystemRebuildActivation') : null;
const systemRebuildRequested = systemRebuildActivation?.activationPolicy(process.env).requested === true;

const express = require('express');
const compression = require('compression');
const { createApplicationCors, effectiveSecureShopOrigins } = require('./middleware/applicationCors');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const http = require('http');
const performanceMonitor = require('./middleware/performanceMonitor');
sessionManager = require('./middleware/sessionManager');
const { eventGate, loginHandler } = require('./middleware/eventGate');
const { requestId, httpLogger } = require('./middleware/requestLogger');
const { requestLogUrl } = require('./utils/requestLogUrl');
const logger = require('./utils/logger');
const { requestContextMiddleware } = require('./utils/requestContext');

// Preserve existing nested-query teaching inputs across Express 5.
app.set('query parser', 'extended');
const PORT = process.env.PORT || 8081;

// Platform IP attribution must not trust client-supplied forwarding headers.
app.set('trust proxy', proxyTrust);

// ── Real HTTP access log (used by FinFlow workshop admin_read_logs) ──────────
const fs = require('fs');
const _logsDir = process.env.LOGS_DIR || path.join(__dirname, 'logs');
if (!fs.existsSync(_logsDir)) fs.mkdirSync(_logsDir, { recursive: true });
app.use((req, res, next) => {
  const start = Date.now();
  const requestPath = req.path; // Capture before mounted routers rewrite req.url.
  res.on('finish', () => {
    const entry = `${new Date().toISOString()} "${req.method} ${requestPath} HTTP/1.1" ${res.statusCode} ${Date.now() - start}ms ${req.ip || '-'} "${req.get('user-agent') || '-'}"\n`;
    try { fs.appendFileSync(path.join(_logsDir, 'access.log'), entry); } catch (_) {}
  });
  next();
});
// ── end access log ──────────────────────────────────────────────────────────

// ── Structured logging middleware ────────────────────────────────────────────
app.use(requestId);    // Stamp every request with X-Request-Id UUID
app.use(httpLogger);   // Morgan → Winston (JSON on AWS, pretty in dev)
// ── end structured logging ──────────────────────────────────────────────────

// Gzip all responses (React bundle + API JSON). Biggest single win for page
// load time — the SPA bundle is served uncompressed otherwise.
app.use(compression());

// Choose CORS before any policy can short-circuit preflight. SecureShop's
// and platform allowlists must not inherit headers from the intentional lab
// policy. Platform requests share the existing operator-controlled origin list.
const ssV2AllowedOrigins = effectiveSecureShopOrigins(process.env);
app.use(createApplicationCors({ secureShopOrigins: ssV2AllowedOrigins }));

app.use('/api/workshop/csrf/browser-attempt', require('./middleware/csrfBrowserBody').csrfBrowserBody);
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Durable teaching cookies retain their intentional challenge attributes while
// remaining bound to canonical PostgreSQL platform sessions.
teachingSessionProduction = require('./services/teachingSessionProduction').createTeachingSessionProduction();
app.use(teachingSessionProduction.middleware);

// Performance monitoring middleware (for 100 concurrent users optimization)
app.use(performanceMonitor.trackRequest());

// Session management middleware for role-based access
app.use(sessionManager.middleware());

// Request context (ALS) — provides userId/username/ip to deep service layers
app.use(requestContextMiddleware);

// Event gate — single shared-password barrier for live event protection
// Controlled by EVENT_GATE_ENABLED=true and EVENT_GATE_PASSWORD env vars.
// ECS health-check paths (/api/monitoring/ping|health) are always whitelisted.
app.post('/event-gate/login', loginHandler);
app.use(eventGate);

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/assets/rag_samples', express.static(path.join(__dirname, 'assets', 'rag_samples')));
app.use('/assets/csrf_samples', express.static(path.join(__dirname, 'assets', 'csrf_samples')));

// Required PostgreSQL workshop initialization gates readiness; model services remain optional.
const workshopInitializers = [
  ...(process.env.SESSION_DISCLOSURE_DATABASE_URL
    ? [{ name: 'session_disclosure', promise: initializeTask(() => require('./database/postgres/sessionDisclosureDb').initializeSessionDisclosureDb()) }] : []),
  ...(process.env.SECURESHOP_REVIEW_DATABASE_URL && process.env.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL
    ? [{ name: 'secureshop_review', promise: initializeTask(() => require('./database/postgres/secureshopReviewDb').initializeSecureShopReviewDb()) }] : []),
  { name: 'identity', promise: initializeTask(() => require('./services/postgresIdentityAdapter').initializePostgresIdentity()) },
  { name: 'supply_chain', promise: initializeTask(() => require('./database/supplyChainWorkshopDb').initializeSupplyChainWorkshopDb()) },
  { name: 'finflow', promise: initializeTask(() => require('./database/sensitiveInfoWorkshopDb').initializeFinflowWorkshopDb()) },
  { name: 'ctf', promise: initializeTask(() => require('./database/ctfDb').initializeCtfDb()) },
  { name: 'legacy_challenge', promise: initializeTask(() => require('./database/postgres/legacyChallengeDb').initializeLegacyChallengeDb()) },
  { name: 'sensitive_lookup', promise: initializeTask(() => require('./database/postgres/sensitiveLookupDb').initializeSensitiveLookupDb()) },
  { name: 'excessive_agency', promise: initializeTask(() => require('./database/postgres/excessiveAgencyLabDb').initializeExcessiveAgencyLabDb()) },
  { name: 'aria', promise: initializeTask(() => require('./database/sqlWorkshopDb').initializeSqlWorkshopDb()) },
  { name: 'nova', promise: initializeTask(() => require('./database/nosqlWorkshopDb').initializeNosqlWorkshopDb()) },
  { name: 'xss', promise: initializeTask(() => require('./database/postgres/xssWorkshopDb').initializeXssWorkshopDb()) },
  { name: 'mcp', promise: initializeTask(() => require('./database/mcpWorkshopDb').initializeMcpWorkshopDb()) },
  { name: 'csrf', promise: initializeTask(() => require('./database/csrfWorkshopDb').initializeCsrfWorkshopDb()) },
]
const workshopInitialization = Promise.allSettled(workshopInitializers.map(item => item.promise))
  .then(results => results.map((result, index) => ({ ...result, name: workshopInitializers[index].name })));
track(workshopInitialization);
let workshopRagInitialization;
function initializeWorkshopRagProduction() {
  if (!workshopRagInitialization) workshopRagInitialization = require('./services/workshopRagProduction')
    .getWorkshopRagProduction().initialize().then(runtime => {
      app.locals.workshopRagProduction = runtime;
      return runtime;
    });
  return workshopRagInitialization;
}

// Import routes
authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const { createAdminExercisesRouter } = require('./routes/adminExercises');
const { createAdminEmailConfigurationRouter } = require('./routes/adminEmailConfiguration');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const monitoringRoutes = require('./routes/monitoring');
const ctfRoutes = (req,res,next) => ctfAuthorityRouter
  ? ctfAuthorityRouter(req,res,next)
  : res.status(503).json({error:'CTF temporarily unavailable'});
const { createChangeRevisionsRouter } = require('./routes/changeRevisions');
const { createAgentRunsRouter } = require('./routes/agentRuns');
const { createObjectiveGradingCore, createDeferredObjectiveGrading } = require('./services/objectiveGradingCore');
const objectiveGrading = createDeferredObjectiveGrading();
// Called only by startup after required stores initialize. Bound SecureShop and
// public recovery receive this same core before either gateway or HTTP listen.
let startupGradingCore;
function getStartupObjectiveGradingCore(preparedCore) {
  if (preparedCore !== undefined) {
    const { pool } = require('./services/postgresPlatformStores').getPostgresPlatformStores();
    require('./services/objectiveGradingCore').resolveObjectiveGradingDependencies(preparedCore, { identityPool: pool });
    if (startupGradingCore && startupGradingCore !== preparedCore) throw new Error('Startup grading core is already configured');
  }
  if (!startupGradingCore) {
    const { pool, progress } = require('./services/postgresPlatformStores').getPostgresPlatformStores();
    const core = preparedCore || createObjectiveGradingCore({ identityPool: pool, progress });
    objectiveGrading.install(core);
    startupGradingCore = core;
    app.locals.objectiveGradingCore = core;
  }
  return startupGradingCore;
}
const changeRevisionService = require('./services/changeRevisionService');
const { authenticateToken, requirePermission, requireAdminLevel, hasPermission } = require('./middleware/adminAuth');

const legacyAiProtectedHistory = require('./services/legacyAiProtectedHistoryProduction')
  .createLegacyAiProtectedHistoryProduction();
app.use('/api/ai', legacyAiProtectedHistory.middleware);
app.use('/api/ai', require('./routes/ai'));
app.use('/api/ecommerce', require('./routes/ecommerce'));
// SecureShop v2 mount-point placeholder — populated when secureshopV2.boot() completes.
// Registered synchronously here so it lives BEFORE the 404 handler.
// M7 cutover (2026-07-03): the legacy `./routes/secureshop.js` route has been
// deleted. All /api/secureshop/* traffic is served by the SecureShop v2
// routers below when SS_ENABLE=true.
app.locals.secureshopV2Router = null;
app.locals.secureshopV2MerchantRouter = null;
app.locals.secureshopV2AdminRouter = null;
app.locals.secureshopV2UploadsRouter = null;
app.locals.secureshopV2EmailRouter = null;
app.locals.secureshopV2AuthRouter = null;
app.locals.secureshopBoundGateway = null;
app.locals.secureshopBoundReadiness = null;
app.locals.secureshopStandaloneAuthRouter = null;
app.locals.secureshopPublicCatalog = null;
// Independent shop authority must never fall through to the workshop login or
// the deliberately vulnerable legacy persona routes while boot is pending.
app.use('/api/secureshop/auth', (req, res, next) => {
  const router = app.locals.secureshopStandaloneAuthRouter;
  if (router) return router(req, res, error => {
    if (error) return next(error);
    return res.status(404).json({ error: 'Shop authentication route not found' });
  });
  res.set('Cache-Control', 'no-store');
  return res.status(503).json({ error: 'Shop authentication unavailable' });
});
app.use('/api/secureshop', require('./middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({
  getGateway: () => app.locals.secureshopBoundGateway,
}));
app.use('/api/secureshop/public', require('./routes/secureshop/publicCatalog').createSecureShopPublicCatalogRouter({
  getRepository: () => app.locals.secureshopPublicCatalog,
  isAvailable: async () => process.env.SS_ENABLE === 'true'
    && process.env.PLATFORM_DATABASE_ENGINE === 'postgres'
    && Boolean(app.locals.secureshopPublicCatalog),
}));
app.use('/api/secureshop/v2/auth', (req, res, next) => {
  const r = app.locals.secureshopV2AuthRouter;
  if (r) return r(req, res, next);
  return next();
});
app.use('/api/secureshop', (req, res, next) => {
  const r = app.locals.secureshopV2Router;
  if (r) return r(req, res, next);
  return next();
});
app.use('/api/secureshop', (req, res, next) => {
  const r = app.locals.secureshopV2MerchantRouter;
  if (r) return r(req, res, next);
  return next();
});
app.use('/api/secureshop', (req, res, next) => {
  const r = app.locals.secureshopV2AdminRouter;
  if (r) return r(req, res, next);
  return next();
});
app.use('/api/secureshop', (req, res, next) => {
  const r = app.locals.secureshopV2UploadsRouter;
  if (r) return r(req, res, next);
  return next();
});
app.use('/api/secureshop', (req, res, next) => {
  const r = app.locals.secureshopV2EmailRouter;
  if (r) return r(req, res, next);
  return next();
});
app.use('/api/workshop/sql', require('./routes/sqlWorkshop'));
app.use('/api/workshop/nosql', require('./routes/nosqlWorkshop'));
// Chat admission needs the canonical session identity, not only the optional
// user projection supplied by the global session manager. Public status and
// teaching-content reads retain their existing access contracts.
app.post('/api/workshop/prompt-injection/chat', authenticateToken);
app.post('/api/workshop/prompt-injection/progress/reset', authenticateToken);
app.use('/api/workshop/prompt-injection', require('./routes/promptInjectionWorkshop'));
app.use('/api/workshop/rag-injection', require('./routes/ragInjection'));
app.use('/api/workshop/sensitive-info', require('./routes/sensitiveInfoWorkshop'));
app.use('/api/email-agent', require('./routes/emailAgent'));
app.use('/api/workshop/config', require('./routes/workshopConfig').createWorkshopConfigRouter());
app.use((req, res, next) => app.locals.csrfTeachingSink
  ? app.locals.csrfTeachingSink(req, res, next) : next());
app.use('/api/workshop', require('./routes/workshop'));
app.use('/api/challenges', require('./routes/challenges'));
app.use('/api/sensitive-info', require('./routes/sensitiveInfo'));
app.use('/api/sensitive-info/mysql', require('./routes/mysqlSensitiveInfo'));
app.use('/api/xss-email', require('./routes/xssEmail'));
app.use('/api/workshop/xss', require('./routes/xssWorkshop'));
app.use('/api/workshop/csrf', require('./routes/csrfWorkshop'));
const mcpWorkshopRoutes = require('./routes/mcpWorkshop');
app.use('/api/workshop/mcp', mcpWorkshopRoutes);
app.use('/api/excessive-agency', require('./routes/excessiveAgencyLab'));
app.use('/api/workshop/supply-chain', require('./routes/supplyChainWorkshop'));

// Routes
app.locals.secureshopBoundLaunchRouter = null;
if (process.env.SS_BOUND_REVIEWS_ENABLED === 'true') {
  app.use('/api/auth/secureshop-launch', (req, res, next) => {
    const router = app.locals.secureshopBoundLaunchRouter;
    if (router) return router(req, res, next);
    res.set('Cache-Control', 'no-store');
    return res.status(503).json({ error: 'Bound SecureShop application unavailable' });
  });
} else if (process.env.SS_LAUNCH_PREPARATION_ENABLED === 'true') {
  const adapter = require('./services/postgresIdentityAdapter').getPostgresIdentityAdapter();
  const repository = require('./database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(adapter.pool);
  app.use('/api/auth/secureshop-launch', require('./routes/secureshopPlatformLaunch').createSecureShopLaunchRouter({
    enabled: true, engine: 'postgres', authenticateToken, repository,
    audit: event => adapter.repository.recordAudit(event),
  }));
}
app.use('/api/auth', authRoutes);
app.use('/api/changes', createChangeRevisionsRouter({
  store: changeRevisionService,
  authenticateToken,
  hasPermission,
}));
app.use('/api/admin/secureshop-runtime-readiness',
  require('./routes/secureshopRuntimeReadiness').createRouter({ authenticateToken, requireAdminLevel,
    getReadiness: () => app.locals.secureshopBoundReadiness }));
app.use('/api/admin/exercises', createAdminExercisesRouter());
app.use('/api/admin/email-configuration', createAdminEmailConfigurationRouter());
app.use('/api/agent-runs', createAgentRunsRouter({ authenticateToken,
  listJudgments: objectiveGrading.listJudgments, regrade: objectiveGrading.regrade }));
app.use('/api/admin/agent-runs', createAgentRunsRouter({ authenticateToken, requirePermission, admin: true }));
app.use('/api/admin', adminRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/monitoring', monitoringRoutes);
app.use('/api/ctf', ctfRoutes);
app.use('/api/solutions', require('./routes/solutions'));
app.use('/api/hints', require('./routes/hints'));

// Serve React app when client/build exists (e.g. Docker)
const clientBuild = path.join(__dirname, '../client/build');
if (require('fs').existsSync(path.join(clientBuild, 'index.html'))) {
  // Content-hashed assets under /static/* (main.<hash>.js, chunks, css) never
  // change for a given hash, so cache them for a year, immutable. This makes
  // the lazy route chunks + repeat visits load instantly from the browser
  // cache instead of revalidating on every request. index.html itself is
  // served with no-cache (below) so new deploys are always picked up.
  app.use('/static', express.static(path.join(clientBuild, 'static'), {
    immutable: true,
    maxAge: '1y'
  }));
  app.use(express.static(clientBuild, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('index.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    }
  }));
  app.get(/.*/, (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile('index.html', { root: clientBuild });
  });
}

// 404 handler: log so we can debug "404" from chat (e.g. prompt-injection route not matched)
app.use((req, res) => {
  console.warn('[Server] 404 - no route matched:', req.method, requestLogUrl(req));
  res.status(404).json({
    error: 'Not found',
    method: req.method,
    path: req.originalUrl,
    hint: req.originalUrl.includes('prompt-injection')
      ? 'If this is the chat URL, ensure the backend was restarted and the request is POST /api/workshop/prompt-injection/chat.'
      : undefined
  });
});

// Error handling middleware - Intentionally verbose for educational purposes
app.use((err, req, res, next) => {
  // Write to real error log (used by FinFlow workshop admin_read_logs error)
  try {
    const entry = `[${new Date().toISOString()}] ERROR ${req.method} ${req.path} — ${err.message}\n  Stack: ${(err.stack||'').split('\n').slice(0,3).join(' | ')}\n`;
    fs.appendFileSync(path.join(_logsDir, 'error.log'), entry);
  } catch (_) {}
  logger.error('unhandled_error', {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    status: 500,
    message: err.message,
    stack: err.stack
  });
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack, // Vulnerable: exposing stack trace
    timestamp: new Date().toISOString()
  });
});

// Create HTTP server. Change propagation uses database-backed HTTP polling.
server = http.createServer(app);

secureShopReady = Promise.resolve(process.env.SS_BOUND_REVIEWS_ENABLED === 'true'
  && process.env.SS_ENABLE !== 'true'
  ? { status: 'rejected', reason: new Error('Bound SecureShop requires SS_ENABLE=true') }
  : { status: 'fulfilled' });

const platformDataLifecycle = platformDataLifecyclePolicy.createPlatformDataLifecycleActivation({
  getComposition: () => require('./services/studentDeletionProduction').getProductionStudentDeletionComposition(),
});

// Never accept workshop traffic before required PostgreSQL migrations/seeds finish.
const startup = workshopInitialization.then(async results => {
  assertActive();
  const shopResult = await checked(secureShopReady);
  if (shopResult.status === 'rejected') {
    logger.error('required_secureshop_init_failed', { message: shopResult.reason.message });
    throw new Error('APPLICATION_INITIALIZATION_FAILED');
  }
  const failed = results.filter(result => result.status === 'rejected');
  if (failed.length) {
    logger.error('required_workshop_database_init_failed', { count: failed.length, failures: failed.map(result => ({
      code: result.reason?.code || result.reason?.name || 'INITIALIZATION_FAILED',
      ...(result.reason?.migration ? { migration: result.reason.migration } : {}),
    })) });
    throw new Error('APPLICATION_INITIALIZATION_FAILED');
  }
  assertActive();
  getStartupObjectiveGradingCore();
  assertActive();
  const sensitiveInfoReset = require('./services/sensitiveInfoResetComposition');
  if (sensitiveInfoReset.enabled(process.env)) await checked(sensitiveInfoReset.getSensitiveInfoResetComposition());
  assertActive();
  const teachingSessionRuntime = await checked(teachingSessionProduction.initialize());
  app.locals.csrfTeachingSink = require('./routes/csrfWorkshop').configureTeachingSessions(teachingSessionRuntime);
  assertActive();
  await checked(initializeWorkshopRagProduction());
  assertActive();
  {
    const identity = require('./services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const authority = await checked(require('./services/ctfAuthorityProduction').initializeProductionCtfAuthority({
      identityPool: identity.pool,
      ctfPool: require('./database/postgres/ctfDb').getCtfPool(),
      validateSession: identity.validateSession.bind(identity),
      coordinator: require('./agent-runtime/runCoordinator').createRunCoordinator({family:'CTF'}),
      env: process.env, signal,
    }));
    assertActive();
    ctfAuthorityRouter = authority.router;
  }
  await checked(platformDataLifecycle.initialize({ initializationResults: results }));
  assertActive();
  await checked(legacyAiProtectedHistory.initialize());
  assertActive();
  try {
    await checked(require('./services/mcp/ownedResourceProduction').installMcpOwnedResourceProduction({
      env: process.env, route: mcpWorkshopRoutes,
    }));
  } catch (error) {
    logger.error('mcp_owned_runtime_init_failed', { code: error.code || error.name || 'INITIALIZATION_FAILED' });
    throw new Error('APPLICATION_INITIALIZATION_FAILED');
  }
  assertActive();
  const codeBotActivation = await checked(require('./services/supplyChain/codeBotProduction')
    .getCodeBotProductionActivation().initialize());
  if (codeBotActivation.enabled && !codeBotActivation.ready) {
    logger.warn('codebot_owned_runtime_unavailable', {
      journalReady: codeBotActivation.journalReady,
      runnerReady: codeBotActivation.runnerReady,
    });
  }
  assertActive();
  const evidencePool=require('./services/postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
  const evidenceRepository=require('./database/postgres/objectiveEvidenceRepository').createObjectiveEvidenceRepository(evidencePool);
  evidenceMaintenance=require('./services/objectiveEvidenceMaintenance').startObjectiveEvidenceMaintenance({repository:evidenceRepository,logger});
  assertActive();
  await checked(new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(PORT, () => {
  server.removeListener('error', reject);
  resolve();
  logger.info('server_started', {
    port: PORT,
    nodeEnv: process.env.NODE_ENV || 'development',
    ollamaBaseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
    ollamaModel: process.env.OLLAMA_MODEL || 'llama3.1:8b',
    aiProvider: process.env.AI_PROVIDER || 'ollama'
  });
  console.log(`🚀 OWASP Agentic AI GOAT Server running on port ${PORT}`);
  console.log(`🔄 Database-backed HTTP revision polling active`);
  console.log(`🤖 Ollama integration enabled; capacity depends on configured model and hardware`);
  console.log(`📊 Performance monitoring active`);
  console.log(`⚠️  WARNING: This is a deliberately vulnerable application!`);
  console.log(`📚 Educational use only - DO NOT deploy to production!`);
  console.log(`\n🔧 Setup Instructions:`);
  console.log(`   1. Install Ollama: https://ollama.ai`);
  console.log(`   2. Pull Llama 3 model: ollama pull llama3.1:8b`);
  console.log(`   3. Start Ollama service: ollama serve`);
  console.log(`   4. Monitor performance: http://localhost:${PORT}/api/monitoring/health`);
  console.log(`   5. CTF Interface: http://localhost:${PORT}/ctf`);
});
  }));
});
// Entry owns failure shutdown; consume rejection immediately while construction finishes.
startup.catch(() => {});
track(startup);

// Load RAG embedding model in background (non-blocking)
const ragVectorStore = require('./services/ragVectorStore');
track(ragVectorStore.initWithRetry()
  .then(() => console.log('[RAG] Embedding model loaded and ready'))
  .catch(err => {
    console.error('[RAG] Embedding model failed to load:', err.message);
    console.log('[RAG] RAG initialization exhausted three attempts. Endpoints return 503; check the model cache/network and restart to retry.');
  }));

// MCP-lab real-execution sidecars (non-blocking). Auto-starts the four backends
// via docker compose so the workshop runs GENUINE exploits by default. Skips on
// AWS Fargate (TEAM_ID) and docker-compose full-app, where the sidecars are
// sibling containers already running. When Docker is unavailable the lab tools
// fail honestly rather than faking results — there is no simulation.
{
  const { McpSidecarSupervisor } = require('./services/mcp/mcpSidecarSupervisor');
  const mcpSidecars = new McpSidecarSupervisor();
  app.locals.mcpSidecars = mcpSidecars; // /infra reads describe()
  const sidecarStarting = track(mcpSidecars.start()
    .then(() => console.log('[mcp-sidecars]', mcpSidecars.status, '—', mcpSidecars.reason || ''))
    .catch(err => console.error('[mcp-sidecars] start failed:', err.message)));
  lifecycle.register(async () => { await sidecarStarting; await mcpSidecars.stop(); });
}

// SecureShop standalone core; optional full-panel qualification remains explicit.
if (process.env.SS_ENABLE === 'true') {
  const secureshopV2 = require('./services/secureshop');
  const revokeSecureShopRuntime = error => {
    if (lifecycle.stopping) return;
    app.locals.secureshopBoundGateway = null;
    app.locals.secureshopBoundLaunchRouter = null;
    app.locals.secureshopBoundReadiness = null;
    // Retain the asset owner until the ordered shutdown drain.
    app.locals.secureshopStandaloneAuthRouter = null;
    app.locals.secureshopPublicCatalog = null;
    app.locals.secureshopV2Router = null;
    app.locals.secureshopV2MerchantRouter = null;
    app.locals.secureshopV2AdminRouter = null;
    app.locals.secureshopV2UploadsRouter = null;
    app.locals.secureshopV2EmailRouter = null;
    app.locals.secureshopV2AuthRouter = null;
    console.error('[secureshop-v2] agent-host terminal failure:', error?.code || 'SS_AGENT_HOST_UNAVAILABLE');
    void lifecycle.shutdown(1);
  };
  secureShopReady = secureshopV2.boot({ onAgentHost: host => {
    app.locals.secureshopAgentHost = host;
    host.setTerminalFailureHandler(revokeSecureShopRuntime);
  } })
    .then(async (handles) => {
      app.locals.secureshopV2 = handles;
      assertActive();
      {
        const initialized = await checked(workshopInitialization);
        const unavailableStores = initialized.filter(result => result.status === 'rejected');
        if (unavailableStores.length) {
          console.error('[workshop-init]', unavailableStores.map(result => ({
            store: result.name,
            category: String(result.reason?.message).includes('pool budget exhausted') ? 'POOL_BUDGET_EXHAUSTED' : 'STORE_INITIALIZATION_FAILED',
          })), require('./database/postgres').getPoolBudgetSnapshot());
          throw new Error(`Bound SecureShop requires initialized workshop stores: ${unavailableStores.map(result => result.name).join(', ')}`);
        }
        const adapter = require('./services/postgresIdentityAdapter').getPostgresIdentityAdapter();
        const mcpTrustFeature = require('./services/secureshopMcpTrustActivationPolicy').activationPolicy(process.env).requested;
        const ssrfFeature = require('./services/secureshopSsrfProduction').activationPolicy(process.env).requested;
        // The grading bootstrap owns the retained cleanup composition. Resolve
        // an explicitly requested restart transport before that singleton is
        // created so reset/deletion and mounted restart share one lifecycle.
        const systemRestartClient = systemRestartActivation
          ? await checked(systemRestartActivation.prepareSystemRestartClient({ env: process.env })) : undefined;
        const gradingBootstrap = await checked(require('./services/secureshopStartupGrading').prepareSecureShopStartupGrading({
          mcpTrustFeature, ssrfFeature,
          ...(mcpTrustFeature ? { mcpTrustFixtureRoot: process.env.SS_MCP_TRUST_FIXTURE_ROOT } : {}),
          ...(ssrfFeature ? { ssrfFixtureRoot: process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT } : {}),
          ...(systemRestartClient === undefined ? {} : { systemRestartClient }),
        }));
        getStartupObjectiveGradingCore(gradingBootstrap.gradingCore);
        const promptPolicyRenderer = promptPolicyActivation
          ? await checked(promptPolicyActivation.preparePromptPolicyRenderer({ env: process.env })) : undefined;
        const systemConfigClient = systemConfigActivation
          ? await checked(systemConfigActivation.prepareSystemConfigClient({ env: process.env })) : undefined;
        const pricingHttpClient = pricingActivation ? await checked(pricingActivation.preparePricingClient({env:process.env})) : undefined;
        const listingTemplateClient = await checked(require('./services/secureshopListingTemplateActivation')
          .prepareListingTemplateClient({environment:process.env}));
        const systemDiagnosticClient = systemDiagnosticActivation
          ? await checked(systemDiagnosticActivation.prepareSystemDiagnosticClient({ env: process.env })) : undefined;
        if (systemRebuildRequested) await checked(initializeWorkshopRagProduction());
        const systemRebuildEnabled = systemRebuildActivation
          ? await checked(systemRebuildActivation.prepareSystemRebuild({ env: process.env,
            workshopRagProduction: app.locals.workshopRagProduction })) : false;
        const uploadAssetProduction = require('./services/secureshopUploadAssetProduction');
        const uploadAssetActivation = uploadAssetProduction.activationPolicy(process.env);
        const bound = await checked(require('./services/secureshopBoundApplication').createSecureShopBoundApplication({
          engine: 'postgres', shopEnabled: true,
          fileSummaryFeature: true, filePathSummaryFeature: true,
          applicationMode: process.env.SS_BOUND_REVIEWS_ENABLED === 'true' ? 'full' : 'standalone',
          authenticateToken, audit: event => adapter.repository.recordAudit(event), agentRuntime: handles,
          progress: require('./services/postgresPlatformStores').getPostgresPlatformStores().progress,
          gradingBootstrap,
          ...(promptPolicyRenderer === undefined ? {} : { promptPolicyRenderer }),
          ...(systemConfigClient === undefined ? {} : { systemConfigClient }),
          ...(systemDiagnosticClient === undefined ? {} : { systemDiagnosticClient }),
          ...(systemRestartClient === undefined ? {} : { systemRestartClient }),
          ...(pricingHttpClient === undefined ? {} : { pricingHttpClient }),
          ...(listingTemplateClient === undefined ? {} : { listingTemplateClient }),
          ...(uploadAssetActivation.enabled ? { uploadAssetOrigin: uploadAssetActivation.origin, uploadAssetCapability: uploadAssetActivation.capability } : {}),
          systemRebuildEnabled,
        }));
        const uploadAssets = await checked(uploadAssetProduction.startSecureShopUploadAssetProduction({
          activation: uploadAssetActivation, backend: bound.uploadAssetBackend, lifecycle,
        }));
        if (uploadAssets.enabled && !uploadAssets.isReady()) throw new Error('SecureShop upload asset service is not ready');
        app.locals.secureshopUploadAssets = uploadAssets;
        app.locals.secureshopBoundGateway = bound.gateway;
        if (process.env.SS_BOUND_REVIEWS_ENABLED === 'true') {
          app.locals.secureshopBoundLaunchRouter = bound.launchRouter;
          app.locals.secureshopBoundReadiness = bound.readiness;
        }
        app.locals.secureshopPublicCatalog = bound.publicCatalog || null;
        if (bound.standaloneAuth) {
          app.locals.secureshopStandaloneAuthRouter = require('./routes/secureshopStandaloneAuth')
            .createSecureShopStandaloneAuthRouter({ service: bound.standaloneAuth.service,
              bootstrap: bound.standaloneAuth.bootstrap, cartImport: bound.standaloneAuth.cartImport, mode: bound.standaloneAuth.mode,
              assessmentObjectives: bound.standaloneAuth.assessmentObjectives,
              assessmentRecovery: bound.standaloneAuth.assessmentRecovery,
              assessmentProgress: bound.standaloneAuth.assessmentProgress,
              registeredAdminReset: bound.standaloneAuth.registeredAdminReset,
              externalMail: bound.standaloneAuth.externalMail,
              reset: bound.standaloneAuth.reset, practices: bound.standaloneAuth.practices, allowedOrigins: ssV2AllowedOrigins,
              secureCookies: ssV2AllowedOrigins.every(origin => origin.startsWith('https://')) });
        }
      }
      // Install the customer router into the pre-registered mount point.
      // Because the placeholder was registered before the 404 handler, this
      // is reachable even though the router is populated asynchronously.
      if (handles.customerRouter) {
        app.locals.secureshopV2Router = handles.customerRouter;
      }
      if (handles.merchantRouter) {
        app.locals.secureshopV2MerchantRouter = handles.merchantRouter;
      }
      if (handles.adminRouter) {
        app.locals.secureshopV2AdminRouter = handles.adminRouter;
      }
      if (handles.uploadsRouter) {
        app.locals.secureshopV2UploadsRouter = handles.uploadsRouter;
      }
      if (handles.emailRouter) {
        app.locals.secureshopV2EmailRouter = handles.emailRouter;
      }
      if (handles.authRouter) {
        app.locals.secureshopV2AuthRouter = handles.authRouter;
      }
      console.log('[secureshop-v2] booted; agent-host on port', handles.agentHost.port);
      return { status: 'fulfilled' };
    })
    .catch((e) => {
      console.error('[secureshop-v2] boot failed:', e.message);
      return { status: 'rejected', reason: e };
    });

  track(secureShopReady);
  // Final child-process guard also covers forced exit after the bounded drain.
  const killAgentHostSync = () => {
    const host = app.locals.secureshopAgentHost;
    if (host?.proc) {
      try { host.proc.kill('SIGTERM'); } catch {}
    }
  };
  process.on('exit', killAgentHostSync);
}

constructionComplete=true;
return startup;

}
module.exports={startApplicationServer};
