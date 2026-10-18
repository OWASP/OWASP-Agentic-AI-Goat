'use strict';
// Test infrastructure only. Configuration is embedded by the owned caller, never
// discovered from ambient environment or a target URL supplied by the learner.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');
const { AsyncLocalStorage } = require('node:async_hooks');
const { isDeepStrictEqual } = require('node:util');
const { isMainThread, workerData, getEnvironmentData, setEnvironmentData } = require('node:worker_threads');
const { validateNetworkConfiguration, allowedDatabaseConnect } = require('./fullBackendBootControls');
const { createSecureShopEndpointCapabilities } = require('./secureShopEndpointCapabilities');
const { createEndpointIpcReceiver } = require('./secureShopEndpointIpc');
const { createSecureShopAgentHostIpcSpawn } = require('./secureShopAgentHostIpcSpawn');
const { createSecureShopEndpointBridge } = require('./secureShopEndpointBridge');
const { createObservedTargetFactory } = require('./secureShopPostBindObserver');
const { installStaticDynamicSocketGuard } = require('./secureShopStaticDynamicSocketGuard');

const QUALIFICATION_PRELOAD_KEY = 'dvaia.secureshop.review-renderer-worker-token';
const MAX_BROWSER_LIFECYCLE_RECORDS = 64;
const SAFE_ERROR_NAMES = new Set(['Error', 'TypeError', 'RangeError', 'AbortError']);
const SAFE_ERROR_CODES = new Set(['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE',
  'OWNER_MISMATCH', 'CONVERSATION_UNAVAILABLE', 'REVIEW_NOT_FOUND', 'TURN_REQUEST_CONFLICT',
  'TURN_CAPACITY', 'TURN_RECOVERY_REQUIRED', 'INVALID_ARGUMENT',
  'SECURESHOP_REVIEW_RENDERER_UNAVAILABLE', 'GRADE_STORE_NOT_READY', 'EXECUTION_REQUIRED',
  'ATTEMPT_SCOPE_MISMATCH', 'STALE_GENERATION', 'CANCELLED']);

function installRendererWorkerGuard(config) {
  if (isMainThread) return false;
  const expected = getEnvironmentData(QUALIFICATION_PRELOAD_KEY);
  const marker = workerData?.qualificationPreload;
  if (process.cwd() !== config.sourceRoot
      || !workerData || Object.getPrototypeOf(workerData) !== Object.prototype
      || Object.keys(workerData).sort().join(',') !== 'qualificationPreload,review'
      || !marker || Object.getPrototypeOf(marker) !== Object.prototype
      || Object.keys(marker).sort().join(',') !== 'purpose,token,version'
      || marker.version !== 1 || marker.purpose !== 'secureshop_review_renderer'
      || typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)
      || marker.token !== expected) throw Error('SecureShop preload renderer worker admission');
  // Review rendering needs no network. Apply the same socket interception used
  // by the parent qualification, with an empty capability set, and replace
  // fetch with an unconditional denial before any artifact bytes execute.
  installStaticDynamicSocketGuard({ staticAllows: () => false, permits: () => false,
    trackSocket: () => { throw Error('QUALIFICATION_ENDPOINT_BLOCKED'); } });
  global.fetch = async () => { throw Error('QUALIFICATION_PROVIDER_BLOCKED'); };
  return true;
}

function browserLifecycleCategory(event) {
  if (event.type === 'assessment_start') return 'started';
  if (event.type === 'transport_abort') return 'transport_abort';
  if (event.type !== 'assessment_settled') return null;
  if (event.outcome === 'fulfilled') return 'fulfilled';
  const code = event.errorCode;
  if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE'].includes(code)) return 'launch_authority';
  if (code === 'REVIEW_NOT_FOUND') return 'review_unavailable';
  if (['TURN_REQUEST_CONFLICT', 'TURN_CAPACITY', 'TURN_RECOVERY_REQUIRED'].includes(code)) return 'turn_admission';
  if (code === 'INVALID_ARGUMENT') return 'invalid_argument';
  if (code === 'SECURESHOP_REVIEW_RENDERER_UNAVAILABLE') return 'renderer_unavailable';
  if (code === 'GRADE_STORE_NOT_READY') return 'grade_store_unavailable';
  if (['EXECUTION_REQUIRED', 'ATTEMPT_SCOPE_MISMATCH', 'STALE_GENERATION'].includes(code)) return 'execution_boundary';
  if (event.errorName === 'AbortError' || code === 'CANCELLED') return 'cancelled';
  return 'unclassified_internal';
}

function installBrowserLifecycleCapture(config) {
  const target = path.join(config.sourceRoot, 'server/routes/secureshop/boundBrowser.js');
  if (require.cache[target]) throw Error('SecureShop browser route imported before diagnostic capture');
  const output = path.join(config.fixtureRoot, '.browser-lifecycle.ndjson');
  const descriptor = fs.openSync(output, 'wx', 0o600);
  process.once('exit', () => { try { fs.closeSync(descriptor); } catch {} });
  let sequence = 0;
  const observe = raw => {
    if (sequence >= MAX_BROWSER_LIFECYCLE_RECORDS || !raw || typeof raw !== 'object') return;
    const category = browserLifecycleCategory(raw);
    if (!category) return;
    const event = { version: 1, sequence: sequence++, type: raw.type, category };
    if (raw.type === 'assessment_settled') {
      event.outcome = raw.outcome === 'fulfilled' ? 'fulfilled' : 'rejected';
      event.errorName = SAFE_ERROR_NAMES.has(raw.errorName) ? raw.errorName : null;
      event.errorCode = SAFE_ERROR_CODES.has(raw.errorCode) ? raw.errorCode : null;
    } else if (raw.type === 'transport_abort') {
      event.source = ['request_aborted', 'response_close'].includes(raw.source) ? raw.source : 'unknown';
      event.headersSent = raw.headersSent === true;
      event.writableEnded = raw.writableEnded === true;
    }
    fs.writeSync(descriptor, JSON.stringify(event) + '\n');
    fs.fsyncSync(descriptor);
  };
  const originalLoad = Module._load;
  Module._load = function qualificationDiagnosticLoad(request, parent, isMain) {
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (resolved !== target) return originalLoad.apply(this, arguments);
    Module._load = originalLoad;
    const exported = originalLoad.apply(this, arguments);
    if (!exported || typeof exported.createBoundBrowserRouter !== 'function') {
      throw Error('SecureShop browser diagnostic route contract');
    }
    const originalFactory = exported.createBoundBrowserRouter;
    const wrappedFactory = options => {
      const existing = options?.observeLifecycle;
      return originalFactory({ ...options, observeLifecycle(event) {
        observe(event);
        if (typeof existing === 'function') existing(event);
      } });
    };
    const wrapped = { ...exported, createBoundBrowserRouter: wrappedFactory };
    require.cache[target].exports = wrapped;
    return wrapped;
  };
  return Object.freeze({ output });
}

function validate(config) {
  if (!config || Object.keys(config).sort().join(',') !== 'assessmentBrowserEndpoint,database,fixtureRoot,network,sourceRoot,version'
      || config.version !== 1) throw Error('SecureShop preload configuration');
  for (const key of ['sourceRoot', 'fixtureRoot']) {
    const value = config[key];
    if (typeof value !== 'string' || !path.isAbsolute(value) || fs.realpathSync(value) !== value
        || !fs.statSync(value).isDirectory() || fs.statSync(value).uid !== process.getuid()) throw Error('SecureShop preload root');
  }
  if (fs.statSync(config.sourceRoot).mode & 0o222) throw Error('SecureShop preload source writable');
  if ((fs.statSync(config.fixtureRoot).mode & 0o777) !== 0o700
      || config.fixtureRoot.startsWith(config.sourceRoot + '/') || config.sourceRoot.startsWith(config.fixtureRoot + '/')
      || config.fixtureRoot === config.sourceRoot) throw Error('SecureShop preload fixture isolation');
  const policy = validateNetworkConfiguration(config.database, config.network);
  if (policy.services.filter(s => s.name === 'agent_host').length !== 1) throw Error('SecureShop preload agent endpoint');
  let browser;
  try { browser = new URL(config.assessmentBrowserEndpoint); } catch { throw Error('SecureShop assessment browser endpoint'); }
  if (typeof config.assessmentBrowserEndpoint !== 'string'
      || browser.href !== config.assessmentBrowserEndpoint
      || browser.protocol !== 'ws:' || browser.hostname !== '127.0.0.1'
      || !/^(?:[1-9][0-9]*)$/.test(browser.port)
      || Number(browser.port) < 1024 || Number(browser.port) > 65535
      || browser.username || browser.password || browser.search || browser.hash
      || !/^\/devtools\/browser\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(browser.pathname)) {
    throw Error('SecureShop assessment browser endpoint');
  }
  if ([policy.database, ...policy.services].some(endpoint => Number(endpoint.port) === Number(browser.port))) {
    throw Error('SecureShop assessment browser endpoint collision');
  }
  return Object.freeze({ policy, assessmentBrowser: Object.freeze({
    endpoint: browser.href, host: browser.hostname, port: Number(browser.port),
  }) });
}

function secureShopPreloadSource(config) {
  validate(config);
  const helper = path.join(config.sourceRoot, 'tests/fixtures/secureShopQualificationPreload.js');
  if (fs.realpathSync(helper) !== helper || !fs.statSync(helper).isFile() || (fs.statSync(helper).mode & 0o222)) throw Error('SecureShop frozen preload helper');
  return `'use strict';require(${JSON.stringify(helper)}).initialize(${JSON.stringify(config)});\n`;
}

function initialize(input) {
  const config = structuredClone(input), validated = validate(config), policy = validated.policy;
  if (installRendererWorkerGuard(config)) return;
  const entry = path.resolve(process.argv[1] || '');
  const parent = entry === path.join(config.sourceRoot, 'server/index.js');
  const child = entry === path.join(config.sourceRoot, 'agent-host/index.js');
  if ((!parent && !child) || process.cwd() !== config.sourceRoot
      || fs.realpathSync(entry) !== entry) throw Error('SecureShop preload entry');
  const marker = Symbol.for('dvaia.secureshop.qualification.preload');
  const hooks = ['server/services/secureshop/agentHostSupervisor.js', 'server/services/secureshopSsrfTargetPool.js',
    'server/services/xssBrowserQualification.js', 'server/routes/secureshop/boundBrowser.js'];
  if (globalThis[marker] || hooks.some(file => require.cache[path.join(config.sourceRoot, file)])) throw Error('SecureShop preload already initialized or imported');
  globalThis[marker] = true;
  if (parent) setEnvironmentData(QUALIFICATION_PRELOAD_KEY, crypto.randomBytes(32).toString('hex'));
  const agentPort = policy.services.find(s => s.name === 'agent_host').port;
  if (child && (typeof process.send !== 'function' || !process.connected
      || process.env.SS_AGENT_HOST_PORT !== String(agentPort)
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(process.env.SS_AGENT_HOST_INSTANCE_ID || ''))) throw Error('SecureShop preload child admission');
  const reservedPorts = [policy.database, ...policy.services].map(e => e.port);
  const registries = new Set();
  const permits = (host, port) => [...registries].some(r => r.permits(host, port));
  const trackSocket = (host, port, socket) => {
    const registry = [...registries].find(r => r.permits(host, port));
    if (!registry) throw Error('SecureShop dynamic endpoint unavailable');
    return registry.trackSocket(host, port, socket);
  };
  function registry() { const value = createSecureShopEndpointCapabilities({ reservedPorts }); registries.add(value); return value; }
  if (child) {
    const value = registry();
    createEndpointIpcReceiver(process, { grant: value.grant, apply: value.apply, revokeAll: value.close });
  }
  // Capture the original once: no earlier static Socket.connect wrapper is run.
  installStaticDynamicSocketGuard({ staticAllows: args => [policy.database, ...policy.services,
    ...(parent ? [validated.assessmentBrowser] : [])].some(e => allowedDatabaseConnect(args, e)), permits, trackSocket });
  const originalFetch = global.fetch;
  global.fetch = async (value, options = {}) => {
    if (!options || typeof options !== 'object' || 'dispatcher' in options
        || !(typeof value === 'string' || value instanceof URL || value instanceof Request)) throw Error('QUALIFICATION_PROVIDER_BLOCKED');
    const raw = typeof value === 'string' ? value : value instanceof URL ? value.href : value.url;
    const url = new URL(raw);
    if (!raw.startsWith(`http://127.0.0.1:${url.port}/`) || url.username || url.password || url.hash
        || !policy.services.some(e => url.hostname === e.host && Number(url.port) === e.port)) throw Error('QUALIFICATION_PROVIDER_BLOCKED');
    return originalFetch(value, { ...options, redirect: 'error' });
  };
  if (child) return;

  installBrowserLifecycleCapture(config);

  const records = new Map(), context = new AsyncLocalStorage();
  let currentChild;
  const adapter = createSecureShopAgentHostIpcSpawn({ sourceRoot: config.sourceRoot,
    spawnProcess(...args) { const value = require('node:child_process').spawn(...args); currentChild = value; return value; },
    revokeChild(value) {
      const errors = [];
      for (const record of records.values()) if (record.child === value) {
        record.retired = true;
        try { record.registry.close(); } catch (error) { errors.push(error); }
      }
      if (errors.length) throw new AggregateError(errors, 'SecureShop child revocation failed');
    } });
  // Populate and replace only the two exact export objects before normal imports.
  const supervisorPath = path.join(config.sourceRoot, 'server/services/secureshop/agentHostSupervisor.js');
  const supervisorExports = require(supervisorPath);
  const Supervisor = supervisorExports.AgentHostSupervisor;
  class ObservedSupervisor extends Supervisor {
    constructor(options = {}) {
      if ('spawnProcess' in options || (options.port !== undefined && options.port !== agentPort)) throw Error('SecureShop supervisor override');
      super({ ...options, port: agentPort, spawnProcess: adapter.spawn });
    }
  }
  require.cache[supervisorPath].exports = { ...supervisorExports, AgentHostSupervisor: ObservedSupervisor };
  const poolPath = path.join(config.sourceRoot, 'server/services/secureshopSsrfTargetPool.js');
  const poolExports = require(poolPath);
  const originalFactory = require(path.join(config.sourceRoot, 'server/services/secureshopSsrfOwnedTarget.js')).createSecureShopSsrfOwnedTarget;
  let poolCreated = false;
  const scopeOf = binding => Object.fromEntries(poolExports.SSRF_SCOPE_KEYS.map(key => [key, binding?.[key]]));
  function createPool(options) {
    if (poolCreated) throw Error('SecureShop single owned pool required');
    if (!options || Object.keys(options).join(',') !== 'root' || options.root !== config.fixtureRoot) throw Error('SecureShop target pool override');
    poolCreated = true;
    const pool = poolExports.createSecureShopSsrfTargetPool({ root: options.root,
      createTarget(args) {
        const record = context.getStore();
        if (!record || record.scope.targetId !== args.targetId) throw Error('SecureShop target context missing');
        return record.factory(args);
      } });
    function existing(binding) {
      const record = records.get(binding.targetId);
      if (record && !isDeepStrictEqual(record.scope, scopeOf(binding))) throw Error('SecureShop target scope mismatch');
      return record;
    }
    return Object.freeze({ ...pool,
      async issue(binding, input) {
        const originalBinding = structuredClone(binding), scope = scopeOf(originalBinding);
        let record = existing(scope);
        if (record) {
          if (record.retired || record.child !== currentChild) throw Error('SecureShop target retired');
          // Check before genuine issue: disconnect must not mint another nonce.
          await record.bridge.flush();
        } else {
          const sender = adapter.senderFor(currentChild), value = registry(), grant = value.grant(scope);
          const bridge = createSecureShopEndpointBridge({ registry: value, grant, sender });
          record = { scope, child: currentChild, registry: value, bridge, retired: false };
          record.factory = createObservedTargetFactory({ createTarget: originalFactory, root: options.root, registry: bridge, grant, scope });
          records.set(scope.targetId, record);
        }
        return context.run(record, () => record.bridge.issue(() => pool.issue(originalBinding, input)));
      },
      async retire(binding) { const record = existing(binding); if (record) record.retired = true; return record ? record.bridge.cleanup(() => pool.retire(binding)) : pool.retire(binding); },
      async retireRecovered(binding) { const record = existing(binding); if (record) record.retired = true; return record ? record.bridge.cleanup(() => pool.retireRecovered(binding)) : pool.retireRecovered(binding); },
      async close() {
        const errors = [];
        for (const record of records.values()) record.retired = true;
        try { await pool.close(); } catch (error) { errors.push(error); }
        const results = await Promise.allSettled([...records.values()].map(r => r.bridge.flush()));
        errors.push(...results.filter(r => r.status === 'rejected').map(r => r.reason));
        if (errors.length) throw new AggregateError(errors, 'SecureShop preload pool cleanup failed');
      } });
  }
  require.cache[poolPath].exports = { ...poolExports, createSecureShopSsrfTargetPool: createPool };

  // The parent-supervised browser is the sole stored-XSS assessment runtime in
  // this qualification. Patch the exact factory before production composition
  // imports it; normal application startup keeps the production default.
  const xssPath = path.join(config.sourceRoot, 'server/services/xssBrowserQualification.js');
  const xssExports = require(xssPath);
  if (!xssExports || typeof xssExports.createXssBrowserQualification !== 'function') {
    throw Error('SecureShop XSS qualification factory contract');
  }
  const originalXssFactory = xssExports.createXssBrowserQualification;
  const connectBrowser = () => require('puppeteer').connect({
    browserWSEndpoint: validated.assessmentBrowser.endpoint, protocolTimeout: 15000,
  });
  const createXssBrowserQualification = (options = {}) => {
    if (!options || Object.getPrototypeOf(options) !== Object.prototype
        || options.puppeteer !== undefined || options.connectBrowser !== undefined) {
      throw Error('SecureShop XSS qualification override');
    }
    return originalXssFactory({ ...options, connectBrowser });
  };
  let singleton;
  const getXssBrowserQualification = () => {
    if (!singleton) singleton = createXssBrowserQualification();
    return singleton;
  };
  require.cache[xssPath].exports = { ...xssExports,
    createXssBrowserQualification, getXssBrowserQualification };
}
module.exports = { secureShopPreloadSource, initialize };
