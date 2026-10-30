'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { StringDecoder } = require('node:string_decoder');
const { assertSupportedApplicationNodeVersion } = require('./application-node-runtime');
const { assertLocalMailpitReady } = require('./local-mailpit');
const exec = promisify(execFile);

const root = path.resolve(__dirname, '..');
const DEFAULT_STARTUP_TIMEOUT_MS = 180_000;
const MAX_READY_LINE_BYTES = 4096;

function publicError(code, message) {
  return Object.assign(new Error(message), { code });
}

function port(value, name) {
  if (!/^\d+$/.test(String(value)) || Number(value) < 1 || Number(value) > 65535) {
    throw publicError('INVALID_STARTUP_PORT', `${name} must be a valid port`);
  }
  return Number(value);
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

async function assertApplicationPortsAvailable(environment = process.env) {
  const uploadAssets = environment.SS_BOUND_UPLOAD_ASSETS_ENABLED === 'true'
    ? require('../server/services/secureshopUploadAssetProduction').activationPolicy(environment) : null;
  const ports = [
    ['backend', port(environment.PORT || 8081, 'PORT'), undefined],
    ['frontend', port(environment.OWASP_AI_GOAT_CLIENT_PORT || 3000, 'OWASP_AI_GOAT_CLIENT_PORT'), undefined],
    ...(environment.SS_ENABLE === 'true'
      ? [['SecureShop agent host', port(environment.SS_AGENT_HOST_PORT || 8082, 'SS_AGENT_HOST_PORT'), undefined]] : []),
    ...(uploadAssets?.enabled
      ? [['SecureShop upload asset', port(uploadAssets.port, 'SS_UPLOAD_ASSET_PORT'), uploadAssets.assetHost]] : []),
  ];
  if (new Set(ports.map(([, value]) => value)).size !== ports.length) {
    throw publicError('APPLICATION_PORT_CONFLICT', 'Application services must use distinct ports.');
  }
  for (const [name, value, host] of ports) {
    await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', error => reject(publicError('APPLICATION_PORT_UNAVAILABLE',
        `${name} port ${value} is unavailable (${error.code || 'listen error'}). Stop the existing application with its owned launcher or configure a free port. No existing process was stopped.`)));
      probe.listen({ port: value, ...(host ? { host, ipv6Only: host === '::1' } : {}), exclusive: true },
        () => probe.close(error => error ? reject(error) : resolve()));
    });
  }
}

function stripAnsi(value) {
  return value.replace(/[\u001B\u009B][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d\/#&.:=?%@~_]+)*)?\u0007)|(?:(?:\d{1,4}(?:[;:]\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g, '');
}

function exactViteReadyLine(line, expectedPort) {
  const normalized = stripAnsi(line).trim();
  const match = /^(?:➜\s*)?Local:\s+http:\/\/(?:localhost|127\.0\.0\.1|\[::1\]):(\d+)\/$/.exec(normalized);
  return Boolean(match && Number(match[1]) === expectedPort);
}

function boundedLineReader(onLine, { maxBytes = MAX_READY_LINE_BYTES } = {}) {
  const decoder = new StringDecoder('utf8');
  let line = '';
  let oversized = false;
  return chunk => {
    const text = decoder.write(chunk);
    for (const character of text) {
      if (character === '\n') {
        if (!oversized) onLine(line.replace(/\r$/, ''));
        line = '';
        oversized = false;
      } else if (!oversized) {
        line += character;
        if (Buffer.byteLength(line, 'utf8') > maxBytes) {
          line = '';
          oversized = true;
        }
      }
    }
  };
}

function childFailure(name, event) {
  if (event.type === 'error') {
    return publicError('APPLICATION_SPAWN_FAILED', `${name} process could not be started`);
  }
  return publicError(
    name === 'backend' ? 'APPLICATION_BACKEND_EXITED' : 'APPLICATION_FRONTEND_EXITED',
    `${name} process exited unexpectedly (${event.code ?? event.signal ?? 'unknown'})`,
  );
}

function observeChild({ name, command, args, options, readiness, spawnProcess = spawn,
  stdout = process.stdout, stderr = process.stderr }) {
  let child;
  try {
    child = spawnProcess(command, args, options);
  } catch {
    throw publicError('APPLICATION_SPAWN_FAILED', `${name} process could not be started`);
  }
  const ready = deferred();
  const outcome = deferred();
  let readySeen = false;
  const markReady = () => {
    if (readySeen) return;
    readySeen = true;
    ready.resolve(true);
  };
  if (child.stdout) {
    const readLine = boundedLineReader(line => {
      if (readiness.type === 'line' && readiness.matches(line)) markReady();
    });
    child.stdout.on('data', chunk => {
      stdout?.write?.(chunk);
      readLine(chunk);
    });
  }
  child.stderr?.on('data', chunk => stderr?.write?.(chunk));
  child.on('message', message => {
    if (message?.type === 'owasp-ai-goat-owned-child-outcome'
        && message.outcome && ['error', 'exit'].includes(message.outcome.type)) {
      outcome.resolve(message.outcome);
      return;
    }
    if (readiness.type === 'ipc') {
      if (message?.type === 'owasp-ai-goat-backend-ready'
          && message.token === readiness.token
          && message.pid === child.pid
          && message.port === readiness.port) markReady();
    }
  });
  child.once('error', error => outcome.resolve({ type: 'error', error }));
  child.once('exit', (code, signal) => outcome.resolve({ type: 'exit', code, signal }));
  return { name, child, ready: ready.promise, outcome: outcome.promise };
}

function waitForReady(observed, blockers, stopRequested, deadline, timers = { setTimeout, clearTimeout }) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) return Promise.reject(publicError('APPLICATION_START_TIMEOUT', 'Application startup timed out'));
  let timer;
  return Promise.race([
    observed.ready,
    stopRequested,
    observed.outcome.then(event => Promise.reject(childFailure(observed.name, event))),
    ...blockers.map(item => item.outcome.then(event => Promise.reject(childFailure(item.name, event)))),
    ...[observed, ...blockers].filter(item => item.job).map(item => item.job.failure),
    new Promise((_, reject) => {
      timer = timers.setTimeout(() => reject(publicError('APPLICATION_START_TIMEOUT', 'Application startup timed out')), remaining);
    }),
  ]).finally(() => timers.clearTimeout(timer));
}

function groupAlive(pgid, kill = process.kill.bind(process)) {
  try { kill(-pgid, 0); return true; }
  catch (error) { return error.code !== 'ESRCH'; }
}

async function waitUntilAbsent(check, { timeoutMs, pollMs }) {
  const deadline = Date.now() + timeoutMs;
  while (check() && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, pollMs));
  }
  return !check();
}

async function waitForChildOutcome(observed, timeoutMs = 5000) {
  let timer;
  try {
    await Promise.race([
      observed.outcome,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(publicError('OWNED_GUARDIAN_REMAINS',
          'Unadmitted Windows guardian did not exit')), timeoutMs);
      }),
    ]);
  } finally { clearTimeout(timer); }
}

async function stopOwnedChild(observed, { platform = process.platform, kill = process.kill.bind(process),
  graceMs = 5000, pollMs = 25, commandTimeoutMs = 5000 } = {}) {
  if (platform === 'win32') {
    if (!observed?.job || typeof observed.job.stop !== 'function' || typeof observed.job.close !== 'function') {
      throw publicError('OWNED_JOB_UNAVAILABLE', 'Owned Windows Job Object authority is unavailable');
    }
    await observed.admission;
    await observed.job.stop({ graceMs, drainTimeoutMs: commandTimeoutMs });
    await observed.job.close();
    return;
  }
  const pid = observed?.child?.pid;
  if (!pid) return;
  try { kill(-pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  if (await waitUntilAbsent(() => groupAlive(pid, kill), { timeoutMs: graceMs, pollMs })) return;
  try { kill(-pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  if (!await waitUntilAbsent(() => groupAlive(pid, kill), { timeoutMs: Math.min(graceMs, 1000), pollMs })) {
    throw publicError('OWNED_PROCESS_GROUP_REMAINS', `Owned process group ${pid} remains after SIGKILL`);
  }
}

function createApplicationSupervisor({ workspace = root, environment = process.env,
  spawnProcess = spawn, startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS,
  backendCommand, backendArgs, frontendCommand, frontendArgs,
  stdout = process.stdout, stderr = process.stderr, platform = process.platform,
  stopChild = stopOwnedChild,
  admitNpm = require('./lib/setup-npm-admission').admitSetupNpm, executeNpm = exec,
  createJob = require('./lib/windows-owned-process').createWindowsOwnedProcess } = {}) {
  if (!Number.isInteger(startupTimeoutMs) || startupTimeoutMs < 1) {
    throw new TypeError('startupTimeoutMs must be a positive integer');
  }
  const backendPort = port(environment.PORT || 8081, 'PORT');
  const clientPort = port(environment.OWASP_AI_GOAT_CLIENT_PORT || 3000, 'OWASP_AI_GOAT_CLIENT_PORT');
  const token = crypto.randomBytes(32).toString('base64url');
  const children = [];
  const stopRequested = deferred();
  const stopped = deferred();
  let stopping = false;
  let started = false;
  let stopPromise;
  let pendingLaunch;

  function launchSpec(command, args, { ipc = false, shell = false } = {}) {
    if (platform !== 'win32') return { command, args, shell };
    return {
      command: process.execPath,
      args: [path.join(workspace, 'scripts/owned-child-guardian.js'), command,
        JSON.stringify(args), ipc ? 'ipc' : 'plain', shell ? 'shell' : 'direct'],
      shell: false,
    };
  }

  async function stop() {
    if (stopPromise) return stopPromise;
    stopping = true;
    stopRequested.resolve({ type: 'stop-requested' });
    stopPromise = (async () => {
      // A stop can arrive while the helper is starting or while the guardian is
      // being admitted. Join that work before deciding which jobs must drain.
      if (pendingLaunch) await pendingLaunch.catch(() => {});
      const results = await Promise.allSettled([...children].reverse().map(child => stopChild(child, { platform })));
        const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
        if (failures.length) throw new AggregateError(failures, 'Owned application process cleanup failed');
    })()
      .finally(() => stopped.resolve({ type: 'stopped' }));
    return stopPromise;
  }

  async function launchChild(spec) {
    if (platform !== 'win32') {
      const observed = observeChild(spec);
      children.push(observed);
      return observed;
    }
    const launch = (async () => {
      const job = await createJob({ platform });
      if (stopping) { await job.close(); return null; }
      let observed;
      try { observed = observeChild(spec); }
      catch (error) {
        try { await job.close(); } catch (cleanupError) { error.cleanupError = cleanupError; }
        throw error;
      }
      observed.job = job;
      children.push(observed);
      observed.admission = job.admitGuardian(observed.child);
      try { await observed.admission; }
      catch (error) {
        // Before admission, the direct ChildProcess handle is the only local
        // authority. The guardian cannot have launched its workload yet.
        try { observed.child.kill?.(); } catch {}
        try {
          await waitForChildOutcome(observed);
          await job.close();
          children.splice(children.indexOf(observed), 1);
        }
        catch (cleanupError) { error.cleanupError = cleanupError; }
        throw error;
      }
      return observed;
    })();
    pendingLaunch = launch;
    try { return await launch; }
    finally { if (pendingLaunch === launch) pendingLaunch = undefined; }
  }

  async function start() {
    if (started) throw new Error('Application supervisor already started');
    started = true;
    if (stopping) return;
    const deadline = Date.now() + startupTimeoutMs;
    try {
      // The Windows bootstrap supplies a private npm CLI without changing
      // PATH. Admit that CLI before any app launch, then run it directly with
      // this Node executable; cmd.exe quoting is not part of default startup.
      const admittedNpm = platform === 'win32' && !frontendCommand
        ? await admitNpm({ environment, execute: executeNpm, node: process.execPath, platform }) : null;
      let frontendEnvironment = environment;
      if (admittedNpm) {
        // npm adds project .bin directories for lifecycle scripts, but does
        // not add the Node directory. Windows Vite shims invoke `node` using
        // PATH. Bind that lookup to the admitted runtime in this child only,
        // with one key so Windows cannot select a different case variant.
        frontendEnvironment = { ...environment };
        const pathKeys = Object.keys(environment).filter(key => key.toLowerCase() === 'path');
        const priorPaths = pathKeys.flatMap(key => String(environment[key] || '').split(';')).filter(Boolean);
        for (const key of pathKeys) delete frontendEnvironment[key];
        frontendEnvironment.Path = [path.win32.dirname(admittedNpm.command), ...priorPaths].join(';');
      }
      if (stopping) return;
      if (Date.now() >= deadline) throw publicError('APPLICATION_START_TIMEOUT', 'Application startup deadline expired');
      const backendLaunch = launchSpec(backendCommand || process.execPath,
        backendArgs || ['--require', path.join(workspace, 'scripts/backend-readiness-ipc.js'), 'server/index.js'],
        { ipc: true });
      const backend = await launchChild({
        name: 'backend',
        command: backendLaunch.command,
        args: backendLaunch.args,
        options: {
          cwd: workspace,
          env: { ...environment, OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN: token },
          stdio: ['inherit', 'inherit', 'inherit', 'ipc'],
          detached: platform !== 'win32',
          shell: backendLaunch.shell,
        },
        readiness: { type: 'ipc', token, port: backendPort },
        spawnProcess, stdout, stderr,
      });
      if (!backend || stopping) return;
      await waitForReady(backend, [], stopRequested.promise, deadline);
      if (stopping) return;

      const npmArguments = frontendArgs || ['--prefix', 'client', 'start', '--', '--port', String(clientPort), '--strictPort'];
      const frontendLaunch = launchSpec(frontendCommand || admittedNpm?.command || 'npm',
        admittedNpm ? [...admittedNpm.prefix, ...npmArguments] : npmArguments,
        { shell: platform === 'win32' && !!frontendCommand });
      const frontend = await launchChild({
        name: 'frontend',
        command: frontendLaunch.command,
        args: frontendLaunch.args,
        options: {
          cwd: workspace,
          env: frontendEnvironment,
          stdio: platform === 'win32'
            ? ['inherit', 'pipe', 'pipe', 'ipc']
            : ['inherit', 'pipe', 'pipe'],
          detached: platform !== 'win32',
          shell: frontendLaunch.shell,
        },
        readiness: { type: 'line', matches: line => exactViteReadyLine(line, clientPort) },
        spawnProcess, stdout, stderr,
      });
      if (!frontend || stopping) return;
      await waitForReady(frontend, [backend], stopRequested.promise, deadline);
    } catch (error) {
      try { await stop(); } catch (cleanupError) { error.cleanupError = cleanupError; }
      throw error;
    }
  }

  async function wait() {
    if (!started) throw new Error('Application supervisor has not started');
    if (stopping) return stopped.promise;
    let event;
    try {
      event = await Promise.race([
        stopped.promise,
        ...children.map(child => child.outcome.then(outcome => ({ child, outcome }))),
        ...children.filter(child => child.job).map(child => child.job.failure),
      ]);
    } catch (failure) {
      try { await stop(); } catch (cleanupError) { failure.cleanupError = cleanupError; }
      throw failure;
    }
    if (event.type === 'stopped' || stopping) return;
    const failure = childFailure(event.child.name, event.outcome);
    try { await stop(); } catch (cleanupError) { failure.cleanupError = cleanupError; }
    throw failure;
  }

  return { start, wait, stop, get children() { return [...children]; } };
}

async function runControlledApplication({ workspace = root, supervisor,
  createController = require('./launcher-control').createController,
  stateFile, signalSource = process } = {}) {
  let controller;
  let controllerStop = false;
  let controllerCloseOutcome;
  let signalStopError;
  const onSignal = () => {
    void supervisor.stop().catch(error => { signalStopError = error; });
  };
  signalSource.once('SIGTERM', onSignal);
  signalSource.once('SIGINT', onSignal);
  try {
    controller = await createController({
      workspace,
      ...(stateFile ? { stateFile } : {}),
      stop: async () => {
        controllerStop = true;
        await supervisor.stop();
        // Let launcher-control finish the authenticated HTTP response before
        // closing the server that owns that response. A failed drain retains
        // its controller state for inspection instead of claiming shutdown.
        controllerCloseOutcome = new Promise(resolve => {
          setImmediate(() => {
            Promise.resolve().then(() => controller.close()).then(
              () => resolve(null),
              error => resolve(error),
            );
          });
        });
      },
    });
  } catch (error) {
    signalSource.removeListener('SIGTERM', onSignal);
    signalSource.removeListener('SIGINT', onSignal);
    try { await supervisor.stop(); }
    catch (cleanupError) { error.cleanupError = cleanupError; }
    throw error;
  }
  let primaryError;
  try {
    await supervisor.start();
    await supervisor.wait();
  } catch (error) { primaryError = error; }
  signalSource.removeListener('SIGTERM', onSignal);
  signalSource.removeListener('SIGINT', onSignal);
  let cleanupError = signalStopError;
  try { await supervisor.stop(); } catch (error) { cleanupError ||= error; }
  if (controllerStop) {
    const closeError = await controllerCloseOutcome;
    cleanupError ||= closeError;
  } else {
    try { await controller.close(); } catch (error) { cleanupError ||= error; }
  }
  if (primaryError) {
    if (cleanupError && !primaryError.cleanupError) primaryError.cleanupError = cleanupError;
    throw primaryError;
  }
  if (cleanupError) throw cleanupError;
}

// The facade owns only retained lab resources; every tunnel remains joined to
// this foreground lifetime, including failures during application readiness.
async function runWindowsStartup({ workspace = root, environment = process.env,
  home = require('node:os').homedir(), startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS,
  prepareLab = require('./lib/windows-lab-installation').prepareWindowsLabInstallation,
  fileSystem = require('node:fs'),
  localPostgres = require('./setup-application').localPostgres,
  baseServices = require('./install/windows-base-lab-services').provisionWindowsBaseLabServices,
  shouldStartBase = require('./setup-application').shouldBindLocalSidecarDocker,
  mailpitReady = assertLocalMailpitReady,
  startAudit = options => require('./install/audit-sql-target').startExisting(options),
  loadMcp = require('../server/services/mcp/ownedManagedConfiguration').loadOwnedManagedConfiguration,
  startMcp = options => require('./install/mcp-owned-provision').startExisting(options),
  mcpReady = async config => require('../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({
    baseURL: config.MCP_OWNED_TARGET_URL, token: config.MCP_OWNED_TARGET_TOKEN, timeoutMs: 1000 }).readiness(),
  protectedServices = ['http', 'shadow'].map(kind => ({
    load: options => { const config = require(`../server/services/mcp/owned${kind === 'http' ? 'Http' : 'Shadow'}ManagedConfiguration`);
      return config.load({ file: config.managedPath(options) }); },
    start: options => require(`./install/mcp-owned-${kind}`).startExisting(options),
    ready: config => { const client = require(`../server/services/mcp/owned${kind === 'http' ? 'Http' : 'Shadow'}ServiceClient`);
      return client[kind === 'http' ? 'createOwnedHttpServiceClient' : 'createOwnedShadowServiceClient']({ baseUrl: config.url, token: config.token,
        fetch: (url, options) => globalThis.fetch(url, { ...options, signal: AbortSignal.any([options.signal, AbortSignal.timeout(1000)]) }) }).readiness(); },
  })),
  prepareApplication = async () => {},
  retryDelay = () => new Promise(resolve => setTimeout(resolve, 200)),
  createSupervisor = createApplicationSupervisor, runApplication = runControlledApplication,
} = {}) {
  const id = require('./application-data-root').workspaceId(workspace);
  const directory = path.win32.join(home, '.owasp-ai-goat', id);
  const retained = name => {
    try { fileSystem.lstatSync(path.win32.join(directory, name)); return true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; return false; }
  };
  const postgresRetained = retained('local-postgres.json'), auditRetained = retained('audit-sql-target.json');
  const baseRequested = shouldStartBase(environment);
  const mailpitRequested = environment.IPI_EMAIL_PROVIDER === 'mailpit' && Boolean(environment.MAILPIT_STATE_PATH);
  const mcp = loadMcp({ root: workspace, home });
  const protectedConfigurations = protectedServices.map(service => ({ service, config: service.load({ root: workspace, home }) }));
  if (!postgresRetained && !auditRetained && !baseRequested && !mailpitRequested
      && mcp.MCP_OWNED_RESOURCES_ENABLED !== 'true' && !protectedConfigurations.some(item => item.config?.enabled)) {
    await prepareApplication();
    const supervisor = createSupervisor({ workspace, environment, startupTimeoutMs });
    return runApplication({ workspace, supervisor });
  }
  const lab = await prepareLab({ root: workspace, homeDirectory: home, environment, mode: 'existing' });
  let primary, forwardFailure, supervisor, stopPromise;
  const assertForwards = () => { if (forwardFailure) throw forwardFailure; };
  const requireReady = async probe => {
    for (let attempt = 0; attempt < 10; attempt++) {
      assertForwards();
      let ready = false;
      try { ready = (await probe())?.ready === true; } catch { /* Keep transport diagnostics private. */ }
      assertForwards();
      if (ready) return;
      if (attempt < 9) await retryDelay();
    }
    throw publicError('WINDOWS_LAB_SERVICE_NOT_READY', 'An owned lab service is not ready.');
  };
  const ownLabChild = async request => {
    const owner = await lab.ownLabChild(request);
    if (!owner || typeof owner.stopAndJoin !== 'function' || !owner.failurePromise?.then) {
      throw publicError('WINDOWS_LAB_FORWARD_DENIED', 'Owned lab forwarding was not admitted.');
    }
    owner.failurePromise.catch(() => {
      forwardFailure ||= publicError('WINDOWS_LAB_FORWARD_FAILED', 'An owned lab forwarding process failed.');
      if (supervisor) stopPromise ||= Promise.resolve().then(() => supervisor.stop());
      // Join the stop below, while preventing an unhandled cleanup rejection.
      stopPromise?.catch(() => {});
    });
    return owner;
  };
  const shared = { root: workspace, home, platform: 'win32', environment, commandEnv: environment,
    ownedLabSession: lab.session, ownLabChild };
  try {
    if (postgresRetained) await localPostgres({ ...shared, directory, id, existingOnly: true });
    assertForwards();
    if (baseRequested) await baseServices({ session: lab.session, root: workspace, mode: 'start', ownLabChild });
    assertForwards();
    if (mailpitRequested) {
      await mailpitReady({ ...shared, statePath: environment.MAILPIT_STATE_PATH, execute: exec });
      assertForwards();
    }
    if (mcp.MCP_OWNED_RESOURCES_ENABLED === 'true') {
      await startMcp(shared);
      await lab.session.openLoopbackForwards([{ local: 8092, guest: 8092 }], { ownChild: ownLabChild });
      await requireReady(() => mcpReady(mcp));
      assertForwards();
    }
    for (const { service, config } of protectedConfigurations) {
      if (!config?.enabled) continue;
      try { await service.start(shared); }
      catch { throw publicError('WINDOWS_LAB_SERVICE_START_FAILED', 'A retained owned lab service could not start.'); }
      const local = Number(new URL(config.url).port);
      await lab.session.openLoopbackForwards([{ local, guest: local }], { ownChild: ownLabChild });
      await requireReady(() => service.ready(config));
      assertForwards();
    }
    if (auditRetained) {
      try { await startAudit(shared); }
      catch { throw publicError('WINDOWS_LAB_SERVICE_START_FAILED', 'A retained owned lab service could not start.'); }
      assertForwards();
    }
    await prepareApplication();
    assertForwards();
    supervisor = createSupervisor({ workspace, environment, startupTimeoutMs });
    await runApplication({ workspace, supervisor });
    if (stopPromise) await stopPromise;
    assertForwards();
  } catch (error) { primary = error; }
  finally {
    for (const cleanup of [() => stopPromise, () => lab.close()]) {
      try { await cleanup(); }
      catch (error) { if (primary) primary.cleanupError ||= error; else primary = error; }
    }
  }
  if (primary) throw primary;
}

async function startManagedPolicyRenderer({ workspace = root, home, environment = process.env,
  managedEnvironment = {}, startExisting = options => require('./install/secureshop-owned-policy-renderer').startExisting(options) } = {}) {
  if (managedEnvironment.SS_BOUND_PROMPT_POLICIES_ENABLED !== 'true') return;
  const result = await startExisting({ root: workspace, home, environment });
  if (result?.ready !== true || result.enabled !== true) {
    throw publicError('POLICY_RENDER_START_UNAVAILABLE', 'The enabled managed policy renderer is not ready.');
  }
}

async function startManagedListingTemplate({workspace=root,home,environment=process.env,
  startExisting=options=>require('./install/secureshop-owned-listing-template').startExisting(options)}={}) {
  const result=await startExisting({root:workspace,home,environment});
  if(result?.absent===true||result?.preservedDisabled===true)return result;
  if(result?.ready!==true||result.enabled!==true||typeof result.baseUrl!=='string'
      ||!/^http:\/\/127\.0\.0\.1:81(?:0[9]|1[0-8])$/.test(result.baseUrl)) {
    throw publicError('LISTING_TEMPLATE_START_UNAVAILABLE','The enabled managed listing template listener is not ready.');
  }
  return result;
}

async function startManagedSecureShopServices({ workspace = root, home, environment = process.env,
  platform = process.platform, systemManaged = {}, pricingManaged = {},
  startSystem = options => require('./install/secureshop-owned-system-provision').startExisting(options),
  startPricing = options => require('./install/secureshop-owned-pricing-provision').startExisting(options) } = {}) {
  // Windows owns its retained lab through runWindowsStartup, not host Docker.
  if (platform === 'win32') return;
  if (systemManaged.SS_BOUND_SYSTEM_CONFIG_ENABLED === 'true') {
    const result = await startSystem({ root: workspace, home, platform, environment });
    if (result?.ready !== true || result.enabled !== true) {
      throw publicError('SYSTEM_START_UNAVAILABLE', 'The enabled managed System listeners are not ready.');
    }
  }
  if (pricingManaged.SS_BOUND_PRICING_ENABLED === 'true') {
    const result = await startPricing({ root: workspace, home, platform, environment });
    if (result?.ready !== true || result.enabled !== true) {
      throw publicError('PRICING_START_UNAVAILABLE', 'The enabled managed Pricing listener is not ready.');
    }
  }
}

async function main(args = process.argv.slice(2), { nodeVersion = process.versions.node,
  startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS, platform = process.platform,
  observeWindowsHost = require('./lib/windows-host-preflight').observeWindowsHostPreflight,
  windowsStartup = runWindowsStartup } = {}) {
  const profile = require('./application-journal-bound-maintenance').selectProfile(args, { startup: true });
  assertSupportedApplicationNodeVersion(nodeVersion);
  if (args.some(arg => !arg.startsWith('--maintenance-profile=') && !['--init-db', '--reset', '--plan'].includes(arg))) throw new Error('Usage: ./start_all.sh [--init-db] [--plan]');
  if (args.includes('--reset')) throw new Error('Database files are never deleted by startup. Use the authenticated workshop reset controls; use explicit migration tools for existing data.');
  if (platform === 'win32') {
    const host = require('./lib/windows-host-preflight').validateWindowsHostPreflight(observeWindowsHost());
    if (args.includes('--plan') && !host.hostSupported) {
      console.log(JSON.stringify(host, null, 2));
      process.exitCode = 1;
      return;
    }
    require('./lib/windows-host-preflight').assertWindowsHostSupported(host);
  }
  require('dotenv').config({ path: path.join(root, '.env'), quiet: true });
  const home = require('node:os').homedir();
  const systemManaged = require('../server/services/secureshopSystemManagedEnvironment').loadWithQualified({root,home,environment:process.env});
  Object.assign(process.env, systemManaged);
  const pricingManaged = require('../server/services/secureshopPricingManagedConfiguration').environment({root,home,environment:process.env});
  Object.assign(process.env, pricingManaged);
  const managedPolicyRenderer = require('../server/services/secureshopPolicyRendererManagedEnvironment').load({root,home,environment:process.env});
  Object.assign(process.env, managedPolicyRenderer);
  const { configurationPlan } = require('../db/postgres/initialize-application');
  if (args.includes('--plan')) {
    console.log(JSON.stringify(configurationPlan(process.env), null, 2));
    return;
  }
  require('../server/services/applicationDatabaseEngine')
    .assertApplicationDatabaseEngine({ env: process.env });
  require('../server/services/platformSigningConfiguration').assertPlatformSigningConfiguration(process.env);
  await assertApplicationPortsAvailable(process.env);
  await startManagedPolicyRenderer({ workspace: root, home, environment: process.env, managedEnvironment: managedPolicyRenderer });
  if (platform === 'win32') {
    await require('./lib/start-managed-listings').startManagedListings({ root, home, platform, environment: process.env });
    await startManagedListingTemplate({workspace:root,home,environment:process.env});
    const missing = configurationPlan(process.env).filter(item => !item.configured);
    if (missing.length) throw new Error(`Missing PostgreSQL URL pairs: ${missing.map(item => item.schema).join(', ')}`);
    await windowsStartup({ environment: process.env, startupTimeoutMs, prepareApplication: async () => {
      process.env.OWASP_AI_GOAT_APP_DATA_ROOT = require('./application-data-root')
        .ensureApplicationDataRoot({ workspace: root, environment: process.env });
      if (args.includes('--init-db')) {
        if (profile !== require('./application-journal-bound-maintenance').PROFILE) throw new Error('Unsupported maintenance profile');
        await require('./application-journal-bound-maintenance').runProspectiveJournalBoundMaintenance({ installationRoot: root });
      }
      await require('../server/services/secureshopSystemManagedEnvironment').assertReady({environment:process.env});
      await require('../server/services/secureshopPricingActivation').preparePricingClient({root,env:process.env});
    } });
    return;
  }
  process.env.OWASP_AI_GOAT_APP_DATA_ROOT = require('./application-data-root')
    .ensureApplicationDataRoot({ workspace: root, environment: process.env });
  if (process.env.IPI_EMAIL_PROVIDER === 'mailpit' && process.env.MAILPIT_STATE_PATH) {
    await assertLocalMailpitReady({ statePath: process.env.MAILPIT_STATE_PATH, execute: exec, environment: process.env });
  }
  const missing = configurationPlan(process.env).filter(item => !item.configured);
  if (missing.length) throw new Error(`Missing PostgreSQL URL pairs: ${missing.map(item => item.schema).join(', ')}`);
  if (args.includes('--init-db')) {
    if (profile !== require('./application-journal-bound-maintenance').PROFILE) throw new Error('Unsupported maintenance profile');
    await require('./application-journal-bound-maintenance').runProspectiveJournalBoundMaintenance({installationRoot:path.resolve(__dirname,'..')});
  }
  await startManagedSecureShopServices({ workspace: root, home, environment: process.env, platform, systemManaged, pricingManaged });
  await require('./lib/start-managed-listings').startManagedListings({ root, home, platform, environment: process.env });
  await startManagedListingTemplate({workspace:root,home,environment:process.env});
  await require('../server/services/secureshopSystemManagedEnvironment').assertReady({environment:process.env});
  await require('../server/services/secureshopPricingActivation').preparePricingClient({root,env:process.env});
  const supervisor = createApplicationSupervisor({ workspace: root, environment: process.env, startupTimeoutMs });
  await runControlledApplication({ workspace: root, supervisor });
}


module.exports = {
  assertApplicationPortsAvailable,
  DEFAULT_STARTUP_TIMEOUT_MS,
  boundedLineReader,
  createApplicationSupervisor,
  exactViteReadyLine,
  main,
  runControlledApplication,
  runWindowsStartup,
  startManagedPolicyRenderer,
  startManagedListingTemplate,
  startManagedSecureShopServices,
  stopOwnedChild,
};

if (require.main === module) main().catch(error => {
  console.error(error.code === 'MAILPIT_LEGACY_STATE_UNSUPPORTED' ? require('./local-mailpit').LEGACY_STATE_MESSAGE
    : ['INVALID_APPLICATION_DATA_ROOT', 'UNSUPPORTED_NODE_RUNTIME', 'APPLICATION_PORT_UNAVAILABLE', 'APPLICATION_PORT_CONFLICT', 'WINDOWS_HOST_UNSUPPORTED', 'WINDOWS_HOST_PREFLIGHT_UNAVAILABLE'].includes(error.code) ? error.message
    : error.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT'
      ? `Startup failed (${require('./application-journal-bound-maintenance').sanitizedFailureCode(error)}); inspect maintenance readiness before retrying.`
      : error.code ? `Startup failed (${error.code}); check application readiness and PostgreSQL configuration.` : error.message);
  if (error.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT') process.exit(1);
  else process.exitCode = 1;
});
