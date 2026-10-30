'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  boundedLineReader,
  createApplicationSupervisor,
  exactViteReadyLine,
  runControlledApplication,
  startManagedPolicyRenderer,
  startManagedSecureShopServices,
  stopOwnedChild,
} = require('../scripts/start-application');
const { requestStop } = require('../scripts/launcher-control');
const { installBackendReadinessIpc } = require('../scripts/backend-readiness-ipc');

const TOKEN = 'a'.repeat(43);

function alive(pid) {
  if (!pid) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code !== 'ESRCH'; }
}

async function waitFor(check, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('condition was not observed');
}

function fixture(directory) {
  const filename = path.join(directory, 'child.js');
  fs.writeFileSync(filename, String.raw`
    'use strict';
    const fs = require('node:fs');
    const { spawn } = require('node:child_process');
    const mode = process.argv[2];
    const own = process.argv[3];
    const descendant = process.argv[4];
    fs.writeFileSync(own, String(process.pid));
    const hold = () => setInterval(() => {}, 1000);
    if (mode === 'backend-fatal') {
      const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
      fs.writeFileSync(descendant, String(child.pid));
      setTimeout(() => process.exit(7), 40);
    } else if (mode === 'backend-ready' || mode === 'backend-dies') {
      process.send({ type: 'owasp-ai-goat-backend-ready', token: process.env.OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN,
        pid: process.pid, port: Number(process.env.PORT || 8081) });
      if (mode === 'backend-dies') setTimeout(() => process.exit(0), 250);
      else hold();
    } else if (mode === 'backend-hang') {
      hold();
    } else if (mode === 'frontend-ready') {
      process.stdout.write('unrelated Local: http://localhost:3000/ suffix\n');
      process.stdout.write('➜  Local:   http://localhost:3999/\n');
      process.stdout.write('\u001b[32m➜  Lo');
      setTimeout(() => process.stdout.write('cal:   http://localhost:3000/\u001b[39m\n'), 20);
      hold();
    } else if (mode === 'frontend-dies') {
      process.stdout.write('➜  Local:   http://localhost:3000/\n');
      setTimeout(() => process.exit(0), 200);
    }
  `);
  return filename;
}

function supervisorFor(directory, backendMode, frontendMode = 'frontend-ready', options = {}) {
  const script = fixture(directory);
  const backendPid = path.join(directory, 'backend.pid');
  const backendDescendant = path.join(directory, 'backend-descendant.pid');
  const frontendPid = path.join(directory, 'frontend.pid');
  const frontendDescendant = path.join(directory, 'frontend-descendant.pid');
  const supervisor = createApplicationSupervisor({
    workspace: path.resolve(__dirname, '..'),
    environment: { ...process.env, PORT: '8081', OWASP_AI_GOAT_CLIENT_PORT: '3000' },
    startupTimeoutMs: options.startupTimeoutMs || 2000,
    backendCommand: process.execPath,
    backendArgs: [script, backendMode, backendPid, backendDescendant],
    frontendCommand: options.frontendCommand || process.execPath,
    frontendArgs: options.frontendArgs || [script, frontendMode, frontendPid, frontendDescendant],
    stdout: { write() {} },
    stderr: { write() {} },
  });
  return { supervisor, paths: { backendPid, backendDescendant, frontendPid, frontendDescendant } };
}

function readPid(filename) {
  try { return Number(fs.readFileSync(filename, 'utf8')); } catch { return null; }
}

test('backend readiness IPC is bound to the exact configured port and child identity payload', () => {
  class FakeServer extends EventEmitter {
    constructor(boundPort) { super(); this.boundPort = boundPort; }
    address() { return { address: '127.0.0.1', port: this.boundPort }; }
  }
  const messages = [];
  const restore = installBackendReadinessIpc({
    Server: FakeServer,
    environment: { PORT: '8081', OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN: TOKEN },
    send: message => messages.push(message),
    pid: 4321,
  });
  try {
    new FakeServer(9090).emit('listening');
    assert.deepEqual(messages, []);
    new FakeServer(8081).emit('listening');
    new FakeServer(8081).emit('listening');
    assert.deepEqual(messages, [{ type: 'owasp-ai-goat-backend-ready', token: TOKEN, pid: 4321, port: 8081 }]);
  } finally { restore(); }
});

test('real preload reports readiness only after its exact loopback server listens', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-ready-ipc-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const reservation = http.createServer();
  await new Promise((resolve, reject) => {
    reservation.once('error', reject);
    reservation.listen(0, '127.0.0.1', resolve);
  });
  const selectedPort = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const serverFixture = path.join(directory, 'server.js');
  fs.writeFileSync(serverFixture, `
    'use strict';
    const http = require('node:http');
    process.send({ type: 'fixture-before-listen', pid: process.pid });
    setTimeout(() => http.createServer((_req, res) => res.end('ready'))
      .listen(Number(process.env.PORT), '127.0.0.1'), 50);
  `);
  const child = spawn(process.execPath, [
    '--require', path.resolve(__dirname, '../scripts/backend-readiness-ipc.js'), serverFixture,
  ], {
    env: { ...process.env, PORT: String(selectedPort), OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN: TOKEN },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    detached: process.platform !== 'win32',
  });
  const messages = [];
  child.on('message', message => messages.push(message));
  t.after(async () => {
    await stopOwnedChild({ child }, { graceMs: 1000, pollMs: 10 }).catch(() => {});
  });
  await waitFor(() => messages.some(message => message.type === 'fixture-before-listen'));
  assert.equal(messages.some(message => message.type === 'owasp-ai-goat-backend-ready'), false);
  await waitFor(() => messages.some(message => message.type === 'owasp-ai-goat-backend-ready'));
  const ready = messages.find(message => message.type === 'owasp-ai-goat-backend-ready');
  assert.deepEqual(ready, {
    type: 'owasp-ai-goat-backend-ready', token: TOKEN, pid: child.pid, port: selectedPort,
  });
  assert.equal(await (await fetch(`http://127.0.0.1:${selectedPort}`)).text(), 'ready');
  await stopOwnedChild({ child }, { graceMs: 1000, pollMs: 10 });
  await waitFor(() => !alive(child.pid));
});

test('owned guardian keeps a live tree root after forwarding workload readiness and exit', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-guardian-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const workload = path.join(directory, 'workload.js');
  fs.writeFileSync(workload, `
    process.send({ type: 'owasp-ai-goat-backend-ready', token: process.env.OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN,
      pid: process.pid, port: 8081 });
    setTimeout(() => process.exit(0), 20);
  `);
  const guardian = spawn(process.execPath, [
    path.resolve(__dirname, '../scripts/owned-child-guardian.js'),
    process.execPath, JSON.stringify([workload]), 'ipc', 'direct',
  ], {
    env: { ...process.env, OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN: TOKEN },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    detached: process.platform !== 'win32',
  });
  const messages = [];
  guardian.on('message', message => messages.push(message));
  t.after(async () => {
    await stopOwnedChild({ child: guardian }, { graceMs: 1000, pollMs: 10 }).catch(() => {});
  });
  await waitFor(() => messages.some(message => message.type === 'owasp-ai-goat-owned-child-outcome'));
  assert.deepEqual(messages.find(message => message.type === 'owasp-ai-goat-backend-ready'), {
    type: 'owasp-ai-goat-backend-ready', token: TOKEN, pid: guardian.pid, port: 8081,
  });
  assert.deepEqual(messages.find(message => message.type === 'owasp-ai-goat-owned-child-outcome'), {
    type: 'owasp-ai-goat-owned-child-outcome', outcome: { type: 'exit', code: 0, signal: null },
  });
  assert.equal(alive(guardian.pid), true);
  await stopOwnedChild({ child: guardian }, { graceMs: 1000, pollMs: 10 });
});

test('Vite readiness accepts only one complete bounded line for the configured port', () => {
  const lines = [];
  const read = boundedLineReader(line => lines.push(line), { maxBytes: 80 });
  read(Buffer.from('unrelated Local: http://localhost:3000/ suffix\n'));
  read(Buffer.from('➜  Local: http://localhost:3999/\n'));
  read(Buffer.from('\u001b[32m➜  Lo'));
  read(Buffer.from('cal: http://localhost:3000/\u001b[39m\n'));
  read(Buffer.from(`${'x'.repeat(81)}\n➜  Local: http://localhost:3000/\n`));
  assert.equal(lines.length, 4);
  assert.equal(lines.filter(line => exactViteReadyLine(line, 3000)).length, 2);
  assert.equal(exactViteReadyLine('prefix Local: http://localhost:3000/', 3000), false);
});

test('fatal backend startup cleans its surviving owned descendant and never starts frontend', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-start-fatal-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { supervisor, paths } = supervisorFor(directory, 'backend-fatal');
  await assert.rejects(supervisor.start(), { code: 'APPLICATION_BACKEND_EXITED' });
  const descendant = readPid(paths.backendDescendant);
  assert.ok(descendant);
  await waitFor(() => !alive(descendant));
  assert.equal(fs.existsSync(paths.frontendPid), false);
});

test('frontend spawn failure cleans a ready backend', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-start-spawn-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { supervisor, paths } = supervisorFor(directory, 'backend-ready', 'frontend-ready', {
    frontendCommand: path.join(directory, 'missing-command'),
    frontendArgs: [],
  });
  await assert.rejects(supervisor.start(), { code: 'APPLICATION_SPAWN_FAILED' });
  const backend = readPid(paths.backendPid);
  assert.ok(backend);
  await waitFor(() => !alive(backend));
});

test('one startup deadline stops a backend that never reports readiness', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-start-timeout-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { supervisor, paths } = supervisorFor(directory, 'backend-hang', 'frontend-ready', { startupTimeoutMs: 100 });
  await assert.rejects(supervisor.start(), { code: 'APPLICATION_START_TIMEOUT' });
  // Under aggregate CPU load the deadline may expire before the child executes
  // its first JS instruction. The supervisor's spawn handle is authoritative;
  // requiring the fixture PID file incorrectly requires startup within 100 ms.
  const children = supervisor.children;
  assert.equal(children.length, 1);
  assert.equal(children[0].name, 'backend');
  assert.ok(children[0].child.pid);
  await waitFor(() => !alive(children[0].child.pid));
  const workloadPid = readPid(paths.backendPid);
  if (workloadPid) await waitFor(() => !alive(workloadPid));
  assert.equal(fs.existsSync(paths.frontendPid), false);
});

test('intentional stop before backend readiness is clean and does not wait for startup timeout', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-start-early-stop-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const stateFile = path.join(directory, 'launcher.json');
  const { supervisor, paths } = supervisorFor(directory, 'backend-hang', 'frontend-ready', { startupTimeoutMs: 5000 });
  const running = runControlledApplication({ workspace: directory, supervisor, stateFile });
  await waitFor(() => fs.existsSync(paths.backendPid) && fs.existsSync(stateFile));
  const started = Date.now();
  await requestStop({ workspace: directory, stateFile });
  await running;
  assert.ok(Date.now() - started < 2000);
  assert.equal(fs.existsSync(paths.frontendPid), false);
  await waitFor(() => !alive(readPid(paths.backendPid)) && !fs.existsSync(stateFile));
});

test('Windows cleanup joins the admitted job and helper without signalling a PID', async () => {
  const calls = [];
  const job = {
    async stop(options) { calls.push(['stop', options]); },
    async close() { calls.push(['close']); },
  };
  await stopOwnedChild({ child: { pid: 7654 }, job, admission: Promise.resolve() }, {
    platform: 'win32', graceMs: 7, commandTimeoutMs: 13,
    kill() { throw new Error('PID signal forbidden'); },
  });
  assert.deepEqual(calls, [['stop', { graceMs: 7, drainTimeoutMs: 13 }], ['close']]);
});

test('Windows cleanup rejects missing job authority and does not trust parent absence', async () => {
  await assert.rejects(stopOwnedChild({ child: { pid: 9876, exitCode: 0 } }, {
    platform: 'win32', kill() { throw new Error('PID probe forbidden'); },
  }), { code: 'OWNED_JOB_UNAVAILABLE' });
});

function controlledGuardian(pid) {
  const child = new EventEmitter();
  Object.assign(child, { pid, connected: true, exitCode: null, signalCode: null });
  child.kill = () => { child.exitCode = 0; child.emit('exit', 0, null); return true; };
  return child;
}

test('Windows supervisor closes an empty job when guardian spawn fails', async () => {
  const events = [];
  const supervisor = createApplicationSupervisor({ platform: 'win32',
    frontendCommand: 'controlled-frontend',
    createJob: async () => { events.push('job-created'); return { async close() { events.push('job-closed'); } }; },
    spawnProcess() { events.push('spawn-attempted'); throw new Error('controlled spawn failure'); },
  });
  await assert.rejects(supervisor.start(), { code: 'APPLICATION_SPAWN_FAILED' });
  assert.deepEqual(events, ['job-created', 'spawn-attempted', 'job-closed']);
});

test('Windows supervisor kills and joins an unadmitted guardian before releasing its job', async () => {
  const events = [];
  const child = controlledGuardian(32001);
  child.kill = () => { events.push('guardian-killed'); child.exitCode = 0; child.emit('exit', 0, null); return true; };
  const supervisor = createApplicationSupervisor({ platform: 'win32',
    frontendCommand: 'controlled-frontend',
    createJob: async () => ({ failure: new Promise(() => {}),
      async admitGuardian() { events.push('admission-denied'); throw new Error('controlled admission denial'); },
      async close() { events.push('job-closed'); } }),
    spawnProcess: () => child,
  });
  await assert.rejects(supervisor.start(), /controlled admission denial/);
  assert.deepEqual(events, ['admission-denied', 'guardian-killed', 'job-closed']);
  assert.equal(supervisor.children.length, 0);
});

test('Windows stop during admission waits before job stop and helper close', async () => {
  const events = [];
  const child = controlledGuardian(32002);
  let admit, entered;
  const enteredAdmission = new Promise(resolve => { entered = resolve; });
  const admitted = new Promise(resolve => { admit = resolve; });
  const supervisor = createApplicationSupervisor({ platform: 'win32',
    frontendCommand: 'controlled-frontend',
    createJob: async () => ({ failure: new Promise(() => {}),
      admitGuardian() { events.push('admission-started'); entered(); return admitted; },
      async stop() { events.push('job-stopped'); },
      async close() { events.push('job-closed'); } }),
    spawnProcess: () => child,
  });
  const starting = supervisor.start();
  await enteredAdmission;
  const stopping = supervisor.stop();
  await Promise.resolve();
  assert.deepEqual(events, ['admission-started']);
  admit({ pid: child.pid });
  await Promise.all([starting, stopping]);
  assert.deepEqual(events, ['admission-started', 'job-stopped', 'job-closed']);
});

test('Windows helper failure after readiness propagates and invokes owned cleanup', async () => {
  const events = [];
  let failBackend;
  const backendFailure = new Promise((_, reject) => { failBackend = reject; });
  backendFailure.catch(() => {});
  let nextPid = 32010;
  const supervisor = createApplicationSupervisor({ platform: 'win32',
    frontendCommand: 'controlled-frontend',
    spawnProcess(_command, _args, options) {
      const child = controlledGuardian(++nextPid);
      child.stdout = new EventEmitter();
      if (nextPid === 32011) setImmediate(() => child.emit('message', {
        type: 'owasp-ai-goat-backend-ready', token: options.env.OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN,
        pid: child.pid, port: 8081,
      }));
      else setImmediate(() => child.stdout.emit('data', Buffer.from('➜  Local: http://localhost:3000/\n')));
      return child;
    },
    createJob: async () => {
      const index = events.filter(value => value === 'job-created').length;
      events.push('job-created');
      return { failure: index === 0 ? backendFailure : new Promise(() => {}),
        async admitGuardian(child) { events.push(`admitted-${child.pid}`); },
        async stop() { events.push(`stopped-${index}`); },
        async close() { events.push(`closed-${index}`); } };
    },
    stdout: { write() {} }, stderr: { write() {} },
  });
  await supervisor.start();
  failBackend(new Error('controlled helper loss'));
  await assert.rejects(supervisor.wait(), /controlled helper loss/);
  assert(events.includes('stopped-0') && events.includes('closed-0'));
  assert(events.includes('stopped-1') && events.includes('closed-1'));
});

test('Unix cleanup fails when an owned group remains after SIGKILL', async () => {
  const signals = [];
  const kill = (pid, signal) => {
    assert.equal(pid, -2468);
    signals.push(signal);
  };
  await assert.rejects(stopOwnedChild({ child: { pid: 2468 } }, {
    platform: 'darwin', kill, graceMs: 1, pollMs: 1,
  }), { code: 'OWNED_PROCESS_GROUP_REMAINS' });
  assert.ok(signals.includes('SIGTERM'));
  assert.ok(signals.includes('SIGKILL'));
});

test('unexpected clean backend exit after full readiness fails and cleans frontend', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-start-postready-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { supervisor, paths } = supervisorFor(directory, 'backend-dies');
  await supervisor.start();
  await assert.rejects(supervisor.wait(), { code: 'APPLICATION_BACKEND_EXITED' });
  const frontend = readPid(paths.frontendPid);
  assert.ok(frontend);
  await waitFor(() => !alive(frontend));
});

test('Windows guardian forwards a post-ready frontend exit through its IPC channel', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-win-frontend-exit-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const script = fixture(directory);
  const stopChild = observed => new Promise((resolve, reject) => {
    if (observed.child.exitCode !== null) return resolve();
    observed.child.once('exit', resolve);
    observed.child.once('error', reject);
    observed.child.kill('SIGTERM');
  });
  const supervisor = createApplicationSupervisor({
    workspace: path.resolve(__dirname, '..'),
    environment: { ...process.env, PORT: '8081', OWASP_AI_GOAT_CLIENT_PORT: '3000' },
    startupTimeoutMs: 2000,
    platform: 'win32',
    backendCommand: process.execPath,
    backendArgs: [script, 'backend-ready', path.join(directory, 'backend.pid'), path.join(directory, 'backend-child.pid')],
    frontendCommand: process.execPath,
    frontendArgs: [script, 'frontend-dies', path.join(directory, 'frontend.pid'), path.join(directory, 'frontend-child.pid')],
    createJob: async () => ({ failure: new Promise(() => {}), admitGuardian: async child => ({ pid: child.pid }),
      async close() {}, async stop() {} }),
    stopChild,
    stdout: { write() {} },
    stderr: { write() {} },
  });
  await supervisor.start();
  await assert.rejects(supervisor.wait(), { code: 'APPLICATION_FRONTEND_EXITED' });
});

test('authenticated intentional stop returns 200, cleans both groups, and removes controller state', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-start-stop-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const stateFile = path.join(directory, 'launcher.json');
  const { supervisor, paths } = supervisorFor(directory, 'backend-ready');
  const running = runControlledApplication({ workspace: directory, supervisor, stateFile });
  await waitFor(() => fs.existsSync(paths.frontendPid));
  await requestStop({ workspace: directory, stateFile });
  await running;
  await waitFor(() => !fs.existsSync(stateFile));
  for (const filename of [paths.backendPid, paths.frontendPid]) {
    const pid = readPid(filename);
    assert.ok(pid);
    await waitFor(() => !alive(pid));
  }
});

test('deferred controller close failure is reported after an intentional stop', async () => {
  let controllerStop;
  let closeCalls = 0;
  const failure = new Error('controller state could not be released');
  const supervisor = {
    async start() {},
    async wait() { await controllerStop(); },
    async stop() {},
  };
  await assert.rejects(runControlledApplication({ workspace: __dirname, supervisor,
    createController: async ({ stop }) => {
      controllerStop = stop;
      return { async close() { closeCalls += 1; throw failure; } };
    },
  }), failure);
  assert.equal(closeCalls, 1);
});

test('managed policy renderer starts only an enabled retained record and propagates failure', async () => {
  const calls = [];
  const options = { workspace: '/controlled/workspace', home: '/controlled/home', environment: { SS_ENABLE: 'true' },
    startExisting: async input => { calls.push(input); return { ready: true, enabled: true }; } };
  await startManagedPolicyRenderer(options);
  await startManagedPolicyRenderer({ ...options, managedEnvironment: {} });
  assert.equal(calls.length, 0);
  await startManagedPolicyRenderer({ ...options, managedEnvironment: { SS_BOUND_PROMPT_POLICIES_ENABLED: 'true' } });
  assert.deepEqual(calls, [{ root: options.workspace, home: options.home, environment: options.environment }]);
  await assert.rejects(startManagedPolicyRenderer({ ...options,
    managedEnvironment: { SS_BOUND_PROMPT_POLICIES_ENABLED: 'true' },
    startExisting: async () => ({ ready: false, enabled: false, preservedDisabled: true }),
  }), { code: 'POLICY_RENDER_START_UNAVAILABLE' });
  const failure = new Error('retained renderer unavailable');
  await assert.rejects(startManagedPolicyRenderer({ ...options,
    managedEnvironment: { SS_BOUND_PROMPT_POLICIES_ENABLED: 'true' },
    startExisting: async () => { throw failure; },
  }), failure);
});

test('managed System and Pricing start only from selected records before application readiness', async () => {
  const calls=[];
  const options={workspace:'/controlled/workspace',home:'/controlled/home',platform:'linux',environment:{},
    startSystem:async input=>{calls.push(['system',input]);return{ready:true,enabled:true};},
    startPricing:async input=>{calls.push(['pricing',input]);return{ready:true,enabled:true};}};
  await startManagedSecureShopServices(options);
  assert.deepEqual(calls,[]);
  await startManagedSecureShopServices({...options,systemManaged:{SS_BOUND_SYSTEM_CONFIG_ENABLED:'true'},pricingManaged:{SS_BOUND_PRICING_ENABLED:'true'}});
  assert.deepEqual(calls.map(([name])=>name),['system','pricing']);
  assert.deepEqual(calls[0][1],{root:options.workspace,home:options.home,platform:'linux',environment:options.environment});
  await startManagedSecureShopServices({...options,platform:'win32',systemManaged:{SS_BOUND_SYSTEM_CONFIG_ENABLED:'true'},pricingManaged:{SS_BOUND_PRICING_ENABLED:'true'}});
  assert.equal(calls.length,2);
  await assert.rejects(startManagedSecureShopServices({...options,systemManaged:{SS_BOUND_SYSTEM_CONFIG_ENABLED:'true'},
    startSystem:async()=>({ready:false,enabled:false})}),{code:'SYSTEM_START_UNAVAILABLE'});
  await assert.rejects(startManagedSecureShopServices({...options,pricingManaged:{SS_BOUND_PRICING_ENABLED:'true'},
    startPricing:async()=>({ready:false,enabled:false})}),{code:'PRICING_START_UNAVAILABLE'});
});

test('launcher plan remains before renderer start and manual server loads managed activation before validation', () => {
  const launcher = fs.readFileSync(path.resolve(__dirname, '../scripts/start-application.js'), 'utf8');
  const application = fs.readFileSync(path.resolve(__dirname, '../server/applicationServer.js'), 'utf8');
  const engineAdmission = launcher.indexOf("require('../server/services/applicationDatabaseEngine')\n    .assertApplicationDatabaseEngine({ env: process.env });");
  assert(launcher.indexOf("if (args.includes('--plan'))") < engineAdmission);
  assert(engineAdmission < launcher.indexOf('await startManagedPolicyRenderer({ workspace: root'));
  assert(engineAdmission < launcher.indexOf("await require('./lib/start-managed-listings').startManagedListings"));
  assert(engineAdmission < launcher.indexOf('await startManagedSecureShopServices({ workspace: root'));
  assert(launcher.indexOf('await startManagedPolicyRenderer({ workspace: root') < launcher.indexOf('await windowsStartup({ environment: process.env'));
  assert(launcher.indexOf('await startManagedPolicyRenderer({ workspace: root') < launcher.indexOf('const supervisor = createApplicationSupervisor({ workspace: root'));
  assert(application.indexOf("require('./services/secureshopPolicyRendererManagedEnvironment').load({")
    < application.indexOf('promptPolicyActivation?.activationPolicy(process.env)'));
  assert(application.indexOf('promptPolicyActivation?.activationPolicy(process.env)')
    < application.indexOf('promptPolicyActivation.preparePromptPolicyRenderer({ env: process.env })'));
});

test('signal handler is active while controller creation is pending and still closes created state', async () => {
  const signals = new EventEmitter();
  let stopped = false;
  let closed = false;
  const supervisor = {
    async stop() { stopped = true; },
    async start() { assert.equal(stopped, true); },
    async wait() {},
  };
  const createController = async () => {
    signals.emit('SIGTERM');
    await Promise.resolve();
    return { async close() { closed = true; } };
  };
  await runControlledApplication({ workspace: __dirname, supervisor, createController, signalSource: signals });
  assert.equal(stopped, true);
  assert.equal(closed, true);
  assert.equal(signals.listenerCount('SIGTERM'), 0);
  assert.equal(signals.listenerCount('SIGINT'), 0);
});

test('controller creation failure removes preinstalled signal handlers', async () => {
  const signals = new EventEmitter();
  const failure = new Error('controller failed');
  let stopCalls = 0;
  const supervisor = { async stop() { stopCalls += 1; }, async start() {}, async wait() {} };
  await assert.rejects(runControlledApplication({
    workspace: __dirname,
    supervisor,
    createController: async () => { throw failure; },
    signalSource: signals,
  }), failure);
  assert.equal(signals.listenerCount('SIGTERM'), 0);
  assert.equal(signals.listenerCount('SIGINT'), 0);
  assert.equal(stopCalls, 1);
});

test('failed owned drain retains controller state instead of claiming shutdown', async () => {
  let controllerStop, closed = false;
  const failure = new Error('controlled drain failure');
  const supervisor = {
    async start() {},
    async wait() { await assert.rejects(controllerStop(), failure); },
    async stop() { throw failure; },
  };
  await assert.rejects(runControlledApplication({ workspace: __dirname, supervisor,
    createController: async ({ stop }) => {
      controllerStop = stop;
      return { async close() { closed = true; } };
    },
  }), failure);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(closed, false);
});
