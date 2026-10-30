'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { McpSidecarSupervisor } = require('../server/services/mcp/mcpSidecarSupervisor');

// Every process and health probe in this suite is injected. Explicitly opt
// these fixtures in while the broad runner keeps actual sidecars disabled.
const previousAutostart = process.env.MCP_SIDECARS_AUTOSTART;
test.before(() => { process.env.MCP_SIDECARS_AUTOSTART = 'true'; });
test.after(() => {
  if (previousAutostart === undefined) delete process.env.MCP_SIDECARS_AUTOSTART;
  else process.env.MCP_SIDECARS_AUTOSTART = previousAutostart;
});

function childThatExits(delay, code = 0) {
  const child = new EventEmitter();
  let finished = false;
  const finish = (exitCode) => {
    if (finished) return;
    finished = true;
    child.emit('exit', exitCode);
  };
  const timer = setTimeout(() => finish(code), delay);
  child.kill = () => { clearTimeout(timer); setImmediate(() => finish(null)); return true; };
  return child;
}
const LOCAL_AUTHORITY = Object.freeze({
  version: 1,
  workspaceId: 'fixture-workspace',
  host: 'unix:///tmp/owasp-ai-goat-docker.sock',
  daemonId: 'daemon-fixture',
  source: 'active-context',
});
function localOptions(extra = {}) {
  return {
    authority: LOCAL_AUTHORITY,
    environment: { MCP_SIDECARS_AUTOSTART: 'true', DOCKER_HOST: 'tcp://remote.invalid:2375', DOCKER_CONTEXT: 'remote' },
    inspectDockerDaemon: async () => LOCAL_AUTHORITY.daemonId,
    ...extra,
  };
}

test('compose detection and startup yield to the event loop', { timeout: 5000 }, async () => {
  const calls = [];
  let completeStartup, markStartup;
  const startupEntered = new Promise(resolve => { markStartup = resolve; });
  const supervisor = new McpSidecarSupervisor(localOptions({
    spawnProcess(command, args) {
      calls.push([command, ...args]);
      if (args.includes('up')) {
        const child = new EventEmitter();
        child.kill = () => { child.emit('exit', null); return true; };
        completeStartup = () => child.emit('exit', 0);
        markStartup();
        return child;
      }
      return childThatExits(0);
    },
  }));
  let probes = 0;
  supervisor._allReachable = async () => ({ all: ++probes > 1, runner: true, ssrf: true, rogue: true, mail: true });
  let eventLoopAdvanced = false;
  const starting = supervisor.start();
  await new Promise(resolve => setImmediate(() => { eventLoopAdvanced = true; resolve(); }));
  assert.equal(eventLoopAdvanced, true);
  await startupEntered;
  assert.equal(supervisor.status, 'starting');
  completeStartup();
  await starting;
  assert.equal(supervisor.status, 'running');
  assert.deepEqual(calls.slice(0, 2), [
    ['docker', '--host', LOCAL_AUTHORITY.host, 'compose', 'version'],
    ['docker', '--host', LOCAL_AUTHORITY.host, 'compose', 'up', '-d', '--build', 'mcp-sandbox', 'ssrf-target', 'rogue-mcp', 'mailpit'],
  ]);
  await supervisor.stop();
});

test('stop cancels an in-flight compose startup and performs bounded cleanup', async () => {
  const calls = [];
  const supervisor = new McpSidecarSupervisor(localOptions({
    spawnProcess(command, args) {
      calls.push([command, ...args]);
      return childThatExits(args.includes('up') ? 60_000 : 0);
    },
  }));
  supervisor._allReachable = async () => ({ all: false, runner: false, ssrf: false, rogue: false, mail: false });
  const starting = supervisor.start();
  while (supervisor.status !== 'starting') await new Promise(resolve => setImmediate(resolve));
  await supervisor.stop();
  await starting;
  assert.equal(supervisor.status, 'stopped');
  assert.equal(supervisor.startedByUs, false);
  assert.ok(calls.some(call => call.includes('stop')));
});

test('shutdown during compose detection cannot start sidecars afterward', async () => {
  const calls = [];
  const supervisor = new McpSidecarSupervisor(localOptions({
    spawnProcess(command, args) {
      calls.push([command, ...args]);
      return childThatExits(60_000);
    },
  }));
  supervisor._allReachable = async () => ({ all: false, runner: false, ssrf: false, rogue: false, mail: false });
  const starting = supervisor.start();
  while (!supervisor.activeCommands.size) await new Promise(resolve => setImmediate(resolve));
  await supervisor.stop();
  await starting;
  assert.equal(supervisor.status, 'stopped');
  assert.equal(calls.some(call => call.includes('up')), false);
});

test('shutdown during the final daemon identity check cannot start or stop compose', async () => {
  const calls = [];
  let inspections = 0, releaseIdentity;
  const identityPending = new Promise(resolve => { releaseIdentity = resolve; });
  const supervisor = new McpSidecarSupervisor(localOptions({
    inspectDockerDaemon: async () => {
      inspections += 1;
      if (inspections === 2) await identityPending;
      return LOCAL_AUTHORITY.daemonId;
    },
    spawnProcess(command, args) { calls.push([command, ...args]);return childThatExits(0); },
  }));
  supervisor._allReachable = async () => ({ all: false });
  const starting = supervisor.start();
  while (inspections < 2) await new Promise(resolve => setImmediate(resolve));
  await supervisor.stop();
  releaseIdentity();
  await starting;
  assert.equal(supervisor.status, 'stopped');
  assert.equal(calls.some(call => call.includes('up') || call.includes('stop')), false);
});

test('shutdown during the initial reachability probe cannot start compose', async () => {
  let finishProbe;
  let spawns = 0;
  const supervisor = new McpSidecarSupervisor(localOptions({ spawnProcess() { spawns++; return childThatExits(0); } }));
  supervisor._allReachable = () => new Promise(resolve => { finishProbe = () => resolve({ all: false }); });
  const starting = supervisor.start();
  while (!finishProbe) await new Promise(resolve => setImmediate(resolve));
  const stopping = supervisor.stop();
  finishProbe();
  await Promise.all([starting, stopping]);
  assert.equal(supervisor.status, 'stopped');
  assert.equal(spawns, 0);
});

test('shutdown while health is pending leaves final status stopped', async () => {
  const supervisor = new McpSidecarSupervisor(localOptions({
    spawnProcess(_command, args) { return childThatExits(args.includes('up') ? 5 : 0); },
    healthTimeoutMs: 60_000,
  }));
  supervisor._allReachable = async () => ({ all: false, runner: false, ssrf: false, rogue: false, mail: false });
  const starting = supervisor.start();
  while (!supervisor.startedByUs || supervisor.activeCommands.size) await new Promise(resolve => setImmediate(resolve));
  await supervisor.stop();
  await starting;
  assert.equal(supervisor.status, 'stopped');
});

test('externally managed sidecars never spawn or stop compose', async () => {
  const previous = process.env.TEAM_ID;
  process.env.TEAM_ID = 'fixture';
  let spawns = 0;
  try {
    const supervisor = new McpSidecarSupervisor({ spawnProcess() { spawns++; return childThatExits(0); } });
    supervisor._allReachable = async () => ({ all: false });
    await supervisor.start();
    assert.equal(supervisor.status, 'degraded');
    await supervisor.stop();
    assert.equal(spawns, 0);
  } finally {
    if (previous === undefined) delete process.env.TEAM_ID; else process.env.TEAM_ID = previous;
  }
});

test('local compose commands use the recorded socket and a sanitized immutable environment', async () => {
  const spawns = [];
  const supervisor = new McpSidecarSupervisor(localOptions({
    spawnProcess(command, args, options) {
      spawns.push({ command, args, env: options.env });
      return childThatExits(0);
    },
  }));
  let probes = 0;
  supervisor._allReachable = async () => ({ all: ++probes > 1, runner: true, ssrf: true, rogue: true, mail: true });
  await supervisor.start();
  assert.equal(supervisor.status, 'running');
  assert.ok(spawns.every(call => call.env.DOCKER_HOST === LOCAL_AUTHORITY.host));
  assert.ok(spawns.every(call => call.env.DOCKER_CONTEXT === undefined));
  assert.ok(spawns.every(call => call.args[0] === '--host' && call.args[1] === LOCAL_AUTHORITY.host));
  await supervisor.stop();
});

test('missing or replaced Docker authority prevents local compose mutation', async () => {
  for (const options of [
    { readAuthority: async () => null },
    { authority: LOCAL_AUTHORITY, inspectDockerDaemon: async () => 'another-daemon' },
  ]) {
    let spawns = 0;
    const supervisor = new McpSidecarSupervisor({
      environment: { MCP_SIDECARS_AUTOSTART: 'true' },
      spawnProcess() { spawns++; return childThatExits(0); },
      ...options,
    });
    supervisor._allReachable = async () => ({ all: false });
    await supervisor.start();
    assert.equal(supervisor.status, 'error');
    assert.equal(spawns, 0);
  }
});

test('daemon replacement after startup prevents compose cleanup on the wrong daemon', async () => {
  const calls = [];
  let inspections = 0;
  const supervisor = new McpSidecarSupervisor(localOptions({
    inspectDockerDaemon: async () => ++inspections < 3 ? LOCAL_AUTHORITY.daemonId : 'replacement-daemon',
    spawnProcess(command, args) { calls.push([command, ...args]);return childThatExits(0); },
  }));
  let probes = 0;
  supervisor._allReachable = async () => ({ all: ++probes > 1, runner: true, ssrf: true, rogue: true, mail: true });
  await supervisor.start();
  assert.equal(supervisor.status, 'running');
  await supervisor.stop();
  assert.equal(supervisor.status, 'error');
  assert.match(supervisor.reason, /different daemon/);
  assert.equal(calls.some(call => call.includes('stop')), false);
  assert.equal(supervisor.startedByUs, true);
});


test('disabled autostart performs no health probes or process launches', async () => {
  process.env.MCP_SIDECARS_AUTOSTART = 'false';
  try {
    const supervisor = new McpSidecarSupervisor({ spawnProcess() { assert.fail('unexpected spawn'); } });
    supervisor._allReachable = async () => { assert.fail('unexpected health probe'); };
    await supervisor.start();
    assert.equal(supervisor.status, 'skipped');
    await supervisor.stop();
  } finally { process.env.MCP_SIDECARS_AUTOSTART = 'true'; }
});
