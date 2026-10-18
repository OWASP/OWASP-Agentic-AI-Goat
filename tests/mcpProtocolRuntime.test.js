'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TOOL_DEFINITIONS } = require('../server/services/mcp/toolRegistry');
const { createMcpServer } = require('../server/services/mcp/sdk/vulnerableMcpServer');
const { createMcpProtocolSessionManager } = require('../server/services/mcp/sdk/sessionManager');
const protocol = require('../server/services/mcp/protocolContext');
const { readProtocolReceipt, RECEIPT_VERSION } = protocol;

function execution(id) {
  let current = true;
  const effects = [];
  return {
    ownerKey: JSON.stringify(['MCP', String(id)]), runId: `run-${id}`, generation: 3,
    check: async () => { if (!current) throw Object.assign(new Error('stale'), { name: 'AbortError' }); },
    effect: async (key, operation) => { effects.push(key); return operation(); },
    revoke: () => { current = false; }, effects,
  };
}

function sandbox(id) {
  const calls = [];
  const value = {
    calls, shadowTools: [],
    toolListTools() { return [...TOOL_DEFINITIONS, ...this.shadowTools]; },
    async toolRunCommand(command) { calls.push({ command }); return { output: `${id}:${command}`, blocked: false }; },
  };
  return value;
}

function fixture() {
  const sandboxes = new Map();
  const manager = createMcpProtocolSessionManager({
    createServer: async sessionId => {
      if (!sandboxes.has(sessionId)) sandboxes.set(sessionId, sandbox(sessionId));
      return createMcpServer(sessionId, { sandbox: sandboxes.get(sessionId) });
    },
  });
  return { manager, sandboxes };
}

test('actual SDK client lists the canonical catalog and calls the selected bytes once', async t => {
  const { manager, sandboxes } = fixture();
  t.after(() => manager.retireSession('mcp_41'));
  const run = execution(41);
  const tools = await manager.listTools('mcp_41', { execution: run, surface: 'chat' });
  assert.deepEqual(tools.map(tool => tool.name), TOOL_DEFINITIONS.map(tool => tool.name));

  const command = 'ls; cat /var/secrets/exact $HOME';
  const result = await manager.callTool('mcp_41', 'run_command', { command }, {
    execution: run, surface: 'chat', effectKey: 'selected-command',
    actor: { platformRole: 'admin', labRole: 'operator' },
  });
  assert.deepEqual(sandboxes.get('mcp_41').calls, [{ command }]);
  assert.deepEqual(result.args, { command });
  assert.deepEqual(run.effects, ['selected-command']);
  const receipt = readProtocolReceipt(result);
  assert.equal(receipt.version, RECEIPT_VERSION);
  assert.equal(receipt.ownerKey, run.ownerKey);
  assert.equal(receipt.effectKey, 'selected-command');
  assert.equal(receipt.labRole, 'operator');
  assert.equal(JSON.stringify(result).includes(run.ownerKey), false);
});

test('missing, mismatched and stale owner contexts fail before a tool effect', async t => {
  const { manager, sandboxes } = fixture();
  t.after(async () => { await manager.retireSession('mcp_51'); await manager.retireSession('mcp_52'); });
  await assert.rejects(manager.listTools('mcp_51'), { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
  await assert.rejects(manager.listTools('mcp_51', { execution: execution(52) }), { code: 'MCP_PROTOCOL_OWNER_MISMATCH' });
  const run = execution(51);
  run.revoke();
  await assert.rejects(manager.callTool('mcp_51', 'run_command', { command: 'ls' }, { execution: run }), { name: 'AbortError' });
  assert.equal(sandboxes.get('mcp_51')?.calls.length || 0, 0);
});

test('concurrent SDK sessions retain owner-local catalogs and retirement fences reopening on cleanup debt', async () => {
  const { manager, sandboxes } = fixture();
  const a = execution(61), b = execution(62);
  await Promise.all([
    manager.listTools('mcp_61', { execution: a }),
    manager.listTools('mcp_62', { execution: b }),
  ]);
  sandboxes.get('mcp_61').shadowTools.push({ name: 'shadow_a', description: 'owner A imported tool', rogue: true });
  const [aTools, bTools] = await Promise.all([
    manager.listTools('mcp_61', { execution: a }),
    manager.listTools('mcp_62', { execution: b }),
  ]);
  assert.equal(aTools.some(tool => tool.name === 'shadow_a'), true);
  assert.equal(bTools.some(tool => tool.name === 'shadow_a'), false);
  await assert.rejects(manager.callTool('mcp_61', 'shadow_a', {}, { execution: a }), /Unknown MCP tool/);
  let entered = 0, release;
  const bothEntered = new Promise(resolve => { release = resolve; });
  for (const sessionId of ['mcp_61', 'mcp_62']) {
    const owned = sandboxes.get(sessionId);
    owned.toolRunCommand = async command => {
      owned.calls.push({ command });
      entered += 1;
      if (entered === 2) release();
      await bothEntered;
      return { output: `${sessionId}:${command}`, blocked: false };
    };
  }
  const [aResult, bResult] = await Promise.all([
    manager.callTool('mcp_61', 'run_command', { command: 'hostname-a' }, { execution: a, effectKey: 'owner-a' }),
    manager.callTool('mcp_62', 'run_command', { command: 'hostname-b' }, { execution: b, effectKey: 'owner-b' }),
  ]);
  assert.deepEqual(sandboxes.get('mcp_61').calls, [{ command: 'hostname-a' }]);
  assert.deepEqual(sandboxes.get('mcp_62').calls, [{ command: 'hostname-b' }]);
  assert.deepEqual([readProtocolReceipt(aResult).ownerKey, readProtocolReceipt(bResult).ownerKey], [a.ownerKey, b.ownerKey]);
  assert.deepEqual([readProtocolReceipt(aResult).runId, readProtocolReceipt(bResult).runId], [a.runId, b.runId]);
  assert.deepEqual([readProtocolReceipt(aResult).generation, readProtocolReceipt(bResult).generation], ['3', '3']);
  assert.equal((await manager.retireSession('mcp_61')).ok, true);
  assert.equal((await manager.retireSession('mcp_62')).ok, true);
});

test('generation changes create a new SDK session and closed invocation context cannot leak to descendants', async () => {
  let created = 0;
  const sb = sandbox('generation');
  const manager = createMcpProtocolSessionManager({ createServer: async sessionId => {
    created += 1;
    return createMcpServer(sessionId, { sandbox: sb });
  } });
  const first = execution(81);
  await manager.listTools('mcp_81', { execution: first });
  const second = { ...execution(81), generation: 4, runId: 'run-81-next' };
  await manager.listTools('mcp_81', { execution: second });
  assert.equal(created, 2);

  let descendantCode = null;
  let release;
  const descendant = new Promise(resolve => { release = resolve; });
  await protocol.withProtocolInvocation({ sessionId: 'mcp_81', execution: second, surface: 'test' }, async () => {
    setImmediate(() => {
      try { protocol.requireProtocolContext('mcp_81'); }
      catch (error) { descendantCode = error.code; }
      release();
    });
  });
  await descendant;
  assert.equal(descendantCode, 'MCP_PROTOCOL_CONTEXT_REQUIRED');
  assert.equal((await manager.retireSession('mcp_81')).ok, true);
  first.revoke();
  await assert.rejects(manager.listTools('mcp_81', { execution: first }), { name: 'AbortError' });
});

test('failed protocol retirement leaves cleanup debt and denies reopening until retry settles it', async () => {
  let failClose = true;
  const manager = createMcpProtocolSessionManager({ createServer: async sessionId => {
    const created = await createMcpServer(sessionId, { sandbox: sandbox(sessionId) });
    const close = created.server.close.bind(created.server);
    created.server.close = async () => {
      if (failClose) { failClose = false; throw new Error('controlled close failure'); }
      return close();
    };
    return created;
  } });
  const run = execution(91);
  await manager.listTools('mcp_91', { execution: run });
  assert.equal((await manager.retireSession('mcp_91')).ok, false);
  await assert.rejects(manager.listTools('mcp_91', { execution: run }), { code: 'MCP_PROTOCOL_RETIREMENT_INCOMPLETE' });
  assert.equal((await manager.retireSession('mcp_91')).ok, true);
  const next = { ...execution(91), generation: 4, runId: 'run-91-next' };
  assert.equal((await manager.listTools('mcp_91', { execution: next })).length, TOOL_DEFINITIONS.length);
  assert.equal((await manager.retireSession('mcp_91')).ok, true);
});

test('retirement fences admission before awaiting a pending SDK factory', async () => {
  let entered, release;
  const factoryEntered = new Promise(resolve => { entered = resolve; });
  const factoryRelease = new Promise(resolve => { release = resolve; });
  const manager = createMcpProtocolSessionManager({ createServer: async sessionId => {
    entered();
    await factoryRelease;
    return createMcpServer(sessionId, { sandbox: sandbox(sessionId) });
  } });
  const run = execution(101);
  const pendingList = manager.listTools('mcp_101', { execution: run });
  await factoryEntered;
  const retirement = manager.retireSession('mcp_101');
  await assert.rejects(manager.listTools('mcp_101', { execution: run }), { code: 'MCP_PROTOCOL_RETIREMENT_INCOMPLETE' });
  release();
  assert.equal((await retirement).ok, true);
  await assert.rejects(pendingList, { code: 'MCP_PROTOCOL_SESSION_RETIRED' });
});

test('malformed generations fail before allocating SDK resources', async () => {
  let factories = 0;
  const manager = createMcpProtocolSessionManager({ createServer: async sessionId => {
    factories += 1;
    return createMcpServer(sessionId, { sandbox: sandbox(sessionId) });
  } });
  for (const generation of [null, false, NaN, -1, 1.5, {}, '01', '-1', '1e3', '9223372036854775808']) {
    const run = { ...execution(111), generation, durableGeneration: undefined };
    await assert.rejects(manager.listTools('mcp_111', { execution: run }), { code: 'MCP_PROTOCOL_CONTEXT_REQUIRED' });
  }
  assert.equal(factories, 0);
});

test('retiring a paused external factory cannot republish a dangling SSE generation', async () => {
  let entered, release;
  const factoryEntered = new Promise(resolve => { entered = resolve; });
  const factoryRelease = new Promise(resolve => { release = resolve; });
  const manager = createMcpProtocolSessionManager({ createServer: async sessionId => {
    entered();
    await factoryRelease;
    return createMcpServer(sessionId, { sandbox: sandbox(sessionId) });
  } });
  const run = execution(121);
  const pendingHttp = manager.handleHttp('mcp_121', {}, {}, { execution: run });
  await factoryEntered;
  const retirement = manager.retireSession('mcp_121');
  await assert.rejects(manager.handleReadOnlyHttp('mcp_121', {}, {}, { ownerId: 121 }), {
    code: 'MCP_PROTOCOL_RETIREMENT_INCOMPLETE',
  });
  release();
  assert.equal((await retirement).ok, true);
  await assert.rejects(pendingHttp, { code: 'MCP_PROTOCOL_SESSION_RETIRED' });
  await assert.rejects(manager.handleReadOnlyHttp('mcp_121', {}, {}, { ownerId: 121 }), {
    code: 'MCP_PROTOCOL_SESSION_REQUIRED',
  });
});
