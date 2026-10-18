'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TOOL_DEFINITIONS, createToolCatalog, catalogFor } = require('../server/services/mcp/toolRegistry');
const { McpSandboxShell } = require('../server/services/mcp/sandboxShell');
const { createMcpServer } = require('../server/services/mcp/sdk/vulnerableMcpServer');
const { createMcpProtocolSessionManager } = require('../server/services/mcp/sdk/sessionManager');

const STATUS_TOOL = 'check_system_status';
const CLEAN_DESCRIPTION = 'Report server health and uptime.';

function execution() {
  return Object.freeze({
    ownerKey: JSON.stringify(['MCP', '701']),
    runId: 'run-clean-metadata', generation: 1,
    check: async () => {}, effect: async (_key, operation) => operation(),
  });
}

function runner(calls) {
  return Object.freeze({
    async exec(_sessionId, command) {
      calls.push(command);
      return Object.freeze({ ok: true, exitCode: 0, stdout: 'Linux 6.8.0 x86_64\n',
        isolation: 'controlled-unit' });
    },
  });
}

test('constructor catalogs preserve the poison default and only replace bounded descriptions', () => {
  const canonical = TOOL_DEFINITIONS.find(tool => tool.name === STATUS_TOOL);
  const defaultShell = new McpSandboxShell('default-catalog');
  assert.equal(defaultShell.toolListTools().find(tool => tool.name === STATUS_TOOL)?.description,
    canonical.description);

  const overrides = { [STATUS_TOOL]: CLEAN_DESCRIPTION };
  const cleanShell = new McpSandboxShell('clean-catalog', { toolDescriptions: overrides });
  overrides[STATUS_TOOL] = 'mutated after construction';
  const cleanCatalog = cleanShell.toolListTools();
  assert.equal(cleanCatalog.find(tool => tool.name === STATUS_TOOL)?.description, CLEAN_DESCRIPTION);
  assert.deepEqual(cleanCatalog.map(tool => tool.name), TOOL_DEFINITIONS.map(tool => tool.name));
  for (const entry of cleanCatalog) {
    const expected = TOOL_DEFINITIONS.find(tool => tool.name === entry.name);
    assert.strictEqual(entry.inputSchema, expected.inputSchema);
    assert.equal(Object.isFrozen(entry), true);
  }
  assert.throws(() => { cleanCatalog.find(tool => tool.name === STATUS_TOOL).description = 'changed'; }, TypeError);

  assert.throws(() => createToolCatalog({ invented_tool: 'new authority' }), /unknown tool/);
  assert.throws(() => createToolCatalog({ [STATUS_TOOL]: {
    description: CLEAN_DESCRIPTION, inputSchema: { type: 'string' },
  } }), /bounded strings/);
  assert.throws(() => createToolCatalog({ [STATUS_TOOL]: '' }), /bounded strings/);
  assert.equal(catalogFor({ toolListTools: () => [{ name: STATUS_TOOL,
    description: 'untrusted mutable replacement', inputSchema: { type: 'string' } }] })[0].description,
  canonical.description);
  assert.strictEqual(catalogFor({ toolListTools: () => [{ name: STATUS_TOOL,
    description: 'untrusted mutable replacement', inputSchema: { type: 'string' } }] })[0].inputSchema,
  canonical.inputSchema);
});

test('actual SDK advertises and observes the same clean server-owned description', async t => {
  const calls = [];
  const shell = new McpSandboxShell('mcp_701', {
    runner: runner(calls),
    toolDescriptions: { [STATUS_TOOL]: CLEAN_DESCRIPTION },
  });
  const manager = createMcpProtocolSessionManager({
    createServer: sessionId => createMcpServer(sessionId, { sandbox: shell }),
  });
  t.after(() => manager.retireSession('mcp_701'));
  const current = execution();
  const tools = await manager.listTools('mcp_701', { execution: current });
  const advertised = tools.find(tool => tool.name === STATUS_TOOL);
  const canonical = TOOL_DEFINITIONS.find(tool => tool.name === STATUS_TOOL);
  assert.equal(advertised.description, CLEAN_DESCRIPTION);
  assert.deepEqual(advertised.inputSchema, canonical.inputSchema);

  const observed = await manager.callTool('mcp_701', STATUS_TOOL, {}, {
    execution: current, effectKey: 'clean-status-observation', purpose: 'tool_poisoning',
  });
  assert.equal(observed.untrustedText, advertised.description);
  assert.equal(observed.source, 'mcp_tool_description');
  assert.equal(observed.real, true);
  assert.deepEqual(calls, ['uname -srm']);

  await assert.rejects(manager.callTool('mcp_701', STATUS_TOOL, {
    toolDescriptions: { [STATUS_TOOL]: 'user supplied' },
  }, { execution: current, effectKey: 'user-catalog-attempt', purpose: 'tool_poisoning' }),
  error => error?.code === -32603 && /Invalid arguments for MCP tool/.test(error.message));
  assert.deepEqual(calls, ['uname -srm']);
  assert.equal((await manager.listTools('mcp_701', { execution: current }))
    .find(tool => tool.name === STATUS_TOOL)?.description, CLEAN_DESCRIPTION);
});
