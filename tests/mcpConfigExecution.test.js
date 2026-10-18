'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { McpSandboxShell } = require('../server/services/mcp/sandboxShell');
const { withOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');

test('config tool uses the verified snapshot operation and preserves raw output plus private proof', async () => {
  const shell = new McpSandboxShell('mcp_7');
  const output = 'DB_PASSWORD=synthetic-fixture-value\n{"secret_key":"synthetic-key"}';
  const token = Object.freeze({});
  const execution = { fixture: true };
  shell._realExec = async () => { throw Error('generic command path must not run'); };
  shell.configObserver = { observe: async input => {
    assert.equal(input.sessionId, 'mcp_7'); assert.equal(input.execution, execution);
    return { output, token };
  } };
  const result = await withOwnerExecution(execution, () => shell.toolGetConfig());
  assert.equal(result.achieved, true); assert.equal(result.real, true);
  assert.equal(result.output, output); assert.equal(result.configObservation, token);
});

test('missing or invalid configuration proof cannot report a successful disclosure', async () => {
  for (const code of ['CONFIG_SNAPSHOT_UNAVAILABLE', 'CONFIG_OBSERVATION_INVALID']) {
    const shell = new McpSandboxShell('mcp_7');
    shell.configObserver = { observe: async () => { throw Object.assign(Error('private-fixture-detail'), { code }); } };
    const result = await shell.toolGetConfig();
    assert.equal(result.achieved, false); assert.equal(result.output, '');
    assert.equal(result.real, false); assert.equal(result.errorCode, 'CONFIG_OBSERVATION_UNAVAILABLE');
    assert.equal(JSON.stringify(result).includes('private-fixture-detail'), false);
  }
});

test('configuration read cancellation is not converted into a normal tool failure', async () => {
  const shell = new McpSandboxShell('mcp_7');
  const error = new DOMException('Cancelled', 'AbortError');
  shell.configObserver = { observe: async () => { throw error; } };
  await assert.rejects(shell.toolGetConfig(), error);
});
