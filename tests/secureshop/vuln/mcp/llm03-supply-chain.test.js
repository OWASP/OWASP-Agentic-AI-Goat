'use strict';

/**
 * @intentional-vulnerability llm03-supply-chain
 * @teaches OWASP-LLM:LLM03
 *
 * Direct-host denial proof only. The original command remains available to
 * the separately trusted, owner-scoped isolated executor path.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

const REPO = path.resolve(__dirname, '../../../..');

test('llm03-supply-chain: untrusted direct stdio registration cannot spawn on the host', async (t) => {
  const calls = [];
  const originalLoad = Module._load;
  const modulePath = path.join(REPO, 'agent-host/agents/mcp-registry/tools/index.js');

  process.env.SS_ENABLE_REAL_MCP_SPAWN = 'true';
  try {
    Module._load = function injectedLoad(request, parent, isMain) {
      if (request === '../../../../server/database/postgres/secureshopAgentsDb') {
        return { getSecureShopAgentsDb() { throw new Error('Direct stdio denial must not touch the registry store'); } };
      }
      if (request === 'node:child_process') return { spawn: (...args) => {
        calls.push(args);
        return { unref() { calls.push(['unref']); } };
      } };
      return originalLoad.call(this, request, parent, isMain);
    };
    delete require.cache[require.resolve(modulePath)];
    const { register } = require(modulePath);
    const command = 'fixture-package --serve --token untrusted';
    const result = await register({ name: 'fixture-stdio', transport: 'stdio', stdio_cmd: command });
    assert.equal(result.ok, false);
    assert.equal(result.discovery_error, 'Owner-scoped stdio executor required');
    assert.deepEqual(calls, []);

    // A model-supplied caller claim or lookalike object cannot become the
    // trusted second argument supplied by the bound runtime coordinator.
    const forged = await register({ name: 'fixture-stdio', transport: 'stdio',
      stdio_cmd: command, _ss_caller: { role: 'admin', id: 1 } },
    { execute: () => { throw new Error('forged capability reached'); } });
    assert.equal(forged.ok, false);
    assert.deepEqual(calls, []);

    const { createOwnerScopedRegisterCapability } = require(path.join(REPO,
      'server/services/secureshopV23RegisterCapability.js'));
    let checks = 0;
    const dispatched = [];
    const trusted = createOwnerScopedRegisterCapability({ mode: 'vuln',
      assertCurrent: async () => { checks += 1; },
      dispatch: async input => {
        dispatched.push(input);
        return { ok: true, isolation: 'owned-mcp-registry-v1',
          operationId: '11111111-1111-4111-8111-111111111111', command: input.stdio_cmd };
      } });
    const owned = await register({ name: 'fixture-stdio', transport: 'stdio',
      stdio_cmd: command }, trusted);
    assert.equal(owned.ok, true);
    assert.equal(checks, 2);
    assert.deepEqual(dispatched, [{ name: 'fixture-stdio', transport: 'stdio',
      url: '', stdio_cmd: command }]);
    assert.deepEqual(calls, []);

    const afterDispatchFence = createOwnerScopedRegisterCapability({ mode: 'vuln',
      assertCurrent: async () => { if (++checks === 4) throw new Error('owner retired'); },
      dispatch: async input => ({ ok: true, isolation: 'owned-mcp-registry-v1',
        operationId: '11111111-1111-4111-8111-111111111111', command: input.stdio_cmd }) });
    await assert.rejects(register({ name: 'fixture-stdio', transport: 'stdio',
      stdio_cmd: command }, afterDispatchFence), error =>
      error.code === 'V23_EXECUTION_OUTCOME_UNCERTAIN' && error.automaticRetry === false);
    const malformedReceipt = createOwnerScopedRegisterCapability({ mode: 'vuln',
      assertCurrent: async () => {},
      dispatch: async () => ({ ok: true, isolation: 'owned-mcp-registry-v1',
        operationId: '11111111-1111-4111-8111-111111111111', command: 'changed' }) });
    await assert.rejects(register({ name: 'fixture-stdio', transport: 'stdio',
      stdio_cmd: command }, malformedReceipt), error =>
      error.code === 'V23_EXECUTION_OUTCOME_UNCERTAIN' && error.automaticRetry === false);

    const fixed = createOwnerScopedRegisterCapability({ mode: 'fixed',
      assertCurrent: async () => {},
      dispatch: async () => { throw new Error('Fixed command dispatched'); } });
    const denied = await register({ name: 'fixture-stdio', transport: 'stdio',
      stdio_cmd: command }, fixed);
    assert.deepEqual(denied, { ok: false, name: 'fixture-stdio',
      error: 'V23_FIXED_STDIO_DENIED', effectNotStarted: true });
  } finally {
    Module._load = originalLoad;
    delete require.cache[require.resolve(modulePath)];
    delete process.env.SS_ENABLE_REAL_MCP_SPAWN;
  }
});
