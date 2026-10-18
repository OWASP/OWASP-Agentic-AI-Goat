'use strict';

/**
 * @intentional-vulnerability llm03-supply-chain
 * @teaches OWASP-LLM:LLM03
 *
 * Invocation proof only: child_process is injected so no host command runs.
 */

const { seedAgents } = require('../_fixture.js');
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

const REPO = path.resolve(__dirname, '../../../..');

test('llm03-supply-chain: enabled stdio registration reaches arbitrary shell spawn boundary', async (t) => {
  const a = await seedAgents();
  t.after(() => a.close());

  const calls = [];
  const originalLoad = Module._load;
  const modulePath = path.join(REPO, 'agent-host/agents/mcp-registry/tools/index.js');

  process.env.SS_ENABLE_REAL_MCP_SPAWN = 'true';
  try {
    Module._load = function injectedLoad(request, parent, isMain) {
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
    assert.equal(result.ok, true);
    assert.deepEqual(calls[0], ['sh', ['-c', command], { stdio: 'ignore', detached: true }]);
    assert.deepEqual(calls[1], ['unref']);
  } finally {
    Module._load = originalLoad;
    delete require.cache[require.resolve(modulePath)];

    delete process.env.SS_ENABLE_REAL_MCP_SPAWN;
    await a.close();
  }
});
