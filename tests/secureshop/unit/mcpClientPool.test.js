'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');
const REPO = path.resolve(__dirname, '../../..');
const { AGENT_NAMES } = require(path.join(REPO, 'server/services/secureshop/mcpClientPool.js'));
const EXPECTED = [
  'product-search','summarizer','price-advisor','cart','support',
  'listing','inventory','pricing-strategy','review-moderator','analytics',
  'user-management','audit','system','policy','mcp-registry','uploads','email',
];

// Actual pool connections, SSE paths, retirement/replacement, and supervisor
// lifecycle are qualified separately by secureshopAgentHostTransport.integration.
test('AGENT_NAMES has all 17 agents', () => {
  assert.deepEqual([...AGENT_NAMES], EXPECTED);
});

test('each agent module exports createServer without executing database tools', () => {
  const previousLoad = Module._load;
  let repositoryCalls = 0;
  const repository = new Proxy({}, {
    get() { return () => { repositoryCalls += 1; throw new Error('Export contract cannot execute a database tool'); }; },
  });
  Module._load = function controlledExportDependencies(request, parent, isMain) {
    if (request.endsWith('/database/postgres/secureshopCommerceDb')) return { getSecureShopCommerceDb: () => repository };
    if (request.endsWith('/database/postgres/secureshopAgentsDb')) return { getSecureShopAgentsDb: () => repository };
    return previousLoad.call(this, request, parent, isMain);
  };
  const previousCache = new Set(Object.keys(require.cache));
  try {
    for (const name of EXPECTED) {
      const mod = require(path.join(REPO, `agent-host/agents/${name}/server.js`));
      assert.equal(typeof mod.createServer, 'function', `${name}.createServer must be a function`);
    }
    assert.equal(repositoryCalls, 0, 'checking exports must not execute teaching tools or repository operations');
  } finally {
    Module._load = previousLoad;
    for (const filename of Object.keys(require.cache)) {
      if (!previousCache.has(filename) && filename.startsWith(`${REPO}${path.sep}`)) delete require.cache[filename];
    }
  }
});
