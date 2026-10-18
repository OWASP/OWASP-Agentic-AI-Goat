'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const express = require('express');
const jwt = require('jsonwebtoken');

test('PostgreSQL monitoring avoids SQLite and requires an active admin session for HTML', { timeout: 15000 }, async () => {
  const previous = process.env.PLATFORM_DATABASE_ENGINE;
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  const routePath = require.resolve('../server/routes/monitoring');
  const load = Module._load;
  const secret = process.env.JWT_SECRET || 'dvaia-secret-key-2024';
  let session = { user: { id: 42, role: 'admin', admin_level: 1 }, session: { user_id: 42 } };
  let repositoryState = 'active', lookups = 0, configUpdates = 0;
  Module._load = function(name, parent, isMain) {
    if (/authDb|sqlite3/.test(name)) throw new Error('Unexpected SQLite import');
    if (parent?.filename === routePath && name === '../middleware/performanceMonitor') return {
      getSystemStats: () => ({ memoryUsage: { percentage: 10 }, activeConnections: 1 }),
    };
    if (parent?.filename === routePath && name === '../services/ollamaService') return {
      healthCheck: async () => ({ status: 'healthy', has_llama3: true }),
      updateConcurrencyLimits: () => { configUpdates += 1; },
      getStats: () => ({}),
    };
    if (parent?.filename === routePath && name === '../services/postgresIdentityAdapter') return {
      getPostgresIdentityAdapter: () => ({ repository: { findActiveSession: async (token, owner) => {
        lookups++; assert.equal(owner, 42); assert.ok(token);
        return repositoryState === 'active' ? session : null;
      } } }),
    };
    if (parent?.filename === routePath && name === '../views/monitoringHealthPage') return () => '<h1>Admin health</h1>';
    return load.call(this, name, parent, isMain);
  };
  let server;
  try {
    delete require.cache[routePath];
    const app = express(); app.use(express.json()); app.use('/monitoring', require(routePath));
    server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const base = `http://127.0.0.1:${server.address().port}/monitoring`;
    assert.equal((await fetch(`${base}/ping`)).status, 200);
    assert.equal(lookups, 0);
    assert.equal((await fetch(`${base}/health?format=json`)).status, 200);
    const headers = { authorization: `Bearer ${jwt.sign({ userId: 42 }, secret, { expiresIn: '1m' })}` };
    assert.equal((await fetch(`${base}/health?format=html`, { headers })).status, 200);
    repositoryState = 'revoked';
    assert.equal((await fetch(`${base}/health?format=html`, { headers })).status, 401);
    repositoryState = 'active';
    session = { user: { id: 42, role: 'student' }, session: { user_id: 42 } };
    assert.equal((await fetch(`${base}/health?format=html`, { headers })).status, 401);
    assert.equal(lookups, 3);
    for (const role of ['student', 'admin', 'super_admin']) {
      for (const admin_level of [0, 1, 2]) {
        session = { user: { id: 42, role, admin_level }, session: { user_id: 42 } };
        const expected = role !== 'student' && admin_level > 0 ? 200 : 401;
        assert.equal((await fetch(`${base}/health?format=html`, { headers })).status,
          expected, `${role}/${admin_level}`);
      }
    }
    const beforeInvalidTokens = lookups;
    for (const token of [
      jwt.sign({ userId: 42 }, `${secret}-wrong-key`, { expiresIn: '1m' }),
      jwt.sign({ userId: 42 }, secret, { expiresIn: -1 }),
      'not-a-jwt',
    ]) {
      const invalidHeaders = { authorization: `Bearer ${token}` };
      assert.equal((await fetch(`${base}/health?format=html`, { headers: invalidHeaders })).status, 401);
      assert.equal((await fetch(`${base}/ollama/config`, { method: 'POST', headers: invalidHeaders })).status, 403);
    }
    assert.equal(lookups, beforeInvalidTokens, 'Invalid JWTs must not reach the durable session lookup');
    const mutationHeaders = { ...headers, 'content-type': 'application/json' };
    session = { user: { id: 42, role: 'admin', admin_level: 1 }, session: { user_id: 42 } };
    repositoryState = 'active';
    assert.equal((await fetch(`${base}/ollama/config`, { method: 'POST', headers: mutationHeaders,
      body: JSON.stringify({ maxConcurrent: 2 }) })).status, 200);
    assert.equal(configUpdates, 1);
    for (const unavailable of ['revoked', 'locked']) {
      repositoryState = unavailable;
      assert.equal((await fetch(`${base}/ollama/config`, { method: 'POST', headers: mutationHeaders,
        body: JSON.stringify({ maxConcurrent: 2 }) })).status, 403, unavailable);
      assert.equal(configUpdates, 1, `${unavailable} session must not reach the mutation`);
    }
    repositoryState = 'active';
    session = { user: { id: 42, role: 'student', admin_level: 0 }, session: { user_id: 42 } };
    assert.equal((await fetch(`${base}/ollama/config`, { method: 'POST', headers: mutationHeaders,
      body: JSON.stringify({ maxConcurrent: 2 }) })).status, 403);
    assert.equal(configUpdates, 1);
    for (const path of ['logs/recent','llm/recent']) {
      assert.equal((await fetch(`${base}/${path}`)).status, 403);
    }
    for (const path of ['stress-test','ollama/config']) {
      assert.equal((await fetch(`${base}/${path}`, { method: 'POST' })).status, 403);
    }
    session = { user: { id: 42, role: 'admin', admin_level: 1 }, session: { user_id: 42 } };
    for (const body of [{ concurrent: 0 }, { concurrent: -1 }, { concurrent: 1.5 }, { requests: 201 }]) {
      const result = await fetch(`${base}/stress-test`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify(body) });
      assert.equal(result.status, 400);
    }
    const invalidConfig = await fetch(`${base}/ollama/config`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ maxConcurrent: -1 }) });
    assert.equal(invalidConfig.status, 400);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    Module._load = load; delete require.cache[routePath];
    if (previous === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = previous;
  }
});
