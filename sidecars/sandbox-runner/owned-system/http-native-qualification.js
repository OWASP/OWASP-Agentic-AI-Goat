'use strict';
// Disposable container-only listener. No host port is published.
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { createSystemConfigHttpHandler } = require('./http-handler');
const { FIXTURES } = require('./executor');
const { createSecureShopSystemConfigClient } = require('/server/services/secureshopSystemConfigClient');
async function qualifySystemHttp() {
  const token = crypto.randomBytes(32).toString('base64url');
  const handler = createSystemConfigHttpHandler({ enabled: true, token, maxConcurrent: 1 });
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ method: req.method, path: req.url });
    handler.handle(req, res).then(handled => {
      if (!handled) { res.writeHead(404); res.end(); }
    }, () => { res.writeHead(500); res.end(); });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const baseURL = `http://127.0.0.1:${server.address().port}`;
  try {
    const client = createSecureShopSystemConfigClient({ baseURL, token, timeoutMs: 5000 });
    assert.equal(await client.assertReady(), true);
    const observations = [];
    for (const path of ['application.json', '....//.env', 'missing']) {
      const operationId = crypto.randomUUID();
      const result = await client.read({ operationId, path });
      assert.equal(result.operationId, operationId);
      assert.equal(result.status, 'completed');
      assert.equal(result.drained, true);
      if (path === 'missing') assert.deepEqual(result.readResult, { ok: false, error: 'config not found' });
      else assert.equal(result.readResult.content, FIXTURES[path === 'application.json' ? '/app/config/application.json' : '/app/.env']);
      observations.push({ operationId, path, readOk: result.readResult.ok,
        targetPath: result.readResult.targetPath, contentSha256: result.readResult.contentSha256 });
    }
    for (const route of ['/secureshop/system/health', '/secureshop/system/config-read']) {
      const response = await fetch(baseURL + route, { method: route.endsWith('/health') ? 'GET' : 'POST',
        headers: { authorization: 'Bearer ' + 'x'.repeat(43), 'content-type': 'application/json' },
        ...(route.endsWith('/health') ? {} : { body: JSON.stringify({ operationId: crypto.randomUUID(), path: '....//.env' }) }) });
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { error: 'SYSTEM_UNAUTHORIZED' });
    }
    assert.equal(requests.length, 9);
    return { scope: 'Actual private client + HTTP handler + checksum-checked native executor; container-local loopback only',
      authenticatedHealth: true, observations, wrongBearerDenials: 2, requests, noHostPortPublished: true };
  } finally {
    await handler.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}
module.exports = { qualifySystemHttp };
