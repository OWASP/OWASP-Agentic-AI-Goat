'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { fetchWithTimeout } = require('../server/services/mcp/mailClient')._internals;
test('mail timeout covers a stalled body after successful headers', async () => {
  const server = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(fetchWithTimeout(`http://127.0.0.1:${server.address().port}/`, {}, 100));
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
test('mail transport rejects oversized response bodies and decodes valid JSON', async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/large') res.end('x'.repeat(1024 * 1024 + 1));
    else res.end(JSON.stringify({ messages: [] }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    await assert.rejects(fetchWithTimeout(base + '/large', {}, 2000), /exceeds limit/);
    assert.deepEqual(await (await fetchWithTimeout(base, {}, 2000)).json(), { messages: [] });
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
