'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const http = require('node:http');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const root = path.resolve(__dirname, '../client');

test('Vite serves built assets locally and proxies only workshop sample directories', async () => {
  const { preview, resolveConfig } = await import('../client/node_modules/vite/dist/node/index.js');
  const requests = [];
  const backend = http.createServer((req, res) => {
    requests.push(req.url);
    res.setHeader('Content-Type', 'text/plain');
    res.end(`owned backend ${req.url}`);
  });
  await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve));
  const output = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-vite-routing-'));
  const previousPort = process.env.PORT;
  let server;
  try {
    process.env.PORT = String(backend.address().port);
    await fs.mkdir(path.join(output, 'assets'));
    await fs.writeFile(path.join(output, 'assets', 'application-test.js'), 'export const rendered = true;');
    await fs.writeFile(path.join(output, 'index.html'), '<main>owned preview fixture</main>');
    const options = { root, configLoader: 'runner', envDir: output, configFile: path.join(root, 'vite.config.mjs'), build: { outDir: output }, preview: { host: '127.0.0.1', port: 0, strictPort: false } };
    const config = await resolveConfig(options, 'serve');
    for (const proxies of [config.server.proxy, config.preview.proxy]) {
      assert.equal(Object.hasOwn(proxies, '/assets'), false);
      assert.ok(proxies['/assets/rag_samples/']);
      assert.ok(proxies['/assets/csrf_samples/']);
    }
    server = await preview(options);
    const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
    const chunk = await fetch(`${origin}/assets/application-test.js`, { signal: AbortSignal.timeout(5000) });
    assert.equal(chunk.status, 200);
    assert.equal(await chunk.text(), 'export const rendered = true;');
    assert.deepEqual(requests, []);
    for (const route of ['/assets/rag_samples/normal_policy.txt', '/assets/csrf_samples/example.html', '/api/monitoring/health']) {
      const response = await fetch(`${origin}${route}`, { signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200);
      assert.equal(await response.text(), `owned backend ${route}`);
    }
    assert.deepEqual(requests, ['/assets/rag_samples/normal_policy.txt', '/assets/csrf_samples/example.html', '/api/monitoring/health']);
  } finally {
    if (previousPort === undefined) delete process.env.PORT;
    else process.env.PORT = previousPort;
    if (server) await server.close();
    await new Promise(resolve => backend.close(resolve));
    await fs.rm(output, { recursive: true, force: true });
  }
});
