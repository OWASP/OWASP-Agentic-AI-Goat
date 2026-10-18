'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { once } = require('node:events');
test('actual access middleware preserves mounted path and excludes query', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owned-access-log-'));
  const express = require('express'), app = express();
  const source = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  const start = source.indexOf('const _logsDir =');
  const end = source.indexOf('// ── end access log', start);
  assert.ok(start > 0 && end > start);
  vm.runInNewContext(source.slice(start, end), { app, fs, path, process: { env: { LOGS_DIR: root } }, Date, __dirname: '/unused' });
  const router = express.Router();router.get('/ping', (_req, res) => res.json({ ok: true }));app.use('/api/monitoring', router);
  const server = app.listen(0, '127.0.0.1');await once(server, 'listening');
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/monitoring/ping?private=excluded`, { signal: AbortSignal.timeout(2000) });
    assert.equal(response.status, 200);await response.text();
    const log = fs.readFileSync(path.join(root, 'access.log'), 'utf8');
    assert.match(log, /GET \/api\/monitoring\/ping HTTP\/1.1/);
    assert.doesNotMatch(log, /private|excluded|\?/);
  } finally { server.closeAllConnections();await new Promise(resolve => server.close(resolve));fs.rmSync(root, { recursive: true }); }
});
