'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function runHelper(args) {
  return spawnSync(process.execPath, [path.join(__dirname, 'xssRenderedViteServer.js'), ...args], { encoding: 'utf8', timeout: 5000 });
}

test('rendered Vite child rejects writable roots inside frozen source', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'xss-vite-helper-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'client'), { recursive: true }); fs.mkdirSync(path.join(root, 'runtime'), { mode: 0o700 });
  fs.writeFileSync(path.join(root, 'client', 'vite.config.mjs'), 'export default {}\n');
  const result = runHelper(['--workspace', root, '--port', '3000', '--backend-port', '8081', '--runtime-root', path.join(root, 'runtime')]);
  assert.notEqual(result.status, 0); assert.match(result.stderr, /outside frozen source/);
});

test('rendered Vite child rejects invalid ports before importing Vite', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'xss-vite-helper-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const runtime = path.join(path.dirname(root), `${path.basename(root)}-runtime`); fs.mkdirSync(runtime);
  t.after(() => fs.rmSync(runtime, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'client'), { recursive: true }); fs.writeFileSync(path.join(root, 'client', 'vite.config.mjs'), 'export default {}\n');
  const result = runHelper(['--workspace', root, '--port', '0', '--backend-port', '8081', '--runtime-root', runtime]);
  assert.notEqual(result.status, 0); assert.match(result.stderr, /ports must be valid/);
});
