'use strict';

// Compatibility entry point for the live CSRF qualification. Ordinary /chat
// effects no longer earn browser objectives; the maintained proof mounts the
// authenticated /browser-attempt route and verifies native v8 receipts.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');

test('CSRF live qualification uses the owned mounted-browser harness', {
  skip: process.env.RUN_LIVE_CSRF_WORKFLOW !== '1',
  timeout: 390000,
}, async () => {
  const root = path.resolve(__dirname, '../..');
  const args = ['tests/postgres/run-csrf-browser-isolated.py', '--live'];
  if (process.env.OWASP_AI_GOAT_TEST_DOCKER_HOST) args.push('--docker-host', process.env.OWASP_AI_GOAT_TEST_DOCKER_HOST);
  const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'PUPPETEER_EXECUTABLE_PATH', 'PUPPETEER_CACHE_DIR']
    .filter(key => process.env[key]).map(key => [key, process.env[key]]));
  const code = await new Promise((resolve, reject) => {
    const child = spawn('python3', args, { cwd: root, env, stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', resolve);
  });
  assert.equal(code, 0, 'Owned live browser qualification must pass');
});
