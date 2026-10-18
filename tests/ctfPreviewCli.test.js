'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);
const script = path.join(__dirname, '../scripts/ctf-adversarial-eval.js');

test('preview CLI requires explicit credentials and redacts a failed authenticated request', async () => {
  await assert.rejects(run(process.execPath, [script], { env: {}, timeout: 5000 }), error => {
    assert.equal(error.code, 1); assert.match(error.stderr, /No default login is assumed/); return true;
  });
  const token = 'owned-preview-token-must-not-be-logged';
  const password = 'owned-preview-password-must-not-be-logged';
  let authenticated = false;
  const server = http.createServer((req, res) => {
    req.resume(); res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/auth/login') { res.end(JSON.stringify({ token })); return; }
    authenticated = req.headers.authorization === `Bearer ${token}`;
    res.statusCode = 500; res.end(JSON.stringify({ error: 'owned upstream failure' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(run(process.execPath, [script], { timeout: 5000, env: {
      CTF_TEST_URL: `http://127.0.0.1:${server.address().port}`,
      CTF_ADMIN_USER: 'owned-instructor', CTF_ADMIN_PASS: password,
    } }), error => {
      assert.equal(error.code, 2); assert.match(error.stderr, /Evaluation failed:/);
      assert.equal(`${error.stdout}${error.stderr}`.includes(token), false);
      assert.equal(`${error.stdout}${error.stderr}`.includes(password), false); return true;
    });
    assert.equal(authenticated, true);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
