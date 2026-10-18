'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const jwt = require('jsonwebtoken');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
const { createWorkshopPlatformAuthority } = require('../server/middleware/workshopPlatformAuthority');
const secret = 'owned-authority-test-secret-32-characters';
const valid = jwt.sign({ sub: '7' }, secret, { expiresIn: '1h' });
const expired = jwt.sign({ sub: '7', exp: 1 }, secret);
let revoked = false;
const canonical = createPostgresAdminAuth({ repository: {}, async validateSession(token) {
  jwt.verify(token, secret);
  return revoked ? null : { user: { id: 7, role: 'student' }, session: { id: 71 } };
} }).authenticateToken;
function request(authorization) {
  return { headers: authorization === undefined ? {} : { authorization },
    session: { userId: 99, role: 'super_admin', adminLevel: 2 }, sessionID: 'old-lab-cookie' };
}
async function invoke(middleware, req) {
  const result = { next: false, status: 200 };
  const res = { status(code) { result.status = code; return this; }, json(body) { result.body = body; return this; } };
  await middleware(req, res, () => { result.next = true; }); return result;
}
function xssIdentity(req) {
  const source = fs.readFileSync(path.join(__dirname, '../server/routes/xssWorkshop.js'), 'utf8');
  const body = source.slice(source.indexOf('function resolveXssIdentity(req) {'), source.indexOf('\nrouter.use((req, _res, next) => {'));
  return vm.runInNewContext(body + '\nresolveXssIdentity(req)', { req, canonicalPlatformAuthority: true });
}
test('required canonical authority rejects cookie-only, malformed, expired and revoked credentials', async () => {
  const middleware = createWorkshopPlatformAuthority({ authenticateToken: canonical });
  for (const value of [undefined, 'Basic '+valid, 'Bearer invalid', 'Bearer '+expired]) {
    const result = await invoke(middleware, request(value)); assert.equal(result.status, 401); assert.equal(result.next, false);
  }
  revoked = true;
  try { assert.equal((await invoke(middleware, request('Bearer '+valid))).status, 401); }
  finally { revoked = false; }
  const req = request('Bearer '+valid);assert.equal((await invoke(middleware, req)).next, true);
  assert.equal(req.user.id, 7);assert.equal(req.user.role, 'student');assert.equal(req.identitySession.id, 71);
});
test('optional XSS authority admits synthetic anonymous scope but never old cookie owner or role', async () => {
  const middleware = createWorkshopPlatformAuthority({ authenticateToken: canonical, optional: true });
  const anonymous = request();anonymous.user = { id: 99, role: 'super_admin' };
  assert.equal((await invoke(middleware, anonymous)).next, true);
  assert.equal(anonymous.user, undefined);assert.equal(xssIdentity(anonymous).platformUserId, null);
  assert.equal(xssIdentity(anonymous).userKey, 'anon_old-lab-cookie');
  for (const value of ['Bearer invalid', 'Bearer '+expired, 'Basic '+valid]) {
    assert.equal((await invoke(middleware, request(value))).status, 401);
  }
  revoked = true;
  try { assert.equal((await invoke(middleware, request('Bearer '+valid))).status, 401); }
  finally { revoked = false; }
  const authenticated = request('Bearer '+valid);
  assert.equal((await invoke(middleware, authenticated)).next, true);
  assert.equal(xssIdentity(authenticated).platformUserId, 7);
  assert.equal(authenticated.session.userId, 99, 'Platform identity is not copied into the challenge cookie');
});
test('optional auth rejects ambiguous authorization rather than silently admitting anonymous state', async () => {
  const req = request('Bearer '+valid);req.rawHeaders = ['Authorization','Bearer '+valid,'Authorization','Bearer '+valid];
  assert.equal((await invoke(createWorkshopPlatformAuthority({ authenticateToken: canonical, optional: true }), req)).status, 401);
});
