'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresAuthRouter } = require('../server/routes/postgresAuth');

async function profile(t, user, target = 8) {
  const reads = [];
  const adapter = {
    validateSession: async token => {
      assert.equal(token, 'controlled-session');
      return { user, session: { id: 71, user_id: user.id } };
    },
    repository: { getUserById: async id => {
      reads.push(id);
      return { id, username: 'synthetic-profile', is_active: true, admin_level: 0 };
    } },
  };
  const pass = (_req, _res, next) => next();
  const router = createPostgresAuthRouter({ adapter,
    loginRuntime: { close() {}, snapshot() { return {}; } },
    limiters: { loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass },
  });
  t.after(() => router.close());
  const route = router.stack.find(layer => layer.route?.path === '/profile/:userId').route;
  const req = { headers: { authorization: 'Bearer controlled-session' }, params: { userId: String(target) } };
  const response = await new Promise((resolve, reject) => {
    let status = 200, index = 0;
    const res = { status(code) { status = code; return this; }, json(body) { resolve({ status, body }); } };
    const next = error => {
      if (error) return reject(error);
      const layer = route.stack[index++];
      if (!layer) return reject(new Error('Profile route did not respond'));
      Promise.resolve(layer.handle(req, res, next)).catch(reject);
    };
    next();
  });
  return { ...response, reads };
}

for (const admin_level of [0, 1, 2]) {
  test(`student level ${admin_level} cannot read a sibling profile`, async t => {
    const result = await profile(t, { id: 7, role: 'student', admin_level });
    assert.equal(result.status, 403);
    assert.deepEqual(result.reads, []);
  });
  test(`student level ${admin_level} retains self-profile without admin fields`, async t => {
    const result = await profile(t, { id: 7, role: 'student', admin_level }, 7);
    assert.equal(result.status, 200);
    assert.deepEqual(result.reads, [7]);
    assert.equal(Object.hasOwn(result.body.user, 'admin_level'), false);
  });
}
for (const role of ['admin', 'super_admin']) {
  test(`${role} with positive level can read a sibling profile`, async t => {
    const result = await profile(t, { id: 7, role, admin_level: 1 });
    assert.equal(result.status, 200);
    assert.deepEqual(result.reads, [8]);
    assert.equal(result.body.user.admin_level, 0);
  });
  test(`${role} without admin level cannot read a sibling profile`, async t => {
    const result = await profile(t, { id: 7, role, admin_level: 0 });
    assert.equal(result.status, 403);
    assert.deepEqual(result.reads, []);
  });
}
