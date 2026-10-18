'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresAuthRouter } = require('../server/routes/postgresAuth');

async function request(t, email) {
  let reads = 0;
  const pass = (_req, _res, next) => next();
  const router = createPostgresAuthRouter({
    adapter: { repository: { findUserByEmail: async () => { reads++; return { id: 7 }; } } },
    loginRuntime: { close() {}, snapshot() { return {}; } },
    limiters: { loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass },
  });
  t.after(() => router.close());
  const route = router.stack.find(layer => layer.route?.path === '/reset-password').route;
  const result = await new Promise((resolve, reject) => {
    let status = 200, index = 0;
    const res = { status(value) { status = value; return this; }, json(body) { resolve({ status, body }); } };
    const next = error => {
      if (error) return reject(error);
      const handler = route.stack[index++];
      if (!handler) return reject(new Error('No response'));
      Promise.resolve(handler.handle({ body: { email } }, res, next)).catch(reject);
    };
    next();
  });
  return { ...result, reads };
}

test('public recovery gives the supported instructor flow without claiming delivery or looking up identity', async t => {
  const first = await request(t, 'learner@example.test');
  const second = await request(t, 'unknown@example.test');
  assert.deepEqual(first, second);
  assert.equal(first.status, 409);
  assert.equal(first.body.success, false);
  assert.equal(first.body.code, 'PASSWORD_RESET_INSTRUCTOR_MANAGED');
  assert.match(first.body.error, /instructor/i);
  assert.doesNotMatch(first.body.error, /has been sent/i);
  assert.equal(first.reads, 0);
});

test('invalid email remains a validation error without reading identity', async t => {
  const result = await request(t, 'not-an-email');
  assert.equal(result.status, 400);
  assert.equal(result.reads, 0);
});
