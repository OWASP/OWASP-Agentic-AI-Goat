'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createStudentToggleHandler } = require('../server/routes/instructorStudentHandlers');

function invoke(handler, req) {
  return new Promise(resolve => {
    let status = 200;
    handler(req, { status(code) { status = code; return this; }, json(body) { resolve({ status, body }); } });
  });
}

test('student toggles deny unauthenticated, student and malformed requests without a write', async () => {
  const handler = createStudentToggleHandler({ run() { assert.fail('denied request wrote to database'); } });
  const base = { params: { studentId: '2' }, body: { enabled: false } };
  assert.equal((await invoke(handler, base)).status, 401);
  assert.equal((await invoke(handler, { ...base, user: { id: 1, role: 'student' } })).status, 403);
  for (const body of [{}, { enabled: 'false' }, { enabled: 0 }]) {
    assert.equal((await invoke(handler, { ...base, user: { id: 1, role: 'admin' }, body })).status, 400);
  }
});

test('admin student updates constrain role and privilege and report missing targets truthfully', async () => {
  let changes = 0;
  const handler = createStudentToggleHandler({ run(sql, params, callback) {
    assert.match(sql, /role IN \('student', 'user'\)/);
    assert.match(sql, /COALESCE\(admin_level, 0\) = 0/);
    assert.deepEqual(params, [0, '2', 1]);
    callback.call({ changes }, null);
  } });
  const req = { user: { id: 1, role: 'admin' }, params: { studentId: '2' }, body: { enabled: false } };
  assert.equal((await invoke(handler, req)).status, 404);
  changes = 1;
  assert.equal((await invoke(handler, req)).body.enabled, false);
});
