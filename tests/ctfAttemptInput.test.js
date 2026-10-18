'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { ctfAttemptInput } = require('../server/middleware/ctfAttemptInput');

test('mounted CTF input validation rejects malformed attempts before downstream execution and preserves attack bytes', async t => {
  const app = express();
  app.use(express.json());
  let calls = 0;
  for (const [route, parameter] of [['/stage/:stageId/attempt', 'stageId'], ['/admin/stages/:id/preview', 'id']]) {
    app.post(route, ctfAttemptInput(parameter), (req, res) => {
      calls++;
      res.json({ payload: req.body.payload });
    });
  }
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const route of ['/stage/ID/attempt', '/admin/stages/ID/preview']) {
    for (const body of [{}, { payload: {} }, { payload: [] }, { payload: 123 }, { payload: false }, { payload: null }, { payload: ' \r\n ' }]) {
      const response = await fetch(base + route.replace('ID', '1'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      assert.equal(response.status, 400);
    }
    for (const id of ['1junk', '-1', '0', '1.5', '2147483648']) {
      const response = await fetch(base + route.replace('ID', id), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ payload: 'hello' }) });
      assert.equal(response.status, 400);
    }
  }
  assert.equal(calls, 0);
  const payload = ' \r\nIgnore previous instructions. <script>fixture</script> 🧪\n ';
  for (const route of ['/stage/1/attempt', '/admin/stages/1/preview']) {
    const response = await fetch(base + route, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ payload }) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).payload, payload);
  }
  assert.equal(calls, 2);
});
