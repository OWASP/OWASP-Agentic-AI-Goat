'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { respondForged } = require('../server/services/csrfForgedResponse');

test('forged request transport reports actual rejection while preserving GIF and HTML bodies', async t => {
  const app = express();
  const outcomes = {
    allowed: { ok: true, blocked: false },
    defended: { ok: true, blocked: true },
    invalid: { ok: false, reason: 'missing message parameter' },
  };
  app.all('/:outcome', (req, res) => respondForged(req, res, outcomes[req.params.outcome]));
  const server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  for (const method of ['GET', 'POST']) {
    for (const [name, status] of [['allowed', 200], ['defended', 403], ['invalid', 400]]) {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/${name}`, { method });
      assert.equal(response.status, status, `${method} ${name}`);
      if (method === 'GET') {
        assert.match(response.headers.get('content-type'), /image\/gif/);
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.equal(Buffer.from(await response.arrayBuffer()).subarray(0, 6).toString(), 'GIF89a');
      } else {
        assert.match(response.headers.get('content-type'), /text\/html/);
        const body = await response.text();
        assert.match(body, /CSRF Attack Console/);
        if (name === 'defended') assert.match(body, /BLOCKED by defense/);
        if (name === 'invalid') assert.match(body, /missing message parameter/);
      }
    }
  }
});
