'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { FLAGS, SCOPE, assertPrivateReceipt, actorWire, loginParent, frameFor } = require('./secureshopAdminAuditJobsRendered.integration.test');
const valid = () => ({ ...Object.fromEntries(FLAGS.map(k => [k, true])), scope: SCOPE,
  actorCalls: 10, actorPhases: 10, roleTurns: 2, jobRuns: 2, judgeCalls: 1, judgeEvaluations: 1, errors: [] });
test('Q61 exported receipt validator accepts exact bounded honest actor and assessment scope', () => {
  assert.doesNotThrow(() => assertPrivateReceipt(valid()));
  assert.doesNotThrow(() => assertPrivateReceipt({ ...valid(), actorCalls: 8, actorPhases: 8, judgeCalls: 2 }));
  assert.doesNotThrow(() => assertPrivateReceipt({ ...valid(), actorCalls: 28, actorPhases: 14, judgeCalls: 12, judgeEvaluations: 2 }));
});
test('Q61 exported receipt validator denies every absent or false proof and unrelated cohort', () => {
  for (const key of FLAGS) {
    const missing = valid(); delete missing[key]; assert.throws(() => assertPrivateReceipt(missing));
    for (const value of [false, 1, 'true', null]) assert.throws(() => assertPrivateReceipt({ ...valid(), [key]: value }));
  }
  for (const value of [null, [], { ...valid(), scope: 'Q63 zero Judge' }, { ...valid(), mocked: true }, { ...valid(), errors: [{ code: 'Error' }] }])
    assert.throws(() => assertPrivateReceipt(value));
});
test('Q61 exported receipt validator denies zero Judge, added jobs and unbounded or coerced counts', () => {
  assert.throws(() => assertPrivateReceipt({ ...valid(), actorCalls: 8 }));
  assert.throws(() => assertPrivateReceipt({ ...valid(), judgeCalls: 1, judgeEvaluations: 2 }));
  for (const [key, values] of Object.entries({ actorCalls: [7, 29, 8.5, '10', true, NaN], actorPhases: [7, 15, 10.5, '10', true],
    roleTurns: [1, 3, '2', true], jobRuns: [1, 3, '2', true], judgeCalls: [0, 13, 1.5, '1', true], judgeEvaluations: [0, 3, 1.5, '1', true] }))
    for (const value of values) assert.throws(() => assertPrivateReceipt({ ...valid(), [key]: value }));
});
test('Q61 actor wire counts actual repair requests and preserves streaming bytes without inference', async () => {
  const http = require('node:http'), requests = []; let count = 0;
  const upstream = http.createServer((q, r) => {
    const chunks = []; q.on('data', b => chunks.push(b)); q.on('end', () => {
      requests.push({ path: q.url, method: q.method, bytes: Buffer.concat(chunks) });
      r.writeHead(200, { 'content-type': 'application/x-ndjson' }); r.write('{"done":false}\n'); r.end('{"done":true}\n');
    });
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  let wire;
  try {
    wire = await actorWire(`http://127.0.0.1:${upstream.address().port}`, () => count++);
    const bytes = '{"message":"unchanged synthetic input","format":{}}';
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await fetch(wire.url + '/api/chat', { method: 'POST', body: bytes });
      assert.equal(response.status, 200); assert.equal(await response.text(), '{"done":false}\n{"done":true}\n');
    }
    assert.equal(count, 2); assert.ok(requests.every(r => r.bytes.equals(Buffer.from(bytes))));
    assert.equal((await fetch(wire.url + '/api/tags')).status, 200); assert.equal(count, 2);
    assert.equal((await fetch(wire.url + '/not-a-model')).status, 400); assert.equal(requests.length, 3);
  } finally {
    await wire?.close(); upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve));
  }
});
test('Q61 login remains in the parent until authenticated bootstrap completes', async () => {
  for (const status of [200, 401]) {
    let submitted = false, mounted = false, acknowledge;
    const response = { url: () => 'http://127.0.0.1:12345/api/secureshop/auth/bootstrap',
      request: () => ({ method: () => 'POST' }), status: () => status };
    const page = {
      async goto(url) { assert.equal(url, 'http://127.0.0.1:12345/secureshop/login?next=%2Fsecureshop%2Fadmin'); },
      async waitForSelector(selector) { assert.equal(selector, '#ss-login-user'); assert.equal(mounted, false); },
      async type(selector) { assert.ok(['#ss-login-user', '#ss-login-pw'].includes(selector)); assert.equal(mounted, false); },
      waitForResponse(predicate) {
        assert.equal(predicate(response), true);
        assert.equal(predicate({ ...response, url: () => 'http://127.0.0.1:12346/api/secureshop/auth/bootstrap' }), false);
        return new Promise(resolve => { acknowledge = () => resolve(response); });
      },
      async click(selector) { assert.equal(selector, 'button[type="submit"]'); submitted = true; acknowledge(); },
      async waitForFunction(predicate) {
        assert.match(String(predicate), /location\.pathname === '\/secureshop\/admin'/);
        assert.equal(submitted, true);
      },
    };
    const mount = async actual => { assert.equal(actual, page); assert.equal(submitted, true); mounted = true; return 'authenticated-frame'; };
    if (status === 200) assert.equal(await loginParent(page, 'http://127.0.0.1:12345', mount), 'authenticated-frame');
    else { await assert.rejects(loginParent(page, 'http://127.0.0.1:12345', mount)); assert.equal(mounted, false); }
  }
});

test('Q61 frame readiness requires the mounted admin assistant', async () => {
  let reads = 0;
  const frame = { detached: false, async evaluate() {
    reads++;
    return { frame: true, url: '/secureshop-frame.html', text: 'Administrator', ready: reads > 1 };
  } };
  const page = { async $(selector) {
    assert.equal(selector, 'iframe[title="SecureShop"]');
    return { async contentFrame() { return frame; } };
  } };
  assert.equal(await frameFor(page), frame);
  assert.equal(reads, 2);
});
