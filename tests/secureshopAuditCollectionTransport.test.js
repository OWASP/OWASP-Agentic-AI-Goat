'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { actorWire,actorWireTimeoutMs } = require('./postgres/secureshopAdminAuditJobsRendered.integration.test.js');

test('V36 proxy alone exceeds the child provider cap while other audit cohorts retain 120 seconds',()=>{
  assert.equal(actorWireTimeoutMs(true),180000);
  assert.equal(actorWireTimeoutMs(false),120000);
  assert.equal(actorWireTimeoutMs(),120000);
  assert.ok(actorWireTimeoutMs(true)>175000);
});

function bounded(promise, milliseconds = 3000) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Controlled loopback transport did not settle')), milliseconds);
  })]).finally(() => clearTimeout(timer));
}

test('V36 actual loopback proxy records downstream cancellation and closes upstream without model traffic', async () => {
  let received, closed;
  const upstreamReceived = new Promise(resolve => { received = resolve; });
  const upstreamClosed = new Promise(resolve => { closed = resolve; });
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    response.once('close', () => closed());
    request.on('data', chunk => chunks.push(chunk));
    request.once('end', () => received(Buffer.concat(chunks)));
    // A controlled pending response: cancellation must close this socket.
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const captures = [];
  let transport, client;
  try {
    let observed = 0;
    transport = await actorWire(`http://127.0.0.1:${upstream.address().port}`,
      () => { observed++; }, captures, true);
    const payload = Buffer.from(JSON.stringify({model:'controlled-no-model',stream:true,messages:[]}));
    client = http.request(`${transport.url}/api/chat`, {method:'POST', headers:{'content-type':'application/json'}});
    client.on('error', () => {});
    client.end(payload);
    assert.deepEqual(await bounded(upstreamReceived), payload);
    client.destroy();
    await bounded(upstreamClosed);
    await bounded(new Promise((resolve, reject) => {
      const deadline = Date.now() + 2000;
      const inspect = () => captures[0]?.terminationReason?.startsWith('downstream_')
        ? resolve() : Date.now() < deadline ? setTimeout(inspect, 5)
          : reject(new Error('No downstream termination record'));
      inspect();
    }));
    assert.equal(observed, 1);
    assert.equal(captures.length, 1);
    assert.equal(captures[0].path, '/api/chat');
    assert.equal(captures[0].requestBytes, payload.length);
    assert.equal(captures[0].requestText, payload.toString());
    assert.deepEqual(captures[0].request, JSON.parse(payload));
    assert.equal(captures[0].responseBytes, 0);
    assert.equal(captures[0].complete, false);
    assert.ok(Number.isSafeInteger(captures[0].elapsedMs));
    assert.ok(captures[0].elapsedMs >= 0 && captures[0].elapsedMs <= 600000);
    assert.equal(Object.hasOwn(captures[0], 'responseText'), false);
  } finally {
    client?.destroy();
    if (transport) await transport.close();
    upstream.closeAllConnections();
    await new Promise(resolve => upstream.close(resolve));
  }
});
