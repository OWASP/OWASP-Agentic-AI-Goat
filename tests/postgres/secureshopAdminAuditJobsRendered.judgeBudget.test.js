'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const { actorWire, boundedJudgeDispatch } = require('./secureshopAdminAuditJobsRendered.integration.test');

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const close = server => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));

test('benign Judge counter rejects a third physical dispatch without changing its two-call cap', () => {
  const counted = [];
  const boundary = boundedJudgeDispatch(2, number => counted.push(number));
  assert.deepEqual(boundary.snapshot(), { acceptedCalls: 0, blockedCalls: 0, limit: 2 });
  boundary.observe(); boundary.observe();
  assert.throws(() => boundary.observe(), /exhausted/);
  assert.deepEqual(counted, [1, 2]);
  assert.deepEqual(boundary.snapshot(), { acceptedCalls: 2, blockedCalls: 1, limit: 2 });
});

test('benign Judge proxy stops the third POST before upstream and retains blocked count', async () => {
  let upstreamPosts = 0;
  const upstream = http.createServer((request, response) => {
    if (request.method === 'POST') upstreamPosts++;
    request.resume(); request.on('end', () => response.writeHead(200).end('{}'));
  });
  await listen(upstream);
  const boundary = boundedJudgeDispatch(2, () => {});
  let proxy;
  try {
    proxy = await actorWire(`http://127.0.0.1:${upstream.address().port}`,
      () => boundary.observe());
    const request = () => fetch(`${proxy.url}/api/chat`, {
      method: 'POST', body: '{}', headers: { 'content-type': 'application/json' },
    }).then(response => response.status);
    assert.equal(await request(), 200);
    assert.equal(await request(), 200);
    assert.equal(await request(), 429);
    assert.equal(upstreamPosts, 2);
    assert.deepEqual(boundary.snapshot(), { acceptedCalls: 2, blockedCalls: 1, limit: 2 });
  } finally {
    if (proxy) await proxy.close();
    await close(upstream);
  }
});

test('concurrent Judge requests reserve the physical budget before upstream dispatch', async () => {
  let upstreamPosts = 0;
  const upstream = http.createServer((request, response) => {
    upstreamPosts++;
    request.resume();
    request.on('end', () => response.writeHead(200).end('{}'));
  });
  await listen(upstream);
  const boundary = boundedJudgeDispatch(2, () => {});
  let proxy;
  try {
    proxy = await actorWire(`http://127.0.0.1:${upstream.address().port}`,
      () => boundary.observe());
    const statuses = await Promise.all(Array.from({ length: 8 }, () =>
      fetch(`${proxy.url}/api/chat`, {
        method: 'POST', body: '{}', headers: { 'content-type': 'application/json' },
      }).then(async response => { await response.text(); return response.status; })));
    assert.equal(statuses.filter(status => status === 200).length, 2);
    assert.equal(statuses.filter(status => status === 429).length, 6);
    assert.equal(upstreamPosts, 2);
    assert.deepEqual(boundary.snapshot(), { acceptedCalls: 2, blockedCalls: 6, limit: 2 });
  } finally {
    if (proxy) await proxy.close();
    await close(upstream);
  }
});
