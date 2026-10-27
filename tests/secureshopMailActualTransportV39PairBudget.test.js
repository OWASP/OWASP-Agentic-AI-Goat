'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { createActualCallBudget, createMailActualTransport } = require('./postgres/secureshopMailActualTransport');
const PROTOCOL = 'v39-mcp-description-atomic-arm-v1';
const DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';

test('atomic arm admission is exact and occurs before metadata or upstream dispatch', async () => {
  const oldFetch = global.fetch; let metadata = 0;
  global.fetch = async () => { metadata++; throw Error('controlled metadata boundary'); };
  try {
    for (const options of [
      { protocol: PROTOCOL, maxHttpCalls: 13, pairArm: 'control' },
      { protocol: PROTOCOL, maxHttpCalls: 15, pairArm: 'control' },
      { protocol: PROTOCOL, maxHttpCalls: 14, pairArm: 'unknown' },
      { protocol: PROTOCOL, maxHttpCalls: 14 },
      { protocol: PROTOCOL, maxHttpCalls: 14, pairArm: 'control', sharedStages: true },
      { maxHttpCalls: 14, pairArm: 'control' },
    ]) await assert.rejects(createMailActualTransport(options), TypeError);
    assert.equal(metadata, 0);
    await assert.rejects(createMailActualTransport({ protocol: PROTOCOL, maxHttpCalls: 14,
      pairArm: 'control' }), /controlled metadata boundary/);
    assert.equal(metadata, 1);
  } finally { global.fetch = oldFetch; }
});

test('each physical arm reserves at most thirteen actor, four Judge, fourteen total; rejection is fail-stop', () => {
  const budget = createActualCallBudget({ protocol: PROTOCOL, maxHttpCalls: 14 });
  for (let i = 0; i < 10; i++) assert.equal(budget.reserve('actor'), true);
  for (let i = 0; i < 4; i++) assert.equal(budget.reserve('judge'), true);
  assert.deepEqual(budget.snapshot(), { total: 14, actor: 10, judge: 4, failed: false });
  assert.equal(budget.reserve('actor'), false);
  assert.deepEqual(budget.snapshot(), { total: 14, actor: 10, judge: 4, failed: true });
  assert.equal(budget.reserve('judge'), false);
  const actorLimit = createActualCallBudget({ protocol: PROTOCOL, maxHttpCalls: 14 });
  for (let i = 0; i < 13; i++) assert.equal(actorLimit.reserve('actor'), true);
  assert.equal(actorLimit.reserve('actor'), false);
  assert.equal(actorLimit.reserve('judge'), false);
  const legacy = createActualCallBudget();
  assert.deepEqual(legacy.snapshot(), { total: 0, actor: 0, judge: 0 });
});

test('pair uses separate physical listener origins, retires control before treatment and records only actual POSTs', async () => {
  const handlers = []; let dispatched = 0;
  const fakeHttp = { createServer(handler) { handlers.push(handler); return {
    on() {}, listen(_port, _host, ready) { ready(); },
    address() { return { port: 24000 + handlers.length }; }, close(done) { done?.(); },
  }; }, request(_options, onResponse) {
    dispatched++; const upstream = new EventEmitter(); let closed = false;
    upstream.destroy = () => { if (!closed) { closed = true; upstream.emit('close'); } };
    upstream.end = () => queueMicrotask(() => {
      const reply = new EventEmitter(); reply.statusCode = 200;
      reply.headers = { 'content-type': 'application/json' };
      onResponse(reply);
      reply.emit('data', Buffer.from('{"message":{"content":"ok"}}'));
      reply.emit('end'); upstream.destroy();
    });
    return upstream;
  } };
  const module = { exports: {} };
  vm.runInNewContext(readFileSync(require.resolve('./postgres/secureshopMailActualTransport'), 'utf8'), {
    module, require: name => name === 'node:http' ? fakeHttp : require(name),
    Buffer, AbortSignal, setTimeout, clearTimeout,
    fetch: async () => ({ ok: true, json: async () => ({ models: [{ name: 'llama3.1:8b', digest: DIGEST }] }) }),
  });
  const records = [], pair = module.exports.createMcpDescriptionAtomicPairTransport({
    controlRunId: 'a'.repeat(32), treatmentRunId: 'b'.repeat(32),
    record: (arm, value) => records.push({ arm, value: structuredClone(value) }),
  });
  async function post(index) {
    const req = Object.assign(new EventEmitter(), { method: 'POST', url: '/api/chat', async *[Symbol.asyncIterator]() {
      yield Buffer.from(JSON.stringify({ model: 'llama3.1:8b', messages: [] }));
    } });
    const res = new EventEmitter(); res.writeHead = status => { res.status = status; };
    res.write = () => {}; res.end = () => {};
    await handlers[index](req, res); await new Promise(resolve => setImmediate(resolve));
    return res.status;
  }
  try {
    const wrongOrder = module.exports.createMcpDescriptionAtomicPairTransport({
      controlRunId: 'c'.repeat(32), treatmentRunId: 'd'.repeat(32) });
    await assert.rejects(wrongOrder.beginArm('treatment', 'd'.repeat(32)), /V39 pair arm sequence invalid/);
    assert.equal(wrongOrder.snapshot().failed, true);
    await assert.rejects(wrongOrder.beginArm('control', 'c'.repeat(32)));
    const control = await pair.beginArm('control', 'a'.repeat(32));
    assert.notEqual(control.transport.actorUrl, control.transport.judgeUrl);
    for (let i = 0; i < 7; i++) assert.equal(await post(0), 200);
    assert.equal(await post(1), 200);
    assert.equal((await control.finish()).arms.control.state, 'finished');
    const treatment = await pair.beginArm('treatment', 'b'.repeat(32));
    assert.notEqual(treatment.transport.actorUrl, control.transport.actorUrl);
    for (let i = 0; i < 7; i++) assert.equal(await post(2), 200);
    assert.equal(await post(3), 200);
    const final = await treatment.finish();
    assert.equal(final.totalPhysical, 16); assert.equal(dispatched, 16);
    assert.deepEqual(records.map(row => row.arm).filter((arm, index, rows) =>
      index === 0 || rows[index - 1] !== arm), ['control', 'treatment']);
    assert(records.every(row => row.value.calls.every(call => call.arm === row.arm)));
    assert.deepEqual([final.arms.control.actor, final.arms.control.judge,
      final.arms.treatment.actor, final.arms.treatment.judge], [7, 1, 7, 1]);
    const excess = module.exports.createMcpDescriptionAtomicPairTransport({
      controlRunId: 'e'.repeat(32), treatmentRunId: 'f'.repeat(32) });
    try {
      const arm = await excess.beginArm('control', 'e'.repeat(32));
      for (let i = 0; i < 10; i++) assert.equal(await post(4), 200);
      for (let i = 0; i < 4; i++) assert.equal(await post(5), 200);
      assert.equal(await post(4), 503);
      await assert.rejects(arm.finish(), /V39 physical arm incomplete/);
      assert.equal(excess.snapshot().failed, true);
      await assert.rejects(excess.beginArm('treatment', 'f'.repeat(32)));
    } finally { await excess.close(); }
  } finally { await pair.close(); }
});
