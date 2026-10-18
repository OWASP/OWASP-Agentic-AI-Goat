'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { createTrackRequestCompletion } = require('../server/middleware/trackRequestCompletion');

function fixture(times = [100, 125]) {
  const readings = [...times];
  const records = [];
  const monitor = {
    systemStats: { activeConnections: 0 },
    recordMetrics(...args) { records.push(args); },
  };
  const response = Object.assign(new EventEmitter(), {
    statusCode: 200,
    writableFinished: false,
    chunks: [],
    write(chunk) { this.chunks.push(chunk); },
    send(payload) {
      this.chunks.push(payload);
      this.writableFinished = true;
      this.emit('finish');
      this.emit('close');
    },
    json(payload) { this.send(JSON.stringify(payload)); },
  });
  const middleware = createTrackRequestCompletion(monitor, {
    now: () => readings.shift(),
  });
  let nextCalls = 0;
  middleware({ path: '/api/example' }, response, () => { nextCalls += 1; });
  return { monitor, records, response, nextCalls };
}

test('JSON delegating to send records one finished response without wrapping either method', () => {
  const f = fixture([10, 34]);
  const originalSend = f.response.send;
  const originalJson = f.response.json;
  assert.equal(f.nextCalls, 1);
  assert.equal(f.monitor.systemStats.activeConnections, 1);

  f.response.json({ ok: true });

  assert.equal(f.response.send, originalSend);
  assert.equal(f.response.json, originalJson);
  assert.deepEqual(f.records, [[
    '/api/example', 24, false,
    { statusCode: 200, aborted: false },
  ]]);
  assert.equal(f.monitor.systemStats.activeConnections, 0);
  assert.equal(f.response.listenerCount('finish'), 0);
  assert.equal(f.response.listenerCount('close'), 0);
});

test('stream writes remain active until finish and use the final status and clock', () => {
  const f = fixture([200, 275]);
  f.response.write('event: message\n');
  f.response.write('data: {}\n\n');
  f.response.statusCode = 503;
  assert.equal(f.records.length, 0);
  assert.equal(f.monitor.systemStats.activeConnections, 1);

  f.response.writableFinished = true;
  f.response.emit('finish');

  assert.deepEqual(f.records, [[
    '/api/example', 75, true,
    { statusCode: 503, aborted: false },
  ]]);
  assert.equal(f.monitor.systemStats.activeConnections, 0);
});

test('premature close records the actual status as an aborted error', () => {
  const f = fixture([500, 511]);
  f.response.statusCode = 202;
  f.response.emit('close');

  assert.deepEqual(f.records, [[
    '/api/example', 11, true,
    { statusCode: 202, aborted: true },
  ]]);
  assert.equal(f.monitor.systemStats.activeConnections, 0);
  assert.equal(f.response.listenerCount('finish'), 0);
  assert.equal(f.response.listenerCount('close'), 0);
});

test('close after finish cannot double count or decrement connections twice', () => {
  const f = fixture([800, 820]);
  f.response.writableFinished = true;
  f.response.emit('finish');
  f.response.emit('close');
  f.response.emit('finish');

  assert.equal(f.records.length, 1);
  assert.equal(f.monitor.systemStats.activeConnections, 0);
});

test('a close marked writableFinished is classified as completed when finish was not observed', () => {
  const f = fixture([900, 899]);
  f.response.statusCode = 204;
  f.response.writableFinished = true;
  f.response.emit('close');

  assert.deepEqual(f.records, [[
    '/api/example', 0, false,
    { statusCode: 204, aborted: false },
  ]]);
  assert.equal(f.monitor.systemStats.activeConnections, 0);
});

test('invalid monitor contracts fail at construction without starting requests', () => {
  assert.throws(() => createTrackRequestCompletion({}), /monitor\.recordMetrics/);
  assert.throws(() => createTrackRequestCompletion({
    recordMetrics() {}, systemStats: { activeConnections: 0 },
  }, { now: null }), /clock/);
});
