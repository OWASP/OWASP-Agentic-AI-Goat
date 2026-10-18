'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createOwnedSystemMetrics } = require('../sidecars/sandbox-runner/owned-system/health-metrics');
const { validateOwnedSystemMetrics } = require('../sidecars/sandbox-runner/owned-system/health-contract');
const defaults = { hostname: () => 'owned-listener', uptime: () => 12.9,
  platform: 'linux', node: 'controlled-node', now: () => new Date('2026-09-20T00:00:00Z') };

test('owned metrics use cgroup limits and listener uptime, never host machine statistics', () => {
  const paths = [];
  const value = createOwnedSystemMetrics({ ...defaults, readFile(file) {
    paths.push(file); return file.endsWith('/memory.max') ? '536870912\n' : '134217728\n';
  } }).snapshot();
  assert.deepEqual(paths, ['/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current']);
  assert.equal(value.totalmem_mb, 512); assert.equal(value.freemem_mb, 384);
  assert.equal(value.version, 'secureshop-owned-system-metrics.v1');
  assert.equal(value.uptime_s, 12); assert.equal(value.uptimeSource, 'listener-process');
  assert.equal(value.memorySource, 'cgroup-v2'); assert.equal(value.loadavg, null);
  assert.ok(Object.isFrozen(value));
  assert.deepEqual(validateOwnedSystemMetrics(value), value);
});

test('unbounded, missing or malformed cgroup limits never fall back to host memory', () => {
  for (const raw of ['max\n', '-1', '0', '1.2', '9007199254740992', '1'.repeat(40)]) {
    const value = createOwnedSystemMetrics({ ...defaults, readFile: () => raw }).snapshot();
    assert.equal(value.totalmem_mb, null); assert.equal(value.freemem_mb, null);
    assert.equal(value.memorySource, 'unavailable');
    assert.deepEqual(validateOwnedSystemMetrics(value), value);
  }
  const value = createOwnedSystemMetrics({ ...defaults, readFile() { throw new Error('private path'); } }).snapshot();
  assert.equal(value.memorySource, 'unavailable');
  assert.ok(!JSON.stringify(value).includes('private path'));
});

test('pressure above limit reports zero available memory and invalid process metrics fail', () => {
  const value = createOwnedSystemMetrics({ ...defaults,
    readFile: file => file.endsWith('/memory.max') ? '1024' : '2048' }).snapshot();
  assert.equal(value.freemem_mb, 0);
  for (const change of [{ uptime: () => NaN }, { uptime: () => -1 }, { hostname: () => '' },
    { now: () => new Date('invalid') }]) assert.throws(() => createOwnedSystemMetrics({ ...defaults, ...change }).snapshot(), /unavailable/);
});
