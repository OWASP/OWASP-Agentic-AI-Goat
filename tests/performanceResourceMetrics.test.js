const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function fixture() {
  const mib = 1024 * 1024;
  const state = { memory: { heapUsed: 56 * mib, heapTotal: 60 * mib, rss: 70 * mib, external: mib },
    limit: 1024 * mib, cpu: { user: 0, system: 0 }, time: 0n, concurrency: null };
  const context = { module: { exports: {} },
    require(name) {
      if (name === 'node:v8') return { getHeapStatistics: () => ({ heap_size_limit: state.limit }) };
      if (name === '../services/ollamaService') return { updateConcurrencyLimits: value => { state.concurrency = value; } };
      if (name === './trackRequestCompletion') return require('../server/middleware/trackRequestCompletion');
      throw new Error(`Unexpected dependency ${name}`);
    },
    process: { memoryUsage: () => ({ ...state.memory }), cpuUsage: () => ({ ...state.cpu }), hrtime: { bigint: () => state.time } },
    setInterval() { return {}; },
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../server/middleware/performanceMonitor.js'), 'utf8'), context);
  return { monitor: context.module.exports, state, mib };
}

test('health memory percentage uses V8 limit rather than currently allocated heap', () => {
  const { monitor } = fixture();
  const memory = monitor.getSystemStats().memoryUsage;
  assert.equal(memory.used, 56);
  assert.equal(memory.total, 1024);
  assert.equal(memory.allocated, 60);
  assert.equal(memory.percentage, 5);
  assert.equal(memory.rss, 70);
  assert.equal(memory.basis, 'v8-heap-limit');
});

test('concurrency reduction responds to heap-limit pressure, not ordinary heap allocation', () => {
  const { monitor, state, mib } = fixture();
  monitor.adjustConcurrency();
  assert.equal(state.concurrency, 24);
  state.memory.heapUsed = 950 * mib;
  state.memory.heapTotal = 1000 * mib;
  monitor.updateSystemStats();
  assert.equal(monitor.getSystemStats().memoryUsage.percentage, 93);
  monitor.adjustConcurrency();
  assert.equal(state.concurrency, 12);
});

test('CPU is measured from CPU-time delta over monotonic elapsed time', () => {
  const { monitor, state } = fixture();
  state.cpu = { user: 200000, system: 50000 }; state.time = 1000000000n;
  monitor.updateSystemStats();
  assert.equal(monitor.getSystemStats().cpuUsage, 25);
  state.time = 3000000000n;
  monitor.updateSystemStats();
  assert.equal(monitor.getSystemStats().cpuUsage, 0);
  state.cpu = { user: 2200000, system: 50000 }; state.time = 4000000000n;
  monitor.updateSystemStats();
  assert.equal(monitor.getSystemStats().cpuUsage, 200);
});
