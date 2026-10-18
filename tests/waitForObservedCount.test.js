'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { waitForObservedCount } = require('./helpers/waitForObservedCount');

test('observed-count wait remains pending until a slow response reaches the terminal count', async () => {
  let time = 0;
  let count = 1;
  let delays = 0;
  const result = await waitForObservedCount({ read: () => count, expected: 2,
    timeoutMs: 100, intervalMs: 10, now: () => time, delay: async ms => {
      delays += 1;
      time += ms;
      if (delays === 7) count = 2;
    } });
  assert.equal(result, 2);
  assert.equal(delays, 7);
  assert.equal(time, 70);
});

test('observed-count wait rejects at its terminal deadline instead of falling through', async () => {
  let time = 0;
  await assert.rejects(waitForObservedCount({ read: () => 1, expected: 2,
    timeoutMs: 35, intervalMs: 10, now: () => time, delay: async ms => { time += ms; } }),
  error => error?.code === 'OBSERVATION_TIMEOUT' && error.observed === 1 && error.expected === 2);
  assert.equal(time, 35);
});
