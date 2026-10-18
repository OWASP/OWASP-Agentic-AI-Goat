'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { main } = require('../scripts/deploy-fresh');

test('initialization aliases await the PostgreSQL initializer exactly once', async () => {
  for (const args of [[], ['init'], ['initialize'], ['full'], ['comprehensive']]) {
    let calls = 0;
    let finished = false;
    const messages = [];
    const code = await main(args, {
      initialize: async () => { calls++; await Promise.resolve(); finished = true; },
      output: text => { assert.equal(finished, true); messages.push(text); },
    });
    assert.equal(code, 0);
    assert.equal(calls, 1);
    assert.match(messages.join('\n'), /Existing learner data was preserved/);
  }
});

test('help, reset and malformed commands never initialize or erase data', async () => {
  for (const args of [['help'], ['--help'], ['-h'], ['reset'], ['reset-full'],
    ['reset-comprehensive'], ['unknown'], ['init', 'reset']]) {
    let calls = 0;
    const code = await main(args, {
      initialize: async () => { calls++; }, output() {}, error() {},
    });
    assert.equal(calls, 0, JSON.stringify(args));
    assert.equal(code, ['help', '--help', '-h'].includes(args[0]) ? 0 : 1);
  }
});

test('initializer rejection reports failure without exposing connection details', async () => {
  const messages = [];
  const code = await main(['init'], {
    initialize: async () => { throw new Error('postgresql://synthetic:secret@host/database'); },
    output: text => messages.push(text), error: text => messages.push(text),
  });
  assert.equal(code, 1);
  assert.match(messages.join('\n'), /initialization failed/);
  assert.doesNotMatch(messages.join('\n'), /synthetic|secret|postgresql:\/\//);
});
