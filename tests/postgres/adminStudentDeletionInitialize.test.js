'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'adminStudentDeletionInitialize.js'), 'utf8');

async function evaluate({ admit = () => {}, initialize = async () => {}, summary = error => ({
  code: error.code || 'OTHER',
}) } = {}) {
  const calls = [];
  const process = {
    env: Object.freeze({ PG_TEST_DISPOSABLE: 'yes' }),
    stderr: { write: value => calls.push(['diagnostic', value]) },
    exitCode: 0,
    exit: value => calls.push(['exit', value]),
  };
  vm.runInNewContext(source, {
    process,
    require: name => {
      if (name === './adminStudentDeletionRenderedSupport') return {
        admitStores: env => { calls.push(['admit', env]); return admit(env); },
      };
      if (name === '../../db/postgres/initialize-application') return {
        initializeApplication: () => { calls.push(['initialize']); return initialize(); },
        initializationFailureSummary: summary,
      };
      throw new Error(`Unexpected test import: ${name}`);
    },
    Promise,
  }, { filename: 'adminStudentDeletionInitialize.js' });
  await new Promise(resolve => setImmediate(resolve));
  return { calls, process };
}

test('disposable store admission precedes the real exported initializer', async () => {
  const { calls, process } = await evaluate();
  assert.deepEqual(calls.map(row => row[0]), ['admit', 'initialize']);
  assert.equal(process.exitCode, 0);
});

test('invalid disposable store admission never initializes', async () => {
  const { calls, process } = await evaluate({ admit: () => { throw new Error('private URL'); } });
  assert.deepEqual(calls.map(row => row[0]), ['admit', 'diagnostic']);
  assert.equal(process.exitCode, 1);
  assert.equal(calls[1][1].includes('private URL'), false);
});

test('uncertain retained maintenance lease forces child exit after sanitized diagnostic', async () => {
  const error = Object.assign(new Error('private URL'), {
    code: 'APPLICATION_INITIALIZATION_REQUIRES_EXIT',
  });
  const { calls, process } = await evaluate({ initialize: async () => { throw error; } });
  assert.deepEqual(calls.map(row => row[0]), ['admit', 'initialize', 'diagnostic', 'exit']);
  assert.equal(calls[3][1], 1);
  assert.equal(process.exitCode, 0);
  assert.equal(calls[2][1].includes('private URL'), false);
});
