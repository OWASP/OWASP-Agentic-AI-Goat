'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, 'postgres/finflowTraversalProvisionWorker.js'), 'utf8');
function load({ admitted = true, failure = false } = {}) {
  const state = { messages: [], pools: 0, ended: 0 };
  const env = { PG_TEST_DISPOSABLE: admitted ? 'yes' : 'no', FINFLOW_TRAVERSAL_ISOLATED: '1',
    FINFLOW_WORKSHOP_DATABASE_URL: 'postgresql://controlled.invalid/fixture',
    FINFLOW_TRAVERSAL_TARGET_ROOT: '/controlled/targets', FINFLOW_TRAVERSAL_OWNER: '41000',
    FINFLOW_TRAVERSAL_GENERATION: '3', FINFLOW_TRAVERSAL_RUN_ID: 'controlled-run' };
  const dependencies = {
    'node:path': path, 'node:crypto': crypto,
    pg: { Pool: class { constructor(options) { state.pools++; state.options = options; } async end() { state.ended++; } } },
    '../../server/database/postgres/finflowTraversalTargetRepository': {
      createFinflowTraversalTargetRepository: ({ pool }) => ({ pool }) },
    '../../server/services/finflowTraversalArtifacts': {
      finflowOwnerKey: value => `owner:${value}`,
      createFinflowTraversalManager: options => { state.manager = options; return {
        async read(value) { state.read = value; if (failure) throw Object.assign(new Error('not emitted'), { code: 'CONTROLLED_FAILURE' });
          return { content: 'controlled artifact bytes' }; }
      }; }
    }
  };
  const run = () => vm.runInNewContext(source, {
    require(name) { assert.ok(Object.hasOwn(dependencies, name), `Unadmitted import: ${name}`); return dependencies[name]; },
    process: { env, send: value => state.messages.push(value), once(event, callback) { assert.equal(event, 'message'); state.release = callback; } }
  });
  return { state, run };
}
test('worker denies absent disposable admission before constructing a pool', () => {
  const { state, run } = load({ admitted: false });
  assert.throws(run, /Owned FinFlow traversal worker boundary required/);
  assert.equal(state.pools, 0);
});
test('worker IPC release binds scope and returns artifact digest, then closes pool', async () => {
  const { state, run } = load(); run();
  assert.deepEqual(state.messages, ['ready']);
  assert.equal(state.read, undefined);
  await state.release('go');
  assert.equal(state.read.execution.ownerId, '41000');
  assert.equal(state.read.execution.durableGeneration, '3');
  assert.equal(state.read.execution.runId, 'controlled-run');
  assert.equal(state.read.params.account_id, '../../sensitive_files/config/secrets.env');
  assert.equal(state.options.max, 1);
  assert.equal(state.messages[1].sha256, crypto.createHash('sha256').update('controlled artifact bytes').digest('hex'));
  assert.equal(state.ended, 1);
});
test('worker reports bounded error code and closes pool on tool rejection', async () => {
  const { state, run } = load({ failure: true }); run(); await state.release('go');
  assert.equal(JSON.stringify(state.messages[1]), '{"ok":false,"code":"CONTROLLED_FAILURE"}');
  assert.equal(state.ended, 1);
});
