'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createPostgresRunLedger } = require('../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');

function fixture({ failInsert = false, failBind = false, failRollback = false } = {}) {
  const state = { committedRuns: new Set(), committedBindings: new Set(), child: '0', queries: [], releases: [] };
  let transaction;
  const client = new EventEmitter();
  client.release = destroy => state.releases.push(destroy === true);
  client.query = async (sql, args = []) => {
    state.queries.push(sql);
    if (sql.includes('pg_try_advisory_lock')) return { rows: [{ acquired: true }] };
    if (sql.includes('SELECT generation FROM graph_runtime.owners')) return { rows: [{ generation: '9' }] };
    if (sql === 'BEGIN') transaction = { runs: new Set(), bindings: new Set() };
    if (sql.startsWith('INSERT INTO graph_runtime.runs')) {
      if (failInsert) throw new Error('run insert failed');
      (transaction?.runs || state.committedRuns).add(args[0]);
    }
    if (sql === 'BIND') {
      assert.ok(transaction, 'binding must share the open run transaction');
      if (failBind) throw new Error('binding failed');
      transaction.bindings.add(args[0]);
    }
    if (sql === 'COMMIT') {
      for (const run of transaction.runs) state.committedRuns.add(run);
      for (const run of transaction.bindings) state.committedBindings.add(run);
      transaction = null;
    }
    if (sql === 'ROLLBACK') {
      if (failRollback) throw new Error('rollback failed');
      transaction = null;
    }
    return { rows: [], rowCount: 1 };
  };
  const scopeAuthority = {
    async bindRun(lane, context) {
      await lane.query('BIND', [context.runId]);
      return { runId: context.runId, ownerId: context.scope.userId, ownerKey: context.ownerKey,
        scopeKey: context.scope.scopeKey, parentGeneration: context.durableGeneration, childGeneration: state.child };
    },
    async assertRunCurrent(_lane, context) {
      if (context.scopeBinding.childGeneration !== state.child) {
        const error = new Error('child generation stale'); error.name = 'AbortError'; throw error;
      }
    },
  };
  const pool = {
    connect: async () => client,
    query: async (sql, args = []) => {
      state.queries.push(sql);
      assert.equal(sql, 'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1');
      assert.deepEqual(args, ['["XSS","1"]']);
      return { rows: [{ generation: '9' }] };
    },
  };
  return { state, scopeAuthority, ledger: createPostgresRunLedger(pool, { scopeAuthority }) };
}
const context = () => ({ ownerKey: '["XSS","1"]', runId: 'owned-run', generation: 0,
  scope: Object.freeze({ userId: 1, scopeKey: 'stored_llm' }) });

for (const failure of ['failInsert', 'failBind']) {
  test(`${failure} leaves neither a committed run nor binding`, async () => {
    const { ledger, state } = fixture({ [failure]: true });
    await assert.rejects(ledger.begin(context()), /failed/);
    assert.equal(state.committedRuns.size, 0);
    assert.equal(state.committedBindings.size, 0);
    assert.ok(state.queries.includes('ROLLBACK'));
    assert.equal(state.releases.length, 1);
  });
}

test('scope and run commit together and a changed child blocks effects and checkpoints', async () => {
  const { ledger, state } = fixture(); const run = context();
  Object.assign(run, await ledger.begin(run));
  assert.deepEqual([...state.committedRuns], ['owned-run']);
  assert.deepEqual([...state.committedBindings], ['owned-run']);
  assert.ok(Object.isFrozen(run.scopeBinding));
  state.child = '1'; let executed = false;
  await assert.rejects(ledger.effect(run, 'effect', () => { executed = true; }), /child generation stale/);
  await assert.rejects(ledger.checkpoint(run, { node: 'after-reset' }), /child generation stale/);
  assert.equal(executed, false);
  await ledger.finish(run, { status: 'cancelled' });
});

test('rollback failure destroys the connection instead of returning it to the pool', async () => {
  const { ledger, state } = fixture({ failBind: true, failRollback: true });
  await assert.rejects(ledger.begin(context()), error => error.rollbackError?.message === 'rollback failed');
  assert.deepEqual(state.releases, [true]);
});

test('unscoped admission never invokes the optional scope authority', async () => {
  const { ledger, scopeAuthority, state } = fixture();
  scopeAuthority.bindRun = () => { throw new Error('unexpected scope hook'); };
  const run = { ...context() }; delete run.scope;
  Object.assign(run, await ledger.begin(run));
  await ledger.assertCurrent(run);
  await ledger.finish(run, { status: 'completed' });
  assert.equal(state.queries.includes('BEGIN'), false);
});

test('coordinator rejects scoped requests on an unsupported ledger', async () => {
  const coordinator = createRunCoordinator({ family: 'XSS', ledger: null });
  let executed = false;
  await assert.rejects(coordinator.run(1, { scope: { userId: 1, scopeKey: 'stored_llm' } }, () => { executed = true; }), /does not support scoped admission/);
  assert.equal(executed, false);
});

test('coordinator snapshots caller scope before queued execution', async () => {
  const { ledger } = fixture();
  const coordinator = createRunCoordinator({ family: 'XSS', ledger });
  const scope = { userId: 1, scopeKey: 'stored_llm' };
  const pending = coordinator.run(1, { scope }, execution => {
    assert.equal(execution.scope.scopeKey, 'stored_llm');
    assert.ok(Object.isFrozen(execution.scope));
    return 'done';
  });
  scope.scopeKey = 'email';
  assert.equal(await pending, 'done');
});

test('scoped coordinator rejects missing capability methods and mismatched owner before execution', async () => {
  let executed = false;
  const coordinator = createRunCoordinator({ family: 'XSS', ledger: { supportsScopedAdmission: true } });
  await assert.rejects(coordinator.run(1, { scope: { userId: 1, scopeKey: 'email' } }, () => { executed = true; }), /does not support scoped admission/);
  await assert.rejects(coordinator.run(1, { scope: { userId: 2, scopeKey: 'email' } }, () => { executed = true; }), /Invalid graph run scope/);
  assert.equal(executed, false);
});

test('invalid returned binding fails closed and finishes the admitted run', async () => {
  let finished = false; let executed = false;
  const ledger = { supportsScopedAdmission: true, begin: async () => ({ durableGeneration: '9' }),
    assertCurrent: async () => {}, finish: async () => { finished = true; } };
  const coordinator = createRunCoordinator({ family: 'XSS', ledger });
  await assert.rejects(coordinator.run(1, { scope: { userId: 1, scopeKey: 'email' } }, () => { executed = true; }), /invalid scope binding/);
  assert.equal(executed, false); assert.equal(finished, true);
});

test('ledger cannot replace coordinator-issued owner/run coordinates through admission output', async () => {
  let issued; let finished; let executed = false;
  const ledger = { supportsScopedAdmission: true,
    begin: async context => {
      issued = { ...context };
      return { durableGeneration: '9', runId: 'replacement', ownerKey: '["XSS","2"]',
        scopeBinding: Object.freeze({ runId: 'replacement', ownerKey: '["XSS","2"]',
          ownerId: 1, scopeKey: 'email', parentGeneration: '9', childGeneration: '0' }) };
    }, assertCurrent: async () => {}, finish: async context => { finished = { ...context }; } };
  const coordinator = createRunCoordinator({ family: 'XSS', ledger });
  await assert.rejects(coordinator.run(1, { scope: { userId: 1, scopeKey: 'email' } }, () => { executed = true; }), /invalid scoped admission fields/);
  assert.equal(executed, false);
  assert.equal(finished.runId, issued.runId);
  assert.equal(finished.ownerKey, issued.ownerKey);
});
