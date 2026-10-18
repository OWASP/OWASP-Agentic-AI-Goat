const test = require('node:test');
const assert = require('node:assert/strict');

const { createAdminChangeRecorder, resolveAdminChangeScope } = require('../server/services/adminChangeRevision');

test('exercise visibility changes use global and workshop aliases resolve to canonical scopes', () => {
  assert.deepEqual(resolveAdminChangeScope({ type: 'challengeVisibility' }), {
    scopeType: 'global', scopeKey: '*', category: 'admin_visibility',
  });
  assert.deepEqual(resolveAdminChangeScope({ type: 'solutionVisibility', workshopKey: 'mcp_server_rce' }), {
    scopeType: 'workshop', scopeKey: 'mcp_workshop', category: 'admin_visibility',
  });
});

test('every workshop challenge alias resolves to the canonical open-lab scope', () => {
  const aliases = {
    reflected_xss_llm: 'xss_workshop',
    csrf_prompt_injection: 'csrf_workshop',
    mcp_server_rce: 'mcp_workshop',
    direct_prompt_injection: 'direct_prompt_injection',
    indirect_prompt_injection: 'indirect_prompt_injection',
    sql_injection_workshop: 'sql_injection_workshop',
    nosql_injection_workshop: 'nosql_injection_workshop',
    sensitive_info_disclosure: 'sensitive_info_disclosure',
    supply_chain_rce: 'supply_chain_rce',
    excessive_agency: 'excessive_agency',
  };

  for (const [workshopKey, expected] of Object.entries(aliases)) {
    assert.equal(resolveAdminChangeScope({ type: 'solutionVisibility', workshopKey }).scopeKey, expected);
  }
});

test('failed mutations never reach recorder while successful mutations signal once', async () => {
  const bumps = [];
  const recorder = createAdminChangeRecorder({ async bump(scope) { bumps.push(scope); } });
  const mutateThenRecord = async (mutation, change) => {
    await mutation();
    await recorder.record(change);
  };

  await assert.rejects(
    mutateThenRecord(async () => { throw new Error('write failed'); }, {
      type: 'hintVisibility', workshopKey: 'xss_workshop',
    }),
    /write failed/
  );
  assert.equal(bumps.length, 0);

  await mutateThenRecord(async () => {}, {
    type: 'hintVisibility', workshopKey: 'xss_workshop',
  });
  assert.equal(bumps.length, 1);
});

test('targeted admin changes use only their selected attendee scope', () => {
  assert.deepEqual(resolveAdminChangeScope({ type: 'progressReset', targetUserId: 101 }), {
    scopeType: 'user', scopeKey: '101', category: 'admin_visibility',
  });
});

test('recorder persists a resolved revision before completing', async () => {
  const bumps = [];
  const recorder = createAdminChangeRecorder({ async bump(change) { bumps.push(change); } });
  assert.equal(await recorder.record({ type: 'hintVisibility', workshopKey: 'mcp_workshop' }), true);
  assert.deepEqual(bumps, [{ scopeType: 'workshop', scopeKey: 'mcp_workshop', category: 'admin_visibility' }]);
});

test('recorder retries a failed signal with bounded backoff and coalesces a scope', async () => {
  const tasks = [];
  let attempts = 0;
  const recorder = createAdminChangeRecorder({
    async bump() { attempts += 1; if (attempts === 1) throw new Error('temporary contention'); },
  }, { error() {} }, {
    setTimeout(callback, delay) {
      const task = { callback, delay, unref() {} };
      tasks.push(task);
      return task;
    },
  });

  assert.equal(await recorder.record({ type: 'hintVisibility', workshopKey: 'mcp_workshop' }), false);
  assert.equal(tasks.length, 1);
  assert.equal(tasks[0].delay, 1000);
  await tasks.shift().callback();
  assert.equal(attempts, 2);
  assert.equal(tasks.length, 0);
});
