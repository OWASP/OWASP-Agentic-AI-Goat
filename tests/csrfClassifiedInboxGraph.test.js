'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { runCsrfInboxGraph } = require('../server/agent-runtime/csrfInboxGraph');

function fixture(overrides = {}) {
  const credits = [];
  const activities = [];
  let checks = 0;
  const execution = { check: async () => { checks++; if (overrides.cancelAt && checks >= overrides.cancelAt) throw new Error('cancelled'); },
    trace: async () => {} };
  const sandbox = { getTabState: () => ({ xssEmailRead: !!overrides.read }),
    flush: async () => {}, forge: () => { throw new Error('legacy interpreter must not run'); } };
  const deps = {
    execution,
    mailbox: { fetchEmails: async () => ({ emails: [] }) },
    mailDispatch: { retrieve: async () => ({ email: { payload: '<img onerror="email()">', body: '<img onerror="email()">', subject: 'subject', from: 'sender' } }) },
    aiService: {}, TABS: { xss: { victim: { name: 'Victim' } } }, LLM_STARTING: 'starting',
    summarizeWithHtml: async () => ({ answer: 'summary <img onerror="email()">', llmOk: true, modelGenerated: true, htmlPreserved: true, provider: 'ollama', model: 'llama3.1:8b' }),
    executeClassifiedEmail: overrides.execute || (async () => ({ qualified: false, proof: null, browser: null })),
    noteClassifiedEmailProof: overrides.note || (async () => {}),
    noteGradeReceipt: async () => {}, extractGadgetMessage: () => 'email',
    getCompleted: async () => new Set(), creditObjective: async (_owner, id) => { credits.push(id); return true; },
    recordActivity: async (...args) => activities.push(args),
  };
  return { execution, sandbox, deps, credits, activities };
}

function input(f) {
  return { userKey: 'owner', userId: 7, t: { xssInbox: 'owner@example.invalid' }, sandbox: f.sandbox,
    wantsList: false, mailScope: { userId: 7, generation: 0 }, execution: f.execution };
}

test('unqualified or malformed classified browser result leaves read state and credit untouched', async () => {
  for (const execute of [
    async () => ({ qualified: false, proof: null, browser: null }),
    async () => ({ qualified: true, proof: {}, browser: { receipt: null, activity: null } }),
  ]) {
    const f = fixture({ execute });
    const result = await runCsrfInboxGraph(input(f), f.deps);
    assert.deepEqual(f.credits, []);
    assert.equal(f.activities.length, 0);
    assert.equal(result.newlyCompleted.length, 0);
    assert.equal(result.ragHtml, null);
  }
});

test('classified browser execution failure does not fall back to interpreter forge', async () => {
  const f = fixture({ execute: async () => { throw new Error('browser unavailable'); } });
  await assert.rejects(runCsrfInboxGraph(input(f), f.deps), /browser unavailable/);
  assert.deepEqual(f.credits, []);
  assert.equal(f.activities.length, 0);
});

test('async classified-proof note failure aborts before grade and presentation', async () => {
  const f = fixture({ execute: async () => ({ qualified: true, proof: {}, browser: {
    receipt: { safe: true }, activity: { result: { stateChanged: true } },
  } }), note: async () => { await Promise.resolve(); throw new Error('proof persistence unavailable'); } });
  await assert.rejects(runCsrfInboxGraph(input(f), f.deps), /proof persistence unavailable/);
  assert.deepEqual(f.credits, []);
  assert.equal(f.activities.length, 0);
});

test('owner cancellation during classified browser stage prevents credit', async () => {
  const f = fixture({ cancelAt: 3, execute: async () => ({ qualified: true, proof: {}, browser: {
    receipt: { safe: true }, activity: { result: { stateChanged: true } },
  } }) });
  await assert.rejects(runCsrfInboxGraph(input(f), f.deps), /cancelled/);
  assert.deepEqual(f.credits, []);
  assert.equal(f.activities.length, 0);
});
