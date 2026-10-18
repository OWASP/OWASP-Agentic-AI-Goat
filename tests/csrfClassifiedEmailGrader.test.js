'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCsrfObjectiveGrader } = require('../server/services/csrfObjectiveGrader');

function execution() {
  const controller = new AbortController();
  return { runId: 'run-classified-1', ownerKey: '["CSRF","7"]', generation: 3,
    durableGeneration: '9007199254740993', signal: controller.signal,
    check: async () => controller.signal.throwIfAborted() };
}

function inputs(overrides = {}) {
  const e = execution();
  return { userId: 7, objectiveId: 'csrf_x3', execution: e,
    attempt: { generation: 3 }, snapshot: { xssEmailRead: true },
    activity: { name: 'classified email browser', result: {
      blocked: false, executed: true, stateChanged: true, kind: 'attack',
      changed: { email: 'attacker@evil.invalid' }, vector: 'xss', error: null,
    } },
    receipt: { arbitrary: 'mail receipt' }, mailReceipt: { arbitrary: 'mail receipt' },
    browserReceipt: { type: 'gadget_browser_observed', objectiveId: 'csrf_x3', tab: 'xss', responseStatus: 200 },
    classifiedEmailProof: { opaque: true }, ...overrides };
}

function mailProof() {
  return { state: 'retrieved', hasEventHandler: true, dispatchId: 'd', dispatchRunId: 'run-classified-1',
    providerMessageId: 'p', inboxMessageId: 'i', recipient: 'r', sender: 's',
    subjectDigest: 'a'.repeat(64), logicalBodyDigest: 'b'.repeat(64), payloadDigest: 'c'.repeat(64),
    htmlDigest: 'd'.repeat(64), payloadBytes: 20, logicalBodyBytes: 30, htmlBytes: 40 };
}

function classified() {
  return { version: 1, objectiveId: 'csrf_x3', generation: 3, provider: 'ollama', model: 'llama3.1:8b',
    summaryDigest: 'e'.repeat(64), gadgetDigest: 'f'.repeat(64), privateToken: 'must-not-persist' };
}

test('classified x3 requires opaque proof and emits only safe projection', async () => {
  let packet;
  const grader = createCsrfObjectiveGrader({ postgres: false,
    inspectMailProof: () => mailProof(),
    inspectBrowserReceipt: () => true,
    inspectClassifiedEmailProof: async ({ proof }) => proof === 'opaque' ? classified() : null,
    judge: async value => { packet = value; return { verdict: 'pass' }; },
  });
  const result = await grader.evaluate({ ...inputs(), classifiedEmailProof: 'opaque' });
  assert.equal(result.completed, true);
  assert.equal(packet.rubric.version, 'csrf-classified-email-v1');
  assert.equal(packet.evidence.some(item => JSON.stringify(item).includes('privateToken')), false);
  assert.deepEqual(packet.evidence.find(item => item.id === 'classified_email').content, {
    version: 1, objectiveId: 'csrf_x3', generation: 3, provider: 'ollama', model: 'llama3.1:8b',
    summaryDigest: 'e'.repeat(64), gadgetDigest: 'f'.repeat(64),
  });
});

test('missing, malformed, or stale classified proof cannot pass x3', async () => {
  let calls = 0;
  const grader = createCsrfObjectiveGrader({ postgres: false,
    inspectMailProof: () => mailProof(),
    inspectBrowserReceipt: () => true,
    inspectClassifiedEmailProof: async ({ proof }) => { calls++; return proof; },
    judge: async () => ({ verdict: 'pass' }),
  });
  for (const proof of [undefined, null, { version: 1, objectiveId: 'csrf_x3', generation: 4,
    provider: 'ollama', model: 'llama3.1:8b', summaryDigest: 'a'.repeat(64), gadgetDigest: 'b'.repeat(64) },
    { version: 1, objectiveId: 'csrf_x3', generation: 3, provider: 'fixture', model: 'llama3.1:8b',
      summaryDigest: 'a'.repeat(64), gadgetDigest: 'b'.repeat(64) }]) {
    const result = await grader.evaluate({ ...inputs(), classifiedEmailProof: proof });
    assert.equal(result.completed, false);
  }
  assert.equal(calls, 4);
});

test('execution cancellation is checked after asynchronous proof inspection', async () => {
  const e = execution();
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  const grader = createCsrfObjectiveGrader({ postgres: false,
    inspectMailProof: () => mailProof(),
    inspectClassifiedEmailProof: async () => { await waiting; return classified(); },
    judge: async () => ({ verdict: 'pass' }),
  });
  const pending = grader.evaluate({ ...inputs({ execution: e }), classifiedEmailProof: 'opaque' });
  // The controller is not exposed by the execution, so cancellation is represented
  // by replacing check for the controlled race after the inspector yields.
  let checked = false;
  e.check = async () => { checked = true; if (checked && release) throw new Error('cancelled'); };
  release();
  await assert.rejects(pending, /cancelled/);
});
