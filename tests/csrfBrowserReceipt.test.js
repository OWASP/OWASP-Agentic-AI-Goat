'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { issueCsrfBrowserReceipt, hasCsrfBrowserReceipt, BROWSER_OBJECTIVES } = require('../server/services/csrfBrowserReceipt');
const { createCsrfObjectiveGrader } = require('../server/services/csrfObjectiveGrader');

test('browser completion rejects JSON copies and receipts from another owner, run, objective or activity', async () => {
  for (const objectiveId of BROWSER_OBJECTIVES) {
    const execution = { runId: 'private-run', ownerKey: '["CSRF","7"]', generation: 2, check: async () => {} };
    const defense = ['csrf_g3', 'csrf_p3'].includes(objectiveId);
    const vector = objectiveId.startsWith('csrf_g') ? 'direct_get' : objectiveId === 'csrf_p2' ? 'fetch' : 'direct_post';
    const activity = { result: { blocked: defense, executed: !defense, stateChanged: !defense,
      vector, defenses: { csrfToken: defense }, changed: defense ? {} : { from: 'old', to: 'new' } } };
    // Trusted issuer fixture; the composition suite proves real Chrome issuance.
    const receipt = issueCsrfBrowserReceipt({ execution, activity,
      binding: { ...execution, objectiveId, payloadDigest: 'b'.repeat(64), tab: objectiveId.startsWith('csrf_g') ? 'get' : 'post' },
      observation: { method: vector === 'direct_get' ? 'GET' : 'POST', cookiePresent: true,
        frameOrigin: 'http://attacker.csrf.invalid', resourceType: 'document' }, responseStatus: defense ? 403 : 200 });
    const packet = { receipt, execution, activity, userId: 7, objectiveId, snapshot: {} };
    assert.equal(hasCsrfBrowserReceipt(packet), true);
    const grader = createCsrfObjectiveGrader({ postgres: false, judge: async () => ({ verdict: 'pass' }) });
    assert.equal((await grader.evaluate(packet)).completed, true);
    for (const patch of [{ receipt: undefined }, { receipt: JSON.parse(JSON.stringify(receipt)) },
      { execution: { ...execution } }, { activity: { ...activity } }, { userId: 8 },
      { objectiveId: objectiveId === 'csrf_p1' ? 'csrf_p2' : 'csrf_p1' }]) {
      assert.equal(hasCsrfBrowserReceipt({ ...packet, ...patch }), false);
      assert.equal((await grader.evaluate({ ...packet, ...patch })).completed, false,
        'even a passing injected Judge cannot override missing private browser authority');
    }
    execution.generation++;
    assert.equal(hasCsrfBrowserReceipt(packet), false);
  }
});
