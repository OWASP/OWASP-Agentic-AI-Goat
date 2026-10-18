'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CHECKS, assertWorkshopUxReceipt, assertChallengeParity } = require('./fixtures/fullBackendRenderedUx');

test('rendered UX receipt requires every browser and isolation check without model-credit claims', () => {
  const receipt = { scope: 'rendered_platform_workshop_ux', passed: true,
    controlledProjectionOnly: true, actualModelProof: false,
    checks: Object.fromEntries(CHECKS.map(key => [key, true])) };
  assert.equal(assertWorkshopUxReceipt(receipt), receipt);
  for (const altered of [
    { ...receipt, actualModelProof: true },
    { ...receipt, controlledProjectionOnly: false },
    { ...receipt, checks: { ...receipt.checks, effectiveSolutionGate: false } },
    { ...receipt, checks: Object.fromEntries(CHECKS.slice(1).map(key => [key, true])) },
  ]) assert.throws(() => assertWorkshopUxReceipt(altered));
});

test('catalog parity compares actual objective text, totals, completion, and time', () => {
  const sql = { workshopKey: 'sql_injection_workshop', objectiveCount: 2,
    completedObjectiveCount: 1, timeSpentSeconds: 30,
    objectives: [
      { id: 'sqli_1', label: 'Edited title', text: 'Edited title', description: 'Edited description', completed: true },
      { id: 'sqli_2', label: 'Second', text: 'Second', description: '', completed: false },
    ] };
  const rows = [sql, { workshopKey: 'nosql_injection_workshop', objectiveCount: 1,
    completedObjectiveCount: 0, timeSpentSeconds: 12,
    objectives: [{ id: 'nosqli_1', label: 'NoSQL', completed: false }] }];
  const challenges = { challenges: rows }, progress = { challenges: structuredClone(rows) };
  const stats = { totalObjectives: 3, completedObjectives: 1, totalTime: 42 };
  assert.equal(assertChallengeParity(challenges, progress, stats,
    { label: 'Edited title', description: 'Edited description' }), sql);
  assert.throws(() => assertChallengeParity(challenges, progress, { ...stats, totalTime: 41 },
    { label: 'Edited title', description: 'Edited description' }));
  assert.throws(() => assertChallengeParity(challenges, progress, stats,
    { label: 'Stale title', description: 'Edited description' }));
});
