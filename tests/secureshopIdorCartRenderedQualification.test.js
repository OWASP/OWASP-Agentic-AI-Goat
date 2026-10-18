'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { V10_BROWSER_SCOPE, V10_BROWSER_FLAGS, assertV10CartBrowserReceipt } =
  require('./postgres/secureshopStandaloneIdorLessonRendered.integration.test');

test('V10-only receipt binds exactly one cart objective and preserves lifecycle fences', () => {
  const receipt = Object.fromEntries(V10_BROWSER_FLAGS.map(key => [key, true]));
  Object.assign(receipt, { scope: V10_BROWSER_SCOPE, actorCalls: 4, judgeCalls: 1,
    roleTurns: 2, genuineCredit: 1, errors: [] });
  assert.equal(assertV10CartBrowserReceipt(receipt), receipt);
  for (const changed of [
    { ...receipt, renderedCartDeletion: false },
    { ...receipt, actorCalls: 3 },
    { ...receipt, judgeCalls: 0 },
    { ...receipt, roleTurns: 4 },
    { ...receipt, genuineCredit: 2 },
    { ...receipt, renderedOrderDisclosure: true },
  ]) assert.throws(() => assertV10CartBrowserReceipt(changed));
});

test('V10 rendered turn requires completed request and result in their distinct cards', () => {
  const fixture = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopStandaloneIdorLessonRendered.integration.test.js'), 'utf8');
  assert.match(fixture, /const savedCard = document\.querySelector\(\s*'section\[aria-label="Saved access-control lesson request"\]'/);
  assert.match(fixture, /const lessonCard = document\.querySelector\(\s*'section\[aria-label="Customer access control lesson"\]'/);
  assert.match(fixture, /const visible = card => Boolean\(card && card\.getClientRects\(\)\.length/);
  assert.match(fixture, /visible\(savedCard\) && visible\(lessonCard\)/);
  assert.match(fixture, /\(savedCard\.textContent \|\| ''\)\.includes\(completedLabel\)/);
  assert.match(fixture, /\(lessonCard\.textContent \|\| ''\)\.includes\(expectedResult\)/);
  assert.match(fixture, /completedLabel: 'Saved customer request · completed'/);
});

test('V10 reset records no surviving projected completion from its retired launch', () => {
  const fixture = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopStandaloneIdorLessonRendered.integration.test.js'), 'utf8');
  assert.match(fixture, /assert\.equal\(cleanup\[0\]\.retired_contribution_count, EXPECTED_CREDIT\)/);
  assert.match(fixture, /assert\.equal\(cleanup\[0\]\.projected_completion_count, 0\)/);
  assert.match(fixture, /assert\.deepEqual\(await assessmentRows\('assessment_completions', objectiveId\),\s*ownerCompletions\[objectiveId\]\)/);
});
