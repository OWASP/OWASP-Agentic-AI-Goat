'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { projectWorkshopChallenges } = require('../server/services/workshopChallengeProjection');

function main(overrides = {}) {
  return { id: 'reflected_xss_llm', challengeKey: 'reflected_xss_llm', workshopKey: 'xss_workshop',
    name: 'Instructor XSS title', title: 'Instructor XSS title', route: '/vulnerabilities/xss',
    status: 'completed', canonicalStatus: 'completed', completed: true, completedAt: '2026-09-01T00:00:00Z',
    objectiveCount: 1, completedObjectiveCount: 1, timeSpentSeconds: 11, showHints: true, showSolutions: true,
    objectives: [{ id: 'xss_r1', completed: true, hintVisible: true, solutionVisible: true }], ...overrides };
}
function builder(overrides = {}) {
  return { id: 'xss_email_builder', challengeKey: 'xss_email_builder', workshopKey: 'xss_email_builder',
    name: 'XSS Email Template Builder', title: 'XSS Email Template Builder', route: '/vulnerabilities/xss?tab=email_builder',
    status: 'in_progress', canonicalStatus: 'in_progress', completed: false,
    objectiveCount: 2, completedObjectiveCount: 1, timeSpentSeconds: 29, showHints: false, showSolutions: true,
    objectives: [
      { id: 'xss_email_level_1', completed: true, hintVisible: false, solutionVisible: true },
      { id: 'xss_email_level_2', completed: false, hintVisible: false, solutionVisible: false },
    ], ...overrides };
}

test('XSS card folds visible families while retaining source authority and objective-specific help URLs', () => {
  const input = [builder(), { id: 'other', workshopKey: 'other', objectives: [] }, main()];
  const result = projectWorkshopChallenges(input);
  assert.deepEqual(result.map(row => row.id), ['other', 'reflected_xss_llm']);
  const card = result[1];
  assert.equal(card.title, 'Instructor XSS title');
  assert.equal(card.route, '/vulnerabilities/xss');
  assert.equal(card.workshopKey, 'xss_workshop');
  assert.equal(card.objectiveCount, 3);
  assert.equal(card.completedObjectiveCount, 2);
  assert.equal(card.timeSpentSeconds, 40);
  assert.equal(card.status, 'in_progress');
  assert.equal(card.completed, false);
  assert.equal(card.completedAt, null);
  assert.deepEqual(card.objectives.map(o => [o.id, o.workshopKey, o.challengeKey]), [
    ['xss_r1', 'xss_workshop', 'reflected_xss_llm'],
    ['xss_email_level_1', 'xss_email_builder', 'xss_email_builder'],
    ['xss_email_level_2', 'xss_email_builder', 'xss_email_builder'],
  ]);
  assert.deepEqual(card.objectives.map(o => o.solutionEndpoint), [
    '/api/solutions/xss-workshop/objective/xss_r1',
    '/api/solutions/xss-email-builder/xss_email_level_1', null,
  ]);
  assert.equal(card.objectives[1].sourceWorkshopKey, 'xss_email_builder');
  assert.equal(card.objectives[1].sourceChallengeKey, 'xss_email_builder');
  assert.deepEqual(projectWorkshopChallenges(result), result, 'projection must be idempotent');
  assert.equal(input[0].objectives[0].workshopKey, undefined, 'input stays unchanged');
});

test('builder-only visibility keeps one canonical XSS page card without restoring hidden main objectives', () => {
  const [card] = projectWorkshopChallenges([builder()]);
  assert.equal(card.id, 'reflected_xss_llm');
  assert.equal(card.title, 'XSS in AI Powered Chat System');
  assert.equal(card.route, '/vulnerabilities/xss');
  assert.equal(card.objectiveCount, 2);
  assert.deepEqual(card.objectives.map(o => o.id), ['xss_email_level_1', 'xss_email_level_2']);
  assert.equal(card.timeSpentSeconds, 29);
  assert.equal(card.status, 'in_progress');
});

test('fully complete visible XSS objectives produce one completed card; hidden builder contributes nothing', () => {
  const onlyMain = projectWorkshopChallenges([main()]);
  assert.equal(onlyMain.length, 1);
  assert.equal(onlyMain[0].objectiveCount, 1);
  assert.equal(onlyMain[0].timeSpentSeconds, 11);
  const [complete] = projectWorkshopChallenges([main(), builder({
    status: 'completed', canonicalStatus: 'completed', completed: true,
    completedAt: '2026-09-02T00:00:00Z', objectiveCount: 1, completedObjectiveCount: 1,
    objectives: [{ id: 'xss_email_level_1', completed: true, solutionVisible: true }],
  })]);
  assert.equal(complete.status, 'completed');
  assert.equal(complete.completed, true);
  assert.equal(complete.completedAt, '2026-09-02T00:00:00Z');
  assert.equal(complete.objectiveCount, 2);
  assert.equal(complete.completedObjectiveCount, 2);
});
