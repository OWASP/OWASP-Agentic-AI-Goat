'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createSecureShopAssessmentProgress } = require('../server/services/secureshopAssessmentProgress');

const principal = randomUUID();
const peer = randomUUID();
const base = Object.freeze({ opaque: 'branded-by-standalone-auth' });
const progress = ({ principalId = principal, role = 'customer', completed = true } = {}) => ({
  principalId, shopUserId: principalId === principal ? 1000000001 : 1000000002,
  username: principalId === principal ? 'customer_one' : 'merchant_two', role, generation: 4,
  objectives: [{ objectiveId: 'ss_sqli_coupon', label: 'Coupon SQL', completed }],
  totalObjectives: 1, completedObjectives: completed ? 1 : 0,
});

function fixture() {
  const calls = [];
  const repository = {
    async readSelf(input) { calls.push(['self', input]); return progress(); },
    async readLearner(input) { calls.push(['learner', input]); return progress({ principalId: input.targetPrincipalId, role: 'admin' }); },
    async listLearners(input) { calls.push(['list', input]); return { learners: [progress(), progress({ principalId: peer, role: 'merchant', completed: false })], nextCursor: null }; },
  };
  return { calls, repository, service: createSecureShopAssessmentProgress({ repository }) };
}

test('self progress forwards only the branded standalone-auth context and projects no evidence', async () => {
  const f = fixture();
  const result = await f.service.readSelf(base);
  assert.deepEqual(f.calls, [['self', { base }]]);
  assert.deepEqual(result, progress());
  assert.deepEqual(Object.keys(result).sort(), ['completedObjectives', 'generation', 'objectives', 'principalId', 'role', 'shopUserId', 'totalObjectives', 'username']);
  assert.deepEqual(Object.keys(result.objectives[0]).sort(), ['completed', 'label', 'objectiveId']);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.objectives), true);
});

test('per-principal and paged admin projections use closed input and preserve repository authority', async () => {
  const f = fixture();
  const learner = await f.service.readLearner(base, { targetPrincipalId: peer.toUpperCase() });
  const page = await f.service.listLearners(base, { limit: 25, cursor: 1000000000 });
  const defaultPage = await f.service.listLearners(base);
  assert.deepEqual(f.calls, [
    ['learner', { base, targetPrincipalId: peer }],
    ['list', { base, limit: 25, cursor: 1000000000 }],
    ['list', { base, limit: 25, cursor: null }],
  ]);
  assert.equal(learner.principalId, peer);
  assert.equal(learner.role, 'admin');
  assert.equal(page.learners.length, 2);
  assert.equal(page.learners[1].completedObjectives, 0);
  assert.equal(page.nextCursor, null);
  assert.equal(defaultPage.learners.length, 2);
});

test('malformed input and repository data fail closed without widening progress disclosure', async () => {
  const f = fixture();
  await assert.rejects(f.service.readLearner(base, { targetPrincipalId: principal, tenantId: randomUUID() }), { code: 'SHOP_PROGRESS_UNAVAILABLE' });
  await assert.rejects(f.service.listLearners(base, { limit: 51, cursor: null }), { code: 'SHOP_PROGRESS_UNAVAILABLE' });
  await assert.rejects(f.service.listLearners(base, { limit: 1, cursor: -1 }), { code: 'SHOP_PROGRESS_UNAVAILABLE' });
  assert.deepEqual(f.calls, []);

  f.repository.readSelf = async () => ({ ...progress(), evidence: { leaked: true } });
  await assert.rejects(f.service.readSelf(base), { code: 'SHOP_PROGRESS_UNAVAILABLE' });
  f.repository.listLearners = async () => ({ learners: [progress(), progress()], nextCursor: null });
  await assert.rejects(f.service.listLearners(base, { limit: 25, cursor: null }), { code: 'SHOP_PROGRESS_UNAVAILABLE' });
});

test('requires the current repository authority boundary rather than a replacement session parser', () => {
  assert.throws(() => createSecureShopAssessmentProgress({ repository: { readSelf() {} } }), /progress repository/i);
});
