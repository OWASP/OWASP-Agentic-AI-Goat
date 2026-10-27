'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundReviewModeration, withBoundReviewPolicy } = require('../server/services/secureshopBoundReviewModeration');
const scope = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1, platformOwnerId: 4, platformSessionId: 8 };
const requestId = '30000000-0000-4000-8000-000000000001';
function fixture(options = {}) {
  const calls = [];
  const dependencies = { conversations: { async create(s, p, purpose) { calls.push(['create', s, p, purpose]); return { id: 'session' }; } },
    runner: { async run(input) { calls.push(['run', input]); return { stopReason: 'end_turn', hops: [], replayed: true }; } } };
  return { calls, dependencies, service: createBoundReviewModeration({ ...dependencies, ...options }) };
}
test('server task captures dual identity and stable request for journaled runner', async () => {
  const f = fixture(); const result = await f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId, limit: 7 });
  assert.deepEqual(f.calls[0], ['create', scope, { id: 5, role: 'merchant' }, 'review_moderation']);
  assert.equal(f.calls[1][1].requestId, requestId); assert.match(f.calls[1][1].message, /up to 7/);
  assert.equal(f.calls[1][1].localToolAuthority.batchLimit, 5);
  assert.deepEqual(f.calls[1][1].localToolAuthority.metadata(), {
    contract: 'bound-review-batch-v1', requested: 7, considered: 0,
    complete: false, continuationRequired: false,
  });
  assert.equal(result.replayed, true); assert.equal(result.processed, 0);
});
test('invalid request and wrong persona create no conversation or model work', async () => {
  for (const input of [{ requestId: 'bad' }, { limit: 101 }, { persona: { id: 5, role: 'customer' } }]) {
    const f = fixture(); await assert.rejects(f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId, ...input }));
    assert.deepEqual(f.calls, []);
  }
});
test('cancellation during conversation acquisition prevents runner admission', async () => {
  const f = fixture(); const controller = new AbortController();
  f.dependencies.conversations.create = async () => { controller.abort(); return { id: 'session' }; };
  await assert.rejects(f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId, signal: controller.signal }), { name: 'AbortError' });
  assert.deepEqual(f.calls, []);
});
test('policy wrapper retains existing persona and external policy content', () => {
  const wrapped = withBoundReviewPolicy((role, options) => `${role}:${options.extra}`);
  assert.match(wrapped('merchant', { extra: '<raw existing policy>' }), /^merchant:<raw existing policy>/);
  assert.match(wrapped('merchant', {}), /including negative feedback/);
});

const completedRun = { stopReason: 'end_turn', hops: [] };
test('completed exact moderation request replays without conversation or model work', async () => {
  let checks = 0;
  const f = fixture({
    checkCurrent: async () => { checks++; },
    journal: { async lookupReviewModerationRequest(input) {
      assert.equal(input.requestId, requestId); assert.match(input.message, /up to 100/);
      return { status: 'completed', result: completedRun };
    } },
  });
  const result = await f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId });
  assert.equal(result.replayed, true); assert.deepEqual(f.calls, []); assert.equal(checks, 3);
});

test('completed versioned request replays the exact bounded batch projection', async () => {
  const stored = { stopReason: 'end_turn', hops: [], taskMetadata: { reviewBatch: {
    contract: 'bound-review-batch-v1', runId: 'stored-run', requested: 7, considered: 5,
    complete: true, continuationRequired: true,
  } } };
  const f = fixture({ checkCurrent: async () => {}, journal: {
    async lookupReviewModerationRequest() { return { status: 'completed', result: stored }; },
  } });
  const result = await f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' },
    requestId, limit: 7 });
  assert.deepEqual(result.batch, { requested: 7, considered: 5, complete: true,
    continuationRequired: true });
  assert.equal(result.replayed, true);
  assert.deepEqual(f.calls, []);
});

test('started, uncertain and hash conflicts fail before model admission', async () => {
  for (const status of ['started', 'uncertain', 'conflict']) {
    const f = fixture({ journal: { async lookupReviewModerationRequest() { return { status }; } } });
    await assert.rejects(f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId }),
      { code: status === 'conflict' ? 'TURN_REQUEST_CONFLICT' : 'TURN_RECOVERY_REQUIRED' });
    assert.deepEqual(f.calls, []);
  }
  const unknown = fixture({ journal: { async lookupReviewModerationRequest() { return { status: 'mystery' }; } } });
  await assert.rejects(unknown.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId }), { code: 'TURN_REQUEST_CONFLICT' });
  assert.deepEqual(unknown.calls, []);
});

test('authority loss after legacy lookup prevents replay or new admission', async () => {
  let checks = 0;
  const f = fixture({
    checkCurrent: async () => { checks++; if (checks === 2) throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' }); },
    journal: { async lookupReviewModerationRequest() { return { status: 'completed', result: completedRun }; } },
  });
  await assert.rejects(f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId }), { code: 'STALE_LAUNCH' });
  assert.deepEqual(f.calls, []); assert.equal(checks, 2);
});

test('cancellation during final authority check prevents replay return', async () => {
  const controller = new AbortController(); let checks = 0;
  const f = fixture({
    checkCurrent: async () => { checks++; if (checks === 3) controller.abort(); },
    journal: { async lookupReviewModerationRequest() { return { status: 'completed', result: completedRun }; } },
  });
  await assert.rejects(f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId, signal: controller.signal }), { name: 'AbortError' });
  assert.deepEqual(f.calls, []);
});

test('foreign binding is treated as no match and remains undisclosed', async () => {
  const f = fixture({ journal: { async lookupReviewModerationRequest(input) {
    assert.equal(input.binding.platformOwnerId, 4); return null;
  } } });
  await f.service.moderateReviews({ scope, persona: { id: 5, role: 'merchant' }, requestId });
  assert.equal(f.calls.filter(call => call[0] === 'create').length, 1);
  assert.equal(f.calls.filter(call => call[0] === 'run').length, 1);
});
