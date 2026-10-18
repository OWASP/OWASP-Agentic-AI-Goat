'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { projectBoundReviewModeration } = require('../server/services/secureshopReviewRunProjection');
function hop(overrides = {}, rowOverrides = {}, outcomeOverrides = {}) {
  const row = { id: 17, product_id: 3, status: 'approved', moderator_kind: 'auto', moderator_notes: null, ...rowOverrides };
  return { tool: 'review-moderator.approve', params: { review_id: 17 },
    result: { content: [{ type: 'text', text: JSON.stringify({ ok: true, applied: true, review: row, ...outcomeOverrides }) }] },
    ...overrides };
}
test('projects applied decisions from this run and preserves partial terminal status', () => {
  const result = projectBoundReviewModeration({ stopReason: 'max_steps', hops: [hop(),
    hop({ tool: 'review-moderator.reject' }, { status: 'rejected', moderator_notes: '<raw reason>' })] });
  assert.equal(result.ok, false); assert.equal(result.processed, 2);
  assert.deepEqual(result.decisions.map(d => d.applied_decision), ['approve', 'reject']);
  assert.equal(result.decisions[1].notes, '<raw reason>');
  assert.equal(Object.isFrozen(result.decisions[0].applied), true);
});
test('prose, observation payloads, failed, manual and mismatched effects never count', () => {
  const result = projectBoundReviewModeration({ stopReason: 'end_turn', text: 'Approved 999 reviews', hops: [
    hop({ tool: 'review-moderator.moderate_pending' }), hop({ error: { message: 'failed' } }),
    hop({}, { moderator_kind: 'manual' }), hop({}, { id: 18 }), hop({}, { status: 'pending' }),
    hop({}, {}, { applied: false }), hop({}, {}, { ok: false }),
    hop({ result: { isError: true, content: [] } }), hop({ result: { content: [{ type: 'text', text: '{' }] } }),
  ] });
  assert.equal(result.processed, 0); assert.deepEqual(result.decisions, []);
});
test('exact request replay projects retained results without synthesizing new work', () => {
  const run = { stopReason: 'end_turn', hops: [hop()], replayed: true };
  const before = JSON.stringify(run); const first = projectBoundReviewModeration(run);
  assert.deepEqual(projectBoundReviewModeration(run), first);
  assert.equal(first.replayed, true); assert.equal(JSON.stringify(run), before);
});

test('public moderation projection forwards only the persisted feature capability', () => {
  const modeCapability = Object.freeze({ version: 1, featureId: 'review',
    policyVersion: 'product-feedback-enforced-decision-v1', effectiveMode: 'fixed',
    scope: Object.freeze({ kind: 'launch_feature', id: 'review' }) });
  const branded = projectBoundReviewModeration({ stopReason: 'end_turn', hops: [], modeCapability });
  assert.equal(branded.modeCapability, modeCapability);
  const historical = projectBoundReviewModeration({ stopReason: 'end_turn', hops: [] });
  assert.equal(Object.hasOwn(historical, 'modeCapability'), false);
});

test('trusted batch metadata gates new-run success and hides the server run id', () => {
  const run = { stopReason: 'end_turn', hops: [], replayed: false,
    taskMetadata: { reviewBatch: { contract: 'bound-review-batch-v1', runId: 'trusted-run',
      requested: 100, considered: 2, complete: false, continuationRequired: false } } };
  assert.deepEqual(projectBoundReviewModeration(run), { ok: false, processed: 0, decisions: [],
    stopReason: 'end_turn', replayed: false,
    batch: { requested: 100, considered: 2, complete: false, continuationRequired: false } });
  run.taskMetadata.reviewBatch.complete = true;
  run.taskMetadata.reviewBatch.continuationRequired = true;
  const completed = projectBoundReviewModeration(run);
  assert.equal(completed.ok, true);
  assert.deepEqual(completed.batch, { requested: 100, considered: 2, complete: true,
    continuationRequired: true });
});
