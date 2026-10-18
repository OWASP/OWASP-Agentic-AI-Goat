'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

function fixture() {
  return {
    commerce: {
      state: {
        reviews: [
          { id: 1, rating: 5, body: 'Excellent product', status: 'pending' },
          { id: 2, rating: 1, body: 'This is spam with a scam link', status: 'pending' },
          { id: 3, rating: 2, body: 'Awful and terrible', status: 'pending' },
        ],
      },
      methods: {
        review_moderator_moderate_pending_3: async ({ state }, limit) => (
          state.reviews.filter((review) => review.status === 'pending').slice(0, limit)
        ),
        review_moderator_approve_1: async ({ state }, reviewId) => {
          const review = state.reviews.find((candidate) => candidate.id === reviewId);
          if (!review) return { changes: 0 };
          review.status = 'approved';
          return { changes: 1 };
        },
        review_moderator_reject_2: async ({ state }, _reason, reviewId) => {
          const review = state.reviews.find((candidate) => candidate.id === reviewId);
          if (!review) return { changes: 0 };
          review.status = 'rejected';
          return { changes: 1 };
        },
      },
    },
  };
}

test('moderate_pending classifies reviews and awaits explicit repository mutations', async () => {
  await withPostgresRepositoryDoubles(fixture(), async (scope) => {
    const tool = scope.loadFresh('agent-host/agents/review-moderator/tools/index.js');
    const result = await tool.moderate_pending({ limit: 3 });

    assert.equal(result.ok, true);
    assert.equal(result.processed, 3);
    assert.deepEqual(result.decisions.map((entry) => entry.applied_decision), ['approve', 'reject', 'approve']);
    assert.deepEqual(scope.commerceState.reviews.map((review) => review.status), [
      'approved',
      'rejected',
      'approved',
    ]);
    assert.deepEqual(scope.calls.map((call) => call.method), [
      'review_moderator_moderate_pending_3',
      'review_moderator_approve_1',
      'review_moderator_reject_2',
      'review_moderator_approve_1',
    ]);
  });
});

test('approve and reject expose repository mutation outcomes without SQL emulation', async () => {
  await withPostgresRepositoryDoubles(fixture(), async (scope) => {
    const tool = scope.loadFresh('agent-host/agents/review-moderator/tools/index.js');

    assert.deepEqual(await tool.approve({ review_id: 1 }), { ok: true, review_id: 1 });
    assert.deepEqual(await tool.reject({ review_id: 2 }), { ok: true, review_id: 2 });
    assert.deepEqual(scope.commerceState.reviews.slice(0, 2).map((review) => review.status), [
      'approved',
      'rejected',
    ]);
  });
});
