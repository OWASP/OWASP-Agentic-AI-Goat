'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundReviewRepository } = require('../server/database/postgres/secureshopBoundReviewRepository');

const scope = Object.freeze({
  targetId: '10000000-0000-4000-8000-000000000081',
  launchId: '20000000-0000-4000-8000-000000000081',
  scenarioId: '30000000-0000-4000-8000-000000000081', generation: 4,
  platformOwnerId: 81, platformSessionId: 801,
});
const submission = Object.freeze({ submissionId: '40000000-0000-4000-8000-000000000081',
  productId: 7, authorId: 999, body: 'raw\0-ish text π <script>sink()</script>', rating: 1 });

function fixture({ enabled = true } = {}) {
  let row = null; let nextId = 17; let inserts = 0; let checks = 0;
  const client = {
    async query(sql, params = []) {
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [], rowCount: 0 };
      if (sql.includes('FROM secureshop_review.review_targets')) {
        return { rows: [{ target_id: scope.targetId, lifecycle: 'active', seed_count: 0, seed_sha256: Buffer.alloc(32) }] };
      }
      if (sql.includes('WHERE target_id=$1 AND submission_id=$2')) return { rows: row ? [row] : [] };
      if (sql.includes('count(*)::integer AS count')) return { rows: [{ count: row ? 1 : 0 }] };
      if (sql.includes('INSERT INTO secureshop_review.reviews')) {
        inserts += 1;
        row = { id: String(nextId++), target_id: params[0], product_id: params[1], author_id: params[2],
          body: params[3], rating: params[4], source_kind: 'learner', source_version: 1,
          submission_id: params[5], request_sha256: params[6], body_sha256: params[7],
          submitted_by_shop_user_id: params[8], submitted_by_shop_role: params[9],
          status: 'pending', created_at: new Date('2026-09-13T12:00:00Z') };
        return { rows: [row], rowCount: 1 };
      }
      if (sql.includes('WHERE target_id=$1 AND id=$2')) return { rows: row && Number(row.id) === params[1] ? [{...row,...(sql.includes('created_at_micros')?{created_at_micros:String(BigInt(row.created_at.getTime())*1000n)}:{})}] : [] };
      throw new Error(`unexpected SQL: ${sql}`);
    }, release() {},
  };
  const repository = createSecureShopBoundReviewRepository({ query: (...args) => client.query(...args),
    async connect() { return client; } }, {
    enableLearnerSubmissions: enabled,
    async checkCurrent(value) { checks += 1; assert.deepEqual(value, scope); },
    async checkRetirement() {}, async checkCleanup() {},
  });
  return { repository, inserts: () => inserts, checks: () => checks };
}

test('stores raw learner content while keeping authenticated persona distinct from author_id', async () => {
  const f = fixture();
  const first = await f.repository.submitReview(scope, { id: 42, role: 'customer' }, submission);
  assert.equal(first.created, true);
  assert.equal(first.body, submission.body);
  assert.equal(first.authorId, 999);
  assert.equal(first.submittedByShopUserId, 42);
  assert.equal(first.submittedByShopRole, 'customer');
  assert.match(first.bodySha256, /^[a-f0-9]{64}$/);
  assert.match(first.requestSha256, /^[a-f0-9]{64}$/);
  assert.equal(f.inserts(), 1);

  const replay = await f.repository.submitReview(scope, { id: 42, role: 'customer' }, submission);
  assert.equal(replay.created, false);
  assert.equal(replay.reviewId, first.reviewId);
  assert.equal(f.inserts(), 1);
  assert.deepEqual(await f.repository.readSubmission(scope, first.reviewId), {...replay,createdAtMicros:String(BigInt(replay.createdAt.getTime())*1000n)});

  await assert.rejects(f.repository.submitReview(scope, { id: 42, role: 'customer' },
    { ...submission, body: `${submission.body}!` }), { code: 'REVIEW_SUBMISSION_CONFLICT' });
});

test('submission feature and closed inputs fail before database access', async () => {
  const disabled = fixture({ enabled: false });
  await assert.rejects(disabled.repository.submitReview(scope, { id: 42, role: 'customer' }, submission),
    { code: 'REVIEW_SUBMISSIONS_UNAVAILABLE' });
  assert.equal(disabled.checks(), 0);

  const enabled = fixture();
  for (const [persona, input] of [
    [{ id: 42, role: 'customer', ownerId: 81 }, submission],
    [{ id: 42, role: 'viewer' }, submission],
    [{ id: 42, role: 'customer' }, { ...submission, platformOwnerId: 81 }],
  ]) {
    await assert.rejects(enabled.repository.submitReview(scope, persona, input), { code: 'INVALID_ARGUMENT' });
  }
  assert.equal(enabled.checks(), 0);
});


test('review admission clock preserves database microseconds and rechecks owner after read without provisioning',async()=>{
 let revoked=false,queries=0,checks=0;const expected='1790806543970999';
 const pool={async query(sql){queries++;assert.equal(sql,'SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::text AS admitted_at_micros');return {rows:[{admitted_at_micros:expected}]};},async connect(){throw Error('No target transaction required');}};
 const deps={async checkCurrent(actual){checks++;assert.equal(actual.launchId,scope.launchId);if(revoked)throw Error('stale owner');},async checkRetirement(){},async checkCleanup(){}};
 const repo=createSecureShopBoundReviewRepository(pool,deps);assert.equal(await repo.captureReviewAdmissionTime(scope),expected);assert.equal(checks,2);assert.equal(queries,1);
 pool.query=async()=>{revoked=true;return {rows:[{admitted_at_micros:expected}]};};await assert.rejects(repo.captureReviewAdmissionTime(scope),/stale owner/);
 revoked=false;pool.query=async()=>({rows:[{admitted_at_micros:null}]});await assert.rejects(repo.captureReviewAdmissionTime(scope),{code:'REVIEW_ADMISSION_TIME_UNAVAILABLE'});
});
