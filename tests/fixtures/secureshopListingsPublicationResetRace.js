'use strict';
// Fixture-only instrumentation: all effects and cleanup use production repositories.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
function createPublicationBarrier(pool) {
  let release, entered, publisherPid, fired = false;
  const held = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  const wrapped = {
    query: (...args) => pool.query(...args),
    async connect() {
      const client = await pool.connect();
      return {
        release: (...args) => client.release(...args),
        async query(...args) {
          const result = await client.query(...args);
          if (!fired && String(args[0]).startsWith('SELECT secureshop_review.publish_owned_listing_import(')) {
            fired = true; publisherPid = client.processID;
            // Snapshot inside the uncommitted publication transaction.
            const publication = (await client.query('SELECT * FROM secureshop_review.owned_listing_publications WHERE operation_id=$1', [args[1][0]])).rows[0];
            const events = (await client.query('SELECT event_id,sequence,state,payload_sha256 FROM secureshop_review.owned_listing_events WHERE operation_id=$1 ORDER BY sequence', [args[1][0]])).rows;
            entered({ publisherPid, publication, events });
            await held;
          }
          return result;
        }
      };
    }
  };
  return { pool: wrapped, started, release, get publisherPid() { return publisherPid; } };
}
async function qualifyPublicationResetRace({ barrier, run, replay, review, identity, launches, admission, request, sibling }) {
  const authority = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identity);
  let cleanupPid, signalCleanup;
  const cleanupStarted = new Promise(resolve => { signalCleanup = resolve; });
  const cleanupPool = {
    query: (...args) => review.query(...args),
    async connect() {
      const client = await review.connect();
      return { release: (...args) => client.release(...args), query(...args) {
        const pending = client.query(...args);
        if (String(args[0]).includes('FROM secureshop_review.product_targets') && String(args[0]).includes('FOR UPDATE')) {
          cleanupPid = client.processID; signalCleanup();
        }
        return pending;
      } };
    }
  };
  const products = require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(cleanupPool, {
    checkCurrent: value => launches.assertCurrent(value), checkCleanup: value => authority.checkProductTarget(value)
  });
  const snapshotSibling = async () => (await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id', [sibling.targetId])).rows;
  const siblingBefore = await snapshotSibling();
  const publicationsBefore = (await review.query('SELECT * FROM secureshop_review.owned_listing_publications ORDER BY operation_id')).rows;
  const completionBefore = (await identity.query('SELECT * FROM workshop_platform.completions ORDER BY user_id,workshop_key,objective_id')).rows;
  const execution = run().then(value => ({ value }), error => ({ error }));
  let cleanup, held, reset, lockProof;
  try {
    held = await Promise.race([barrier.started, execution.then(() => { throw Error('Publication did not reach SQL barrier'); })]);
    assert.ok(held.publication); assert.equal(held.events.at(-1).state, 'completed');
    reset = await launches.beginReset({ ...admission.scope, expectedGeneration: admission.scope.generation, idempotencyKey: randomUUID() });
    await assert.rejects(launches.assertCurrent(admission.scope));
    cleanup = products.cleanup({ ...admission.scope, targetId: admission.targetId }, { operationId: reset.resetId }).then(value => ({ value }), error => ({ error }));
    await Promise.race([cleanupStarted, cleanup.then(() => { throw Error('Cleanup did not reach target lock'); })]);
    const deadline = Date.now() + 2000;
    do {
      // Actual server lock graph establishes contention; elapsed time is never proof.
      const row = (await review.query('SELECT $1::integer AS cleanup_pid, $2::integer AS publisher_pid, pg_blocking_pids($1::integer) AS blockers', [cleanupPid, held.publisherPid])).rows[0];
      if (row.blockers.includes(held.publisherPid)) { lockProof = row; break; }
    } while (Date.now() < deadline);
    assert.ok(lockProof, 'Canonical cleanup must block on the live publication transaction');
    assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_publications WHERE operation_id=$1', [request.request.operationId])).rows[0].n, 0, 'Uncommitted publication must remain invisible');
  } finally {
    barrier.release();
    await Promise.all([execution, ...(cleanup ? [cleanup] : [])]);
  }
  const executionResult = await execution, cleaned = await cleanup;
  if (cleaned.error) throw cleaned.error;
  assert.ok(executionResult.error, 'Reset must prevent stale actor success');
  await assert.rejects(replay());
  const finalPublication = (await review.query('SELECT * FROM secureshop_review.owned_listing_publications WHERE operation_id=$1', [request.request.operationId])).rows[0];
  assert.deepEqual(finalPublication, held.publication);
  const finalEvents = (await review.query('SELECT event_id,sequence,state,payload_sha256,payload_json,redacted_at FROM secureshop_review.owned_listing_events WHERE operation_id=$1 ORDER BY sequence', [request.request.operationId])).rows;
  assert.deepEqual(finalEvents.map(({ payload_json, redacted_at, ...immutable }) => immutable), held.events);
  assert.ok(finalEvents.every(row => row.payload_json === null && row.redacted_at));
  const retired = (await review.query('SELECT lifecycle FROM secureshop_review.product_targets WHERE target_id=$1', [admission.targetId])).rows[0];
  assert.equal(retired.lifecycle, 'retired');
  assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.product_target_products WHERE target_id=$1', [admission.targetId])).rows[0].n, 0);
  const redacted = (await review.query('SELECT request_json,redacted_at FROM secureshop_review.owned_listing_admissions WHERE operation_id=$1', [request.request.operationId])).rows[0];
  assert.equal(redacted.request_json, null); assert.ok(redacted.redacted_at);
  const receipt = (await review.query('SELECT * FROM secureshop_review.owned_listing_cleanup_receipts WHERE target_id=$1', [admission.targetId])).rows[0];
  assert.equal(receipt.operation_count, 1); assert.equal(receipt.event_count, held.events.length);
  assert.deepEqual(await snapshotSibling(), siblingBefore);
  assert.deepEqual((await review.query('SELECT * FROM secureshop_review.owned_listing_publications WHERE operation_id<>$1 ORDER BY operation_id', [request.request.operationId])).rows, publicationsBefore);
  assert.deepEqual((await identity.query('SELECT * FROM workshop_platform.completions ORDER BY user_id,workshop_key,objective_id')).rows, completionBefore);
  return { actualModelCalls: 0, lockProof, resetId: reset.resetId, actorError: executionResult.error.code || executionResult.error.name,
    cleanupReceipt: receipt, publicationReceipt: finalPublication, immutableEventsPreserved: true, siblingPreserved: true,
    staleReplayRejected: true, completionRowsUnchanged: true, retiredProducts: 0,
    limitations: ['Target cleanup qualified; full reset reconciliation/commit is outside this case', 'No actual model, browser, or Judge-credit qualification'] };
}
module.exports = { createPublicationBarrier, qualifyPublicationResetRace };
