'use strict';

const { withTransaction } = require('../database/postgres');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

function owner(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw new TypeError('Valid deletion owner required');
  }
  return value;
}
function createStudentDeletionStoreCleanup({ identityPool, xssPool, finflowPool } = {}) {
  if (![identityPool, xssPool, finflowPool].every(pool => typeof pool?.query === 'function')) {
    throw new TypeError('Deletion store pools required');
  }
  const bounded = (value, label) => {
    const count = Number(value);
    if (!Number.isSafeInteger(count) || count < 0 || count > 1000000) {
      throw new Error(`Invalid ${label} deletion receipt`);
    }
    return count;
  };
  return Object.freeze({
    async codeBotExecutionAbsent({ subjectId, jobId, check, signal }) {
      const id = owner(subjectId);
      if (typeof jobId !== 'string' || !UUID.test(jobId) || typeof check !== 'function') {
        throw new TypeError('Valid deletion job and lease check required');
      }
      const ownerKey = JSON.stringify(['CodeBot', String(id)]);
      signal?.throwIfAborted(); await check();
      const proof = (await identityPool.query(`SELECT
        EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks
          WHERE owner_key=$2 AND job_id=$3::uuid) AS blocked,
        NOT EXISTS(
          SELECT 1 FROM graph_runtime.runs WHERE owner_key=$2
          UNION ALL SELECT 1 FROM graph_runtime.effects WHERE owner_key=$2
          UNION ALL SELECT 1 FROM graph_runtime.codebot_requests
            WHERE user_id=$1 OR owner_key=$2
        ) AS absent`, [id, ownerKey, jobId])).rows[0];
      signal?.throwIfAborted(); await check();
      if (proof?.blocked !== true) {
        throw Object.assign(new Error('CodeBot deletion run block is unavailable'), {
          code: 'DELETION_RUN_BLOCK_MISMATCH',
        });
      }
      if (typeof proof.absent !== 'boolean') throw new Error('Invalid CodeBot execution absence proof');
      return proof.absent;
    },
    async xss({ subjectId, check, signal }) {
      const id = owner(subjectId); signal?.throwIfAborted(); await check();
      const removed = bounded((await xssPool.query(
        'SELECT xss.destroy_student_owner($1::bigint) AS removed', [id])).rows[0]?.removed, 'XSS');
      signal?.throwIfAborted(); await check();
      return Object.freeze({ completed: true, removed });
    },
    async finflow({ subjectId, jobId, check, signal }) {
      const id = owner(subjectId); signal?.throwIfAborted(); await check();
      const removed = bounded((await finflowPool.query(
        'SELECT finflow.destroy_student_owner($1::bigint,$2::uuid) AS removed', [id, jobId])).rows[0]?.removed,
      'FinFlow');
      signal?.throwIfAborted(); await check();
      return Object.freeze({ completed: true, removed });
    },
    async identity({ subjectId, jobId, leaseToken, check, signal }) {
      const id = owner(subjectId); signal?.throwIfAborted(); await check();
      await withTransaction(identityPool, async client => {
        // The finalizer is the authority boundary: it locks and verifies the
        // exact live job/lease and requires every earlier deletion step.
        const finalized = (await client.query(
          'SELECT identity.finalize_student_deletion($1::uuid,$2::uuid,$3::integer) AS finalized',
          [jobId, leaseToken, id])).rows[0]?.finalized;
        if (finalized !== true) throw new Error('Invalid identity deletion receipt');

        // 0050 was added after the identity finalizer. The retained account
        // tombstone means its ON DELETE CASCADE never runs, so remove only the
        // owner content while retaining immutable request/run bindings.
        await client.query('DELETE FROM workshop_conversations.turns WHERE user_id=$1', [id]);
        await client.query(`UPDATE workshop_conversations.requests
          SET user_text=NULL,response_json=NULL WHERE user_id=$1`, [id]);
        const remaining = (await client.query(`SELECT
          EXISTS(SELECT 1 FROM workshop_conversations.turns WHERE user_id=$1) AS turns_remain,
          EXISTS(SELECT 1 FROM workshop_conversations.requests WHERE user_id=$1
            AND (user_text IS NOT NULL OR response_json IS NOT NULL)) AS request_content_remains`, [id])).rows[0];
        if (!remaining || remaining.turns_remain !== false || remaining.request_content_remains !== false) {
          throw new Error('MCP conversation deletion is incomplete');
        }
        // The finalizer validated and locked this row at transaction start, but
        // wall-clock lease expiry can still occur while cleanup is running.
        // Recheck the exact authority on this same client immediately before
        // commit; an external renewal check would block behind our row lock.
        const authority = (await client.query(`SELECT EXISTS(
          SELECT 1 FROM identity.student_deletion_jobs
          WHERE job_id=$1::uuid AND lease_token=$2::uuid AND subject_user_id=$3::integer
            AND state='running' AND lease_expires_at>clock_timestamp()
        ) AS current`, [jobId, leaseToken, id])).rows[0];
        if (authority?.current !== true) {
          throw Object.assign(new Error('Deletion authority expired before commit'), {
            code: 'STALE_DELETION_LEASE',
          });
        }
        // Do not call check() while the finalizer's deletion-job row lock is
        // held: renewal uses another pooled connection and would self-deadlock.
        signal?.throwIfAborted();
      });
      signal?.throwIfAborted(); await check();
      return Object.freeze({ completed: true });
    },
  });
}
module.exports = { createStudentDeletionStoreCleanup };
