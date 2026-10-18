'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { withTransaction } = require('./index');
const { lockStudentLifecycleTransaction } = require('./studentLifecycleLock');
const id = value => {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw new TypeError('Valid account ID required');
  return value;
};
const failure = code => Object.assign(new Error(code), { code });
async function assertIdentityFinalized(client, jobId, subjectId) {
  const remaining = await client.query(`SELECT id FROM identity.users WHERE id=$1 AND NOT (
    is_active=0 AND role='student' AND admin_level=0
    AND username='deleted-'||$2::uuid::text
    AND email='deleted-'||$2::uuid::text||'@invalid.local'
  )`, [subjectId, jobId]);
  if (remaining.rowCount) throw failure('DELETION_IDENTITY_REMAINS');
}

// Internal, unmounted foundation. steps is a server-owned cleanup manifest.
function createStudentDeletionRepository(pool, { steps, sceneResetPreflight } = {}) {
  if (!Array.isArray(steps) || !steps.length || steps.length > 100 || new Set(steps).size !== steps.length
    || steps.some(step => typeof step !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(step))
    || steps[0] !== 'revoke_runs' || steps.at(-1) !== 'identity') throw new TypeError('Cleanup manifest must begin with revoke_runs and end with identity');
  const manifest = [...steps];
  const uuid = value => {
    if (typeof value !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value)) throw new TypeError('Valid job token required');
    return value;
  };
  return {
    async resumeQuarantined({ requesterId, jobId }) {
      id(requesterId); uuid(jobId);
      return withTransaction(pool, async client => {
        const requester = (await client.query('SELECT role,admin_level,is_active FROM identity.users WHERE id=$1 FOR UPDATE', [requesterId])).rows[0];
        if (!requester || requester.is_active !== 1 || !['admin','super_admin'].includes(requester.role) || requester.admin_level !== 2) throw failure('ADMIN_REQUIRED');
        const job = (await client.query('SELECT state FROM identity.student_deletion_jobs WHERE job_id=$1 FOR UPDATE', [jobId])).rows[0];
        if (!job || job.state !== 'quarantined') throw failure('DELETION_NOT_QUARANTINED');
        const steps = (await client.query('SELECT step_key FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal FOR UPDATE', [jobId])).rows;
        if (steps.length !== manifest.length || steps.some((step,index) => step.step_key !== manifest[index])) throw failure('DELETION_MANIFEST_MISMATCH');
        await client.query("UPDATE identity.student_deletion_jobs SET state='pending',failure_code=NULL,updated_at=clock_timestamp() WHERE job_id=$1", [jobId]);
        return {state:'pending'};
      });
    },
    async quarantine({ jobId, leaseToken }) {
      uuid(jobId); uuid(leaseToken);
      return withTransaction(pool, async client => {
        const job = (await client.query(`SELECT job_id FROM identity.student_deletion_jobs
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp() FOR UPDATE`, [jobId,leaseToken])).rows[0];
        if (!job) throw failure('STALE_DELETION_LEASE');
        const steps = (await client.query('SELECT step_key FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal FOR UPDATE', [jobId])).rows;
        if (steps.length === manifest.length && steps.every((step,index) => step.step_key === manifest[index])) throw failure('DELETION_MANIFEST_MATCHES');
        const result = await client.query(`UPDATE identity.student_deletion_jobs
          SET state='quarantined',failure_code='DELETION_MANIFEST_MISMATCH',lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp()
          RETURNING job_id`, [jobId,leaseToken]);
        if (!result.rowCount) throw failure('STALE_DELETION_LEASE');
        return {state:'quarantined',code:'DELETION_MANIFEST_MISMATCH'};
      });
    },
    // Discovery is not a claim. Multiple processes may see the same ID; claim()
    // remains the atomic authority before any cleanup starts.
    async listRecoverable({ limit = 20, retryAfterMs = 30000 } = {}) {
      if (!Number.isInteger(limit) || limit < 1 || limit > 100
        || !Number.isInteger(retryAfterMs) || retryAfterMs < 1000 || retryAfterMs > 3600000) throw new TypeError('Invalid recovery bounds');
      const result = await pool.query(`SELECT job_id FROM identity.student_deletion_jobs
        WHERE state='pending'
          OR (state='running' AND lease_expires_at<=clock_timestamp())
          OR (state='failed' AND updated_at<=clock_timestamp()-($2 * interval '1 millisecond'))
        ORDER BY updated_at,job_id LIMIT $1`, [limit,retryAfterMs]);
      return result.rows.map(row => row.job_id);
    },
    async claim(jobId, leaseMs = 30000) {
      uuid(jobId);
      if (!Number.isInteger(leaseMs) || leaseMs < 1000 || leaseMs > 300000) throw new TypeError('Invalid lease duration');
      const token = randomUUID();
      const result = await pool.query(`UPDATE identity.student_deletion_jobs
        SET state='running',lease_token=$2,lease_expires_at=clock_timestamp()+($3 * interval '1 millisecond'),updated_at=clock_timestamp()
        WHERE job_id=$1 AND (state IN ('pending','failed') OR (state='running' AND lease_expires_at<=clock_timestamp()))
        RETURNING job_id,subject_user_id,lease_expires_at`, [jobId,token,leaseMs]);
      return result.rows[0] ? {...result.rows[0],leaseToken:token} : null;
    },
    async nextStep({ jobId, leaseToken }) {
      uuid(jobId); uuid(leaseToken);
      return withTransaction(pool, async client => {
        const job = (await client.query(`SELECT subject_user_id FROM identity.student_deletion_jobs
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp() FOR UPDATE`,[jobId,leaseToken])).rows[0];
        if (!job) throw failure('STALE_DELETION_LEASE');
        const steps = (await client.query('SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[jobId])).rows;
        if (steps.length !== manifest.length || steps.some((step,index)=>step.step_key!==manifest[index])) throw failure('DELETION_MANIFEST_MISMATCH');
        const next = steps.find(step=>step.state!=='completed');
        return next ? {subjectId:job.subject_user_id,stepKey:next.step_key} : null;
      });
    },
    async renew({ jobId, leaseToken, leaseMs = 30000 }) {
      uuid(jobId); uuid(leaseToken);
      if (!Number.isInteger(leaseMs) || leaseMs < 1000 || leaseMs > 300000) throw new TypeError('Invalid lease duration');
      const result = await pool.query(`UPDATE identity.student_deletion_jobs
        SET lease_expires_at=clock_timestamp()+($3 * interval '1 millisecond'),updated_at=clock_timestamp()
        WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp()
        RETURNING lease_expires_at`,[jobId,leaseToken,leaseMs]);
      if (!result.rowCount) throw failure('STALE_DELETION_LEASE');
      return {expiresAt:result.rows[0].lease_expires_at};
    },
    async fail({ jobId, leaseToken, stepKey }) {
      uuid(jobId); uuid(leaseToken);
      if (!manifest.includes(stepKey)) throw new TypeError('Unknown cleanup step');
      return withTransaction(pool, async client => {
        const job = (await client.query(`SELECT job_id FROM identity.student_deletion_jobs
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp() FOR UPDATE`,[jobId,leaseToken])).rows[0];
        if (!job) throw failure('STALE_DELETION_LEASE');
        const result = await client.query(`UPDATE identity.student_deletion_steps SET state='failed',error_code='CLEANUP_FAILED',attempts=attempts+1
          WHERE job_id=$1 AND step_key=$2 AND state<>'completed' RETURNING step_key`,[jobId,stepKey]);
        if (!result.rowCount) throw failure('DELETION_STEP_NOT_PENDING');
        const failed = await client.query(`UPDATE identity.student_deletion_jobs
          SET state='failed',lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp()
          RETURNING job_id`,[jobId,leaseToken]);
        if (!failed.rowCount) throw failure('STALE_DELETION_LEASE');
        return {state:'failed'};
      });
    },
    async acknowledge({ jobId, leaseToken, stepKey }) {
      uuid(jobId); uuid(leaseToken);
      if (!manifest.includes(stepKey)) throw new TypeError('Unknown cleanup step');
      return withTransaction(pool, async client => {
        const job = (await client.query(`SELECT job_id,subject_user_id FROM identity.student_deletion_jobs
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp() FOR UPDATE`,[jobId,leaseToken])).rows[0];
        if (!job) throw failure('STALE_DELETION_LEASE');
        const result = await client.query(`UPDATE identity.student_deletion_steps AS target
          SET state='completed',completed_at=clock_timestamp(),error_code=NULL,attempts=attempts+1
          WHERE target.job_id=$1 AND target.step_key=$2 AND target.state<>'completed'
          AND NOT EXISTS (SELECT 1 FROM identity.student_deletion_steps previous
            WHERE previous.job_id=target.job_id AND previous.ordinal<target.ordinal AND previous.state<>'completed')
          RETURNING step_key`,[jobId,stepKey]);
        if (!result.rowCount) {
          const prior = (await client.query('SELECT state FROM identity.student_deletion_steps WHERE job_id=$1 AND step_key=$2',[jobId,stepKey])).rows[0];
          if (prior?.state !== 'completed') throw failure('DELETION_STEP_OUT_OF_ORDER');
        }
        // Immutable launch and grading receipts retain the numeric identity.
        // Completion accepts physical absence (legacy finalizers) or only the
        // exact inactive tombstone bound to this durable deletion job.
        if (stepKey === 'identity') await assertIdentityFinalized(client, jobId, job.subject_user_id);
        const current = await client.query(`UPDATE identity.student_deletion_jobs SET updated_at=updated_at
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp()
          RETURNING job_id`,[jobId,leaseToken]);
        if (!current.rowCount) throw failure('STALE_DELETION_LEASE');
        return {completed:true};
      });
    },
    async complete({ jobId, leaseToken }) {
      uuid(jobId); uuid(leaseToken);
      return withTransaction(pool, async client => {
        const job = (await client.query(`SELECT subject_user_id FROM identity.student_deletion_jobs
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp() FOR UPDATE`,[jobId,leaseToken])).rows[0];
        if (!job) throw failure('STALE_DELETION_LEASE');
        const steps = (await client.query('SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal FOR UPDATE',[jobId])).rows;
        if (steps.length !== manifest.length || steps.some((step,index) => step.step_key !== manifest[index] || step.state !== 'completed')) throw failure('DELETION_INCOMPLETE');
        await assertIdentityFinalized(client, jobId, job.subject_user_id);
        const completed = await client.query(`UPDATE identity.student_deletion_jobs
          SET state='completed',completed_at=clock_timestamp(),updated_at=clock_timestamp(),lease_token=NULL,lease_expires_at=NULL
          WHERE job_id=$1 AND state='running' AND lease_token=$2 AND lease_expires_at>clock_timestamp()
          RETURNING job_id`,[jobId,leaseToken]);
        if (!completed.rowCount) throw failure('STALE_DELETION_LEASE');
        return {state:'completed'};
      });
    },
    async listSecureShopResetIds({ jobId, subjectId, leaseToken }) {
      uuid(jobId); id(subjectId); uuid(leaseToken);
      const job = (await pool.query(`SELECT state,subject_user_id FROM identity.student_deletion_jobs
        WHERE job_id=$1 AND state='running' AND lease_token=$2
          AND lease_expires_at>clock_timestamp()`, [jobId,leaseToken])).rows[0];
      if (!job || Number(job.subject_user_id) !== subjectId) {
        throw failure('DELETION_JOB_UNAVAILABLE');
      }
      const rows = (await pool.query(`SELECT m.reset_id,m.launch_id,o.status,
          l.original_platform_owner_id,l.status AS launch_status
        FROM identity.student_deletion_secureshop_resets m
        JOIN identity.secureshop_launch_resets o ON o.reset_id=m.reset_id AND o.launch_id=m.launch_id
        JOIN identity.secureshop_launches l ON l.launch_id=m.launch_id
        WHERE m.job_id=$1 ORDER BY m.launch_id`, [jobId])).rows;
      if (rows.length > 256 || rows.some(row => Number(row.original_platform_owner_id) !== subjectId
          || !['aborted','committed'].includes(row.status) || row.launch_status !== 'revoked')) {
        throw failure('SECURESHOP_DELETION_SCOPE_MISMATCH');
      }
      return rows.map(row => row.reset_id);
    },
    async admit({ requesterId, subjectId }) {
      id(requesterId); id(subjectId);
      if (requesterId === subjectId) throw failure('SELF_DELETION_DENIED');
      return withTransaction(pool, async client => {
        await lockStudentLifecycleTransaction(client, subjectId);
        const admitUnderSceneLease = async () => {
        // Stable ordering prevents opposite-target requests from deadlocking.
        const accounts = (await client.query(
          'SELECT id,role,admin_level,is_active FROM identity.users WHERE id=ANY($1::integer[]) ORDER BY id FOR UPDATE',
          [[requesterId, subjectId]],
        )).rows;
        const requester = accounts.find(row => row.id === requesterId);
        if (!requester || requester.is_active !== 1 || !['admin','super_admin'].includes(requester.role) || requester.admin_level !== 2) throw failure('ADMIN_REQUIRED');
        const prior = (await client.query('SELECT job_id,state FROM identity.student_deletion_jobs WHERE subject_user_id=$1', [subjectId])).rows[0];
        if (prior) return { jobId: prior.job_id, state: prior.state, replayed: true };
        const subject = accounts.find(row => row.id === subjectId);
        if (!subject || subject.role !== 'student' || subject.admin_level !== 0) throw failure('STUDENT_NOT_FOUND');
        const jobId = randomUUID();
        await client.query('INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by) VALUES($1,$2,$3)', [jobId,subjectId,requesterId]);
        for (const [ordinal, step] of manifest.entries()) {
          await client.query('INSERT INTO identity.student_deletion_steps(job_id,step_key,ordinal) VALUES($1,$2,$3)', [jobId,step,ordinal]);
        }
        const { RUN_FAMILIES } = require('./agentRunReadRepository');
        for (const family of RUN_FAMILIES) {
          await client.query('INSERT INTO identity.student_deletion_run_blocks(owner_key,job_id) VALUES($1,$2)', [JSON.stringify([family,String(subjectId)]),jobId]);
        }
        // Match launch lifecycle lock order. Every unresolved launch receives
        // cleanup authority; receipt-proven retired tombstones remain intact.
        await client.query('SELECT id FROM identity.user_sessions WHERE user_id=$1 ORDER BY id FOR UPDATE', [subjectId]);
        const launches = (await client.query(`SELECT * FROM identity.secureshop_launches
          WHERE original_platform_owner_id=$1 AND NOT identity.secureshop_launch_is_retired(launch_id)
          ORDER BY launch_id FOR UPDATE`, [subjectId])).rows;
        if (launches.length > 256) throw failure('SECURESHOP_DELETION_CAPACITY');
        for (const launch of launches) {
          let reset;
          if (launch.status === 'active') {
            const resetId = randomUUID(), from = Number(launch.generation), to = from + 1;
            if (!Number.isSafeInteger(to) || to > Number.MAX_SAFE_INTEGER) throw failure('SECURESHOP_DELETION_CAPACITY');
            await client.query(`UPDATE identity.secureshop_launches
              SET generation=$2,status='resetting',updated_at=clock_timestamp() WHERE launch_id=$1`, [launch.launch_id,to]);
            reset = (await client.query(`INSERT INTO identity.secureshop_launch_resets
              (reset_id,launch_id,from_generation,to_generation,idempotency_hash)
              VALUES($1,$2,$3,$4,$5) RETURNING reset_id`, [resetId,launch.launch_id,from,to,
              createHash('sha256').update(`${jobId}:secureshop:${launch.launch_id}`).digest()])).rows[0];
          } else if (launch.status === 'resetting') {
            const rows = (await client.query(`SELECT reset_id FROM identity.secureshop_launch_resets
              WHERE launch_id=$1 AND to_generation=$2
                AND status='fenced'
              ORDER BY created_at DESC,reset_id LIMIT 2`, [launch.launch_id,launch.generation])).rows;
            if (rows.length !== 1) throw failure('SECURESHOP_CLEANUP_AUTHORITY_REQUIRED');
            reset = rows[0];
          } else if (launch.status === 'revoked') {
            // A reset aborted by logout already identifies the generation that
            // needs cleanup. A normally revoked active launch has no such
            // journal, so advance only its cleanup generation and create an
            // already-aborted operation. It remains revoked throughout.
            const rows = (await client.query(`SELECT reset_id FROM identity.secureshop_launch_resets
              WHERE launch_id=$1 AND to_generation=$2 AND status='aborted'
              ORDER BY created_at DESC,reset_id LIMIT 2`, [launch.launch_id,launch.generation])).rows;
            if (rows.length > 1) throw failure('SECURESHOP_CLEANUP_AUTHORITY_REQUIRED');
            if (rows.length === 1) {
              reset = rows[0];
            } else {
              const resetId = randomUUID(), from = Number(launch.generation), to = from + 1;
              if (!Number.isSafeInteger(to) || to > Number.MAX_SAFE_INTEGER) {
                throw failure('SECURESHOP_DELETION_CAPACITY');
              }
              const advanced = await client.query(`UPDATE identity.secureshop_launches
                SET generation=$2,updated_at=clock_timestamp()
                WHERE launch_id=$1 AND status='revoked' AND generation=$3`,
              [launch.launch_id,to,from]);
              if (advanced.rowCount !== 1) throw failure('SECURESHOP_CLEANUP_AUTHORITY_REQUIRED');
              reset = (await client.query(`INSERT INTO identity.secureshop_launch_resets
                (reset_id,launch_id,from_generation,to_generation,idempotency_hash,
                 status,aborted_at,abort_reason)
                VALUES($1,$2,$3,$4,$5,'aborted',clock_timestamp(),'account_deletion_recovery')
                RETURNING reset_id`, [resetId,launch.launch_id,from,to,
                createHash('sha256').update(`${jobId}:secureshop:${launch.launch_id}`).digest()])).rows[0];
            }
          } else {
            throw failure('SECURESHOP_CLEANUP_AUTHORITY_REQUIRED');
          }
          await client.query(`INSERT INTO identity.student_deletion_secureshop_resets(job_id,reset_id,launch_id)
            VALUES($1,$2,$3)`, [jobId,reset.reset_id,launch.launch_id]);
        }
        await client.query('UPDATE identity.users SET is_active=0,updated_at=clock_timestamp() WHERE id=$1', [subjectId]);
        await client.query("UPDATE identity.user_sessions SET is_active=0,revoked_at=COALESCE(revoked_at,clock_timestamp()),revoked_by=$2,revoke_reason='account_deletion' WHERE user_id=$1 AND is_active=1", [subjectId,requesterId]);
        return { jobId, state: 'pending', replayed: false };
        };
        return sceneResetPreflight
          ? sceneResetPreflight.withOwnerLease(subjectId, async lease => {
            await lease.preflightLaunches(await lease.listOwnerLaunches());
            return admitUnderSceneLease();
          })
          : admitUnderSceneLease();
      });
    },
  };
}
module.exports = { createStudentDeletionRepository };
