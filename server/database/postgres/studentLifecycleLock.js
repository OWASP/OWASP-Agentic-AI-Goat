'use strict';

// Shared admission order for learner reset and deletion. A session lock can
// span reset work performed by other PostgreSQL connections without retaining
// a transaction or blocking their foreign-key/row locks.
const STUDENT_LIFECYCLE_LOCK_CLASS = 1886610806;

function studentId(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw new TypeError('Valid student ID required');
  }
  return value;
}

async function lockStudentLifecycleTransaction(client, value) {
  const id = studentId(value);
  await client.query('SELECT pg_advisory_xact_lock($1,$2)', [STUDENT_LIFECYCLE_LOCK_CLASS, id]);
}

async function withStudentLifecycleLock(pool, value, work) {
  if (typeof pool?.connect !== 'function') throw new TypeError('PostgreSQL pool is required');
  if (typeof work !== 'function') throw new TypeError('Student lifecycle work is required');
  const id = studentId(value);
  const client = await pool.connect();
  let held = false;
  let discard = false;
  let primaryError;
  let connectionError;
  let active = false;
  const assertAvailable = () => {
    if (!active || connectionError) throw Object.assign(new Error(
      'Student lifecycle lock is no longer available'), {
      code: 'STUDENT_LIFECYCLE_LOCK_LOST', cause: connectionError,
    });
  };
  // Cross-store callers may recheck authority at each effect boundary. This
  // detects loss; it does not make effects in another database atomic.
  const guard = Object.freeze({
    ownerId: id,
    async check() {
      assertAvailable();
      try {
        const result = await client.query(`SELECT EXISTS (
          SELECT 1 FROM pg_catalog.pg_locks
          WHERE locktype = 'advisory' AND pid = pg_catalog.pg_backend_pid()
            AND classid = $1::oid AND objid = $2::oid
            AND objsubid = 2 AND granted
        ) AS held`, [STUDENT_LIFECYCLE_LOCK_CLASS, id]);
        assertAvailable();
        if (result.rows[0]?.held !== true) throw new Error('Student lifecycle advisory lock was lost');
      } catch (error) {
        connectionError ||= error;
        discard = true;
        assertAvailable();
      }
    },
  });
  const lost = error => { connectionError ||= error || new Error('Student lifecycle lock connection was lost'); };
  client.on?.('error', lost);
  try {
    await client.query('SELECT pg_advisory_lock($1,$2)', [STUDENT_LIFECYCLE_LOCK_CLASS, id]);
    held = true;
    active = true;
    const result = await work(client, guard);
    if (connectionError) throw Object.assign(new Error('Student lifecycle lock connection was lost'), {
      code: 'STUDENT_LIFECYCLE_LOCK_LOST', cause: connectionError,
    });
    return result;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    active = false;
    if (connectionError) discard = true;
    let unlockError;
    if (held) {
      try {
        const unlocked = (await client.query('SELECT pg_advisory_unlock($1,$2) AS unlocked',
          [STUDENT_LIFECYCLE_LOCK_CLASS, id])).rows[0]?.unlocked;
        if (unlocked !== true) throw new Error('Student lifecycle advisory lock was not held');
      } catch (error) {
        discard = true;
        unlockError = error;
      }
    }
    if (connectionError) {
      discard = true;
      unlockError ||= connectionError;
    }
    try { client.release(discard ? new Error('Student lifecycle lock connection was lost') : undefined); }
    finally { client.removeListener?.('error', lost); }
    if (!primaryError && unlockError) throw Object.assign(new Error('Student lifecycle lock release failed'), {
      code: 'STUDENT_LIFECYCLE_LOCK_LOST', cause: unlockError,
    });
  }
}

module.exports = {
  STUDENT_LIFECYCLE_LOCK_CLASS,
  lockStudentLifecycleTransaction,
  withStudentLifecycleLock,
};
