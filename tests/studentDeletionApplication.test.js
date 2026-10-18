'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createStudentDeletionApplication, createLazyStudentDeletionApplication,
  getStudentDeletionApplication } = require(
  '../server/services/studentDeletionApplication');

test('admin deletion admits one durable job and reports success only after terminal worker cleanup', async () => {
  const events = [];
  const application = createStudentDeletionApplication({
    repository: { async admit(input) { events.push(['admit', input]); return {
      jobId: '11111111-1111-4111-8111-111111111111', replayed: false,
    }; } },
    worker: { async run(jobId) { events.push(['run', jobId]); return { state: 'completed' }; } },
  });
  assert.deepEqual(await application.deleteStudent({ requesterId: 2, subjectId: 7 }), {
    completed: true, jobId: '11111111-1111-4111-8111-111111111111', replayed: false,
  });
  assert.deepEqual(events, [['admit', { requesterId: 2, subjectId: 7 }],
    ['run', '11111111-1111-4111-8111-111111111111']]);
});

test('completed deletion retry rechecks authority and returns its durable receipt without cleanup', async () => {
  let authorized = true; let admissions = 0; let runs = 0;
  const jobId = '11111111-1111-4111-8111-111111111111';
  const application = createStudentDeletionApplication({
    repository: { async admit(input) {
      admissions += 1;
      assert.deepEqual(input, { requesterId: 2, subjectId: 7 });
      if (!authorized) throw Object.assign(new Error('Administrator required'), { code: 'ADMIN_REQUIRED' });
      return { jobId, replayed: true, state: 'completed' };
    } },
    worker: { async run() { runs += 1; return { state: 'not_claimed' }; } },
  });
  assert.deepEqual(await application.deleteStudent({ requesterId: 2, subjectId: 7 }), {
    completed: true, jobId, replayed: true,
  });
  authorized = false;
  await assert.rejects(application.deleteStudent({ requesterId: 2, subjectId: 7 }), { code: 'ADMIN_REQUIRED' });
  assert.equal(admissions, 2); assert.equal(runs, 0);
});

test('nonterminal replay never inherits completed deletion success', async () => {
  for (const state of ['pending', 'running', 'failed', 'quarantined']) {
    let runs = 0;
    const application = createStudentDeletionApplication({
      repository: { async admit() { return {
        jobId: '11111111-1111-4111-8111-111111111111', replayed: true, state,
      }; } },
      worker: { async run() { runs += 1; return { state: 'not_claimed' }; } },
    });
    await assert.rejects(application.deleteStudent({ requesterId: 2, subjectId: 7 }), {
      code: 'DELETION_UNAVAILABLE', statusCode: 503,
    });
    assert.equal(runs, 1);
  }
});

test('failed or unclaimed cleanup remains retryable and never becomes deletion success', async () => {
  for (const state of ['not_claimed', 'incomplete', 'cancelled']) {
    let admitted = 0;
    const application = createStudentDeletionApplication({
      repository: { async admit() { admitted += 1; return {
        jobId: '11111111-1111-4111-8111-111111111111', replayed: admitted > 1,
      }; } },
      worker: { async run() { return { state }; } },
    });
    await assert.rejects(application.deleteStudent({ requesterId: 2, subjectId: 7 }), {
      code: 'DELETION_UNAVAILABLE', statusCode: 503,
    });
    await assert.rejects(application.deleteStudent({ requesterId: 2, subjectId: 7 }), {
      code: 'DELETION_UNAVAILABLE', statusCode: 503,
    });
    assert.equal(admitted, 2);
  }
});

test('lazy production boundary admits nothing before the complete registry is ready and retries readiness', async () => {
  let attempts = 0; let admitted = 0;
  const lazy = createLazyStudentDeletionApplication({ initialize: async () => {
    attempts += 1;
    if (attempts === 1) throw Object.assign(new Error('partial manifest'), {
      code: 'DELETION_UNAVAILABLE', statusCode: 503,
    });
    return { async deleteStudent() { admitted += 1; return { completed: true }; } };
  } });
  await assert.rejects(lazy.deleteStudent({ requesterId: 2, subjectId: 7 }), {
    code: 'DELETION_UNAVAILABLE', statusCode: 503,
  });
  assert.equal(admitted, 0);
  assert.deepEqual(await lazy.deleteStudent({ requesterId: 2, subjectId: 7 }), { completed: true });
  assert.equal(attempts, 2); assert.equal(admitted, 1);
});

test('lazy production boundary maps initialization defects to availability but preserves application validation', async () => {
  let attempts = 0;
  const lazy = createLazyStudentDeletionApplication({ initialize: async () => {
    attempts += 1;
    if (attempts === 1) throw new TypeError('private initialization detail');
    return { async deleteStudent() {
      throw Object.assign(new TypeError('Valid account IDs required'), { code: 'BAD_REQUEST' });
    } };
  } });
  await assert.rejects(lazy.deleteStudent({ requesterId: 2, subjectId: 7 }), {
    message: 'Student deletion cleanup is unavailable', code: 'DELETION_UNAVAILABLE', statusCode: 503,
  });
  await assert.rejects(lazy.deleteStudent({ requesterId: 0, subjectId: 7 }), {
    message: 'Valid account IDs required', code: 'BAD_REQUEST',
  });
  assert.equal(attempts, 2);
});

test('production getter is a stable lazy facade and cannot fall back to direct deletion', async () => {
  const first = getStudentDeletionApplication();
  assert.equal(first, getStudentDeletionApplication());
  const prior = process.env.PLATFORM_DATABASE_ENGINE;
  process.env.PLATFORM_DATABASE_ENGINE = 'sqlite';
  try {
    await assert.rejects(first.deleteStudent({ requesterId: 2, subjectId: 7 }), {
      code: 'DELETION_UNAVAILABLE', statusCode: 503,
    });
  } finally {
    if (prior === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = prior;
  }
});
