'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { qualifyMcpRenderedAdminLifecycle } = require('./fixtures/mcpRenderedAdminLifecycle');

const ORIGIN = 'http://127.0.0.1:54321';
const JOB_ID = '47cb31d0-acde-4c9b-8af8-6d3551d5306d';

function response(pathname, method, body, status = 200) {
  return {
    url: () => `${ORIGIN}${pathname}`,
    status: () => status,
    request: () => ({ method: () => method }),
    json: async () => body,
  };
}

class FakePage extends EventEmitter {
  constructor({ subject, sibling, overrides = {} } = {}) {
    super();
    this.subject = subject;
    this.sibling = sibling;
    this.overrides = overrides;
    this.calls = [];
    this.deleteModal = false;
    this.typed = [];
  }

  waitForResponse(predicate, { timeout, signal } = {}) {
    return new Promise((resolve, reject) => {
      const finish = (callback, value) => {
        clearTimeout(timer); this.off('response', listener); signal?.removeEventListener('abort', onAbort); callback(value);
      };
      const onAbort = () => finish(reject, new Error('response wait aborted'));
      const timer = setTimeout(() => finish(reject, new Error('response timeout')), timeout || 1_000);
      const listener = value => {
        if (!predicate(value)) return;
        finish(resolve, value);
      };
      this.on('response', listener);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  async goto(url) {
    this.calls.push(['goto', url]);
    const students = this.overrides.students || [this.subject, this.sibling];
    queueMicrotask(() => this.emit('response', response('/api/admin/students', 'GET', { success: true, students })));
  }

  async waitForFunction(_fn, _options, argument) {
    this.calls.push(['waitForFunction', argument]);
    return true;
  }

  async waitForSelector(selector, options) {
    this.calls.push(['waitForSelector', selector, options]);
    if (selector === '#delete-confirmation' && !this.deleteModal) throw new Error('delete modal absent');
    return true;
  }

  async type(selector, value) {
    this.typed.push([selector, value]);
  }

  async evaluate(_fn, argument) {
    if (argument?.action === 'Details') {
      this.calls.push(['row', argument.username, 'Details']);
      queueMicrotask(() => this.emit('response', response(`/api/admin/students/${this.subject.id}/progress`, 'GET',
        this.overrides.details || { success: true, student: this.subject,
          workshopObjectives: { mcp_workshop: [{ objective_id: 'mcp_indirect_injection' }] } })));
      return { ok: this.overrides.detailsClick !== false, reason: 'fixture detail click failed' };
    }
    if (argument?.action === 'Delete') {
      this.calls.push(['row', argument.username, 'Delete']);
      this.deleteModal = true;
      return { ok: this.overrides.deleteClick !== false, reason: 'fixture delete click failed' };
    }
    if (argument === 'Mcp Workshop') {
      this.calls.push(['reset', argument]);
      const dialog = {
        type: () => 'confirm',
        message: () => this.overrides.dialogMessage
          || `Reset all objectives for "mcp_workshop" for ${this.subject.username}?`,
        accept: async () => { this.calls.push(['dialog', 'accept']); },
        dismiss: async () => { this.calls.push(['dialog', 'dismiss']); },
      };
      queueMicrotask(() => {
        this.emit('dialog', dialog);
        if (!this.overrides.omitResetResponse) {
          this.emit('response', response(`/api/admin/students/${this.subject.id}/workshops/mcp_workshop/reset`, 'POST',
            this.overrides.resetBody || { success: true, result: { reset: true } }, this.overrides.resetStatus || 200));
        }
      });
      return { ok: true };
    }
    this.calls.push(['delete-confirm']);
    queueMicrotask(() => this.emit('response', response(`/api/admin/students/${this.subject.id}`, 'DELETE',
      this.overrides.deleteBody || { success: true, jobId: JOB_ID }, this.overrides.deleteStatus || 200)));
    return { ok: true };
  }
}

function fixture(overrides = {}) {
  const subject = Object.freeze({ id: 41, username: 'target-student' });
  const sibling = Object.freeze({ id: 42, username: 'sibling-student' });
  const administratorPage = new FakePage({ subject, sibling, overrides });
  const passivePage = {
    goto() {}, waitForResponse() {}, waitForFunction() {}, evaluate() {}, waitForSelector() {}, type() {},
  };
  const calls = [];
  const nativeEvidence = {
    snapshotAdminReset: async coordinates => { calls.push(['snapshot-reset', coordinates]); return Object.freeze({ revision: 1 }); },
    verifyAdminReset: async input => {
      calls.push(['verify-reset', input]);
      return { administratorId: 7, subjectId: subject.id, siblingId: sibling.id,
        ownerResourcesRetired: true, siblingPreserved: true, immutableJudgmentsPreserved: true,
        ...overrides.resetProof };
    },
    snapshotDeletion: async coordinates => { calls.push(['snapshot-delete', coordinates]); return Object.freeze({ revision: 2 }); },
    captureDeletionFailure: async input => {
      calls.push(['capture-delete-failure', input]);
      return overrides.deletionFailure || { ownerId: subject.id, administratorId: 7,
        jobPresent: false, steps: [] };
    },
    verifyDeletion: async input => {
      calls.push(['verify-delete', input]);
      return { administratorId: 7, subjectId: subject.id, siblingId: sibling.id, jobId: JOB_ID,
        ownerResourcesRetired: true, siblingPreserved: true, subjectAnonymized: true,
        subjectSessionsRevoked: true, judgmentReceiptsPreserved: true, conversationContentRemoved: true,
        ...overrides.deletionProof };
    },
  };
  let turn = 0;
  return { subject, sibling, administratorPage, calls, args: {
    origin: ORIGIN, administratorPage, subjectPage: passivePage, siblingPage: passivePage,
    administratorId: 7, subject, sibling, nativeEvidence, timeoutMs: 1_000,
    performPositiveTurn: async input => {
      calls.push(['positive', input]); turn += 1;
      return { ownerId: subject.id, verified: true, awarded: true,
        requestId: `request-${turn}`, runId: `run-${turn}` };
    },
  } };
}

test('qualifies exact-target administrative reset then deletion from real UI actions and native receipts', async () => {
  const f = fixture();
  const result = await qualifyMcpRenderedAdminLifecycle(f.args);
  assert.deepEqual(result, {
    verified: true, administratorId: 7, subjectId: 41, siblingId: 42,
    reset: { verified: true, requestId: 'request-1', runId: 'run-1' },
    deletion: { verified: true, requestId: 'request-2', runId: 'run-2', jobId: JOB_ID },
  });
  assert.deepEqual(f.administratorPage.typed, [['#delete-confirmation', 'DELETE']]);
  assert.deepEqual(f.calls.map(call => call[0]), [
    'positive', 'snapshot-reset', 'verify-reset', 'positive', 'snapshot-delete', 'verify-delete',
  ]);
  const resetInput = f.calls.find(call => call[0] === 'verify-reset')[1];
  assert.equal(resetInput.positiveReceipt.runId, 'run-1');
  assert.equal(resetInput.responseBody.success, true);
  const deletionInput = f.calls.find(call => call[0] === 'verify-delete')[1];
  assert.equal(deletionInput.positiveReceipt.runId, 'run-2');
  assert.equal(deletionInput.jobId, JOB_ID);
  assert.deepEqual(f.administratorPage.calls.filter(call => call[0] === 'row'), [
    ['row', 'target-student', 'Details'], ['row', 'target-student', 'Delete'],
  ]);
});

test('fails before lifecycle effects when the roster cannot uniquely bind the target account', async () => {
  const f = fixture({ students: [
    { id: 41, username: 'target-student' }, { id: 99, username: 'target-student' },
  ] });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(f.args), /uniquely bind/);
  assert.deepEqual(f.calls.map(call => call[0]), ['positive', 'snapshot-reset']);
  assert.equal(f.administratorPage.calls.some(call => call[0] === 'reset'), false);
});

test('rejects a reset dialog for any other target without waiting for an absent POST', async () => {
  const f = fixture({ dialogMessage: 'Reset all objectives for "mcp_workshop" for sibling-student?', omitResetResponse: true });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(f.args), /exact target/);
  assert.equal(f.administratorPage.calls.some(call => call[0] === 'dialog' && call[1] === 'accept'), false);
  assert.equal(f.calls.some(call => call[0] === 'verify-reset'), false);
});

test('requires all native lifecycle flags and exact deletion operation ID', async () => {
  const missingReset = fixture({ resetProof: { siblingPreserved: false } });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(missingReset.args), /siblingPreserved/);

  const wrongJob = fixture({ deletionProof: { jobId: '99d195ee-04a4-45d0-973e-0406fe9c19ac' } });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(wrongJob.args), /different operation ID/);

  const malformedJob = fixture({ deleteBody: { success: true, jobId: 'not-an-operation-id' } });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(malformedJob.args), /valid operation ID/);
  assert.equal(malformedJob.calls.some(call => call[0] === 'verify-delete'), false);
});

test('does not infer reset or deletion success from HTTP 200 alone', async () => {
  const reset = fixture({ resetBody: { success: false } });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(reset.args), /did not confirm success/);
  assert.equal(reset.calls.some(call => call[0] === 'verify-reset'), false);

  const deletion = fixture({ deleteBody: { success: false, jobId: JOB_ID } });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(deletion.args), /did not confirm success/);
  assert.equal(deletion.calls.some(call => call[0] === 'verify-delete'), false);
});

test('non-200 deletion captures exact durable categorical state once without reading success or retrying', async () => {
  const f = fixture({ deleteStatus: 503, deleteBody: { secret: 'must-not-escape' },
    deletionFailure: { ownerId: 41, administratorId: 7, jobPresent: true,
      jobId: JOB_ID, jobState: 'failed', jobFailureCode: null, replayed: false,
      steps: [
        { stepKey: 'revoke_runs', ordinal: 0, state: 'completed' },
        { stepKey: 'mcp_workshop', ordinal: 1, state: 'failed' },
      ] } });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(f.args), error => {
    assert.match(error.message, /did not return HTTP 200 \(HTTP 503/);
    assert.match(error.message, /"jobState":"failed"/);
    assert.match(error.message, /"stepKey":"mcp_workshop"/);
    assert.equal(error.message.includes('must-not-escape'), false);
    return true;
  });
  assert.deepEqual(f.calls.filter(call => call[0] === 'capture-delete-failure'), [[
    'capture-delete-failure', { administratorId: 7, subjectId: 41 },
  ]]);
  assert.equal(f.calls.some(call => call[0] === 'verify-delete'), false);
  assert.equal(f.administratorPage.calls.filter(call => call[0] === 'delete-confirm').length, 1);
});

test('malformed deletion diagnostics fail closed while retaining the exact HTTP failure', async () => {
  const f = fixture({ deleteStatus: 503,
    deletionFailure: { ownerId: 41, administratorId: 7, jobPresent: true,
      jobId: JOB_ID, jobState: 'running', jobFailureCode: null, replayed: false,
      steps: [{ stepKey: 'mcp_workshop', ordinal: 3, state: 'pending', secret: 'hidden' }] } });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(f.args), error => {
    assert.match(error.message, /did not return HTTP 200 \(HTTP 503; durable deletion diagnostic unavailable\)/);
    assert.equal(error.message.includes('hidden'), false);
    return true;
  });
  assert.equal(f.calls.filter(call => call[0] === 'capture-delete-failure').length, 1);
  assert.equal(f.calls.some(call => call[0] === 'verify-delete'), false);
});

test('requires a fresh model turn after the administrative reset', async () => {
  const f = fixture();
  f.args.performPositiveTurn = async () => ({
    ownerId: f.subject.id, verified: true, awarded: true, requestId: 'same-request', runId: 'same-run',
  });
  await assert.rejects(qualifyMcpRenderedAdminLifecycle(f.args), /fresh request and run/);
  assert.equal(f.calls.some(call => call[0] === 'snapshot-delete'), false);
});
