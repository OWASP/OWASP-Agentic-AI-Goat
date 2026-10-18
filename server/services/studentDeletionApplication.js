'use strict';

function unavailable(message = 'Student deletion cleanup is unavailable') {
  return Object.assign(new Error(message), { code: 'DELETION_UNAVAILABLE', statusCode: 503 });
}

function createStudentDeletionApplication({ repository, worker } = {}) {
  if (typeof repository?.admit !== 'function' || typeof worker?.run !== 'function') {
    throw new TypeError('Student deletion repository and worker required');
  }
  return Object.freeze({
    async deleteStudent({ requesterId, subjectId, signal } = {}) {
      requesterId = Number(requesterId); subjectId = Number(subjectId);
      if (!Number.isSafeInteger(requesterId) || requesterId < 1
          || !Number.isSafeInteger(subjectId) || subjectId < 1) {
        throw Object.assign(new TypeError('Valid account IDs required'), { code: 'BAD_REQUEST' });
      }
      const admitted = await repository.admit({ requesterId, subjectId });
      // Admission rechecks administrator authority before returning the durable
      // terminal state. Completed jobs cannot be claimed again; acknowledge the
      // recorded success without re-running destructive cleanup.
      if (admitted.replayed === true && admitted.state === 'completed') {
        return Object.freeze({ completed: true, jobId: admitted.jobId, replayed: true });
      }
      const result = await worker.run(admitted.jobId, { signal });
      if (result?.state !== 'completed') {
        throw unavailable('Student deletion is pending cleanup');
      }
      return Object.freeze({ completed: true, jobId: admitted.jobId, replayed: admitted.replayed === true });
    },
  });
}

function createLazyStudentDeletionApplication({ initialize } = {}) {
  if (typeof initialize !== 'function') throw new TypeError('Student deletion initializer required');
  let application;
  let pending;
  async function ready() {
    if (application) return application;
    pending ||= Promise.resolve().then(initialize).then(value => {
      if (typeof value?.deleteStudent !== 'function') throw unavailable();
      application = value;
      return value;
    }).finally(() => { pending = undefined; });
    return pending;
  }
  return Object.freeze({
    async deleteStudent(input) {
      let application;
      try { application = await ready(); }
      catch (error) {
        if (error?.code === 'DELETION_UNAVAILABLE' && error?.statusCode === 503) throw error;
        throw unavailable();
      }
      // Input validation and repository errors belong to the initialized
      // application. Keep them outside the readiness boundary so a genuine
      // client BAD_REQUEST is not rewritten as an infrastructure outage.
      return application.deleteStudent(input);
    },
  });
}

let production;
function getStudentDeletionApplication() {
  production ||= createLazyStudentDeletionApplication({
    initialize: async () => (await require('./studentDeletionProduction')
      .getProductionStudentDeletionComposition()).application,
  });
  return production;
}
function clearStudentDeletionApplication() { production = undefined; }

module.exports = { createStudentDeletionApplication, createLazyStudentDeletionApplication,
  getStudentDeletionApplication, clearStudentDeletionApplication };
