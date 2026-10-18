'use strict';

function createSecureShopStudentDeletionCleanup({ repository, launchResetCoordinator, auditCleanup, auditSqlCleanup, analyticsCleanup } = {}) {
  if (typeof repository?.listSecureShopResetIds !== 'function'
      || typeof launchResetCoordinator?.recover !== 'function'
      || (analyticsCleanup !== undefined && typeof analyticsCleanup !== 'function')
      || (auditSqlCleanup !== undefined && typeof auditSqlCleanup !== 'function')
      || (auditCleanup !== undefined && typeof auditCleanup !== 'function')) {
    throw new TypeError('SecureShop deletion cleanup dependencies required');
  }
  return async function cleanSecureShopDeletion({ subjectId, jobId, leaseToken, check, signal } = {}) {
    if (!Number.isSafeInteger(subjectId) || subjectId < 1 || typeof jobId !== 'string'
        || typeof leaseToken !== 'string' || typeof check !== 'function') {
      throw new TypeError('Deletion owner, job, and lease check required');
    }
    signal?.throwIfAborted();await check();
    const scope = { jobId, subjectId, leaseToken };
    const auditScope = { jobId, subjectId, leaseToken, check, signal };
    const resetIds = await repository.listSecureShopResetIds(scope);
    if (!Array.isArray(resetIds) || resetIds.length > 256 || new Set(resetIds).size !== resetIds.length) {
      throw new Error('SecureShop deletion reset mapping is invalid');
    }
    for (const resetId of resetIds) {
      signal?.throwIfAborted();await check();
      const recovered = await launchResetCoordinator.recover(resetId, { signal });
      if (recovered?.resetId !== resetId || recovered.resolved !== true || recovered.activated !== false
          || !['aborted','committed'].includes(recovered.status)) {
        throw new Error('SecureShop deletion cleanup is incomplete');
      }
      signal?.throwIfAborted();await check();
    }
    // Immutable mapping replay prevents a disappearing or newly attached reset
    // from being acknowledged as the same deletion step.
    const replay = await repository.listSecureShopResetIds(scope);
    if (JSON.stringify(replay) !== JSON.stringify(resetIds)) throw new Error('SecureShop deletion reset mapping changed');
    signal?.throwIfAborted();await check();
    if(auditSqlCleanup){const value=await auditSqlCleanup({...auditScope,resetIds});if(value?.completed!==true)throw new Error('Owned audit SQL deletion incomplete');await check();}
    if(analyticsCleanup){const value=await analyticsCleanup({...auditScope,resetIds});if(value?.completed!==true)throw new Error('Owned Analytics deletion incomplete');await check();}
    if (auditCleanup) {
      const receipt = await auditCleanup(auditScope);
      if (receipt?.completed !== true) throw new Error('SecureShop bound audit deletion cleanup is incomplete');
      signal?.throwIfAborted();await check();
    }
    return Object.freeze({ completed: true, resetCount: resetIds.length });
  };
}

module.exports = { createSecureShopStudentDeletionCleanup };
