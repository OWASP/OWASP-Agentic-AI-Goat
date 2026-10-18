'use strict';

// Agent run snapshots require canonical policy authority even when the optional
// policy editor/renderer is disabled. This lazy resolver never enables that UI.
function createAgentSnapshotPolicyResolver({ repository, personaAuthority, agentsPool,
  identityPool, auditStore, createRepository, createRunBinding } = {}) {
  let pending;
  return function resolveAgentSnapshotPolicies() {
    if (!pending) pending = (async () => {
      if (repository) {
        if (typeof repository.admitRunSnapshot !== 'function') throw new TypeError('Canonical agent policy snapshots required');
        return repository;
      }
      if (typeof personaAuthority?.capture !== 'function' || typeof agentsPool?.query !== 'function'
          || typeof identityPool?.query !== 'function' || !auditStore) {
        throw new TypeError('Prepared persona authority and canonical policy stores required');
      }
      const makeBinding = createRunBinding || require('./secureshopPromptPolicyRunBinding').createPromptPolicyRunBinding;
      const makeRepository = createRepository || require('../database/postgres/secureshopBoundPromptPolicyRepository').createBoundPromptPolicyRepository;
      const policies = makeRepository({ pool: agentsPool, personaAuthority, audit: auditStore,
        checkRunBinding: makeBinding({ identityPool }) });
      if (typeof policies?.checkReadiness !== 'function' || typeof policies.admitRunSnapshot !== 'function') {
        throw new TypeError('Canonical agent policy repository required');
      }
      await policies.checkReadiness();
      return policies;
    })();
    return pending;
  };
}
module.exports = { createAgentSnapshotPolicyResolver };
