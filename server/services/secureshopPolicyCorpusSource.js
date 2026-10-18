'use strict';

const { buildTaskPolicySnapshot } = require('./secureshopPromptPolicyTaskSnapshot');
const { buildPolicyRetrievalSnapshot } = require('./secureshopPolicyRetrievalSnapshot');

function invalid() { throw Object.assign(new Error('Policy corpus source unavailable'), { code: 'POLICY_CORPUS_UNAVAILABLE' }); }

function createSecureShopPolicyCorpusSource({ policyRepository } = {}) {
  if (typeof policyRepository?.list !== 'function') throw new TypeError('Bound prompt policy repository required');
  return Object.freeze({
    async capture(raw) {
      const input = structuredClone(raw);
      if (!input?.scope || input.persona?.role !== 'admin' || !input.personaSession) invalid();
      const listed = await policyRepository.list(input);
      if (!listed || typeof listed.version !== 'string' || !Array.isArray(listed.policies)) invalid();
      const task = buildTaskPolicySnapshot({ policyVersion: listed.version, role: 'customer',
        recipient: 'summarizer', policies: listed.policies.map(policy => ({ name: policy.name,
          rendered: policy.rendered, renderedSha256: policy.renderedSha256, targets: policy.targets })) });
      return buildPolicyRetrievalSnapshot(task);
    },
  });
}

module.exports = { createSecureShopPolicyCorpusSource };
