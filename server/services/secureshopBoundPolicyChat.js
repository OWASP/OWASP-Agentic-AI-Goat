'use strict';

const C = require('./secureshopRolePolicyProposal');
const render = require('./secureshopPromptPolicyContract');
const tasks = require('./secureshopPromptPolicyTaskMutation');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { canonicalDigest } = require('./mcp/protocolContext');
const fail = code => Object.assign(new Error('Policy conversation unavailable'), { code });
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',');

// This adapter never renders while preparing a candidate. The existing policy
// service remains the sole owner of admission, rendering, CAS and receipts.
function createBoundPolicyChat({ service, supportedTaskTargets = [] } = {}) {
  if (['list', 'render', 'remove', 'operation'].some(k => typeof service?.[k] !== 'function')) {
    throw new TypeError('Bound policy service required');
  }
  const allowed = C.policySupportedTargets(supportedTaskTargets);
  async function snapshot(context) {
    const value = await service.list(structuredClone(context));
    if (!value || !Array.isArray(value.policies) || value.policies.length > 32
        || value.administration?.versionedPolicy !== true
        || !/^[a-f0-9]{64}$/.test(value.administration.scopeKey || '')
        || typeof value.version !== 'string' || !/^[1-9]\d{0,15}$/.test(value.version)
        || BigInt(value.version) > 9007199254740991n) throw fail('POLICY_CHAT_STATE_INVALID');
    const scopeKey = value.administration.scopeKey, headVersion = value.version;
    const policies = value.policies.map(row => {
      const p = { ...C.normalizePolicyCandidate({ name: row.name, markdown: row.markdown,
        targets: row.targets }, C.HISTORICAL_TARGETS), version: row.version };
      if (typeof p.version !== 'string' || !/^[1-9]\d{0,15}$/.test(p.version)
          || BigInt(p.version) > BigInt(headVersion)) throw fail('POLICY_CHAT_STATE_INVALID');
      return { name: p.name, version: p.version, markdown: p.markdown, targets: p.targets,
        snapshotSha256: C.policySnapshotDigest({ scopeKey, headVersion, policy: p }) };
    });
    if (new Set(policies.map(p => p.name)).size !== policies.length) throw fail('POLICY_CHAT_STATE_INVALID');
    return { version: 1, scopeKey, headVersion, supportedTargets: [...allowed], policies };
  }
  async function prepare(raw) {
    const input = structuredClone(raw);
    const { context, source, origin, action, selected, candidate, modeCapability } = input;
    const state = await snapshot(context);
    let name, before = null, after = null;
    if (action === 'create') {
      if (selected !== null) throw fail('POLICY_CHOICE_STALE');
      const c = C.normalizePolicyCandidate(candidate, allowed);
      name = c.name;
      if (state.policies.some(p => p.name === name)) throw fail('POLICY_NAME_EXISTS');
      after = { markdown: c.markdown, targets: c.targets };
    } else {
      if (!exact(selected, ['choiceId', 'name', 'snapshotSha256'])) throw fail('POLICY_CHOICE_STALE');
      const current = state.policies.find(p => p.name === selected.name);
      if (!current || current.snapshotSha256 !== selected.snapshotSha256) throw fail('POLICY_CHOICE_STALE');
      name = current.name; before = { markdown: current.markdown, targets: current.targets };
      if (action === 'delete') {
        if (candidate !== null) throw fail('ROLE_POLICY_PROPOSAL_INVALID');
      } else {
        const c = C.normalizePolicyCandidate(candidate, allowed);
        if (c.name !== name) throw fail('POLICY_CHOICE_STALE');
        after = { markdown: c.markdown, targets: c.targets };
        if (action === 'edit' && JSON.stringify(before) === JSON.stringify(after)) throw fail('POLICY_NO_CHANGE');
      }
    }
    return C.createRolePolicyProposal({ source, origin, action, selected, before, after, name,
      expectedVersion: state.headVersion, scopeKey: state.scopeKey, modeCapability }, allowed);
  }
  function envelope(value) {
    if (value === null) return null;
    if (value?.state === 'pending') {
      if (!exact(value, ['state', 'operationId'])) throw fail('POLICY_CHAT_STATE_INVALID');
      return { ok: false, state: 'pending', operationId: value.operationId };
    }
    return { ok: true, receipt: structuredClone(value) };
  }
  async function confirm(raw) {
    const { context, proposal, source } = structuredClone({ context: raw.context,
      proposal: raw.proposal, source: raw.source });
    const { signal, beforeEffect } = raw;
    if (beforeEffect !== undefined && typeof beforeEffect !== 'function') throw fail('ROLE_POLICY_PROPOSAL_INVALID');
    signal?.throwIfAborted();
    const p = C.validateRolePolicyProposal(proposal, source, allowed);
    const state = await snapshot(context);
    if (state.scopeKey !== p.scopeKey) throw fail('POLICY_SCOPE_MISMATCH');
    // The graph owns original scene/mode authority. Recheck it after the
    // asynchronous policy-scope read, before entering existing admission.
    if (beforeEffect) await beforeEffect();
    signal?.throwIfAborted();
    // Do not compare current head/row here: exact UUID replay must reach the
    // repository before its CAS, even after this operation changed the policy.
    if (p.action === 'delete') {
      // Identical to the existing repository's delete identity after its scope
      // and persona-session normalization; do not invent another receipt hash.
      const expectedDigest = canonicalDigest(['prompt-policy-delete-v1', createLaunchScope(context.scope),
        context.persona, { sessionId: context.personaSession.sessionId.toLowerCase(),
          authorityVersion: context.personaSession.authorityVersion }, p.proposalId, p.name, p.expectedVersion]);
      const receipt = await service.remove({ ...context, operationId: p.proposalId,
        name: p.name, expectedVersion: p.expectedVersion }, {signal,beforeEffect});
      if (!exact(receipt, ['version', 'operationId', 'requestSha256', 'deleted',
        ...(Object.hasOwn(receipt || {}, 'replayed') ? ['replayed'] : [])])
          || (Object.hasOwn(receipt, 'replayed') && receipt.replayed !== true)
          || receipt.operationId !== p.proposalId || receipt.deleted !== true
          || receipt.version !== String(BigInt(p.expectedVersion) + 1n)
          || receipt.requestSha256 !== expectedDigest) throw fail('POLICY_CHAT_STATE_INVALID');
      return envelope(receipt);
    }
    const request = C.policyMutationRequest(p);
    const value = await service.render({ ...context, action: p.action === 'preview' ? 'preview' : 'upsert',
      expectedVersion: p.expectedVersion, request }, { signal,beforeEffect });
    if (value?.state === 'pending') {
      if (value.operationId !== p.proposalId) throw fail('POLICY_CHAT_STATE_INVALID');
      return envelope(value);
    }
    const receipt = value?.receipt;
    const task = request.contractVersion === 2;
    const rendererRequest = task ? tasks.renderRequest(request) : request;
    if (value?.state !== 'completed' || !exact(receipt, ['version', 'operationId', 'requestSha256',
      'renderResult', ...(task ? ['policyRequestSha256'] : []),
      ...(Object.hasOwn(receipt || {}, 'replayed') ? ['replayed'] : [])])
        || (Object.hasOwn(receipt, 'replayed') && receipt.replayed !== true)
        || receipt.operationId !== p.proposalId
        || receipt.version !== (p.action === 'preview' ? p.expectedVersion : String(BigInt(p.expectedVersion) + 1n))
        || receipt.requestSha256 !== render.requestDigest(rendererRequest)
        || (task && receipt.policyRequestSha256 !== tasks.taskMutationDigest(request))) throw fail('POLICY_CHAT_STATE_INVALID');
    if(receipt.renderResult?.version===2)render.validateRenderExecutionResult({version:2,mode:receipt.renderResult.kind==='literal'?'fixed':'vuln',request:rendererRequest},receipt.renderResult);
    else render.validateRenderResult(rendererRequest, receipt.renderResult);
    return envelope(receipt);
  }
  return Object.freeze({ snapshot, prepare, confirm,
    readAssessmentPublication: ({context,operationId}) => service.readAssessmentPublication({...structuredClone(context),operationId}),
    operation: async ({ context, operationId }) => envelope(await service.operation({ ...structuredClone(context), operationId })) });
}
module.exports = { createBoundPolicyChat };
