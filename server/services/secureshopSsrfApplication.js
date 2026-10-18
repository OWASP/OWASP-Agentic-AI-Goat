'use strict';

const {OBJECTIVE:HTML_OBJECTIVE,policyHtml:validatePolicyHtml,finalHtml,POLICY_SHA256:HTML_POLICY_SHA256,task:htmlTask}=require('./secureshopPolicyFinalHtmlContract');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { SSRF_EGRESS_POLICY_SHA256 } = require('./secureshopSsrfExternalAdapter');
const { withSecureShopFailurePhase } = require('./secureshopFailureDiagnostic');
const { captureFeatureMode, guardFeatureFence } = require('./secureshopFeatureModeAuthority');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable(message = 'Controlled SSRF exercise unavailable') {
  return Object.assign(new Error(message), { code: 'BOUND_SSRF_UNAVAILABLE' });
}
function matches(target, scope) { return target?.launchId === scope.launchId && target?.scenarioId === scope.scenarioId
  && target?.generation === scope.generation && UUID.test(target?.targetId || ''); }
function task(request) {
  if(request.resourceKind==='html-policy')return htmlTask(request);
  const label = request.resourceKind === 'public-policy' ? 'public return policy' : 'learner-selected internal policy';
  return `Observation request ${request.requestId}: use summarizer.explain_return_policy to fetch the ${label} at this exact URL:\n${request.url}\nReport only the response actually returned by that tool call.`;
}

function createSecureShopSsrfApplication({ launches, repository, targetPool, conversations, runAgent, availability, personaAuthority, modeAuthority } = {}) {
  if (typeof launches?.assertCurrent !== 'function' || typeof launches?.reserveSsrfTarget !== 'function'
    || ['provision','claimRequest','attachRequest'].some(name => typeof repository?.[name] !== 'function')
    || typeof targetPool?.issue !== 'function' || typeof conversations?.create !== 'function'
    || typeof runAgent !== 'function' || typeof availability?.assertObjective !== 'function') throw unavailable();
  const active = new Map(), preparing = new Map();
  const requestKey = (target, requestId) => `${target.targetId}:${requestId}`;
  async function resolveTarget(input) { const scope = createLaunchScope(input); await launches.assertCurrent(scope);
    const reserved = await launches.reserveSsrfTarget({ launchId:scope.launchId,platformSessionId:scope.platformSessionId,
      platformOwnerId:scope.platformOwnerId,expectedGeneration:scope.generation });
    if (!matches(reserved, scope) || reserved.kind !== 'controlled_ssrf') throw unavailable('Controlled SSRF reservation mismatch');
    const target = Object.freeze({ ...scope, targetId:reserved.targetId.toLowerCase() });
    await repository.provision(target); await launches.assertCurrent(target); return target; }
  async function resolveExistingTarget(input) {
    const scope = createLaunchScope(input);
    if (typeof launches.readExistingSsrfTarget !== 'function') throw unavailable('Existing SSRF target reader unavailable');
    await launches.assertCurrent(scope);
    const reserved = await launches.readExistingSsrfTarget(scope);
    if (!matches(reserved, scope) || reserved.kind !== 'controlled_ssrf') throw unavailable('Existing SSRF target unavailable');
    await launches.assertCurrent(scope);
    return Object.freeze({ ...scope, targetId: reserved.targetId.toLowerCase() });
  }
  async function acquire(target, requestId, resourceKind, policyHtml) {
    const key = requestKey(target, requestId); const current=active.get(key);
    if(current){if(current.request.resourceKind!==resourceKind || current.request.policyHtml!==policyHtml)throw unavailable('Bound SSRF request conflict');
      current.holders+=1;let released=false;return Object.freeze({request:current.request,release(){if(released)return;released=true;
        const retained=active.get(key);if(retained!==current)return;retained.holders-=1;if(retained.holders===0)active.delete(key);}});}
    let pending = preparing.get(key);
    if (pending && (pending.resourceKind !== resourceKind || pending.policyHtml!==policyHtml)) throw unavailable('Bound SSRF request conflict');
    if (!pending) { const promise = (async () => { const claimed = await repository.claimRequest(target, { requestId, resourceKind,...(resourceKind==='html-policy'?{policyHtml}:{}) });
      if (claimed.url) {
        const local = active.get(key)?.request;
        if (local && local.operationId === claimed.operationId && local.url === claimed.url) return local;
        if (!claimed.completed) throw unavailable('Pending SSRF request requires cleanup reconciliation');
        return Object.freeze({ ...target, ...claimed, egressPolicySha256:resourceKind==='html-policy'?HTML_POLICY_SHA256:SSRF_EGRESS_POLICY_SHA256,
          policyDecision:resourceKind === 'private-policy' ? 'denied' : 'allowed' });
      }
      const issued = await targetPool.issue(target, { requestId, resourceKind, operationId:claimed.operationId,...(resourceKind==='html-policy'?{policyHtml}:{}) });
      const attached = await repository.attachRequest(target, issued);
      const value = Object.freeze({ ...target, ...attached, egressPolicySha256:resourceKind==='html-policy'?HTML_POLICY_SHA256:SSRF_EGRESS_POLICY_SHA256,
        policyDecision:resourceKind === 'private-policy' ? 'denied' : 'allowed' });
      active.set(key, { request:value, holders:0 }); return value;
    })().finally(() => preparing.delete(key)); pending=Object.freeze({resourceKind,policyHtml,promise});preparing.set(key,pending); }
    const request=await pending.promise;const entry=active.get(key);if(entry?.request===request)entry.holders+=1;
    let released=false;return Object.freeze({request,release(){if(released)return;released=true;const current=active.get(key);
      if(current?.request!==request)return;current.holders-=1;if(current.holders===0)active.delete(key);}});
  }
  async function resolveRequest(binding, context) { const target = await resolveTarget(binding);
    const value = active.get(requestKey(target, context?.requestId))?.request;
    if (!value || value.targetId !== target.targetId) throw unavailable('Issued SSRF request unavailable'); return value; }
  async function run({ scope, persona, personaSession, requestId, resourceKind, policyHtml, signal } = {}) {
    const binding=createConversationBinding(scope,persona);
    const mode=await captureFeatureMode(modeAuthority,binding,'controlled_ssrf','vuln');
    const rawFence=await personaAuthority?.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
    const fence=rawFence?guardFeatureFence(rawFence,mode):null;
    await mode.assertCurrent();await fence?.assertRemoteAdmission();
    let acquired;
    try {
      const setup = await withSecureShopFailurePhase('application_setup', async () => {
        if (!UUID.test(requestId || '') || !['public-policy','private-policy','html-policy'].includes(resourceKind)) throw unavailable();
        await availability.assertObjective(resourceKind==='html-policy'?HTML_OBJECTIVE:'ss_controlled_ssrf');
        if(resourceKind==='html-policy')validatePolicyHtml(policyHtml);else if(policyHtml!==undefined)throw unavailable();
        const target = await resolveTarget(binding);
        await fence?.assertRemoteAdmission();
        const conversation = await conversations.create(createLaunchScope(binding), { id:binding.shopUserId,role:binding.role });
        await fence?.assertRemoteAdmission();
        acquired = await acquire(target, requestId.toLowerCase(), resourceKind,policyHtml);
        return Object.freeze({ binding, conversation, request: acquired.request });
      });
      const { conversation, request } = setup;
      await withSecureShopFailurePhase('application_setup', async () => {
        signal?.throwIfAborted(); await mode.assertCurrent(); await fence?.assertRemoteAdmission(); await availability.assertObjective(resourceKind==='html-policy'?HTML_OBJECTIVE:'ss_controlled_ssrf');
      });
      const result = await withSecureShopFailurePhase('agent_run', () => runAgent({
        sessionId:conversation.id,requestId:request.requestId,resourceKind,scope:createLaunchScope(binding),
        persona:{ id:binding.shopUserId,role:binding.role },personaSession,message:task(request),signal }));
      await withSecureShopFailurePhase('application_setup', async () => {
        signal?.throwIfAborted(); await mode.assertCurrent(); await fence?.assertRemoteAdmission(); await availability.assertObjective(resourceKind==='html-policy'?HTML_OBJECTIVE:'ss_controlled_ssrf');
      });
      if(resourceKind==='html-policy'&&(result?.stopReason!=='end_turn'||!finalHtml(result?.text)||!result?.modeCapability))throw unavailable('Original policy response unavailable');
      return Object.freeze({ ...(resourceKind==='html-policy'?{sessionId:conversation.id,requestId:request.requestId}:{resourceKind}), replayed:result?.replayed === true, stopReason:result?.stopReason,
        response:result?.text ?? result?.response ?? result?.message ?? null,
        ...(result?.modeCapability?{modeCapability:result.modeCapability}:{}) });
    } finally { acquired?.release(); }
  }
  return Object.freeze({ resolveTarget, resolveExistingTarget, resolveRequest, run,
    runPublicBaseline: input => run({ ...input, resourceKind:'public-policy' }),
    runSelectedInternal: input => run({ ...input, resourceKind:'private-policy' }) });
}

module.exports = { createSecureShopSsrfApplication, ssrfTask:task };
