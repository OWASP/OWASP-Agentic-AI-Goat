'use strict';

const renderContract = require('./secureshopPromptPolicyContract');
const { normalizeRenderRequest, requestDigest, validateRenderResult } = renderContract;
const { captureFeatureMode } = require('./secureshopFeatureModeAuthority');
const { createHash } = require('node:crypto');
const taskContract = require('./secureshopPromptPolicyTaskMutation');

// Server-composed dependencies only. Repository methods own current-persona,
// launch, version and audit fencing; rendering runs outside their transactions.
function createBoundPromptPolicyService({ repository, renderer, maxConcurrentRenders = 2, modeAuthority } = {}) {
  if (['beginRender', 'publish', 'remove', 'operation', 'list'].some(key => typeof repository?.[key] !== 'function')
    || typeof renderer?.render !== 'function') throw new TypeError('Prompt policy dependencies required');
  if (!Number.isInteger(maxConcurrentRenders) || maxConcurrentRenders < 1 || maxConcurrentRenders > 16) {
    throw new TypeError('Bounded prompt policy concurrency required');
  }
  if (modeAuthority !== undefined && (typeof modeAuthority?.capture !== 'function' || typeof modeAuthority?.assertToken !== 'function')) throw new TypeError('Policy mode authority required');
  const capture = input => modeAuthority === undefined ? null : captureFeatureMode(modeAuthority, input.scope, 'policy');
  const inspectRender = (request, result) => result?.version === 2
    ? renderContract.validateRenderExecutionResult({version:2,mode:result.kind === 'literal' ? 'fixed' : 'vuln',request},result)
    : validateRenderResult(request,result);
  const uncertain = cause => Object.assign(new Error('Policy publication requires authoritative readback'),{code:'POLICY_OUTCOME_UNCERTAIN',cause});
  let active = 0;
  async function executeRender(raw, { signal, beforeEffect } = {}) {
    if (beforeEffect !== undefined && typeof beforeEffect !== 'function') throw new TypeError('Policy effect callback required');
    const captured = structuredClone(raw);
    if (!['upsert', 'preview'].includes(captured?.action)) throw new TypeError('Invalid policy render action');
    const taskPolicy = captured.request?.contractVersion === 2;
    captured.request = taskPolicy ? taskContract.normalizeTaskMutationRequest(captured.request) : normalizeRenderRequest(captured.request);
    const renderRequest = taskPolicy ? taskContract.renderRequest(captured.request) : captured.request;
    const policyDigest = taskPolicy ? taskContract.taskMutationDigest(captured.request) : null;
    const inspectReceipt = receipt => {
      if (taskPolicy || modeToken) {
        if (!receipt || receipt.operationId !== captured.request.operationId
          || (taskPolicy && receipt.policyRequestSha256 !== policyDigest) || receipt.requestSha256 !== requestDigest(renderRequest))
          throw new Error('Invalid task policy receipt');
        inspectRender(renderRequest, receipt.renderResult);
      }
      return structuredClone(receipt);
    };
    const modeToken = await capture(captured);
    const check = async () => { signal?.throwIfAborted(); if (modeToken) await modeToken.assertCurrent(); if (beforeEffect) await beforeEffect(); signal?.throwIfAborted(); };
    if (modeToken) captured.execution = structuredClone(modeToken.snapshot);
    await check();
    const admission = await repository.beginRender(captured, modeToken ? {modeToken} : undefined);
    if (admission?.operationId !== captured.request.operationId
      || admission.requestSha256 !== requestDigest(renderRequest)
      || (taskPolicy && admission.policyRequestSha256 !== policyDigest)
      || !['admitted', 'pending', 'completed'].includes(admission.state)) {
      throw new Error('Invalid policy render admission');
    }
    if (admission.state === 'completed') {
      if (!admission.receipt) throw new Error('Missing completed policy receipt');
      return Object.freeze({ state: 'completed', receipt: inspectReceipt(admission.receipt) });
    }
    // An earlier worker might still be executing. Neither a retry nor an
    // uncertain transport outcome authorizes a second sandbox execution.
    if (admission.state === 'pending') return Object.freeze({ state: 'pending', operationId: admission.operationId });
    await check();
    // @intentional-vulnerability ssti-policy-template — vulnerable bound policy publication executes the owned isolated template renderer.
    const rendered = modeToken?.snapshot.mode === 'fixed'
      ? renderContract.createLiteralRenderResult(renderRequest)
      : await renderer.render(renderRequest, { signal, ...(modeToken ? {executionMode:modeToken.snapshot.mode} : {}) });
    const renderResult = modeToken
      ? renderContract.validateRenderExecutionResult({version:2,mode:modeToken.snapshot.mode,request:renderRequest},rendered)
      : validateRenderResult(renderRequest, rendered);
    await check();
    const receipt = await repository.publish({ ...captured, renderResult }, modeToken ? {modeToken} : undefined);
    try { await check(); } catch (cause) { throw uncertain(cause); }
    return Object.freeze({ state: 'completed', receipt: inspectReceipt(receipt) });
  }
  return Object.freeze({
    async readiness(context) {
      if (context && modeAuthority !== undefined) {
        const token = await capture(context); await token.assertCurrent();
        if (token.snapshot.mode === 'fixed') return Object.freeze({ready:true});
      }
      // The route supplies current admin authority; no policy render or durable
      // operation is admitted by this installation capability check.
      if (typeof renderer.checkReadiness !== 'function' || await renderer.checkReadiness() !== true) {
        throw Object.assign(new Error('Strict policy renderer unavailable'), { code: 'POLICY_RENDER_UNAVAILABLE' });
      }
      return Object.freeze({ ready: true });
    },
    async render(raw, options = {}) {
      options.signal?.throwIfAborted();
      // Refuse before durable admission: a busy response must not strand a
      // pending operation which never reached its renderer. Readback stays free.
      if (active >= maxConcurrentRenders) throw Object.assign(new Error('Prompt policy renderer busy'), { code: 'POLICY_RENDER_BUSY' });
      active++;
      try { return await executeRender(raw, options); }
      finally { active--; }
    },
    async list(raw) {
      const input = structuredClone(raw);
      const value = await repository.list(input);
      const scopeKey = createHash('sha256').update(JSON.stringify(['prompt-policy-admin-v1',
        ...['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(key => input.scope[key]),
        input.persona.id, input.persona.role, input.personaSession.sessionId, input.personaSession.authorityVersion,
      ])).digest('hex');
      return { ...value, administration: { versionedPolicy: true, scopeKey } };
    },
    operation: input => repository.operation(structuredClone(input)),
    readAssessmentPublication: input => {
      if(typeof repository.readAssessmentPublication !== 'function') throw new TypeError('Policy evidence repository required');
      return repository.readAssessmentPublication(structuredClone(input));
    },
    async remove(input, {signal,beforeEffect} = {}) {
      const captured = structuredClone(input), modeToken = await capture(captured);
      const check = async () => { signal?.throwIfAborted(); if(modeToken)await modeToken.assertCurrent();if(beforeEffect)await beforeEffect();signal?.throwIfAborted(); };
      await check(); const result = await repository.remove(captured,modeToken?{modeToken}:undefined);
      try { await check(); } catch(cause) { throw uncertain(cause); }
      return result;
    },
  });
}

module.exports = { createBoundPromptPolicyService };
