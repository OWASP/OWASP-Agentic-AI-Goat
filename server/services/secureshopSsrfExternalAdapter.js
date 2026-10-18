'use strict';

const crypto = require('node:crypto');
const {POLICY_SHA256: HTML_POLICY_SHA256}=require('./secureshopPolicyFinalHtmlContract');
const policyHash=kind=>kind==='html-policy'?HTML_POLICY_SHA256:EGRESS_POLICY_SHA256;
const policyDecision=kind=>kind==='private-policy'?'denied':'allowed';
const { digestMcpValue } = require('./secureshopMcpTrustTools');
const { createPrivateRecoverableToolErrorClassifier } = require('./secureshopRecoverableToolError');
const { featureModeForFence } = require('./secureshopFeatureModeAuthority');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CALL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SCOPE_KEYS = Object.freeze(['targetId', 'launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']);
const LAUNCH_SCOPE_KEYS = Object.freeze(SCOPE_KEYS.filter(key => key !== 'targetId'));
const DIGEST_KEYS = Object.freeze(['argumentsSha256', 'resultSha256', 'responseSha256', 'egressReceiptSha256']);
const EGRESS_POLICY = Object.freeze({ allowedResourceKinds: Object.freeze(['public-policy']),
  deniedResourceKinds: Object.freeze(['private-policy']) });
const EGRESS_POLICY_SHA256 = digestMcpValue(EGRESS_POLICY);

function unavailable(message = 'Bound SSRF observation unavailable') {
  return Object.assign(new Error(message), { code: 'BOUND_SSRF_UNAVAILABLE' });
}
function sameScope(left, right) { return SCOPE_KEYS.every(key => left?.[key] === right?.[key]); }
function sameLaunchScope(left, right) { return LAUNCH_SCOPE_KEYS.every(key => left?.[key] === right?.[key]); }
function parseResult(result) {
  try { return JSON.parse(result?.content?.[0]?.text); }
  catch { throw unavailable('SSRF tool result unavailable'); }
}

function createSecureShopSsrfExternalAdapter({ resolveRequest, targetPool, upstreamPool,
  recordInvocation, checkCurrent } = {}) {
  if (typeof resolveRequest !== 'function' || typeof targetPool?.consume !== 'function'
    || typeof targetPool?.readReceipt !== 'function'
    || typeof upstreamPool?.callTool !== 'function' || typeof recordInvocation !== 'function'
    || typeof checkCurrent !== 'function') throw unavailable();

  async function current(request, personaFence) {
    try { await checkCurrent(request); await personaFence?.assertRemoteAdmission(); }
    catch (error) { if (personaFence) error.executionBoundary = true; throw error; }
  }

  async function resolve(binding, context) {
    const value = await resolveRequest(binding, context);
    if (!value || !sameLaunchScope(value, binding) || !UUID.test(value.targetId) || !UUID.test(value.requestId)
      || value.requestId !== context.requestId || !UUID.test(value.nonce) || !UUID.test(value.operationId)
      || !['public-policy', 'private-policy','html-policy'].includes(value.resourceKind) || value.egressPolicySha256 !== policyHash(value.resourceKind)
      || value.policyDecision !== policyDecision(value.resourceKind)
      || typeof value.url !== 'string') throw unavailable();
    let url;
    try { url = new URL(value.url); } catch { throw unavailable(); }
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.hash
      || url.search) throw unavailable();
    return Object.freeze({ ...value, url: url.href });
  }

  async function createToolPool(binding, context, personaFence) {
    const execution = context?.execution;
    if (!execution || !UUID.test(execution.runId) || typeof execution.ownerKey !== 'string' || !execution.ownerKey
      || execution.durableGeneration == null || typeof execution.check !== 'function'
      || !UUID.test(context?.requestId) || typeof context?.sessionId !== 'string' || !context.sessionId) throw unavailable();
    await execution.check();
    const request = await resolve(binding, context);
    await current(request, personaFence);
    const recoverableErrors = createPrivateRecoverableToolErrorClassifier();
    const fixed = featureModeForFence(personaFence)?.effectiveMode === 'fixed';
    return Object.freeze({
      async callTool(agent, tool, args, callContext) {
        await execution.check();
        await current(request, personaFence);
        if (!CALL_ID.test(callContext?.callId || '')) {
          throw unavailable('Selected SSRF tool request is unavailable');
        }
        if (agent !== 'summarizer' || tool !== 'explain_return_policy') {
          throw recoverableErrors.brand(unavailable('Selected SSRF tool request is unavailable'), 'INVALID_TOOL_SELECTION');
        }
        if (Object.keys(args || {}).length !== 1 || args.policy_url !== request.url) {
          throw recoverableErrors.brand(unavailable('Selected SSRF tool request is unavailable'), 'INVALID_TOOL_ARGUMENTS');
        }
        if (fixed) {
          if (!['public-policy','html-policy'].includes(request.resourceKind) || request.policyDecision !== 'allowed') {
            throw recoverableErrors.brand(unavailable('Private destination blocked by fixed egress policy'), 'INVALID_TOOL_SELECTION');
          }
          if (typeof targetPool.assertIssuedPublicRequest !== 'function') throw unavailable('Owned public destination authority unavailable');
          targetPool.assertIssuedPublicRequest(request, { nonce: request.nonce, requestId: request.requestId,
            resourceKind: request.resourceKind, url: args.policy_url });
          await current(request, personaFence);
        }
        const result = await upstreamPool.callTool(agent, tool, args, { ...callContext, signal: execution.signal });
        await execution.check();
        await current(request, personaFence);
        const receipt = targetPool.readReceipt(request, { nonce: request.nonce, requestId: context.requestId });
        const parsed = parseResult(result);
        if (fixed && parsed?.status !== 200) throw unavailable('Owned public destination did not return an admitted response');
        if (parsed?.url !== request.url || parsed.status !== receipt.status || typeof parsed.body !== 'string'
          || crypto.createHash('sha256').update(parsed.body).digest('hex') !== receipt.responseSha256
          || receipt.operationId !== request.operationId || receipt.resourceKind !== request.resourceKind) {
          throw unavailable('SSRF response receipt mismatch');
        }
        return Object.freeze({
          ...result,
          _meta: Object.freeze({
            version: 1, operationId: request.operationId, targetId: request.targetId,
            runId: execution.runId, ownerKey: execution.ownerKey,
            generation: String(execution.durableGeneration), requestId: context.requestId,
            sessionId: context.sessionId, callId: callContext.callId, nonce: request.nonce,
            resourceKind: request.resourceKind, requestMethod: receipt.method, requestPath: receipt.path,
            responseStatus: receipt.status, responseSha256: receipt.responseSha256,
            egressReceiptSha256: receipt.receiptSha256, egressPolicySha256: request.egressPolicySha256,
            policyDecision: request.policyDecision, argumentsSha256: digestMcpValue(args),
            resultSha256: digestMcpValue(parsed),
          }),
        });
      },
      projectRecoverableToolError(error) { return recoverableErrors.project(error); },
    });
  }

  async function observeExternalTool(packet, personaFence) {
    const execution = packet?.run, observation = packet?.observation, meta = observation?.result?._meta;
    if (!execution || !UUID.test(execution.runId) || typeof execution.ownerKey !== 'string' || !execution.ownerKey
      || execution.durableGeneration == null || typeof execution.check !== 'function' || !UUID.test(packet?.requestId)
      || typeof packet?.sessionId !== 'string' || !packet.sessionId || !CALL_ID.test(observation?.callId || '')
      || observation.tool !== 'summarizer.explain_return_policy' || meta?.version !== 1
      || meta.runId !== execution.runId || meta.ownerKey !== execution.ownerKey
      || meta.generation !== String(execution.durableGeneration) || meta.requestId !== packet.requestId
      || meta.sessionId !== packet.sessionId || meta.callId !== observation.callId || !UUID.test(meta.operationId)
      || DIGEST_KEYS.some(key => typeof meta[key] !== 'string' || !/^[0-9a-f]{64}$/.test(meta[key]))
      || meta.egressPolicySha256 !== policyHash(meta.resourceKind)
      || meta.policyDecision !== policyDecision(meta.resourceKind)
      || !['public-policy', 'private-policy','html-policy'].includes(meta.resourceKind)
      || meta.requestMethod !== 'GET' || typeof meta.requestPath !== 'string' || meta.responseStatus !== 200
      || digestMcpValue(observation.args) !== meta.argumentsSha256) throw unavailable();
    await execution.check();
    const effect = observation.effectReceipt;
    const expected = `${packet.requestId}:${JSON.stringify([observation.step, observation.callId, observation.tool])}`;
    if (effect?.version !== 1 || effect.status !== 'completed' || effect.runId !== execution.runId
      || effect.ownerKey !== execution.ownerKey || effect.generation !== String(execution.durableGeneration)
      || effect.effectKey !== expected) throw unavailable('Completed SSRF effect receipt mismatch');
    const request = await resolve(packet.binding, {
      requestId: packet.requestId, sessionId: packet.sessionId, execution,
    });
    await current(request, personaFence);
    if (featureModeForFence(personaFence)?.effectiveMode === 'fixed'
      && (!['public-policy','html-policy'].includes(request.resourceKind) || request.policyDecision !== 'allowed')) throw unavailable('Fixed egress receipt unavailable');
    if (request.targetId !== meta.targetId || request.nonce !== meta.nonce || request.operationId !== meta.operationId
      || request.resourceKind !== meta.resourceKind) throw unavailable();
    const parsed = parseResult(observation.result);
    if (digestMcpValue(parsed) !== meta.resultSha256) throw unavailable('SSRF result changed');
    const authoritative = targetPool.readReceipt(request, { nonce: request.nonce, requestId: packet.requestId });
    if (authoritative.operationId !== meta.operationId || authoritative.targetId !== meta.targetId
      || authoritative.nonce !== meta.nonce || authoritative.requestId !== meta.requestId
      || authoritative.resourceKind !== meta.resourceKind || authoritative.method !== meta.requestMethod
      || authoritative.path !== meta.requestPath || authoritative.status !== meta.responseStatus
      || authoritative.responseSha256 !== meta.responseSha256 || authoritative.receiptSha256 !== meta.egressReceiptSha256
      || parsed.url !== request.url || parsed.status !== authoritative.status || typeof parsed.body !== 'string'
      || crypto.createHash('sha256').update(parsed.body).digest('hex') !== authoritative.responseSha256) {
      throw unavailable('SSRF authoritative receipt mismatch');
    }
    const recorded = await recordInvocation(request, {
      operationId: meta.operationId, runId: execution.runId, requestId: packet.requestId,
      sessionId: packet.sessionId, callId: observation.callId, argumentsSha256: meta.argumentsSha256,
      resultSha256: meta.resultSha256, responseSha256: meta.responseSha256,
      egressReceiptSha256: meta.egressReceiptSha256, requestMethod: meta.requestMethod,
      requestPath: meta.requestPath, responseStatus: meta.responseStatus, resourceKind: meta.resourceKind,
      egressPolicySha256: meta.egressPolicySha256, policyDecision: meta.policyDecision,
    }, { id: packet.binding.shopUserId, role: packet.binding.role }, personaFence);
    await execution.check();
    await current(request, personaFence);
    const consumed = targetPool.consume(request, { nonce: request.nonce, requestId: packet.requestId });
    if (consumed !== authoritative) throw unavailable('SSRF receipt changed before commit');
    return Object.freeze({ invocation: recorded, effectReceipt: effect, observation });
  }

  return Object.freeze({ createToolPool, observeExternalTool });
}

module.exports = { createSecureShopSsrfExternalAdapter, SSRF_EGRESS_POLICY: EGRESS_POLICY,
  SSRF_EGRESS_POLICY_SHA256: EGRESS_POLICY_SHA256 };
