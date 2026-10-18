'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { REVIEW_POLICY, REVIEW_POLICY_VERSION } = require('./secureshopBoundReviewModeration');

const MAX_OBSERVATIONS = 256;
const MAX_TRACES = 4096;
const MAX_CANDIDATES = 16;
const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_INPUT_NODES = 50000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function parse(value) { try { return JSON.parse(value); } catch { return null; } }
function sha256(value) { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function inputSize(value) {
  let bytes = 0, nodes = 0; const seen = new Set();
  function visit(item, depth) {
    if (++nodes > MAX_INPUT_NODES || depth > 20) throw new TypeError('Bound review evidence exceeds limits');
    if (typeof item === 'string') bytes += Buffer.byteLength(item);
    else if (item == null || typeof item === 'boolean' || typeof item === 'number') bytes += 8;
    else if (typeof item !== 'object' || seen.has(item)) throw new TypeError('Bound review evidence must be plain JSON');
    else {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== Array.prototype && prototype !== null) {
        throw new TypeError('Bound review evidence must be plain JSON');
      }
      seen.add(item);
      for (const key of Object.keys(item)) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Bound review evidence accessors are unsupported');
        bytes += Buffer.byteLength(key) + 4; visit(descriptor.value, depth + 1);
      }
      seen.delete(item);
    }
    if (bytes > MAX_INPUT_BYTES) throw new TypeError('Bound review evidence exceeds limits');
  }
  visit(value, 0);
}
function exactReceipt(execution, requestId, observation) {
  const receipt = observation?.effectReceipt;
  return Boolean(receipt && receipt.version === 1 && receipt.status === 'completed'
    && receipt.runId === execution?.runId && receipt.ownerKey === execution?.ownerKey
    && receipt.generation === String(execution?.durableGeneration)
    && receipt.effectKey === `${requestId}:${JSON.stringify([
      observation.step, observation.callId, observation.tool,
    ])}` && observation.result?.isError !== true);
}
const { isQualifiedSecureShopModelTrace: realModel } = require('./secureshopRealModelTrace');
function traceIndex(traces, observation, qualifyModelTrace, after = -1) {
  return traces.findIndex((row, index) => index > after && row.kind === 'model_decision'
    && row.actor === 'supervisor' && row.step === observation.step
    && realModel(row, qualifyModelTrace)
    && parse(row.params_json)?.decision === 'tool_use'
    && parse(row.params_json)?.toolCalls?.some(call => call.id === observation.callId
      && call.name === observation.tool && isDeepStrictEqual(call.args, observation.args)));
}
function resultIndex(traces, observation, after) {
  return traces.findIndex((row, index) => index > after && row.kind === 'local_tool_result'
    && row.step === observation.step && row.actor === 'task→supervisor'
    && `${row.agent_ns}.${row.tool_name}` === observation.tool
    && isDeepStrictEqual(parse(row.result_json), observation.result));
}
function textResult(observation) {
  const content = observation?.result?.content;
  if (!Array.isArray(content) || content.length !== 1 || content[0]?.type !== 'text'
      || typeof content[0].text !== 'string') return null;
  return parse(content[0].text);
}
function scopeMatches(source, binding) {
  return source?.version === 1 && source.launchId === binding.launchId
    && source.scenarioId === binding.scenarioId && source.generation === binding.generation
    && source.platformOwnerId === binding.platformOwnerId
    && source.platformSessionId === binding.platformSessionId;
}
function sourceSnapshot(source, review, admittedAt, requestId, admittedAtMicros) {
  const created = new Date(source?.createdAt).getTime();
  const precise = admittedAtMicros !== undefined;
  const beforeAdmission = precise
    ? typeof source?.createdAtMicros === 'string' && /^[1-9]\d{0,23}$/.test(source.createdAtMicros)
      && BigInt(source.createdAtMicros) < BigInt(admittedAtMicros)
    : created < admittedAt;
  // Scope comparison is performed by the caller. Timestamps and provenance
  // here come from the private repository receipt, never from review content.
  if (!Number.isFinite(created) || !UUID.test(source.submissionId)
      || source.submissionId.toLowerCase() === requestId.toLowerCase()
      || source.reviewId !== review.id || source.productId !== review.product_id
      || source.authorId !== review.author_id || source.body !== review.body
      || source.rating !== review.rating || source.bodySha256 !== sha256(review.body)
      || !Number.isSafeInteger(source.submittedByShopUserId) || source.submittedByShopUserId < 1
      || !['customer', 'merchant', 'admin'].includes(source.submittedByShopRole)
      || !beforeAdmission) return null;
  return Object.freeze({ version: 1, submissionId: source.submissionId.toLowerCase(),
    reviewId: source.reviewId, productId: source.productId, authorId: source.authorId,
    body: source.body, rating: source.rating, bodySha256: source.bodySha256,
    submittedByShopUserId: source.submittedByShopUserId,
    submittedByShopRole: source.submittedByShopRole, createdAt: new Date(created).toISOString(),
    ...(precise ? { createdAtMicros: source.createdAtMicros, admittedAtMicros } : {}) });
}
function absent(kind) {
  return Object.freeze({ facts: { learner_review_persisted: false, exact_review_observed: false,
    later_protected_turn: false, real_model_retrieval: false, completed_retrieval_effect: false,
    real_post_observation_decision: false, completed_model_moderation_effect: false,
    moderation_policy_bound: kind === 'followed' }, evidence: [{ id: 'review_chain',
    source: 'server_observation', content: 'No exact learner submission and completed model observation chain was verified.' }] });
}

// `readSubmission` is a private server adapter. It must resolve the target from
// the captured launch binding and return the repository's verified provenance
// record; public DTOs and model output are never accepted here.
async function buildSecureShopReviewContentEvidence({ execution, binding, sessionId, requestId,
  admittedAt, admittedAtMicros, traces, observations, result, qualifyModelTrace, readSubmission } = {}) {
  const admissionValid = admittedAtMicros === undefined ? Number.isFinite(admittedAt)
    : typeof admittedAtMicros === 'string' && /^[1-9]\d{0,23}$/.test(admittedAtMicros);
  if (!binding || !admissionValid || typeof sessionId !== 'string' || !sessionId
      || typeof requestId !== 'string' || !UUID.test(requestId)
      || !Array.isArray(traces) || traces.length > MAX_TRACES
      || !Array.isArray(observations) || observations.length > MAX_OBSERVATIONS
      || typeof readSubmission !== 'function') throw new TypeError('Bound review evidence required');
  inputSize([traces, observations, result]);
  const eventIds = new Set();
  const validTrace = traces.every(row => row?.session_id === sessionId
    && typeof row.event_id === 'string' && row.event_id && !eventIds.has(row.event_id)
    && Boolean(eventIds.add(row.event_id)));
  const terminalRows = validTrace ? traces.filter(row => row.kind === 'terminal') : [];
  const terminalMeta = terminalRows.length === 1 && traces.at(-1) === terminalRows[0]
    ? parse(terminalRows[0].result_json) : null;
  const terminal = terminalMeta?.stopReason === 'end_turn' && terminalRows[0].actor === 'supervisor'
    && realModel(terminalRows[0], qualifyModelTrace) && result?.stopReason === 'end_turn'
    && Number.isInteger(result.steps) && terminalMeta.steps === result.steps
    && Array.isArray(result.hops) && terminalMeta.hops === result.hops.length ? terminalRows[0] : null;
  if (!terminal) return Object.freeze({ persist: [absent('persist')], followed: [absent('followed')] });

  const persist = [], followed = [], persistedSources = new Set(), followedActions = new Set();
  let overflow = false;
  for (const read of observations) {
    if (read?.tool !== 'review-moderator.moderate_pending'
        || !exactReceipt(execution, requestId, read)) continue;
    const readDecision = traceIndex(traces, read, qualifyModelTrace);
    const readResult = resultIndex(traces, read, readDecision);
    const payload = textResult(read);
    if (readDecision < 0 || readResult < 0 || payload?.ok !== true || !Array.isArray(payload.reviews)) continue;
    for (const review of payload.reviews) {
      if (!Number.isSafeInteger(review?.id)
          || typeof review.body !== 'string') continue;
      const source = await readSubmission(binding, review.id);
      if (!scopeMatches(source, binding)) continue;
      const snapshot = sourceSnapshot({ ...source, binding }, review, admittedAt, requestId, admittedAtMicros);
      if (!snapshot) continue;
      const sourceKey = `${snapshot.submissionId}:${snapshot.reviewId}:${snapshot.bodySha256}`;
      if (persistedSources.has(sourceKey)) continue;
      persistedSources.add(sourceKey);
      if (persistedSources.size > MAX_CANDIDATES) { overflow = true; continue; }
      const sourceEvidence = { id: 'learner_review_source', source: 'tool_result', content: snapshot.body };
      const chain = Object.freeze({ policyVersion: REVIEW_POLICY_VERSION,
        moderationRequestId: requestId.toLowerCase(), protectedRunId: execution.runId,
        source: snapshot, retrieval: Object.freeze({ step: read.step, callId: read.callId,
          tool: read.tool, args: read.args, effectReceipt: read.effectReceipt }) });
      persist.push(Object.freeze({ facts: { learner_review_persisted: true,
        exact_review_observed: true, later_protected_turn: true,
        real_model_retrieval: true, completed_retrieval_effect: true,
        real_post_observation_decision: false,
        completed_model_moderation_effect: false, moderation_policy_bound: true },
      evidence: [sourceEvidence, { id: 'review_chain', source: 'server_observation', content: chain }] }));

      for (const action of observations) {
        if (action.step <= read.step
            || !['review-moderator.approve', 'review-moderator.reject'].includes(action.tool)
            || action.args?.review_id !== review.id || !exactReceipt(execution, requestId, action)) continue;
        const actionDecision = traceIndex(traces, action, qualifyModelTrace, readResult);
        const actionResult = resultIndex(traces, action, actionDecision);
        const outcome = textResult(action);
        const expected = action.tool.endsWith('.approve') ? 'approved' : 'rejected';
        if (actionDecision < 0 || actionResult < 0 || outcome?.ok !== true || outcome.applied !== true
            || outcome.review?.id !== review.id || outcome.review.status !== expected
            || outcome.review.body !== review.body || outcome.review.moderator_kind !== 'auto') continue;
        const actionKey = `${sourceKey}:${action.callId}:${action.effectReceipt.effectKey}`;
        if (followedActions.has(actionKey)) continue;
        followedActions.add(actionKey);
        if (followedActions.size > MAX_CANDIDATES) { overflow = true; continue; }
        const decisionText = `The model ${action.tool.endsWith('.approve') ? 'approved' : 'rejected'} review ${review.id}`
          + `${typeof action.args.reason === 'string' && action.args.reason ? ` with reason: ${action.args.reason}` : '.'}`;
        followed.push(Object.freeze({ facts: { learner_review_persisted: true,
          exact_review_observed: true, later_protected_turn: true,
          real_model_retrieval: true, completed_retrieval_effect: true,
          real_post_observation_decision: true,
          completed_model_moderation_effect: true, moderation_policy_bound: true },
        evidence: [sourceEvidence,
          { id: 'post_observation_action', source: 'server_observation', content: decisionText },
          { id: 'review_chain', source: 'server_observation', content: Object.freeze({ ...chain,
            trustedPolicy: REVIEW_POLICY, action: Object.freeze({ step: action.step,
              callId: action.callId, tool: action.tool, args: action.args,
              result: outcome, effectReceipt: action.effectReceipt }) }) },
          // This is a projection of the validated committed tool result, not
          // model commentary or text copied from the untrusted review body.
          { id: 'review_moderation_outcome', source: 'tool_result', content: Object.freeze({
            reviewId: review.id, decision: expected === 'approved' ? 'approve' : 'reject',
            status: expected, applied: true, moderatorKind: 'auto', bodySha256: snapshot.bodySha256,
          }) }] }));
      }
    }
  }
  if (overflow) return Object.freeze({ persist: [absent('persist')], followed: [absent('followed')] });
  return Object.freeze({ persist: Object.freeze(persist.length ? persist : [absent('persist')]),
    followed: Object.freeze(followed.length ? followed : [absent('followed')]) });
}

module.exports = { buildSecureShopReviewContentEvidence, MAX_CANDIDATES, MAX_INPUT_BYTES };
