'use strict';

const { isDeepStrictEqual } = require('node:util');
const { requestDigest } = require('../database/postgres/secureshopPersonaInboxRepository');
const { createConversationBinding } = require('./secureshopConversationBinding');
const mailScene = require('./secureshopMailSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function invalid() { return Object.assign(new Error('Persona inbox final response unavailable'), {
  code: 'PERSONA_INBOX_FINAL_RESPONSE_UNAVAILABLE',
}); }
function parseResult(result) {
  if (result?.isError === true || !Array.isArray(result?.content) || result.content.length !== 1
      || result.content[0]?.type !== 'text' || typeof result.content[0].text !== 'string') return null;
  try { return JSON.parse(result.content[0].text); } catch { return null; }
}
function scopeMatches(value, binding) {
  const current=mailScene.current(value);
  return current?.launchId === binding.launchId && current.scenarioId === binding.scenarioId
    && current.generation === binding.generation && current.platformOwnerId === binding.platformOwnerId
    && current.platformSessionId === binding.platformSessionId;
}

function createSecureShopPersonaInboxFinalResponseGate({ requestAuthority, resolveTarget,
  readAccessEvent, checkCurrent } = {}) {
  if (typeof requestAuthority?.resolve !== 'function' || typeof resolveTarget !== 'function'
      || typeof readAccessEvent !== 'function' || typeof checkCurrent !== 'function') throw invalid();
  return async function enterFinalResponse(packet) {
    const { execution, sessionId, requestId, localToolAuthority, observation } = packet || {};
    const binding = createConversationBinding(packet?.binding, { id: packet?.binding?.shopUserId,
      role: packet?.binding?.role });
    const allowed = requestAuthority.resolve(localToolAuthority, { binding, sessionId, requestId });
    const receipt = observation?.effectReceipt;
    const payload = parseResult(observation?.result);
    if (observation?.tool !== 'persona-inbox.read_message'
        || !Number.isSafeInteger(observation?.step) || observation.step < 1
        || typeof observation?.callId !== 'string' || !observation.callId
        || !isDeepStrictEqual(observation.args, { message_id: allowed.messageId })
        || payload?.ok !== true || payload.message_id !== allowed.messageId
        || typeof payload.event_id !== 'string' || !UUID.test(payload.event_id)
        || receipt?.version !== 1 || receipt.status !== 'completed'
        || receipt.runId !== execution?.runId || receipt.ownerKey !== execution?.ownerKey
        || receipt.generation !== String(execution?.durableGeneration)
        || receipt.effectKey !== `${requestId}:${JSON.stringify([
          observation.step, observation.callId, observation.tool])}`) return false;
    await execution.check();
    const target = await resolveTarget(binding);
    if (!scopeMatches(target, binding) || target.targetId !== allowed.targetId) return false;
    await checkCurrent(target);
    const source = await readAccessEvent(target, payload.event_id);
    await checkCurrent(target);
    if (!source || !scopeMatches(source, binding) || source.targetId !== allowed.targetId
        || source.eventId !== payload.event_id || source.operationId !== payload.event_id
        || source.messageId !== allowed.messageId || source.callerShopUserId !== binding.shopUserId
        || source.callerShopRole !== binding.role || source.ownerShopUserId !== payload.owner_persona_id
        || source.ownerShopRole !== payload.owner_role || source.subject !== payload.subject
        || source.body !== payload.body || source.bodySha256 !== payload.body_sha256
        || source.aclVersion !== payload.acl?.version || source.aclMode !== payload.acl?.mode
        || source.aclDecision !== payload.acl?.decision || source.crossPersona !== payload.acl?.cross_persona
        || source.disclosed !== payload.acl?.disclosed
        || source.requestSha256 !== requestDigest(target, { id: binding.shopUserId, role: binding.role },
          allowed.messageId, payload.event_id).toString('hex')) return false;
    await execution.check();
    return true;
  };
}

module.exports = { createSecureShopPersonaInboxFinalResponseGate };
