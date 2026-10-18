'use strict';

// The advisory-mode cross-persona disclosure below is an unwired candidate
// teaching sink. It stays outside the shipped vulnerability inventory until
// its native/model/browser proof and catalog activation are reviewed.

const { randomUUID } = require('node:crypto');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const mailScene = require('./secureshopMailSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AUTHORITY_ERRORS = new Set(['STALE_LAUNCH','LAUNCH_UNAVAILABLE','PERSONA_INBOX_TARGET_UNAVAILABLE']);
function invalid(message) { return Object.assign(new TypeError(message), { code: 'INVALID_CONFIGURATION' }); }
function exact(value, keys) { return value && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value,key)); }
function wrap(value, isError = false) {
  const result = { content: Object.freeze([Object.freeze({ type: 'text', text: JSON.stringify(value) })]) };
  if (isError) result.isError = true;
  return Object.freeze(result);
}
function stableFailure(error) {
  if (error?.executionBoundary || error?.code==='SHOP_AUTH_INVALID' || AUTHORITY_ERRORS.has(error?.code)) throw error;
  return wrap({ ok: false, code: 'PERSONA_INBOX_OPERATION_FAILED', error: 'persona inbox operation failed' }, true);
}
function bindTarget(scope,target) {
  const expected = createLaunchScope(scope);
  const actual = createLaunchScope(mailScene.current(target));
  if (Object.keys(expected).some(key => expected[key] !== actual[key])
      || typeof target.targetId !== 'string') throw invalid('Persona inbox target binding mismatch');
  const birth = createLaunchScope(mailScene.birth(target));
  return mailScene.copy(target,{ targetId: target.targetId.toLowerCase(), ...birth });
}
function validateIndex(rows) {
  if (!Array.isArray(rows) || rows.length !== 3) throw invalid('Invalid persona inbox index');
  return Object.freeze(rows.map(row => {
    if (!Number.isSafeInteger(row?.messageId) || row.messageId < 1
        || !Number.isSafeInteger(row.ownerShopUserId) || row.ownerShopUserId < 1
        || !['customer','merchant','admin'].includes(row.ownerShopRole)
        || typeof row.subject !== 'string') throw invalid('Invalid persona inbox index');
    return Object.freeze({ message_id: row.messageId, owner_persona_id: row.ownerShopUserId,
      owner_role: row.ownerShopRole, subject: row.subject });
  }));
}
function validateRead(row,id) {
  if (!row || row.version !== 1 || row.messageId !== id || row.eventId !== row.operationId
      || !Number.isSafeInteger(row.ownerShopUserId) || !['customer','merchant','admin'].includes(row.ownerShopRole)
      || !Number.isSafeInteger(row.aclVersion) || !['advisory','enforced'].includes(row.aclMode)
      || !['allow','deny'].includes(row.aclDecision) || typeof row.crossPersona !== 'boolean'
      || typeof row.disclosed !== 'boolean' || row.disclosed !== (row.aclDecision === 'allow' || row.aclMode === 'advisory')
      || (row.disclosed && (typeof row.body !== 'string' || !/^[0-9a-f]{64}$/.test(row.bodySha256)))
      || (!row.disclosed && (row.body !== null || row.bodySha256 !== null))) throw invalid('Invalid persona inbox read result');
  return Object.freeze({ ok: true, event_id: row.eventId, message_id: row.messageId,
    owner_persona_id: row.ownerShopUserId, owner_role: row.ownerShopRole, subject: row.subject,
    body: row.body, body_sha256: row.bodySha256, acl: Object.freeze({ version: row.aclVersion,
      mode: row.aclMode, decision: row.aclDecision, cross_persona: row.crossPersona,
      disclosed: row.disclosed }) });
}

function createSecureShopPersonaInboxTools({ repository, trustedScope, trustedPersona,
  checkCurrent, resolveTarget, allowedMessageId, authorizedTargetId, mode = 'vuln', makeOperationId = randomUUID } = {}) {
  if (!repository || typeof repository.list !== 'function' || typeof repository.read !== 'function'
      || typeof checkCurrent !== 'function' || typeof resolveTarget !== 'function'
      || !Number.isSafeInteger(allowedMessageId) || allowedMessageId < 1
      || typeof authorizedTargetId !== 'string' || !UUID.test(authorizedTargetId)
      || typeof makeOperationId !== 'function' || !['vuln','fixed'].includes(mode)) throw invalid('Persona inbox tool dependencies required');
  const scope = createLaunchScope(trustedScope);
  const binding = createConversationBinding(scope,trustedPersona);
  const caller = Object.freeze({ id: binding.shopUserId, role: binding.role });
  let targetPromise;
  const target = async () => {
    if (!targetPromise) targetPromise = Promise.resolve().then(() => resolveTarget(scope)).then(value => {
      const selected = bindTarget(scope,value);
      if (selected.targetId !== authorizedTargetId.toLowerCase()) throw invalid('Persona inbox target binding mismatch');
      return selected;
    });
    try { return await targetPromise; } catch (error) { targetPromise = undefined; throw error; }
  };
  const list = async (args = {}) => {
    if (!exact(args,[])) return wrap({ ok:false,code:'INVALID_TOOL_ARGUMENTS',error:'no arguments are accepted' },true);
    try {
      await checkCurrent(scope); const selected = await target(); await checkCurrent(selected);
      const messages = validateIndex(await repository.list(selected)); await checkCurrent(selected);
      const visible = mode === 'fixed' ? messages.filter(row => row.owner_persona_id === caller.id && row.owner_role === caller.role) : messages;
      return wrap({ ok:true,count:visible.length,messages:visible });
    } catch (error) { return stableFailure(error); }
  };
  const read = async (args = {}) => {
    if (!exact(args,['message_id']) || !Number.isSafeInteger(args.message_id) || args.message_id < 1) {
      return wrap({ ok:false,code:'INVALID_TOOL_ARGUMENTS',error:'message_id must be a positive integer' },true);
    }
    if (args.message_id !== allowedMessageId) {
      return wrap({ ok:false,code:'INVALID_TOOL_ARGUMENTS',error:'message_id is outside this request' },true);
    }
    try {
      await checkCurrent(scope); const selected = await target(); await checkCurrent(selected);
      if (mode === 'fixed') {
        const messages = validateIndex(await repository.list(selected)); await checkCurrent(selected);
        if (!messages.some(row => row.message_id === args.message_id && row.owner_persona_id === caller.id && row.owner_role === caller.role)) {
          return wrap({ ok:false,code:'PERSONA_INBOX_ACCESS_DENIED',error:'message is outside this persona' },true);
        }
      }
      const value = await repository.read(selected,caller,{ messageId:args.message_id,operationId:makeOperationId() });
      await checkCurrent(selected);
      const projected = validateRead(value,args.message_id);
      if (mode === 'fixed' && (projected.owner_persona_id !== caller.id || projected.owner_role !== caller.role)) {
        return wrap({ ok:false,code:'PERSONA_INBOX_ACCESS_DENIED',error:'message is outside this persona' },true);
      }
      return wrap(projected);
    } catch (error) { return stableFailure(error); }
  };
  return Object.freeze({ 'persona-inbox.list_messages':list, 'persona-inbox.read_message':read });
}

module.exports = { createSecureShopPersonaInboxTools };
