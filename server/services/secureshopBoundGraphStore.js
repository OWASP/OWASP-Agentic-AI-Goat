'use strict';
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTraceBuffer } = require('./secureshop/traceBuffer');
const { snapshotBoundTraceRows } = require('./secureshopBoundTraceRecord');
const { normalizeConversationPurpose } = require('./secureshopConversationPurpose');

// This metadata is supplied only by the runner's privately branded feature fence.
// Never derive it from content, tool output, or the current UI selection.
function capability(value){
 const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Reflect.ownKeys(v).length===keys.length&&keys.every(k=>Object.hasOwn(Object.getOwnPropertyDescriptor(v,k)||{},'value'));
 if(!exact(value,['version','featureId','policyVersion','effectiveMode','scope'])||value.version!==1||!['vuln','fixed'].includes(value.effectiveMode)||typeof value.featureId!=='string'||!/^[a-z][a-z0-9_]{0,63}$/.test(value.featureId)||typeof value.policyVersion!=='string'||!/^[a-z0-9-]{1,128}$/.test(value.policyVersion)||!exact(value.scope,['kind','id'])||value.scope.kind!=='launch_feature'||value.scope.id!==value.featureId)throw new TypeError('Trusted feature mode capability required');
 return Object.freeze({...value,scope:Object.freeze({...value.scope})});
}
function matchingFixed(value,current){
 try{const saved=capability(value);return saved.effectiveMode==='fixed'&&saved.version===current.version&&saved.featureId===current.featureId&&saved.policyVersion===current.policyVersion;}catch{return false;}
}
function modelMessage(value){const {modeCapability:_mode,...message}=value;return message;}


// Per-run closure; no platform binding is added to messages or trace payloads.
// Independent task batches can limit model context and budget to this turn while
// retaining every message, trace and token increment in the durable conversation.
function createBoundGraphStore({ sessionId, scope, persona, service, repository, check, onTracesPersisted,
  conversationPurpose, tokenBudget = 100000, executionScope = 'conversation', modeCapability }) {
  const trustedMode=modeCapability===undefined?undefined:capability(modeCapability);
  const binding = createConversationBinding(scope, persona);
  const purpose = normalizeConversationPurpose(conversationPurpose);
  if (!['conversation', 'turn'].includes(executionScope)) throw new TypeError('Invalid execution scope');
  const turnMessages = [];
  let turnTokens = 0;
  const trustedPersona = Object.freeze({ id: binding.shopUserId, role: binding.role });
  if (!Number.isInteger(tokenBudget) || tokenBudget < 1) throw new TypeError('Invalid token budget');
  if (onTracesPersisted !== undefined && typeof onTracesPersisted !== 'function') throw new TypeError('Invalid trace observer');
  async function authorize(id) {
    if (id !== sessionId) throw new Error('Conversation mismatch');
    if (check) await check();
    await service.assertOwned(sessionId, binding, trustedPersona, purpose);
    if (check) await check();
  }
  async function append(id, message) {
    await authorize(id);
    const stored=trustedMode?{...message,modeCapability:trustedMode}:message;
    if (executionScope === 'conversation') return repository.appendMessage(sessionId, binding, stored, purpose);
    const snapshot = structuredClone(message);
    const result = await repository.appendMessage(sessionId, binding, structuredClone(stored), purpose);
    turnMessages.push(snapshot);
    return result;
  }
  const store = Object.freeze({
    appendUserMessage: (id, content) => append(id, { role: 'user', content }),
    appendAssistantMessage: (id, content) => append(id, { role: 'assistant', content }),
    appendToolResult: (id, toolCallId, content) => append(id, { role: 'tool', tool_call_id: toolCallId, content }),
    appendAssistantToolCalls: (id, calls) => append(id, { role: 'assistant', content: '', tool_calls: calls.map(call => ({
      id: call.id, type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args || {}) },
    })) }),
    async getMessages(id) {
      await authorize(id);
      if(executionScope==='turn')return structuredClone(turnMessages);
      const history=await service.getMessages(sessionId,binding,trustedPersona,purpose);
      return history.filter(row=>trustedMode?.effectiveMode!=='fixed'||matchingFixed(row.modeCapability,trustedMode)).map(modelMessage);
    },
    async remainingBudget(id) {
      await authorize(id);
      return tokenBudget - (executionScope === 'turn' ? turnTokens
        : await repository.getTokens(sessionId, binding, purpose));
    },
    async addUsedTokens(id, count) {
      await authorize(id);
      if (executionScope === 'turn' && (!Number.isSafeInteger(count) || count < 0
          || !Number.isSafeInteger(turnTokens + count))) throw new TypeError('Invalid token count');
      const result = await repository.addTokens(sessionId, binding, count, purpose);
      if (executionScope === 'turn') turnTokens += count;
      return result;
    },
  });
  class Trace {
    constructor(id) {
      if (id !== sessionId) throw new Error('Conversation mismatch');
      this.buffer = createTraceBuffer(async rows => {
        const persisted = snapshotBoundTraceRows(rows);
        await authorize(sessionId);
        await repository.appendTraces(sessionId, binding, persisted, purpose);
        if (onTracesPersisted) {
          await authorize(sessionId);
          await onTracesPersisted(persisted);
        }
      });
    }
    record(row) { this.buffer.record({ ...row, session_id: sessionId }); }
    flush() { return this.buffer.flush(); }
  }
  return Object.freeze({ store, Trace });
}
module.exports = { createBoundGraphStore };
