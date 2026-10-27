'use strict';
const { createHash } = require('node:crypto');
const capabilities = new WeakMap();
const consumed = new WeakSet();
const INSTRUCTION = 'The previous decision has invalid audit tool arguments or invalid JSON. No tool or policy admission was executed. Return one corrected decision matching the existing tool schema and original requested count. Choose argument values from the original task; do not invent identifiers.';
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const failure = () => Object.assign(new Error('Audit decision correction is invalid'), { code: 'AUDIT_DECISION_CORRECTION_INVALID' });
function auditDecisionSchema() {
  const tools=require('./secureshopAuditExecutionConfig').createSecureShopAuditExecutionConfig({enableFocus:true}).manifest.getForRole('admin');
  return require('./secureshop/providers/ollamaProvider').closedDecisionSchema(tools);
}
function classification(raw, count) {
  let value; try { value = JSON.parse(raw); } catch { return 'invalid_json'; }
  if (!value || Object.keys(value).length !== 1 || !Array.isArray(value.tool_calls)
      || value.tool_calls.length !== 1) return 'terminal';
  const call = value.tool_calls[0];
  if (!call || Object.keys(call).sort().join(',') !== 'agent,args,tool'
      || call.agent !== 'audit' || call.tool !== 'summarize_anomalies') return 'terminal';
  const args = call.args;
  return args && Object.getPrototypeOf(args) === Object.prototype
    && Object.keys(args).sort().join(',') === 'focus_action,limit' && args.limit === count
    && typeof args.focus_action === 'string' && /^[A-Za-z0-9_.:-]{1,100}$/.test(args.focus_action)
    ? 'accepted' : 'invalid_arguments';
}
function createAuditDecisionCorrection({ requestedCount, check, record }) {
  if (!Number.isSafeInteger(requestedCount) || requestedCount < 1
      || typeof check !== 'function' || typeof record !== 'function') throw failure();
  const token = Object.freeze({});
  capabilities.set(token, Object.freeze({ requestedCount, check, record }));
  return token;
}
function captureAuditDecisionCorrection(token) {
  if (!capabilities.has(token) || consumed.has(token)) throw failure();
  consumed.add(token);
  return capabilities.get(token);
}
function verifyAuditDecisionAttempts(attempts, count) {
  if (!Array.isArray(attempts) || attempts.length < 1 || attempts.length > 2) throw failure();
  for (const [index, attempt] of attempts.entries()) {
    const versioned=attempt&&Object.hasOwn(attempt,'schemaVersion');
    if (!attempt || Object.keys(attempt).sort().join(',') !== (versioned?'classification,index,model,provider,raw,request,schemaVersion,usage':'classification,index,model,provider,raw,request,usage')
        ||versioned&&attempt.schemaVersion!==2
        || attempt.index !== index || attempt.provider !== 'ollama' || typeof attempt.model !== 'string'
        || !attempt.model || typeof attempt.raw !== 'string' || Buffer.byteLength(attempt.raw) > 65536
        || attempt.classification !== classification(attempt.raw, count)
        || !attempt.request || Object.keys(attempt.request).sort().join(',') !== 'format,messages,numPredict'
        || !Array.isArray(attempt.request.messages) || Buffer.byteLength(JSON.stringify(attempt.request)) > 131072
        || !Number.isSafeInteger(attempt.request.numPredict) || attempt.request.numPredict < 1
        || attempt.request.numPredict > 2048) throw failure();
    if (!attempt.usage || Object.keys(attempt.usage).sort().join(',') !== 'inputTokens,outputTokens,totalTokens'
        || Object.values(attempt.usage).some(value=>value!==null&&(!Number.isSafeInteger(value)||value<0))
        || attempt.usage.outputTokens!==null&&attempt.usage.outputTokens>attempt.request.numPredict
        || JSON.stringify(attempt.request.format)!==JSON.stringify(versioned?auditDecisionSchema():require('./secureshop/providers/ollamaProvider').DECISION_SCHEMA)) throw failure();
    if (index === 0 && attempts.length === 2) {
      if (!['invalid_json', 'invalid_arguments'].includes(attempt.classification)
          || !Number.isSafeInteger(attempt.usage?.outputTokens) || attempt.usage.outputTokens < 0
          || attempt.usage.outputTokens >= attempt.request.numPredict) throw failure();
    }
    if (index === 1) {
      const first = attempts[0];
      if (attempt.schemaVersion !== first.schemaVersion || attempt.model !== first.model || attempt.request.numPredict !== first.request.numPredict - first.usage.outputTokens
          || JSON.stringify(attempt.request.format) !== JSON.stringify(first.request.format)
          || JSON.stringify(attempt.request.messages) !== JSON.stringify([...first.request.messages,
            { role: 'assistant', content: first.raw }, { role: 'user', content: INSTRUCTION }])) throw failure();
    }
  }
  if (attempts.at(-1).classification !== 'accepted') throw failure();
  return hash(attempts);
}
module.exports = { createAuditDecisionCorrection, captureAuditDecisionCorrection,
  classifyAuditDecision: classification, verifyAuditDecisionAttempts, auditDecisionSchema, AUDIT_DECISION_CORRECTION_INSTRUCTION: INSTRUCTION };
