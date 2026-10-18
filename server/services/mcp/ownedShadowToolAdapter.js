'use strict';
const protocol = require('./protocolContext');
const { verifyOwnedShadowReceipt } = require('./ownedShadowReceipt');
const VERSION = 'mcp-owned-shadow-model-observation.v1';
const receipts = new WeakMap(), decisions = new WeakMap(), witnesses = new WeakSet(), byResult = new WeakMap();
const freeze = value => { if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const toolName = id => `shadow_${id.replaceAll('-', '')}_read_policy`;
function identity(receipt, args) {
  return { binding: receipt.binding, request: { action: receipt.action, operationId: receipt.operationId,
    registrationId: receipt.registrationId, runId: receipt.runId, invocationId: receipt.invocationId, ...args } };
}
function createOwnedShadowToolAdapter({ client } = {}) {
  if (client?.centralPersistence !== true || ['register', 'invoke', 'readRegistration'].some(k => typeof client[k] !== 'function')) throw TypeError('Durable owned shadow client required');
  async function execute(sessionId, action, args) {
    const context = protocol.requireProtocolContext(sessionId);
    await context.execution.check();
    const registration = action === 'invoke' ? await client.readRegistration(sessionId, args.registrationId) : null;
    let receipt;
    try {
      receipt = action === 'register' ? await client.register(sessionId, args.endpoint)
        : await client.invoke(sessionId, args.registrationId, args.remoteName, args.args);
    } catch (error) {
      if (error.code !== 'SHADOW_UNAPPROVED_PEER') throw error;
      await context.execution.check();
      // A verified policy refusal is a normal teaching outcome, not a successful
      // SDK effect. Never attach a success receipt or model-credit witness.
      return { output: 'The MCP trust policy rejected this unapproved endpoint.',
        error: 'SHADOW_UNAPPROVED_PEER', blocked: true, real: false,
        objective: 'mcp_shadow_server', achieved: false };
    }
    const requestArgs = action === 'register' ? { endpoint: args.endpoint, mode: receipt.mode }
      : { remoteName: args.remoteName, args: args.args };
    verifyOwnedShadowReceipt(receipt, identity(receipt, requestArgs), registration);
    if (receipt.runId !== context.execution.runId || receipt.invocationId !== context.invocationId
        || (registration && receipt.registrationId !== args.registrationId)) throw Object.assign(Error('SHADOW_RECEIPT_MISMATCH'), { code: 'SHADOW_RECEIPT_MISMATCH' });
    await context.execution.check();
    const result = { output: action === 'invoke' ? receipt.result.result.content[0].text
      : `Imported ${toolName(receipt.registrationId)} from ${receipt.result.endpoint}`,
      error: null, blocked: false, real: true, objective: 'mcp_shadow_server', achieved: false,
      registrationId: receipt.registrationId, endpoint: receipt.result.endpoint,
      importedTool: toolName(receipt.registrationId), operationId: receipt.operationId };
    receipts.set(result, freeze({ receipt, registration, requestArgs: structuredClone(requestArgs) }));
    return result;
  }
  return Object.freeze({ register: (sessionId, endpoint) => execute(sessionId, 'register', { endpoint }),
    invoke: (sessionId, registrationId, remoteName, args) => execute(sessionId, 'invoke', { registrationId, remoteName, args }) });
}
function adoptTool(source, target) {
  if (target && typeof target === 'object') {
    const receipt = receipts.get(source);
    receipts.delete(target); decisions.delete(target); byResult.delete(target);
    if (receipt) receipts.set(target, receipt);
  }
  return target;
}
function bindModelDecision(result, { decisionSource, tool, args, execution, registrationResult } = {}) {
  if (!result || typeof result !== 'object') return null;
  decisions.delete(result); byResult.delete(result);
  const record = receipts.get(result), p = protocol.readProtocolReceipt(result), r = record?.receipt;
  if (!r || decisionSource !== 'model' || !p || p.tool !== tool || p.runId !== execution?.runId
      || r.runId !== execution.runId || p.invocationId !== r.invocationId
      || p.ownerKey !== execution.ownerKey || p.generation !== protocol._internals.normalizeGeneration(execution)
      || p.argsSha256 !== protocol.canonicalDigest(args)) return null;
  if (r.action === 'register') {
    if (tool !== 'register_server' || !args || typeof args.url !== 'string'
        || args.url !== record.requestArgs.endpoint || Object.keys(args).some(k => !['url', 'name'].includes(k))) return null;
  } else if (tool !== toolName(r.registrationId) || protocol.canonicalDigest(args) !== protocol.canonicalDigest(record.requestArgs.args)) return null;
  const decision = Object.freeze({ invocationId: p.invocationId, argsSha256: p.argsSha256,
    tool, registrationResult: registrationResult || null });
  decisions.set(result, decision);
  return decision;
}
function chain(result, registrationResult) {
  const invoke = receipts.get(result), register = receipts.get(registrationResult);
  const a = invoke?.receipt, b = register?.receipt;
  const da = decisions.get(result), db = decisions.get(registrationResult);
  try {
    if (!da || !db || protocol.canonicalDigest(result.args) !== da.argsSha256
        || protocol.canonicalDigest(registrationResult.args) !== db.argsSha256
        || (result.tool !== undefined && result.tool !== da.tool)
        || (registrationResult.tool !== undefined && registrationResult.tool !== db.tool)) return null;
  } catch { return null; }
  if (!a || !b || !da || !db || a.action !== 'invoke' || b.action !== 'register'
      || a.mode !== 'vuln' || b.mode !== 'vuln' || a.result.approved !== false || b.result.approved !== false
      || a.runId !== b.runId || a.invocationId === b.invocationId || a.registrationId !== b.registrationId
      || protocol.canonicalDigest(invoke.registration) !== protocol.canonicalDigest(b)
      || a.runtimeDigest !== b.runtimeDigest || a.result.catalogDigest !== b.result.catalogDigest
      || result.output !== a.result.result?.content?.[0]?.text || !result.output
      || result.error !== null || result.blocked !== false || result.real !== true) return null;
  try { verifyOwnedShadowReceipt(b, identity(b, register.requestArgs)); verifyOwnedShadowReceipt(a, identity(a, invoke.requestArgs), b); } catch { return null; }
  return { invoke, register, da, db };
}
function isCandidate(result) { return Boolean(chain(result, decisions.get(result)?.registrationResult)); }
function witnessFor(result, { registrationResult = decisions.get(result)?.registrationResult, scope, execution } = {}) {
  const value = chain(result, registrationResult);
  if (!value || !scope || !execution) return null;
  const { receipt } = value.invoke, b = receipt.binding;
  if (receipt.runId !== execution.runId || b.targetId !== scope.targetId
      || String(b.ownerId) !== String(scope.platformOwnerId) || String(b.platformSessionId) !== String(scope.platformSessionId)
      || String(b.generation) !== String(scope.generation) || String(b.generation) !== protocol._internals.normalizeGeneration(execution)
      || execution.ownerKey !== JSON.stringify(['MCP', String(scope.platformOwnerId)])) return null;
  const previous = byResult.get(result); if (previous) return previous;
  const witness = freeze({ version: VERSION, receipt, registration: value.register.receipt,
    invocationDecision: { invocationId: value.da.invocationId, argsSha256: value.da.argsSha256, tool: value.da.tool },
    registrationDecision: { invocationId: value.db.invocationId, argsSha256: value.db.argsSha256, tool: value.db.tool },
    platformOwnerId: Number(scope.platformOwnerId), platformSessionId: Number(scope.platformSessionId),
    targetId: scope.targetId, generation: String(scope.generation), runId: execution.runId });
  witnesses.add(witness); byResult.set(result, witness); return witness;
}
function matchesWitness(result, witness) { return witnesses.has(witness) && byResult.get(result) === witness && isCandidate(result); }
module.exports = { VERSION, createOwnedShadowToolAdapter, adoptTool, bindModelDecision, isCandidate, witnessFor,
  isTrustedWitness: value => Boolean(value && witnesses.has(value)), matchesWitness, toolName };
