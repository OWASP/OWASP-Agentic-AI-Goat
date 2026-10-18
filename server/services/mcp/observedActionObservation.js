'use strict';

const crypto = require('node:crypto');
const protocol = require('./protocolContext');
const { TOOL_DEFINITIONS } = require('./toolRegistry');

const records = new WeakMap();
const witnesses = new WeakSet();
const VERSION = 'mcp-observed-action-witness.v2';
const DESCRIPTION_SOURCE = 'mcp_tool_description';

const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const description = () => TOOL_DEFINITIONS.find(item => item.name === 'check_system_status')?.description || '';

function bindTool(result, { state, tool, args } = {}) {
  if (state?.purpose !== 'tool_poisoning' || tool !== 'read_file') return result;
  if (!result || typeof result !== 'object' || Array.isArray(result)
      || !state.observation || state.observation.source !== DESCRIPTION_SOURCE
      || typeof state.observation.untrustedText !== 'string'
      || typeof result.consequenceOutput !== 'string' || !result.consequenceOutput.length) {
    return result;
  }
  const returned = result.consequenceOutput;
  records.set(result, Object.freeze({
    version: VERSION,
    ownerKey: state.execution.ownerKey,
    runId: state.execution.runId,
    generation: String(state.execution.durableGeneration ?? state.execution.generation),
    observationSource: DESCRIPTION_SOURCE,
    observationSha256: protocol.canonicalDigest({ source: DESCRIPTION_SOURCE,
      untrustedText: state.observation.untrustedText }),
    tool,
    args: Object.freeze({ ...args }),
    argsSha256: protocol.canonicalDigest(args),
    resolvedPath: result.resolvedPath,
    isolation: result.isolation,
    returnedSha256: digest(returned),
    returnedByteCount: Buffer.byteLength(returned),
  }));
  return result;
}

function adoptTool(source, target) {
  const record = source && typeof source === 'object' ? records.get(source) : null;
  if (record && target && typeof target === 'object' && !Array.isArray(target)) records.set(target, record);
  return target;
}

function witnessFor({ result, scope, execution } = {}) {
  const record = result && typeof result === 'object' ? records.get(result) : null;
  const decision = require('../../agent-runtime/mcpDecision').readObservedActionEffect(result);
  const canonicalDescription = description();
  const expectedObservation = protocol.canonicalDigest({ source: DESCRIPTION_SOURCE,
    untrustedText: canonicalDescription });
  if (!record || !decision || decision.scenario !== 'tool_poisoning'
      || decision.action !== record.tool || decision.argsSha256 !== record.argsSha256
      || decision.ownerKey !== record.ownerKey || decision.runId !== record.runId
      || decision.generation !== record.generation
      || decision.observationSource !== DESCRIPTION_SOURCE
      || decision.observationSha256 !== record.observationSha256
      || !canonicalDescription || record.observationSha256 !== expectedObservation
      || record.ownerKey !== execution?.ownerKey || record.runId !== execution?.runId
      || record.generation !== String(execution?.durableGeneration)
      || scope?.platformOwnerId !== Number(String(execution?.ownerKey || '').match(/^\["MCP","([1-9][0-9]*)"\]$/)?.[1])
      || !Number.isSafeInteger(scope?.platformSessionId) || scope.platformSessionId < 1
      || String(scope?.generation) !== record.generation
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(scope?.targetId || '')
      || result?.modelAction?.tool !== record.tool
      || protocol.canonicalDigest(result?.modelAction?.params) !== record.argsSha256
      || protocol.canonicalDigest(result?.selectedArgs) !== record.argsSha256) return null;
  const witness = Object.freeze({
    version: VERSION,
    targetId: scope.targetId,
    platformOwnerId: scope.platformOwnerId,
    platformSessionId: scope.platformSessionId,
    generation: scope.generation,
    runId: record.runId,
    observation: Object.freeze({ source: DESCRIPTION_SOURCE, description: canonicalDescription,
      sha256: record.observationSha256 }),
    action: Object.freeze({ tool: record.tool, args: record.args, argsSha256: record.argsSha256,
      invocationId: decision.invocationId, modelReceiptSha256: decision.receiptSha256 }),
    returned: Object.freeze({ resolvedPath: record.resolvedPath, isolation: record.isolation,
      sha256: record.returnedSha256, byteCount: record.returnedByteCount }),
  });
  witnesses.add(witness);
  return witness;
}

function isTrustedWitness(value) { return witnesses.has(value); }

module.exports = { VERSION, bindTool, adoptTool, witnessFor, isTrustedWitness };
