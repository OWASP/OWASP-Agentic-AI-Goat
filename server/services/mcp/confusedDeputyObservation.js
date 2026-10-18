'use strict';
const crypto = require('node:crypto');
const protocol = require('./protocolContext');
const reportPayload = require('./reportPayload');

// These observations never cross the MCP protocol. They join the original
// server-side objects returned by the owned mail adapter and tool handler.
const deliveries = new WeakMap();
const tools = new WeakMap();
const modelDecisions = new WeakMap();
const trustedWitnesses = new WeakSet();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const INDIRECT_EFFECT_KEY = 'mcp_indirect_injection_consequence';

function plain(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function bindDelivery(result, observation) {
  if (!plain(result) || !plain(observation)) throw new TypeError('Private MCP delivery observation is required');
  deliveries.set(result, Object.freeze({ ...observation }));
  return result;
}

function bindTool(delivery, result, protectedContent) {
  const observation = plain(delivery) ? deliveries.get(delivery) : null;
  if (!observation || !plain(result) || typeof protectedContent !== 'string' || !protectedContent.length) return result;
  tools.set(result, Object.freeze({ ...observation, protectedContent }));
  return result;
}

function adoptTool(source, target) {
  const observation = plain(source) ? tools.get(source) : null;
  if (observation && plain(target)) tools.set(target, observation);
  return target;
}

function bindModelDecision(result, { decisionSource, tool, args, execution } = {}) {
  if (!plain(result)) return result;
  modelDecisions.delete(result);
  const observation = tools.get(result);
  const receipt = protocol.readProtocolReceipt(result);
  const exactArgs = plain(args) && Object.keys(args).sort().join(',') === 'body,to'
    && typeof args.body === 'string' && Buffer.byteLength(args.body) <= 65536
    && typeof args.to === 'string' && args.to.length > 0 && Buffer.byteLength(args.to) <= 320;
  const generation = execution?.durableGeneration ?? execution?.generation;
  const ownerKey = JSON.stringify(['MCP', String(observation?.scope?.platformOwnerId)]);
  const valid = decisionSource === 'model' && tool === 'send_report' && exactArgs
    && observation && receipt?.version === protocol.RECEIPT_VERSION
    && receipt.tool === 'send_report' && UUID.test(receipt.invocationId || '')
    && receipt.runId === execution?.runId && receipt.runId === observation.runId
    && receipt.ownerKey === execution?.ownerKey && receipt.ownerKey === ownerKey
    && receipt.generation === String(generation)
    && receipt.generation === String(observation?.scope?.generation)
    && receipt.effectKey === observation.effectKey
    && receipt.argsSha256 === protocol.canonicalDigest(args)
    && observation.to === reportPayload.recipient(args.to)
    && observation.body === reportPayload.externalPayload(args.body, observation.protectedContent)
    && observation.intentId === intentIdFor(observation.runId, observation.effectKey);
  if (valid) modelDecisions.set(result, Object.freeze({
    version: 'mcp-confused-deputy-model-decision.v1', invocationId: receipt.invocationId,
    runId: receipt.runId, argsSha256: receipt.argsSha256,
    effectKeySha256: crypto.createHash('sha256').update(receipt.effectKey).digest('hex'),
  }));
  return result;
}

function isTrustedModelDecision(result) {
  return Boolean(plain(result) && modelDecisions.has(result));
}

function readTool(result) {
  if (!plain(result)) return null;
  const observation = tools.get(result);
  return observation && modelDecisions.has(result) ? observation : null;
}

function readIndirectTool(result) {
  if (!plain(result)) return null;
  const observation = tools.get(result);
  return observation?.effectKey === INDIRECT_EFFECT_KEY ? observation : null;
}

function intentIdFor(runId, effectKey) {
  if (typeof runId !== 'string' || typeof effectKey !== 'string' || !effectKey.length || Buffer.byteLength(effectKey) > 500) {
    throw new TypeError('Exact MCP mail effect identity is required');
  }
  const bytes = Buffer.from(crypto.createHash('sha256').update(`${runId}:${effectKey}:mail`).digest().subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return `${bytes.toString('hex', 0, 4)}-${bytes.toString('hex', 4, 6)}-${bytes.toString('hex', 6, 8)}-${bytes.toString('hex', 8, 10)}-${bytes.toString('hex', 10, 16)}`;
}

function trustWitness(witness) {
  if (!plain(witness)) throw new TypeError('MCP deputy witness is required');
  for (const value of Object.values(witness)) if (plain(value)) Object.freeze(value);
  Object.freeze(witness); trustedWitnesses.add(witness); return witness;
}
function isTrustedWitness(witness) { return plain(witness) && trustedWitnesses.has(witness); }

module.exports = { bindDelivery, bindTool, adoptTool, bindModelDecision, readTool, readIndirectTool,
  isTrustedModelDecision, trustWitness, isTrustedWitness, intentIdFor };
