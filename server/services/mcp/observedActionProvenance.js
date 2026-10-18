'use strict';

const crypto = require('node:crypto');
const protocol = require('./protocolContext');

const VERSION = 'mcp-observed-action-provenance.v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SCENARIOS = Object.freeze({
  tool_poisoning: Object.freeze({ action: 'read_file', keys: Object.freeze(['path']),
    source: 'mcp_tool_description' }),
  indirect_injection: Object.freeze({ action: 'send_report', keys: Object.freeze(['to', 'body']),
    source: 'support_ticket' }),
});

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const plain = value => Boolean(value && Object.getPrototypeOf(value) === Object.prototype);

function coordinates(execution) {
  if (!plain(execution) || typeof execution.runId !== 'string' || !execution.runId.length
      || typeof execution.ownerKey !== 'string'
      || !/^\["MCP","[1-9][0-9]*"\]$/.test(execution.ownerKey)) return null;
  let generation;
  try { generation = protocol._internals.normalizeGeneration(execution); } catch { return null; }
  return Object.freeze({ ownerKey: execution.ownerKey, runId: execution.runId, generation });
}

function sameCoordinates(snapshot, execution) {
  const current = coordinates(execution);
  return Boolean(snapshot && current && current.ownerKey === snapshot.ownerKey
    && current.runId === snapshot.runId && current.generation === snapshot.generation);
}

function exactParams(value, definition) {
  return plain(value) && Object.keys(value).sort().join(',') === [...definition.keys].sort().join(',')
    && definition.keys.every(key => typeof value[key] === 'string' && value[key].length > 0);
}

function createObservedActionProvenance() {
  const decisions = new WeakMap();
  const effects = new WeakMap();

  function snapshot({ scenario, source, untrustedText, userRequest, execution } = {}) {
    const definition = SCENARIOS[scenario];
    const bound = coordinates(execution);
    if (!definition || source !== definition.source || typeof untrustedText !== 'string'
        || !untrustedText.length || typeof userRequest !== 'string' || !bound) return null;
    return Object.freeze({ scenario, source, untrustedText, userRequest, coordinates: bound,
      observationSha256: protocol.canonicalDigest({ source, untrustedText }) });
  }

  function recordDecision(value, context, execution) {
    const definition = SCENARIOS[context?.scenario];
    const params = plain(value?.params) ? Object.freeze({ ...value.params }) : Object.freeze({});
    const decision = Object.freeze({ decided: value?.decided === true, action: value?.action || null,
      params, decisionSource: value?.decisionSource, attempt: value?.attempt });
    if (!context || !definition || !sameCoordinates(context.coordinates, execution)
        || decision.decided !== true || decision.decisionSource !== 'model'
        || decision.action !== definition.action || !exactParams(params, definition)) return decision;
    decisions.set(decision, Object.freeze({ version: VERSION, scenario: context.scenario,
      ownerKey: context.coordinates.ownerKey, runId: context.coordinates.runId,
      generation: context.coordinates.generation, observationSource: context.source,
      observationSha256: context.observationSha256, action: decision.action,
      argsSha256: protocol.canonicalDigest(params) }));
    return decision;
  }

  function bindEffect(result, { decision, observation, execution } = {}) {
    if (plain(result)) effects.delete(result);
    const selected = decisions.get(decision);
    const definition = SCENARIOS[selected?.scenario];
    const receipt = protocol.readProtocolReceipt(result);
    const selectedArgs = result?.selectedArgs;
    const valid = plain(result) && selected && definition && sameCoordinates(selected, execution)
      && plain(observation) && observation.source === selected.observationSource
      && protocol.canonicalDigest({ source: observation.source,
        untrustedText: observation.untrustedText }) === selected.observationSha256
      && exactParams(selectedArgs, definition)
      && protocol.canonicalDigest(selectedArgs) === selected.argsSha256
      && receipt?.version === protocol.RECEIPT_VERSION && UUID.test(receipt.invocationId || '')
      && receipt.surface === 'chat' && receipt.purpose === selected.scenario
      && receipt.effectKey === `mcp_${selected.scenario}_consequence`
      && receipt.tool === selected.action && receipt.argsSha256 === selected.argsSha256
      && receipt.observationSource === selected.observationSource
      && receipt.observationSha256 === selected.observationSha256
      && receipt.ownerKey === selected.ownerKey && receipt.runId === selected.runId
      && receipt.generation === selected.generation;
    if (!valid) return result;
    const body = Object.freeze({ ...selected, invocationId: receipt.invocationId,
      effectKey: receipt.effectKey });
    effects.set(result, Object.freeze({ ...body,
      receiptSha256: sha256(Buffer.from(protocol._internals.canonical(body))) }));
    return result;
  }

  function readEffect(result) {
    const value = plain(result) ? effects.get(result) : null;
    const definition = SCENARIOS[value?.scenario];
    const receipt = protocol.readProtocolReceipt(result);
    if (!value || !definition || !receipt || receipt.version !== protocol.RECEIPT_VERSION
        || receipt.invocationId !== value.invocationId || receipt.surface !== 'chat'
        || receipt.purpose !== value.scenario || receipt.effectKey !== value.effectKey
        || receipt.tool !== value.action || receipt.argsSha256 !== value.argsSha256
        || receipt.observationSource !== value.observationSource
        || receipt.observationSha256 !== value.observationSha256
        || receipt.ownerKey !== value.ownerKey || receipt.runId !== value.runId
        || receipt.generation !== value.generation
        || !exactParams(result.selectedArgs, definition)
        || protocol.canonicalDigest(result.selectedArgs) !== value.argsSha256) return null;
    return value;
  }

  return Object.freeze({ snapshot, recordDecision, bindEffect, readEffect });
}

module.exports = { VERSION, createObservedActionProvenance };
