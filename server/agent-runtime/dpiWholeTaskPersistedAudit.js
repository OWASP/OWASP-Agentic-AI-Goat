'use strict';

// The repository selects and locks the original grade packet.  This helper
// binds a serialized whole-task observation back to that packet before the
// ordinary audit replays its two model stages.  It deliberately has no query
// or expiry policy: a retained original packet may be persisted after a retry
// admission window has elapsed.
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { prepareJudgeInput } = require('./objectiveJudge');
const { admitPolicyBinding } = require('./dpiPolicyBinding');
const { VERSION } = require('./dpiWholeTaskIntentComparison');

const sha256 = value => createHash('sha256').update(value).digest('hex');
const reject = () => { throw Error('Invalid persisted DPI whole-task packet'); };
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function exactEvidence(evidence, id, source) {
  const records = evidence.filter(record => record?.id === id);
  if (records.length !== 1 || records[0].source !== source) reject();
  return records[0].content;
}

function same(left, right) {
  return isDeepStrictEqual(left, right);
}

function sameOptional(left, right) {
  return (left == null && right == null) || left === right;
}

function validateSelectedScope(row, packetRow, result) {
  if (!row || !packetRow || row.family !== 'DPI' || row.scenario !== 'aws_assistant'
    || !['virtualization', 'obfuscation'].includes(row.objective_id)
    || row.rubric_version !== `dpi-${row.objective_id}-v15`
    || row.mode !== 'vuln' || row.canonical_mode !== 'vuln'
    || typeof row.evidence_digest !== 'string' || !/^[a-f0-9]{64}$/.test(row.evidence_digest)
    || typeof row.run_id !== 'string' || !row.run_id
    || typeof row.evaluation_id !== 'string' || !row.evaluation_id
    || !Number.isInteger(Number(row.user_id)) || Number(row.user_id) < 1
    || typeof packetRow.packet !== 'string' || !packetRow.packet
    || packetRow.user_id !== row.user_id
    || (packetRow.evaluation_id !== row.evaluation_id && packetRow.child_evaluation_id !== row.evaluation_id)
    || packetRow.owner_key !== JSON.stringify(['DPI', String(row.user_id)])
    || packetRow.owner_generation == null || String(packetRow.owner_generation).length === 0
    || packetRow.bound_digest !== row.evidence_digest || packetRow.bound_run !== row.run_id
    || packetRow.bound_objective !== row.objective_id || packetRow.bound_rubric !== row.rubric_version
    || String(packetRow.bound_generation) !== String(row.generation)
    || packetRow.bound_mode !== row.mode || !sameOptional(packetRow.bound_mode_stamp, row.mode_stamp)
    || !sameOptional(packetRow.mode_stamp, row.mode_stamp)
    || packetRow.bound_canonical_mode !== row.canonical_mode
    || typeof result?.judgeVersion !== 'string' || packetRow.judge_version !== result.judgeVersion) reject();
}

function validatePacket(row, packetRow) {
  if (sha256(packetRow.packet) !== row.evidence_digest) reject();
  let parsed;
  try {
    parsed = JSON.parse(packetRow.packet);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.keys(parsed).sort().join(',') !== 'evidence,facts,rubric') reject();
    const prepared = prepareJudgeInput(parsed);
    if (prepared.evidenceError || prepared.packet !== packetRow.packet
      || prepared.evidenceDigest !== row.evidence_digest) reject();
    const { rubric, evidence } = prepared;
    if (rubric.family !== row.family || rubric.scenario !== row.scenario
      || rubric.objectiveId !== row.objective_id || rubric.version !== row.rubric_version
      || rubric.mode !== row.mode || rubric.dpiAnswerComparison?.protocolVersion !== VERSION) reject();
    const binding = admitPolicyBinding({ rubric, evidence, facts: parsed.facts });
    if (!binding?.proof) reject();
    return { parsed, prepared, binding };
  } catch (_) { reject(); }
}

function validateObservation(result, row, packet) {
  const audit = result?.dpiAnswerComparison;
  const observation = audit?.observation;
  if (!audit || audit.version !== VERSION) reject();

  const { rubric, evidence } = packet.prepared;
  const binding = packet.binding;
  if (!observation) return binding.proof;
  if (typeof observation !== 'object' || observation.version !== VERSION || observation.objective !== row.objective_id) reject();
  const request = exactEvidence(evidence, 'request', 'student_input');
  const response = exactEvidence(evidence, 'response', 'assistant_response');
  const legacy = exactEvidence(evidence, row.objective_id === 'obfuscation' ? 'owned_decoder' : 'owned_actor', 'server_observation');
  const { proof, ...serializedBinding } = binding || {};
  if (!proof || typeof request !== 'string' || typeof response !== 'string'
    || observation.originalRequest !== request || observation.originalResponse !== response
    || !same(observation.provenance, proof) || !same(observation.legacyProvenance, legacy)
    || !same(observation.policyBinding, serializedBinding)) reject();
  if (row.objective_id === 'obfuscation') {
    const decoded = exactEvidence(evidence, 'decoded_request', 'server_observation');
    if (!own(observation, 'decodedRequest') || !same(observation.decodedRequest, decoded)) reject();
  } else if (own(observation, 'decodedRequest')) reject();
  return proof;
}

function validatePersisted(result, row, packetRow) {
  validateSelectedScope(row, packetRow, result);
  const packet = validatePacket(row, packetRow);
  const proof = validateObservation(result, row, packet);
  const execution = {
    runId: row.run_id,
    ownerKey: packetRow.owner_key,
    durableGeneration: String(packetRow.owner_generation),
    mode: 'vuln',
  };
  if (proof.runId !== execution.runId || proof.ownerKey !== execution.ownerKey
    || proof.generation !== execution.durableGeneration || proof.mode !== execution.mode) reject();
  return Object.freeze(execution);
}

module.exports = { validatePersisted };
