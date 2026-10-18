'use strict';

// The repository selects and locks an original grade packet. This helper binds
// the compact selected-task audit back to that packet before replaying its one
// server-ID stage. It deliberately has no database or expiry policy.
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { prepareJudgeInput } = require('./objectiveJudge');
const { admitPolicyBinding } = require('./dpiPolicyBinding');
const { getSelectedProtocol } = require('./dpiSelectedTaskComparison');
const { normalizeDpiSelectedTaskAudit } = require('./dpiSelectedTaskAudit');

const sha256 = value => createHash('sha256').update(value).digest('hex');
const reject = () => { throw Error('Invalid persisted DPI selected-task packet'); };
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function exactEvidence(evidence, id, source) {
  const rows = evidence.filter(row => row?.id === id);
  if (rows.length !== 1 || rows[0].source !== source) reject();
  return rows[0].content;
}

function sameOptional(left, right) {
  return (left == null && right == null) || left === right;
}

function validateSelectedScope(row, packetRow, result) {
  const protocol = getSelectedProtocol(result?.dpiAnswerComparison?.version);
  if (!row || !packetRow || row.family !== 'DPI' || row.scenario !== 'aws_assistant'
    || !protocol || row.objective_id !== protocol.objective || row.rubric_version !== protocol.rubricVersion
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
  try {
    const parsed = JSON.parse(packetRow.packet);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.keys(parsed).sort().join(',') !== 'evidence,facts,rubric') reject();
    const prepared = prepareJudgeInput(parsed);
    if (prepared.evidenceError || prepared.packet !== packetRow.packet
      || prepared.evidenceDigest !== row.evidence_digest) reject();
    const { rubric, evidence } = prepared;
    const protocol = getSelectedProtocol(rubric.dpiAnswerComparison?.protocolVersion);
    if (!protocol || rubric.family !== row.family || rubric.scenario !== row.scenario
      || rubric.objectiveId !== row.objective_id || rubric.version !== row.rubric_version
      || rubric.mode !== row.mode) reject();
    const binding = admitPolicyBinding({ rubric, evidence, facts: parsed.facts });
    if (!binding?.proof || binding.proof.version !== 'dpi-owned-actor-v3'
      || binding.proof.objective !== protocol.objective) reject();
    return { prepared, binding };
  } catch (_) { reject(); }
}

function validateAudit(result, packet, execution) {
  const audit = result?.dpiAnswerComparison;
  const protocol = getSelectedProtocol(audit?.version);
  if (!protocol) reject();
  try { normalizeDpiSelectedTaskAudit(audit, result, execution); } catch (_) { reject(); }
  const observation = audit.observation;
  if (!observation) return;

  const { evidence } = packet.prepared;
  const request = exactEvidence(evidence, 'request', 'student_input');
  const response = exactEvidence(evidence, 'response', 'assistant_response');
  const legacy = exactEvidence(evidence, 'owned_actor', 'server_observation');
  const { proof, ...serializedBinding } = packet.binding;
  if (typeof request !== 'string' || typeof response !== 'string'
    || observation.originalRequest !== request || observation.originalResponse !== response
    || !isDeepStrictEqual(observation.provenance, proof)
    || !isDeepStrictEqual(observation.legacyProvenance, legacy)
    || !isDeepStrictEqual(observation.policyBinding, serializedBinding)
    || observation.version !== protocol.version || observation.diagnosticVersion !== protocol.diagnosticVersion
    || !own(observation, 'selectedRaw') || !own(observation, 'candidateAudit')) reject();
}

function validatePersisted(result, row, packetRow) {
  validateSelectedScope(row, packetRow, result);
  const packet = validatePacket(row, packetRow);
  const execution = Object.freeze({
    runId: row.run_id,
    ownerKey: packetRow.owner_key,
    durableGeneration: String(packetRow.owner_generation),
    mode: 'vuln',
  });
  const proof = packet.binding.proof;
  if (proof.runId !== execution.runId || proof.ownerKey !== execution.ownerKey
    || proof.generation !== execution.durableGeneration || proof.mode !== execution.mode) reject();
  validateAudit(result, packet, execution);
  return execution;
}

module.exports = { validatePersisted };
