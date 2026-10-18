'use strict';

// Replays the sole server-ID selected-task stage from the retained audit
// material.  The repository supplies a packet it has already selected and
// locked; this module performs no database lookup or expiry decision.
const { z } = require('zod');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { VERSION, CONJUNCTION_VERSION, JAILBREAK_VERSION, ROLE_PLAYING_VERSION, CONTEXT_JAILBREAK_VERSION, CONTEXT_ROLE_PLAYING_VERSION, COMPACT_CONTEXT_JAILBREAK_VERSION, COMPACT_CONTEXT_ROLE_PLAYING_VERSION, COMPACT_CONJUNCTION_VERSION, getSelectedProtocol, createDpiSelectedTaskComparison } = require('./dpiSelectedTaskComparison');

const sha256 = value => createHash('sha256').update(value).digest('hex');
const stable = value => Array.isArray(value) ? '[' + value.map(stable).join(',') + ']'
  : value && typeof value === 'object' ? '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
    : JSON.stringify(value);
const reject = () => { throw Error('Invalid DPI selected-task audit'); };

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const stage = z.object({
  stage: z.literal('selected'), attempts: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  provider: z.string().min(1).max(100).nullable(),
  model: z.string().min(1).max(200).nullable(), completed: z.boolean(),
  responseSha256: z.array(digest.nullable()).max(2),
}).strict();
const inputSchema = z.object({
  version: z.enum([VERSION, CONJUNCTION_VERSION, JAILBREAK_VERSION, ROLE_PLAYING_VERSION, CONTEXT_JAILBREAK_VERSION, CONTEXT_ROLE_PLAYING_VERSION, COMPACT_CONTEXT_JAILBREAK_VERSION, COMPACT_CONTEXT_ROLE_PLAYING_VERSION, COMPACT_CONJUNCTION_VERSION]), stages: z.array(stage).length(1), observation: z.unknown().nullable().optional(),
}).strict();

function validExecution(execution) {
  return execution && Object.keys(execution).sort().join(',') === 'durableGeneration,mode,ownerKey,runId'
    && typeof execution.runId === 'string' && execution.runId
    && typeof execution.ownerKey === 'string' && execution.ownerKey
    && execution.durableGeneration != null && String(execution.durableGeneration)
    && execution.mode === 'vuln';
}

function baseRubric(protocol) {
  return {
    family: 'DPI', scenario: 'aws_assistant', objectiveId: protocol.objective,
    version: protocol.rubricVersion, mode: 'vuln',
    dpiPolicyBinding: 'dpi-policy-binding-v2',
  };
}

function replay(observation, execution) {
  const protocol = getSelectedProtocol(observation?.version);
  if (!observation || typeof observation !== 'object' || Array.isArray(observation)
    || Object.keys(observation).sort().join(',') !== 'candidateAudit,diagnosticVersion,legacyProvenance,objective,originalRequest,originalResponse,policyBinding,provenance,selectedRaw,version'
    || !protocol || observation.diagnosticVersion !== protocol.diagnosticVersion
    || observation.objective !== protocol.objective || typeof observation.originalRequest !== 'string'
    || typeof observation.originalResponse !== 'string' || typeof observation.selectedRaw !== 'string'
    || Buffer.byteLength(observation.selectedRaw) > 16384 || !observation.candidateAudit
    || !observation.legacyProvenance || !observation.policyBinding || !observation.provenance) reject();

  const evidence = [
    { id: 'request', source: 'student_input', content: observation.originalRequest },
    { id: 'response', source: 'assistant_response', content: observation.originalResponse },
    { id: 'owned_actor', source: 'server_observation', content: observation.legacyProvenance },
    { id: 'owned_policy', source: 'server_observation', content: observation.policyBinding },
  ];
  const rubric = baseRubric(protocol);
  let comparison, selected, expected;
  try {
    const binding = require('./dpiPolicyBinding').admitPolicyBinding({ rubric, evidence, facts: {} });
    const { proof, ...compact } = binding || {};
    if (!proof || !isDeepStrictEqual(observation.provenance, proof)
      || !isDeepStrictEqual(observation.policyBinding, compact)) reject();
    if (proof.runId !== execution.runId || proof.ownerKey !== execution.ownerKey
      || proof.generation !== String(execution.durableGeneration) || proof.mode !== execution.mode
      || proof.objective !== protocol.objective) reject();
    comparison = createDpiSelectedTaskComparison(
      { objective: protocol.objective, primary: true, protocolVersion: protocol.version }, evidence, execution,
      { rubric, facts: {} },
    );
    selected = comparison.stages[0].validate(observation.selectedRaw);
    expected = comparison.combine(selected);
  } catch (_) { reject(); }
  return expected;
}

function normalizeDpiSelectedTaskAudit(input, result, execution) {
  const value = inputSchema.parse(input);
  const selected = value.stages[0];
  const compact = [COMPACT_CONTEXT_JAILBREAK_VERSION, COMPACT_CONTEXT_ROLE_PLAYING_VERSION, COMPACT_CONJUNCTION_VERSION].includes(value.version);
  const maximumAttempts = compact ? 2 : 1;
  if (!validExecution(execution) || result?.attempts !== selected.attempts || result.mode !== 'vuln'
    || result.runId !== execution.runId || (result.provider ?? null) !== selected.provider
    || (result.model ?? null) !== selected.model || selected.responseSha256.length > selected.attempts
    || selected.attempts > maximumAttempts
    || (selected.provider === null) !== (selected.model === null)
    || (selected.completed && (!selected.provider || !selected.model || selected.responseSha256.length !== selected.attempts
      || !selected.responseSha256.at(-1) || /mock|scripted|fallback|fixture/i.test(selected.provider)))) reject();

  if (value.observation == null) {
    const contextLimited = selected.attempts === 0;
    if (!['unavailable', 'inconclusive'].includes(result.verdict)
      || !Array.isArray(result.criteria) || result.criteria.length
      || (contextLimited && (result.verdict !== 'inconclusive' || result.errorCode !== 'JUDGE_CONTEXT_LIMIT'
        || selected.completed || selected.provider !== null || selected.model !== null || selected.responseSha256.length))) reject();
    return value;
  }
  if (selected.attempts < 1 || selected.attempts > maximumAttempts || !selected.completed
    || selected.responseSha256.length !== selected.attempts) reject();
  if (value.observation?.version !== value.version) reject();
  const expected = replay(value.observation, execution);
  if (selected.responseSha256.at(-1) !== sha256(value.observation.selectedRaw)
    || expected.verdict !== result.verdict || stable(expected.criteria) !== stable(result.criteria)
    || stable(expected.observation) !== stable(value.observation)) reject();
  return value;
}

module.exports = { normalizeDpiSelectedTaskAudit };
