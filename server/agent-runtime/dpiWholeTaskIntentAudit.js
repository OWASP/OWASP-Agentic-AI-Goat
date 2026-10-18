'use strict';

const { z } = require('zod');
const { createHash } = require('node:crypto');
const { VERSION, createDpiWholeTaskIntentComparison } = require('./dpiWholeTaskIntentComparison');

const stable = value => Array.isArray(value) ? '[' + value.map(stable).join(',') + ']' : value && typeof value === 'object' ? '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}' : JSON.stringify(value);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const stage = z.object({ stage: z.enum(['source', 'verify']), attempts: z.literal(1), provider: z.string().min(1).max(100).nullable(), model: z.string().min(1).max(200).nullable(), completed: z.boolean(), responseSha256: z.array(digest.nullable()).max(1) }).strict();
const inputSchema = z.object({ version: z.literal(VERSION), stages: z.array(stage).min(1).max(2), observation: z.unknown().nullable().optional() }).strict();
const sha256 = value => createHash('sha256').update(value).digest('hex');
const reject = () => { throw Error('Invalid DPI whole-task intent audit'); };

function normalizeDpiWholeTaskIntentAudit(input, result, execution) {
  const value = inputSchema.parse(input);
  const observation = value.observation;
  if (!execution || Object.keys(execution).sort().join(',') !== 'durableGeneration,mode,ownerKey,runId' || typeof execution.runId !== 'string' || !execution.runId ||
    typeof execution.ownerKey !== 'string' || !execution.ownerKey || execution.durableGeneration == null || execution.mode !== 'vuln' ||
    value.stages.map(row => row.stage).join(',') !== ['source', 'verify'].slice(0, value.stages.length).join(',') || result?.attempts !== value.stages.length ||
    result.mode !== 'vuln' || result.runId !== execution.runId || result.provider !== value.stages.at(-1).provider || result.model !== value.stages.at(-1).model) reject();
  for (const row of value.stages) {
    if (row.responseSha256.length > row.attempts || (row.provider === null) !== (row.model === null) ||
      (row.completed && (!row.provider || !row.model || row.responseSha256.length !== 1 || !row.responseSha256[0])) ||
      (row.provider && /mock|scripted|fallback|fixture/i.test(row.provider))) reject();
  }
  // A transport/schema failure may have no observation to replay.  It can only
  // remain an unqualified unavailable/inconclusive result, never a success or
  // definitive failure manufactured from a partial stage transcript.
  if (!observation) {
    if (!['unavailable', 'inconclusive'].includes(result.verdict) || result.criteria?.length) reject();
    return value;
  }
  if (value.stages.length !== 2 || value.stages.some(row => !row.completed) || observation.version !== VERSION || observation.diagnosticVersion !== 'dpi-whole-task-intent-server-ids-v5' ||
    !['virtualization', 'obfuscation'].includes(observation.objective) || typeof observation.originalRequest !== 'string' ||
    typeof observation.originalResponse !== 'string' || typeof observation.sourceRaw !== 'string' || typeof observation.verifyRaw !== 'string' ||
    result?.attempts !== 2) reject();
  const evidence = [
    { id: 'request', source: 'student_input', content: observation.originalRequest },
    { id: 'response', source: 'assistant_response', content: observation.originalResponse },
  ];
  if (!observation.policyBinding || !observation.legacyProvenance) reject();
  if (observation.objective === 'obfuscation') {
    if (!observation.decodedRequest) reject();
    evidence.push({ id: 'decoded_request', source: 'server_observation', content: observation.decodedRequest });
    evidence.push({ id: 'owned_decoder', source: 'server_observation', content: observation.legacyProvenance });
  } else evidence.push({ id: 'owned_actor', source: 'server_observation', content: observation.legacyProvenance });
  evidence.push({ id: 'owned_policy', source: 'server_observation', content: observation.policyBinding });
  let comparison, sourceValue, verifyValue, expected;
  try {
    comparison = createDpiWholeTaskIntentComparison({ objective: observation.objective, primary: true, protocolVersion: VERSION }, evidence, execution, {
      rubric: { family: 'DPI', scenario: 'aws_assistant', objectiveId: observation.objective, mode: 'vuln', dpiPolicyBinding: 'dpi-policy-binding-v2' }, facts: {},
    });
    sourceValue = comparison.stages[0].validate(observation.sourceRaw);
    verifyValue = comparison.stages[1].validate(observation.verifyRaw);
    expected = comparison.combine(sourceValue, verifyValue);
  } catch { reject(); }
  if (value.stages[0].responseSha256[0] !== sha256(observation.sourceRaw) || value.stages[1].responseSha256[0] !== sha256(observation.verifyRaw) ||
    expected.verdict !== result.verdict || stable(expected.criteria) !== stable(result.criteria) ||
    stable(expected.observation) !== stable(observation)) reject();
  return value;
}

module.exports = { VERSION, normalizeDpiWholeTaskIntentAudit };
