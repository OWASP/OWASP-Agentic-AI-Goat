'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createObjectiveJudge } = require('../../server/agent-runtime/objectiveJudge');
const calibration = require('./secureshopReviewContentJudgeCalibration');

const CASE_IDS = Object.freeze([
  'r38_advertising_approve_exploit',
  'r38_advertising_rejected_control',
]);
const CRITERIA = calibration.CRITERIA;
const ARMS = Object.freeze(['current_union', 'flat_boolean']);
const REPEATS = 2;
const EXPECTED_CELLS = CASE_IDS.length * ARMS.length * REPEATS;
const MAX_PROVIDER_CALLS = EXPECTED_CELLS * CRITERIA.length;
const MAX_RAW_RESPONSE_BYTES = 16 * 1024;
const TRUSTED_MARKER = 'TRUSTED SERVER CRITERION:\n';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const clone = value => JSON.parse(JSON.stringify(value));

function criterionFromMessages(messages) {
  assert.equal(messages.length, 2);
  assert.equal(messages[0].role, 'system');
  assert.equal(messages[1].role, 'user');
  assert.ok(messages[0].content.startsWith(TRUSTED_MARKER));
  const start = TRUSTED_MARKER.length;
  const end = messages[0].content.indexOf('\n', start);
  assert.ok(end > start);
  const scoped = JSON.parse(messages[0].content.slice(start, end));
  assert.ok(CRITERIA.includes(scoped.criterion.id));
  return scoped.criterion.id;
}

function flatBooleanFormat(current) {
  const value = clone(current);
  assert.deepEqual(Object.keys(value).sort(), ['$schema', 'anyOf'].sort());
  assert.equal(value.anyOf.length, 2);
  const [positive, negative] = value.anyOf;
  assert.equal(positive.properties.satisfied.const, true);
  assert.equal(negative.properties.satisfied.const, false);
  assert.deepEqual(positive.required, negative.required);
  assert.deepEqual(positive.properties.evidenceRefs.items,
    negative.properties.evidenceRefs.items);
  assert.deepEqual(positive.properties.citations.items,
    negative.properties.citations.items);
  assert.equal(positive.properties.citations.maxItems, 0);
  assert.equal(negative.properties.citations.maxItems, 0);
  return Object.freeze({
    type: 'object',
    properties: Object.freeze({
      satisfied: Object.freeze({ type: 'boolean' }),
      evidenceRefs: Object.freeze({
        type: 'array',
        items: Object.freeze(clone(positive.properties.evidenceRefs.items)),
        maxItems: 30,
      }),
      citations: Object.freeze({ type: 'array',
        items: Object.freeze(clone(positive.properties.citations.items)), maxItems: 0 }),
    }),
    required: Object.freeze([...positive.required]),
    additionalProperties: false,
    $schema: value.$schema,
  });
}

function responseRecord(result) {
  const raw = result?.response;
  assert.equal(typeof raw, 'string');
  assert.ok(Buffer.byteLength(raw) <= MAX_RAW_RESPONSE_BYTES,
    'Diagnostic response exceeded its retention bound');
  let parsed = null;
  try { parsed = JSON.parse(raw); } catch { /* retain the bounded raw response */ }
  return Object.freeze({
    rawResponse: raw,
    rawResponseSha256: sha256(raw),
    rawResponseBytes: Buffer.byteLength(raw),
    parsedResponse: parsed,
    provider: result?.provider ?? null,
    model: result?.model ?? null,
  });
}

function diagnosticModel(provider, arm, callRecords) {
  const seen = new Set();
  return Object.freeze({
    async chat(messages, tools, options) {
      assert.deepEqual(tools, []);
      const criterionId = criterionFromMessages(messages);
      if (seen.has(criterionId)) {
        throw Object.assign(new Error('Schema diagnostic forbids Judge repairs'),
          { code: 'SCHEMA_DIAGNOSTIC_REPAIR_FORBIDDEN' });
      }
      if (seen.size >= CRITERIA.length) {
        throw Object.assign(new Error('Schema diagnostic cell call bound exceeded'),
          { code: 'SCHEMA_DIAGNOSTIC_CALL_BOUND' });
      }
      seen.add(criterionId);
      const format = arm === 'current_union' ? options.format
        : flatBooleanFormat(options.format);
      const record = {
        criterionId,
        promptSha256: sha256(JSON.stringify(messages)),
        systemSha256: sha256(messages[0].content),
        userSha256: sha256(messages[1].content),
        formatSha256: sha256(JSON.stringify(format)),
        options: Object.freeze({ temperature: options.temperature,
          max_tokens: options.max_tokens, num_predict: options.num_predict,
          num_ctx: options.num_ctx }),
      };
      record.diagnosticRequestSha256 = sha256(JSON.stringify({ messages, tools,
        format, options: record.options }));
      try {
        const result = await provider.chat(messages, tools, { ...options, format });
        Object.assign(record, responseRecord(result));
        return result;
      } catch (error) {
        record.errorCode = typeof error?.code === 'string' ? error.code : 'PROVIDER_ERROR';
        throw error;
      } finally {
        callRecords.push(Object.freeze(record));
      }
    },
  });
}

async function selectedCases() {
  const all = await calibration.cases();
  return Object.freeze(CASE_IDS.map(id => {
    const found = all.find(item => item.definition.id === id);
    assert.ok(found, `Missing schema diagnostic case ${id}`);
    return found;
  }));
}

function compactJudgment(judgment) {
  return Object.freeze({
    verdict: judgment?.verdict ?? null,
    criteria: judgment?.criteria ?? [],
    attempts: judgment?.attempts ?? 0,
    provider: judgment?.provider ?? null,
    model: judgment?.model ?? null,
    errorCode: judgment?.errorCode ?? null,
    scopedCriteria: judgment?.scopedCriteria ?? [],
  });
}

async function runSchemaDiagnostic({ provider, recordCell = async () => {}, signal } = {}) {
  assert.equal(typeof provider?.chat, 'function');
  assert.equal(typeof recordCell, 'function');
  const runSignal = signal || new AbortController().signal;
  assert.equal(typeof runSignal?.throwIfAborted, 'function');
  const packets = await selectedCases();
  const cells = [];
  for (let repeat = 1; repeat <= REPEATS; repeat += 1) {
    for (const packet of packets) {
      for (const arm of ARMS) {
        const calls = [];
        const judge = createObjectiveJudge({ model: diagnosticModel(provider, arm, calls),
          timeoutMs: 60000 });
        const judgment = await judge({ rubric: packet.rubric, facts: packet.facts,
          evidence: packet.evidence, execution: Object.freeze({ ownerId: 'schema-diagnostic',
            runId: `schema-diagnostic-${repeat}-${packet.definition.id}-${arm}`,
            signal: runSignal, async check() { runSignal.throwIfAborted(); },
            async emit() {} }) });
        const cell = Object.freeze({ caseId: packet.definition.id, repeat, arm,
          packetSha256: sha256(JSON.stringify({ rubric: packet.rubric,
            facts: packet.facts, evidence: packet.evidence })),
          calls: Object.freeze(calls), judgment: compactJudgment(judgment) });
        cells.push(cell);
        await recordCell(cell);
      }
    }
  }
  assert.equal(cells.length, EXPECTED_CELLS);
  assert.ok(cells.reduce((count, cell) => count + cell.calls.length, 0)
    <= MAX_PROVIDER_CALLS);
  for (let repeat = 1; repeat <= REPEATS; repeat += 1) {
    for (const caseId of CASE_IDS) {
      const pair = ARMS.map(arm => cells.find(cell => cell.repeat === repeat
        && cell.caseId === caseId && cell.arm === arm));
      assert.ok(pair.every(Boolean));
      assert.equal(pair[0].packetSha256, pair[1].packetSha256);
      for (const criterionId of CRITERIA) {
        const calls = pair.map(cell => cell.calls.find(call => call.criterionId === criterionId));
        assert.ok(calls.every(Boolean), `${caseId}/${repeat}/${criterionId} call missing`);
        assert.equal(calls[0].promptSha256, calls[1].promptSha256,
          `${caseId}/${repeat}/${criterionId} prompt changed between schema arms`);
        assert.equal(calls[0].systemSha256, calls[1].systemSha256);
        assert.equal(calls[0].userSha256, calls[1].userSha256);
        assert.deepEqual(calls[0].options, calls[1].options);
        assert.notEqual(calls[0].formatSha256, calls[1].formatSha256);
      }
    }
  }
  return Object.freeze({ cells: Object.freeze(cells) });
}

module.exports = { CASE_IDS, CRITERIA, ARMS, REPEATS, EXPECTED_CELLS,
  MAX_PROVIDER_CALLS, MAX_RAW_RESPONSE_BYTES, flatBooleanFormat,
  criterionFromMessages, selectedCases, runSchemaDiagnostic };
