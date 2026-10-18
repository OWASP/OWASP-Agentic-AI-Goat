'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const enabled = process.env.IPI_SAME_QUESTION_JUDGE_CALIBRATION_ACTUAL8B === '1';
const fixture = require('./fixtures/ipiSameQuestionJudgeCalibration.json');
const { createObjectiveJudge, JUDGE_VERSION } = require('../server/agent-runtime/objectiveJudge');
const { buildIpiRubric } = require('../server/agent-runtime/indirectObjectiveJudge');

test('actual current Judge calibrates exact execution, quoted refusal, and retained grounded output', {
  skip: !enabled, timeout: 900000,
}, async () => {
  assert.equal(process.env.JUDGE_PROVIDER, 'ollama');
  assert.equal(process.env.JUDGE_MODEL || process.env.OLLAMA_MODEL, 'llama3.1:8b');
  const evidencePath = process.env.IPI_SAME_QUESTION_JUDGE_CALIBRATION_EVIDENCE_PATH;
  assert.ok(path.isAbsolute(evidencePath || ''));
  assert.notEqual(path.resolve(evidencePath).startsWith(process.cwd() + path.sep), true);
  const artifact = { version: 1, status: 'running', scope: 'Judge-only actual Ollama calibration with two synthetic responses and one frozen actual response; no actor, database, application, completion, or positive actor claim',
    fixtureSha256: crypto.createHash('sha256').update(fs.readFileSync(require.resolve('./fixtures/ipiSameQuestionJudgeCalibration.json'))).digest('hex'),
    callBudget: { cases: 3, maximumCallsPerCase: 6, maximumCalls: 18, stages: ['source', 'effect', 'support'] }, calls: [], cases: [] };
  const persist = () => { const temp = `${evidencePath}.${process.pid}.tmp`; fs.writeFileSync(temp, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 }); fs.renameSync(temp, evidencePath); };
  persist();
  const configured = require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({ provider: 'ollama', model: 'llama3.1:8b', baseURL: 'http://127.0.0.1:11434' });
  const model = { async chat(messages, tools, options) {
    if (artifact.calls.length >= artifact.callBudget.maximumCalls) throw Object.assign(new Error('Actual Judge call budget exhausted'), { code: 'JUDGE_CALL_BUDGET_EXHAUSTED' });
    const result = await configured.chat(messages, tools, options);
    artifact.calls.push({ index: artifact.calls.length + 1, request: { messages, options: { temperature: options.temperature, max_tokens: options.max_tokens,
      num_predict: options.num_predict, num_ctx: options.num_ctx } }, result: JSON.parse(JSON.stringify(result)) }); persist();
    return result;
  } };
  const judge = createObjectiveJudge({ model });
  try {
    assert.equal(fixture.objectiveId, 'rag_query_injection');
    assert.deepEqual(fixture.cases.map(item => item.expectedVerdict), ['pass', 'fail', 'fail']);
    for (const entry of fixture.cases) {
      const before = artifact.calls.length;
      const rubric = buildIpiRubric(fixture.objectiveId);
      assert.equal(rubric.version, 'ipi-rag-obligation-verified-v4');
      const evidence = [
        { id: 'question', source: 'student_input', content: fixture.question },
        { id: 'context', source: 'tool_result', content: fixture.source },
        { id: 'raw_response', source: 'assistant_response', content: entry.response },
      ];
      const result = await judge({ rubric, evidence, facts: { retrieved_context: true, real_model: true, raw_response_present: true },
        execution: { runId: `judge-calibration-${entry.id}`, ownerId: `calibration-${entry.id}`, check: async () => {}, emit: async () => {} } });
      const record = { id: entry.id, provenance: entry.provenance, originalRunId: entry.originalRunId || null,
        originalEvaluationId: entry.originalEvaluationId || null, expectedVerdict: entry.expectedVerdict,
        calls: artifact.calls.length - before, rubric, result };
      artifact.cases.push(record); persist();
      assert.ok(record.calls >= 1 && record.calls <= artifact.callBudget.maximumCallsPerCase, entry.id);
      assert.equal(result.provider, 'ollama', entry.id); assert.equal(result.model, 'llama3.1:8b', entry.id);
      assert.equal(result.judgeVersion, JUDGE_VERSION, entry.id);
      assert.equal(result.comparisonVersion, 'source-only-obligation-verified-v4', entry.id);
      assert.ok(result.semanticObservation, `${entry.id}: ${result.verdict}: ${result.errorCode || result.explanation}`);
      assert.deepEqual(result.semanticObservation.sourceObligations.find(item => item.sourceQuoteId === 'q2'),
        { sourceQuoteId: 'q2', kind: 'control_only', requirementQuote: null, match: null }, entry.id);
      assert.deepEqual(result.semanticObservation.sourceObligations.find(item => item.sourceQuoteId === 'q3'),
        { sourceQuoteId: 'q3', kind: 'literal_output', requirementQuote: fixture.directiveMarker, match: 'entire_response' }, entry.id);
      assert.equal(result.verdict, entry.expectedVerdict, `${entry.id}: ${result.explanation}`);
    }
    assert.ok(artifact.calls.length <= artifact.callBudget.maximumCalls);
    assert.ok(artifact.calls.every(call => call.result.provider === 'ollama' && call.result.model === 'llama3.1:8b'));
    artifact.status = 'passed'; artifact.actualCalls = artifact.calls.length; persist();
  } catch (error) {
    artifact.status = 'failed'; artifact.failure = { name: error.name, code: error.code || null, message: error.message }; persist(); throw error;
  }
});
