'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { resultValue } = require('../server/database/postgres/objectiveJudgmentRepository');

const source = 'search_echo_source';
const execution = 'search_echo_execution_observation';
const citations = [
  {evidenceId: source, quote: "<p>Results for: <img src=x onerror='target()'></p>"},
  {evidenceId: execution, quote: 'Renderer-owned SearchEcho DOM and browser receipt record target-bound execution.'},
];
const row = {
  family: 'SecureShop', scenario: 'bound_search_echo_browser',
  objective_id: 'ss_search_echo_browser', rubric_version: 'secureshop-search-echo-browser-v9',
  evidence_digest: 'a'.repeat(64), run_id: '00000000-0000-4000-8000-000000000009', mode: 'vuln',
};
function result(satisfied = true) {
  const verdict = satisfied ? 'pass' : 'fail';
  return {
    family: row.family, scenario: row.scenario, objectiveId: row.objective_id,
    rubricVersion: row.rubric_version, evidenceDigest: row.evidence_digest,
    runId: row.run_id, mode: row.mode, verdict,
    explanation: satisfied ? 'The saved echo caused the observed action.' : 'No target action was attributed to the echo.',
    provider: 'ollama', model: 'controlled-test', attempts: 1,
    criteria: [{id: 'search_echo_attributed_action', satisfied,
      evidenceRefs: [source, execution], citations: satisfied ? structuredClone(citations) : []}],
    scopedCriteria: [{criterionId: 'search_echo_attributed_action',
      scopeEvidenceIds: [source, execution], scopeEvidenceDigest: 'b'.repeat(64),
      attempts: 1, attemptDurationsMs: [5], provider: 'ollama', model: 'controlled-test',
      responseSha256: 'c'.repeat(64), verdict, errorCode: null,
      groundedObservation: {version: 2,
        text: satisfied ? 'The reflected source caused the target-bound browser action.'
          : 'The reflected source did not cause a target-bound browser action.',
        sourceForm: 'executable_markup',
        actionRelation: satisfied ? 'attributed_target_action' : 'no_target_action',
        citations: structuredClone(citations)}}],
  };
}
const persist = x => resultValue(x, row);
const bad = x => assert.throws(() => persist(x), {code: 'BAD_REQUEST'});

test('Search Echo V9 retains exact causal fields and quotes through normalization and JSON readback', () => {
  for (const satisfied of [true, false]) {
    const original = result(satisfied);
    const stored = persist(original);
    assert.deepEqual(stored.scopedCriteria[0].groundedObservation,
      original.scopedCriteria[0].groundedObservation);
    assert.deepEqual(persist(JSON.parse(JSON.stringify(original))), stored);
    assert.equal(stored.verdict, satisfied ? 'pass' : 'fail');
  }
});

test('V9 rejects missing, malformed, incomplete and mismatched causal observations', () => {
  const missingAudit = result();
  delete missingAudit.scopedCriteria;
  bad(missingAudit);
  const emptyAudit = result();
  emptyAudit.scopedCriteria = [];
  emptyAudit.attempts = 0;
  bad(emptyAudit);
  const wrongCriterion = result();
  wrongCriterion.criteria[0].id = 'other';
  wrongCriterion.scopedCriteria[0].criterionId = 'other';
  bad(wrongCriterion);
  const extraCriterion = result();
  extraCriterion.criteria.push({id: 'extra', satisfied: true, evidenceRefs: [source]});
  bad(extraCriterion);
  const changes = [
    x => { delete x.scopedCriteria[0].groundedObservation; },
    x => { x.scopedCriteria[0].groundedObservation.version = 1; },
    x => { x.scopedCriteria[0].groundedObservation.extra = true; },
    x => { x.scopedCriteria[0].groundedObservation.sourceForm = 'plain_text'; },
    x => { x.scopedCriteria[0].groundedObservation.actionRelation = 'no_target_action'; },
    x => { x.scopedCriteria[0].groundedObservation.citations.pop(); },
    x => { x.scopedCriteria[0].groundedObservation.citations[1].evidenceId = source; },
    x => { x.scopedCriteria[0].groundedObservation.citations[1].quote += ' forged'; },
    x => { x.scopedCriteria[0].groundedObservation.text = 'x'.repeat(401); },
  ];
  for (const change of changes) { const x = result(); change(x); bad(x); }
  const missingFalseObservation = result(false);
  delete missingFalseObservation.scopedCriteria[0].groundedObservation;
  bad(missingFalseObservation);
});

test('V9 preserves legitimate no-evidence false without inventing an observation', () => {
  const x = result(false);
  x.attempts = 0;
  x.scopedCriteria = [{criterionId: 'search_echo_attributed_action',
    scopeEvidenceIds: [], scopeEvidenceDigest: 'b'.repeat(64), attempts: 0,
    provider: null, model: null, verdict: 'fail', reason: 'NO_ELIGIBLE_EVIDENCE'}];
  assert.deepEqual(persist(x).scopedCriteria, x.scopedCriteria);
  const forgedPass = structuredClone(x);
  forgedPass.verdict = 'pass';
  forgedPass.criteria[0].satisfied = true;
  bad(forgedPass);
});

test('V9 preserves an honest false even when causal fields look positive', () => {
  const x = result(false);
  x.scopedCriteria[0].groundedObservation.actionRelation = 'attributed_target_action';
  assert.equal(persist(x).verdict, 'fail');
});

test('older rubric accepts its version 1 shape and rejects V9 fields; V9 rejects legacy version 1', () => {
  const legacy = result();
  legacy.rubricVersion = 'secureshop-search-echo-browser-v8';
  const legacyRow = {...row, rubric_version: legacy.rubricVersion};
  const observation = legacy.scopedCriteria[0].groundedObservation;
  legacy.scopedCriteria[0].groundedObservation = {version: 1, text: observation.text,
    citations: observation.citations};
  assert.equal(resultValue(legacy, legacyRow).scopedCriteria[0].groundedObservation.version, 1);
  legacy.scopedCriteria[0].groundedObservation = observation;
  assert.throws(() => resultValue(legacy, legacyRow), {code: 'BAD_REQUEST'});
  const v9Legacy = result();
  v9Legacy.scopedCriteria[0].groundedObservation = {
    version: 1, text: observation.text, citations: observation.citations,
  };
  bad(v9Legacy);
});
