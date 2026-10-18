'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { resultValue } = require('../server/database/postgres/objectiveJudgmentRepository');

const row = {
  family: 'DPI', scenario: 'single', objective_id: 'jailbreak', rubric_version: 'dpi-v11',
  evidence_digest: 'a'.repeat(64), run_id: null, mode: 'vuln',
};
function result(overrides = {}) {
  return {
    family: row.family, scenario: row.scenario, objectiveId: row.objective_id,
    rubricVersion: row.rubric_version, evidenceDigest: row.evidence_digest,
    runId: row.run_id, mode: row.mode, verdict: 'pass',
    criteria: [{ id: 'observed', satisfied: true, evidenceRefs: ['tool'] }],
    explanation: 'Observed result.', attempts: 2, ...overrides,
  };
}

test('persists bounded verbatim citations through JSON storage without changing legacy verdicts', () => {
  const quote = '  Synthetic protected record\nKey: TRAINING-ONLY  ';
  const criteria = [
    { id: 'action', satisfied: true, evidenceRefs: ['context'], citations: [] },
    { id: 'disclosure', satisfied: true, evidenceRefs: ['tool'], citations: [{ evidenceId: 'tool', quote }] },
  ];
  assert.deepEqual(JSON.parse(JSON.stringify(resultValue(result({ criteria }), row))).criteria, criteria);
  assert.equal(Object.hasOwn(resultValue(result(), row).criteria[0], 'citations'), false);
});

test('rejects malformed, oversized, unrelated or unsatisfied criterion citations', () => {
  const criterion = { id: 'observed', satisfied: true, evidenceRefs: ['tool'] };
  for (const citations of [null, {}, [{ evidenceId: 'other', quote: 'record' }],
    [{ evidenceId: 'tool', quote: '' }], [{ evidenceId: 'tool', quote: 'x'.repeat(1001) }],
    Array.from({ length: 11 }, () => ({ evidenceId: 'tool', quote: 'record' }))]) {
    assert.throws(() => resultValue(result({ criteria: [{ ...criterion, citations }] }), row), { code: 'BAD_REQUEST' });
  }
  assert.throws(() => resultValue(result({ verdict: 'fail', criteria: [{ ...criterion,
    satisfied: false, citations: [{ evidenceId: 'tool', quote: 'record' }] }] }), row), { code: 'BAD_REQUEST' });
});

test('stores only bounded source-verification summary with a consistent call total', () => {
  const value = resultValue(result({ verification: { verdict: 'pass', attempts: 2 }, totalCalls: 4 }), row);
  assert.deepEqual(value.verification, { verdict: 'pass', attempts: 2 });
  assert.equal(value.totalCalls, 4);
  assert.equal(JSON.stringify(value).includes('reasoning'), false);
});

test('source verifier cannot disagree with a final pass or smuggle unbounded metadata', () => {
  for (const verdict of ['fail', 'inconclusive', 'unavailable']) {
    assert.throws(() => resultValue(result({ verification: { verdict, attempts: 1 }, totalCalls: 3 }), row),
      error => error.code === 'BAD_REQUEST' && /successful source verification/.test(error.message));
  }
  assert.throws(() => resultValue(result({ verification: { verdict: 'pass', attempts: 1, explanation: 'raw' }, totalCalls: 3 }), row),
    error => error.code === 'BAD_REQUEST' && /verification metadata/.test(error.message));
  assert.throws(() => resultValue(result({ verification: { verdict: 'pass', attempts: 3 }, totalCalls: 4 }), row), { code: 'BAD_REQUEST' });
});

test('requires exact call accounting while preserving old receipt shape', () => {
  assert.throws(() => resultValue(result({ verification: { verdict: 'pass', attempts: 1 } }), row), { code: 'BAD_REQUEST' });
  assert.throws(() => resultValue(result({ verification: { verdict: 'pass', attempts: 1 }, totalCalls: 2 }), row), { code: 'BAD_REQUEST' });
  assert.throws(() => resultValue(result({ totalCalls: 3 }), row), { code: 'BAD_REQUEST' });
  const legacy = resultValue(result(), row);
  assert.equal(Object.hasOwn(legacy, 'verification'), false);
  assert.equal(Object.hasOwn(legacy, 'totalCalls'), false);
  assert.equal(resultValue(result({ totalCalls: 2 }), row).totalCalls, 2);
});

test('completed judgments reject partial scoped audits while unavailable judgments preserve them', () => {
  const completedAudit = {criterionId:'observed',scopeEvidenceIds:['tool'],
    scopeEvidenceDigest:'b'.repeat(64),attempts:1,attemptDurationsMs:[3],
    provider:'controlled',model:'controlled',responseSha256:'c'.repeat(64),
    errorCode:null,verdict:'pass'};
  const completed = resultValue(result({attempts:1,scopedCriteria:[completedAudit]}),row);
  assert.deepEqual(completed.scopedCriteria,[completedAudit]);

  const partialAudit = {...completedAudit,verdict:'unavailable',errorCode:'JUDGE_TIMEOUT'};
  assert.throws(() => resultValue(result({attempts:1,scopedCriteria:[partialAudit]}),row),
    error => error.code === 'BAD_REQUEST' && /terminal scoped criterion audits/.test(error.message));

  const unavailable = resultValue(result({verdict:'unavailable',criteria:[],attempts:1,
    errorCode:'JUDGE_TIMEOUT',scopedCriteria:[partialAudit]}),row);
  assert.equal(unavailable.verdict,'unavailable');
  assert.deepEqual(unavailable.scopedCriteria,[partialAudit]);
});


test('persists only bounded semantic observation identifiers and roles', () => {
  const semanticObservation = {
    sourceInstruction: { classification: 'embedded_redirect', sourceQuoteId: 'q2' },
    spans: [
      { spanId: 'p0', role: 'business_summary', sourceQuoteId: 'q0' },
      { spanId: 'p1', role: 'executed_request', sourceQuoteId: 'q2' },
    ],
  };
  const stored = resultValue(result({ semanticObservation }), row);
  assert.deepEqual(stored.semanticObservation, semanticObservation);
  assert.equal(JSON.stringify(stored).includes('raw response'), false);
});

test('rejects malformed or unbounded semantic observation metadata', () => {
  const valid = { sourceInstruction: { classification: 'embedded_redirect', sourceQuoteId: 'q1' },
    spans: [{ spanId: 'p0', role: 'executed_request', sourceQuoteId: 'q1' }] };
  const invalid = [
    { ...valid, privateReasoning: 'drop' },
    { ...valid, sourceInstruction: { classification: 'ordinary_content', sourceQuoteId: 'q1' } },
    { ...valid, spans: [{ spanId: 'p0', role: 'neutral_text', sourceQuoteId: 'q1' }] },
    { ...valid, spans: [{ spanId: 'p0', role: 'executed_request', sourceQuoteId: null }] },
    { ...valid, spans: [{ spanId: 'raw response text', role: 'executed_request', sourceQuoteId: 'q1' }] },
    { ...valid, spans: [{ spanId: 'p0', role: 'executed_request', sourceQuoteId: 'raw source text' }] },
    { ...valid, spans: [{ spanId: 'p0', role: 'executed_request', sourceQuoteId: 'q1' }, { spanId: 'p0', role: 'rejected_request', sourceQuoteId: 'q1' }] },
    { ...valid, spans: Array.from({ length: 65 }, (_, index) => ({ spanId: `p${index}`, role: 'executed_request', sourceQuoteId: 'q1' })) },
  ];
  for (const semanticObservation of invalid) {
    assert.throws(() => resultValue(result({ semanticObservation }), row), { code: 'BAD_REQUEST' });
  }
  const legacy = resultValue(result(), row);
  assert.equal(Object.hasOwn(legacy, 'semanticObservation'), false);
});

for (const comparisonVersion of ['source-only-obligation-verified-v4','source-only-obligation-verified-v5']) test(`${comparisonVersion} persists exact ordered obligations and three bounded stage call totals`, () => {
  const kinds=['literal_output','semantic_output','external_action','control_only'];
  const sourceInstructions=kinds.map((_,i)=>({sourceQuoteId:`q${i}`}));
  const sourceObligations=kinds.map((kind,i)=>({sourceQuoteId:`q${i}`,kind,requirementQuote:kind==='control_only'?null:'  exact source requirement  ',match:kind==='literal_output'?'entire_response':null}));
  const semanticObservation={sourceInstruction:{classification:'embedded_redirect',sourceQuoteId:'q0'},sourceInstructions,sourcePassages:kinds.map((_,i)=>({sourceQuoteId:`q${i}`,classification:'embedded_redirect'})),sourceObligations,spans:[{spanId:'p0',role:'rejected_request',sourceQuoteId:'q0'}]};
  const comparisonStages=['source','effect','support'].map(stage=>({stage,attempts:2,provider:'controlled',model:'fixture',completed:true}));
  const input=result({verdict:'fail',criteria:[{id:'observed',satisfied:false,evidenceRefs:[]}],attempts:6,totalCalls:6,comparisonVersion,comparisonStages,semanticObservation});
  const stored=resultValue(input,row);assert.equal(stored.verdict,'fail');assert.deepEqual(stored.semanticObservation,semanticObservation);assert.deepEqual(stored.comparisonStages,comparisonStages);
  assert.equal(stored.semanticObservation.sourceObligations[0].requirementQuote,'  exact source requirement  ');
  for(const changed of [
    {...semanticObservation,sourceObligations:sourceObligations.slice(1)},
    {...semanticObservation,sourceObligations:[...sourceObligations].reverse()},
    {...semanticObservation,sourceObligations:sourceObligations.map((v,i)=>i? v:{...v,extra:true})},
    {...semanticObservation,sourceObligations:sourceObligations.map((v,i)=>i? v:{...v,requirementQuote:''})},
    {...semanticObservation,sourceObligations:sourceObligations.map((v,i)=>i? v:{...v,requirementQuote:'x'.repeat(1001)})},
    {...semanticObservation,sourceObligations:sourceObligations.map((v,i)=>i? v:{...v,match:null})},
    {...semanticObservation,sourceObligations:sourceObligations.map((v,i)=>i===1?{...v,match:'contains'}:v)},
    {...semanticObservation,sourceObligations:sourceObligations.map((v,i)=>i===3?{...v,requirementQuote:'text'}:v)},
  ])assert.throws(()=>resultValue({...input,semanticObservation:changed},row),{code:'BAD_REQUEST'});
  for(const sourceQuoteId of ['q2','q3'])assert.throws(()=>resultValue({...input,semanticObservation:{...semanticObservation,spans:[{spanId:'p0',role:'executed_request',sourceQuoteId}]}},row),{code:'BAD_REQUEST'});
  for(const sourceQuoteId of ['q0','q1'])assert.equal(resultValue({...input,semanticObservation:{...semanticObservation,spans:[{spanId:'p0',role:'executed_request',sourceQuoteId}]}},row).semanticObservation.spans[0].role,'executed_request');
  const old={...semanticObservation};delete old.sourceObligations;
  assert.throws(()=>resultValue({...input,semanticObservation:old},row),{code:'BAD_REQUEST'});
  assert.throws(()=>resultValue({...input,comparisonVersion:'source-only-extraction-verified-v3'},row),{code:'BAD_REQUEST'});
  assert.throws(()=>resultValue({...input,comparisonVersion:'source-only-obligation-verified-v6'},row),{code:'BAD_REQUEST'});
  assert.throws(()=>resultValue({...input,comparisonStages:comparisonStages.map((v,i)=>i===2?{...v,attempts:3}:v),attempts:7,totalCalls:7},row),{code:'BAD_REQUEST'});
});
