'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { FLAG, assertLegacySensitiveCandidateReadiness,
  createLegacySensitiveCandidateComposition } = require('../server/services/legacySensitiveCandidateComposition');
const { createSensitiveInfoAggregateReset } = require('../server/services/sensitiveInfoAggregateReset');
const { OBJECTIVES } = require('../server/services/legacySensitiveObjectiveGrader');

function catalogRows(overrides = {}) {
  return OBJECTIVES.slice().sort().map(objective_id => ({ objective_id, is_enabled: true,
    catalog_active: true, is_visible: true, exercise_active: true, ...overrides }));
}
function journalFixture(order) {
  let state;
  return { assertReady: async () => true,
    begin: async ({ ownerId }) => (state = { operationId: '11111111-1111-4111-8111-111111111111', ownerId, status: 'pending', step: 0 }),
    read: async () => state, claim: async () => ({ ...state, fromGeneration:2,toGeneration:3,
      leaseToken: '22222222-2222-4222-8222-222222222222' }),
    nextStep: async () => ['legacy_store','finflow_store'][state.step] || null,
    acknowledge: async () => { state.step += 1; }, fail: async () => {},
    complete: async () => { state.status = 'completed'; order.push('canonical-complete'); return state; } };
}
function cleanupFixture(order){const receipts=new Map();return{assertReady:async()=>true,
 apply:async scope=>{order.push(scope.stepKey);receipts.set(`${scope.operationId}:${scope.stepKey}`,{...scope});},
 readReceipt:async scope=>receipts.get(`${scope.operationId}:${scope.stepKey}`)}};

test('readiness requires catalog structure but permits instructor-disabled objectives', async () => {
  await assert.doesNotReject(assertLegacySensitiveCandidateReadiness({
    pool: { query: async () => ({ rows: catalogRows() }) },
  }));
  await assert.rejects(assertLegacySensitiveCandidateReadiness({
    pool: { query: async () => ({ rows: catalogRows().slice(1) }) },
  }), { code: 'GRADE_STORE_NOT_READY' });
  await assert.doesNotReject(assertLegacySensitiveCandidateReadiness({
    pool: { query: async () => ({ rows: catalogRows().map((row, index) => ({ ...row, is_enabled: index !== 0 })) }) },
  }));
  await assert.rejects(assertLegacySensitiveCandidateReadiness({
    pool: { query: async () => ({ rows: catalogRows({ is_visible: false }) }) },
  }), { code: 'GRADE_STORE_NOT_READY' });
});

test('explicitly disabled composition and does not inspect stores or create a provider', async () => {
  let touched = false;
  const result = await createLegacySensitiveCandidateComposition({ env: { [FLAG]: 'false' },
    platformStores: { pool: { query: async () => { touched = true; } } },
    agentProduction: { get agent() { touched = true; } } });
  assert.equal(result, null);
  assert.equal(touched, false);
  assert.equal(FLAG, 'LEGACY_SENSITIVE_CANONICAL_AGENT_ENABLED');
});

test('default-enabled composition uses the supplied real contracts and shared aggregate reset', async () => {
  const order = [];
  const execution={runId:'11111111-1111-4111-8111-111111111111',ownerKey:'["LegacySensitiveInfo","8"]',durableGeneration:'0',signal:new AbortController().signal,check:async()=>{},effectWithReceipt:async(key,work)=>({value:await work(),receipt:{status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,generation:'0',effectKey:execution.runId+':'+key}})};
  const runs = {
    run: async (_owner, _options, work) => work(execution),
    reset: async (_owner, work) => { order.push('legacy'); return work(); },
  };
  const completionService = { beginAttempt: async () => ({}), evaluate: async input => ({
    judgment: { verdict: 'pass', objectiveId: input.rubric.objectiveId }, completed: true,
  }) };
  let exerciseVisible = true;
  const platformStores = { pool: { query: async sql => ({ rows: sql.includes('JOIN') ? catalogRows()
    : [{ is_visible: exerciseVisible, catalog_active: true }] }) },
    progress: {getEvaluationScope: async () => ({generation:0,mode:null,modeStamp:'default'})} };
  const journal=journalFixture(order),cleanup=cleanupFixture(order);
  const aggregateReset=createSensitiveInfoAggregateReset({legacyRuns:runs,
    finflowReset:async (_owner, work) => { order.push('finflow'); return work(); },journal,cleanup});
  const composition = await createLegacySensitiveCandidateComposition({ env: {},
    legacyRuns: runs, platformStores, completionService,
    agentProduction: { snapshot: Object.freeze({ provider: 'fixture', model: 'controlled' }),
      agent: require('../server/services/legacySensitiveAgent').createLegacySensitiveAgent({
       model:{generateResponse:async(messages,options)=>({provider:'fixture',response:options.qualificationPhase==='response'?'Observed the protected teaching file.':JSON.stringify(messages.some(m=>m.role==='assistant')?{action:'finish',params:{}}:{action:'read_teaching_file',params:{path:'../secret/a'}})})},
       qualifyModel:()=>true,tools:{renderSsiTemplate:()=>assert.fail('Unexpected SSI tool'),readTeachingFile:()=>({success:true,content:'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}',boundary:{outsidePublic:true}})}
      }) },
    aggregateReset,
    legacyStore: { sensitiveFilesDir: '/owned/sensitive', publicDir: '/owned/sensitive/public' },
  });
  assert.equal((await composition.application.run({ userId: 8, message: 'read' })).completed, true);
  exerciseVisible = false;
  await assert.rejects(composition.application.run({ userId: 8, message: 'read again' }), { code: 'OBJECTIVE_DISABLED' });
  await composition.application.reset(8);
  assert.deepEqual(order, ['legacy', 'finflow', 'legacy_store', 'finflow_store', 'canonical-complete']);
});
