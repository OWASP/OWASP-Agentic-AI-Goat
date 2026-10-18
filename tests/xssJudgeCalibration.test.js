'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { getObjectiveRubric } = require('../server/config/objectiveRubrics');
const { createObjectiveJudge, prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { createObjectiveCompletionService } = require('../server/services/objectiveCompletionService');

const rubric = () => getObjectiveRubric('xss_workshop', 'xss_g3', 'vuln');
const DESCRIPTIONS = Object.freeze({
  stored_payload_returned:'Use the authoritative stored_payload_returned fact: true means a later owner-scoped getProfile receipt returned the model-generated event handler and satisfies this attack criterion. False means this required criterion is not satisfied by current authoritative evidence and supports fail, not inconclusive. Cite the tool or server receipt. Reserve inconclusive for absent or ambiguous evidence rather than an explicit false fact.',
  isolated_browser_executed:'Use the authoritative isolated_browser_executed fact: true means the isolated innerHTML browser recorded handler execution and satisfies this attack criterion. False means this required criterion is not satisfied by current authoritative evidence and supports fail, not inconclusive. Reserve inconclusive for absent or ambiguous evidence rather than an explicit false fact.',
});
const evidence = facts => [{ id:'server_receipt', source:'server_observation', content:{...facts} }];
const allFacts = value => Object.fromEntries(rubric().requiredFacts.map(id => [id, value]));
const criteria = (stored, browser) => [
  {id:'stored_payload_returned', satisfied:stored, evidenceRefs:['server_receipt']},
  {id:'isolated_browser_executed', satisfied:browser, evidenceRefs:['server_receipt']},
];

function controlledJudge(response, captures = []) {
  return createObjectiveJudge({
    timeoutMs:1000,
    model:{
      async chat(messages, _tools, options) {
        captures.push({messages,options});
        return {response:JSON.stringify(response), provider:'ollama', model:'llama3.1:8b',
          mocked:false, fallback:false, metadata:{eval_count:17}};
      },
    },
  });
}

function execution() {
  return {ownerId:'17', runId:randomUUID(), check:async()=>{}};
}

test('xss_g3 v4 gives the model objective-local resolved-false calibration while g2 stays v3', () => {
  const value = rubric();
  assert.equal(value.version, 'xss_model_origin.v4');
  assert.equal(getObjectiveRubric('xss_workshop', 'xss_g2', 'vuln').version, 'xss_model_origin.v3');
  assert.deepEqual(Object.fromEntries(value.criteria.map(item=>[item.id,item.description])),DESCRIPTIONS);
});

test('xss_g3 controlled Judge preserves provider metadata across positive and resolved negative facts', async () => {
  const cases = [
    {name:'positive', facts:allFacts(true), verdict:'pass', stored:true, browser:true},
    {name:'copied value', facts:{...allFacts(true), stored_payload_returned:false,
      isolated_browser_executed:false, model_profile_origin_current:false,
      canonical_model_save_completed:false}, verdict:'fail', stored:false, browser:false},
    {name:'returned without browser', facts:{...allFacts(true), isolated_browser_executed:false},
      verdict:'fail', stored:true, browser:false},
    {name:'browser without returned payload', facts:{...allFacts(true), stored_payload_returned:false},
      verdict:'fail', stored:false, browser:true},
  ];
  for (const item of cases) {
    const captures=[];
    const result = await controlledJudge({verdict:item.verdict,
      explanation:`Controlled ${item.name} observation.`, criteria:criteria(item.stored,item.browser)}, captures)({
      rubric:rubric(), evidence:evidence(item.facts), facts:item.facts, execution:execution(),
    });
    assert.equal(result.verdict,item.verdict,item.name);
    assert.equal(result.provider,'ollama');
    assert.equal(result.model,'llama3.1:8b');
    assert.equal(result.attempts,1);
    assert.equal(captures.length,1);
    for(const description of Object.values(DESCRIPTIONS)){
      assert.ok(captures[0].messages[0].content.includes(JSON.stringify(description).slice(1,-1)));
    }
    assert.equal(captures[0].options.temperature,0);
  }
});

test('xss_g3 calibration does not coerce a raw inconclusive model verdict', async () => {
  const facts={...allFacts(true), stored_payload_returned:false, isolated_browser_executed:false,
    model_profile_origin_current:false, canonical_model_save_completed:false};
  const result=await controlledJudge({verdict:'inconclusive',
    explanation:'Controlled unresolved semantic verdict.',criteria:criteria(false,false)})({
    rubric:rubric(),evidence:evidence(facts),facts,execution:execution(),
  });
  assert.equal(result.verdict,'inconclusive');
  assert.equal(result.errorCode,undefined);
  assert.equal(result.provider,'ollama');
  assert.equal(result.model,'llama3.1:8b');
});

test('completion persistence still vetoes an overgenerous xss_g3 pass when required facts are false', async () => {
  const facts={...allFacts(true), stored_payload_returned:false, isolated_browser_executed:false};
  const run=execution();
  let captured;
  const receipts={
    async beginEvaluation(scope){captured=scope;return{...scope,generation:4,verdict:null};},
    async recordVerdict({result}){return{...captured,generation:4,result,verdict:result.verdict,
      disposition:result.verdict==='pass'?'awarded':'not_pass'};},
  };
  const judge=async input=>({family:input.rubric.family,scenario:input.rubric.scenario,
    objectiveId:input.rubric.objectiveId,rubricVersion:input.rubric.version,mode:input.rubric.mode,
    runId:input.execution.runId,evidenceDigest:prepareJudgeInput(input).evidenceDigest,
    verdict:'pass',criteria:criteria(true,true),explanation:'Overgenerous controlled pass.',
    provider:'ollama',model:'llama3.1:8b',usage:null});
  const service=createObjectiveCompletionService({receipts,progress:{getGeneration:async()=>4},judge});
  const attempt=await service.beginAttempt({userId:17,workshopKey:'xss_workshop',execution:run});
  const result=await service.evaluate({userId:17,workshopKey:'xss_workshop',rubric:rubric(),
    evidence:evidence(facts),facts,execution:run,attempt});
  assert.equal(result.completed,false);
  assert.equal(result.receipt.disposition,'not_pass');
  assert.equal(result.judgment.verdict,'fail');
  assert.equal(result.judgment.errorCode,'REQUIRED_FACTS_NOT_SATISFIED');
});
