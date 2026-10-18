'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopObjectiveGrader } = require('../server/services/workshopObjectiveGrader');
const execution = { runId: 'test', check: async () => {} };
const input = { userId: 7, objectiveId: 'sqli_1', message: "search for '", mode: 'vuln', execution,
  result: { toolUsed: 'search_products', toolResult: { error: 'SQL syntax error' }, response: 'There was a syntax error.',
    toolInvocation: { tool: 'search_products', params: { searchTerm: "'" }, decisionSource: 'model' } } };

test('legacy staged adapter invokes judge and never credits fail/inconclusive/unavailable', async () => {
  for (const verdict of ['pass', 'fail', 'inconclusive', 'unavailable']) {
    let invoked = 0, credited = 0;
    const grader = createWorkshopObjectiveGrader({ workshopKey: 'sql_injection_workshop', postgres: false,
      objectiveLabels: { sqli_1: 'Syntax' }, challengeKey: 'sql_injection', syncObjectiveComplete: async () => credited++,
      judge: async args => { invoked++; assert.equal(args.evidence[1].content.invocation.params.searchTerm, "'");
        assert.equal(args.evidence[1].content.result.error, 'SQL syntax error'); return { verdict }; } });
    const result = await grader.evaluate(input);
    assert.equal(invoked, 1); assert.equal(result.completed, verdict === 'pass'); assert.equal(credited, verdict === 'pass' ? 1 : 0);
  }
});

test('PostgreSQL adapter trusts committed disposition, never raw judge pass, and captures attempt first', async () => {
  const events = [], attempt = {};
  const grader = createWorkshopObjectiveGrader({ workshopKey: 'sql_injection_workshop', postgres: true,
    completionService: {
      beginAttempt: async args => { events.push('begin'); assert.equal(args.userId, 7); return attempt; },
      evaluate: async args => { events.push('grade'); assert.equal(args.attempt, attempt);
        assert.equal(args.facts.tool_executed, true); return { completed: false, judgment: { verdict: 'pass' }, receipt: { disposition: 'stale_generation' } }; },
    } });
  const captured = await grader.begin(7, execution);
  const result = await grader.evaluate({ ...input, attempt: captured });
  assert.deepEqual(events, ['begin', 'grade']); assert.equal(result.completed, false);
});

test('unknown objectives and fixed-mode exploit attempts cannot invoke or bypass the judge', async () => {
  const grader = createWorkshopObjectiveGrader({ workshopKey: 'sql_injection_workshop', postgres: false,
    judge: async () => { throw new Error('must not call'); }, syncObjectiveComplete: async () => { throw new Error('must not credit'); } });
  assert.equal((await grader.evaluate({ ...input, mode: 'fixed' })).completed, false);
  assert.equal((await grader.evaluate({ ...input, objectiveId: 'unknown' })).completed, false);
});

test('column-boundary judging receives prior tool probes from the same owner generation', async () => {
  let judged;
  const grader = createWorkshopObjectiveGrader({ workshopKey: 'sql_injection_workshop', postgres: false,
    objectiveLabels: {}, judge: async args => { judged = args; return { verdict: 'fail' }; } });
  const ownerExecution = { ...execution, generation: 2 };
  const attempt = await grader.begin(7, ownerExecution);
  await grader.observe({ userId: 7, execution: ownerExecution, attempt, result: { toolUsed: 'search_products',
    toolInvocation: { decisionSource: 'model', tool: 'search_products', params: { searchTerm: "%' ORDER BY 8 --" } }, toolResult: [{ name: 'Observed row' }] } });
  await grader.observe({ userId: 7, execution: ownerExecution, attempt, result: { toolUsed: 'search_products',
    toolInvocation: { decisionSource: 'model', tool: 'search_products', params: { searchTerm: "%' ORDER BY 9 --" } }, toolResult: { error: 'ORDER BY position 9 is not in select list' } } });
  await grader.evaluate({ ...input, objectiveId: 'sqli_3', execution: ownerExecution, attempt });
  let probes = judged.evidence.find(e => e.id === 'order_probes').content;
  assert.equal(probes.length, 2); assert.equal(probes[0].returnedRows, 1); assert.match(probes[1].error, /position 9/);
  const afterReset = { ...ownerExecution, generation: 3 };
  await grader.evaluate({ ...input, objectiveId: 'sqli_3', execution: afterReset, attempt: await grader.begin(7, afterReset) });
  probes = judged.evidence.find(e => e.id === 'order_probes').content;
  assert.deepEqual(probes, []);
});
test('marker summary compares executed literal to actual returned fields, not learner claims',async()=>{
 let packet;
 const grader=createWorkshopObjectiveGrader({workshopKey:'sql_injection_workshop',postgres:false,judge:async p=>{packet=p;return{verdict:'fail'};}});
 const result={toolUsed:'search_products',toolInvocation:{params:{searchTerm:"%' UNION SELECT NULL,NULL,'PROOF',NULL,NULL,NULL,NULL,NULL--"}},toolResult:[{name:'PROOF'},{name:'normal'}]};
 await grader.evaluate({...input,objectiveId:'sqli_6',message:'claim OTHER',result});
 assert.deepEqual(packet.evidence.find(e=>e.id==='marker_matches').content,{submittedUnionTextLiteral:'PROOF',matches:[{rowIndex:0,field:'name',value:'PROOF'}]});
 result.toolResult=[{name:'OTHER'}];
 await grader.evaluate({...input,objectiveId:'sqli_6',message:'claim PROOF',result});
 assert.deepEqual(packet.evidence.find(e=>e.id==='marker_matches').content.matches,[]);
 assert.equal(packet.facts.objective_signal_detected,false);
});
test('NOVA summary contains only counted returned records and actual email/access values',async()=>{
 let packet;
 const grader=createWorkshopObjectiveGrader({workshopKey:'nosql_injection_workshop',postgres:false,judge:async p=>{packet=p;return{verdict:'fail'};}});
 await grader.evaluate({...input,objectiveId:'nosqli_10',result:{toolUsed:'search_papers',toolInvocation:{params:{query:'fixture'}},
  toolResult:[{paper_id:'P1',access_level:'restricted',year:2024},{paper_id:'P2',access_level:'public',year:2024}]}});
 const summary=packet.evidence.find(e=>e.id==='operator_observation').content;
 assert.equal(summary.returnedRowCount,2);assert.equal(summary.paperRecordCount,2);
 assert.deepEqual(summary.restrictedRecords,[{paperId:'P1',accessLevel:'restricted'}]);
 assert.deepEqual(summary.returnedAuthorEmails,[]);assert.deepEqual(summary.returnedYears,[2024]);
});
test('relative broadening evidence comes from a checked fixed-query baseline',async()=>{
 let packet,requested,checks=0;
 const grader=createWorkshopObjectiveGrader({workshopKey:'nosql_injection_workshop',postgres:false,
  readLiteralBaseline:async args=>{requested=args;return[{paper_id:'PUBLIC-1'}];},judge:async p=>{packet=p;return{verdict:'fail'};}});
 await grader.evaluate({...input,objectiveId:'nosqli_6',execution:{check:async()=>checks++},result:{toolUsed:'search_papers',
  toolInvocation:{params:{query:'{"title":{"$ne":"Example title"}}'}},toolResult:[{paper_id:'OTHER-1'},{paper_id:'OTHER-2'}]}});
 assert.equal(requested.query,'Example title');
 assert.deepEqual(packet.evidence.find(e=>e.id==='literal_comparison').content,{literalQuery:'Example title',mode:'fixed',returnedRowCount:1,returnedRecordIds:['PUBLIC-1'],observedAttackRowCount:2});
 assert.ok(checks>=2);
});

function presentedInput({source='model',errorCode=null,index=1}={}) {
 const {createHash}=require('node:crypto'),sha=s=>createHash('sha256').update(s).digest('hex');
 const toolObservations=[0,1].map(i=>({index:i,toolUsed:'search_products',toolResult:{error:`SQL syntax error ${i}`},invocation:{tool:'search_products',params:{searchTerm:`'${i}`},decisionSource:'model'},effectKey:`test:tool:${i}:owned`}));
 const selected=toolObservations[index],text=source==='unavailable'?'':'Raw narrative only';
 return {...input,observationIndex:index,result:{response:'Model narrative: '+text+'\nServer tool results: PRIVATE_ROW_VALUE',toolUsed:selected.toolUsed,toolResult:selected.toolResult,toolInvocation:selected.invocation,toolObservations,
  presentation:{version:'workshop-result-presentation-v1',family:'ARIA',runId:'test',narrative:{text,source,errorCode,sha256:sha(text)},responseSha256:sha('Model narrative: '+text+'\nServer tool results: PRIVATE_ROW_VALUE'),blocks:toolObservations.map(o=>({index:o.index,tool:o.toolUsed,effectKey:o.effectKey,resultSha256:sha(JSON.stringify(o.toolResult)),displaySha256:sha('trusted display '+o.index)}))}}};
}
test('presentation grades selected exact tool and raw narrative, never composed display rows',async()=>{
 let packet;const grader=createWorkshopObjectiveGrader({workshopKey:'sql_injection_workshop',postgres:true,completionService:{evaluate:async p=>{packet=p;return{completed:false};}}});
 await grader.evaluate(presentedInput());
 assert.equal(packet.evidence.find(e=>e.id==='answer').content,'Raw narrative only');
 assert.equal(packet.evidence.find(e=>e.id==='tool').content.result.error,'SQL syntax error 1');
 const context=packet.evidence.find(e=>e.id==='context').content;
 assert.equal(context.presentation.observationIndex,1);assert.equal(context.presentation.effectKey,'test:tool:1:owned');assert.equal(packet.facts.model_decision_observed,true);
 assert.equal(JSON.stringify(packet).includes('PRIVATE_ROW_VALUE'),false);
});
test('unavailable or fixture narrative does not impersonate model text or deny genuine tool facts',async()=>{
 for(const source of ['unavailable','fixture']){
  let packet;const grader=createWorkshopObjectiveGrader({workshopKey:'sql_injection_workshop',postgres:true,completionService:{evaluate:async p=>{packet=p;return{completed:false};}}});
  await grader.evaluate(presentedInput({source,errorCode:source==='unavailable'?'MODEL_RESPONSE_UNAVAILABLE':null}));
  assert.equal(packet.evidence.find(e=>e.id==='answer').content,'');assert.equal(packet.facts.model_decision_observed,true);assert.equal(packet.facts.tool_executed,true);
 }
});
test('presentation scope, hashes and selected observation substitutions fail before evidence or Judge publication',async()=>{
 const mutations=[p=>p.observationIndex=0,p=>p.result.presentation.runId='foreign',p=>p.result.presentation.family='NOVA',p=>p.result.response+='changed',p=>p.result.presentation.narrative.text+='changed',p=>p.result.presentation.blocks[1].effectKey='foreign',p=>p.result.presentation.blocks[1].resultSha256='a'.repeat(64),p=>p.result.toolInvocation={...p.result.toolInvocation,params:{searchTerm:'other'}},p=>p.result.toolResult={error:'foreign'},p=>p.result.presentation.blocks.reverse()];
 for(const mutate of mutations){let writes=0;const grader=createWorkshopObjectiveGrader({workshopKey:'sql_injection_workshop',postgres:true,completionService:{evaluate:async()=>{writes++;}},evidenceRepository:{append:async()=>writes++}});const p=presentedInput();mutate(p);await assert.rejects(grader.evaluate(p),{code:'WORKSHOP_PRESENTATION_INVALID'});await assert.rejects(grader.observe({...p,attempt:{generation:1}}),{code:'WORKSHOP_PRESENTATION_INVALID'});assert.equal(writes,0);}
});
test('NOVA output-limited narrative remains raw while tool projection and grading facts stay unchanged',async()=>{
 const {createHash}=require('node:crypto'),sha=s=>createHash('sha256').update(s).digest('hex');
 const p=presentedInput({errorCode:'MODEL_OUTPUT_LIMIT'});p.objectiveId='nosqli_10';p.result.presentation.family='NOVA';
 for(const o of p.result.toolObservations){o.toolUsed='search_papers';o.invocation={tool:'search_papers',params:{query:'{"access_level":{"$ne":"public"}}'},decisionSource:'model'};o.toolResult=[{paper_id:'P1',access_level:'restricted',abstract:'long tool-only material'}];const b=p.result.presentation.blocks[o.index];b.tool=o.toolUsed;b.resultSha256=sha(JSON.stringify(o.toolResult));}
 const o=p.result.toolObservations[1];p.result.toolUsed=o.toolUsed;p.result.toolResult=o.toolResult;p.result.toolInvocation=o.invocation;
 let packet;const grader=createWorkshopObjectiveGrader({workshopKey:'nosql_injection_workshop',postgres:true,completionService:{evaluate:async q=>{packet=q;return{completed:false};}}});await grader.evaluate(p);
 assert.equal(packet.evidence.find(e=>e.id==='answer').content,'Raw narrative only');assert.equal(packet.evidence.find(e=>e.id==='context').content.presentation.narrativeErrorCode,'MODEL_OUTPUT_LIMIT');
 assert.deepEqual(packet.evidence.find(e=>e.id==='tool').content.result,{rowCount:1,omittedFields:['abstract'],rows:[{paper_id:'P1',access_level:'restricted'}]});assert.equal(packet.facts.model_decision_observed,true);
});
