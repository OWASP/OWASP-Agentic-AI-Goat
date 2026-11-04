'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createObjectiveJudgmentRepository,currentReceipt}=require('../server/database/postgres/objectiveJudgmentRepository');
const {projectJudgment,gradingUnqualified}=require('../server/agent-runtime/dpiSemanticCreditPolicy');
const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
function fixture({objective='virtualization',mode='vuln',current={},terminal=false,missingMigration=false}={}){
 const row={user_id:17,evaluation_id:randomUUID(),run_id:randomUUID(),workshop_key:'direct_prompt_injection',family:'DPI',scenario:'aws_assistant',objective_id:objective,rubric_version:'historical-v1',evidence_digest:'a'.repeat(64),generation:0,mode,canonical_mode:mode,mode_stamp:'default',verdict:null,disposition:'pending'};
 const raw={family:'DPI',scenario:row.scenario,objectiveId:objective,rubricVersion:row.rubric_version,evidenceDigest:row.evidence_digest,runId:row.run_id,mode,verdict:'pass',criteria:[{id:'observed',satisfied:true,evidenceRefs:['response']}],explanation:'Raw semantic prediction',provider:'ollama',model:'arbitrary',usage:null};
 const queries=[],state={generation:0,mode,modeStamp:'default',is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true,...current};let interactionCount=0;
 const query=async(sql,args=[])=>{queries.push(sql);if(sql.includes('INSERT INTO workshop_platform.activity_counters'))return{rows:[{activity_count:++interactionCount}]};if(sql.includes('RETURNING revision'))return{rows:[{revision:1}]};if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{...state,workshop_key:row.workshop_key}]};if(sql.includes('SELECT generation FROM'))return{rows:[{generation:state.generation}]};if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:state.mode,stamp:state.modeStamp}]};if(sql.includes('SELECT * FROM workshop_platform.objective_judgments'))return{rows:args[0]===17?[row]:[]};if(sql.startsWith('UPDATE workshop_platform.objective_judgments')){if(missingMigration)throw Object.assign(Error('constraint'),{code:'23514',constraint:'objective_judgments_disposition_check'});Object.assign(row,{verdict:args[2],result_json:JSON.parse(args[3]),result_digest:args[4],disposition:args[5]});return{rows:[row]};}return{rows:[],rowCount:1};};
 const repo=createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});return{row,raw,queries,state,repo,commit:()=>repo.recordVerdict({userId:17,evaluationId:row.evaluation_id,result:raw})};
}
test('canonical persistence denies new semantic credit for both objectives, retaining raw verdict and no completion SQL',async()=>{for(const objective of ['virtualization','obfuscation']){const f=fixture({objective}),receipt=await f.commit();assert.equal(receipt.disposition,'grading_unqualified');assert.equal(receipt.result.verdict,'pass');assert.equal(receipt.result.explanation,f.raw.explanation);assert(!f.queries.some(q=>q.includes('INSERT INTO workshop_platform.completions')));const digest=f.row.result_digest;const replay=await f.commit();assert.equal(replay.disposition,'grading_unqualified');assert.equal(f.row.result_digest,digest);assert.equal(projectJudgment(replay).gradingStatus,'pending');}});
test('fixed attack packets cannot award credit even with a fabricated semantic pass',async()=>{for(const objective of ['system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation']){const f=fixture({objective,mode:'fixed'});const receipt=await f.commit();assert.equal(receipt.disposition,'grading_unqualified',objective);assert.equal(receipt.result.verdict,'pass');assert(!f.queries.some(q=>q.includes('INSERT INTO workshop_platform.completions')),objective);}});
test('fixed AWS practice keeps the two-receipt threshold and only then awards completion',async()=>{const f=fixture({objective:'interact',mode:'fixed'});const first=await f.commit();assert.equal(first.disposition,'threshold_pending');assert(!f.queries.some(q=>q.includes('INSERT INTO workshop_platform.completions')));const firstId=f.row.evaluation_id;f.row.evaluation_id=randomUUID();f.row.run_id=randomUUID();f.row.verdict=null;f.row.disposition='pending';f.raw.runId=f.row.run_id;const second=await f.commit();assert.notEqual(second.evaluationId,firstId);assert.equal(second.disposition,'awarded');assert.equal(f.queries.filter(q=>q.includes('INSERT INTO workshop_platform.activity_counters')).length,2);assert.equal(f.queries.filter(q=>q.includes('INSERT INTO workshop_platform.completions')).length,1);});
test('qualification cannot be supplied by provider/environment/client fields; other objectives unchanged',async()=>{const f=fixture();assert.equal(gradingUnqualified({...f.row,qualified:true,provider:'trusted',modelRevision:'invented'}),true);const old=process.env.DPI_GRADING_QUALIFIED;process.env.DPI_GRADING_QUALIFIED='true';try{assert.equal(gradingUnqualified(f.row),true);}finally{if(old===undefined)delete process.env.DPI_GRADING_QUALIFIED;else process.env.DPI_GRADING_QUALIFIED=old;}const other=fixture({objective:'jailbreak'});assert.equal((await other.commit()).disposition,'awarded');});
test('scope fences take precedence; old accepted receipt projection is not rewritten',async()=>{for(const [current,want]of [[{generation:1},'stale_generation'],[{is_enabled:false},'hidden'],[{mode:'fixed'},'mode_changed']])assert.equal((await fixture({current}).commit()).disposition,want);const f=fixture();await assert.rejects(f.repo.recordVerdict({userId:18,evaluationId:f.row.evaluation_id,result:f.raw}),{code:'NOT_FOUND'});const old={...f.row,verdict:'pass',disposition:'awarded',result_json:f.raw};assert.equal(currentReceipt(old,f.state).disposition,'awarded');assert.equal(projectJudgment(currentReceipt(old,f.state)),f.raw);});
test('terminal retry and initial replay project pending without inference or changing raw receipt',async()=>{const f=fixture(),receipt=await f.commit();const service=createObjectiveCompletionService({progress:{getGeneration:async()=>0},receipts:{beginEvaluation:async()=>receipt,beginRetry:async()=>({receipt}),recordVerdict:()=>{throw Error('No replay writes');}},judge:()=>{throw Error('No replay inference');}});const execution={runId:randomUUID(),check:async()=>{}},attempt=await service.beginAttempt({userId:17,workshopKey:f.row.workshop_key,execution});const initial=await service.evaluate({userId:17,workshopKey:f.row.workshop_key,execution,attempt,rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:'virtualization',version:'historical-v1',mode:'vuln',criteria:[{id:'observed',description:'Observed'}],requiredFacts:[]},evidence:[{id:'response',source:'assistant_response',content:'Synthetic'}]});const retry=await service.retry({userId:17,evaluationId:receipt.evaluationId,execution});for(const r of [initial,retry]){assert.equal(r.completed,false);assert.equal(r.judgment.gradingStatus,'pending');assert.equal(r.judgment.verdict,'pass');assert.equal(r.judgment.canRetry,false);}assert(!Object.hasOwn(receipt.result,'gradingStatus'));});
test('public feedback renders pending even raw pass and never offers automatic retry',async()=>{const {getJudgeFeedback}=await import('../client/src/utils/judgeFeedback.mjs');const f=fixture(),receipt=await f.commit(),raw=JSON.stringify(receipt.result);const feedback=getJudgeFeedback({judgment:{...projectJudgment(receipt),evaluationId:receipt.evaluationId,canRetry:true}});assert.equal(feedback[0].verdict,'pending');assert.equal(feedback[0].canRetry,false);assert.match(feedback[0].content,/no completion was awarded/);assert.equal(JSON.stringify(receipt.result),raw);});
test('fresh retry passes raw result through canonical repository but cannot award',async()=>{
 const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge'),f=fixture();const rubric={family:'DPI',scenario:'aws_assistant',objectiveId:'virtualization',version:'historical-v1',mode:'vuln',criteria:[{id:'observed',description:'Observed'}],requiredFacts:[]};const prepared=prepareJudgeInput({rubric,evidence:[{id:'response',source:'assistant_response',content:'Synthetic'}]});f.row.evidence_digest=prepared.evidenceDigest;f.raw.evidenceDigest=prepared.evidenceDigest;
 const service=createObjectiveCompletionService({progress:{getGeneration:async()=>0},receipts:{beginEvaluation:async()=>{},beginRetry:async()=>({receipt:{evaluationId:f.row.evaluation_id,runId:f.row.run_id,rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest},packet:prepared.packet}),recordVerdict:args=>f.repo.recordVerdict(args)},judge:async()=>f.raw});const out=await service.retry({userId:17,evaluationId:randomUUID(),execution:{runId:randomUUID(),check:async()=>{}}});assert.equal(out.completed,false);assert.equal(out.judgment.verdict,'pass');assert.equal(out.judgment.gradingStatus,'pending');assert.equal(out.receipt.disposition,'grading_unqualified');assert(!f.queries.some(q=>q.includes('INSERT INTO workshop_platform.completions')));
});
test('recovery GET projects explicit pending and disables retry even unavailable raw result',async()=>{const f=fixture();const row={...f.row,verdict:'unavailable',disposition:'grading_unqualified',result_json:{errorCode:'MODEL_UNAVAILABLE'},has_packet:true,expires_at:new Date(Date.now()+60000),judge_version:'v1',owner_generation:'0',live_owner_generation:'0',xss_binding_current:true,live_generation:0,live_mode:'vuln',live_mode_stamp:'default',is_visible:true,exercise_active:true,is_enabled:true,objective_active:true};const repo=createObjectiveJudgmentRepository({query:async()=>({rows:[row]}),connect(){throw Error('No writes');}});const [out]=await repo.listRecoverable({userId:17,judgeVersion:'v1'});assert.equal(out.gradingStatus,'pending');assert.equal(out.canRetry,false);assert.equal(out.verdict,'unavailable');});

test('missing additive migration fails closed with actionable readiness error and rollback',async()=>{const f=fixture({missingMigration:true});await assert.rejects(f.commit(),e=>e.code==='GRADE_STORE_NOT_READY'&&e.message.includes('0103'));assert(f.queries.includes('ROLLBACK'));assert.equal(f.row.verdict,null);assert(!f.queries.some(q=>q.includes('INSERT INTO workshop_platform.completions')));});


test('new side-stepping server-ID contract remains credit-gated independently of a pass prediction', () => {
 const row = {workshop_key:'direct_prompt_injection', family:'DPI', scenario:'aws_assistant', objective_id:'side_stepping', rubric_version:'dpi-side_stepping-server-ids-v1', mode:'vuln'};
 for (const verdict of ['pass','fail','inconclusive','unavailable']) {
  assert.equal(gradingUnqualified(row, {verdict,provider:'ollama',model:'llama3.3:70b'}), true);
  const projected = projectJudgment({disposition:'grading_unqualified', result:{verdict}});
  assert.equal(projected.gradingStatus, 'pending');
  assert.equal(projected.gradingDisposition, 'grading_unqualified');
 }
 assert.equal(gradingUnqualified({...row,workshop_key:'other'}, {verdict:'pass'}), false);
});

function qualifiedSideFixture() {
 const raw = '{"assessment":"retained provider bytes"}';
 const model = {provider:'ollama',model:'llama3.3:70b'};
 const row = {workshop_key:'direct_prompt_injection',family:'DPI',scenario:'aws_assistant',objective_id:'side_stepping',rubric_version:'dpi-side_stepping-conjunction-v2',mode:'vuln',canonical_mode:'vuln',run_id:randomUUID(),user_id:17,generation:2};
 const result = {verdict:'pass',...model,dpiAnswerComparison:{version:'dpi-answer-comparison-v16',observation:{version:'dpi-answer-comparison-v16',diagnosticVersion:'dpi-side-conjunction-v8',candidateAudit:{version:'dpi-side-conjunction-v8',verdict:'pass',reduction:{verdict:'pass'}},provenance:{version:'dpi-owned-actor-v3',objective:'side_stepping',runId:row.run_id,ownerKey:JSON.stringify(['DPI','17']),generation:'9',mode:'vuln',...model},selectedRaw:raw},stages:[{stage:'selected',attempts:1,completed:true,...model,responseSha256:[require('node:crypto').createHash('sha256').update(raw).digest('hex')]}]}};
 return {row,result};
}
test('audited v16 side result admits only the bounded qualified model contract',()=>{
 for(const verdict of ['pass','fail']) {
  const {row,result}=qualifiedSideFixture();result.verdict=verdict;
  result.dpiAnswerComparison.observation.candidateAudit.verdict=verdict;
  result.dpiAnswerComparison.observation.candidateAudit.reduction.verdict=verdict;
  assert.equal(gradingUnqualified(row,result),false);
 }
});
test('v16 side qualification rejects mismatched scope, model, ownership, stage and raw response',()=>{
 const mutations=[
  f=>f.row.scenario='another',f=>f.row.mode='fixed',f=>f.row.canonical_mode='fixed',
  f=>f.result.verdict='inconclusive',f=>f.result.model='llama3.1:8b',f=>f.result.provider='mock',
  f=>f.result.dpiAnswerComparison.version='dpi-answer-comparison-v15',
  f=>f.result.dpiAnswerComparison.observation.version='dpi-answer-comparison-v15',
  f=>f.result.dpiAnswerComparison.observation.diagnosticVersion='dpi-side-source-link-v7',
  f=>f.result.dpiAnswerComparison.observation.candidateAudit.version='dpi-side-source-link-v7',
  f=>f.result.dpiAnswerComparison.observation.candidateAudit.verdict='fail',
  f=>f.result.dpiAnswerComparison.observation.candidateAudit.reduction.verdict='fail',
  f=>f.result.dpiAnswerComparison.observation.provenance.version='dpi-owned-actor-v2',
  f=>f.result.dpiAnswerComparison.observation.provenance.objective='jailbreak',
  f=>f.result.dpiAnswerComparison.observation.provenance.runId=randomUUID(),
  f=>f.result.dpiAnswerComparison.observation.provenance.ownerKey=JSON.stringify(['DPI','18']),
  f=>f.result.dpiAnswerComparison.observation.provenance.generation='',
  f=>f.result.dpiAnswerComparison.observation.provenance.mode='fixed',
  f=>f.result.dpiAnswerComparison.observation.provenance.model='another',
  f=>f.result.dpiAnswerComparison.stages.push({...f.result.dpiAnswerComparison.stages[0]}),
  f=>f.result.dpiAnswerComparison.stages[0].stage='verify',
  f=>f.result.dpiAnswerComparison.stages[0].attempts=2,
  f=>f.result.dpiAnswerComparison.stages[0].completed=false,
  f=>f.result.dpiAnswerComparison.stages[0].provider='mock',
  f=>f.result.dpiAnswerComparison.stages[0].model='another',
  f=>f.result.dpiAnswerComparison.stages[0].responseSha256.push('extra'),
  f=>f.result.dpiAnswerComparison.observation.selectedRaw+=' ',
  f=>delete f.result.dpiAnswerComparison.observation.selectedRaw,
 ];
 mutations.forEach((mutate,index)=>{const f=qualifiedSideFixture();mutate(f);assert.equal(gradingUnqualified(f.row,f.result),true,`mutation ${index}`);});
 const f=qualifiedSideFixture();f.row.rubric_version='dpi-side_stepping-server-ids-v1';
 assert.equal(gradingUnqualified(f.row,f.result),true,'v15 remains pending even with v16 result');
});

test('v24 side compact successor qualifies a grounded pass (like jailbreak v3) but rejects invalid evidence',()=>{
 // side_stepping compact-conjunction is now creditable on a valid grounded
 // grade (parity with jailbreak/role_playing compact-context v3), so the lab's
 // side-stepping objective can complete. A valid standard-model pass qualifies;
 // every structural mutation still fails closed.
 const good=qualifiedTechniqueFixture('side_stepping','dpi-answer-comparison-v24',{modelName:'llama3.3:70b',attempts:1});
 assert.equal(gradingUnqualified(good.row,good.result),false,'grounded 70B pass qualifies');
 // A non-pass/fail verdict or a mismatched/mocked model must NOT qualify.
 for(const mutate of [
   f=>f.result.verdict='unavailable',
   f=>f.result.provider='mock',
   f=>f.result.dpiAnswerComparison.stages[0].completed=false,
   f=>f.result.dpiAnswerComparison.observation.selectedRaw+=' ',
 ]){
   const f=qualifiedTechniqueFixture('side_stepping','dpi-answer-comparison-v24',{modelName:'llama3.3:70b',attempts:1});
   mutate(f);
   assert.equal(gradingUnqualified(f.row,f.result),true,'invalid side evidence stays unqualified');
 }
});

function qualifiedTechniqueFixture(objective, protocolOverride, {modelName='llama3.3:70b',attempts=1,provider='ollama'}={}) {
 const raw = '{\"assessment\":\"retained provider bytes\"}',model = {provider,model:modelName};
 const protocol = require('../server/agent-runtime/dpiSelectedTaskComparison').getSelectedProtocol(protocolOverride || (objective === 'jailbreak' ? 'dpi-answer-comparison-v17' : 'dpi-answer-comparison-v18'));
 const row = {workshop_key:'direct_prompt_injection',family:'DPI',scenario:'aws_assistant',objective_id:objective,rubric_version:protocol.rubricVersion,mode:'vuln',canonical_mode:'vuln',run_id:randomUUID(),user_id:17,generation:2};
 const finalHash=require('node:crypto').createHash('sha256').update(raw).digest('hex');
 const result = {verdict:'pass',...model,dpiAnswerComparison:{version:protocol.version,observation:{version:protocol.version,diagnosticVersion:protocol.diagnosticVersion,objective, candidateAudit:{version:protocol.diagnosticVersion,verdict:'pass'},provenance:{version:'dpi-owned-actor-v3',objective,runId:row.run_id,ownerKey:JSON.stringify(['DPI','17']),generation:'9',mode:'vuln',...model},selectedRaw:raw},stages:[{stage:'selected',attempts,completed:true,...model,responseSha256:[...Array(Math.max(0,attempts-1)).fill('a'.repeat(64)),finalHash]}]}};
 return {row,result};
}
test('v17 and v18 admit only the exact registry-selected 70B actor and selected-stage contract',()=>{
 for(const objective of ['jailbreak','role_playing']) for(const verdict of ['pass','fail']) {
  const {row,result}=qualifiedTechniqueFixture(objective);result.verdict=verdict;result.dpiAnswerComparison.observation.candidateAudit.verdict=verdict;
  assert.equal(gradingUnqualified(row,result),false,`${objective} ${verdict}`);
 }
 const mutations=[
  f=>f.result.dpiAnswerComparison.version='dpi-answer-comparison-v16',
  f=>f.result.dpiAnswerComparison.observation.diagnosticVersion='dpi-side-conjunction-v8',f=>f.result.dpiAnswerComparison.observation.objective='side_stepping',
  f=>f.result.dpiAnswerComparison.observation.candidateAudit.version='dpi-side-conjunction-v8',f=>f.result.dpiAnswerComparison.observation.candidateAudit.verdict='fail',
  f=>f.result.dpiAnswerComparison.observation.provenance.version='dpi-owned-actor-v2',f=>f.result.dpiAnswerComparison.observation.provenance.runId=randomUUID(),
  f=>f.result.dpiAnswerComparison.observation.provenance.ownerKey=JSON.stringify(['DPI','18']),f=>f.result.dpiAnswerComparison.observation.provenance.generation='',
  f=>f.result.provider='mock',f=>f.result.dpiAnswerComparison.stages[0].model='llama3.1:8b',f=>f.result.dpiAnswerComparison.stages[0].attempts=2,
  f=>f.result.dpiAnswerComparison.stages[0].completed=false,f=>f.result.dpiAnswerComparison.stages[0].responseSha256.push('extra'),f=>f.result.dpiAnswerComparison.observation.selectedRaw+=' ',
 ];
 mutations.forEach((mutate,index)=>{const f=qualifiedTechniqueFixture('jailbreak');mutate(f);assert.equal(gradingUnqualified(f.row,f.result),true,`mutation ${index}`);});
});
test('v15 jailbreak and role-playing rows remain pending even with otherwise qualified v17/v18 output',()=>{
 for(const objective of ['jailbreak','role_playing']) {
  const {row,result}=qualifiedTechniqueFixture(objective);row.rubric_version='dpi-'+objective+'-server-ids-v1';result.dpiAnswerComparison.version='dpi-answer-comparison-v15';
  assert.equal(gradingUnqualified(row,result),true);assert.equal(projectJudgment({disposition:'grading_unqualified',result}).gradingStatus,'pending');
 }
});

test('context successors reject unqualified results',()=>{for(const [objective,rubric]of [['jailbreak','dpi-jailbreak-context-v2'],['role_playing','dpi-role_playing-context-v2'],['jailbreak','dpi-jailbreak-compact-context-v3'],['role_playing','dpi-role_playing-compact-context-v3']]){const f=fixture({objective});f.row.rubric_version=rubric;assert.equal(gradingUnqualified(f.row,{...f.raw,model:'llama3.3:70b'}),true);}});

test('v19 and v20 require their exact context protocol and qualified evidence envelope',()=>{
 for(const [objective,version]of [['jailbreak','dpi-answer-comparison-v19'],['role_playing','dpi-answer-comparison-v20']])for(const verdict of ['pass','fail']){
  const f=qualifiedTechniqueFixture(objective,version);f.result.verdict=verdict;f.result.dpiAnswerComparison.observation.candidateAudit.verdict=verdict;
  assert.equal(gradingUnqualified(f.row,f.result),false);
  for(const mutate of [x=>x.result.dpiAnswerComparison.observation.diagnosticVersion='dpi-direct-witness-server-ids-v6',x=>x.result.dpiAnswerComparison.observation.selectedRaw+=' ',x=>x.result.model='mock',x=>x.result.dpiAnswerComparison.observation.provenance.generation='']){
   const g=structuredClone(f);mutate(g);assert.equal(gradingUnqualified(g.row,g.result),true);
  }
 }
});
test('v21 and v22 admit only exact current 8B one-call and bounded-repair evidence',()=>{
 for(const [objective,version]of [['jailbreak','dpi-answer-comparison-v21'],['role_playing','dpi-answer-comparison-v22']])for(const verdict of ['pass','fail'])for(const attempts of [1,2]){
  const f=qualifiedTechniqueFixture(objective,version,{modelName:'llama3.1:8b',attempts});f.result.verdict=verdict;f.result.dpiAnswerComparison.observation.candidateAudit.verdict=verdict;
  assert.equal(gradingUnqualified(f.row,f.result),false,`${objective} ${verdict} attempt ${attempts}`);
 }
});
test('v21 and v22 reject mixed, malformed, repeated-invalid and provenance-mismatched current evidence',()=>{
 const mutations=[
  f=>f.result.model='llama3.3:70b',f=>f.result.provider='mock',f=>f.result.dpiAnswerComparison.stages[0].model='llama3.3:70b',
  f=>f.result.dpiAnswerComparison.stages[0].attempts=3,f=>f.result.dpiAnswerComparison.stages[0].attempts=0,
  f=>f.result.dpiAnswerComparison.stages[0].completed=false,f=>f.result.dpiAnswerComparison.stages[0].responseSha256.pop(),
  f=>f.result.dpiAnswerComparison.stages[0].responseSha256.push('b'.repeat(64)),f=>f.result.dpiAnswerComparison.stages[0].responseSha256[1]='b'.repeat(64),
  f=>f.result.dpiAnswerComparison.observation.selectedRaw+=' ',f=>f.result.dpiAnswerComparison.observation.provenance.runId=randomUUID(),
  f=>f.result.dpiAnswerComparison.observation.provenance.ownerKey=JSON.stringify(['DPI','18']),f=>f.result.dpiAnswerComparison.observation.provenance.generation='',
  f=>f.result.dpiAnswerComparison.observation.provenance.mode='fixed',f=>f.result.dpiAnswerComparison.observation.provenance.objective='role_playing',
  f=>f.result.dpiAnswerComparison.observation.candidateAudit.verdict='fail',f=>f.result.dpiAnswerComparison.observation.version='dpi-answer-comparison-v20',
 ];
 for(const [index,mutate]of mutations.entries()){const f=qualifiedTechniqueFixture('jailbreak','dpi-answer-comparison-v21',{modelName:'llama3.1:8b',attempts:2});mutate(f);assert.equal(gradingUnqualified(f.row,f.result),true,`mutation ${index}`);}
 for(const verdict of ['inconclusive','unavailable']){const f=qualifiedTechniqueFixture('jailbreak','dpi-answer-comparison-v21',{modelName:'llama3.1:8b',attempts:2});f.result.verdict=verdict;assert.equal(gradingUnqualified(f.row,f.result),true,`repeated invalid ${verdict}`);}
 for(const version of ['dpi-answer-comparison-v21','dpi-answer-comparison-v22']){const objective=version.endsWith('21')?'jailbreak':'role_playing',f=qualifiedTechniqueFixture(objective,version);assert.equal(gradingUnqualified(f.row,f.result),true,'compact 70B remains unqualified');}
});

test('Bedrock judgments qualify these objectives when the deployed model matches', () => {
  // On a Bedrock deployment the provider is "bedrock" and the model is the
  // configured BEDROCK_MODEL_ID/JUDGE_MODEL. The attacks succeed the same way;
  // credit must be awarded when the trusted deployment model proves them.
  const previous = process.env.JUDGE_MODEL;
  const previousActor = process.env.BEDROCK_MODEL_ID;
  // A single-model Bedrock deployment: actor and judge are the same model.
  process.env.JUDGE_MODEL = 'us.meta.llama3-1-8b-instruct-v1:0';
  process.env.BEDROCK_MODEL_ID = 'us.meta.llama3-1-8b-instruct-v1:0';
  try {
    for (const [objective, version] of [['jailbreak', 'dpi-answer-comparison-v21'], ['role_playing', 'dpi-answer-comparison-v22']]) {
      const f = qualifiedTechniqueFixture(objective, version, {
        modelName: 'us.meta.llama3-1-8b-instruct-v1:0', provider: 'bedrock', attempts: 1,
      });
      f.result.verdict = 'pass';
      f.result.dpiAnswerComparison.observation.candidateAudit.verdict = 'pass';
      assert.equal(gradingUnqualified(f.row, f.result), false, `${objective} bedrock should qualify`);
    }
    // A Bedrock judgment naming a DIFFERENT model must NOT qualify.
    const wrong = qualifiedTechniqueFixture('jailbreak', 'dpi-answer-comparison-v21', {
      modelName: 'some-other-model', provider: 'bedrock', attempts: 1,
    });
    wrong.result.verdict = 'pass';
    wrong.result.dpiAnswerComparison.observation.candidateAudit.verdict = 'pass';
    assert.equal(gradingUnqualified(wrong.row, wrong.result), true, 'wrong bedrock model must stay unqualified');
  } finally {
    if (previous === undefined) delete process.env.JUDGE_MODEL; else process.env.JUDGE_MODEL = previous;
    if (previousActor === undefined) delete process.env.BEDROCK_MODEL_ID; else process.env.BEDROCK_MODEL_ID = previousActor;
  }
});

test('technique-witness objectives complete on a clean runtime verdict, not only an offline qualification', () => {
  // jailbreak/role_playing/side_stepping in vuln mode use the technique-witness
  // path. The runtime Judge computes a real pass/fail; a clean pass must now be
  // credited (on ollama OR bedrock), while an unavailable/mocked verdict stays
  // pending and uncredited.
  const { gradingUnqualified } = require('../server/agent-runtime/dpiSemanticCreditPolicy');
  for (const objective of ['jailbreak', 'role_playing', 'side_stepping']) {
    const row = { workshop_key: 'direct_prompt_injection', family: 'DPI', scenario: 'aws_assistant',
      objective_id: objective, rubric_version: `dpi-${objective}-technique-v2`, mode: 'vuln', canonical_mode: 'vuln' };
    for (const provider of ['ollama', 'bedrock']) {
      const pass = { verdict: 'pass', provider, model: 'm', dpiTechniqueWitness: {},
        criteria: [{ id: 'observed_objective', satisfied: true, evidenceRefs: ['response'] }] };
      assert.equal(gradingUnqualified(row, pass), false, `${objective}/${provider} clean pass must be credited`);
      const fail = { verdict: 'fail', provider, model: 'm', dpiTechniqueWitness: {},
        criteria: [{ id: 'observed_objective', satisfied: false, evidenceRefs: [] }] };
      assert.equal(gradingUnqualified(row, fail), false, `${objective}/${provider} clean fail is a real graded verdict`);
    }
    // Unavailable, mocked, wrong-criteria and wrong-provider stay unqualified.
    for (const bad of [
      { verdict: 'unavailable', provider: 'bedrock', dpiTechniqueWitness: undefined, criteria: [] },
      { verdict: 'pass', provider: 'bedrock', mocked: true, dpiTechniqueWitness: {}, criteria: [{ id: 'observed_objective', satisfied: true }] },
      { verdict: 'pass', provider: 'mock', dpiTechniqueWitness: {}, criteria: [{ id: 'observed_objective', satisfied: true }] },
      { verdict: 'pass', provider: 'bedrock', dpiTechniqueWitness: {}, criteria: [{ id: 'wrong', satisfied: true }] },
    ]) {
      assert.equal(gradingUnqualified(row, { model: 'm', ...bad }), true, `${objective} bad verdict must stay pending`);
    }
  }
});

test('single 8B model qualifies for actor AND judge; a different judge model does not', () => {
  const { gradingUnqualified } = require('../server/agent-runtime/dpiSemanticCreditPolicy');
  const prevJudge = process.env.JUDGE_MODEL, prevActor = process.env.BEDROCK_MODEL_ID;
  // The deployment pins the SAME 8B model for both the actor and the judge
  // (JUDGE_MODEL === BEDROCK_MODEL_ID). The provenance names the actor model and
  // the grading stages name the judge model; both are the one 8B model.
  const EIGHTB = 'us.meta.llama3-1-8b-instruct-v1:0';
  process.env.BEDROCK_MODEL_ID = EIGHTB;
  process.env.JUDGE_MODEL = EIGHTB;
  try {
    for (const [objective, version] of [['jailbreak', 'dpi-answer-comparison-v21'], ['role_playing', 'dpi-answer-comparison-v22']]) {
      const f = qualifiedTechniqueFixture(objective, version, { modelName: EIGHTB, provider: 'bedrock', attempts: 1 });
      f.result.verdict = 'pass';
      f.result.dpiAnswerComparison.observation.candidateAudit.verdict = 'pass';
      // Actor provenance AND grading stages are the one configured 8B model.
      f.result.dpiAnswerComparison.observation.provenance.model = EIGHTB;
      assert.equal(gradingUnqualified(f.row, f.result), false, `${objective} single-8B-model should qualify`);
    }
    // A judge rendered by a DIFFERENT model (e.g. 70B) must NOT qualify: the
    // deployment uses only the configured 8B model as judge.
    const wrongJudge = qualifiedTechniqueFixture('jailbreak', 'dpi-answer-comparison-v21', { modelName: 'us.meta.llama3-1-70b-instruct-v1:0', provider: 'bedrock', attempts: 1 });
    wrongJudge.result.verdict = 'pass';
    wrongJudge.result.dpiAnswerComparison.observation.candidateAudit.verdict = 'pass';
    wrongJudge.result.dpiAnswerComparison.observation.provenance.model = EIGHTB;
    assert.equal(gradingUnqualified(wrongJudge.row, wrongJudge.result), true, 'a non-8B judge model stays unqualified');
    // Actor on the WRONG model must not qualify either.
    const wrongActor = qualifiedTechniqueFixture('jailbreak', 'dpi-answer-comparison-v21', { modelName: EIGHTB, provider: 'bedrock', attempts: 1 });
    wrongActor.result.verdict = 'pass';
    wrongActor.result.dpiAnswerComparison.observation.candidateAudit.verdict = 'pass';
    wrongActor.result.dpiAnswerComparison.observation.provenance.model = 'some-other-actor-model';
    assert.equal(gradingUnqualified(wrongActor.row, wrongActor.result), true, 'wrong actor model stays unqualified');
  } finally {
    if (prevJudge === undefined) delete process.env.JUDGE_MODEL; else process.env.JUDGE_MODEL = prevJudge;
    if (prevActor === undefined) delete process.env.BEDROCK_MODEL_ID; else process.env.BEDROCK_MODEL_ID = prevActor;
  }
});
