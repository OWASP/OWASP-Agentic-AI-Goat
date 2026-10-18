'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {VERSION,validProof,inspectPacket}=require('../server/services/csrfReconProof');
const run='11111111-1111-4111-8111-111111111111',prior='22222222-2222-4222-8222-222222222222';
const execution={ownerKey:'["CSRF","7"]',runId:run,durableGeneration:'3',check:async()=>{}};
const proof=()=>({version:1,ownerKey:execution.ownerKey,generation:'3',currentRunId:run,runs:[run,prior].map(runId=>({runId,provider:'ollama',model:'llama3.1:8b',decisionSeq:2,effectSeq:4,endSeq:5}))});
const packet=()=>({rubric:{family:'CSRF',objectiveId:'csrf_g1',version:VERSION,requiredFacts:['required_observation','actual_recon_history']},facts:{required_observation:true,actual_recon_history:true},evidence:[{id:'recon_history',source:'server_observation',content:proof()}]});
test('two real current-generation distinct run proofs accepted, mixed and scope mutations denied',()=>{assert.ok(validProof(proof(),execution));assert.equal(inspectPacket(packet(),execution),null);for(const mutate of [p=>p.runs[1].provider='mock',p=>p.runs[0].model='fallback',p=>p.runs[1].provider='',p=>p.runs[1].runId=run,p=>p.currentRunId=prior,p=>p.ownerKey='["CSRF","8"]',p=>p.generation='2',p=>p.runs[0].endSeq=3,p=>p.runs.pop(),p=>p.runs[0]=null,p=>p.runs[0]=[]]){const p=packet();mutate(p.evidence[0].content);assert.equal(inspectPacket(p,execution),'CSRF_RECON_HISTORY_INVALID');}});
test('historical packet unchanged and unsupported rather than silently upgraded',()=>{const p=packet();p.rubric.version='csrf-observed-v8';const before=JSON.stringify(p);assert.equal(inspectPacket(p,execution),'CSRF_RECON_VERSION_UNSUPPORTED');assert.equal(JSON.stringify(p),before);});
test('repository uses exact owner/generation, current run and ordered GET effect, not count or generic history',async()=>{const sql=[];let released=false;const client={query:async(q,args)=>{sql.push({q,args});return{rows:q.includes('SELECT r.run_id')?proof().runs:[]};},release(){released=true;}};const repo=require('../server/database/postgres/csrfReconProofRepository').createCsrfReconProofRepository({connect:async()=>client});assert.deepEqual(await repo.read({execution,userId:7}),proof());const query=sql.find(x=>x.q.includes('SELECT r.run_id'));assert.deepEqual(query.args,[execution.ownerKey,'3',run]);for(const condition of ["m.node='csrf_recon_get'","e.node='recon'","e.event_type='node_end'","r.status='completed'","o.generation=$2::bigint","d.metadata->>'decisionSource'='model'","LIMIT 2"])assert.ok(query.q.includes(condition));assert.ok(sql.some(x=>x.q.includes("statement_timeout='3s'")));assert.ok(released);});
test('mock teaching count plus one real run stays ungraded even if injected Judge says pass',async()=>{const grader=require('../server/services/csrfObjectiveGrader').createCsrfObjectiveGrader({postgres:false,judge:async()=>({verdict:'pass'})});const result=await grader.evaluate({userId:7,objectiveId:'csrf_g1',execution,snapshot:{reconCount:2},activity:{result:{kind:'recon',surface:{actions:[{id:'change_email'}],vectors:[{id:'direct_get'}]}}}});assert.equal(result.completed,false);});

test('real Judge entry denies old and contradictory packets before any model call',async()=>{let calls=0;const judge=require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{generate:async()=>{calls++;throw Error('unexpected');}}});for(const version of ['csrf-observed-v8',VERSION]){const p=packet();p.rubric={...p.rubric,version,scenario:'get',mode:'vuln',criteria:[{id:'observed_outcome',description:'Two actual recon interactions.',allowedSources:['server_observation']}]};if(version===VERSION)p.evidence[0].content.runs[1].provider='mock';const r=await judge({...p,execution});assert.equal(r.verdict,'unavailable');assert.equal(r.attempts,0);assert.equal(require('../server/agent-runtime/judgeErrors').canRetryJudgeError(r.errorCode),false);}assert.equal(calls,0);});

test('canonical retry preserves v8 packet and stores supported unavailable audit; v9 real proof reaches Judge once',async()=>{
 const {createObjectiveJudge,prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
 const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
 const {resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
 for(const version of ['csrf-observed-v8',VERSION]){
  let calls=0;const p=packet();p.rubric={...p.rubric,version,scenario:'get',mode:'vuln',criteria:[{id:'observed_outcome',description:'Two actual recon interactions.',allowedSources:['server_observation']}]};
  const prepared=prepareJudgeInput(p),stored=prepared.packet;
  const receipt={evaluationId:prior,runId:run,verdict:null,evidenceDigest:prepared.evidenceDigest,rubricVersion:version,family:'CSRF',scenario:'get',objectiveId:'csrf_g1',mode:'vuln'};
  const judge=createObjectiveJudge({model:{generate:async()=>{calls++;return{response:JSON.stringify({verdict:'pass',explanation:'Two scoped real recon observations.',criteria:[{id:'observed_outcome',satisfied:true,evidenceRefs:['recon_history']}]}),provider:'ollama',model:'llama3.1:8b'};}}});
  let persisted;
  const service=createObjectiveCompletionService({judge,progress:{getGeneration:async()=>0},receipts:{beginEvaluation:async()=>{},beginRetry:async()=>({receipt,packet:stored}),recordVerdict:async({result})=>{const row={family:'CSRF',scenario:'get',objective_id:'csrf_g1',rubric_version:version,evidence_digest:prepared.evidenceDigest,run_id:run,mode:'vuln'};persisted=resultValue(result,row);return{...receipt,result:persisted,verdict:persisted.verdict,disposition:persisted.verdict==='pass'?'awarded':'not_pass'};}}});
  const result=await service.retry({userId:7,evaluationId:prior,execution:{...execution,runId:'33333333-3333-4333-8333-333333333333'}});
  assert.equal(stored,prepared.packet);assert.equal(calls,version===VERSION?1:0);assert.equal(result.completed,version===VERSION);assert.equal(result.judgment.canRetry,false);assert.equal(persisted.verdict,version===VERSION?'pass':'unavailable');
 }
});

test('GET marker follows persisted recon; mock teaching remains observable but lacks actual decision, other tabs and failures cannot supply marker',async()=>{
 const {runCsrfAgentGraph}=require('../server/agent-runtime/csrfAgentGraph');
 for(const [tabId,mock,fail]of [['get',false,false],['get',true,false],['post',false,false],['get',false,true]]){
  const events=[],tab={reconCount:0};const sandbox={tab:()=>tab,getTabState:()=>({reconCount:tab.reconCount}),describeSurface:()=>({actions:[{id:'change_email'}],vectors:[{id:'direct_get'}]}),flush:async()=>{events.push({node:'flush'});if(fail)throw Error('storage unavailable');}};
  const args={sandboxMod:{ACTIONS:{change_email:{}},VECTORS:{direct_get:{}},getOrCreateSandbox:()=>sandbox},model:mock?{provider:'mock'}:{provider:'ollama',chatWithTools:async()=>({content:JSON.stringify({intent:'recon',action:'none',vector:'none',defenseOn:false,params:{}}),provider:'ollama',model:'llama3.1:8b'})},detectIntent:()=>({intent:'recon'}),reconObjectives:t=>{t.reconCount++;return[];},reconNudge:(_,text)=>text,phraseRecon:async()=> 'surface',execution:{...execution,trace:async event=>events.push(event)}};
  const invoke=()=>runCsrfAgentGraph('owned',tabId,'Show capabilities',{},args);
  if(fail)await assert.rejects(invoke,/storage unavailable/);else await invoke();
  assert.equal(events.filter(e=>e.node==='csrf_recon_get').length,tabId==='get'&&!fail?1:0);
  if(tabId==='get'&&!fail)assert.ok(events.findIndex(e=>e.node==='flush')<events.findIndex(e=>e.node==='csrf_recon_get'));
  assert.equal(events.some(e=>e.node==='classify'&&e.type==='decision'&&e.data.decisionSource==='model'),!mock);
 }
});

test('malformed retained proof is unavailable before model invocation',async()=>{let calls=0;const p=packet();p.rubric={...p.rubric,scenario:'get',mode:'vuln',criteria:[{id:'observed_outcome',description:'Two real recon runs.',allowedSources:['server_observation']}]};p.evidence[0].content.runs[0]=null;const judge=require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{generate:async()=>{calls++;throw Error('unexpected');}}});assert.equal((await judge({...p,execution})).errorCode,'CSRF_RECON_HISTORY_INVALID');assert.equal(calls,0);});

test('checked-in GET teaching copy describes model recon provenance and blocked outcome',()=>{
 const rows=require('../server/data/csrfWorkshopSolutions').objectiveSolutions;
 const g1=rows.find(r=>r.objective_id==='csrf_g1'),g3=rows.find(r=>r.objective_id==='csrf_g3');
 assert.match(g1.hint,/Two successful actual-model GET recon tool runs/);assert.match(g1.hint,/mock responses, ordinary chat and message count alone cannot earn credit/);
 assert.match(g3.explanation,/observed 403, blocked result/);assert.match(g3.explanation,/HTTP 200/);assert.doesNotMatch(g3.explanation,/returns 403/);
});
