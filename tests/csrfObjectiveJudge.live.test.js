'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const {buildCsrfJudgeCases}=require('./fixtures/csrfJudgeCases');
const {createCsrfObjectiveGrader,CRITERIA}=require('../server/services/csrfObjectiveGrader');
const {issueCsrfGadgetBrowserReceipt}=require('../server/services/csrfGadgetBrowserReceipt');
const {ATTACKER_ORIGIN,BROWSER_OBJECTIVES,issueCsrfBrowserReceipt}=require('../server/services/csrfBrowserReceipt');
const mailProofs=new WeakMap();
const reconProofs=new WeakMap();
const reconProofRepository={read:async({execution})=>reconProofs.get(execution)||null};
const inspectMailProof=(receipt,scope)=>{
 const proof=receipt&&mailProofs.get(receipt);return proof?.kind===scope.kind?proof:null;
};

function prepareTrustedJudgeFixture(item) {
 const activity=structuredClone(item.activity);
 if(item.positive&&activity?.result?.executed===true&&activity.result.changed
   &&Object.keys(activity.result.changed).length>0)activity.result.stateChanged=true;
 const execution={check:async()=>{},runId:randomUUID(),ownerKey:JSON.stringify(['CSRF','7']),generation:0,durableGeneration:'0'};
 if(item.positive&&item.objectiveId==='csrf_g1')reconProofs.set(execution,{version:1,ownerKey:execution.ownerKey,generation:'0',currentRunId:execution.runId,runs:[randomUUID(),execution.runId].map(runId=>({runId,provider:'ollama',model:'llama3.1:8b',decisionSeq:1,effectSeq:2,endSeq:3}))});
 let receipt=item.receipt;
 let mailReceipt=item.receipt;
 if(item.positive&&['csrf_x2','csrf_x3'].includes(item.objectiveId)){
  mailProofs.set(mailReceipt,{kind:item.objectiveId==='csrf_x2'?'accepted':'retrieved',
   state:item.objectiveId==='csrf_x2'?'accepted':'retrieved',hasEventHandler:true});
 }
 if(item.positive&&BROWSER_OBJECTIVES.includes(item.objectiveId)){
  const post=item.objectiveId.startsWith('csrf_p');
  receipt=issueCsrfBrowserReceipt({
   binding:{runId:execution.runId,ownerKey:execution.ownerKey,generation:execution.generation,
    objectiveId:item.objectiveId,tab:post?'post':'get',payloadDigest:createHash('sha256').update(`trusted-fixture:${item.objectiveId}`).digest('hex')},
   observation:{method:post?'POST':'GET',frameOrigin:ATTACKER_ORIGIN,
    resourceType:item.objectiveId==='csrf_p2'?'fetch':post?'document':'image',cookiePresent:true},
   responseStatus:['csrf_g3','csrf_p3'].includes(item.objectiveId)?403:200,
   execution,activity,
  });
 }
 let classifiedEmailProof=null;
 if(item.positive&&item.objectiveId==='csrf_x3'){
  activity.userKey='7'; activity.tabId='xss';
  receipt=issueCsrfGadgetBrowserReceipt({
   binding:{runId:execution.runId,ownerKey:execution.ownerKey,generation:execution.generation,
    objectiveId:'csrf_x3',tab:'xss',expectedVector:'xss',payloadDigest:createHash('sha256').update('trusted-fixture:csrf_x3').digest('hex')},
   observation:{method:'POST',frameOrigin:'http://victim.csrf.invalid',resourceType:'fetch',cookiePresent:true},
   responseStatus:200,execution,activity,
  });
  classifiedEmailProof={version:1,objectiveId:'csrf_x3',generation:0,provider:'ollama',model:'llama3.1:8b',
   summaryDigest:'a'.repeat(64),gadgetDigest:'b'.repeat(64)};
 }
 return {activity,execution,receipt,mailReceipt,browserReceipt:item.positive&&item.objectiveId==='csrf_x3'?receipt:undefined,classifiedEmailProof};
}
test('CSRF qualification covers all12 objective pairs',()=>{
 const cases=buildCsrfJudgeCases();assert.equal(cases.length,24);
 assert.deepEqual([...new Set(cases.map(c=>c.objectiveId))].sort(),Object.keys(CRITERIA).sort());
});
test('v8 supplied-evidence matrix uses private trusted receipt fixtures for browser objectives',async()=>{
 const grader=createCsrfObjectiveGrader({postgres:false,inspectMailProof,reconProofRepository,
  inspectClassifiedEmailProof:async({proof})=>proof,
  inspectBrowserReceipt:()=>true,judge:async({facts,rubric})=>({
  verdict:facts.required_observation?'pass':'fail',explanation:'Deterministic prerequisite projection.',criteria:[],rubricVersion:rubric.version,
  }),
 });
 for(const item of buildCsrfJudgeCases()){
  const fixture=prepareTrustedJudgeFixture(item);
  const result=await grader.evaluate({...item,...fixture,userId:7});
  assert.equal(result.completed,item.positive,`${item.objectiveId} positive=${item.positive}`);
  assert.equal(result.judgment.verdict,item.positive?'pass':'fail');
  assert.equal(result.judgment.rubricVersion,item.objectiveId==='csrf_g1'?'csrf-recon-v9':item.objectiveId==='csrf_x3'?'csrf-classified-email-v1':'csrf-observed-v8');
 }
});
test('local8B CSRF matrix uses trusted receipt fixtures; it does not claim browser execution',{skip:process.env.RUN_LIVE_JUDGE!=='1',timeout:600000},async t=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 const model=require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'});
 const grader=createCsrfObjectiveGrader({postgres:false,inspectMailProof,reconProofRepository,judge:createObjectiveJudge({model})});
 const failures=[];
 for(const item of buildCsrfJudgeCases()){
  const fixture=prepareTrustedJudgeFixture(item);
  const result=await grader.evaluate({...item,...fixture,userId:7});
  assert.equal(result.judgment.rubricVersion,item.objectiveId==='csrf_g1'?'csrf-recon-v9':item.objectiveId==='csrf_x3'?'csrf-classified-email-v1':'csrf-observed-v8');
  t.diagnostic(JSON.stringify({id:item.objectiveId,expected:item.positive?'pass':'not_pass',positive:item.positive,
   evidenceBoundary:BROWSER_OBJECTIVES.includes(item.objectiveId)&&item.positive?'trusted private receipt fixture; no browser executed':'synthetic server observation; no browser executed',judgment:result.judgment}));
  if(item.positive?result.judgment.verdict!=='pass':result.completed)failures.push({id:item.objectiveId,positive:item.positive,actual:result.judgment.verdict});
 }
 assert.deepEqual(failures,[]);
});

test('recon rejects absent, stale, sibling and malformed repository evidence',async()=>{
 const item=buildCsrfJudgeCases().find(item=>item.objectiveId==='csrf_g1'&&item.positive);
 const fixture=prepareTrustedJudgeFixture(item),valid=reconProofs.get(fixture.execution);
 for(const proof of [null,{...valid,generation:'1'},{...valid,ownerKey:JSON.stringify(['CSRF','8'])},{...valid,runs:[valid.runs[0],valid.runs[0]]}]){
  const grader=createCsrfObjectiveGrader({postgres:false,reconProofRepository:{read:async()=>proof},judge:async()=>({verdict:'pass',criteria:[],explanation:'Controlled positive Judge'})});
  assert.equal((await grader.evaluate({...item,...fixture,userId:7})).completed,false);
 }
 const defaultLegacy=createCsrfObjectiveGrader({postgres:false,judge:async()=>({verdict:'pass',criteria:[],explanation:'Controlled positive Judge'})});
 assert.equal((await defaultLegacy.evaluate({...item,...fixture,userId:7})).completed,false);
});
