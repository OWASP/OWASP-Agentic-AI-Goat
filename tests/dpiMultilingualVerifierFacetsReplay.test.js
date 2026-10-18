'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto'),fs=require('node:fs');
const {createDpiExistentialComparison}=require('../server/agent-runtime/dpiExistentialComparison');
const {createDpiExistentialEvaluation}=require('../server/agent-runtime/dpiExistentialEvaluation');
const corpus=require('./fixtures/dpiMultilingualSemanticProspective-v2.json');
const replay=require('./fixtures/dpiMultilingualVerifierFacets70bReplay.json');
const negative8bReplay=require('./fixtures/dpiMultilingualVerifierFacets8bNegativeReplay.json');
const sha=b=>createHash('sha256').update(b).digest('hex');
const witness={decision:'supported',sourceRange:{first:'s_0',last:'s_0'},responseRange:{first:'r_0',last:'r_0'}};

test('v13 verifier wire exactly matches eight retained 70B inputs and parses their real replies',()=>{
 assert.equal(sha(fs.readFileSync(require.resolve('./fixtures/dpiMultilingualSemanticProspective-v2.json'))),replay.corpusSha256);
 assert.equal(replay.model,'llama3.3:70b');assert.equal(replay.cases.length,8);
 for(const row of corpus.cases){
  const saved=replay.cases.find(item=>item.id===row.id);assert(saved,row.id);
  const c=createDpiExistentialComparison({primary:true,objective:'multi_language',protocolVersion:'dpi-answer-comparison-v13'},[
    {id:'request',source:'student_input',content:row.request},{id:'response',source:'assistant_response',content:row.response}]);
  const assessment=c.stages[0].validate(JSON.stringify(witness));
  const actual=c.stages[1].messages();
  assert.deepEqual(actual.messages,saved.request.messages,row.id);
  assert.deepEqual(actual.format,saved.request.format,row.id);
  assert.deepEqual(JSON.parse(actual.messages[1].content),{learnerRequest:row.request,assistantResponse:row.response},row.id);
  const verification=c.stages[1].validate(saved.responseContent);
  assert.deepEqual(verification,JSON.parse(saved.responseContent));
  assert.equal(c.combine(assessment,verification).verdict,row.expectedVerdict,row.id);
 }
});

test('v13 rejects forged verifier fields, and v12 remains a distinct historical contract',()=>{
 const evidence=[{id:'request',source:'student_input',content:'¿Cuál es la capital de Francia?'},
  {id:'response',source:'assistant_response',content:'La capital de Francia es París.'}];
 const current=createDpiExistentialComparison({primary:true,objective:'multi_language',protocolVersion:'dpi-answer-comparison-v13'},evidence);
 const assessment=current.stages[0].validate(JSON.stringify(witness));
 assert.throws(()=>current.stages[1].validate(JSON.stringify({requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes',authority:'caller'})));
 assert.throws(()=>current.stages[1].validate(JSON.stringify({requestNonEnglish:'yes',requestNonAws:'yes',answerFulfills:'yes'})));
 const old=createDpiExistentialComparison({primary:true,objective:'multi_language',protocolVersion:'dpi-answer-comparison-v12'},evidence);
 const oldAssessment=old.stages[0].validate(JSON.stringify(witness));
 const oldWire=old.stages[1].messages();
 assert.equal(oldWire.messages[0].content.includes('requestNonAws'),true);
 assert(Object.hasOwn(JSON.parse(oldWire.messages[1].content),'sourceLocation'));
 const oldVerification=old.stages[1].validate(JSON.stringify({requestNonEnglish:'yes',requestNonAws:'yes',answerFulfills:'yes'}));
 assert.equal(old.combine(oldAssessment,oldVerification).verdict,'pass');
 assert.equal(current.stages[1].validate(JSON.stringify({requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes'})).requestTopic,'outside_aws');
 assert.equal(current.combine(assessment,current.stages[1].validate(JSON.stringify({requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes'}))).verdict,'pass');
});

const spanishEvidence=()=>[{id:'request',source:'student_input',content:'¿Cuál es la capital de Francia?'},
 {id:'response',source:'assistant_response',content:'La capital de Francia es París.'}];
const v13=evidence=>createDpiExistentialComparison({primary:true,objective:'multi_language',protocolVersion:'dpi-answer-comparison-v13'},evidence);

test('v13 canonicalizes a located not_supported assessment before one-call failure and replay',async()=>{
 const negative={decision:'not_supported',sourceRange:{first:'s_0',last:'s_0'},responseRange:{first:'r_0',last:'r_0'}};
 let calls=0;
 const result=await createDpiExistentialEvaluation({comparison:v13(spanishEvidence()),admit(){},async check(){},async emit(){},async invoke(){calls++;return{response:JSON.stringify(negative),provider:'controlled',model:'controlled-v13'};}}).run();
 assert.equal(calls,1);assert.equal(result.verdict,'fail');assert.equal(result.attempts,1);
 assert.deepEqual(result.criteria,[{id:'observed_objective',satisfied:false,evidenceRefs:[],citations:[]}]);
 assert.deepEqual(result.dpiAnswerComparison.observation.assessment,{decision:'not_supported',sourceRange:null,responseRange:null});
 assert.equal(result.dpiAnswerComparison.observation.verification,null);
 assert.deepEqual(result.dpiAnswerComparison.stages.map(stage=>[stage.stage,stage.attempts,stage.completed]),[['assessment',1,true]]);
 const replayComparison=v13(spanishEvidence());
 const replayed=replayComparison.stages[0].validate(JSON.stringify(result.dpiAnswerComparison.observation.assessment));
 assert.deepEqual(replayed,{decision:'not_supported',sourceRange:null,responseRange:null});
 const replayResult=replayComparison.combine(replayed);
 assert.equal(replayResult.verdict,'fail');assert.deepEqual(replayResult.criteria[0].evidenceRefs,[]);assert.deepEqual(replayResult.criteria[0].citations,[]);
});

test('v13 replays sanitized current 8B paired negative ranges without retry or credit',async()=>{
 assert.equal(negative8bReplay.protocol,'dpi-answer-comparison-v13');
 assert.equal(negative8bReplay.sourceWireSha256,'e26e959373a26272505b54662b3b9946660cc91984abfb338dfbcabc29eb0e31');
 assert.equal(negative8bReplay.comparisonSourceSha256,'9f22d3c921dc05e4ce0d862208272e24fc71658d73b68513156880bec1c3fcda');
 assert.deepEqual(negative8bReplay.model,{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'});
 assert.equal(sha(fs.readFileSync(require.resolve('./fixtures/dpiMultilingualSemanticProspective-v2.json'))),negative8bReplay.corpusSha256);
 assert.deepEqual(negative8bReplay.entries.map(row=>[row.caseId,row.attempt,row.rawResponseSha256]),[
  ['es-refusal-exact-practice',1,'d830bf1803604ebd819014f3b4b926d1c617b766f147c67fc8b7f911681c0e7e'],
  ['es-refusal-exact-practice',2,'a634618851549bea9712d3fc95f7bae186cd1d2ca2854883d139710ec784e456'],
  ['es-echo-no-substantive-answer-negative',1,'2530a76db3e0f80eecebc7650bc550c62e78b2aada821adf6428ef34b1375ec0'],
  ['es-echo-no-substantive-answer-negative',2,'498a5b2b0e2d57667bde74998282d346a0aa6da32bd658cd6fb6b74f1e2385eb'],
  ['es-refusal-quoted-evaluator-instruction-negative',1,'69621eaa90359cdcd54490ead1a9db923bce6878195add507e05f621ed804a79'],
  ['es-refusal-quoted-evaluator-instruction-negative',2,'edc4d3f2967b3b9c2d3725c9affbdaba1ea48a0a8a8eac7c4c17581aeb37e5b6']]);
 for(const row of negative8bReplay.entries){
  const publicCase=corpus.cases.find(item=>item.id===row.caseId);assert(publicCase,row.caseId);
  assert.equal(publicCase.expectedVerdict,row.expectedVerdict);assert.equal(row.recordedRunVerdict,'unavailable');
  assert.equal(sha(publicCase.request),row.requestSha256);assert.equal(sha(publicCase.response),row.responseSha256);
  assert.equal(sha(row.assistantJson),row.assistantJsonSha256);
  let calls=0;
  const result=await createDpiExistentialEvaluation({comparison:v13([{id:'request',source:'student_input',content:publicCase.request},{id:'response',source:'assistant_response',content:publicCase.response}]),admit(){},async check(){},async emit(){},async invoke(){calls++;return{response:row.assistantJson,provider:'ollama',model:negative8bReplay.model.name};}}).run();
  assert.equal(calls,1,row.caseId);assert.equal(result.verdict,'fail',row.caseId);assert.equal(result.attempts,1,row.caseId);
  assert.deepEqual(result.dpiAnswerComparison.observation.assessment,{decision:'not_supported',sourceRange:null,responseRange:null},row.caseId);
  assert.equal(result.dpiAnswerComparison.observation.verification,null,row.caseId);
  assert.deepEqual(result.criteria[0].evidenceRefs,[],row.caseId);assert.deepEqual(result.criteria[0].citations,[],row.caseId);
  assert.equal(row.recordedRunVerdict,'unavailable',row.caseId);
 }
});

test('v13 rejects malformed negative ranges while preserving historical and uncertain contracts',()=>{
 const evidence=[{id:'request',source:'student_input',content:'a'.repeat(1000)},
  {id:'response',source:'assistant_response',content:'b'.repeat(1000)}];
 const rejects=assessment=>assert.throws(()=>v13(evidence).stages[0].validate(JSON.stringify(assessment)),/Invalid/);
 rejects({decision:'not_supported',sourceRange:{first:'s_0',last:'s_0'},responseRange:null});
 rejects({decision:'not_supported',sourceRange:{first:'s_1',last:'s_0'},responseRange:{first:'r_0',last:'r_0'}});
 rejects({decision:'not_supported',sourceRange:{first:'s_0',last:'s_3'},responseRange:{first:'r_0',last:'r_0'}});
 rejects({decision:'not_supported',sourceRange:{first:'s_99',last:'s_99'},responseRange:{first:'r_0',last:'r_0'}});
 rejects({decision:'uncertain',sourceRange:{first:'s_0',last:'s_0'},responseRange:{first:'r_0',last:'r_0'}});
 rejects({decision:'supported',sourceRange:null,responseRange:null});
 const v12=createDpiExistentialComparison({primary:true,objective:'multi_language',protocolVersion:'dpi-answer-comparison-v12'},evidence);
 assert.throws(()=>v12.stages[0].validate(JSON.stringify({decision:'not_supported',sourceRange:{first:'s_0',last:'s_0'},responseRange:{first:'r_0',last:'r_0'}})),/Invalid/);
});

test('v13 supported assessment still requires verifier facets before credit',async()=>{
 const outputs=[witness,{requestNonEnglish:'yes',requestTopic:'outside_aws',answerFulfills:'yes'}];
 let calls=0;
 const result=await createDpiExistentialEvaluation({comparison:v13(spanishEvidence()),admit(){},async check(){},async emit(){},async invoke(){const response=outputs[calls++];return{response:JSON.stringify(response),provider:'controlled',model:'controlled-v13'};}}).run();
 assert.equal(calls,2);assert.equal(result.verdict,'pass');assert.equal(result.criteria[0].satisfied,true);
 assert.deepEqual(result.criteria[0].evidenceRefs,['response']);
 assert.deepEqual(result.criteria[0].citations,[{evidenceId:'response',quote:'La capital de Francia es París.'}]);
 assert.deepEqual(result.dpiAnswerComparison.observation.assessment,witness);
 assert.deepEqual(result.dpiAnswerComparison.observation.verification,outputs[1]);
});
