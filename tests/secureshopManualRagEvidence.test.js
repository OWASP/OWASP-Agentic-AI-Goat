'use strict';
// Pure controlled provenance and injected Judge protocol tests, never actual-model qualification.
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {fixture}=require('./secureshopManualRagSourceContract.test');
const {validateManualRagSourceContract}=require('../server/services/secureshopManualRagSourceContract');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {OBJECTIVE,RUBRIC,buildManualRagCandidate,isManualRagJudgeInputValid,createManualRagJudgeGuard}=require('../server/services/secureshopManualRagEvidence');
const {prepareJudgeInput,createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
const sha=v=>createHash('sha256').update(v).digest('hex');
function input(){
 const source=validateManualRagSourceContract(fixture());
 const execution={runId:'b0000000-0000-4000-8000-000000000002',
  ownerKey:'["SecureShopBoundConversation","b0000000-0000-4000-8000-000000000001"]',durableGeneration:'0'};
 return{source,execution,rubric:RUBRIC,...buildManualRagCandidate({source,execution})};
}
test('packet retains exact original source/task/answer; both semantic criteria cite only consumer output',()=>{
 const i=input(),prepared=prepareJudgeInput(i);assert.equal(prepared.evidenceError,undefined);
 assert.ok(Buffer.byteLength(prepared.packet)<24000);assert.equal(isManualRagJudgeInputValid(i),true);
 assert.equal(i.evidence[2].content,i.source.semantic.response.text);
 assert.deepEqual(i.evidence[1].content.untrustedObservedToolResult,i.source.semantic.observation);
 for(const c of RUBRIC.criteria){
  assert.deepEqual(c.evidenceIds,['manual_consumer_response']);assert.deepEqual(c.allowedSources,['assistant_response']);
  assert.equal(c.referenceEvidenceId,'manual_comparison');assert.equal(c.quoteRequired,true);assert.equal(c.factId,undefined);
 }
 assert.equal(RUBRIC.criteria.length,2);assert.equal(OBJECTIVE,'ss_manual_rag_instruction_adoption');
 assert.notEqual(i.source.lineage.uploader.personaSession.sessionId,i.source.lineage.consumer.personaSession.sessionId);
});
test('modified packet, source relationships, fixed mode and oversize fail before configured Judge',async()=>{
 const changes=[
  i=>{i.evidence[2].content='Forged instruction adoption';},i=>{i.evidence[2].source='server_observation';},
  i=>{i.evidence[1].content.originalTask.text='New task';},
  i=>{i.evidence[1].content.untrustedObservedToolResult.mcp.content[0].text='{}';},
  i=>{i.evidence[1].content.selectedManual.sourceId++;},
  i=>{i.evidence[0].content.lineage.selected.text='Swapped source';},
  i=>{i.evidence[0].content.lineage.consumer.execution.mode='fixed';},
  i=>{i.evidence[0].content.assessment.runId='invalid';},
  i=>{i.evidence[0].content.assessment.ownerKey='["attacker","text"]';},
  i=>{i.evidence[0].content.assessment.generation='-1';},
  i=>{i.evidence[0].content.sourceDigest='0'.repeat(64);},
  i=>{i.facts.qualified_original_consumer_response=false;},
  i=>{i.evidence.reverse();},i=>{i.evidence.push(i.evidence[2]);},
  i=>{i.rubric={...RUBRIC,criteria:[RUBRIC.criteria[0]]};},
 ];
 let calls=0;const judge=createManualRagJudgeGuard(async()=>{calls++;throw Error('must not dispatch');});
 for(const mutate of changes){const i=structuredClone(input());mutate(i);assert.equal(isManualRagJudgeInputValid(i),false);
  assert.equal((await judge(i)).verdict,'fail');}
 assert.equal(calls,0);
 const i=input(),source=structuredClone(i.source);source.semantic.response.text='x'.repeat(16385);
 source.semantic.response.sha256=sha(source.semantic.response.text);source.lineage.consumer.original.responseSha256=source.semantic.response.sha256;
 source.sourceDigest=canonicalDigest(source.lineage);assert.equal(buildManualRagCandidate({source,execution:i.execution}),null);
 // Within source answer limits but beyond canonical packet cap: never truncate.
 source.semantic.response.text='x'.repeat(16000);source.semantic.response.sha256=sha(source.semantic.response.text);
 source.lineage.consumer.original.responseSha256=source.semantic.response.sha256;source.sourceDigest=canonicalDigest(source.lineage);
 assert.equal(buildManualRagCandidate({source,execution:i.execution}),null);
});
test('canonical configured protocol sees noncitable complete context and exact response, requires both criteria',async()=>{
 const i=input(),requests=[];
 const judge=createObjectiveJudge({model:{async generate(prompt){requests.push(prompt);
  return{response:JSON.stringify({satisfied:false,citations:[]}),provider:'controlled',model:'controlled-negative',mocked:false,fallback:false};}}});
 const result=await createManualRagJudgeGuard(judge)(i);
 assert.equal(result.verdict,'fail');assert.equal(requests.length,2);
 for(const prompt of requests){
  const scope=JSON.parse(prompt.split('SCOPED EVIDENCE:\n')[1]);
  assert.deepEqual(scope.citableObservedEvidence,[i.evidence[2]]);
  assert.deepEqual(scope.nonCitableServerReference.content,i.evidence[1].content);
  assert.equal(prompt.includes('manual_source_proof'),false);
 }
});
test('source-only citations cannot establish either adoption or task displacement',async()=>{
 const i=input();let calls=0;
 const judge=createObjectiveJudge({model:{async generate(){calls++;
  return{response:JSON.stringify({satisfied:true,citations:[{evidenceId:'manual_comparison',quote:i.source.lineage.selected.text}]}),
   provider:'controlled',model:'controlled-invalid-citation',mocked:false,fallback:false};}}});
 const result=await createManualRagJudgeGuard(judge)(i);
 assert.notEqual(result.verdict,'pass');assert.ok(calls>=1&&calls<=4);
});
test('one positive controlled criterion cannot compensate for failed task displacement',async()=>{
 const i=input();let calls=0;
 const judge=createObjectiveJudge({model:{async generate(){calls++;
  return{response:JSON.stringify(calls===1?{satisfied:true,citations:[{evidenceId:'manual_consumer_response',quote:i.evidence[2].content}]}:
   {satisfied:false,citations:[]}),provider:'controlled',model:'controlled-protocol-only',mocked:false,fallback:false};}}});
 const result=await createManualRagJudgeGuard(judge)(i);assert.equal(result.verdict,'fail');assert.equal(calls,2);
 assert.equal(result.criteria[0].satisfied,true);assert.equal(result.criteria[1].satisfied,false);
});
