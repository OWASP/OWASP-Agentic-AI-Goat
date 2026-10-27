'use strict';
// Judge-only semantic calibration on five fixed answers and one recorded generated tool result.
// No actor, PostgreSQL, completion service, or objective-credit write is present.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {transport,reconstruct,MODEL,DIGEST}=require('./pricingDirectiveGroupsActualJudge');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const CASES_SHA='74ff860ce5c0edfa6f47fe6af5c161f5bdbeae64110b2d8e86885ceef6d41f1b';
const OBSERVED_SHA='827012d4dbb7f4a908018859fcde7acdeb3025dfcaa0c389bbd1c44e24c75cce';
const ACTUAL_SHA='0aa4d0a1e220b438cfab72493be57b074576b5de24f37fb105f51f29fe5fdc91';
function declarations(root){
 const read=(name,expected)=>{const bytes=fs.readFileSync(path.join(root,'tests/fixtures',name));assert.equal(sha(bytes),expected);return JSON.parse(bytes);};
 const set=read('pricingGroundingSemanticCases.json',CASES_SHA),observed=read('pricingGroundingObservedSource.json',OBSERVED_SHA);
 assert.equal(observed.actualArtifactSha256,ACTUAL_SHA);assert.equal(observed.toolResult.grounded,false);
 assert.equal(observed.recordedAnswer,set.recordedBadAward.response);
 const cases=[{id:'recordedBadAward',...set.recordedBadAward},...set.cases];
 assert.equal(cases.length,5);assert.equal(new Set(cases.map(item=>item.id)).size,5);
 assert.deepEqual(cases.map(item=>item.expectedVerdict),['fail','pass','fail','fail','fail']);
 return {cases,observed};
}
function packet(rubric,observation,answer){return {rubric,facts:Object.fromEntries(rubric.requiredFacts.map(id=>[id,true])),evidence:[
 {id:'pricing_source',source:'tool_result',content:observation},
 {id:'pricing_final_answer',source:'assistant_response',content:answer},
]};}
async function main(){
 assert.equal(process.env.PRICING_GROUNDING_ACTUAL_JUDGE,'1');
 const output=process.env.PRICING_GROUNDING_RESULT;assert(path.isAbsolute(output));
 const declared=declarations(process.cwd());
 const state={version:1,status:'running',scope:'Judge-only five fixed responses against a saved generated observation; assumed prerequisite facts, no actor/database/credit proof.',model:{name:MODEL,digest:DIGEST},bounds:{allHttp:11,judgeCalls:10,perCase:2,perHttpSeconds:60,overallSeconds:480},actualArtifactSha256:ACTUAL_SHA,cases:[],calls:[]};
 const save=()=>{const temp=output+'.tmp',fd=fs.openSync(temp,'w',0o600);try{fs.writeFileSync(fd,JSON.stringify(state,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,output);};
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('Owned Pricing Judge deadline')),480000),originalFetch=global.fetch;
 const wire=transport({fetch:originalFetch,signal:controller.signal,profile:'grounding10',record:()=>{state.calls=wire.calls;save();}});global.fetch=wire.fetch;save();
 try{
  const admitted=await fetch('http://127.0.0.1:11434/api/tags');assert.equal(admitted.status,200);
  const tags=await admitted.json();assert.equal(tags.models.find(item=>item.name===MODEL)?.digest,DIGEST);
  const {LEGACY_PRICING_RUBRICS}=require('../../server/services/secureshopPricingAssessment');
  const rubric={...LEGACY_PRICING_RUBRICS.ss_pricing_false_grounding,mode:'vuln'};
  assert.equal(rubric.version,'secureshop-pricing-grounding-v2');
  assert.equal(rubric.sourceComparison.supportContract,'pricing-grounding-comparison-v1');
  const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',baseURL:'http://127.0.0.1:11434',model:MODEL});
  for(const item of declared.cases){
   controller.signal.throwIfAborted();wire.beginCase(item.id);
   const row={id:item.id,expected:item.expectedVerdict,answerSha256:sha(item.response),assumedFacts:true,result:null,transcript:null};state.cases.push(row);save();
   const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model,timeoutMs:120000,observeExecutionTranscript:value=>{row.transcript=value;save();}});
   row.result=await judge({...packet(rubric,declared.observed.toolResult,item.response),execution:{signal:controller.signal}});save();
   const sent=wire.calls.filter(call=>call.caseId===item.id);
   assert.equal(row.transcript?.complete,true);assert.equal(row.transcript.header.maximumCalls,2);
   assert.equal(sent.length,row.transcript.calls.length);assert(sent.length<=2);
   for(let i=0;i<sent.length;i++){
    const request=JSON.parse(sent[i].request),trace=row.transcript.calls[i];
    assert.deepEqual(request.messages.map(message=>({role:message.role,content:message.content})),trace.request.input);
    assert.deepEqual(request.format,trace.request.schema);
    assert.equal(sent[i].status,'returned');assert.equal(sent[i].httpStatus,200);
    assert.equal(reconstruct(sent[i].response),trace.response);
    assert.equal(trace.responseSha256,sha(trace.response));
    assert.equal(trace.metadata.provider,'ollama');assert.equal(trace.metadata.model,MODEL);
   }
   row.technicalComplete=true;row.semanticMatch=row.result.verdict===item.expectedVerdict;
   wire.endCase();save();
  }
  state.technicalComplete=state.cases.length===5&&state.cases.every(item=>item.technicalComplete);
  state.semanticAccepted=state.technicalComplete&&state.cases.every(item=>item.semanticMatch);
  state.status=state.semanticAccepted?'semantic-accepted-controlled-inputs':'semantic-mismatch';
  if(!state.semanticAccepted)process.exitCode=1;
 }catch(error){state.status='incomplete';state.errorCode=typeof error.code==='string'?error.code:'DIAGNOSTIC_INCOMPLETE';process.exitCode=1;}
 finally{clearTimeout(timer);controller.abort();wire.close();global.fetch=originalFetch;save();}
}
module.exports={declarations,packet,MODEL,DIGEST};
if(require.main===module)main().catch(()=>{console.error('Pricing grounding Judge diagnostic unavailable');process.exitCode=1;});
