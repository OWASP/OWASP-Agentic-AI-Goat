'use strict';
// Four fixed manual-rubric Judge calibrations. No actor, database, credit, or source copy.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {transport,reconstruct,MODEL,DIGEST,admitJudgeIdentity,assertMetadataIdentity}=require('./pricingDirectiveGroupsActualJudge');
const sha=value=>createHash('sha256').update(value).digest('hex');
const CASES_SHA='85b1efe71f4bcfd7862fc0c638452f5fe8a5e7c3e36e7c68b9fe4ac62ee7ca24';
function declarations(root){
 const bytes=fs.readFileSync(path.join(root,'tests/fixtures/pricingManualSemanticCalibrationCases.json'));
 assert.equal(sha(bytes),CASES_SHA);const set=JSON.parse(bytes);
 assert.equal(set.version,1);assert.equal(set.cases.length,4);assert.equal(new Set(set.cases.map(item=>item.id)).size,4);
 assert.deepEqual(set.cases.map(item=>item.expectedVerdict),['fail','pass','fail','fail']);
 return set;
}
function packet(rubric,item,question){return {rubric,facts:Object.fromEntries(rubric.requiredFacts.map(id=>[id,true])),evidence:[
 {id:'pricing_manual_source',source:'tool_result',content:item.source},
 {id:'pricing_final_answer',source:'assistant_response',content:item.response},
 {id:'pricing_learner_question',source:'student_input',content:question}
]};}
async function main({judgeIdentity,contract='v4'}={}){
 assert(['v4','v5','v6'].includes(contract),'Unknown Pricing calibration contract');
 const identity=admitJudgeIdentity(judgeIdentity);
 assert.equal(process.env.PRICING_MANUAL_CALIBRATION_ACTUAL_JUDGE,'1');const output=process.env.PRICING_MANUAL_CALIBRATION_RESULT;assert(path.isAbsolute(output));
 const declared=declarations(process.cwd());
 const perCase=contract==='v6'?4:6;
 const state={version:1,contract,status:'running',scope:'Judge-only four fixed manual semantic inputs; no actor/database/credit proof.',model:{name:identity.model,digest:identity.digest},bounds:{allHttp:perCase*4+1,judgeCalls:perCase*4,perCase,perHttpSeconds:60,overallSeconds:720},cases:[],calls:[]};
 const save=()=>{const temp=output+'.tmp',fd=fs.openSync(temp,'w',0o600);try{fs.writeFileSync(fd,JSON.stringify(state,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,output);};
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('Owned Pricing manual Judge deadline')),720000),originalFetch=global.fetch;
 const wire=transport({fetch:originalFetch,signal:controller.signal,profile:contract==='v6'?'manual16':'manual24',judgeIdentity,record:()=>{state.calls=wire.calls;save();}});global.fetch=wire.fetch;save();
 try{
  const admitted=await fetch('http://127.0.0.1:11434/api/tags');assert.equal(admitted.status,200);const tags=await admitted.json();assertMetadataIdentity(tags,judgeIdentity);
  const {PRICING_RUBRICS}=require('../../server/services/secureshopPricingAssessment');const current=PRICING_RUBRICS.ss_pricing_manual_injection,rubric={...current,version:'secureshop-pricing-manual-v7',sourceComparison:{...current.sourceComparison,supportContract:'pricing-semantic-decomposition-v4'},mode:'vuln'};
  assert.equal(rubric.version,'secureshop-pricing-manual-v7');assert.equal(rubric.sourceComparison.supportContract,'pricing-semantic-decomposition-v4');
  if(contract==='v5'){rubric.version='secureshop-pricing-manual-v8';rubric.sourceComparison={...rubric.sourceComparison,supportContract:'pricing-semantic-decomposition-v5'};}
  if(contract==='v6'){rubric.version='secureshop-pricing-manual-v9';rubric.sourceComparison={...rubric.sourceComparison,supportContract:'pricing-semantic-decomposition-v6'};}
  const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',baseURL:'http://127.0.0.1:11434',model:identity.model});
  for(const item of declared.cases){
   controller.signal.throwIfAborted();wire.beginCase(item.id);const row={id:item.id,expectedVerdict:item.expectedVerdict,inputSha256:sha(JSON.stringify([item.source,item.response,declared.learnerQuestion])),assumedFacts:true,result:null,transcript:null};state.cases.push(row);save();
   const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model,timeoutMs:120000,observeExecutionTranscript:value=>{row.transcript=value;save();}});
   row.result=await judge({...packet(rubric,item,declared.learnerQuestion),execution:{signal:controller.signal}});save();
   const sent=wire.calls.filter(call=>call.caseId===item.id);assert.equal(row.transcript?.complete,true);assert.equal(row.transcript.header.maximumCalls,perCase);assert.equal(sent.length,row.transcript.calls.length);assert(sent.length<=perCase);
   for(let i=0;i<sent.length;i++){const request=JSON.parse(sent[i].request),trace=row.transcript.calls[i];assert.deepEqual(request.messages.map(message=>({role:message.role,content:message.content})),trace.request.input);assert.deepEqual(request.format,trace.request.schema);assert.equal(sent[i].status,'returned');assert.equal(sent[i].httpStatus,200);assert.equal(reconstruct(sent[i].response,judgeIdentity),trace.response);assert.equal(trace.responseSha256,sha(trace.response));assert.equal(trace.metadata.provider,'ollama');assert.equal(trace.metadata.model,identity.model);}
   row.technicalComplete=true;row.semanticMatch=row.result.verdict===item.expectedVerdict;wire.endCase();save();
  }
  state.technicalComplete=state.cases.length===4&&state.cases.every(item=>item.technicalComplete);state.semanticAccepted=state.technicalComplete&&state.cases.every(item=>item.semanticMatch);assert(state.calls.filter(call=>call.kind==='inference').length<=perCase*4);state.status=state.semanticAccepted?'semantic-accepted-controlled-inputs':'semantic-mismatch';if(!state.semanticAccepted)process.exitCode=1;
 }catch(error){state.status='incomplete';state.errorCode=typeof error.code==='string'?error.code:'DIAGNOSTIC_INCOMPLETE';process.exitCode=1;}
 finally{clearTimeout(timer);controller.abort();wire.close();global.fetch=originalFetch;save();}
}
module.exports={declarations,packet,main,MODEL,DIGEST};
if(require.main===module)main().catch(()=>{console.error('Pricing manual Judge calibration unavailable');process.exitCode=1;});
