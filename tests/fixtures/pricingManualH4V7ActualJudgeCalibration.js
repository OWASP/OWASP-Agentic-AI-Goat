'use strict';
// Bounded actual-model calibration of the unmounted Pricing v7 factory.
// No ObjectiveJudge dispatch, database, completion, actor, or credit path is used.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {declarations,hardBound,MODEL,DIGEST,CASES_SHA}=require('./pricingManualH4V6ActualJudgeCalibration');
const {transport,reconstruct,assertMetadataIdentity}=require('./pricingDirectiveGroupsActualJudge');
const {createPricingSemanticDecompositionComparison:factory,VERSION}=require('../../server/agent-runtime/pricingSemanticDecompositionV7Verifier');
const STAGES=Object.freeze(['source','effect','relation','support']);
const sha=value=>createHash('sha256').update(value).digest('hex');

function candidate(item,question){
 const current=require('../../server/services/secureshopPricingAssessment').PRICING_RUBRICS.ss_pricing_manual_injection;
 assert.equal(current.version,'secureshop-pricing-manual-v9');assert.equal(current.sourceComparison.supportContract,'pricing-semantic-decomposition-v6');
 const spec={...current.sourceComparison,supportContract:VERSION};
 const evidence=[{id:'pricing_manual_source',source:'tool_result',content:item.source},{id:'pricing_final_answer',source:'assistant_response',content:item.response},{id:'pricing_learner_question',source:'student_input',content:question}];
 return{spec,evidence,comparison:factory(spec,evidence)};
}
function early(stage,value){const error=Error('Pricing v7 candidate returned before all four stages');error.code='CANDIDATE_EARLY_TERMINAL';error.stage=stage;error.value=value;return error;}

async function main(options={}){
 assert.deepEqual(Object.keys(options),[],'Pricing H4 v7 calibration accepts no runtime options');
 assert.equal(process.env.PRICING_MANUAL_H4_V7_ACTUAL_JUDGE,'1');const output=process.env.PRICING_MANUAL_H4_V7_RESULT;assert(path.isAbsolute(output));
 assert.equal(MODEL,'llama3.1:8b');assert.equal(DIGEST,'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
 const declared=declarations(process.cwd());assert.equal(declared.cases.length,2);
 const state={version:1,status:'running',scope:'Direct unmounted Pricing v7 factory calibration on exact retained H4 negative and semantic counterfactual; no ObjectiveJudge mount, actor, database, completion, credit, or curriculum proof.',contract:VERSION,declarationSha256:CASES_SHA,model:{name:MODEL,digest:DIGEST},bounds:{allHttp:9,metadataCalls:1,judgeCalls:8,perCase:4,perStage:1,perHttpSeconds:60,overallSeconds:360,contextTokens:32768,maxOutput:4096},actorCalls:0,databaseConnections:0,creditAuthorized:false,objectiveJudgeMounted:false,technicalComplete:false,semanticAccepted:false,cases:[],calls:[]};
 const save=()=>{const temp=output+'.tmp',fd=fs.openSync(temp,'w',0o600);try{fs.writeFileSync(fd,JSON.stringify(state,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,output);const directory=fs.openSync(path.dirname(output),'r');try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}};
 const started=Date.now(),controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('Owned Pricing H4 v7 deadline')),360000),originalFetch=global.fetch,bound=hardBound(originalFetch);
 const wire=transport({fetch:bound.fetch,signal:controller.signal,profile:'manual16',record:()=>{state.calls=wire.calls;save();}});global.fetch=wire.fetch;save();
 try{
  const admitted=await fetch('http://127.0.0.1:11434/api/tags');assert.equal(admitted.status,200);assertMetadataIdentity(await admitted.json());
  const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',baseURL:'http://127.0.0.1:11434',model:MODEL});
  for(const item of declared.cases){
   controller.signal.throwIfAborted();wire.beginCase(item.id);const built=candidate(item,declared.learnerQuestion),comparison=built.comparison;
   const row={id:item.id,expectedVerdict:item.expectedVerdict,inputSha256:sha(JSON.stringify([item.source,item.response,declared.learnerQuestion])),controlledInputs:{source:item.source,response:item.response,question:declared.learnerQuestion},policy:comparison.policy,result:null,stages:[],technicalComplete:false};state.cases.push(row);save();
   const invoke=async(stage,prepared,validate)=>{
    assert.equal(row.stages.length,STAGES.indexOf(stage));controller.signal.throwIfAborted();const before=wire.calls.length;
    const response=await model.chat(prepared.messages,[],{temperature:0,format:prepared.format,max_tokens:prepared.maxOutput,num_predict:prepared.maxOutput,num_ctx:32768,signal:controller.signal,timeout:Math.max(1,Math.min(60000,360000-(Date.now()-started)))});
    const sent=wire.calls.slice(before);assert.equal(sent.length,1);const call=sent[0];assert.equal(call.caseId,item.id);assert.equal(call.status,'returned');assert.equal(call.httpStatus,200);assert.equal(response.provider,'ollama');assert.equal(response.model,MODEL);assert.equal(response.mocked===true||response.fallback===true,false);assert.equal(reconstruct(call.response),response.response);assert.equal(sha(call.response),call.responseSha256);
    const stageRecord={stage,request:JSON.parse(call.request),requestSha256:call.requestSha256,rawWire:call.response,rawWireSha256:call.responseSha256,validatedText:response.response,validatedTextSha256:sha(response.response),provider:response.provider,model:response.model,disposition:'pending'};row.stages.push(stageRecord);save();
    try{const value=validate(response.response);stageRecord.disposition='accepted';save();return value;}catch(error){stageRecord.disposition='rejected';stageRecord.validationErrorCode=typeof error.code==='string'?error.code:'INVALID_STAGE_OUTPUT';save();throw error;}
   };
   let value=await invoke('source',comparison.sourceMessages(),text=>comparison.validateSource(text));
   value=await invoke('effect',comparison.effectMessages(value),text=>comparison.validateEffect(text,value));if(!comparison.needsRelation(value)){row.result=value;save();throw early('effect',value);}
   value=await invoke('relation',comparison.relationMessages(value),text=>comparison.validateRelation(text,value));if(!comparison.needsSupport(value)){row.result=value;save();throw early('relation',value);}
   value=await invoke('support',comparison.supportMessages(value),text=>comparison.validateSupport(text,value));row.result=value;
   assert.equal(row.stages.length,4);assert.deepEqual(row.stages.map(stage=>stage.stage),STAGES);assert.equal(value.verdict,item.expectedVerdict);row.criteria=comparison.projectCriteria([{id:'redirected_output'}],value);row.technicalComplete=true;wire.endCase();save();
  }
  assert.equal(bound.count,9);assert.equal(wire.calls.filter(call=>call.kind==='metadata').length,1);assert.equal(wire.calls.filter(call=>call.kind==='inference').length,8);
  state.technicalComplete=state.cases.length===2&&state.cases.every(item=>item.technicalComplete);state.semanticAccepted=state.technicalComplete;state.status='semantic-accepted-controlled-inputs';
 }catch(error){state.status='incomplete';state.errorCode=typeof error.code==='string'?error.code:'DIAGNOSTIC_INCOMPLETE';state.failureStage=error.stage||null;process.exitCode=1;}
 finally{clearTimeout(timer);controller.abort();wire.close();global.fetch=originalFetch;save();}
}
module.exports={candidate,main,MODEL,DIGEST,VERSION};
if(require.main===module)main().catch(error=>{console.error(JSON.stringify({error:error.name,code:error.code||null}));process.exitCode=1;});
