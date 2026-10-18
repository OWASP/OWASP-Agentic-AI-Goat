'use strict';
// Exact two-case Judge-only qualification for the current Pricing v9/v6 contract.
// It never dispatches an actor, opens a database, or invokes completion/credit code.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {packet}=require('./pricingManualActualJudgeCalibration');
const {transport,reconstruct,MODEL,DIGEST,assertMetadataIdentity}=require('./pricingDirectiveGroupsActualJudge');
const CASES_SHA='39365b1f8bd994d83beebb3cbb90858ee03cb40cceafef9dc92fe82eff17a574';
const MODEL_SHA='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const STAGES=Object.freeze(['source','effect','relation','support']);
const sha=value=>createHash('sha256').update(value).digest('hex');

function declarations(root){
 const bytes=fs.readFileSync(path.join(root,'tests/fixtures/pricingManualH4V6CalibrationCases.json'));
 assert.equal(sha(bytes),CASES_SHA);const value=JSON.parse(bytes);
 assert.equal(value.version,1);assert.equal(value.cases.length,2);assert.equal(new Set(value.cases.map(item=>item.id)).size,2);
 assert.deepEqual(value.cases.map(item=>item.expectedVerdict),['fail','pass']);
 assert.equal(sha(value.learnerQuestion),'c607f1225f0e00f10e018066197bdc61eade71cdcdd4e6b91b678dc052737ffa');
 assert.equal(sha(value.cases[0].source),'ac505b78d05a2e2e2a34d3179f86a332bc1414f0733d28c82201f8dcae4c0fbe');
 assert.equal(value.cases[1].source,value.cases[0].source);
 assert.equal(sha(value.cases[0].response),'380494f9fd7827505e55921de1943059d2e916814e31b495c5f4f7e96d919db8');
 assert.equal(sha(value.cases[1].response),'51314c7bf5cb9f422ef4e290ab71439f81045e5b0dd57600dc6df6f4a78e2b41');
 return value;
}
function hardBound(fetchImpl,maximum=9){
 assert.equal(typeof fetchImpl,'function');assert.equal(maximum,9);let count=0;
 const fetch=async(url,options={})=>{const target=new URL(typeof url==='string'?url:url.url||String(url));if(target.pathname==='/api/chat'){assert.equal(typeof options.body,'string');const request=JSON.parse(options.body);assert.equal(request.model,MODEL);assert.equal(request.stream,true);assert.equal(request.options?.temperature,0);assert.equal(request.options?.num_ctx,32768);assert.equal(request.options?.num_predict,4096);assert(request.format&&typeof request.format==='object');}if(count>=maximum){const error=Error('Pricing H4 HTTP budget exhausted');error.code='HTTP_BUDGET_EXHAUSTED';throw error;}count++;return fetchImpl(url,options);};
 return Object.freeze({fetch,get count(){return count;}});
}
function persisted(result){return require('../../server/database/postgres/objectiveJudgmentRepository').resultValue(result,{family:result.family,scenario:result.scenario,objective_id:result.objectiveId,rubric_version:result.rubricVersion,evidence_digest:result.evidenceDigest,run_id:result.runId,mode:result.mode});}

async function main(options={}){
 assert.deepEqual(Object.keys(options),[],'Pricing H4 calibration accepts no runtime options');
 assert.equal(process.env.PRICING_MANUAL_H4_V6_ACTUAL_JUDGE,'1');
 const output=process.env.PRICING_MANUAL_H4_V6_RESULT;assert(path.isAbsolute(output));
 assert.equal(MODEL,'llama3.1:8b');assert.equal(DIGEST,MODEL_SHA);
 const declared=declarations(process.cwd());
 const {PRICING_RUBRICS}=require('../../server/services/secureshopPricingAssessment');
 const rubric={...PRICING_RUBRICS.ss_pricing_manual_injection,mode:'vuln'};
 assert.equal(rubric.version,'secureshop-pricing-manual-v9');assert.equal(rubric.sourceComparison.supportContract,'pricing-semantic-decomposition-v6');
 const state={version:1,status:'running',scope:'Judge-only exact retained H4 negative and semantic counterfactual under current Pricing v9/v6; no actor, database, completion, credit, or curriculum proof.',declarationSha256:CASES_SHA,model:{name:MODEL,digest:DIGEST},bounds:{allHttp:9,metadataCalls:1,judgeCalls:8,perCase:4,perStage:1,perHttpSeconds:60,overallSeconds:360,contextTokens:32768},actorCalls:0,databaseConnections:0,creditAuthorized:false,technicalComplete:false,semanticAccepted:false,cases:[],calls:[]};
 const save=()=>{const temp=output+'.tmp',fd=fs.openSync(temp,'w',0o600);try{fs.writeFileSync(fd,JSON.stringify(state,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,output);const directory=fs.openSync(path.dirname(output),'r');try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}};
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('Owned Pricing H4 Judge deadline')),360000),originalFetch=global.fetch,bound=hardBound(originalFetch);
 const wire=transport({fetch:bound.fetch,signal:controller.signal,profile:'manual16',record:()=>{state.calls=wire.calls;save();}});global.fetch=wire.fetch;save();
 try{
  const admitted=await fetch('http://127.0.0.1:11434/api/tags');assert.equal(admitted.status,200);assertMetadataIdentity(await admitted.json());
  const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',baseURL:'http://127.0.0.1:11434',model:MODEL});
  for(const item of declared.cases){
   controller.signal.throwIfAborted();wire.beginCase(item.id);
   const controlledInputs={source:item.source,response:item.response,question:declared.learnerQuestion},judgePacket=packet(rubric,item,declared.learnerQuestion);
   assert.equal(Object.hasOwn(judgePacket,'expectedVerdict'),false);assert.equal(judgePacket.evidence.some(entry=>Object.hasOwn(entry,'expectedVerdict')),false);
   const row={id:item.id,expectedVerdict:item.expectedVerdict,controlledInputs,inputSha256:sha(JSON.stringify([item.source,item.response,declared.learnerQuestion])),result:null,persistedShape:null,transcript:null,technicalComplete:false};state.cases.push(row);save();
   const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model,contextTokens:32768,timeoutMs:120000,observeExecutionTranscript:value=>{row.transcript=value;save();}});
   row.result=await judge({...judgePacket,execution:{signal:controller.signal}});save();
   const sent=wire.calls.filter(call=>call.caseId===item.id);
   assert.equal(row.result.rubricVersion,'secureshop-pricing-manual-v9');assert.equal(row.result.comparisonVersion,'pricing-semantic-decomposition-v6');assert.equal(row.result.attempts,4);
   assert.deepEqual(row.result.comparisonStages.map(stage=>stage.stage),STAGES);assert(row.result.comparisonStages.every(stage=>stage.completed===true&&stage.attempts===1));
   assert.equal(row.transcript?.complete,true);assert.equal(row.transcript.header.maximumCalls,4);assert.equal(row.transcript.calls.length,4);assert.equal(sent.length,4);
   for(let index=0;index<4;index++){
    const request=JSON.parse(sent[index].request),trace=row.transcript.calls[index];
    assert.deepEqual(request.messages.map(message=>({role:message.role,content:message.content})),trace.request.input);assert.deepEqual(request.format,trace.request.schema);
    assert.equal(request.model,MODEL);assert.equal(request.options.temperature,0);assert.equal(request.options.num_ctx,32768);assert.equal(request.options.num_predict,4096);
    assert.equal(sent[index].status,'returned');assert.equal(sent[index].httpStatus,200);assert.equal(reconstruct(sent[index].response),trace.response);assert.equal(trace.responseSha256,sha(trace.response));assert.equal(trace.validatedTextSha256,trace.responseSha256);assert.equal(trace.metadata.provider,'ollama');assert.equal(trace.metadata.model,MODEL);
   }
   row.persistedShape=persisted(row.result);row.technicalComplete=true;row.semanticMatch=row.result.verdict===item.expectedVerdict;wire.endCase();save();
  }
  assert.equal(bound.count,9);assert.equal(wire.calls.filter(call=>call.kind==='metadata').length,1);assert.equal(wire.calls.filter(call=>call.kind==='inference').length,8);
  state.technicalComplete=state.cases.length===2&&state.cases.every(item=>item.technicalComplete);state.semanticAccepted=state.technicalComplete&&state.cases.every(item=>item.semanticMatch);state.status=state.semanticAccepted?'semantic-accepted-controlled-inputs':'semantic-mismatch';if(!state.semanticAccepted)process.exitCode=1;
 }catch(error){state.status='incomplete';state.errorCode=typeof error.code==='string'?error.code:'DIAGNOSTIC_INCOMPLETE';process.exitCode=1;}
 finally{clearTimeout(timer);controller.abort();wire.close();global.fetch=originalFetch;save();}
}
module.exports={declarations,hardBound,main,CASES_SHA,MODEL,DIGEST};
if(require.main===module)main().catch(error=>{console.error(JSON.stringify({error:error.name,code:error.code||null}));process.exitCode=1;});
