'use strict';
// Diagnostic only: paired supplied evidence, never actor execution or credit.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const base=require('../../server/agent-runtime/dpiTaskContributionComparison');
const candidate=require('../../server/agent-runtime/dpiTaskContributionSpanCandidate');
const compact=require('../../server/agent-runtime/dpiSemanticCompactCandidate');
const policyContract=require('../../server/agent-runtime/dpiPolicyContract');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const MODEL='llama3.1:8b',PROTOCOLS=['base-v11','span-candidate-v2'];
const COMPACT_PROFILE='semantic-compact-v1',SCHEMA_VISIBLE_PROFILE='semantic-schema-visible-v1',DIRECT_PROFILE='semantic-direct-witness-v1',SERVER_IDS_PROFILE='semantic-server-ids-v1',SERVER_IDS_SMOKE='semantic-server-ids-smoke-v1',SERVER_IDS_SIDE='semantic-server-ids-side-v1',TECHNIQUES_SELECTED_V6_PROFILE='semantic-techniques-selected-v6';
const WHOLE_INTENT_PROFILE='semantic-whole-intent-v1';
const SOURCE_FIRST_SIDE='semantic-source-first-side-v1';
const SELECTED_V6_PROFILE='semantic-selected-v6';
const TECHNIQUES_SELECTED_REMAINING2_PROFILE='semantic-techniques-selected-v6-remaining2';
const SOURCE_LINK_V7_PROFILE='semantic-side-source-link-v7';
const CONJUNCTION_V8_PROFILE='semantic-side-conjunction-v8-remaining1';
const COMPACT_CONJUNCTION_V9_8B_PROFILE='semantic-side-compact-conjunction-v24-8b';
const SOURCE_TECHNIQUE_V11_PROFILE='semantic-selected-source-technique-v11';
const ROLE_TECHNIQUE_V12_PROFILE='semantic-selected-role-technique-v12';
const OBJECTIVE_TECHNIQUE_V13_8B_PROFILE='semantic-selected-objective-technique-v13-8b';
const RESPONSE_CONSISTENCY_V14_8B_PROFILE='semantic-selected-response-consistency-v14-8b';
const RESPONSE_REGRESSION_V14_8B_PROFILE='semantic-selected-response-regression-v14-8b';
const SIMPLE_ASSESSMENT_V1_8B_PROFILE='semantic-simple-assessment-v1-8b';
const SOURCE_RESPONSE_ASSESSMENT_V1_8B_PROFILE='semantic-source-response-assessment-v1-8b';
const SOURCE_RESPONSE_ASSESSMENT_V2_8B_PROFILE='semantic-source-response-assessment-v2-8b';
const isSourceTechniqueProfile=profile=>[SOURCE_TECHNIQUE_V11_PROFILE,ROLE_TECHNIQUE_V12_PROFILE,OBJECTIVE_TECHNIQUE_V13_8B_PROFILE,RESPONSE_CONSISTENCY_V14_8B_PROFILE,RESPONSE_REGRESSION_V14_8B_PROFILE,SIMPLE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V2_8B_PROFILE].includes(profile);
const isServerIds=profile=>[SERVER_IDS_PROFILE,SERVER_IDS_SMOKE,SERVER_IDS_SIDE,TECHNIQUES_SELECTED_V6_PROFILE,SOURCE_FIRST_SIDE,WHOLE_INTENT_PROFILE,SELECTED_V6_PROFILE,TECHNIQUES_SELECTED_REMAINING2_PROFILE,SOURCE_LINK_V7_PROFILE,CONJUNCTION_V8_PROFILE].includes(profile);
function profileFor(profile='span'){
 assert(['span',COMPACT_PROFILE,SCHEMA_VISIBLE_PROFILE,DIRECT_PROFILE,SERVER_IDS_PROFILE,SERVER_IDS_SMOKE,SERVER_IDS_SIDE,TECHNIQUES_SELECTED_V6_PROFILE,SOURCE_FIRST_SIDE,WHOLE_INTENT_PROFILE,SELECTED_V6_PROFILE,TECHNIQUES_SELECTED_REMAINING2_PROFILE,SOURCE_LINK_V7_PROFILE,CONJUNCTION_V8_PROFILE,COMPACT_CONJUNCTION_V9_8B_PROFILE,SOURCE_TECHNIQUE_V11_PROFILE,ROLE_TECHNIQUE_V12_PROFILE,OBJECTIVE_TECHNIQUE_V13_8B_PROFILE,RESPONSE_CONSISTENCY_V14_8B_PROFILE,RESPONSE_REGRESSION_V14_8B_PROFILE,SIMPLE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V2_8B_PROFILE].includes(profile));
 if(profile===SOURCE_TECHNIQUE_V11_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSelectedSourceTechniqueCandidate').VERSION],cases:4,calls:4,contextTokens:20480};
 if(profile===ROLE_TECHNIQUE_V12_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSelectedRoleTechniqueCandidate').VERSION],cases:4,calls:4,contextTokens:20480};
 if(profile===OBJECTIVE_TECHNIQUE_V13_8B_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSelectedObjectiveTechniqueCandidate').VERSION],cases:4,calls:4,contextTokens:20480};
 if(profile===RESPONSE_CONSISTENCY_V14_8B_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSelectedResponseConsistencyCandidate').VERSION],cases:4,calls:4,contextTokens:20480};
 if(profile===RESPONSE_REGRESSION_V14_8B_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSelectedResponseConsistencyCandidate').VERSION],cases:8,calls:8,contextTokens:20480};
 if(profile===SIMPLE_ASSESSMENT_V1_8B_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSimpleAssessmentCandidate').VERSION],cases:12,calls:12,contextTokens:20480};
 if(profile===SOURCE_RESPONSE_ASSESSMENT_V1_8B_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSourceResponseAssessmentCandidate').VERSION],cases:12,calls:24,contextTokens:20480};
 if(profile===SOURCE_RESPONSE_ASSESSMENT_V2_8B_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSourceResponseAssessmentV2Candidate').VERSION],cases:12,calls:24,contextTokens:20480};
 if(profile===TECHNIQUES_SELECTED_V6_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').VERSION],cases:6,calls:6};
 if(profile===COMPACT_CONJUNCTION_V9_8B_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSideCompactConjunctionCandidate').VERSION],cases:6,calls:12,contextTokens:20480};
 if(profile===CONJUNCTION_V8_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSideConjunctionCandidate').VERSION],cases:1,calls:1};
 if(profile===TECHNIQUES_SELECTED_REMAINING2_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').VERSION],cases:2,calls:2};
 if(profile===SOURCE_LINK_V7_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiSideSourceLinkCandidate').VERSION],cases:6,calls:6};
 if(profile===SELECTED_V6_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').VERSION],cases:6,calls:6};
 if(profile===WHOLE_INTENT_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiWholeTaskIntentCandidate').VERSION],cases:8,calls:16};
 if(profile===SOURCE_FIRST_SIDE)return {protocols:[require('../../server/agent-runtime/dpiSourceFirstServerIdsCandidate').VERSION],cases:4,calls:8};
 if(profile===DIRECT_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiDirectWitnessCandidate').VERSION],cases:20,calls:56};
 if(profile===SERVER_IDS_SIDE)return {protocols:[require('../../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').VERSION],cases:4,calls:4};
 if(profile===SERVER_IDS_SMOKE)return {protocols:[require('../../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').VERSION],cases:6,calls:10};
 if(profile===SERVER_IDS_PROFILE)return {protocols:[require('../../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').VERSION],cases:20,calls:28};
 if(profile===SCHEMA_VISIBLE_PROFILE)return {protocols:[compact.SCHEMA_VISIBLE_VERSION],cases:20,calls:56};
 return profile===COMPACT_PROFILE?{protocols:[compact.VERSION],cases:20,calls:56}:{protocols:PROTOCOLS,cases:24,calls:96};
}
function evidenceFor(item,profile='span'){
 profileFor(profile);
 if(isSourceTechniqueProfile(profile)){
  assert.deepEqual(Object.keys(item).sort(),['id','objective','request','response']);
  assert(typeof item.id==='string'&&item.id.length>0&&item.id.length<=100);
  assert(['jailbreak','role_playing'].includes(item.objective));
  assert(typeof item.request==='string'&&item.request.length>0);
  assert(typeof item.response==='string'&&item.response.length>0);
  return [{id:'request',source:'student_input',content:item.request},{id:'response',source:'assistant_response',content:item.response}];
 }
 if(profile!=='span'){
  assert.deepEqual(Object.keys(item).sort(),['evidence','id','objective','policyIdentity']);
  assert(typeof item.id==='string'&&item.id.length>0&&item.id.length<=100);
  assert(['jailbreak','role_playing','side_stepping','virtualization','obfuscation'].includes(item.objective));
  policyContract.validatePolicy(item.policyIdentity,item.objective,'vuln');
  assert(Array.isArray(item.evidence));
  const expected=item.objective==='obfuscation'?['decoded_request','request','response']:['request','response'];
  assert.deepEqual(item.evidence.map(e=>e.id).sort(),expected);
  for(const e of item.evidence){assert.deepEqual(Object.keys(e).sort(),['content','id','source']);assert.equal(e.source,e.id==='request'?'student_input':e.id==='response'?'assistant_response':'server_observation');}
  return structuredClone(item.evidence);
 }
 assert(item&&typeof item.id==='string'&&item.id.length<=100);
 // Virtualization is diagnostic-only here: canonical hypothetical prerequisites remain unchanged.
 assert.equal(typeof item.request,'string');assert.equal(typeof item.response,'string');
 // Intentionally project only source/response. Never concatenate task policy or labels.
 const evidence=[{id:'request',source:'student_input',content:item.request},{id:'response',source:'assistant_response',content:item.response}];

 return evidence;
}
function createCalibration({provider,transport,record=()=>{},profile='span',judgeIdentity}){
 const config=profileFor(profile);
 assert(judgeIdentity===undefined||[DIRECT_PROFILE,SERVER_IDS_PROFILE,SERVER_IDS_SMOKE,SERVER_IDS_SIDE,TECHNIQUES_SELECTED_V6_PROFILE,SOURCE_FIRST_SIDE,WHOLE_INTENT_PROFILE,SELECTED_V6_PROFILE,TECHNIQUES_SELECTED_REMAINING2_PROFILE,SOURCE_LINK_V7_PROFILE,CONJUNCTION_V8_PROFILE,SOURCE_TECHNIQUE_V11_PROFILE,ROLE_TECHNIQUE_V12_PROFILE].includes(profile),'Judge override only admitted for direct-witness diagnostic');
 const {model:MODEL}=require('./ragWholeEvidenceActualTransport').admitJudgeIdentity(judgeIdentity);
 const contextTokens=config.contextTokens||32768;
 assert.equal(typeof provider.chat,'function');let expected=null,activeSignal=null,calls=0,busy=false,poisoned=false;const seen=new Set(),pending=new Set();
 function admitWire(body){assert(expected&&!poisoned&&activeSignal&&!activeSignal.aborted);assert.deepEqual(JSON.parse(body),expected);expected=null;assert(++calls<=config.calls);}
 async function run(item,protocol,{signal:outerSignal}={}){let signal=outerSignal;
 assert(!busy&&!poisoned&&config.protocols.includes(protocol)&&seen.size<config.cases);const id=item.id+':'+protocol;assert(!seen.has(id));
 const evidence=evidenceFor(item,profile),contract=profile===SOURCE_TECHNIQUE_V11_PROFILE?require('../../server/agent-runtime/dpiSelectedSourceTechniqueCandidate').createDpiSelectedSourceTechniqueCandidate({objective:item.objective,evidence}):profile===ROLE_TECHNIQUE_V12_PROFILE?require('../../server/agent-runtime/dpiSelectedRoleTechniqueCandidate').createDpiSelectedRoleTechniqueCandidate({objective:item.objective,evidence}):profile===OBJECTIVE_TECHNIQUE_V13_8B_PROFILE?require('../../server/agent-runtime/dpiSelectedObjectiveTechniqueCandidate').createDpiSelectedObjectiveTechniqueCandidate({objective:item.objective,evidence}):[RESPONSE_CONSISTENCY_V14_8B_PROFILE,RESPONSE_REGRESSION_V14_8B_PROFILE].includes(profile)?require('../../server/agent-runtime/dpiSelectedResponseConsistencyCandidate').createDpiSelectedResponseConsistencyCandidate({objective:item.objective,evidence}):profile===SIMPLE_ASSESSMENT_V1_8B_PROFILE?require('../../server/agent-runtime/dpiSimpleAssessmentCandidate').createDpiSimpleAssessmentCandidate({objective:item.objective,evidence}):profile===SOURCE_RESPONSE_ASSESSMENT_V1_8B_PROFILE?require('../../server/agent-runtime/dpiSourceResponseAssessmentCandidate').createDpiSourceResponseAssessmentCandidate({objective:item.objective,evidence}):profile===SOURCE_RESPONSE_ASSESSMENT_V2_8B_PROFILE?require('../../server/agent-runtime/dpiSourceResponseAssessmentV2Candidate').createDpiSourceResponseAssessmentV2Candidate({objective:item.objective,evidence}):profile===COMPACT_CONJUNCTION_V9_8B_PROFILE?require('../../server/agent-runtime/dpiSideCompactConjunctionCandidate').createDpiSideCompactConjunctionCandidate({objective:item.objective,evidence}):profile===CONJUNCTION_V8_PROFILE?require('../../server/agent-runtime/dpiSideConjunctionCandidate').createDpiSideConjunctionCandidate({objective:item.objective,evidence}):profile===SOURCE_LINK_V7_PROFILE?require('../../server/agent-runtime/dpiSideSourceLinkCandidate').createDpiSideSourceLinkCandidate({objective:item.objective,evidence}):profile===WHOLE_INTENT_PROFILE?require('../../server/agent-runtime/dpiWholeTaskIntentCandidate').createWholeTaskIntentCandidate({objective:item.objective,evidence}):profile===SOURCE_FIRST_SIDE?require('../../server/agent-runtime/dpiSourceFirstServerIdsCandidate').createSourceFirstServerIdsCandidate({objective:item.objective,evidence}):profile===DIRECT_PROFILE?require('../../server/agent-runtime/dpiDirectWitnessCandidate').createDirectWitnessCandidate({objective:item.objective,evidence}):isServerIds(profile)?require('../../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').createDirectWitnessServerIdsCandidate({objective:item.objective,evidence}):profile!=='span'?compact.createCompactCandidate({objective:item.objective,evidence,protocolVersion:config.protocols[0]}):protocol===PROTOCOLS[0]?base.createDpiTaskContributionComparison({objective:'virtualization',primary:true,protocolVersion:base.VERSION},evidence):candidate.createDpiTaskContributionSpanCandidate({objective:'virtualization',primary:true,protocolVersion:candidate.VERSION},evidence);
 const requestText=evidence.find(e=>e.id==='request').content,responseText=evidence.find(e=>e.id==='response').content,maxOutput=contract.policy.maxOutput;
 assert([900,1800].includes(maxOutput));
 seen.add(id);busy=true;const controller=new AbortController(),deadline=performance.now()+300000;activeSignal=controller.signal;const revoke=()=>{expected=null;poisoned=true;};controller.signal.addEventListener('abort',revoke,{once:true});const abort=()=>controller.abort(signal?.reason);signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();const timer=setTimeout(()=>controller.abort(Error('Case deadline')),300000);signal=controller.signal;
 const row={id,protocol,diagnosticObjective:profile!=='span'?item.objective:'virtualization',...([DIRECT_PROFILE,SERVER_IDS_PROFILE,SERVER_IDS_SMOKE,SERVER_IDS_SIDE,TECHNIQUES_SELECTED_V6_PROFILE,SOURCE_FIRST_SIDE,WHOLE_INTENT_PROFILE,TECHNIQUES_SELECTED_REMAINING2_PROFILE,SOURCE_LINK_V7_PROFILE,CONJUNCTION_V8_PROFILE].includes(profile)?{reusedRegression:true,heldOut:false}:{}),...([CONJUNCTION_V8_PROFILE,TECHNIQUES_SELECTED_REMAINING2_PROFILE].includes(profile)?{recovery:true,subset:true,reused:true}:{}),...(profile!== 'span'&&!isSourceTechniqueProfile(profile)?{profile,selectedPolicy:structuredClone(item.policyIdentity)}:isSourceTechniqueProfile(profile)?{profile}:{}),exerciseQualification:false,requestSha256:sha(requestText),responseSha256:sha(responseText),creditAuthorized:false,genuineActor:false,steps:[],status:'pending'};
 try{
 transport.beginCase(id);const values=[];
 for(const stage of contract.stages){let valid=false,error;
  for(let attempt=0;attempt<stage.maximumCalls;attempt++){
   signal?.throwIfAborted();const request=stage.messages(error),wire={model:MODEL,messages:request.messages,stream:true,format:request.format,options:{temperature:0,num_predict:maxOutput,num_ctx:contextTokens}};
   const step={stage:stage.id,attempt:attempt+1,request:wire,requestSha256:sha(JSON.stringify(wire)),status:'pending'};row.steps.push(step);record(structuredClone(row));expected=wire;
   const task=Promise.resolve().then(()=>{signal.throwIfAborted();return provider.chat(request.messages,[],{temperature:0,max_tokens:maxOutput,num_predict:maxOutput,num_ctx:contextTokens,format:request.format,signal,...([TECHNIQUES_SELECTED_V6_PROFILE,TECHNIQUES_SELECTED_REMAINING2_PROFILE,SOURCE_TECHNIQUE_V11_PROFILE,ROLE_TECHNIQUE_V12_PROFILE,OBJECTIVE_TECHNIQUE_V13_8B_PROFILE,RESPONSE_CONSISTENCY_V14_8B_PROFILE,RESPONSE_REGRESSION_V14_8B_PROFILE,SIMPLE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V2_8B_PROFILE].includes(profile)?{timeout:180000}:{})});});pending.add(task);task.then(()=>pending.delete(task),()=>pending.delete(task));let listener;const value=await Promise.race([task,new Promise((_,reject)=>{listener=()=>reject(Error('Provider cancelled'));signal.addEventListener('abort',listener,{once:true});if(signal.aborted)listener();})]).finally(()=>signal.removeEventListener('abort',listener));assert(performance.now()<deadline);signal?.throwIfAborted();assert.equal(expected,null,'Unadmitted dispatch');assert.equal(value.provider,'ollama');assert.equal(value.model,MODEL);assert(!value.mocked&&!value.fallback&&!value._error);
   const rows=transport.snapshot().calls.filter(x=>x.caseId===id&&x.kind==='external/api/chat');assert.equal(rows.length,row.steps.length);const raw=rows.at(-1);assert.equal(raw.status,'returned');assert.equal(raw.httpStatus,200);assert.equal(raw.requestSha256,sha(raw.request));assert.equal(raw.responseSha256,sha(raw.response));assert.deepEqual(JSON.parse(raw.request),wire);
   const frames=raw.response.trim().split('\n').map(JSON.parse);assert(frames.length);assert(frames.every((f,i)=>f.model===MODEL&&!f.error&&!f.message?.tool_calls&&f.message?.role==='assistant'&&typeof f.message.content==='string'&&f.done===(i===frames.length-1)));assert(['stop','length'].includes(frames.at(-1).done_reason));assert.equal(frames.map(f=>f.message.content).join(''),value.response);
   assert.equal(typeof value.response,'string');step.response=value.response;step.responseSha256=sha(value.response);step.wireResponseSha256=raw.responseSha256;step.termination=frames.at(-1).done_reason;record(structuredClone(row));
   try{if(step.termination==='length')throw Error('MODEL_OUTPUT_LIMIT');values.push(stage.validate(value.response));valid=true;step.status='valid';}catch(caught){step.status='invalid';if(attempt+1<stage.maximumCalls&&(!stage.retryWhen||stage.retryWhen(caught)))error=stage.repairMessage(caught);else break;}record(structuredClone(row));if(valid)break;
  }
  if(!valid){row.status='model-invalid';break;}
 }
 if(values.length===contract.stages.length){row.result=contract.combine(...values);row.status='complete';}
 transport.endCase();record(structuredClone(row));return row;
 }catch(error){expected=null;poisoned=true;row.status='mechanical-failure';record(structuredClone(row));throw error;}finally{clearTimeout(timer);outerSignal?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',revoke);controller.abort();expected=null;activeSignal=null;busy=false;}
 }
 return {run,admitWire,state:()=>({calls,cases:seen.size,busy,poisoned,providerPending:pending.size})};
}
module.exports={createCalibration,evidenceFor,profileFor,COMPACT_PROFILE,SCHEMA_VISIBLE_PROFILE,DIRECT_PROFILE,SERVER_IDS_PROFILE,SERVER_IDS_SMOKE,SERVER_IDS_SIDE,TECHNIQUES_SELECTED_V6_PROFILE,SOURCE_FIRST_SIDE,WHOLE_INTENT_PROFILE,SELECTED_V6_PROFILE,TECHNIQUES_SELECTED_REMAINING2_PROFILE,SOURCE_LINK_V7_PROFILE,CONJUNCTION_V8_PROFILE,COMPACT_CONJUNCTION_V9_8B_PROFILE,SOURCE_TECHNIQUE_V11_PROFILE,ROLE_TECHNIQUE_V12_PROFILE,OBJECTIVE_TECHNIQUE_V13_8B_PROFILE,RESPONSE_CONSISTENCY_V14_8B_PROFILE,RESPONSE_REGRESSION_V14_8B_PROFILE,SIMPLE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V1_8B_PROFILE,SOURCE_RESPONSE_ASSESSMENT_V2_8B_PROFILE,PROTOCOLS,MODEL};
