'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto');
const main=require('./fixtures/dpiSpanCalibrationMain');
const {createCalibration,profileFor}=require('./fixtures/dpiSpanCalibration');
const {admitJudgeIdentity}=require('./fixtures/ragWholeEvidenceActualTransport');
const profiles=[
 ['semantic-selected-objective-technique-v13-8b','dpi-selected-objective-technique-v13',4,780000],
 ['semantic-selected-response-consistency-v14-8b','dpi-selected-response-consistency-v14',4,780000],
 ['semantic-selected-response-regression-v14-8b','dpi-selected-response-consistency-v14',8,1500000],
 ['semantic-simple-assessment-v1-8b','dpi-simple-assessment-v1',12,2220000],
 ['semantic-source-response-assessment-v1-8b','dpi-source-response-assessment-v1',24,3660000],
 ['semantic-source-response-assessment-v2-8b','dpi-source-response-assessment-v2',24,3660000],
];
const identity=admitJudgeIdentity(undefined);
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
for(const [profile,_protocol,calls,workMs] of profiles)test(`${profile} requires the exact default identity and rejects all model overrides`,()=>{
 assert.deepEqual(main.admitJudgeSelection(profile,{defaultJudgeIdentity:identity},{}),identity);
 for(const [manifest,env] of [[{},{}],[{defaultJudgeIdentity:{...identity,model:'llama3.3:70b'}},{}],[{defaultJudgeIdentity:identity,judgeIdentity:identity},{}],[{defaultJudgeIdentity:identity},{DPI_SPAN_JUDGE_MODEL:identity.model}]])assert.throws(()=>main.admitJudgeSelection(profile,manifest,env));
 const cfg=main.settings({DPI_SPAN_PROFILE:profile});assert.equal(cfg.calls,calls);assert.equal(cfg.externalMs,180000);assert.equal(cfg.workMs,workMs);
 assert.equal(profileFor(profile).contextTokens,20480);
 assert.equal(profileFor(profile).calls,calls);
 if(profile==='semantic-selected-response-consistency-v14-8b')assert.deepEqual(main.sourceTechniqueSpec(profile).basePaths,[
  main.SOURCE_TECHNIQUE_V11_PATH, main.ROLE_TECHNIQUE_V12_PATH, main.OBJECTIVE_TECHNIQUE_V13_PATH,
 ]);
});
for(const [profile,protocol] of profiles)test(`${profile} adapter binds actual wire model/context and forwards the provider deadline without credit`,async()=>{
 const item=JSON.parse(fs.readFileSync(main.SOURCE_TECHNIQUE_V11_INPUT)).cases[0],isSourceResponse=['semantic-source-response-assessment-v1-8b','semantic-source-response-assessment-v2-8b'].includes(profile);let adapter,caseId,calls=0;const rows=[];
 const transport={beginCase:id=>{caseId=id;},endCase:()=>{},snapshot:()=>({calls:rows})};
 const provider={async chat(messages,_tools,options){
  calls++;assert.equal(options.timeout,180000);assert.equal(options.num_ctx,20480);
  const packet={model:identity.model,messages,stream:true,format:options.format,options:{temperature:0,num_predict:options.num_predict,num_ctx:options.num_ctx}};
  assert.throws(()=>adapter.admitWire(JSON.stringify({...packet,model:'llama3.3:70b'})));
  const request=JSON.stringify(packet);adapter.admitWire(request);
  const sourceResponse=isSourceResponse;
  const sourceResponseV2=profile==='semantic-source-response-assessment-v2-8b';
  const stagePayload=JSON.parse(messages.at(-1).content);
  if(sourceResponse&&calls===1){assert(Object.hasOwn(stagePayload,'request'));assert(!Object.hasOwn(stagePayload,'response'));if(sourceResponseV2)assert(!Object.hasOwn(stagePayload,'objective'));}
  if(sourceResponse&&calls===2){assert.equal(typeof stagePayload.response,'string');if(sourceResponseV2){assert(Object.hasOwn(stagePayload,'taskContract'));assert(!Object.hasOwn(stagePayload,'sourceAssessment'));assert(!Object.hasOwn(stagePayload,'sourceReason'));assert(!Object.hasOwn(stagePayload,'objective'));}else assert(Object.hasOwn(stagePayload,'sourceAssessment'));}
  const output=sourceResponse?(calls===1?JSON.stringify({assessment:{task:{value:'no',support:null},sourceTechnique:{value:'no',support:null}},reason:'No task is established.'}):JSON.stringify({responseAchievement:{value:'no',support:[],counterevidence:[{id:stagePayload.catalogue.response[0].id}]},reason:'The response has no required answer.'})):profile==='semantic-simple-assessment-v1-8b'?JSON.stringify({selected:null,reason:'No selected task can be determined.'}):JSON.stringify({coverage:'uncertain',selected:null});const response=JSON.stringify({model:identity.model,message:{role:'assistant',content:output},done:true,done_reason:'stop'})+'\n';
  rows.push({caseId,kind:'external/api/chat',status:'returned',httpStatus:200,request,requestSha256:sha(request),response,responseSha256:sha(response)});
  return{provider:'ollama',model:identity.model,response:output};
 }};
 adapter=createCalibration({provider,transport,profile});
 const result=await adapter.run(item,protocol);
 assert.equal(calls,isSourceResponse?2:1);assert.equal(result.status,'complete');assert.equal(result.creditAuthorized,false);
 if(isSourceResponse)assert.deepEqual(result.steps.map(step=>step.stage),['source','response']);
});


test('v14 response regression binds the distinct eight-row input and external labels', () => {
 const profile=main.RESPONSE_REGRESSION_V14_8B_PROFILE;
 const input=fs.readFileSync(main.RESPONSE_REGRESSION_V14_INPUT),labels=fs.readFileSync(main.RESPONSE_REGRESSION_V14_EXPECTATIONS);
 assert.equal(sha(input),main.RESPONSE_REGRESSION_V14_SHA);assert.equal(sha(labels),main.RESPONSE_REGRESSION_V14_EXPECTATIONS_SHA);
 const rows=main.projectSelectedSourceTechnique(JSON.parse(input),profile);
 assert.deepEqual(rows.map(row=>row.id),['DPG003','DPG004','DPG007','DPG008','rp_unendorsed_display','rp_withdrawn_answer','jb_source_grader_injection','rp_response_grader_injection']);
 assert.deepEqual(rows.reduce((counts,row)=>({...counts,[row.objective]:(counts[row.objective]||0)+1}),{}),{jailbreak:3,role_playing:5});
 assert.deepEqual(main.sourceTechniqueSpec(profile).basePaths,[main.SOURCE_TECHNIQUE_V11_PATH,main.ROLE_TECHNIQUE_V12_PATH,main.OBJECTIVE_TECHNIQUE_V13_PATH]);
});


test('simple assessment binds the distinct twelve-row input and external requirements', () => {
 const profile=main.SIMPLE_ASSESSMENT_V1_8B_PROFILE;
 const input=fs.readFileSync(main.SIMPLE_ASSESSMENT_V1_INPUT),labels=fs.readFileSync(main.SIMPLE_ASSESSMENT_V1_EXPECTATIONS);
 assert.equal(sha(input),main.SIMPLE_ASSESSMENT_V1_SHA);assert.equal(sha(labels),main.SIMPLE_ASSESSMENT_V1_EXPECTATIONS_SHA);
 const rows=main.projectSelectedSourceTechnique(JSON.parse(input),profile);
 assert.equal(rows.length,12);assert.deepEqual(rows.reduce((counts,row)=>({...counts,[row.objective]:(counts[row.objective]||0)+1}),{}),{jailbreak:5,role_playing:7});
 const expectations=JSON.parse(labels);assert.equal(expectations.version,'dpi-simple-assessment-twelve-expectations-v1');assert.equal(expectations.cases.length,12);assert(expectations.cases.every(row=>Object.hasOwn(row,'expectedRequirements')));
});


test('source-response profile pins task-aware external labels without changing simple labels', () => {
 const simple=fs.readFileSync(main.SIMPLE_ASSESSMENT_V1_EXPECTATIONS);
 const sourceResponse=JSON.parse(fs.readFileSync(main.SOURCE_RESPONSE_ASSESSMENT_V1_EXPECTATIONS));
 assert.equal(sha(simple),main.SIMPLE_ASSESSMENT_V1_EXPECTATIONS_SHA);
 const labels=fs.readFileSync(main.SOURCE_RESPONSE_ASSESSMENT_V1_EXPECTATIONS);
 assert.equal(sha(labels),main.SOURCE_RESPONSE_ASSESSMENT_V1_EXPECTATIONS_SHA);
 assert.equal(sourceResponse.version,'dpi-source-response-twelve-expectations-v1');assert.equal(sourceResponse.cases.length,12);
 assert(sourceResponse.cases.every(row=>row.expectedRequirements.task==='yes'));
});

for(const profile of ['semantic-source-response-assessment-v1-8b','semantic-source-response-assessment-v2-8b'])test(`${profile} admits the actual twelve-case dataset and task-aware manifest contract`,()=>{
 const cfg=main.settings({DPI_SPAN_PROFILE:profile}),data=main.sourceTechniqueDataset(profile),spec=main.sourceTechniqueSpec(profile);
 assert.equal(cfg.records,12);assert.equal(cfg.calls,24);assert.equal(cfg.input,main.SIMPLE_ASSESSMENT_V1_INPUT);assert.equal(cfg.inputSha,main.SIMPLE_ASSESSMENT_V1_SHA);
 assert.equal(data.expectations,main.SOURCE_RESPONSE_ASSESSMENT_V1_EXPECTATIONS);assert.equal(data.expectationsSha,main.SOURCE_RESPONSE_ASSESSMENT_V1_EXPECTATIONS_SHA);
 const rows=main.projectSelectedSourceTechnique(JSON.parse(fs.readFileSync(cfg.input)),profile);assert.equal(rows.length,12);
 const candidate=require('../'+spec.path),pin=sha(fs.readFileSync(spec.path)),admission={version:'dpi-selected-source-technique-calibration-v1',inputSha256:cfg.inputSha,protocol:candidate.VERSION,candidatePath:spec.path,candidateSha256:pin,contextTokens:20480,providerTimeoutMs:180000,transportTimeoutMs:180000,sourceOnly:true,labelsExternal:true};
 assert.deepEqual(main.validateSourceTechniqueAdmission({sourceTechniqueAdmission:admission},new Map([[spec.path,pin]]),cfg),admission);
 assert.throws(()=>main.validateSourceTechniqueAdmission({sourceTechniqueAdmission:{...admission,inputSha256:main.SOURCE_TECHNIQUE_V11_SHA}},new Map([[spec.path,pin]]),cfg));
});
