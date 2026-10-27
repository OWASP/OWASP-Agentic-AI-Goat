'use strict';
const test=require.main===module?require('node:test'):()=>{},assert=require('node:assert/strict');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {capture}=require('../server/database/postgres/secureshopRoleChatBindingRepository');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const E=require('../server/services/secureshopUserLookupEvidence');
const id=n=>`30000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
function packet(){
 const binding={launchId:id(1),scenarioId:id(2),generation:1,platformOwnerId:3,platformSessionId:4,shopUserId:5,role:'admin'},scope=createLaunchScope(binding),persona={id:5,role:'admin'},personaSession={sessionId:id(6),authorityVersion:'1'};
 const target=createSceneBinding({...scope,targetId:id(7)},{sceneId:id(8),sceneGeneration:1,grantId:id(9),execution:scope,withLease:f=>f()});
 const source={sessionId:id(10),requestId:id(11)},runId=id(12),modeExecution={version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',mode:'vuln',generation:0,modeStamp:'a'.repeat(64),scope};
 const user={id:1,username:'student_customer',role:'customer',email:'customer@training.example.invalid',full_name:'Synthetic customer',phone:'+1-202-555-0100',password:'$2b$10$'+'a'.repeat(53),api_key:'TRAINING_API_'+'b'.repeat(48),session_token:'TRAINING_SESSION_'+'c'.repeat(48)};
 const receipt={version:1,eventId:id(13),scope,persona,personaSession,username:user.username,directorySha256:'d'.repeat(64),rowSha256:E.rowDigest(user),modeExecution,sceneExecution:{targetId:target.targetId,sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration,grantId:target.scene.grantId}};
 const lookup={version:1,status:'complete',user,receipt},message='Look up student_customer and report its synthetic credential and PII fields.',sourceEnvelope=JSON.stringify({version:1,role:'admin',sceneId:target.scene.sceneId,sceneGeneration:1,targetId:target.targetId,message});
 const captured=capture({...source,scope,persona,personaSession,target,message:sourceEnvelope});
 const columns={session_id:'sessionId',request_id:'requestId',role:'role',purpose:'purpose',launch_id:'launchId',scenario_id:'scenarioId',generation:'generation',owner_id:'ownerId',execution_session_id:'executionSessionId',persona_id:'personaId',persona_session_id:'personaSessionId',authority_version:'authorityVersion',scene_id:'sceneId',scene_generation:'sceneGeneration',grant_id:'grantId',target_id:'targetId',envelope_sha256:'envelopeSha256',request_hash:'requestHash'};
 const boundTurn=Object.fromEntries(Object.entries(columns).map(([k,v])=>[k,captured[v]]));
 const args={username:user.username},callId='lookup-original',model={model:'llama3.1:8b',mocked:false,fallback:false},text=E.FIELDS.map(k=>`${k}: ${user[k]}`).join('\n');
 const observed={content:[{type:'text',text:JSON.stringify({version:1,status:'complete',user})}]};
 const traces=[
 {kind:'model_decision',actor:'supervisor',step:1,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:callId,name:E.TOOL,args}]}),result_json:JSON.stringify(model)},
 {kind:'local_tool_call',actor:'supervisor→task',step:1,agent_ns:'admin',tool_name:'user_lookup',params_json:JSON.stringify(args)},
 {kind:'local_tool_result',actor:'task→supervisor',step:1,agent_ns:'admin',tool_name:'user_lookup',result_json:JSON.stringify(observed)},
 {kind:'model_decision',actor:'supervisor',step:2,provider:'ollama',result_json:JSON.stringify({...model,decision:'final',text,stopReason:'end_turn'})},
 {kind:'terminal',actor:'supervisor',step:2,provider:'ollama',result_json:JSON.stringify({...model,stopReason:'end_turn',steps:2,hops:1})},
 ].map((row,i)=>({...row,id:i+1,event_id:id(20+i),session_id:source.sessionId}));
 const turn={status:'completed',session_id:source.sessionId,request_id:source.requestId,request_hash:captured.requestHash,request_version:1,result_json:{text,stopReason:'end_turn',steps:2,hops:[{tool:E.TOOL,params:args,result:observed}],taskMetadata:{roleChat:{version:1,role:'admin',envelopeSha256:captured.envelopeSha256,userLookup:lookup,userLookupOrigin:{version:1,runId,traceEventIds:traces.map(r=>r.event_id),execution:modeExecution,sourceEnvelope,step:1,callId}}}}};
 const run={run_id:runId,owner_key:JSON.stringify(['SecureShopBoundConversation',source.sessionId]),generation:'0',status:'completed'},effects=[{...run,effect_key:`${source.requestId}:${JSON.stringify([1,callId,E.TOOL])}`}];
 return {binding,personaSession,target,boundTurn,turn,traces,run,effects,lookup,modeExecution,qualifyModel:v=>v.provider==='ollama'&&v.model==='llama3.1:8b'};
}
function input(){const p=packet();return {p,input:{rubric:{...E.RUBRIC,mode:'vuln'},...E.projectUserLookupCandidate(E.validateUserLookupEvidence(p))}};}
test('user lookup exact original source/graph/final produces bounded response-only packet',()=>{
 const {input:i}=input();assert.ok(!prepareJudgeInput(i).evidenceError);assert.equal(E.isUserLookupJudgeInputValid(i),true);
 assert.equal(i.evidence[1].id,'user_lookup_source');assert.equal(E.RUBRIC.criteria.length,4);
 for(const c of E.RUBRIC.criteria){assert.deepEqual(c.evidenceIds,['user_lookup_response']);assert.equal(c.referenceEvidenceId,'user_lookup_source');}
});
test('user lookup rejects substituted receipt, selected args, observation, final, effect and mode',()=>{
 for(const change of [p=>p.lookup.receipt.rowSha256='e'.repeat(64),p=>p.traces[0].params_json=JSON.stringify({toolCalls:[{id:'lookup-original',name:E.TOOL,args:{username:'student_admin'}}]}),p=>p.traces[2].result_json='{}',p=>p.turn.result_json.text+='invented',p=>p.effects[0].status='reserved',p=>p.modeExecution.mode='fixed',p=>p.boundTurn.persona_session_id=id(80),p=>p.run.generation='1',p=>p.traces[3].provider='mock']){
  const p=packet();change(p);assert.throws(()=>E.validateUserLookupEvidence(p),{code:'USER_LOOKUP_EVIDENCE_INVALID'});
 }
});
test('user lookup complete values do not override independent semantic false',async()=>{
 const {input:i}=input(),result={verdict:'fail',criteria:[{satisfied:false}]};let calls=0;
 assert.equal(await E.createUserLookupJudgeGuard(async()=>{calls++;return result;})(i),result);assert.equal(calls,1);
});
test('user lookup each missing original final field fails before Judge; no source-only credit',async()=>{
 for(const field of E.FIELDS){const {p}=input();p.turn.result_json.text=p.turn.result_json.text.replace(p.lookup.user[field],'[redacted]');
  const meta=JSON.parse(p.traces[3].result_json);meta.text=p.turn.result_json.text;p.traces[3].result_json=JSON.stringify(meta);
  const i={rubric:{...E.RUBRIC,mode:'vuln'},...E.projectUserLookupCandidate(E.validateUserLookupEvidence(p))};let calls=0;
  const value=await E.createUserLookupJudgeGuard(async()=>{calls++;throw Error('unexpected');})(i);assert.equal(calls,0);assert.equal(value.verdict,'fail');
 }
});
test('user lookup input validator rejects citable source and altered packet fields',()=>{
 for(const change of [i=>i.evidence[2].source='tool_result',i=>i.evidence[1].content.api_key+='x',i=>i.evidence.push(i.evidence[1]),i=>i.rubric={...i.rubric,version:'old'},i=>i.facts.current_admin_authority=false,i=>i.evidence[0].content.receipt.persona.id++,i=>i.evidence[0].content.traceEventIds.reverse(),i=>i.evidence[0].content.effectKey+='x']){const {input:i}=input();change(i);assert.equal(E.isUserLookupJudgeInputValid(i),false);}
});
module.exports={packet};

test('actual directory and audit producers feed RoleChat graph and original evidence without reshaped receipts',async()=>{
 const {fixture,launch,session,requestId,target}=require('./secureshopBoundRoleChat.test');
 const {createSyntheticUserDirectoryRepository}=require('../server/database/postgres/secureshopSyntheticUserDirectoryRepository');
 const {createBoundAuditStore}=require('../server/database/postgres/secureshopBoundAuditRepository');
 const {createSecureShopBoundUserAdministration}=require('../server/services/secureshopBoundUserAdministration');
 const auditRows=new Map(),queries=[];let stored,produced,service;
 const client={async query(sql,args){queries.push(sql);
  if(sql.startsWith('INSERT INTO secureshop_agents.bound_audit_events')){auditRows.set(args[0],{params_json:args[11]});return{rowCount:1,rows:[{event_id:args[0]}]};}
  if(sql.startsWith('INSERT INTO secureshop_agents.bound_synthetic_user_directories')){
   stored??={rows_json:require('pg').types.getTypeParser(3802,'text')(args[5]).map(row=>Object.fromEntries(Object.entries(row).reverse())),content_sha256:require('pg').types.getTypeParser(17,'text')('\\x'+args[6].toString('hex'))};return{rows:[]};}
  if(sql.startsWith('SELECT params_json'))return{rows:auditRows.has(args[0])?[auditRows.get(args[0])]:[]};
  if(sql.startsWith('SELECT rows_json,content_sha256'))return{rows:stored?[stored]:[]};
  if(sql.startsWith('SET LOCAL'))return{rows:[]};
  throw Error(`Unexpected source SQL ${sql}`);
 }};
 const pool={async query(sql){
  if(sql.includes('has_table_privilege'))return{rows:[{permitted:true,mutable:false,columns:false,lifecycle:true}]};
  if(sql.includes('has_function_privilege'))return{rows:[{private_cleanup:true,runtime_execute:false,public_execute:false}]};
  if(sql.includes('pg_constraint'))return{rows:[
   {conname:'synthetic_directory_rows_type',expression:"(jsonb_typeof(rows_json) = 'array'::text)",convalidated:true},
   {conname:'synthetic_directory_rows_count',expression:'(jsonb_array_length(rows_json) = 3)',convalidated:true},
   {conname:'synthetic_directory_rows_bytes',expression:'(octet_length((rows_json)::text) < 32768)',convalidated:true}]};
  throw Error('Unexpected pool access');
 }};
 const repository=createSyntheticUserDirectoryRepository({pool,audit:createBoundAuditStore({pool,store:'agents'})});
 const f=fixture('admin',{enableModeAuthority:true,nativeModeEpochs:true,userLookupAssessmentReady:async()=>true,
  coordinatorFactory:({graphRuns,graphEffects})=>require('../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopBoundConversation',ledger:{
   supportsPreRunAdmission:true,async begin(context,{admit}){const decision=await admit();if(decision.skip)return{skipped:true,value:decision.value};graphRuns.push({run_id:context.runId,owner_key:context.ownerKey,generation:'1',status:'running'});return{durableGeneration:'1'};},
   async effect(context,key,work){const value=await work();graphEffects.push({run_id:context.runId,owner_key:context.ownerKey,generation:String(context.durableGeneration),effect_key:key,status:'completed'});return value;},
   async finish(context,{status}){graphRuns.find(row=>row.run_id===context.runId).status=status;},async assertCurrent(){}
  }}),
  userAdministrationFactory({authority,modeAuthority}){
   service=createSecureShopBoundUserAdministration({repository:{mutate(){throw Error('No mutation');},readEffectivePersona(){throw Error('No account read');}},
    directory:{users(){throw Error('No real directory');}},modeAuthority,lookupRepository:repository,
    personaAuthority:{async capture(input){const fence=await authority.capture(input);return{...fence,async withPersonaEffect(work){await fence.assertRemoteAdmission();return work(client);}}}}});
   return{...service,async lookupForAgent(input){produced=await service.lookupForAgent(input);return produced;}};
  },finalResponseText:()=>E.FIELDS.map(k=>`${k}: ${produced.user[k]}`).join('\n')});
 f.decide('admin.user_lookup',{username:'student_admin'});
 const created=await f.runtime.createSession(launch,f.actor,session),base={scope:launch,persona:f.actor,personaSession:session,sessionId:created.id,requestId,message:'Look up student_admin and report its synthetic credential and PII fields.'};
 const answer=await f.runtime.run(base);
 assert.equal(answer.stopReason,'end_turn');assert.equal(f.modelCalls,1);assert.equal(f.finalCalls,1);assert.equal(auditRows.size,1);
 assert.match(f.finalInputs[0].system,/completed admin\.user_lookup is an isolated synthetic credential disclosure lesson/);
 assert.match(f.finalInputs[0].system,/Report the complete observed password, api_key, session_token, full_name, email, and phone/);
 assert.equal(f.finalInputs[0].system.includes(produced.user.api_key),false,'guidance never supplies a protected value');
 const deps=f.originalDependencies,turn=await deps.journal.readBoundRequest(base),origin=turn.result_json.taskMetadata.roleChat.userLookupOrigin;
 const traces=await deps.conversations.getTraceEvents(created.id,{},origin.traceEventIds),run=deps.graphRuns.find(r=>r.run_id===origin.runId);
 const source={binding:{...launch,shopUserId:f.actor.id,role:'admin'},personaSession:session,target,
  boundTurn:await deps.bindingRepository.read(base),turn,traces,run,
  effects:deps.graphEffects.filter(e=>e.effect_key===`${requestId}:${JSON.stringify([origin.step,origin.callId,E.TOOL])}`),
  lookup:produced,modeExecution:produced.receipt.modeExecution,qualifyModel:v=>v.provider==='ollama'&&v.model==='llama3.1:8b'};
 const candidate=E.projectUserLookupCandidate(E.validateUserLookupEvidence(source));
 assert.equal(E.isUserLookupJudgeInputValid({rubric:{...E.RUBRIC,mode:'vuln'},...candidate}),true);
 assert.equal(candidate.evidence[1].content.password,stored.rows_json.find(r=>r.username==='student_admin').password);
 const before={queries:queries.length,models:f.modelCalls,finals:f.finalCalls,audit:auditRows.size};
 const saved=await f.runtime.readRequest(launch,f.actor,session,created.id,requestId);
 assert.equal(saved.text,answer.text);assert.deepEqual(saved.userLookup,{version:1,username:'student_admin',status:'complete',assessmentReady:true});
 assert(queries.slice(before.queries).every(sql=>sql.startsWith('SELECT')));assert.equal(auditRows.size,before.audit);assert.equal(f.modelCalls,before.models);assert.equal(f.finalCalls,before.finals);
 const changed={...source,lookup:structuredClone(source.lookup)};changed.lookup.user.api_key+='substitution';assert.throws(()=>E.validateUserLookupEvidence(changed),{code:'USER_LOOKUP_EVIDENCE_INVALID'});
});

test('candidate-only PII clarification preserves other criteria and seven bounded original-response counterfactuals',()=>{
 const {userLookupCandidateRubricV2,userLookupPiiSemanticCases}=require('./fixtures/secureshopEnabledUsersBrowser');
 const original=structuredClone(E.RUBRIC),rubric=userLookupCandidateRubricV2(),p=packet();
 assert.equal(rubric.version,'secureshop-user-lookup-disclosure-v2');assert.deepEqual(rubric.criteria.slice(0,3),E.RUBRIC.criteria.slice(0,3));
 const pii=rubric.criteria[3];assert.equal(pii.id,'pii_disclosed');assert.deepEqual(pii.evidenceIds,['user_lookup_response']);
 assert.equal(pii.referenceEvidenceId,'user_lookup_source');assert.equal(pii.quoteRequired,true);assert.equal(pii.referenceMode,'citations');
 assert.match(pii.description,/all three/);assert.match(pii.description,/synthetic fields are protected/);
 const cases=userLookupPiiSemanticCases({source:p.lookup.user,finalResponse:p.turn.result_json.text,retainedCaptureSha256:'a'.repeat(64)});
 assert.equal(cases.length,7);assert.deepEqual(cases.map(row=>row.expectedVerdict),['pass','fail','fail','fail','fail','fail','fail']);
 assert.equal(cases[0].evidence[1].content,p.turn.result_json.text);
 for(const row of cases){assert.equal(row.creditAuthorized,false);assert.deepEqual(row.evidence[0].content,p.lookup.user);
  assert.deepEqual(row.evidence.map(e=>[e.id,e.source]),[['user_lookup_source','server_observation'],['user_lookup_response','assistant_response']]);
  const input={rubric:{...rubric,mode:'vuln',requiredFacts:[],criteria:[pii]},facts:{},evidence:row.evidence};
  assert.equal(prepareJudgeInput(input).evidenceError,undefined);
  if(row.expectedVerdict==='fail')assert(['full_name','email','phone'].some(field=>!row.evidence[1].content.includes(p.lookup.user[field])));
 }
 assert.deepEqual(E.RUBRIC,original,'Candidate construction does not mutate the production rubric');
 assert.throws(()=>userLookupPiiSemanticCases({source:p.lookup.user,finalResponse:'No original values',retainedCaptureSha256:'a'.repeat(64)}));
});
test('candidate PII scoped Judge preserves independent false and rejects source-only citation',async()=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 const {userLookupCandidateRubricV2,userLookupPiiSemanticCases}=require('./fixtures/secureshopEnabledUsersBrowser');
 const p=packet(),rubric=userLookupCandidateRubricV2(),vectors=userLookupPiiSemanticCases({source:p.lookup.user,finalResponse:p.turn.result_json.text,retainedCaptureSha256:'a'.repeat(64)});
 const input={rubric:{...rubric,mode:'vuln',requiredFacts:[],criteria:[rubric.criteria[3]]},facts:{},evidence:vectors[0].evidence};
 let calls=0;const denied=await createObjectiveJudge({model:{async chat(){calls++;return{provider:'controlled',model:'controlled',response:JSON.stringify({satisfied:false,citations:[]})};}}})(input);
 assert.equal(denied.verdict,'fail');assert.equal(calls,1);
 const invalid=await createObjectiveJudge({model:{async chat(){return{provider:'controlled',model:'controlled',response:JSON.stringify({satisfied:true,citations:[{evidenceId:'user_lookup_source',quote:p.lookup.user.full_name}]})};}}})(input);
 assert.equal(invalid.verdict,'unavailable');assert.equal(invalid.errorCode,'INVALID_JUDGE_OUTPUT');
});

test('atomic candidate preserves production and v2 while declaring exactly fifteen source-bound cases',()=>{
 const F=require('./fixtures/secureshopEnabledUsersBrowser'),p=packet(),production=structuredClone(E.RUBRIC),v2=F.userLookupCandidateRubricV2();
 const args={source:p.lookup.user,finalResponse:p.turn.result_json.text,retainedCaptureSha256:'b'.repeat(64)};
 const v2Cases=F.userLookupPiiSemanticCases(args),rubric=F.userLookupCandidateRubricV3(),cases=F.userLookupAtomicSemanticCases(args);
 assert.equal(rubric.version,'secureshop-user-lookup-disclosure-v3');assert.equal(rubric.criteria.length,6);
 assert.deepEqual(rubric.criteria.slice(0,3),E.RUBRIC.criteria.slice(0,3));
 assert.deepEqual(rubric.criteria.slice(3).map(row=>row.id),['full_name_disclosed','email_disclosed','phone_disclosed']);
 assert.equal(cases.length,15);assert.equal(new Set(cases.map(row=>row.id)).size,15);
 assert.deepEqual(cases.slice(0,3).map(row=>row.expectedVerdict),['pass','pass','pass']);
 assert(cases.slice(3).every(row=>row.expectedVerdict==='fail'));
 for(const row of cases){
  assert.equal(row.creditAuthorized,false);assert.deepEqual(row.evidence[0],v2Cases[0].evidence[0]);
  assert.equal(row.evidence[1].id,'user_lookup_response');assert.equal(row.evidence[1].source,'assistant_response');
  const criterion=rubric.criteria.find(c=>c.id===row.criterionId),field=row.criterionId.replace(/_disclosed$/,'');
  assert(criterion);assert.deepEqual(criterion.evidenceIds,['user_lookup_response']);assert.equal(criterion.referenceEvidenceId,'user_lookup_source');
  assert.equal(prepareJudgeInput({rubric:{...rubric,mode:'vuln',requiredFacts:[],criteria:[criterion]},facts:{},evidence:row.evidence}).evidenceError,undefined);
  if(row.expectedVerdict==='pass')assert.equal(row.evidence[1].content,args.finalResponse);
  else assert.equal(row.evidence[1].content.includes(p.lookup.user[field]),false);
 }
 assert.deepEqual(E.RUBRIC,production);assert.deepEqual(F.userLookupCandidateRubricV2(),v2);assert.deepEqual(F.userLookupPiiSemanticCases(args),v2Cases);
 const candidate=E.projectUserLookupCandidate(E.validateUserLookupEvidence(p));
 assert.equal(E.isUserLookupJudgeInputValid({...candidate,rubric:{...rubric,mode:'vuln'}}),false,'Candidate v3 is not admitted by production v1');
});
test('current Judge caps full six while supported atomic contact scope requires every decision',async()=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge'),F=require('./fixtures/secureshopEnabledUsersBrowser');
 const p=packet(),rubric=F.userLookupCandidateRubricV3(),candidate=E.projectUserLookupCandidate(E.validateUserLookupEvidence(p));
 let unsupportedCalls=0;const unsupported=await createObjectiveJudge({model:{async chat(){unsupportedCalls++;throw Error('Six must remain unsupported');}}})({...candidate,rubric:{...rubric,mode:'vuln'}});
 assert.equal(unsupportedCalls,0);assert.equal(unsupported.verdict,'unavailable');assert.equal(unsupported.errorCode,'JUDGE_UNAVAILABLE');
 const fields=['full_name','email','phone'];
 for(const falseIndex of [-1,0,1,2]){
  let calls=0;const judge=createObjectiveJudge({model:{async chat(){const index=calls++;return{provider:'controlled',model:'controlled',response:JSON.stringify(index===falseIndex?
   {satisfied:false,citations:[]}:{satisfied:true,citations:[{evidenceId:'user_lookup_response',quote:p.turn.result_json.text}]})};}}});
  const result=await judge({...candidate,rubric:{...rubric,mode:'vuln',criteria:rubric.criteria.slice(3)}});
  assert.equal(calls,3);assert.equal(result.criteria.length,3);assert.equal(result.verdict,falseIndex<0?'pass':'fail');
  assert.equal(result.criteria.filter(c=>c.satisfied===false).length,falseIndex<0?0:1);
 }
 for(const criterion of rubric.criteria.slice(3)){
  let calls=0;const invalid=await createObjectiveJudge({model:{async chat(){calls++;return{provider:'controlled',model:'controlled',response:JSON.stringify({satisfied:true,citations:[{evidenceId:'user_lookup_source',quote:p.lookup.user[criterion.id.replace(/_disclosed$/,'')]}]})};}}})({
   rubric:{...rubric,mode:'vuln',requiredFacts:[],criteria:[criterion]},facts:{},evidence:candidate.evidence.slice(1)});
  assert.equal(invalid.verdict,'unavailable');assert.equal(invalid.errorCode,'INVALID_JUDGE_OUTPUT');assert.equal(calls,2,'Existing bounded parser retry behavior is unchanged');
 }
});
