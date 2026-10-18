'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {buildSystemConfigCandidate,createSystemConfigJudgeGuard,RUBRIC}=require('../server/services/secureshopSystemConfigEvidence');
const {configReadOperationId,boundedConfigObservation}=require('../server/services/secureshopRoleSystemReads');
const {normalizeRequest,requestDigest,hash,VERSION,ISOLATION}=require('../sidecars/sandbox-runner/owned-system/contract');
const {FIXTURES}=require('../sidecars/sandbox-runner/owned-system/executor');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');

function sourceFixture(path='....//.env',overrides={}){
 const binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:4,
  platformSessionId:5,...overrides.scope,shopUserId:overrides.personaId||7,role:'admin'};
 const scope={launchId:binding.launchId,scenarioId:binding.scenarioId,generation:1,
  platformOwnerId:binding.platformOwnerId,platformSessionId:binding.platformSessionId};
 const personaSession=overrides.personaSession||{sessionId:randomUUID(),authorityVersion:'2'};
 const sessionId=randomUUID(),requestId=randomUUID(),origin={step:1,callId:'owned-config-call'};
 const context={scope:binding,persona:{id:binding.shopUserId,role:'admin'},personaSession};
 const operationId=configReadOperationId(context,{sessionId,requestId},origin);
 const request=normalizeRequest({operationId,path}),requestSha256=requestDigest(request);
 const targetPath=path==='application.json'?'/app/config/application.json':'/app/.env';
 const content=FIXTURES[targetPath];
 const sanitized=path.replace(/\.\.\//g,'').replace(/\.\.\\/g,'');
 const receipt={version:VERSION,isolation:ISOLATION,operationId,requestSha256,status:'completed',
  exitCode:0,timedOut:false,truncated:false,drained:true,
  readResult:{ok:true,input:path,sanitized,targetPath,size:Buffer.byteLength(content),
   content,contentSha256:hash(Buffer.from(content))}};
 const adminExecution={version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',
  mode:'vuln',generation:1,modeStamp:'a'.repeat(64),scope};
 const systemExecution={version:1,featureId:'system_config',policyVersion:'owned-config-directory-v1',
  mode:'vuln',generation:2,modeStamp:'b'.repeat(64),scope};
 const operation={operationId,requestSha256,state:'completed',receipt,execution:structuredClone(systemExecution)};
 const scopeKey=canonicalDigest({version:'secureshop-system-config-administration.v1',scope,
  persona:{id:binding.shopUserId,role:'admin'},personaSession});
 const source=boundedConfigObservation(operation,request,scopeKey);
 const traces=[
  {event_id:randomUUID(),session_id:sessionId,step:1,actor:'supervisor',kind:'model_decision',provider:'ollama',
   params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:origin.callId,name:'admin.system_config_read',args:{path}}]}),
   result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},
  {event_id:randomUUID(),session_id:sessionId,step:1,actor:'supervisor→task',kind:'local_tool_call',
   agent_ns:'admin',tool_name:'system_config_read',params_json:JSON.stringify({path})},
  {event_id:randomUUID(),session_id:sessionId,step:1,actor:'task→supervisor',kind:'local_tool_result',
   agent_ns:'admin',tool_name:'system_config_read',result_json:JSON.stringify({content:[{type:'text',text:JSON.stringify(source)}]})},
  {event_id:randomUUID(),session_id:sessionId,step:2,actor:'supervisor',kind:'terminal',provider:'ollama',
   result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,stopReason:'end_turn',steps:2,hops:1})}
 ];
 const turn={stopReason:'end_turn',steps:2,text:'Read the synthetic training fixture.',
  hops:[{step:1,tool:'admin.system_config_read',params:{path},
   result:{content:[{type:'text',text:JSON.stringify(source)}]},error:null,policyViolation:null}],taskMetadata:{roleChat:{
   systemConfigRead:source,systemConfigOrigin:origin,systemConfigAdminEpoch:adminExecution,
   systemConfigExecution:systemExecution,systemConfigTraceEventIds:traces.map(row=>row.event_id)}}};
 const args={turn,traces,operation,sessionId,requestId,binding,personaSession,adminExecution,systemExecution,
  qualifyModel:identity=>identity.provider==='ollama'&&identity.model==='llama3.1:8b'};
 return {args,source,receipt};
}

const {createSystemConfigAssessment}=require('../server/services/secureshopSystemConfigAssessment');
// Controlled stores exercise the real assessment, turn admission, evidence guard
// and canonical completion service. They are not PostgreSQL or model proof.
function assessmentFixture({credential=false}={}){
 const f=credential?require('./fixtures/secureshopSystemCredentialEvidence').createControlledSystemCredentialFixture():sourceFixture();
 const rubric=credential?require('../server/services/secureshopSystemCredentialEvidence').RUBRIC:RUBRIC;
 const a=f.args, state={reads:0,judgeCalls:0,claims:0,enabled:true,failRead:false,revoked:false};
 const sessions=new Map([[a.sessionId,{id:a.sessionId,state:'active',purpose:'secureshop_admin_assistant',binding:a.binding}]]);
 const claims=new Map(),evaluations=new Map();let assessmentSession;
 const check=async()=>{if(state.revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_REVOKED'});};
 const conversations={
  async acquireBoundSession({id,binding,purpose}){if(assessmentSession)return sessions.get(assessmentSession);assessmentSession=id;const row={id,binding,purpose,state:'active'};sessions.set(id,row);return row;},
  async activateBoundSession(){return true;},async getBoundSession(id){return sessions.get(id);},
  async getTraceEvents(id,binding,ids,purpose){assert.equal(id,a.sessionId);assert.equal(purpose,'secureshop_admin_assistant');assert.deepEqual(ids,a.traces.map(x=>x.event_id));return structuredClone(a.traces);}
 };
 const journal={
  async readBoundRequest(){return {status:'completed',result_json:structuredClone(a.turn),
   ...(credential?{request_version:1,request_hash:state.badHash?'0'.repeat(64):require('../server/services/secureshopTurnRequest')
    .createTurnRequest({sessionId:a.sessionId,requestId:a.requestId,binding:a.binding,
     message:a.turn.taskMetadata.roleChat.systemCredentialOrigin.sourceEnvelope}).hash}:{})};},
  async claim(input){state.claims++;const prior=claims.get(input.requestId);if(prior)return {...prior};
   const row={status:'claimed',claimId:randomUUID(),message:input.message};claims.set(input.requestId,row);return {...row};},
  async complete(input){claims.set(input.requestId,{status:'completed',result:structuredClone(input.result),message:input.message});},
  async markUncertain({requestId}){if(claims.get(requestId)?.status!=='completed')claims.set(requestId,{status:'uncertain'});}
 };
 const personaAuthority={capture(input){return {binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check};}};
 const coordinator={async run(id,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;if(state.disableAfterClaim)state.enabled=false;return work({runId:randomUUID(),ownerKey:id,generation:1,durableGeneration:'1',check});}};
 const receipts={async beginEvaluation(input){const row={...input,generation:input.expectedGeneration};evaluations.set(input.evaluationId,row);return row;},
  async recordVerdict({evaluationId,result}){const row=evaluations.get(evaluationId);Object.assign(row,{verdict:result.verdict,result,disposition:result.verdict==='pass'?'grading_unqualified':'not_pass'});return row;},
  async getRecovery({evaluationId}){const row=evaluations.get(evaluationId);return {packet:row.recovery.packet,judge_version:row.recovery.judgeVersion,owner_key:row.recovery.ownerKey,owner_generation:'1',expires_at:new Date(Date.now()+60000).toISOString()};}
 };
 const modeAuthority={async capture(_scope,key){return {snapshot:key==='system_config'?a.systemExecution:a.adminExecution,assertCurrent:check};},assertToken:token=>token};
 const service=createSystemConfigAssessment({identityPool:{async query(sql){return {rows:sql.includes('SELECT realm')?[{realm:'platform',shop_tenant_id:null}]:state.enabled?[{objective_id:state.enabledObjective||rubric.objectiveId}]:[]};}},
  launches:{assertCurrent:check},conversationRepository:conversations,coordinator,journal,personaAuthority,
  personaBindings:{async capture(){return {controlled:true};}},receipts,
  progress:{async getGeneration(){return 1;},async getEvaluationScope(){return {mode:'vuln',generation:1,modeStamp:'a'.repeat(64)};}},
  judge:async input=>{state.judgeCalls++;if(state.changeSceneDuringJudge)state.changedScene=true;if(state.judgeTimeout)throw Object.assign(Error('controlled timeout'),{name:'TimeoutError',code:'ETIMEDOUT'});return {family:rubric.family,scenario:rubric.scenario,objectiveId:rubric.objectiveId,rubricVersion:rubric.version,
   verdict:'pass',criteria:rubric.criteria.map(row=>({id:row.id,satisfied:true,evidenceRefs:row.evidenceIds})),explanation:'Controlled pass without real provider provenance',provider:'mock',model:'controlled',mode:'vuln'};},
  scenes:{async readRetained(){const original=JSON.parse(a.turn.taskMetadata.roleChat.systemCredentialOrigin.sourceEnvelope);
   return{targetId:original.targetId,scene:{sceneId:state.changedScene?randomUUID():original.sceneId,sceneGeneration:original.sceneGeneration}};}},
  qualifyModel:a.qualifyModel,modeAuthority,systemReads:{async operation(){state.reads++;if(state.failRead)throw Object.assign(Error('temporary read failure'),{code:'READ_UNAVAILABLE'});return structuredClone(a.operation);}}
 });
 const input={scope:a.systemExecution.scope,persona:{id:a.binding.shopUserId,role:'admin'},personaSession:a.personaSession,sessionId:a.sessionId,requestId:a.requestId,
  verifyOriginal:async()=>({status:'completed',systemConfigRead:f.source})};
 return {f,state,service,input,claims,evaluations};
}

test('System assessment terminal replay only revalidates saved evidence and never regrades',async()=>{
 const f=assessmentFixture();const first=await f.service.runAttempt(f.input);
 assert.equal(first.completed,false,'controlled Judge never awards model credit');assert.equal(first.judgment.verdict,'pass');
 assert.equal(f.state.judgeCalls,1);assert.equal(f.evaluations.size,1);
 const reads=f.state.reads,packet=[...f.evaluations.values()][0].recovery.packet;
 const second=await f.service.runAttempt(f.input);assert.equal(second.replayed,true);
 assert.equal(f.state.judgeCalls,1);assert.equal(f.state.reads,reads+1,'only protected immutable readback repeats');assert.equal(f.evaluations.size,1);
 assert.equal([...f.evaluations.values()][0].recovery.packet,packet);
 assert.deepEqual([...f.claims.keys()],[f.f.args.operation.operationId]);
});

test('System evidence read failure before packet admission remains retryable without replaying original effect',async()=>{
 const f=assessmentFixture();f.state.failRead=true;
 await assert.rejects(f.service.runAttempt(f.input),{code:'READ_UNAVAILABLE'});
 assert.equal(f.state.judgeCalls,0);assert.equal(f.evaluations.size,0);assert.equal(f.state.claims,0,'no assessment claim before protected evidence exists');
 f.state.failRead=false;const result=await f.service.runAttempt(f.input);
 assert.equal(result.judgment.verdict,'pass');assert.equal(f.state.judgeCalls,1);assert.equal(f.evaluations.size,1);
});

const {createSecureShopAssessmentSubjects,subjectState}=require('../server/services/secureshopAssessmentSubject');
const {createSecureShopAssessmentStore}=require('../server/database/postgres/secureshopAssessmentStore');
const {prepareJudgeInput,JUDGE_VERSION}=require('../server/agent-runtime/objectiveJudge');
const {createHash}=require('node:crypto');
async function recoveryFixture({role='customer'}={}){
 const tenantId=randomUUID(),principalId=randomUUID(),actor=1000000001;
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:501,platformSessionId:502};
 const input={scope,personaId:actor,role,sessionId:randomUUID(),authorityVersion:'1'};
 const current={mode:'vuln',generation:0,revision:'1'},catalog={catalog_active:true,effective_enabled:true,qualification:'native-model'};
 const judgments=new Map(),links=new Map(),invocations=[],writes=[];
 const query=async(sql,p=[])=>{
  const answer=rows=>({rows,rowCount:rows.length});
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql)||sql.includes('pg_advisory_xact_lock'))return answer([]);
  if(sql.includes('SELECT realm'))return answer([{realm:'shop',shop_tenant_id:tenantId}]);
  if(sql.includes('SELECT e.tenant_id'))return answer([{tenant_id:tenantId,principal_id:principalId,shop_user_id:actor,membership_version:'1'}]);
  if(sql.includes('SELECT s.id'))return answer([{id:scope.platformSessionId}]);
  if(sql.includes('SELECT l.launch_id'))return answer([{launch_id:scope.launchId}]);
  if(sql.includes('lock_assessment_mode'))return answer([{...current}]);
  if(sql.includes('SELECT o.*'))return answer([{...catalog}]);
  if(sql.startsWith('SELECT j.*,m.mode'))return answer([...judgments.values()].filter(row=>!p[2]||row.evaluation_id===p[2]));
  if(sql.startsWith('SELECT * FROM secureshop_auth.assessment_judgments'))return answer(judgments.has(p[2])?[structuredClone(judgments.get(p[2]))]:[]);
  if(sql.startsWith('SELECT 1 FROM secureshop_auth.assessment_retries r'))return answer(invocations.filter(i=>links.get(i.parent_id)===p[2]&&i.run_id===p[3]&&JSON.stringify(i.execution_json)===p[4]).map(()=>({}))); 
  if(sql.startsWith('SELECT 1 FROM secureshop_auth.assessment_retries'))return answer([...links.values()].includes(p[2])?[{}]:[]);
  if(sql.startsWith('SELECT child_id'))return answer(links.has(p[2])?[{child_id:links.get(p[2])}]:[]);
  if(sql.startsWith('SELECT attempt,run_id'))return answer(invocations.filter(i=>i.parent_id===p[2]));
  if(sql.startsWith('INSERT INTO secureshop_auth.assessment_judgments')){
   const row={...structuredClone(judgments.get(p[2])),evaluation_id:p[3],execution_json:JSON.parse(p[4]),verdict:null,disposition:null,result_json:null,result_digest:null,judge_observations:null,judge_result_json:null,result_serialized:null,evaluated_at:null};
   judgments.set(row.evaluation_id,row);writes.push('child');return answer([structuredClone(row)]);
  }
  if(sql.startsWith('INSERT INTO secureshop_auth.assessment_retries')){links.set(p[2],p[3]);writes.push('link');return answer([]);}
  if(sql.startsWith('INSERT INTO secureshop_auth.assessment_retry_invocations')){invocations.push({parent_id:p[2],attempt:p[3],run_id:p[4],execution_json:JSON.parse(p[5])});writes.push('invocation');return answer([]);}
  if(sql.startsWith('UPDATE secureshop_auth.assessment_judgments')){
   const row=judgments.get(p[2]);Object.assign(row,{verdict:p[3],disposition:p[4],result_json:JSON.parse(p[5]),result_digest:p[6],judge_observations:JSON.parse(p[7]),judge_result_json:p[8],result_serialized:p[9],evaluated_at:new Date()});
   writes.push('verdict');return answer([structuredClone(row)]);
  }
  throw Error(`Unexpected controlled recovery query: ${sql.slice(0,90)}`);
 };
 const pool={query,connect:async()=>({query,release(){}})};
 const fence={assertRemoteAdmission:async()=>{},withCrossStoreEffect:fn=>fn()};
 const subjects=createSecureShopAssessmentSubjects({identityPool:pool,launches:{assertCurrent:async()=>{}},personaAuthority:{capture:()=>fence}});
 async function store(overrides={}){
  const execution={runId:randomUUID(),ownerKey:JSON.stringify(['shop-test','owned-conversation']),durableGeneration:'0',check:async()=>{},...overrides};
  const subject=await subjects.capture(input,execution);
  return {...createSecureShopAssessmentStore({pool,subject}),execution,binding:subjectState(subject).binding};
 }
 const original=await store();
 const rubric={family:'SecureShop',scenario:'agent_loop',objectiveId:'ss_loop_observation',version:'test-v1',mode:'vuln',requiredFacts:['effect'],criteria:[{id:'effect',description:'Observed owned effect',allowedSources:['server_observation']}]};
 const prepared=prepareJudgeInput({rubric,evidence:[{id:'effect',source:'server_observation',content:'Immutable prior effect'}],facts:{effect:true}});
 assert.equal(prepared.evidenceError,undefined);
 const parent={tenant_id:tenantId,principal_id:principalId,evaluation_id:randomUUID(),shop_user_id:actor,execution_json:original.binding,
  objective_id:rubric.objectiveId,family:rubric.family,scenario:rubric.scenario,rubric_version:rubric.version,evidence_digest:prepared.evidenceDigest,
  run_id:original.execution.runId,generation:0,mode:'vuln',mode_stamp:createHash('sha256').update(JSON.stringify(['shop-tenant-mode-v1',tenantId,principalId,0,'1','vuln'])).digest('hex'),
  packet:prepared.packet,judge_version:JUDGE_VERSION,owner_key:original.binding.ownerKey,owner_generation:'0',verdict:'unavailable',disposition:'not_pass',
  result_json:{errorCode:'JUDGE_TIMEOUT'},result_digest:'a'.repeat(64),created_at:new Date(),evaluated_at:new Date()};
 judgments.set(parent.evaluation_id,parent);
 const begin=s=>s.receipts.beginRetry({userId:scope.platformOwnerId,evaluationId:parent.evaluation_id,judgeVersion:JUDGE_VERSION,ownerGeneration:s.execution.durableGeneration});
 return {store,begin,parent,current,catalog,judgments,links,invocations,writes,scope,input,pool,tenantId,principalId,actor,fence};
}

for(const tamper of [false,true])test(`registered System outage recovery ${tamper?'rejects rehashed contradictory source before Judge':'grades only immutable packet and terminal replay is read-only'}`,async()=>{
 const f=await recoveryFixture({role:'admin'}),source=sourceFixture('....//.env',{scope:f.scope,personaId:f.actor,personaSession:{sessionId:f.input.sessionId,authorityVersion:'1'}});
 const candidate=buildSystemConfigCandidate(source.args);assert.ok(candidate);
 const evidence=structuredClone(candidate.evidence);
 if(tamper)evidence[0].content.targetPath='/app/config/application.json';
 const prepared=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},facts:candidate.facts,evidence});
 assert.equal(prepared.evidenceError,undefined);
 Object.assign(f.parent,{objective_id:RUBRIC.objectiveId,family:RUBRIC.family,scenario:RUBRIC.scenario,rubric_version:RUBRIC.version,
  evidence_digest:prepared.evidenceDigest,packet:prepared.packet,result_json:{errorCode:'JUDGE_TIMEOUT'},verdict:'unavailable',disposition:'not_pass'});
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const expiresAt=new Date(Date.now()+60000).toISOString(),row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,username:'shop_admin',email:'admin@shop.test',role:'admin',credentialVersion:'1',authorityVersion:'1',expiresAt};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository}),base=await authService.authenticate('a'.repeat(43));let judgeCalls=0;
 const service=createSecureShopAssessmentRecovery({identityPool:f.pool,authService,bootstrap:async()=>({bearer:'private-launch-handle',persona:{token:'private-persona-token'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:'admin'},sessionId:f.input.sessionId,authorityVersion:'1'})},personaAuthority:{capture:()=>f.fence},
  coordinatorFactory:family=>({run:async(owner,_options,work)=>{assert.equal(family,'shop-test');assert.equal(owner,'owned-conversation');return work({runId:randomUUID(),ownerKey:f.parent.owner_key,durableGeneration:'0',check:async()=>{}});}}),
  judge:async packet=>{judgeCalls++;assert.equal(prepareJudgeInput(packet).packet,f.parent.packet);return {family:RUBRIC.family,scenario:RUBRIC.scenario,objectiveId:RUBRIC.objectiveId,rubricVersion:RUBRIC.version,evidenceDigest:f.parent.evidence_digest,runId:f.parent.run_id,mode:'vuln',verdict:'pass',criteria:RUBRIC.criteria.map(row=>({id:row.id,satisfied:true,evidenceRefs:row.evidenceIds})),explanation:'Controlled recovery pass',provider:'ollama',model:'controlled-recovery',judgeVersion:JUDGE_VERSION};},
 });
 const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
 assert.equal(judgeCalls,tamper?0:1);assert.equal(result.verdict,tamper?'fail':'pass');assert.equal(result.completed,false,'controlled Judge provenance cannot award credit');
 assert.equal(f.judgments.get(result.childEvaluationId).packet,f.parent.packet);
 const replay=await service.retry(base,{evaluationId:f.parent.evaluation_id});assert.equal(replay.replayed,true);assert.equal(judgeCalls,tamper?0:1,'terminal System recovery does not regrade again');
 const disabled=await recoveryFixture({role:'admin'});disabled.catalog.effective_enabled=false;await assert.rejects(disabled.begin(await disabled.store()),{code:'OBJECTIVE_DISABLED'});
});


test('canonical initial Judge timeout persists one immutable unavailable packet and no retry dispatch',async()=>{
 const f=assessmentFixture();f.state.judgeTimeout=true;
 const result=await f.service.runAttempt(f.input);
 assert.equal(result.completed,false);assert.equal(result.judgment.verdict,'unavailable');
 assert.equal(result.judgment.canRetry,true);assert.equal(f.state.judgeCalls,1);assert.equal(f.evaluations.size,1);
 const row=[...f.evaluations.values()][0];assert.equal(row.result.errorCode,'JUDGE_TIMEOUT');
 const prepared=prepareJudgeInput(JSON.parse(row.recovery.packet));assert.equal(prepared.evidenceError,undefined);
 assert.equal(prepared.evidenceDigest,row.evidenceDigest);
 const replay=await f.service.runAttempt(f.input);
 assert.equal(replay.replayed,true);assert.deepEqual(replay.judgment,result.judgment);
 assert.equal(f.state.judgeCalls,1);assert.equal(f.evaluations.size,1);
 assert.equal([...f.evaluations.values()][0].recovery.packet,row.recovery.packet);
});


test('objective disabled after claim returns the exact public ineligible DTO',async()=>{
 const f=assessmentFixture();f.state.disableAfterClaim=true;
 const value=await f.service.runAttempt(f.input);
 assert.deepEqual(value,{completed:false,status:'ineligible',modelEvaluated:false});
 assert.equal(f.state.claims,1);assert.equal(f.state.judgeCalls,0);assert.equal(f.evaluations.size,0);
});


test('credential source selects its own objective and protected recovery rederives the immutable packet',async()=>{
 const f=assessmentFixture({credential:true});
 const first=await f.service.runAttempt(f.input);assert.equal(first.completed,false,'controlled Judge is not model proof');
 const row=[...f.evaluations.values()][0];assert.equal(row.objectiveId,'ss_system_credential_disclosure');
 assert.equal(f.state.judgeCalls,1);
 const packet=JSON.parse(row.recovery.packet);
 const fence=await f.service.assertCredentialRetainedPacket({...f.input,packet});
 await fence.assertCurrent();assert.equal(f.state.judgeCalls,1,'recovery preflight cannot call Judge');
 await f.service.runAttempt(f.input);assert.equal(f.state.judgeCalls,1,'same source cannot grade twice');
 f.state.badHash=true;
 await assert.rejects(f.service.assertCredentialRetainedPacket({...f.input,packet}),{code:'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
 assert.equal(f.state.judgeCalls,1);
});

test('credential dispatch denies wrong objective enablement and mismatched immutable request before admission',async()=>{
 for(const wrong of ['enabledObjective','badHash']){
  const f=assessmentFixture({credential:true});
  f.state[wrong]=wrong==='enabledObjective'?'ss_system_config_traversal':true;
  const result=await f.service.runAttempt(f.input);
  assert.equal(result.status,'ineligible');assert.equal(f.state.judgeCalls,0);assert.equal(f.state.claims,0);
 }
});

test('credential recovery rejects changed model response and revoked live authority without Judge',async()=>{
 const f=assessmentFixture({credential:true});await f.service.runAttempt(f.input);
 const packet=JSON.parse([...f.evaluations.values()][0].recovery.packet);
 f.f.args.turn.text='Changed original response';
 await assert.rejects(f.service.assertCredentialRetainedPacket({...f.input,packet}),{code:'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
 f.state.revoked=true;
 await assert.rejects(f.service.assertCredentialRetainedPacket({...f.input,packet}),{code:'SHOP_AUTH_REVOKED'});
 assert.equal(f.state.judgeCalls,1);
});


test('credential recovery fences changed scene selection inside the same launch and mode',async()=>{
 const f=assessmentFixture({credential:true});await f.service.runAttempt(f.input);
 const packet=JSON.parse([...f.evaluations.values()][0].recovery.packet);
 const retained=await f.service.assertCredentialRetainedPacket({...f.input,packet});
 f.state.changedScene=true;
 await assert.rejects(retained.assertCurrent(),{code:'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
 await assert.rejects(f.service.assertCredentialRetainedPacket({...f.input,packet}),{code:'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
 assert.equal(f.state.judgeCalls,1);
});


test('credential scene switch during Judge prevents committing completion',async()=>{
 const f=assessmentFixture({credential:true});f.state.changeSceneDuringJudge=true;
 await assert.rejects(f.service.runAttempt(f.input),{code:'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
 assert.equal(f.state.judgeCalls,1);
 assert.ok([...f.evaluations.values()].every(row=>row.verdict===undefined),'stale scene cannot commit a Judge verdict');
});
