'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {createSecureShopAssessmentSubjects,subjectState}=require('../server/services/secureshopAssessmentSubject');
const {createSecureShopAssessmentStore}=require('../server/database/postgres/secureshopAssessmentStore');
const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
const {prepareJudgeInput,JUDGE_VERSION}=require('../server/agent-runtime/objectiveJudge');
const {createRolePolicyProposal}=require('../server/services/secureshopRolePolicyProposal');
const render=require('../server/services/secureshopPromptPolicyContract');
const {RUBRIC,buildPolicyTemplateCandidate,projectPolicyTemplateCandidate}=require('../server/services/secureshopPolicyTemplateEvidence');
const searchEchoEvidence=require('../server/services/secureshopSearchEchoBrowserEvidence');
const {fixture:searchEchoFixture}=require('./secureshopSearchEchoBrowserEvidence.test');
const {captureFor:searchEchoDomCapture}=require('./secureshopSearchEchoBrowserV8.test');
const {fixture:manualRagSourceFixture}=require('./secureshopManualRagSourceContract.test');
const {validateManualRagSourceContract}=require('../server/services/secureshopManualRagSourceContract');
const manualRagEvidence=require('../server/services/secureshopManualRagEvidence');
const idorEvidence=require('../server/services/secureshopIdorLessonEvidence');

// Controlled SQL adapter tests exercise the production admission/Judge wrapper.
// PostgreSQL constraints, concurrency and real-provider credit need native proof.
async function fixture({role='customer'}={}){
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

async function recoveryContext(f,{role='customer'}={}){
 const retryRuns=[];
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,
  username:'customer',email:'customer@shop.test',role,credentialVersion:'1',
  authorityVersion:'1',expiresAt:new Date(Date.now()+60000).toISOString()};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin',
  'createSession','rotateSession','revokeSession','readCredentialForSession','changePassword',
  'revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,
  ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,
  tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository});
 return {base:await authService.authenticate('a'.repeat(43)),deps:{identityPool:f.pool,authService,
  bootstrap:async()=>({bearer:'private',persona:{token:'private'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},
  personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role},
    sessionId:f.input.sessionId,authorityVersion:'1'})},personaAuthority:{capture:()=>f.fence},
  coordinatorFactory:()=>({run:async(_owner,_options,work)=>{
   const runId=randomUUID();retryRuns.push(runId);
   return work({runId,ownerKey:f.parent.owner_key,durableGeneration:'0',check:async()=>{}});
  }})},retryRuns};
}

test('historical V12 order packets stay visible but cannot start a new Judge retry',async()=>{
 const f=await fixture({role:'customer'});
 const {base,deps}=await recoveryContext(f);
 let judgeCalls=0;
 const service=require('../server/services/secureshopAssessmentRecovery')
  .createSecureShopAssessmentRecovery({...deps,judge:async()=>{judgeCalls++;
   throw Error('Historical order rubric reached Judge');}});
 for(const version of [idorEvidence.IDOR_LESSON_LEGACY_VERSION,
  idorEvidence.IDOR_LESSON_PREVIOUS_VERSION,idorEvidence.IDOR_LESSON_VERSION]){
  const evidence=[{id:'idor_request',source:'server_observation',content:'historical'},
   {id:'idor_birth',source:'server_observation',content:'historical'},
   {id:'idor_effect',source:'server_observation',content:'historical'}];
  if(version!==idorEvidence.IDOR_LESSON_LEGACY_VERSION)evidence.push(
   {id:'idor_effect_excerpt',source:'server_observation',content:'historical'});
  evidence.push({id:'idor_response',source:'assistant_response',content:'historical'});
  const historical=prepareJudgeInput({rubric:{...idorEvidence.idorLessonRubric(
   'order_status',version),mode:'vuln'},
  facts:Object.fromEntries(idorEvidence.IDOR_LESSON_FACTS.map(key=>[key,true])),evidence});
  assert.equal(historical.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:idorEvidence.IDOR_LESSON_OBJECTIVES.order_status,
   family:historical.rubric.family,scenario:historical.rubric.scenario,
   rubric_version:historical.rubric.version,packet:historical.packet,
   evidence_digest:historical.evidenceDigest});
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'RETRY_NOT_ALLOWED'});
  assert.equal(judgeCalls,0);assert.deepEqual(f.writes,[]);
  f.parent.rubric_version=idorEvidence.IDOR_LESSON_ORDER_VERSION;
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'RETRY_NOT_ALLOWED'},'relabeling a historical packet cannot bypass the fence');
  assert.equal(judgeCalls,0);assert.deepEqual(f.writes,[]);
 }
});

function policyPacket(f){
 const binding={...f.scope,shopUserId:f.actor,role:'admin'},source={sessionId:randomUUID(),requestId:randomUUID()};
 const capability={version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'admin_assistant'}};
 const proposal=createRolePolicyProposal({source,origin:{step:1,callId:'policy-call'},action:'create',selected:null,before:null,
  after:{markdown:'{{ owned_policy_effect() }}',targets:['customer']},name:'Owned policy',expectedVersion:'3',scopeKey:'a'.repeat(64),modeCapability:capability},['admin','customer','merchant']);
 const request={operationId:proposal.proposalId,name:proposal.name,...proposal.after},execution={version:1,featureId:'policy',policyVersion:'owned-policy-literal-render-v1',mode:'vuln',generation:0,modeStamp:'policy-mode',scope:{launchId:f.scope.launchId,scenarioId:f.scope.scenarioId,generation:1,platformOwnerId:f.scope.platformOwnerId,platformSessionId:f.scope.platformSessionId}};
 const rendered='controlled rendered owned policy',result=render.validateRenderExecutionResult({version:2,mode:'vuln',request},{version:2,kind:'isolated_template',operationId:request.operationId,requestSha256:render.requestDigest(request),executionSha256:render.renderExecutionDigest({version:2,mode:'vuln',request}),rendered,renderedSha256:createHash('sha256').update(rendered).digest('hex'),isolation:render.ISOLATION,exitCode:0,timedOut:false,truncated:false,drained:true,effectWitness:{version:1,workerAttested:true,commandEffectObserved:true,effectSha256:'b'.repeat(64),compilerSha256:render.COMPILER_SHA256,workerSha256:render.WORKER_SHA256}});
 const publication={operationId:proposal.proposalId,action:'upsert',expectedVersion:'3',request,execution,receipt:{version:'4',operationId:proposal.proposalId,requestSha256:render.requestDigest(request),renderResult:result},revision:{name:proposal.name,version:'4',action:'upsert',payload:{markdown:request.markdown,targets:request.targets,rendered:result.rendered,renderedSha256:result.renderedSha256},payloadSha256:createHash('sha256').update(JSON.stringify({markdown:request.markdown,targets:request.targets,rendered:result.rendered,renderedSha256:result.renderedSha256})).digest('hex')}};
 const selected={event_id:randomUUID(),session_id:source.sessionId,step:1,actor:'supervisor',kind:'model_decision',provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'policy-call',name:'admin.policy_create_prepare',args:{name:proposal.name,...proposal.after}}]}),result_json:JSON.stringify({model:'controlled-model',mocked:false,fallback:false})};
 const observed={event_id:randomUUID(),session_id:source.sessionId,step:1,actor:'task→supervisor',kind:'local_tool_result',agent_ns:'admin',tool_name:'policy_create_prepare',params_json:null,result_json:JSON.stringify({content:[{type:'text',text:JSON.stringify({status:'prepared',proposalId:proposal.proposalId,action:'create',name:proposal.name,requestSha256:proposal.requestSha256})}]})};
 const terminal={event_id:randomUUID(),session_id:source.sessionId,step:2,actor:'supervisor',kind:'terminal',provider:'ollama',params_json:null,result_json:JSON.stringify({model:'controlled-model',mocked:false,fallback:false,stopReason:'end_turn',steps:2,hops:1})};
 const candidate=buildPolicyTemplateCandidate({proposal,publication,traces:[selected,observed,terminal],turn:{stopReason:'end_turn',steps:2,hops:[{}]},sessionId:source.sessionId,requestId:source.requestId,binding,personaSession:{sessionId:f.input.sessionId,authorityVersion:'1'},allowedTargets:['admin','customer','merchant'],policyExecution:execution,qualifyModel:row=>row.provider==='ollama'&&row.model==='controlled-model'});
 assert.ok(candidate);return prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},facts:projectPolicyTemplateCandidate(candidate).facts,evidence:projectPolicyTemplateCandidate(candidate).evidence});
}

test('instructor-enabled policy template recovery regrades the same guarded packet without publication or actor work',async()=>{
 const f=await fixture({role:'admin'}),prepared=policyPacket(f);
 assert.equal(prepared.evidenceError,undefined);
 Object.assign(f.parent,{objective_id:RUBRIC.objectiveId,family:RUBRIC.family,scenario:RUBRIC.scenario,rubric_version:RUBRIC.version,
  evidence_digest:prepared.evidenceDigest,packet:prepared.packet,result_json:{errorCode:'JUDGE_TIMEOUT'},verdict:'unavailable',disposition:'not_pass'});
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const expiresAt=new Date(Date.now()+60000).toISOString(),row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,username:'shop_admin',email:'admin@shop.test',role:'admin',credentialVersion:'1',authorityVersion:'1',expiresAt};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository}),base=await authService.authenticate('a'.repeat(43));let judgeCalls=0,actorCalls=0,publicationCalls=0;
 const service=createSecureShopAssessmentRecovery({identityPool:f.pool,authService,bootstrap:async()=>({bearer:'private-launch-handle',persona:{token:'private-persona-token'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:'admin'},sessionId:f.input.sessionId,authorityVersion:'1'})},personaAuthority:{capture:()=>f.fence},
  coordinatorFactory:family=>({run:async(owner,_options,work)=>{assert.equal(family,'shop-test');assert.equal(owner,'owned-conversation');return work({runId:randomUUID(),ownerKey:f.parent.owner_key,durableGeneration:'0',check:async()=>{}});}}),
  judge:async packet=>{judgeCalls++;assert.equal(prepareJudgeInput(packet).packet,f.parent.packet);return {family:RUBRIC.family,scenario:RUBRIC.scenario,objectiveId:RUBRIC.objectiveId,rubricVersion:RUBRIC.version,evidenceDigest:f.parent.evidence_digest,runId:f.parent.run_id,mode:'vuln',verdict:'pass',criteria:RUBRIC.criteria.map(row=>({id:row.id,satisfied:true,evidenceRefs:row.evidenceIds})),explanation:'Controlled recovery pass',provider:'ollama',model:'controlled-recovery',judgeVersion:JUDGE_VERSION};},
 });
 const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
 assert.equal(judgeCalls,1);assert.equal(result.verdict,'pass');assert.equal(result.completed,false,'controlled Judge provenance cannot award credit');
 assert.equal(actorCalls,0);assert.equal(publicationCalls,0);assert.equal(f.judgments.get(result.childEvaluationId).packet,f.parent.packet);
 const replay=await service.retry(base,{evaluationId:f.parent.evaluation_id});assert.equal(replay.replayed,true);assert.equal(judgeCalls,1,'terminal policy recovery does not regrade again');
 const disabled=await fixture({role:'admin'});disabled.catalog.effective_enabled=false;await assert.rejects(disabled.begin(await disabled.store()),{code:'OBJECTIVE_DISABLED'});
});

test('retained Judge retry creates one child, keeps original evidence/run, and injected pass earns no credit',async()=>{
 const f=await fixture(),s=await f.store();let calls=0;
 const judge=async packet=>{calls++;assert.equal(packet.execution.runId,f.parent.run_id);assert.equal(prepareJudgeInput(packet).packet,f.parent.packet);
  return {family:f.parent.family,scenario:f.parent.scenario,objectiveId:f.parent.objective_id,rubricVersion:f.parent.rubric_version,
   evidenceDigest:f.parent.evidence_digest,runId:f.parent.run_id,mode:'vuln',verdict:'pass',criteria:[{id:'effect',satisfied:true,evidenceRefs:['effect']}],explanation:'Controlled pass',provider:'ollama',model:'fixture',judgeVersion:JUDGE_VERSION};};
 const completion=createObjectiveCompletionService({receipts:s.receipts,progress:s.progress,judge:p=>s.observeJudge(p,judge)});
 const first=await completion.retry({userId:f.scope.platformOwnerId,evaluationId:f.parent.evaluation_id,execution:s.execution});
 assert.equal(calls,1);assert.equal(first.completed,false);assert.equal(first.receipt.disposition,'grading_unqualified');assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 assert.equal(f.judgments.get(first.receipt.evaluationId).packet,f.parent.packet);
 const replayStore=await f.store(),replay=createObjectiveCompletionService({receipts:replayStore.receipts,progress:replayStore.progress,judge:()=>{throw Error('Terminal replay invoked Judge');}});
 const second=await replay.retry({userId:f.scope.platformOwnerId,evaluationId:f.parent.evaluation_id,execution:replayStore.execution});
 assert.equal(second.replayed,true);assert.equal(second.receipt.evaluationId,first.receipt.evaluationId);assert.equal(f.invocations.length,1);
 const saved=f.judgments.get(first.receipt.evaluationId);saved.result_json.explanation='tampered';
 await assert.rejects(replay.retry({userId:f.scope.platformOwnerId,evaluationId:f.parent.evaluation_id,execution:replayStore.execution}),{code:'JUDGMENT_INTEGRITY'});
});

test('standalone Audit recovery gives the Judge a bounded deadline and returns no private authority',async()=>{
 const f=await fixture();
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const {createSecureShopAuditTiming}=require('../server/services/secureshopAuditTiming');
 const expiresAt=new Date(Date.now()+60000).toISOString();
 const row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,username:'shop_actor',email:'actor@shop.test',role:'customer',credentialVersion:'1',authorityVersion:'1',expiresAt};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository}),base=await authService.authenticate('a'.repeat(43));
 const old=JSON.parse(f.parent.packet);old.rubric.scenario='bound_audit_summary';old.rubric.objectiveId='ss_audit_instruction_followed';
 const prepared=prepareJudgeInput(old);assert.equal(prepared.evidenceError,undefined);
 Object.assign(f.parent,{scenario:old.rubric.scenario,objective_id:old.rubric.objectiveId,packet:prepared.packet,evidence_digest:prepared.evidenceDigest});
 let calls=0,timeout;
 const service=createSecureShopAssessmentRecovery({identityPool:f.pool,authService,
  bootstrap:async()=>({bearer:'private-launch-handle',persona:{token:'private-persona-token'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},
  personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:'customer'},sessionId:f.input.sessionId,authorityVersion:'1'})},
  personaAuthority:{capture:()=>f.fence},
  coordinatorFactory:family=>({run:async(owner,options,work)=>{assert.equal(family,'shop-test');assert.equal(owner,'owned-conversation');timeout=options.timeoutMs;
   return work({runId:randomUUID(),ownerKey:f.parent.owner_key,durableGeneration:'0',check:async()=>{}});}}),
  judge:async packet=>{calls++;assert.ok(Number.isFinite(packet.execution.auditDeadline));
   assert.ok(createSecureShopAuditTiming().remainingJudgeMs(packet.execution.auditDeadline)>0);
   return {family:f.parent.family,scenario:f.parent.scenario,objectiveId:f.parent.objective_id,rubricVersion:f.parent.rubric_version,
    evidenceDigest:f.parent.evidence_digest,runId:f.parent.run_id,mode:'vuln',verdict:'unavailable',criteria:[],explanation:'Controlled timeout',errorCode:'JUDGE_TIMEOUT',provider:null,model:null};},
 });
 const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
 assert.equal(calls,1);assert.equal(timeout,createSecureShopAuditTiming().runTimeoutMs);
 assert.deepEqual(Object.keys(result).sort(),['childEvaluationId','completed','disposition','evaluationId','replayed','verdict']);
 assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
});

test('pending recovery admits at most three distinct runs and never creates another child',async()=>{
 const f=await fixture(),a=await f.store();const first=await f.begin(a),again=await f.begin(a);
 assert.equal(first.receipt.evaluationId,again.receipt.evaluationId);assert.equal(f.invocations.length,1);
 for(let n=0;n<2;n++){const result=await f.begin(await f.store());assert.equal(result.receipt.evaluationId,first.receipt.evaluationId);}
 await assert.rejects(f.begin(await f.store()),{code:'RETRY_EXHAUSTED'});
 assert.equal(f.invocations.length,3);assert.equal(f.links.size,1);assert.equal(f.writes.filter(x=>x==='child').length,1);
});

test('recovery rejects changed authority, mode, generation, catalog, version and expired packets before child creation',async t=>{
 for(const [label,mutate,code] of [
  ['session',f=>{f.parent.execution_json={...f.parent.execution_json,personaSessionId:randomUUID()};},'SHOP_ASSESSMENT_STALE'],
  ['owner generation',f=>{f.parent.owner_generation='1';},'SHOP_ASSESSMENT_STALE'],
  ['mode',f=>{f.current.mode='fixed';},'MODE_CHANGED'],
  ['generation',f=>{f.current.generation=1;},'STALE_GENERATION'],
  ['disabled',f=>{f.catalog.effective_enabled=false;},'OBJECTIVE_DISABLED'],
  ['pending qualification',f=>{f.catalog.qualification='pending';},'RETRY_NOT_ALLOWED'],
  ['judge version',f=>{f.parent.judge_version='old';},'JUDGE_VERSION_CHANGED'],
  ['expired',f=>{f.parent.created_at=new Date(Date.now()-86400001);},'EVIDENCE_EXPIRED'],
  ['packet',f=>{f.parent.packet=f.parent.packet.replace('Immutable prior effect','Different effect');},'BAD_REQUEST'],
 ])await t.test(label,async()=>{const f=await fixture();mutate(f);await assert.rejects(f.begin(await f.store()),{code});assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);});
});

test('V43 retained recovery rejects contradictory immutable packet before configured Judge',async()=>{
 const f=await fixture({role:'admin'});
 const {RUBRIC:rubric}=require('../server/services/secureshopMcpImpersonationEvidence');
 const binding={...f.scope,shopUserId:f.actor,role:'admin'};
 const execution={version:1,featureId:'registered_mcp',policyVersion:'registered-schema-approval-v1',mode:'vuln',generation:0,modeStamp:'a'.repeat(64),scope:f.scope};
 let live=structuredClone(execution);
 const modeAuthority={capture:async()=>({snapshot:structuredClone(live),assertCurrent:async()=>{assert.deepEqual(live,execution);}}),assertToken:value=>value};
 const prepared=prepareJudgeInput({rubric:{...rubric,mode:'vuln'},facts:Object.fromEntries(rubric.requiredFacts.map(key=>[key,true])),
  evidence:[{id:'mcp_registry_publication',source:'server_observation',content:{entryId:randomUUID(),proofSha256:'a'.repeat(64)}},
    {id:'mcp_invocation',source:'server_observation',content:{proof:{forged:true,binding,execution},proofSha256:'b'.repeat(64)}}]});
 assert.equal(prepared.evidenceError,undefined);
 Object.assign(f.parent,{objective_id:rubric.objectiveId,family:rubric.family,scenario:rubric.scenario,rubric_version:rubric.version,
  evidence_digest:prepared.evidenceDigest,packet:prepared.packet,live_mode:'vuln',live_generation:0,live_revision:'1',
  live_owner_generation:'0',catalog_active:true,enabled:true,qualification:'native-model',is_child:false,retry_count:0});
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,username:'shop_admin',email:'admin@shop.test',role:'admin',credentialVersion:'1',authorityVersion:'1',expiresAt:new Date(Date.now()+60000).toISOString()};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository}),base=await authService.authenticate('a'.repeat(43));let judgeCalls=0;
 const service=createSecureShopAssessmentRecovery({identityPool:f.pool,authService,modeAuthority,bootstrap:async()=>({bearer:'private',persona:{token:'private'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:'admin'},sessionId:f.input.sessionId,authorityVersion:'1'})},personaAuthority:{capture:()=>f.fence},
  coordinatorFactory:()=>({run:async(_owner,_options,work)=>work({runId:randomUUID(),ownerKey:f.parent.owner_key,durableGeneration:'0',check:async()=>{}})}),
  judge:async()=>{judgeCalls++;throw Error('Malformed evidence reached configured Judge');}});
 for(const changed of [{...execution,mode:'fixed'},{...execution,generation:1},{...execution,modeStamp:'b'.repeat(64)}]){
  live=changed;
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.equal(judgeCalls,0);assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);
  assert.equal(f.current.mode,'vuln','global mode remains vulnerable');
 }
 live=structuredClone(execution);
 assert.equal((await service.list(base)).judgments[0].canRetry,false,'malformed same-epoch packet is not advertised');
 assert.equal(f.links.size,0);assert.equal(judgeCalls,0);
 const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
 assert.equal(judgeCalls,0);assert.equal(result.completed,false);assert.equal(result.verdict,'fail');
 assert.equal(f.judgments.get(result.childEvaluationId).packet,f.parent.packet);
 const replay=await service.retry(base,{evaluationId:f.parent.evaluation_id});assert.equal(replay.replayed,true);assert.equal(judgeCalls,0);
});

test('V43 feature epoch change during Judge denies verdict persistence',async()=>{
 const f=await fixture({role:'admin'});
 const {RUBRIC:rubric,projectMcpImpersonationCandidate}=require('../server/services/secureshopMcpImpersonationEvidence');
 const binding={...f.scope,shopUserId:f.actor,role:'admin'};
 const execution={version:1,featureId:'registered_mcp',policyVersion:'registered-schema-approval-v1',mode:'vuln',generation:0,modeStamp:'a'.repeat(64),scope:f.scope};
 let live=structuredClone(execution);
 const modeAuthority={capture:async()=>({snapshot:structuredClone(live),assertCurrent:async()=>{if(JSON.stringify(live)!==JSON.stringify(execution))throw Object.assign(Error('Changed feature epoch'),{code:'SECURESHOP_FEATURE_MODE_STALE'});}}),assertToken:value=>value};
 const requestId=randomUUID(),callId='owned-call';
 const proof={binding,execution,entryId:randomUUID(),trustedVersion:'1',replacementVersion:'2',
  replacementOperationId:randomUUID(),invocationId:randomUUID(),runId:randomUUID(),requestId,callId,
  schemaSha256:'c'.repeat(64),remoteReceiptSha256:'d'.repeat(64),effectKey:`${requestId}:${JSON.stringify([1,callId,'owned_a.tool_0'])}`};
 const receiptDigest=require('../server/services/secureshopOwnedMcpInvocationContract').digest;
 const selectedArgs={query:'owned training catalog'},attackerResult={peer:'attacker',query:selectedArgs.query,catalog:[{name:'Owned synthetic catalog entry'}]};
 Object.assign(proof,{registryName:'catalog',trustedEndpoint:'http://benign.training/mcp',replacementEndpoint:'http://attacker.training:8080/mcp',
  trustedSchemaSha256:'e'.repeat(64),selectedTool:'search_catalog',selectedAlias:`owned_${proof.entryId.replaceAll('-','')}.tool_0`,
  selectedArgs,argumentsSha256:receiptDigest(selectedArgs),resultSha256:'f'.repeat(64),attackerResult,
  attackerResultSha256:receiptDigest(attackerResult)});
 proof.invocationResult={content:[{type:'text',text:JSON.stringify(attackerResult)}]};
 proof.resultSha256=receiptDigest(proof.invocationResult);
 proof.effectKey=`${requestId}:${JSON.stringify([1,callId,proof.selectedAlias])}`;
 const candidate=projectMcpImpersonationCandidate(proof);
 const prepared=prepareJudgeInput({rubric:{...rubric,mode:'vuln'},...candidate});
 assert.equal(prepared.evidenceError,undefined);
 Object.assign(f.parent,{objective_id:rubric.objectiveId,family:rubric.family,scenario:rubric.scenario,rubric_version:rubric.version,
  evidence_digest:prepared.evidenceDigest,packet:prepared.packet,live_mode:'vuln',live_generation:0,live_revision:'1',
  live_owner_generation:'0',catalog_active:true,enabled:true,qualification:'native-model',is_child:false,retry_count:0});
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,username:'shop_admin',email:'admin@shop.test',role:'admin',credentialVersion:'1',authorityVersion:'1',expiresAt:new Date(Date.now()+60000).toISOString()};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository}),base=await authService.authenticate('a'.repeat(43));let judgeCalls=0;
 const service=createSecureShopAssessmentRecovery({identityPool:f.pool,authService,modeAuthority,bootstrap:async()=>({bearer:'private',persona:{token:'private'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:'admin'},sessionId:f.input.sessionId,authorityVersion:'1'})},personaAuthority:{capture:()=>f.fence},
  coordinatorFactory:()=>({run:async(_owner,_options,work)=>work({runId:randomUUID(),ownerKey:f.parent.owner_key,durableGeneration:'0',check:async()=>{}})}),
  judge:async()=>{judgeCalls++;live={...execution,modeStamp:'b'.repeat(64)};throw Error('Controlled provider unavailable');}});
 assert.equal((await service.list(base)).judgments[0].canRetry,true);
 for(const changed of [{...execution,mode:'fixed'},{...execution,generation:1},{...execution,modeStamp:'b'.repeat(64)}]){
  live=changed;assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.equal(judgeCalls,0);assert.equal(f.links.size,0);
 }
 live=structuredClone(execution);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(judgeCalls,1);assert.equal(f.links.size,1);
 assert.equal(f.writes.includes('verdict'),false,'changed epoch cannot persist a verdict or award');
 assert.equal(f.current.mode,'vuln');
});

test('coupon recovery requires a current read-only evidence fence before retry admission',async()=>{
 const f=await fixture();
 Object.assign(f.parent,{objective_id:'ss_sqli_coupon',live_mode:'vuln',live_generation:0,live_revision:'1',
  live_owner_generation:'0',catalog_active:true,enabled:true,qualification:'native-model',is_child:false,retry_count:0});
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,username:'customer',email:'customer@shop.test',role:'customer',credentialVersion:'1',authorityVersion:'1',expiresAt:new Date(Date.now()+60000).toISOString()};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository}),base=await authService.authenticate('a'.repeat(43));
 let checks=0,judgeCalls=0,stale=false;
 const deps={identityPool:f.pool,authService,bootstrap:async()=>({bearer:'private',persona:{token:'private'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:'customer'},sessionId:f.input.sessionId,authorityVersion:'1'})},personaAuthority:{capture:()=>f.fence},
  judge:async()=>{judgeCalls++;throw Error('Must not invoke Judge');},qualifyCouponModel:()=>true};
 const absent=createSecureShopAssessmentRecovery(deps);
 if(!require('../server/config/secureshopCurriculum').isAssessmentReleaseAllowed(f.parent.objective_id)){
  assert.equal((await absent.list(base)).judgments[0].canRetry,false);
  await assert.rejects(absent.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'RETRY_NOT_ALLOWED'});
  assert.equal(judgeCalls,0);assert.equal(reads,0);assert.deepEqual(f.writes,[]);return;
 }
 assert.equal((await absent.list(base)).judgments[0].canRetry,false);
 await assert.rejects(absent.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 const service=createSecureShopAssessmentRecovery({...deps,couponAssessment:{async assertRetainedPacket(input){
  assert.deepEqual(input.packet,JSON.parse(f.parent.packet));assert.deepEqual(input.scope,f.scope);
  assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
  assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
  return {async assertCurrent(){checks++;if(stale)throw Object.assign(Error('SQL receipt retired'),{code:'COUPON_AGENT_ASSESSMENT_UNAVAILABLE'});}};
 }}});
 assert.equal((await service.list(base)).judgments[0].canRetry,true);assert.equal(checks,1);
 stale=true;assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'COUPON_AGENT_ASSESSMENT_UNAVAILABLE'});
 assert.equal(judgeCalls,0);assert.equal(f.links.size,0);assert.equal(f.writes.length,0);
});

test('ticket browser recovery requires the current admin and retained private evidence before retry admission',async()=>{
 const f=await fixture({role:'admin'});
 const {RUBRIC:rubric}=require('../server/services/secureshopTicketBrowserEvidence');
 const packet=prepareJudgeInput({rubric:{...rubric,mode:'vuln'},
  facts:Object.fromEntries(rubric.requiredFacts.map(key=>[key,true])),
  evidence:[{id:'ticket_browser',source:'server_observation',content:{controlled:true}}]});
 assert.equal(packet.evidenceError,undefined);
 Object.assign(f.parent,{objective_id:rubric.objectiveId,family:rubric.family,
  scenario:rubric.scenario,rubric_version:rubric.version,packet:packet.packet,
  evidence_digest:packet.evidenceDigest,qualification:'native-browser-judge',
  live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
  catalog_active:true,enabled:true,is_child:false,retry_count:0});
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,
  username:'admin',email:'admin@shop.test',role:'admin',credentialVersion:'1',
  authorityVersion:'1',expiresAt:new Date(Date.now()+60000).toISOString()};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin',
  'createSession','rotateSession','revokeSession','readCredentialForSession',
  'changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,
  ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,
  tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository});
 const base=await authService.authenticate('a'.repeat(43));
 let reads=0,checks=0,judgeCalls=0,stale=false;
 const deps={identityPool:f.pool,authService,
  bootstrap:async()=>({bearer:'private',persona:{token:'private'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},
  personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:'admin'},
    sessionId:f.input.sessionId,authorityVersion:'1'})},
  personaAuthority:{capture:()=>f.fence},
  judge:async()=>{judgeCalls++;throw Error('Stale ticket reached Judge');}};
 const absent=createSecureShopAssessmentRecovery(deps);
 if(!require('../server/config/secureshopCurriculum').isAssessmentReleaseAllowed(f.parent.objective_id)){
  assert.equal((await absent.list(base)).judgments[0].canRetry,false);
  await assert.rejects(absent.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'RETRY_NOT_ALLOWED'});
  assert.equal(judgeCalls,0);assert.equal(reads,0);assert.deepEqual(f.writes,[]);return;
 }
 assert.equal((await absent.list(base)).judgments[0].canRetry,false);
 await assert.rejects(absent.retry(base,{evaluationId:f.parent.evaluation_id}),
  {code:'SECURESHOP_FEATURE_MODE_STALE'});
 const service=createSecureShopAssessmentRecovery({...deps,ticketAssessment:{
  async assertRetainedPacket(input){reads++;
   assert.deepEqual(input.packet,JSON.parse(f.parent.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'admin'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){checks++;if(stale)throw Object.assign(
    Error('Original ticket or browser effect retired'),{code:'TICKET_BROWSER_ASSESSMENT_UNAVAILABLE'});}};
  }}});
 assert.equal((await service.list(base)).judgments[0].canRetry,true);
 assert.equal(reads,1);assert.equal(checks,1);
 const originalDigest=f.parent.evidence_digest;
 f.parent.evidence_digest='b'.repeat(64);
 assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
  {code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(reads,1,'changed stored digest is denied before a private ticket read');
 f.parent.evidence_digest=originalDigest;
 stale=true;
 assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
  {code:'TICKET_BROWSER_ASSESSMENT_UNAVAILABLE'});
 assert.equal(judgeCalls,0);assert.equal(f.links.size,0);
 assert.equal(f.invocations.length,0);assert.equal(f.writes.length,0);
});

for(const spec of [
 {name:'Mail inline summary',role:'merchant',module:'secureshopMailInlineEvidence',dependency:'mailInlineAssessment',error:'MAIL_INLINE_ASSESSMENT_UNAVAILABLE'},
 {name:'System diagnostic',role:'admin',module:'secureshopSystemDiagnosticEvidence',dependency:'systemDiagnosticAssessment',error:'SYSTEM_DIAGNOSTIC_ASSESSMENT_UNAVAILABLE'},
 {name:'MCP manifest',role:'admin',module:'secureshopMcpManifestEvidence',dependency:'mcpManifestAssessment',error:'MCP_MANIFEST_ASSESSMENT_UNAVAILABLE'},
 {name:'User lookup',role:'admin',module:'secureshopUserLookupEvidence',dependency:'userLookupAssessment',error:'USER_LOOKUP_ASSESSMENT_UNAVAILABLE'},
 {name:'MCP discovery',role:'admin',module:'secureshopMcpRegistrySsrfEvidence',dependency:'mcpRegistrySsrfAssessment',error:'MCP_REGISTRY_SSRF_ASSESSMENT_UNAVAILABLE'},
 {name:'Search echo',role:'customer',module:'secureshopSearchEchoBrowserEvidence',dependency:'searchEchoAssessment',error:'SEARCH_ECHO_ASSESSMENT_UNAVAILABLE'},
]) test(`${spec.name} recovery requires current persona and original evidence before retry admission`,async()=>{
 const f=await fixture({role:spec.role});
 const {RUBRIC:rubric}=require(`../server/services/${spec.module}`);
 const evidence=spec.module==='secureshopMailInlineEvidence'
  ? [{id:'mail_inline_source',source:'tool_result',content:{imageContext:'<img src="http://127.0.0.1:'}},
    {id:'mail_inline_execution',source:'server_observation',content:{verifiedContext:
      'The controlled listener recorded an inline image GET with HTTP 200.'}}]
  : spec.name==='User lookup'?[{id:'user_lookup_response',source:'assistant_response',content:'controlled response'},{id:'user_lookup_source',source:'server_observation',content:{controlled:true}}]
  : rubric.criteria[0].evidenceIds.map(id=>({id,source:'server_observation',content:{controlled:true}}));
 const packet=prepareJudgeInput({rubric:{...rubric,mode:'vuln'},
  facts:Object.fromEntries(rubric.requiredFacts.map(key=>[key,true])),
  evidence});
 assert.equal(packet.evidenceError,undefined);
 Object.assign(f.parent,{objective_id:rubric.objectiveId,family:rubric.family,
  scenario:rubric.scenario,rubric_version:rubric.version,packet:packet.packet,
  evidence_digest:packet.evidenceDigest,qualification:'native-model',
  live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
  catalog_active:true,enabled:true,is_child:false,retry_count:0});
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentRecovery}=require('../server/services/secureshopAssessmentRecovery');
 const row={principalId:f.principalId,ownerId:90,sessionId:91,shopUserId:f.actor,
  username:'admin',email:'admin@shop.test',role:spec.role,credentialVersion:'1',
  authorityVersion:'1',expiresAt:new Date(Date.now()+60000).toISOString()};
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin',
  'createSession','rotateSession','revokeSession','readCredentialForSession',
  'changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row;
 repository.readOrCreateDefaultExecutionSession=async()=>({...row,principalOwnerId:90,
  ownerId:f.scope.platformOwnerId,authSessionId:91,sessionId:f.scope.platformSessionId,
  tenantId:f.tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository});
 const base=await authService.authenticate('a'.repeat(43));
 let reads=0,checks=0,judgeCalls=0,stale=false;
 const deps={identityPool:f.pool,authService,
  coordinatorFactory:()=>({run:async(_owner,_options,work)=>work({runId:randomUUID(),ownerKey:f.parent.owner_key,durableGeneration:'0',check:async()=>{}})}),
  bootstrap:async()=>({bearer:'private',persona:{token:'private'}}),
  launches:{resolveCapability:async()=>f.scope,assertCurrent:async()=>{}},
  personaAuth:{authenticateBoundToken:async()=>({user:{id:f.actor,role:spec.role},
    sessionId:f.input.sessionId,authorityVersion:'1'})},
  personaAuthority:{capture:()=>f.fence},
  judge:async()=>{judgeCalls++;throw Error('Stale manifest reached Judge');}};
 const absent=createSecureShopAssessmentRecovery(deps);
 if(!require('../server/config/secureshopCurriculum').isAssessmentReleaseAllowed(f.parent.objective_id)){
  assert.equal((await absent.list(base)).judgments[0].canRetry,false);
  await assert.rejects(absent.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'RETRY_NOT_ALLOWED'});
  assert.equal(judgeCalls,0);assert.equal(reads,0);assert.deepEqual(f.writes,[]);return;
 }
 assert.equal((await absent.list(base)).judgments[0].canRetry,false);
 await assert.rejects(absent.retry(base,{evaluationId:f.parent.evaluation_id}),
  {code:'SECURESHOP_FEATURE_MODE_STALE'});
 const service=createSecureShopAssessmentRecovery({...deps,[spec.dependency]:{
  async assertRetainedPacket(input){reads++;
   assert.deepEqual(input.packet,JSON.parse(f.parent.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:spec.role});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){checks++;if(stale)throw Object.assign(
    Error('Original manifest import retired'),{code:spec.error});}};
  }}});
 assert.equal((await service.list(base)).judgments[0].canRetry,true);
 assert.equal(reads,1);assert.equal(checks,1);
 const originalDigest=f.parent.evidence_digest;
 f.parent.evidence_digest='b'.repeat(64);
 assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
  {code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(reads,1,'changed stored digest is denied before a private import read');
 f.parent.evidence_digest=originalDigest;
 stale=true;
 assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
  {code:spec.error});
 assert.equal(judgeCalls,0);assert.equal(f.links.size,0);
 assert.equal(f.invocations.length,0);assert.equal(f.writes.length,0);
 if(spec.name==='MCP discovery'||spec.name==='User lookup'){
  stale=false;
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'fail');
  assert.equal(judgeCalls,0,'the original discovery guard rejects fabricated evidence before provider');
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
  const child=f.judgments.get(f.links.get(f.parent.evaluation_id));
  assert.equal(child.result_json.errorCode,'INVALID_OR_OVERSIZED_EVIDENCE');
 }
});

function bindV8SearchEchoReceipt(f,source,evidenceVersion){
 if(evidenceVersion<8)return;
 source.execution.runId=f.parent.run_id;
 source.execution.ownerKey=f.parent.owner_key;
 source.execution.durableGeneration=f.parent.owner_generation;
 source.effect.receipt.runId=f.parent.run_id;
 source.effect.receipt.ownerKey=f.parent.owner_key;
 source.effect.receipt.generation=f.parent.owner_generation;
 source.effect.value.domCapture=searchEchoDomCapture(source);
}

test('V60 recovery dispatches exact persisted v1, v2, v8 and v9 packets without replaying browser work',async t=>{
 for(const [label,rubric,evidenceVersion] of [
  ['v1',searchEchoEvidence.RUBRIC,1],['v2',searchEchoEvidence.RUBRIC_V2,2],
  ['v8',searchEchoEvidence.RUBRIC_V8,8],['v9',searchEchoEvidence.RUBRIC_V9,9],
 ])await t.test(label,async()=>{
  const f=await fixture({role:'customer'}),source=searchEchoFixture();
  bindV8SearchEchoReceipt(f,source,evidenceVersion);
  const candidate=searchEchoEvidence.buildSearchEchoBrowserCandidate({...source,evidenceVersion});
  const prepared=prepareJudgeInput({rubric:{...rubric,mode:'vuln'},...candidate});
  assert.equal(prepared.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:rubric.objectiveId,family:rubric.family,
   scenario:rubric.scenario,rubric_version:rubric.version,packet:prepared.packet,
   evidence_digest:prepared.evidenceDigest,qualification:'native-browser-judge',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const storedPacket=f.parent.packet,{base,deps,retryRuns}=await recoveryContext(f);
  let retainedReads=0,currentChecks=0,judgeCalls=0,browserEffects=0;
  const service=require('../server/services/secureshopAssessmentRecovery')
   .createSecureShopAssessmentRecovery({...deps,qualifyIdorModel:source.qualifyModel,
    searchEchoAssessment:{async assertRetainedPacket(input){retainedReads++;
     assert.equal(JSON.stringify(input.packet),storedPacket);
     assert.equal(input.packet.rubric.version,rubric.version);
     assert.deepEqual(input.scope,f.scope);
     assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
     assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
     return {async assertCurrent(){currentChecks++;}};
    },async qualifySearchEcho(){browserEffects++;throw Error('Recovery replayed browser work');}},
    judge:async input=>{judgeCalls++;
     const actual=prepareJudgeInput(input);assert.equal(actual.packet,storedPacket);
     assert.equal(actual.rubric.version,rubric.version);
     if(evidenceVersion===8){
      assert.equal(input.execution.runId,f.parent.run_id);
      assert.equal(input.execution.ownerKey,f.parent.owner_key);
      assert.equal(input.execution.durableGeneration,f.parent.owner_generation);
     }
     return {family:rubric.family,scenario:rubric.scenario,objectiveId:rubric.objectiveId,
      rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest,runId:f.parent.run_id,
      mode:'vuln',verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',
      criteria:rubric.criteria.map(row=>({id:row.id,satisfied:false,evidenceRefs:[]})),
      explanation:'Controlled recovery remains unavailable',provider:null,model:null,
      judgeVersion:JUDGE_VERSION};},
   });
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
  if(evidenceVersion===8){assert.equal(retryRuns.length,1);assert.notEqual(retryRuns[0],f.parent.run_id);}
  assert.equal(judgeCalls,1);assert.equal(browserEffects,0);
  assert.equal(f.parent.packet,storedPacket,'historical parent bytes remain unchanged');
  assert.equal(f.judgments.get(result.childEvaluationId).packet,storedPacket);
  const writes=f.writes.length,replay=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(replay.replayed,true);assert.equal(judgeCalls,1);
  assert.equal(browserEffects,0);assert.equal(f.writes.length,writes,'terminal retry is read-only');
  assert.ok(retainedReads>=2);assert.ok(currentChecks>=retainedReads);
 });
});

test('V60 recovery rejects substituted packet versions and stale retained authority before Judge or writes',async t=>{
 for(const [label,rubric,evidenceVersion] of [
  ['v1',searchEchoEvidence.RUBRIC,1],['v2',searchEchoEvidence.RUBRIC_V2,2],
  ['v8',searchEchoEvidence.RUBRIC_V8,8],['v9',searchEchoEvidence.RUBRIC_V9,9],
 ])await t.test(label,async()=>{
  const setup=async()=>{
   const f=await fixture({role:'customer'}),source=searchEchoFixture();
   bindV8SearchEchoReceipt(f,source,evidenceVersion);
   const candidate=searchEchoEvidence.buildSearchEchoBrowserCandidate({...source,evidenceVersion});
   const prepared=prepareJudgeInput({rubric:{...rubric,mode:'vuln'},...candidate});
   Object.assign(f.parent,{objective_id:rubric.objectiveId,family:rubric.family,
    scenario:rubric.scenario,rubric_version:rubric.version,packet:prepared.packet,
    evidence_digest:prepared.evidenceDigest,qualification:'native-browser-judge',
    live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
    catalog_active:true,enabled:true,is_child:false,retry_count:0});
   return {f,source,...await recoveryContext(f)};
  };
  const changed=await setup();let changedReads=0,changedJudge=0;
  changed.f.parent.rubric_version=evidenceVersion===1
   ? searchEchoEvidence.RUBRIC_V2.version:searchEchoEvidence.RUBRIC.version;
  const changedService=require('../server/services/secureshopAssessmentRecovery')
   .createSecureShopAssessmentRecovery({...changed.deps,qualifyIdorModel:changed.source.qualifyModel,
    searchEchoAssessment:{async assertRetainedPacket(){changedReads++;throw Error('Version mismatch reached private read');}},
    judge:async()=>{changedJudge++;throw Error('Version mismatch reached Judge');}});
  assert.equal((await changedService.list(changed.base)).judgments[0].canRetry,false);
  await assert.rejects(changedService.retry(changed.base,
   {evaluationId:changed.f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.equal(changedReads,0);assert.equal(changedJudge,0);assert.equal(changed.f.writes.length,0);

  const stale=await setup();let staleJudge=0,staleChecks=0;
  const staleService=require('../server/services/secureshopAssessmentRecovery')
   .createSecureShopAssessmentRecovery({...stale.deps,qualifyIdorModel:stale.source.qualifyModel,
    searchEchoAssessment:{async assertRetainedPacket(){return {async assertCurrent(){staleChecks++;
     throw Object.assign(Error('Retained V60 owner reset'),{code:'SEARCH_ECHO_ASSESSMENT_UNAVAILABLE'});}};}},
    judge:async()=>{staleJudge++;throw Error('Stale V60 reached Judge');}});
  assert.equal((await staleService.list(stale.base)).judgments[0].canRetry,false);
  await assert.rejects(staleService.retry(stale.base,
   {evaluationId:stale.f.parent.evaluation_id}),{code:'SEARCH_ECHO_ASSESSMENT_UNAVAILABLE'});
  assert.ok(staleChecks>=2);assert.equal(staleJudge,0);assert.equal(stale.f.writes.length,0);
 });
});

test('manual RAG recovery requires the exact customer retained packet and current authority before Judge retry',async t=>{
 const setup=async()=>{
  const f=await fixture(),source=manualRagSourceFixture(),original=validateManualRagSourceContract(source);
  const execution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
  const candidate=manualRagEvidence.buildManualRagCandidate({source:original,execution});
  assert.ok(candidate);const prepared=prepareJudgeInput({rubric:{...manualRagEvidence.RUBRIC,mode:'vuln'},...candidate});
  assert.equal(prepared.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:manualRagEvidence.OBJECTIVE,family:manualRagEvidence.RUBRIC.family,
   scenario:manualRagEvidence.RUBRIC.scenario,rubric_version:manualRagEvidence.RUBRIC.version,
   packet:prepared.packet,evidence_digest:prepared.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  return {f,...await recoveryContext(f),packet:prepared.packet};
 };
 const valid=await setup();let validChecks=0,validJudge=0;
 const validService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...valid.deps,
  manualRagAssessment:{async assertRetainedPacket(input){
   assert.equal(input.persona.role,'customer');assert.deepEqual(input.packet,JSON.parse(valid.f.parent.packet));
   return {async assertCurrent(){validChecks++;}}; }},
  judge:async input=>{validJudge++;assert.equal(prepareJudgeInput(input).packet,valid.f.parent.packet);
   return {family:manualRagEvidence.RUBRIC.family,scenario:manualRagEvidence.RUBRIC.scenario,
    objectiveId:manualRagEvidence.OBJECTIVE,rubricVersion:manualRagEvidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:prepareJudgeInput(input).evidenceDigest,runId:input.execution.runId,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:manualRagEvidence.RUBRIC.criteria.map(c=>({id:c.id,satisfied:false,evidenceRefs:[]})),
    explanation:'Controlled retained-packet retry',provider:null,model:null,judgeVersion:JUDGE_VERSION};}});
 assert.equal((await validService.list(valid.base)).judgments[0].canRetry,true);
 const validResult=await validService.retry(valid.base,{evaluationId:valid.f.parent.evaluation_id});
 assert.equal(validResult.verdict,'unavailable');assert.equal(validJudge,1);assert.ok(validChecks>=2);

 const missing=await setup();
 const missingService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery(missing.deps);
 assert.equal((await missingService.list(missing.base)).judgments[0].canRetry,false);
 await assert.rejects(missingService.retry(missing.base,{evaluationId:missing.f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(missing.f.writes.length,0);

 const tampered=await setup();tampered.f.parent.packet=tampered.f.parent.packet.replace('Find products similar','Find unrelated products');
 let tamperedReads=0,tamperedJudge=0;
 const tamperedService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...tampered.deps,
  manualRagAssessment:{async assertRetainedPacket(){tamperedReads++;throw Error('tampered packet reached retained reader');}},
  judge:async()=>{tamperedJudge++;throw Error('tampered packet reached Judge');}});
 assert.equal((await tamperedService.list(tampered.base)).judgments[0].canRetry,false);
 await assert.rejects(tamperedService.retry(tampered.base,{evaluationId:tampered.f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(tamperedReads,0);assert.equal(tamperedJudge,0);assert.equal(tampered.f.writes.length,0);

 const stale=await setup();let retainedReads=0,staleJudge=0;
 const staleService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...stale.deps,
  manualRagAssessment:{async assertRetainedPacket(input){
   assert.equal(input.persona.role,'customer');assert.deepEqual(input.packet,JSON.parse(stale.f.parent.packet));retainedReads++;
   return {async assertCurrent(){retainedReads++;throw Object.assign(Error('manual source authority retired'),{code:'MANUAL_RAG_ASSESSMENT_UNAVAILABLE'});}}; }},
  judge:async()=>{staleJudge++;throw Error('stale packet reached Judge');}});
 assert.equal((await staleService.list(stale.base)).judgments[0].canRetry,false);
 await assert.rejects(staleService.retry(stale.base,{evaluationId:stale.f.parent.evaluation_id}),{code:'MANUAL_RAG_ASSESSMENT_UNAVAILABLE'});
 assert.ok(retainedReads>=2);assert.equal(staleJudge,0);assert.equal(stale.f.writes.length,0);
});

test('product summary recovery requires the exact customer retained packet and current authority before Judge retry',async t=>{
 const productSummaryEvidence=require('../server/services/secureshopProductSummaryEvidence');
 const setup=async()=>{
  const f=await fixture(),source=require('./secureshopProductSummaryEvidence.test').originalFixture(),original=require('../server/services/secureshopProductSummarySourceContract').validateProductSummarySourceContract(source);
  const execution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
  const candidate=productSummaryEvidence.buildProductSummaryCandidate({source:original,execution});
  assert.ok(candidate);const prepared=prepareJudgeInput({rubric:{...productSummaryEvidence.RUBRIC,mode:'vuln'},...candidate});
  assert.equal(prepared.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:productSummaryEvidence.OBJECTIVE,family:productSummaryEvidence.RUBRIC.family,
   scenario:productSummaryEvidence.RUBRIC.scenario,rubric_version:productSummaryEvidence.RUBRIC.version,
   packet:prepared.packet,evidence_digest:prepared.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  return {f,...await recoveryContext(f),packet:prepared.packet};
 };
 const valid=await setup();let validChecks=0,validJudge=0;
 const validService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...valid.deps,
  productSummaryAssessment:{async assertRetainedPacket(input){
   assert.equal(input.persona.role,'customer');assert.deepEqual(input.packet,JSON.parse(valid.f.parent.packet));
   return {async assertCurrent(){validChecks++;}}; }},
  judge:async input=>{validJudge++;assert.equal(prepareJudgeInput(input).packet,valid.f.parent.packet);
   return {family:productSummaryEvidence.RUBRIC.family,scenario:productSummaryEvidence.RUBRIC.scenario,
    objectiveId:productSummaryEvidence.OBJECTIVE,rubricVersion:productSummaryEvidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:prepareJudgeInput(input).evidenceDigest,runId:input.execution.runId,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:productSummaryEvidence.RUBRIC.criteria.map(c=>({id:c.id,satisfied:false,evidenceRefs:[]})),
    explanation:'Controlled retained-packet retry',provider:null,model:null,judgeVersion:JUDGE_VERSION};}});
 assert.equal((await validService.list(valid.base)).judgments[0].canRetry,true);
 const validResult=await validService.retry(valid.base,{evaluationId:valid.f.parent.evaluation_id});
 assert.equal(validResult.verdict,'unavailable');assert.equal(validJudge,1);assert.ok(validChecks>=2);

 const missing=await setup();
 const missingService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery(missing.deps);
 assert.equal((await missingService.list(missing.base)).judgments[0].canRetry,false);
 await assert.rejects(missingService.retry(missing.base,{evaluationId:missing.f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(missing.f.writes.length,0);

 const tampered=await setup();tampered.f.parent.packet=tampered.f.parent.packet.replace('Summarize product 9.','Summarize product 8.');
 let tamperedReads=0,tamperedJudge=0;
 const tamperedService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...tampered.deps,
  productSummaryAssessment:{async assertRetainedPacket(){tamperedReads++;throw Error('tampered packet reached retained reader');}},
  judge:async()=>{tamperedJudge++;throw Error('tampered packet reached Judge');}});
 assert.equal((await tamperedService.list(tampered.base)).judgments[0].canRetry,false);
 await assert.rejects(tamperedService.retry(tampered.base,{evaluationId:tampered.f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(tamperedReads,0);assert.equal(tamperedJudge,0);assert.equal(tampered.f.writes.length,0);

 const stale=await setup();let retainedReads=0,staleJudge=0;
 const staleService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...stale.deps,
  productSummaryAssessment:{async assertRetainedPacket(input){
   assert.equal(input.persona.role,'customer');assert.deepEqual(input.packet,JSON.parse(stale.f.parent.packet));retainedReads++;
   return {async assertCurrent(){retainedReads++;throw Object.assign(Error('product source authority retired'),{code:'PRODUCT_SUMMARY_ASSESSMENT_UNAVAILABLE'});}}; }},
  judge:async()=>{staleJudge++;throw Error('stale packet reached Judge');}});
 assert.equal((await staleService.list(stale.base)).judgments[0].canRetry,false);
 await assert.rejects(staleService.retry(stale.base,{evaluationId:stale.f.parent.evaluation_id}),{code:'PRODUCT_SUMMARY_ASSESSMENT_UNAVAILABLE'});
 assert.ok(retainedReads>=2);assert.equal(staleJudge,0);assert.equal(stale.f.writes.length,0);
});

test('avatar traversal recovery requires the exact customer retained packet and current authority before Judge retry',async t=>{
 const traversal=require('../server/services/secureshopV46TraversalEvidence');
 const productSummaryEvidence={OBJECTIVE:traversal.TRAVERSAL_OBJECTIVE,RUBRIC:traversal.TRAVERSAL_RUBRIC};
 const setup=async()=>{
  const f=await fixture(),source=require('./secureshopV46TraversalEvidence.test').fixture();
  const execution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
  const candidate=traversal.buildTraversalCandidate(source);
  assert.ok(candidate);const prepared=prepareJudgeInput({rubric:{...productSummaryEvidence.RUBRIC,mode:'vuln'},...candidate});
  assert.equal(prepared.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:productSummaryEvidence.OBJECTIVE,family:productSummaryEvidence.RUBRIC.family,
   scenario:productSummaryEvidence.RUBRIC.scenario,rubric_version:productSummaryEvidence.RUBRIC.version,
   packet:prepared.packet,evidence_digest:prepared.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  return {f,...await recoveryContext(f),packet:prepared.packet};
 };
 const valid=await setup();let validChecks=0,validJudge=0;
 const validService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...valid.deps,
  traversalAssessment:{async assertRetainedPacket(input){
   assert.equal(input.persona.role,'customer');assert.deepEqual(input.packet,JSON.parse(valid.f.parent.packet));
   return {async assertCurrent(){validChecks++;}}; }},
  judge:async input=>{validJudge++;assert.equal(prepareJudgeInput(input).packet,valid.f.parent.packet);
   return {family:productSummaryEvidence.RUBRIC.family,scenario:productSummaryEvidence.RUBRIC.scenario,
    objectiveId:productSummaryEvidence.OBJECTIVE,rubricVersion:productSummaryEvidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:prepareJudgeInput(input).evidenceDigest,runId:input.execution.runId,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:productSummaryEvidence.RUBRIC.criteria.map(c=>({id:c.id,satisfied:false,evidenceRefs:[]})),
    explanation:'Controlled retained-packet retry',provider:null,model:null,judgeVersion:JUDGE_VERSION};}});
 assert.equal((await validService.list(valid.base)).judgments[0].canRetry,true);
 const validResult=await validService.retry(valid.base,{evaluationId:valid.f.parent.evaluation_id});
 assert.equal(validResult.verdict,'unavailable');assert.equal(validJudge,1);assert.ok(validChecks>=2);

 const missing=await setup();
 const missingService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery(missing.deps);
 assert.equal((await missingService.list(missing.base)).judgments[0].canRetry,false);
 await assert.rejects(missingService.retry(missing.base,{evaluationId:missing.f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(missing.f.writes.length,0);

 const tampered=await setup();tampered.f.parent.packet=tampered.f.parent.packet.replace('Store this synthetic attachment','Store a different attachment');
 let tamperedReads=0,tamperedJudge=0;
 const tamperedService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...tampered.deps,
  traversalAssessment:{async assertRetainedPacket(){tamperedReads++;throw Error('tampered packet reached retained reader');}},
  judge:async()=>{tamperedJudge++;throw Error('tampered packet reached Judge');}});
 assert.equal((await tamperedService.list(tampered.base)).judgments[0].canRetry,false);
 await assert.rejects(tamperedService.retry(tampered.base,{evaluationId:tampered.f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(tamperedReads,0);assert.equal(tamperedJudge,0);assert.equal(tampered.f.writes.length,0);

 const stale=await setup();let retainedReads=0,staleJudge=0;
 const staleService=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...stale.deps,
  traversalAssessment:{async assertRetainedPacket(input){
   assert.equal(input.persona.role,'customer');assert.deepEqual(input.packet,JSON.parse(stale.f.parent.packet));retainedReads++;
   return {async assertCurrent(){retainedReads++;throw Object.assign(Error('product source authority retired'),{code:'AVATAR_UPLOAD_ASSESSMENT_UNAVAILABLE'});}}; }},
  judge:async()=>{staleJudge++;throw Error('stale packet reached Judge');}});
 assert.equal((await staleService.list(stale.base)).judgments[0].canRetry,false);
 await assert.rejects(staleService.retry(stale.base,{evaluationId:stale.f.parent.evaluation_id}),{code:'AVATAR_UPLOAD_ASSESSMENT_UNAVAILABLE'});
 assert.ok(retainedReads>=2);assert.equal(staleJudge,0);assert.equal(stale.f.writes.length,0);
});


test('diagnostic recovery retains the original execution anchor and packet while retrying only Judge',async()=>{
 const f=await fixture({role:'admin'});
 const evidence=require('../server/services/secureshopSystemDiagnosticEvidence');
 const source=require('./secureshopSystemDiagnosticEvidence.test').fixture().input;
 f.parent.owner_key=JSON.stringify(['SecureShopBoundConversation',randomUUID()]);
 f.parent.execution_json={...f.parent.execution_json,ownerKey:f.parent.owner_key};
 const candidate=evidence.buildSystemDiagnosticCandidate({...source,execution:{runId:f.parent.run_id,
  ownerKey:f.parent.owner_key,durableGeneration:'0'}});
 assert.ok(candidate);
 const prepared=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
 assert.equal(prepared.evidenceError,undefined);
 Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
  scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
  packet:prepared.packet,evidence_digest:prepared.evidenceDigest,qualification:'native-model',
  live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
  catalog_active:true,enabled:true,is_child:false,retry_count:0});
 const {base,deps}=await recoveryContext(f,{role:'admin'});
 let reads=0,checks=0,judges=0;
 const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
  qualifyIdorModel:source.qualifyModel,
  systemDiagnosticAssessment:{async assertRetainedPacket(input){reads++;
   assert.deepEqual(input.packet,JSON.parse(prepared.packet));assert.equal(input.persona.role,'admin');
   return {async assertCurrent(){checks++;}};}},
  judge:async input=>{judges++;assert.equal(prepareJudgeInput(input).packet,prepared.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,
    objectiveId:evidence.OBJECTIVE,rubricVersion:evidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:prepared.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
    explanation:'Controlled diagnostic retry'};}});
 assert.equal((await service.list(base)).judgments[0].canRetry,true);
 const outcome=await service.retry(base,{evaluationId:f.parent.evaluation_id});
 assert.equal(outcome.verdict,'unavailable');assert.equal(outcome.completed,false);
 assert.equal(judges,1);assert.ok(reads>=2);assert.ok(checks>=3);
 const child=f.judgments.get(outcome.childEvaluationId);
 assert.equal(child.packet,prepared.packet);assert.equal(child.run_id,f.parent.run_id);
 assert.notEqual(child.execution_json.runId,f.parent.run_id,'retry invocation remains separately identified');
});

test('V48 recovery binds the original packet and customer before a read-only source fence or Judge retry',async t=>{
 const evidence=require('../server/services/secureshopCouponBlindEvidence');
 const sourceFixture=require('./secureshopCouponBlindEvidence.test').fixture;
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='customer'){
  const f=await fixture({role}),source=sourceFixture();
  const candidate=evidence.buildCouponBlindCandidate(source);assert.ok(candidate);
  const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
   scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
   packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role});
  const calls={reads:0,checks:0,judge:0};
  const service=createRecovery({...deps,couponBlindAssessment:{async assertRetainedPacket(input){
   calls.reads++;
   assert.deepEqual(input.packet,JSON.parse(packet.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){calls.checks++;}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,
    objectiveId:evidence.OBJECTIVE,rubricVersion:evidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:packet.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
    explanation:'Controlled V48 recovery branch; no genuine credit'};
  }});
  return {f,base,service,calls,packet};
 }
 await t.test('valid customer retries the exact retained packet without source effects',async()=>{
  const {f,base,service,calls,packet}=await setup();
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
  assert.equal(calls.judge,1);assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);
  const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.packet,packet.packet);assert.equal(child.run_id,f.parent.run_id);
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const [name,mutate,role] of [
  ['malformed packet',f=>{f.parent.packet='{';}],
  ['modified packet',f=>{const p=JSON.parse(f.parent.packet);p.evidence.at(-1).content+=' changed';f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['outer rubric',f=>{f.parent.rubric_version='unknown-v48-version';}],
  ['outer scenario',f=>{f.parent.scenario='different-scenario';}],
  ['non-customer',()=>{},'merchant'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});
  assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
});

test('V53 recovery binds the original packet and customer before a read-only source fence or Judge retry',async t=>{
 const evidence=require('../server/services/secureshopProductUnionEvidence');
 const sourceFixture=require('./secureshopProductUnionEvidence.test').fixture;
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='customer'){
  const f=await fixture({role}),source=sourceFixture();
  const candidate=evidence.buildProductUnionCandidate(source);assert.ok(candidate);
  const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
   scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
   packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role});
  const calls={reads:0,checks:0,judge:0};
  const service=createRecovery({...deps,productUnionAssessment:{async assertRetainedPacket(input){
   calls.reads++;
   assert.deepEqual(input.packet,JSON.parse(packet.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){calls.checks++;}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,
    objectiveId:evidence.OBJECTIVE,rubricVersion:evidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:packet.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
    explanation:'Controlled V53 recovery branch; no genuine credit'};
  }});
  return {f,base,service,calls,packet};
 }
 await t.test('valid customer retries the exact retained packet without source effects',async()=>{
  const {f,base,service,calls,packet}=await setup();
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
  assert.equal(calls.judge,1);assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);
  const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.packet,packet.packet);assert.equal(child.run_id,f.parent.run_id);
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const [name,mutate,role] of [
  ['malformed packet',f=>{f.parent.packet='{';}],
  ['modified packet',f=>{const p=JSON.parse(f.parent.packet);p.evidence.at(-1).content+=' changed';f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['outer rubric',f=>{f.parent.rubric_version='unknown-v53-version';}],
  ['outer scenario',f=>{f.parent.scenario='different-scenario';}],
  ['non-customer',()=>{},'merchant'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});
  assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
});

test('V50 recovery binds the original packet and customer before a read-only source fence or Judge retry',async t=>{
 const evidence=require('../server/services/secureshopOrderStatusErrorEvidence');
 const sourceFixture=require('./secureshopOrderStatusErrorEvidence.test').fixture;
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='customer'){
  const f=await fixture({role}),source=await sourceFixture();
  const candidate=evidence.buildOrderStatusErrorCandidate(source);assert.ok(candidate);
  const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
   scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
   packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role});
  const calls={reads:0,checks:0,judge:0};
  const service=createRecovery({...deps,orderStatusErrorAssessment:{async assertRetainedPacket(input){
   calls.reads++;
   assert.deepEqual(input.packet,JSON.parse(packet.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){calls.checks++;}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,
    objectiveId:evidence.OBJECTIVE,rubricVersion:evidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:packet.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
    explanation:'Controlled V50 recovery branch; no genuine credit'};
  }});
  return {f,base,service,calls,packet};
 }
 await t.test('valid customer retries the exact retained packet without source effects',async()=>{
  const {f,base,service,calls,packet}=await setup();
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
  assert.equal(calls.judge,1);assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);
  const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.packet,packet.packet);assert.equal(child.run_id,f.parent.run_id);
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const [name,mutate,role] of [
  ['malformed packet',f=>{f.parent.packet='{';}],
  ['modified packet',f=>{const p=JSON.parse(f.parent.packet);p.evidence.at(-1).content+=' changed';f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['outer rubric',f=>{f.parent.rubric_version='unknown-v50-version';}],
  ['outer scenario',f=>{f.parent.scenario='different-scenario';}],
  ['non-customer',()=>{},'merchant'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});
  assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
});

test('V04 recovery binds the original packet and admin before a read-only source fence or Judge retry',async t=>{
 const evidence=require('../server/services/secureshopSystemRestartInjectionEvidence');
 const sourceFixture=require('./secureshopSystemRestartInjectionEvidence.test').fixture;
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='admin'){
  const f=await fixture({role}),source=sourceFixture().input;
  f.parent.owner_key=JSON.stringify(['SecureShopBoundConversation',randomUUID()]);
  f.parent.execution_json={...f.parent.execution_json,ownerKey:f.parent.owner_key};
  const candidate=evidence.buildSystemRestartInjectionCandidate({...source,execution:{runId:f.parent.run_id,ownerKey:f.parent.owner_key,durableGeneration:'0'}});assert.ok(candidate);
  const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
   scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
   packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role});
  const calls={reads:0,checks:0,judge:0};
  const service=createRecovery({...deps,qualifyIdorModel:source.qualifyModel,systemRestartInjectionAssessment:{async assertRetainedPacket(input){
   calls.reads++;
   assert.deepEqual(input.packet,JSON.parse(packet.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'admin'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){calls.checks++;}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,
    objectiveId:evidence.OBJECTIVE,rubricVersion:evidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:packet.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
    explanation:'Controlled V04 recovery branch; no genuine credit'};
  }});
  return {f,base,service,calls,packet};
 }
 await t.test('valid admin retries the exact retained packet without source effects',async()=>{
  const {f,base,service,calls,packet}=await setup();
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
  assert.equal(calls.judge,1);assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);
  const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.packet,packet.packet);assert.equal(child.run_id,f.parent.run_id);
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const [name,mutate,role] of [
  ['malformed packet',f=>{f.parent.packet='{';}],
  ['modified packet',f=>{const p=JSON.parse(f.parent.packet);p.evidence.at(-1).content+=' changed';f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['outer rubric',f=>{f.parent.rubric_version='unknown-v50-version';}],
  ['outer scenario',f=>{f.parent.scenario='different-scenario';}],
  ['non-admin',()=>{},'merchant'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});
  assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
});

test('V01 retained checkout audit retry binds exact original packet and customer before Judge',async t=>{
 const evidence=require('../server/services/secureshopV01AuditEvidence');
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='customer'){
  const f=await fixture({role});
  // This controlled packet tests recovery routing; source validity is covered by the V01 evidence tests.
  const rubric=evidence.V01_AUDIT_RUBRIC;
  const packet=prepareJudgeInput({rubric,evidence:[
   {id:'audit_request',source:'server_observation',content:'Original customer request'},
   {id:'audit_effect_excerpt',source:'server_observation',content:'Completed owned protected read'},
   {id:'audit_response',source:'assistant_response',content:'The protected report was observed'},
  ],facts:Object.fromEntries(rubric.requiredFacts.map(id=>[id,true]))});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.V01_AUDIT_OBJECTIVE,
   family:evidence.V01_AUDIT_RUBRIC.family,scenario:evidence.V01_AUDIT_RUBRIC.scenario,
   rubric_version:evidence.V01_AUDIT_RUBRIC.version,packet:packet.packet,
   evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role});
  const calls={reads:0,checks:0,judge:0};
  const service=createRecovery({...deps,v01AuditAssessment:{async assertRetainedPacket(input){
   calls.reads++;assert.deepEqual(input.packet,JSON.parse(packet.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){calls.checks++;}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.V01_AUDIT_RUBRIC.family,
    scenario:evidence.V01_AUDIT_RUBRIC.scenario,objectiveId:evidence.V01_AUDIT_OBJECTIVE,
    rubricVersion:evidence.V01_AUDIT_RUBRIC.version,mode:'vuln',
    evidenceDigest:packet.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
    explanation:'Controlled V01 retry; no genuine credit'};
  }});
  return {f,base,service,calls,packet};
 }
 await t.test('original receipt retries Judge with no new audit read or actor effect',async()=>{
  const {f,base,service,calls,packet}=await setup();
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
  assert.equal(calls.judge,1);assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);
  const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.packet,packet.packet);assert.equal(child.run_id,f.parent.run_id);
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const [name,mutate,role] of [
  ['malformed packet',f=>{f.parent.packet='{';}],
  ['modified packet',f=>{const p=JSON.parse(f.parent.packet);p.evidence.at(-1).content+=' changed';f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['outer rubric',f=>{f.parent.rubric_version='unknown-v01-version';}],
  ['outer scenario',f=>{f.parent.scenario='different-scenario';}],
  ['non-customer',()=>{},'merchant'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});
  assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
});

test('V08 retained SVG browser retry binds exact original packet and customer without a new browser effect',async t=>{
 const evidence=require('../server/services/secureshopV08SvgEvidence');
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='customer'){
  const f=await fixture({role}),rubric=evidence.RUBRIC;
  const packet=prepareJudgeInput({rubric,evidence:[
   {id:'svg_upload_source',source:'server_observation',content:{sourceDigest:'a'.repeat(64),sessionId:randomUUID(),requestId:randomUUID(),excerpt:'Original qualified upload source excerpt.'}},
   {id:'svg_browser_execution',source:'server_observation',content:{receiptVersion:rubric.version,browser:{executed:true},excerpt:'Original attributed browser execution excerpt.'}},
  ],facts:Object.fromEntries(rubric.requiredFacts.map(id=>[id,true]))});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:rubric.family,scenario:rubric.scenario,
   rubric_version:rubric.version,packet:packet.packet,evidence_digest:packet.evidenceDigest,
   qualification:'native-browser-judge',live_mode:'vuln',live_generation:0,live_revision:'1',
   live_owner_generation:'0',catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role}),calls={reads:0,checks:0,judge:0};
  const service=createRecovery({...deps,svgUploadAssessment:{async assertRetainedPacket(input){
   calls.reads++;assert.deepEqual(input.packet,JSON.parse(packet.packet));assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){calls.checks++;}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   return {family:rubric.family,scenario:rubric.scenario,objectiveId:evidence.OBJECTIVE,
    rubricVersion:rubric.version,mode:'vuln',evidenceDigest:packet.evidenceDigest,
    runId:input.execution.runId,judgeVersion:JUDGE_VERSION,verdict:'unavailable',
    errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
    explanation:'Controlled V08 retry; no browser effect or genuine credit'};
  }});
  return {f,base,service,calls,packet};
 }
 await t.test('valid customer retries only Judge from the exact retained packet',async()=>{
  const {f,base,service,calls,packet}=await setup();
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(calls.judge,1);
  assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);
  assert.equal(f.judgments.get(result.childEvaluationId).packet,packet.packet);
 });
 for(const [name,mutate,role] of [
  ['modified packet',f=>{const p=JSON.parse(f.parent.packet);p.evidence[0].content.sourceDigest='b'.repeat(64);f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['non-customer',()=>{},'merchant'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});assert.equal(f.writes.length,0);
 });
});

test('V11 recovery binds the original packet and merchant before a read-only source fence or Judge retry',async t=>{
 const evidence=require('../server/services/secureshopMailAgentReadEvidence');
 const sourceFixture=require('./secureshopMailAgentReadEvidence.test').fixture;
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='merchant',reply='unavailable'){
  const f=await fixture({role}),original=sourceFixture(),source=original.input;
  f.parent.owner_key=JSON.stringify(['SecureShopBoundConversation',randomUUID()]);
  f.parent.execution_json={...f.parent.execution_json,ownerKey:f.parent.owner_key};
  const candidate=evidence.buildMailAgentReadCandidate({source:original.source,qualifyModel:source.qualifyModel,execution:{runId:f.parent.run_id,ownerKey:f.parent.owner_key,durableGeneration:'0'}});assert.ok(candidate);
  const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
   scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
   packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role});
  const calls={reads:0,checks:0,judge:0};
  const service=createRecovery({...deps,qualifyIdorModel:source.qualifyModel,mailAgentReadAssessment:{async assertRetainedPacket(input){
   calls.reads++;
   assert.deepEqual(input.packet,JSON.parse(packet.packet));
   assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'merchant'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){calls.checks++;}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,
    objectiveId:evidence.OBJECTIVE,rubricVersion:evidence.RUBRIC.version,mode:'vuln',
    evidenceDigest:packet.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:reply==='unavailable'?'unavailable':'pass',errorCode:reply==='unavailable'?'JUDGE_TIMEOUT':null,criteria:reply==='unavailable'?[]:[{id:'foreign_body_observed',satisfied:true,evidenceRefs:['mail_agent_read'],citations:[{evidenceId:'mail_agent_read',quote:reply==='body'?original.source.mail.message.bodyMarkdown:original.source.mail.message.subject}]}],provider:null,model:null,
    explanation:'Controlled V11 recovery branch; no genuine credit'};
  }});
  return {f,base,service,calls,packet};
 }
 await t.test('valid merchant retries the exact retained packet without source effects',async()=>{
  const {f,base,service,calls,packet}=await setup();
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);
  assert.equal(calls.judge,1);assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);
  const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.packet,packet.packet);assert.equal(child.run_id,f.parent.run_id);
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const reply of ['body','header'])await t.test('retry applies the original '+reply+' citation guard',async()=>{
  const {f,base,service,calls}=await setup('merchant',reply);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(calls.judge,1);assert.equal(result.completed,false,'controlled Judge cannot award credit');
  const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.verdict,reply==='body'?'pass':'unavailable');
  if(reply==='header')assert.equal(child.result_json.errorCode,'INVALID_JUDGE_OUTPUT');
  assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const [name,mutate,role] of [
  ['malformed packet',f=>{f.parent.packet='{';}],
  ['modified packet',f=>{const p=JSON.parse(f.parent.packet);p.evidence.at(-1).content+=' changed';f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['outer rubric',f=>{f.parent.rubric_version='unknown-v50-version';}],
  ['outer scenario',f=>{f.parent.scenario='different-scenario';}],
  ['non-merchant',()=>{},'admin'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),
   {code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});
  assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
});

test('V51 retry binds the immutable original NL SQL packet before read-only current-source checks',async t=>{
 const evidence=require('../server/services/secureshopAnalyticsNlSqlEvidence');
 const sourceFixture=require('./secureshopAnalyticsNlSqlEvidence.test').fixture;
 const createRecovery=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
 async function setup(role='merchant'){
  const f=await fixture({role}),original=sourceFixture();
  f.parent.owner_key=JSON.stringify(['SecureShopBoundConversation',randomUUID()]);
  f.parent.execution_json={...f.parent.execution_json,ownerKey:f.parent.owner_key};
  original.assessmentExecution={runId:f.parent.run_id,ownerKey:f.parent.owner_key,durableGeneration:'0'};
  const candidate=evidence.buildAnalyticsNlSqlCandidate(original);assert.ok(candidate);
  const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,
   rubric_version:evidence.RUBRIC.version,packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps}=await recoveryContext(f,{role});const calls={reads:0,checks:0,judge:0};let stale=false;
  const service=createRecovery({...deps,qualifyAnalyticsModel:original.qualifyModel,analyticsNlSqlAssessment:{async assertRetainedPacket(input){
   calls.reads++;assert.deepEqual(input.packet,JSON.parse(packet.packet));assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role});assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   if(stale)throw Error('Original source retired');return {async assertCurrent(){calls.checks++;if(stale)throw Error('Original source retired');}};
  }},judge:async input=>{
   calls.judge++;assert.equal(prepareJudgeInput(input).packet,packet.packet);assert.equal(input.execution.runId,f.parent.run_id);
   assert.deepEqual(evidence.readAnalyticsNlSqlOriginal(input,original.qualifyModel),original.source);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,objectiveId:evidence.OBJECTIVE,rubricVersion:evidence.RUBRIC.version,
    mode:'vuln',evidenceDigest:packet.evidenceDigest,runId:input.execution.runId,judgeVersion:JUDGE_VERSION,
    verdict:'unavailable',errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,explanation:'Controlled V51 retry; no genuine credit'};
  }});
  return {f,base,service,calls,packet,retire:()=>{stale=true;}};
 }
 for(const role of ['merchant','admin'])await t.test(role+' retries original packet without actor or SQL effects',async()=>{
  const {f,base,service,calls,packet}=await setup(role);
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'unavailable');assert.equal(result.completed,false);assert.equal(calls.judge,1);
  assert.ok(calls.reads>=2);assert.ok(calls.checks>=3);const child=f.judgments.get(result.childEvaluationId);
  assert.equal(child.packet,packet.packet);assert.equal(child.run_id,f.parent.run_id);assert.equal(f.links.size,1);assert.equal(f.invocations.length,1);
 });
 for(const [name,mutate,role] of [
  ['malformed packet',f=>{f.parent.packet='{';}],
  ['modified semantic evidence',f=>{const p=JSON.parse(f.parent.packet);p.evidence.at(-1).content.selectedSql='SELECT 1';f.parent.packet=JSON.stringify(p);}],
  ['outer digest',f=>{f.parent.evidence_digest='b'.repeat(64);}],
  ['outer rubric',f=>{f.parent.rubric_version='unknown-v51';}],
  ['outer scenario',f=>{f.parent.scenario='different-scenario';}],
  ['customer role',()=>{},'customer'],
 ])await t.test(name,async()=>{
  const {f,base,service,calls}=await setup(role);mutate(f);
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
  assert.deepEqual(calls,{reads:0,checks:0,judge:0});assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
 await t.test('retired original source denies before claiming a retry or invoking Judge',async()=>{
  const {f,base,service,calls,retire}=await setup();retire();
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),/Original source retired/);
  assert.equal(calls.judge,0);assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual(f.writes,[]);
 });
});

test('V44 malformed retained rubric fails closed before reader, Judge or retry writes', async () => {
 const f=await fixture();
 Object.assign(f.parent,{objective_id:'ss_file_path_traversal_read',family:'SecureShop',
  scenario:'bound_file_path_traversal',rubric_version:'secureshop-file-path-traversal-read-v1',
  packet:JSON.stringify({rubric:null,evidence:[],facts:{}}),qualification:'native-model',
  live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
  catalog_active:true,enabled:true,is_child:false,retry_count:0});
 const {deps,base}=await recoveryContext(f);let reads=0,calls=0;
 const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
  filePathSummaryAssessment:{async assertRetainedPacket(){reads++;throw Error('invalid packet reached reader');}},
  judge:async()=>{calls++;throw Error('invalid packet reached Judge');}});
 assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(reads,0);assert.equal(calls,0);assert.equal(f.writes.length,0);
});

test('V36 recovery denies unsafe historical contracts without rewriting history and preserves grounded successors',async t=>{
 const evidence=require('../server/services/secureshopAuditUnboundedEvidence');
 const {AUDIT_UNBOUNDED_RUBRIC_V1:V1,AUDIT_UNBOUNDED_RUBRIC_V2:V2,AUDIT_UNBOUNDED_RUBRIC_V3:V3}=evidence;
 async function setup(version=V3,role='admin'){
  const f=await fixture({role}),runId=f.parent.run_id,requestId=randomUUID(),nonce=randomUUID();
  const sha=value=>createHash('sha256').update(value).digest('hex');
  const witness=`[2026-10-16T06:30:43.216226Z] actor=admin action=audit_unbounded_requested target=${runId} params=${JSON.stringify({requestId,requestedCount:5000,nonce})}`;
  const packet=prepareJudgeInput({rubric:evidence.auditUnboundedRubric('vuln',version),
   facts:{completed_owned_audit_effect:true,qualified_model_received_exact_observation:true,observation_exceeds_fixed_projection_bounds:true},
   evidence:[{id:'audit_witness',source:'tool_result',content:witness},
    {id:'audit_summary',source:'assistant_response',content:'The summary mentions session creation but omits the protected event.'},
    {id:'audit_unbounded_provenance',source:'server_observation',content:{runId,requestedCount:5000,rowCount:130,sourceBytes:173361,
     logSha256:sha('owned log'),sourcesSha256:sha('owned sources'),observationSha256:sha('owned observation'),witnessSha256:sha(witness)}}]});
  assert.equal(packet.evidenceError,undefined);
  Object.assign(f.parent,{objective_id:evidence.AUDIT_UNBOUNDED_OBJECTIVE,family:'SecureShop',scenario:'bound_audit_summary',
   rubric_version:version,packet:packet.packet,evidence_digest:packet.evidenceDigest,
   qualification:'native-model',live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const {base,deps,retryRuns}=await recoveryContext(f,{role});let calls=0;
  const controlledJudge=require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{async chat(){
   const retained=JSON.parse(f.parent.packet);
   return {provider:'controlled',model:'recovery-fixture',mocked:false,response:JSON.stringify({
    observation:'The original summary omits the protected audit request and its identifiers.',
    responseRelation:'omits_event',satisfied:false,
    ...(retained.rubric.version===V3?{selectedRefs:['witness_record','summary_record']}
     :{citations:retained.evidence.filter(row=>['audit_witness','audit_summary'].includes(row.id))
      .map(row=>({evidenceId:row.id,quote:row.content}))})})};
  }}});
  const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
   judge:async input=>{calls++;assert.equal(prepareJudgeInput(input).packet,f.parent.packet);
    return controlledJudge(input);}});
  return {f,base,service,retryRuns,calls:()=>calls};
 }
 for(const [name,version,mutate,role] of [
  ['historical v1',V1,()=>{}],
  ['completed historical v1 remains immutable',V1,f=>{f.parent.verdict='pass';f.parent.disposition='awarded';}],
  ['v1 row relabeled v3',V1,f=>{f.parent.rubric_version=V3;}],
  ['v1 packet relabeled v3',V1,f=>{const p=JSON.parse(f.parent.packet);p.rubric.version=V3;f.parent.packet=JSON.stringify(p);} ],
  ['v1 row and packet relabeled v3',V1,f=>{const p=JSON.parse(f.parent.packet);p.rubric.version=V3;f.parent.packet=JSON.stringify(p);f.parent.rubric_version=V3;}],
  ['malformed packet',V3,f=>{f.parent.packet='{';}],
  ['null rubric',V3,f=>{const p=JSON.parse(f.parent.packet);p.rubric=null;f.parent.packet=JSON.stringify(p);} ],
  ['wrong digest',V3,f=>{f.parent.evidence_digest='b'.repeat(64);} ],
  ['wrong scenario',V3,f=>{f.parent.scenario='agent_loop';}],
  ['wrong family',V3,f=>{f.parent.family='Other';}],
  ['wrong mode',V3,f=>{f.parent.mode='fixed';}],
  ['v2 row with v3 packet',V3,f=>{f.parent.rubric_version=V2;}],
  ['non-admin',V3,()=>{},'customer'],
 ])await t.test(name,async()=>{
  const {f,base,service,retryRuns,calls}=await setup(version,role);mutate(f);
  const before=structuredClone([...f.judgments]);
  const listed=await service.list(base);assert.equal(listed.judgments.length,1);
  assert.equal(listed.judgments[0].canRetry,false);assert.equal(listed.judgments[0].verdict,f.parent.verdict);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'RETRY_NOT_ALLOWED'});
  assert.equal(calls(),0);assert.deepEqual(retryRuns,[]);assert.deepEqual(f.writes,[]);
  assert.equal(f.links.size,0);assert.equal(f.invocations.length,0);assert.deepEqual([...f.judgments],before);
 });
 for(const version of [V2,V3])await t.test(`valid ${version} recovery and replay`,async()=>{
  const {f,base,service,calls}=await setup(version),original=structuredClone(f.parent);
  assert.equal((await service.list(base)).judgments[0].canRetry,true);
  const result=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(result.verdict,'fail');assert.equal(result.completed,false);assert.equal(calls(),1);
  assert.deepEqual(f.parent,original);assert.equal(f.judgments.get(result.childEvaluationId).packet,original.packet);
  const replay=await service.retry(base,{evaluationId:f.parent.evaluation_id});
  assert.equal(replay.replayed,true);assert.equal(calls(),1);assert.deepEqual(f.parent,original);
 });
});


test('V29 recovery denies absent source authority before any retry or Judge',async()=>{
 const f=await fixture(),{base,deps,retryRuns}=await recoveryContext(f);let calls=0;
 const evidence=require('../server/services/secureshopAgencyRoleEvidence');
 const source=require('./secureshopAgencyRoleEvidence.test').fixture();
 const candidate=evidence.buildAgencyRoleCandidate(source);assert.ok(candidate);
 const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
 Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
  scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
  packet:packet.packet,evidence_digest:packet.evidenceDigest});
 const before=structuredClone([...f.judgments]);
 const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
  judge:async()=>{calls++;throw Error('Unqualified V29 reached Judge');}});
 assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(calls,0);assert.deepEqual(retryRuns,[]);assert.deepEqual(f.writes,[]);
 assert.deepEqual([...f.judgments],before);
});

test('V29 recovery rejects malformed or mismatched retained packets before source admission',async t=>{
 for(const [name,mutate] of [
  ['malformed JSON',f=>{f.parent.packet='{';}],
  ['foreign objective packet',()=>{}],
  ['digest mismatch',f=>{f.parent.evidence_digest='0'.repeat(64);}]
 ])await t.test(name,async()=>{
  const f=await fixture(),{base,deps,retryRuns}=await recoveryContext(f);
  f.parent.objective_id='ss_customer_role_escalation';mutate(f);
  const before=structuredClone([...f.judgments]);let sourceCalls=0,judgeCalls=0;
  const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
   agencyRoleAssessment:{assertRetainedPacket:async()=>{sourceCalls++;throw Error('Invalid packet reached source');}},
   judge:async()=>{judgeCalls++;throw Error('Invalid packet reached Judge');}});
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}));
  assert.equal(sourceCalls,0);assert.equal(judgeCalls,0);assert.deepEqual(retryRuns,[]);
  assert.deepEqual(f.writes,[]);assert.deepEqual([...f.judgments],before);
 });
});

test('V29 historical v2, v3 and v4 packets remain immutable and cannot retry under current v5 Judge',async()=>{
 const evidence=require('../server/services/secureshopAgencyRoleEvidence');
 const source=require('./secureshopAgencyRoleEvidence.test').fixture();
 for(const [version,rubric] of [[evidence.PREVIOUS_VERSION,evidence.RUBRIC_V2],
  [evidence.HISTORICAL_V3,evidence.RUBRIC_V3],[evidence.HISTORICAL_V4,evidence.RUBRIC_V4]]){
  const candidate=evidence.buildAgencyRoleCandidate(source,{evidenceVersion:version});
  assert.ok(candidate);
  const packet=prepareJudgeInput({rubric,...candidate});assert.equal(packet.evidenceError,undefined);
  const f=await fixture();Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:rubric.family,
   scenario:rubric.scenario,rubric_version:version,packet:packet.packet,
   evidence_digest:packet.evidenceDigest,qualification:'native-model',
   live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
   catalog_active:true,enabled:true,is_child:false,retry_count:0});
  const original=structuredClone(f.parent),{base,deps,retryRuns}=await recoveryContext(f);
  let sourceCalls=0,judgeCalls=0;
  const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
   agencyRoleAssessment:{async assertRetainedPacket(){sourceCalls++;throw Error('Historical source was retried');}},
   judge:async()=>{judgeCalls++;throw Error('Historical Judge was called');}});
  assert.equal((await service.list(base)).judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'RETRY_NOT_ALLOWED'});
  assert.equal(sourceCalls,0);assert.equal(judgeCalls,0);assert.deepEqual(retryRuns,[]);
  assert.deepEqual(f.writes,[]);assert.deepEqual(f.parent,original);
 }
});

test('V29 v4 model insufficient is terminal without a recovery model retry',async()=>{
 const evidence=require('../server/services/secureshopAgencyRoleEvidence');
 const source=require('./secureshopAgencyRoleEvidence.test').fixture();
 const candidate=evidence.buildAgencyRoleCandidate(source);assert.ok(candidate);
 const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});
 const f=await fixture();Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,
  family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,rubric_version:evidence.VERSION,
  packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
  live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
  catalog_active:true,enabled:true,is_child:false,retry_count:0,
  verdict:'unavailable',result_json:{verdict:'unavailable',errorCode:'SEMANTIC_COVERAGE_UNAVAILABLE'}});
 const original=structuredClone(f.parent),{base,deps,retryRuns}=await recoveryContext(f);
 let sourceCalls=0,judgeCalls=0;
 const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
  qualifyIdorModel:source.qualifyModel,
  agencyRoleAssessment:{async assertRetainedPacket(){sourceCalls++;return{assertCurrent:async()=>{}};}},
  judge:async()=>{judgeCalls++;throw Error('Insufficient result reached model');}});
 assert.equal((await service.list(base)).judgments[0].canRetry,false);
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'RETRY_NOT_ALLOWED'});
 assert.equal(sourceCalls,1,'read-only feature fence precedes terminal retry decision');
 assert.equal(judgeCalls,0);assert.equal(retryRuns.length,1);
 assert.deepEqual(f.writes,[]);assert.deepEqual(f.parent,original);
});

test('V29 valid recovery retains original evidence and checks current source before Judge',async()=>{
 const evidence=require('../server/services/secureshopAgencyRoleEvidence');
 const source=require('./secureshopAgencyRoleEvidence.test').fixture();
 const candidate=evidence.buildAgencyRoleCandidate(source);assert.ok(candidate);
 const packet=prepareJudgeInput({rubric:evidence.RUBRIC,...candidate});assert.equal(packet.evidenceError,undefined);
 const f=await fixture();Object.assign(f.parent,{objective_id:evidence.OBJECTIVE,family:evidence.RUBRIC.family,
  scenario:evidence.RUBRIC.scenario,rubric_version:evidence.RUBRIC.version,
  packet:packet.packet,evidence_digest:packet.evidenceDigest,qualification:'native-model',
  live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',
  catalog_active:true,enabled:true,is_child:false,retry_count:0});
 const original=structuredClone(f.parent),{base,deps}=await recoveryContext(f);
 let checks=0,calls=0,retired=false;
 const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,
  qualifyIdorModel:source.qualifyModel,
  agencyRoleAssessment:{async assertRetainedPacket(input){
   assert.deepEqual(input.packet,JSON.parse(packet.packet));assert.deepEqual(input.scope,f.scope);
   assert.deepEqual(input.persona,{id:f.actor,role:'customer'});
   assert.deepEqual(input.personaSession,{sessionId:f.input.sessionId,authorityVersion:'1'});
   return {async assertCurrent(){checks++;if(retired)throw Error('Agency source retired');}};
  }},judge:async input=>{
   calls++;assert.equal(prepareJudgeInput(input).packet,packet.packet);
   assert.equal(input.execution.runId,f.parent.run_id);
   return {family:evidence.RUBRIC.family,scenario:evidence.RUBRIC.scenario,objectiveId:evidence.OBJECTIVE,
    rubricVersion:evidence.RUBRIC.version,mode:'vuln',evidenceDigest:packet.evidenceDigest,
   runId:input.execution.runId,judgeVersion:JUDGE_VERSION,verdict:'unavailable',
    criteria:evidence.RUBRIC.criteria.map(c=>({id:c.id,satisfied:false,evidenceRefs:[]})),
    provider:null,model:null,explanation:'Controlled retry; no actual model qualification'};
  }});
 assert.equal((await service.list(base)).judgments[0].canRetry,true);
 const outcome=await service.retry(base,{evaluationId:f.parent.evaluation_id});
 assert.equal(outcome.completed,false);assert.equal(outcome.verdict,'unavailable');assert.equal(calls,1);
 assert.ok(checks>=2);assert.equal(f.judgments.get(outcome.childEvaluationId).packet,packet.packet);
 assert.deepEqual(f.parent,original);
 const replay=await service.retry(base,{evaluationId:f.parent.evaluation_id});
 assert.equal(replay.replayed,true);assert.equal(calls,1);
 retired=true;
 await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),/Agency source retired/);
 assert.equal(calls,1);assert.deepEqual(f.parent,original);
});

test('release exclusions deny stale qualified retries and keep recovery history visible',async()=>{
 for(const id of require('../server/config/secureshopCurriculum').RELEASE_EXCLUDED_OBJECTIVE_IDS){
  const f=await fixture();f.parent.objective_id=id;
  Object.assign(f.parent,{live_mode:'vuln',live_generation:0,live_revision:'1',live_owner_generation:'0',catalog_active:true,enabled:true,qualification:'native-model',is_child:false,retry_count:0});
  const before=structuredClone(f.parent),store=await f.store();
  await assert.rejects(f.begin(store),{code:'RETRY_NOT_ALLOWED'});
  const {base,deps}=await recoveryContext(f);let calls=0;
  const service=require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({...deps,judge:async()=>{calls++;throw Error('Excluded Judge');}});
  const list=await service.list(base);assert.equal(list.judgments.length,1);assert.equal(list.judgments[0].canRetry,false);
  await assert.rejects(service.retry(base,{evaluationId:f.parent.evaluation_id}),{code:'RETRY_NOT_ALLOWED'});
  assert.equal(calls,0);assert.deepEqual(f.writes,[]);assert.deepEqual(f.parent,before);
 }
});

test('stale enabled release-excluded catalog cannot award a passing result',async()=>{
 for(const id of require('../server/config/secureshopCurriculum').RELEASE_EXCLUDED_OBJECTIVE_IDS){
  const f=await fixture();Object.assign(f.parent,{objective_id:id,verdict:null,result_json:null,result_digest:null,disposition:'pending'});
  const s=await f.store({runId:f.parent.run_id});
  const result={family:f.parent.family,scenario:f.parent.scenario,objectiveId:id,rubricVersion:f.parent.rubric_version,
   evidenceDigest:f.parent.evidence_digest,runId:f.parent.run_id,mode:'vuln',verdict:'pass',criteria:[{id:'effect',satisfied:true,evidenceRefs:['effect']}],explanation:'Controlled pass',provider:'ollama',model:'fixture',judgeVersion:JUDGE_VERSION};
  const saved=await s.receipts.recordVerdict({userId:f.scope.platformOwnerId,evaluationId:f.parent.evaluation_id,result});
  assert.equal(saved.disposition,'grading_unqualified');assert.deepEqual(f.writes,['verdict']);
 }
});
