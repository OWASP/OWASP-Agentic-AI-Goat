'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {seedSecureShopAssessmentDefaults}=require('../server/database/postgres/secureshopAssessmentSeed');
const {OBJECTIVES}=require('../server/config/secureshopCurriculum');
const {createSecureShopAssessmentSubjects,subjectState}=require('../server/services/secureshopAssessmentSubject');
const {createObjectiveCompletionService}=require('../server/services/secureshopObjectiveCompletionService');
const {createObjectiveJudge,prepareJudgeInput,readConfiguredJudgeProvenance}=require('../server/agent-runtime/objectiveJudge');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:501,platformSessionId:502};
const execution=()=>({runId:randomUUID(),ownerKey:'shop-test',durableGeneration:'0',check:async()=>{}});
test('shop default seed registers disabled System traversal on fresh stores and preserves populated instructor state on no-op',async()=>{
 const makePool=rows=>{const calls=[];const client={release(){},async query(sql,p){calls.push(sql);if(!sql.includes('INSERT'))return{};
  if(rows.has(p[0]))return{rowCount:0};rows.set(p[0],{enabled:p[2],qualification:p[3],source:JSON.parse(p[5]),sha:p[4]});return{rowCount:1};}};
  return {calls,pool:{connect:async()=>client}};};
 const id='ss_system_config_traversal',objective=OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective?.qualification,'native-model');assert.equal(objective?.defaultEnabled,false);
 const freshRows=new Map(),fresh=makePool(freshRows);
 assert.equal((await seedSecureShopAssessmentDefaults(fresh.pool)).inserted,OBJECTIVES.length);
 const freshSystem=freshRows.get(id);assert.deepEqual(freshSystem.source,{version:1,id,label:objective.text,defaultEnabled:false,qualification:'native-model'});
 assert.equal(freshSystem.enabled,false);assert.equal(freshSystem.qualification,'native-model');assert.match(freshSystem.sha,/^[a-f0-9]{64}$/);
 const populatedRows=new Map([[id,{enabled:true,qualification:'instructor-owned',source:{instructor:true},sha:'custom'}]]),populated=makePool(populatedRows);
 assert.equal((await seedSecureShopAssessmentDefaults(populated.pool)).inserted,OBJECTIVES.length-1);
 assert.deepEqual(populatedRows.get(id),{enabled:true,qualification:'instructor-owned',source:{instructor:true},sha:'custom'});
 assert.equal((await seedSecureShopAssessmentDefaults(populated.pool)).inserted,0);
 assert.deepEqual(populatedRows.get(id),{enabled:true,qualification:'instructor-owned',source:{instructor:true},sha:'custom'});
 assert.equal(fresh.calls.filter(sql=>sql==='COMMIT').length,1);assert.equal(populated.calls.filter(sql=>sql==='COMMIT').length,2);
});
test('private subject binds exact actor and explicit realm without accepting serialized authority',async()=>{
 let realm='shop',actor=1000000001;const tenantId=randomUUID(),principalId=randomUUID();
 const identityPool={async query(sql,p){if(sql.includes('SELECT realm'))return{rows:[{realm,shop_tenant_id:realm==='platform'?null:tenantId}]};return{rows:p[2]===actor?[{tenant_id:tenantId,principal_id:principalId,shop_user_id:actor,membership_version:'1'}]:[]};}};
 const fence={assertRemoteAdmission:async()=>{},withCrossStoreEffect:fn=>fn()};
 const subjects=createSecureShopAssessmentSubjects({identityPool,launches:{assertCurrent:async()=>{}},personaAuthority:{capture:()=>fence}});
 const input={scope,personaId:actor,role:'customer',sessionId:randomUUID(),authorityVersion:'1'},run=execution();
 const subject=await subjects.capture(input,run);assert.equal(subjectState(subject).binding.principalId,principalId);
 assert.throws(()=>subjectState({...subject}),{code:'SHOP_ASSESSMENT_STALE'});
 await assert.rejects(subjects.capture({...input,personaId:actor+1},run),{code:'SHOP_ASSESSMENT_STALE'});
 realm='platform';assert.equal(await subjects.capture(input,run),null);
 realm='unknown';await assert.rejects(subjects.capture(input,run),{code:'SHOP_ASSESSMENT_STALE'});
});
test('completion selects the private shop store before progress and preserves legacy selection',async()=>{
 const calls=[],store=name=>({progress:{getGeneration:async()=>{calls.push(name);return 0;}},receipts:{beginEvaluation:async()=>{},recordVerdict:async()=>{}}});
 const legacy=store('legacy'),shop=store('shop'),subject=Object.freeze({});let resolve=0;
 const service=createObjectiveCompletionService({...legacy,resolveExecutionStores:async()=>{resolve++;return{...shop,subject,observeJudge:(input,judge)=>judge(input)};},captureInstanceScope:async()=>scope});
 const run=execution(),input={userId:501,workshopKey:'secureshop_agent_security',objectiveId:'ss_loop_observation',execution:run};
 const attempt=await service.beginAttempt(input);await service.beginAttempt(input);
 assert.deepEqual(calls,['shop','shop']);assert.equal(resolve,1);
 await assert.rejects(service.evaluate({...input,execution:execution(),attempt}),/Matching assessment attempt/);
 await assert.rejects(service.retry({...input,evaluationId:randomUUID()}),{code:'RETRY_NOT_ALLOWED'});
 const old=createObjectiveCompletionService({...legacy,resolveExecutionStores:async()=>null,captureInstanceScope:async()=>scope,capturePersonaEvaluation:async()=>({})});
 await old.beginAttempt({...input,execution:execution()});assert.equal(calls.at(-1),'legacy');
});
test('injected Judge transport and forged event labels cannot create configured provenance',async()=>{
 const rubric={family:'SecureShop',scenario:'agent_loop',objectiveId:'ss_loop_observation',version:'test-v1',mode:'vuln',requiredFacts:['effect'],criteria:[{id:'effect',description:'Observed effect occurred',allowedSources:['server_observation']}]};
 const packet={rubric,evidence:[{id:'effect',source:'server_observation',content:'Observed exact owned effect'}],facts:{effect:true}};
 let calls=0;
 const judge=createObjectiveJudge({model:{chat:async()=>{calls++;return{provider:'ollama',model:'pretend',mocked:false,fallback:false,response:JSON.stringify({verdict:'pass',criteria:[{id:'effect',satisfied:true,evidenceRefs:['effect']}],explanation:'Observed effect'})};}}});
 const result=await judge({...packet,execution:execution()});assert.ok(calls>0);assert.equal(readConfiguredJudgeProvenance(result),null);
 const forged={...result,evidenceDigest:prepareJudgeInput(packet).evidenceDigest,verdict:'pass',provider:'ollama',model:'pretend'};
 assert.equal(readConfiguredJudgeProvenance(forged),null);assert.equal(readConfiguredJudgeProvenance(JSON.parse(JSON.stringify(result))),null);
});

test('assessment catalog accepts only private admin authority and exact CAS input',async()=>{
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopAssessmentCatalog}=require('../server/services/secureshopAssessmentCatalog');
 const tenantId=randomUUID(),principalId=randomUUID(),expiresAt=new Date(Date.now()+60000).toISOString();let role='admin',code;
 const row=()=>({principalId,ownerId:90,sessionId:91,shopUserId:1000000001,username:'admin_test',email:'admin@shop.test',
  role,credentialVersion:'1',authorityVersion:'1',expiresAt});
 const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession',
  'revokeSession','readCredentialForSession','changePassword','revokeAll'].map(name=>[name,async()=>{}]));
 repository.readCurrentSession=async()=>row();repository.readOrCreateDefaultExecutionSession=async()=>({...row(),principalOwnerId:90,ownerId:500,authSessionId:91,sessionId:92,tenantId,membershipVersion:'1'});
 const authService=createSecureShopStandaloneAuthService({repository});let calls=0,listedId='ss_loop_observation';
 const catalog=createSecureShopAssessmentCatalog({authService,pool:{async query(sql,p){calls++;if(code)throw Object.assign(Error('private SQL detail'),{code});
  if(sql.includes('set_assessment_objective')){assert.deepEqual(p,[92,tenantId,principalId,'ss_loop_observation',true,'1']);return{rows:[{objective_id:p[3],is_enabled:true,qualification:'native-model',revision:'2'}]};}
  return{rows:[{objective_id:listedId,label:'Observe loop',is_enabled:listedId!=='ss_loop_observation',qualification:'native-model',revision:'1'}]};}}});
 const base=await authService.authenticate('a'.repeat(43));
 assert.equal((await catalog.list(base)).objectives[0].enabled,false);
 assert.deepEqual(await catalog.set(base,{objectiveId:'ss_loop_observation',enabled:true,expectedRevision:'1'}),{objectiveId:'ss_loop_observation',enabled:true,qualification:'native-model',revision:'2'});
 await assert.rejects(catalog.set(base,{objectiveId:'ss_loop_observation',enabled:true,expectedRevision:'1',tenantId}),{code:'INVALID_ARGUMENT'});
 for(const [sqlCode,errorCode] of [['40001','SHOP_OBJECTIVE_CONFLICT'],['22023','SHOP_OBJECTIVE_UNQUALIFIED'],['28000','SHOP_ADMIN_REQUIRED']]){
  code=sqlCode;await assert.rejects(catalog.set(base,{objectiveId:'ss_loop_observation',enabled:true,expectedRevision:'1'}),{code:errorCode});
 }
 code=undefined;
 for(const id of require('../server/config/secureshopCurriculum').RELEASE_EXCLUDED_OBJECTIVE_IDS){
  listedId=id;const prior=calls;await assert.rejects(catalog.set(base,{objectiveId:id,enabled:true,expectedRevision:'1'}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});assert.equal(calls,prior);
  const row=(await catalog.list(base)).objectives[0];assert.equal(row.enabled,false);assert.equal(row.qualification,'pending');
 }
 await assert.rejects(catalog.list({...base}),{code:'SHOP_AUTH_INVALID'});
 role='customer';const customer=await authService.authenticate('b'.repeat(43)),before=calls;
 await assert.rejects(catalog.list(customer),{code:'SHOP_ADMIN_REQUIRED'});assert.equal(calls,before);
});

test('disabled assessment skips inference and emits a canonical inconclusive result without an infrastructure error',async()=>{
 const {createSecureShopAssessmentStore}=require('../server/database/postgres/secureshopAssessmentStore');
 const {resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
 const tenantId=randomUUID(),principalId=randomUUID(),actor=1000000001,run=execution();
 let effectiveEnabled=false;
 const query=async(sql)=>{
  if(['BEGIN','COMMIT'].includes(sql)||sql.includes('pg_advisory_xact_lock'))return{rows:[]};
  if(sql.includes('SELECT realm'))return{rows:[{realm:'shop',shop_tenant_id:tenantId}]};
  if(sql.includes('SELECT e.tenant_id'))return{rows:[{tenant_id:tenantId,principal_id:principalId,shop_user_id:actor,membership_version:'1'}]};
  if(sql.includes('SELECT s.id'))return{rows:[{id:scope.platformSessionId}]};
  if(sql.includes('SELECT l.launch_id'))return{rows:[{launch_id:scope.launchId}]};
  if(sql.includes('lock_assessment_mode'))return{rows:[{mode:'vuln',generation:0,revision:'1'}]};
  if(sql.includes('SELECT o.*'))return{rows:[{catalog_active:true,effective_enabled:effectiveEnabled,qualification:'native-model'}]};
  throw Error('Unexpected assessment query');
 };
 const pool={query,connect:async()=>({query,release(){}})},fence={assertRemoteAdmission:async()=>{},withCrossStoreEffect:fn=>fn()};
 const subjects=createSecureShopAssessmentSubjects({identityPool:pool,launches:{assertCurrent:async()=>{}},personaAuthority:{capture:()=>fence}});
 const subject=await subjects.capture({scope,personaId:actor,role:'customer',sessionId:randomUUID(),authorityVersion:'1'},run);
 const store=createSecureShopAssessmentStore({pool,subject});
 const rubric={family:'SecureShop',scenario:'agent_loop',objectiveId:'ss_loop_observation',version:'test-v1',mode:'vuln',requiredFacts:['effect'],criteria:[{id:'effect',description:'Observed owned effect',allowedSources:['server_observation']}]};
 let modelCalls=0;
 const result=await store.observeJudge({rubric,evidence:[{id:'effect',source:'server_observation',content:'Owned effect'}],facts:{effect:true},execution:run},async()=>{modelCalls++;throw Error('Disabled objective invoked Judge');});
 assert.equal(modelCalls,0);assert.equal(result.verdict,'inconclusive');assert.equal(Object.hasOwn(result,'errorCode'),false);
 const normalized=resultValue(result,{family:rubric.family,scenario:rubric.scenario,objective_id:rubric.objectiveId,
  rubric_version:rubric.version,evidence_digest:result.evidenceDigest,run_id:run.runId,mode:'vuln'});
 effectiveEnabled=true;
 for(const id of require('../server/config/secureshopCurriculum').RELEASE_EXCLUDED_OBJECTIVE_IDS){
  const denied=await store.observeJudge({rubric:{...rubric,objectiveId:id},evidence:[{id:'effect',source:'server_observation',content:'Owned effect'}],facts:{effect:true},execution:run},()=>{modelCalls++;throw Error('Excluded inference');});
  assert.equal(denied.verdict,'inconclusive');assert.equal(modelCalls,0);
 }
 assert.equal(normalized.errorCode,null);assert.equal(normalized.verdict,'inconclusive');assert.equal(normalized.provider,null);
});

test('release exclusions deny stale enabled eligibility in both supported authority realms',async()=>{
 const {readSecureShopAssessmentEligibility}=require('../server/services/secureshopAssessmentEligibility');
 const {RELEASE_EXCLUDED_OBJECTIVE_IDS:ids}=require('../server/config/secureshopCurriculum');
 for(const realm of ['shop','platform']){
  let queries=0;const pool={async query(sql,args){queries++;if(sql.includes('SELECT realm'))return{rows:[{realm,shop_tenant_id:realm==='shop'?randomUUID():null}]};
   assert.deepEqual(args.at(-1),['ss_idor_cart_delete']);return{rows:[...ids,'ss_idor_cart_delete'].map(objective_id=>({objective_id}))};}};
  assert.deepEqual(await readSecureShopAssessmentEligibility(pool,scope,ids),[]);assert.equal(queries,0);
  assert.deepEqual(await readSecureShopAssessmentEligibility(pool,scope,[...ids,'ss_idor_cart_delete']),['ss_idor_cart_delete']);
 }
});
