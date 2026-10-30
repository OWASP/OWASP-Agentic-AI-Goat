'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
const req=name=>require('../../'+name);
test('owned Analytics crosses a real persona transaction without reacquiring its locks',{skip:process.env.ANALYTICS_EFFECT_ONLY!=='1',timeout:150000},async()=>{
 const evidence={scope:'Zero-model canonical persona and private SQL effect qualification',calls:[],status:'running',semanticComplete:false},save=()=>fs.writeFileSync(process.env.ANALYTICS_ACTUAL_EVIDENCE,JSON.stringify(evidence,null,2)+'\n',{mode:0o600});save();
 const nonce=process.env.ANALYTICS_ACTUAL_OWNER;assert.match(nonce,/^[a-f0-9]{12}$/);const pools=[],state={};
 const createPool=config=>{const p=new Pool(config);p.on('error',()=>{});return p;};
 for(const store of ['IDENTITY','AGENTS','COMMERCE'])for(const role of ['MIGRATION','RUNTIME']){const url=new URL(process.env[`ANALYTICS_ACTUAL_${store}_${role}_URL`]);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,`/owasp_ai_goat_test_analytics_model_${nonce}_${store.toLowerCase()}`);state[`${store}_${role}`]=createPool({connectionString:url.href,max:8,connectionTimeoutMillis:1500,query_timeout:5000,...(store==='AGENTS'&&role==='RUNTIME'?{options:'-c lock_timeout=750ms'}:{})});pools.push(state[`${store}_${role}`]);}
 const controlDatabase=`owasp_ai_goat_analytics_control_${nonce}`,connection={host:'127.0.0.1',port:Number(process.env.ANALYTICS_ACTUAL_TARGET_PORT),user:'postgres',database:controlDatabase,connectionTimeoutMillis:1500,query_timeout:4000};assert.ok(connection.port>1024&&connection.port<65536);
 const control=createPool({...connection,max:5});pools.push(control);let service,scope;const nativeFetch=globalThis.fetch;globalThis.fetch=async()=>{throw Error('No network/model transport permitted');};
 try{
  const {migrate}=req('db/postgres/migrate');await migrate(state.IDENTITY_MIGRATION,'db/postgres/identity-migrations');await migrate(state.AGENTS_MIGRATION,'db/postgres/workshop-migrations/secureshop_agents');await migrate(state.COMMERCE_MIGRATION,'db/postgres/workshop-migrations/secureshop');await req('server/database/postgres/secureshopSeed').seedSecureShop(state.COMMERCE_MIGRATION);
  await control.query(fs.readFileSync('docs/modernization/drafts/secureshop-bound-analytics/control-schema.candidate.sql','utf8'));
  const systemIdentifier=(await control.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier;
  service=req('sidecars/analytics-sql-target/service').createOwnedAnalyticsService({controlPool:control,identity:{systemIdentifier,controlDatabase,clusterName:`owasp-ai-goat-owned-analytics-${nonce}`},createPool,connection});
  const identity=state.IDENTITY_RUNTIME,agents=state.AGENTS_RUNTIME;
  const launches=req('server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),progress=req('server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
  const bootstrap=await req('server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({identityPool:identity,agentsPool:agents,progress,resetComposition:{launches},expectedIdentityDatabase:`owasp_ai_goat_test_analytics_model_${nonce}_identity`,expectedAgentsDatabase:`owasp_ai_goat_test_analytics_model_${nonce}_agents`});
  const authority=bootstrap.personaAuthority,audit=req('server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
  const personas=req('server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:state.COMMERCE_RUNTIME,agentsPool:agents,personaAuthority:authority,auditStore:audit});await personas.ensureTemplates();
  const auth=req('server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-analytics-effect-fixture-secret-at-least-32-bytes'});
  const users=req('server/database/postgres/identityRepository').createIdentityRepository(identity),passwordHash=await require('bcryptjs').hash('owned-analytics',4),user=await users.createUser({username:'analytics-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash}),platformToken=randomUUID(),expiresAt=new Date(Date.now()+3600000).toISOString();
  const session=await users.createSession({userId:user.id,token:platformToken,expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});scope=req('server/services/secureshopConversationBinding').createLaunchScope(issued.binding);
  const login=await auth.login({scope,username:'student_merchant',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token}),persona={id:login.user.id,role:login.user.role},personaSession={sessionId:verified.sessionId,authorityVersion:verified.authorityVersion};
  const fence=await authority.capture({scope,personaId:persona.id,role:persona.role,...personaSession});
  // Reproduce the old nested check against actual held owner/launch locks. The
  // inner canonical transaction is canceled by its configured DB lock deadline.
  await assert.rejects(fence.withCrossStoreEffect(()=>fence.assertRemoteAdmission()),error=>{evidence.oldBoundaryError={code:error.code,causeCode:error.cause?.code,message:error.cause?.message};save();return error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&['55P03','57014'].includes(error.cause?.code);});
  const target=await service.provision(scope),adapter=req('server/services/secureshopOwnedAnalyticsAdapter').createOwnedAnalyticsAdapter({launches,personaAuthority:authority,targetService:service,schema:service.schema});
  const input={target,scope,persona,personaSession,signal:undefined,checkCurrent:()=>fence.assertRemoteAdmission(),operationId:randomUUID(),runId:randomUUID(),requestId:randomUUID(),sessionId:randomUUID(),callId:'native-query',sql:'SELECT COUNT(*) AS count FROM products'};
  const result=await adapter.execute(input);assert.equal(result.result.rows[0].count,'256');assert.deepEqual(await adapter.execute(input),result);assert.equal(Number((await control.query('SELECT count(*) FROM owned_analytics_queries')).rows[0].count),1);
  evidence.receipt={targetId:result.targetId,resultSha256:result.resultSha256,rowCount:result.result.row_count,count:result.result.rows[0].count};
  await auth.logout({scope,token:login.token});await assert.rejects(adapter.execute({...input,operationId:randomUUID()}));assert.equal(Number((await control.query('SELECT count(*) FROM owned_analytics_queries')).rows[0].count),1);
  evidence.semanticComplete=true;evidence.status='passed';save();
 }finally{globalThis.fetch=nativeFetch;let retirementError;try{if(scope)await service?.retire(scope);}catch(error){retirementError=error;evidence.cleanupError=error.code||error.message;}const closed=await Promise.allSettled(pools.map(p=>p.end()));save();assert.ok(closed.every(r=>r.status==='fulfilled'));if(retirementError)throw retirementError;}
});
