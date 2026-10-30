'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{randomUUID,createHash}=require('node:crypto'),path=require('node:path'),{Pool}=require('pg');
const req=name=>require('../../'+name);
const agentsDirectory=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
function migrationView(before){
 assert.ok(before==='0032_'||before==='0034_');
 const fsp=require('node:fs/promises'),{Module,createRequire}=require('node:module');
 const filename=require.resolve('../../db/postgres/migrate'),localRequire=createRequire(filename),loaded=new Module(filename,module);
 loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?{
  async readdir(directory,...args){assert.equal(path.resolve(directory),agentsDirectory);return(await fsp.readdir(directory,...args)).filter(name=>name<before);},
  readFile:(...args)=>fsp.readFile(...args),
 }:localRequire(name);
 loaded._compile(fs.readFileSync(filename,'utf8'),filename);return loaded.exports;
}
test('Analytics historical-prefix views preserve canonical SQL checksums without filesystem mutation',async()=>{
 const fsp=require('node:fs/promises'),original=fsp.readdir,full=await req('db/postgres/migrate').readMigrations(agentsDirectory);
 for(const before of ['0032_','0034_'])assert.deepEqual(await migrationView(before).readMigrations(agentsDirectory),full.filter(row=>row.name<before));
 assert.equal(fsp.readdir,original);assert.deepEqual(await req('db/postgres/migrate').readMigrations(agentsDirectory),full);
 assert.deepEqual(fs.readFileSync('docs/modernization/drafts/secureshop-bound-analytics/0032_analytics_request_admission.candidate.sql'),fs.readFileSync(path.join(agentsDirectory,'0032_analytics_request_admission.sql')));
});
test('Analytics candidate admission migration, original-session races and lifecycle',{skip:process.env.ANALYTICS_ADMISSION_ONLY!=='1',timeout:process.env.ANALYTICS_MOUNTED_ONLY==='1'?270000:210000},async()=>{
 const evidence={scope:'Zero-model Analytics historical-prefix upgrade followed by canonical current-tail admission; native result required',calls:[],status:'running',semanticComplete:false},save=()=>fs.writeFileSync(process.env.ANALYTICS_ACTUAL_EVIDENCE,JSON.stringify(evidence,null,2)+'\n',{mode:0o600});save();
 const nonce=process.env.ANALYTICS_ACTUAL_OWNER;assert.match(nonce,/^[a-f0-9]{12}$/);const pools=[],state={};
 const createPool=config=>{const p=new Pool(config);p.on('error',()=>{});return p;};
 for(const store of ['IDENTITY','AGENTS','COMMERCE',...(process.env.ANALYTICS_MOUNTED_ONLY==='1'?['REVIEW']:[])])for(const role of ['MIGRATION','RUNTIME']){const url=new URL(process.env[`ANALYTICS_ACTUAL_${store}_${role}_URL`]);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,`/owasp_ai_goat_test_analytics_model_${nonce}_${store.toLowerCase()}`);state[`${store}_${role}`]=createPool({connectionString:url.href,max:8,connectionTimeoutMillis:1500,query_timeout:5000,...(store==='AGENTS'&&role==='RUNTIME'?{options:'-c lock_timeout=750ms'}:{})});pools.push(state[`${store}_${role}`]);}
 const controlDatabase=`owasp_ai_goat_analytics_control_${nonce}`,connection={host:'127.0.0.1',port:Number(process.env.ANALYTICS_ACTUAL_TARGET_PORT),user:'postgres',database:controlDatabase,connectionTimeoutMillis:1500,query_timeout:4000};assert.ok(connection.port>1024&&connection.port<65536);

 const control=createPool({...connection,max:5});pools.push(control);let service,scope;const nativeFetch=globalThis.fetch;globalThis.fetch=async()=>{throw Error('No network/model transport permitted');};
 try{
  const {migrate}=req('db/postgres/migrate');await migrate(state.IDENTITY_MIGRATION,'db/postgres/identity-migrations');await req('server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(state.IDENTITY_MIGRATION);await migrationView('0032_').migrate(state.AGENTS_MIGRATION,agentsDirectory);await migrate(state.COMMERCE_MIGRATION,'db/postgres/workshop-migrations/secureshop');await req('server/database/postgres/secureshopSeed').seedSecureShop(state.COMMERCE_MIGRATION);if(state.REVIEW_MIGRATION)await migrate(state.REVIEW_MIGRATION,'db/postgres/workshop-migrations/secureshop_review');
  const systemIdentifier=(await control.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier;
  const controlIdentity={systemIdentifier,controlDatabase,clusterName:`owasp-ai-goat-owned-analytics-${nonce}`},controlBootstrap=req('sidecars/analytics-sql-target/bootstrap');
  const requiredVersion=process.env.ANALYTICS_MOUNTED_ONLY==='1'?2:1;const initialized=await controlBootstrap.initializeControl({pool:control,identity:controlIdentity,requiredVersion});assert.deepEqual(await controlBootstrap.initializeControl({pool:control,identity:controlIdentity,requiredVersion}),initialized);
  await control.query("UPDATE owned_analytics_schema_migrations SET sha256=$1 WHERE name=$2",['0'.repeat(64),initialized.migration]);await assert.rejects(controlBootstrap.initializeControl({pool:control,identity:controlIdentity}));await control.query('UPDATE owned_analytics_schema_migrations SET sha256=$1 WHERE name=$2',[initialized.sha256,initialized.migration]);
  await control.query('ALTER TABLE owned_analytics_queries DISABLE TRIGGER owned_analytics_query_immutable');await assert.rejects(controlBootstrap.assertControlReady({pool:control,identity:controlIdentity}));await control.query('ALTER TABLE owned_analytics_queries ENABLE TRIGGER owned_analytics_query_immutable');await controlBootstrap.assertControlReady({pool:control,identity:controlIdentity});
  evidence.controlBootstrap={requiredVersion,fresh:true,noop:true,checksumDriftRejected:true,triggerDriftRejected:true};save();
  service=req('sidecars/analytics-sql-target/service').createOwnedAnalyticsService({controlPool:control,identity:controlIdentity,createPool,connection});
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
  const candidate='docs/modernization/drafts/secureshop-bound-analytics/0032_analytics_request_admission.candidate.sql',migrationName='0032_analytics_request_admission.sql';
  const selectedMigration=migrationView('0034_');
  try{
   assert.deepEqual(fs.readFileSync(candidate),fs.readFileSync(path.join(agentsDirectory,migrationName)));
   const before=(await state.AGENTS_MIGRATION.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;
   const registered=await selectedMigration.readMigrations(agentsDirectory),registeredNames=registered.map(row=>row.name);assert.deepEqual(await selectedMigration.migrate(state.AGENTS_MIGRATION,agentsDirectory),registeredNames.filter(name=>name>=migrationName));assert.deepEqual(await selectedMigration.migrate(state.AGENTS_MIGRATION,agentsDirectory),[]);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,before);
   const fresh={};for(const role of ['MIGRATION','RUNTIME']){const url=new URL(process.env[`ANALYTICS_ACTUAL_FRESH_${role}_URL`]);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,`/owasp_ai_goat_test_analytics_model_${nonce}_fresh`);fresh[role]=createPool({connectionString:url.href,max:2,query_timeout:5000});pools.push(fresh[role]);}
   assert.deepEqual(await selectedMigration.migrate(fresh.MIGRATION,agentsDirectory),registeredNames);assert.deepEqual(await selectedMigration.migrate(fresh.MIGRATION,agentsDirectory),[]);
   // Separate historical owners keep later capacity/reset cohorts independent.
   const legacyConversations=req('server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
   const legacyFields=['launch_id','scenario_id','generation','platform_owner_id','platform_session_id','persona_id','role','request_id','persona_session_id','authority_version','session_id','question_sha256','question'];
   for(const label of ['owner','sibling']){
    const legacyUser=await users.createUser({username:'legacy-mode-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash});
    const legacySession=await users.createSession({userId:legacyUser.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});
    const legacyLaunch=await launches.issueOrRenew({platformOwnerId:legacyUser.id,platformSessionId:legacySession.id,expiresAt});
    const legacyScope=req('server/services/secureshopConversationBinding').createLaunchScope(legacyLaunch.binding);
    const legacyLogin=await auth.login({scope:legacyScope,username:'student_merchant',password:'student123'}),legacyVerified=await auth.authenticateBoundToken({scope:legacyScope,token:legacyLogin.token});
    const legacyBinding={...legacyScope,shopUserId:legacyLogin.user.id,role:legacyLogin.user.role};
    const legacyConversation=await legacyConversations.acquireBoundSession({id:randomUUID(),binding:legacyBinding,purpose:'secureshop_analytics'});await legacyConversations.activateBoundSession(legacyConversation.id,legacyBinding,'secureshop_analytics');
    const question='Historical '+label+' admission';
    await agents.query(`INSERT INTO secureshop_agents.analytics_request_admissions(${legacyFields.join(',')}) VALUES(${legacyFields.map((_,i)=>'$'+(i+1)).join(',')})`,[legacyScope.launchId,legacyScope.scenarioId,legacyScope.generation,legacyScope.platformOwnerId,legacyScope.platformSessionId,legacyLogin.user.id,legacyLogin.user.role,randomUUID(),legacyVerified.sessionId,legacyVerified.authorityVersion,legacyConversation.id,createHash('sha256').update(question).digest('hex'),question]);
   }
   const legacyAdmissions=(await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions ORDER BY request_id')).rows;assert.equal(legacyAdmissions.length,2);assert.equal(new Set(legacyAdmissions.map(row=>row.platform_owner_id)).size,2);
   // Retain the historical transition above, then qualify current schema too.
   const historicalSessions=(await state.AGENTS_MIGRATION.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;
   const historicalLedger=(await state.AGENTS_MIGRATION.query('SELECT name,checksum,applied_at FROM dvaia_migrations.ledger ORDER BY name')).rows;
   const fullCanonical=await req('db/postgres/migrate').readMigrations(agentsDirectory);
   const remainingNames=fullCanonical.filter(row=>row.name>='0034_').map(row=>row.name);
   for(const target of [state.AGENTS_MIGRATION,fresh.MIGRATION]){
    assert.deepEqual(await migrate(target,agentsDirectory),remainingNames);
    assert.deepEqual(await migrate(target,agentsDirectory),[]);
    assert.deepEqual((await target.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,fullCanonical.map(({name,checksum})=>({name,checksum})));
   }
   assert.deepEqual((await state.AGENTS_MIGRATION.query('SELECT name,checksum,applied_at FROM dvaia_migrations.ledger WHERE name<$1 ORDER BY name',['0034_'])).rows,historicalLedger);
   assert.deepEqual((await state.AGENTS_MIGRATION.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows.map(row=>Object.fromEntries(Object.keys(historicalSessions[0]).map(key=>[key,row[key]]))),historicalSessions);
   assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions ORDER BY request_id')).rows,legacyAdmissions.map(row=>({...row,mode_snapshot:null})));
   evidence.populated0034={owners:2,exactRowsPreserved:true,legacyModesNull:true};save();
   const readiness=pool=>req('server/database/postgres/secureshopAnalyticsRequestReadiness').assertAnalyticsRequestReadiness(pool,{requiredVersion:2});await readiness(agents);await readiness(fresh.RUNTIME);
   let drifts=0;async function drift(change,restore){await fresh.MIGRATION.query(change);try{await assert.rejects(readiness(fresh.RUNTIME));drifts++;}finally{await fresh.MIGRATION.query(restore);}await readiness(fresh.RUNTIME);}
   await drift('GRANT UPDATE ON secureshop_agents.analytics_request_admissions TO dvaia_secureshop_agents_runtime','REVOKE UPDATE ON secureshop_agents.analytics_request_admissions FROM dvaia_secureshop_agents_runtime');
   await drift('REVOKE INSERT ON secureshop_agents.analytics_request_admissions FROM dvaia_secureshop_agents_runtime','GRANT INSERT ON secureshop_agents.analytics_request_admissions TO dvaia_secureshop_agents_runtime');
   await drift('ALTER TABLE secureshop_agents.analytics_request_admissions DISABLE TRIGGER analytics_request_admission_guard','ALTER TABLE secureshop_agents.analytics_request_admissions ENABLE TRIGGER analytics_request_admission_guard');
   await drift("CREATE OR REPLACE FUNCTION secureshop_agents.guard_analytics_request_admission() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$",fs.readFileSync(path.join(agentsDirectory,'0052_analytics_registered_actor_admission.sql'),'utf8'));
   await drift('GRANT EXECUTE ON FUNCTION secureshop_agents.cleanup_analytics_request_admissions() TO PUBLIC','REVOKE EXECUTE ON FUNCTION secureshop_agents.cleanup_analytics_request_admissions() FROM PUBLIC');evidence.readinessDrifts=drifts;save();
   const checksum=(await state.AGENTS_MIGRATION.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[migrationName])).rows[0].checksum;assert.equal(checksum,createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'));
   const repository=req('server/database/postgres/secureshopAnalyticsRequestRepository').createAnalyticsRequestRepository({personaAuthority:authority});
   const conversations=req('server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
   const standalone=req('server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:req('server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity})});
   const registeredAuth=await standalone.register({username:'analytics_registered_'+randomUUID().slice(0,8),email:randomUUID()+'@analytics.invalid',password:'disposable analytics merchant password',role:'merchant'});
   const registeredPrincipal=await standalone.establishTenantContext(registeredAuth.context);
   const registeredLaunch=await launches.issueOrRenew({platformOwnerId:registeredPrincipal.ownerId,platformSessionId:registeredPrincipal.sessionId,expiresAt,shopPrincipal:registeredPrincipal});
   const registeredScope=req('server/services/secureshopConversationBinding').createLaunchScope(registeredLaunch.binding);
   const registeredBound=await auth.establishSession({scope:registeredScope,shopPrincipal:registeredPrincipal});
   const registeredVerified=await auth.authenticateBoundToken({scope:registeredScope,token:registeredBound.token});
   const registeredPersona={id:registeredBound.user.id,role:registeredBound.user.role};
   assert.ok(registeredPersona.id>=1000000000);assert.equal(registeredPersona.role,'merchant');
   const registeredSession={sessionId:registeredVerified.sessionId,authorityVersion:registeredVerified.authorityVersion};
   const registeredBinding={...registeredScope,shopUserId:registeredPersona.id,role:registeredPersona.role};
   const registeredConversation=await conversations.acquireBoundSession({id:randomUUID(),binding:registeredBinding,purpose:'secureshop_analytics'});
   await conversations.activateBoundSession(registeredConversation.id,registeredBinding,'secureshop_analytics');
   const registeredMode=await req('server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity).getEvaluationScope(registeredScope.platformOwnerId,'secureshop_agent_security',registeredScope);
   const registeredInput={scope:registeredScope,persona:registeredPersona,personaSession:registeredSession,modeSnapshot:registeredMode,sessionId:registeredConversation.id,requestId:randomUUID(),question:'Registered merchant bounded analytics admission'};
   assert.equal((await repository.admit(registeredInput)).created,true);
   assert.equal((await repository.read(registeredInput)).status,'admitted');
   assert.equal((await agents.query('SELECT count(*)::integer AS n FROM secureshop_agents.bound_persona_templates WHERE shop_user_id=$1',[registeredPersona.id])).rows[0].n,0);
   const registeredStored=(await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions WHERE request_id=$1',[registeredInput.requestId])).rows[0];
   assert.ok(registeredStored);evidence.registeredActorAdmission={shopUserId:registeredPersona.id,templateRows:0,admitted:true};save();
   const binding={...scope,shopUserId:persona.id,role:persona.role};const conversation=await conversations.acquireBoundSession({id:randomUUID(),binding,purpose:'secureshop_analytics'});await conversations.activateBoundSession(conversation.id,binding,'secureshop_analytics');
   const modeSnapshot=await progress.getEvaluationScope(scope.platformOwnerId,'secureshop_agent_security');
   const context={scope,persona,personaSession,modeSnapshot},input={...context,sessionId:conversation.id,requestId:randomUUID(),question:'original synthetic question'};
   const secondLogin=await auth.login({scope,username:'student_merchant',password:'student123'}),second=await auth.authenticateBoundToken({scope,token:secondLogin.token});
   const alternative={...input,personaSession:{sessionId:second.sessionId,authorityVersion:second.authorityVersion}};
   const race=await Promise.allSettled([repository.admit(input),repository.admit(alternative)]);evidence.admissionRace=race.map(r=>r.status==='fulfilled'?{status:r.status,value:r.value}:{status:r.status,error:{name:r.reason.name,code:r.reason.code||null,message:r.reason.message,detail:r.reason.detail||null,where:r.reason.where||null,stack:r.reason.stack}});save();assert.equal(race.filter(x=>x.status==='fulfilled').length,1);assert.equal(race.find(x=>x.status==='rejected').reason.code,'SHOP_AUTH_INVALID');
   const winner=race[0].status==='fulfilled'?input:alternative;assert.equal((await repository.admit(winner)).created,false);assert.equal((await repository.read(winner)).status,'admitted');
   await assert.rejects(repository.admit({...winner,question:'changed'}),{code:'ANALYTICS_REQUEST_CONFLICT'});
   // Database guard independently rejects stale authority; not just application capture.
   const fields=['launch_id','scenario_id','generation','platform_owner_id','platform_session_id','persona_id','role','request_id','persona_session_id','authority_version','session_id','question_sha256','question','mode_snapshot'];
   const stored=(await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions WHERE request_id=$1',[winner.requestId])).rows[0];
   async function raw(changes={}){const row={...stored,request_id:randomUUID(),...changes};return agents.query(`INSERT INTO secureshop_agents.analytics_request_admissions(${fields.join(',')}) VALUES(${fields.map((_,i)=>'$'+(i+1)).join(',')})`,fields.map(k=>row[k]));}
   async function registeredRaw(changes={}){const row={...registeredStored,request_id:randomUUID(),...changes};return agents.query(`INSERT INTO secureshop_agents.analytics_request_admissions(${fields.join(',')}) VALUES(${fields.map((_,i)=>'$'+(i+1)).join(',')})`,fields.map(k=>row[k]));}
   await assert.rejects(registeredRaw({platform_owner_id:scope.platformOwnerId}));
   await assert.rejects(registeredRaw({persona_session_id:randomUUID()}));
   await assert.rejects(registeredRaw({authority_version:'999'}));
   const membership=(await agents.query(`SELECT tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,membership_version,role
    FROM secureshop_agents.bound_actor_tenant_memberships WHERE tenant_owner_id=$1 AND shop_user_id=$2 ORDER BY membership_version DESC LIMIT 1`,[registeredScope.platformOwnerId,registeredPersona.id])).rows[0];
   assert.ok(membership);
   await state.AGENTS_MIGRATION.query(`INSERT INTO secureshop_agents.bound_actor_tenant_memberships
    (tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,membership_version,role,is_active)
    VALUES($1,$2,$3,$4,$5,$6,$7,false)`,[membership.tenant_owner_id,membership.tenant_id,membership.shop_user_id,membership.principal_id,membership.principal_owner_id,(BigInt(membership.membership_version)+1n).toString(),membership.role]);
   await assert.rejects(registeredRaw());
   assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions WHERE request_id=$1',[registeredInput.requestId])).rows[0],registeredStored);
   evidence.registeredActorAdmission={...evidence.registeredActorAdmission,foreignDenied:true,wrongSessionDenied:true,wrongAuthorityDenied:true,staleMembershipDenied:true};save();
   await assert.rejects(raw({authority_version:'2'}));await assert.rejects(raw({role:'admin'}));
   const coordinates=[scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId,persona.id];
   await state.AGENTS_MIGRATION.query(`INSERT INTO secureshop_agents.bound_persona_state(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,shop_user_id,effective_role,authority_version,banned_at) VALUES($1,$2,$3,$4,$5,$6,'merchant',1,clock_timestamp())`,coordinates);
   await assert.rejects(raw());await assert.rejects(repository.admit({...winner,requestId:randomUUID()}));
   await state.AGENTS_MIGRATION.query('UPDATE secureshop_agents.bound_persona_state SET banned_at=NULL,authority_version=2 WHERE platform_launch_id=$1',[scope.launchId]);await assert.rejects(raw());
   const renewed=await auth.login({scope,username:'student_merchant',password:'student123'}),renewedVerified=await auth.authenticateBoundToken({scope,token:renewed.token});const live={...winner,personaSession:{sessionId:renewedVerified.sessionId,authorityVersion:renewedVerified.authorityVersion},requestId:randomUUID()};assert.equal(live.personaSession.authorityVersion,'2');await repository.admit(live);
   // Fill to255 under valid trigger checks, then two real-fence admissions race for one slot.
   const liveStored=(await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions WHERE request_id=$1',[live.requestId])).rows[0];
   for(let n=2;n<255;n++)await raw({persona_session_id:liveStored.persona_session_id,authority_version:'2'});
   const capacity=await Promise.allSettled([repository.admit({...live,requestId:randomUUID()}),repository.admit({...live,requestId:randomUUID()})]);assert.equal(capacity.filter(x=>x.status==='fulfilled').length,1);assert.equal(capacity.find(x=>x.status==='rejected').reason.code,'ANALYTICS_REQUEST_CAPACITY');
   const page=await repository.history({...live,limit:2,cursor:null});assert.equal(page.requests.length,2);assert.ok(page.nextCursor);const next=await repository.history({...live,limit:2,cursor:page.nextCursor});assert.equal(new Set([...page.requests,...next.requests].map(r=>r.requestId)).size,4);
   for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await agents.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',['secureshop_agents.analytics_request_admissions',privilege])).rows[0].allowed,false);
   await assert.rejects(agents.query('UPDATE secureshop_agents.analytics_request_admissions SET question=NULL'));await assert.rejects(agents.query('DELETE FROM secureshop_agents.analytics_request_admissions'));
   // Promote the existing persona through canonical state and obtain a new valid session.
   await state.AGENTS_MIGRATION.query("UPDATE secureshop_agents.bound_persona_state SET effective_role='admin',authority_version=3 WHERE platform_launch_id=$1",[scope.launchId]);await assert.rejects(repository.admit({...live,requestId:randomUUID()}));
   const promotedLogin=await auth.login({scope,username:'student_merchant',password:'student123'}),promotedVerified=await auth.authenticateBoundToken({scope,token:promotedLogin.token});assert.equal(promotedLogin.user.role,'admin');
   const promotedPersona={id:persona.id,role:'admin'},promotedSession={sessionId:promotedVerified.sessionId,authorityVersion:promotedVerified.authorityVersion},promotedBinding={...binding,role:'admin'},promotedConversation=await conversations.acquireBoundSession({id:randomUUID(),binding:promotedBinding,purpose:'secureshop_analytics'});await conversations.activateBoundSession(promotedConversation.id,promotedBinding,'secureshop_analytics');
   await repository.admit({scope,persona:promotedPersona,personaSession:promotedSession,modeSnapshot,sessionId:promotedConversation.id,requestId:randomUUID(),question:'promoted original session'});
   // Fixed chart query uses the owned target and consumes no model/query journal admission.
   await service.provision(scope);const adapter=req('server/services/secureshopOwnedAnalyticsAdapter').createOwnedAnalyticsAdapter({launches,personaAuthority:authority,targetService:service,schema:service.schema});
   const chart=await adapter.topProducts({scope,persona:promotedPersona,personaSession:promotedSession,limit:2,checkCurrent:()=>launches.assertCurrent(scope)});assert.equal(chart.rows.length,2);assert.equal(chart.rows[0].id,2);assert.equal(Number(chart.rows[0].revenue),33);assert.equal(Number((await control.query('SELECT count(*) FROM owned_analytics_queries')).rows[0].count),0);
   // Real sibling owner/session/launch, with an independently authorized admission.
   const siblingUser=await users.createUser({username:'sibling-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash}),siblingPlatform=await users.createSession({userId:siblingUser.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash}),siblingIssued=await launches.issueOrRenew({platformOwnerId:siblingUser.id,platformSessionId:siblingPlatform.id,expiresAt}),siblingScope=req('server/services/secureshopConversationBinding').createLaunchScope(siblingIssued.binding),siblingLogin=await auth.login({scope:siblingScope,username:'student_merchant',password:'student123'}),siblingVerified=await auth.authenticateBoundToken({scope:siblingScope,token:siblingLogin.token});
   const siblingBinding={...siblingScope,shopUserId:persona.id,role:'merchant'},siblingConversation=await conversations.acquireBoundSession({id:randomUUID(),binding:siblingBinding,purpose:'secureshop_analytics'});await conversations.activateBoundSession(siblingConversation.id,siblingBinding,'secureshop_analytics');
   await repository.admit({scope:siblingScope,persona,modeSnapshot:await progress.getEvaluationScope(siblingScope.platformOwnerId,'secureshop_agent_security'),personaSession:{sessionId:siblingVerified.sessionId,authorityVersion:siblingVerified.authorityVersion},sessionId:siblingConversation.id,requestId:randomUUID(),question:'sibling preserved'});
   await conversations.appendMessage(siblingConversation.id,siblingBinding,{role:'user',content:'sibling conversation preserved'},'secureshop_analytics');
   const siblingConversationBefore=(await agents.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[siblingConversation.id])).rows;
   assert.equal(siblingConversationBefore.length,1);
   assert.deepEqual(await conversations.getMessages(siblingConversation.id,siblingBinding,'secureshop_analytics'),[{role:'user',content:'sibling conversation preserved'}]);
   const siblingBefore=(await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions WHERE platform_owner_id=$1',[siblingUser.id])).rows;
   const hashes=(await agents.query('SELECT request_id,question_sha256 FROM secureshop_agents.analytics_request_admissions ORDER BY request_id')).rows;
   await agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),...coordinates.slice(0,5)]);
   assert.equal(Number((await agents.query('SELECT count(*) FROM secureshop_agents.analytics_request_admissions WHERE question IS NOT NULL AND platform_owner_id='+scope.platformOwnerId)).rows[0].count),0);assert.deepEqual((await agents.query('SELECT request_id,question_sha256 FROM secureshop_agents.analytics_request_admissions ORDER BY request_id')).rows,hashes);await assert.rejects(repository.admit({...live,requestId:randomUUID()}));
   assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[siblingConversation.id])).rows,siblingConversationBefore);
   await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[scope.platformOwnerId,randomUUID()]);assert.equal(Number((await agents.query('SELECT count(*) FROM secureshop_agents.analytics_request_admissions WHERE platform_owner_id=$1',[scope.platformOwnerId])).rows[0].count),0);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.analytics_request_admissions WHERE platform_owner_id=$1',[siblingUser.id])).rows,siblingBefore);
   assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[siblingConversation.id])).rows,siblingConversationBefore);
   evidence.assertions=['fresh','populated','noop','checksum','original-session race','capacity race','history cursor','stale authority','banned persona','renewed authority','promoted persona','fixed owned chart','sibling preserved','least privilege','retirement redaction','owner deletion'];
  }finally{/* Migration views hold no temporary filesystem resources. */}
  if(process.env.ANALYTICS_MOUNTED_ONLY==='1')await require('./secureshopAnalyticsMounted.cohort')({state,control,service,controlIdentity,connection,launches,authority,auth,users,passwordHash,createPool,pools,nativeFetch,evidence,save});
  evidence.semanticComplete=true;evidence.status='passed';save();
 }catch(error){const chain=[];for(let cause=error;cause&&chain.length<6;cause=cause.cause)chain.push({name:cause.name,code:cause.code||null,message:cause.message,detail:cause.detail||null,where:cause.where||null,stack:cause.stack});evidence.failure=chain;evidence.status='failed';save();throw error;}finally{globalThis.fetch=nativeFetch;let retirementError;try{if(scope)await service?.retire(scope);}catch(error){retirementError=error;evidence.cleanupError=error.code||error.message;}const closed=await Promise.allSettled(pools.map(p=>p.end()));save();assert.ok(closed.every(r=>r.status==='fulfilled'));if(retirementError)throw retirementError;}
});
