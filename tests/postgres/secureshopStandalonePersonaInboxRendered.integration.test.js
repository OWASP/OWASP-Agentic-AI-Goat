'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomUUID,randomBytes,createHash}=require('node:crypto');
const SOURCE=path.resolve(__dirname,'../..');
const PREFIX='PG_SECURESHOP_STANDALONE_PERSONA_';
const ENABLED=process.env.SECURESHOP_STANDALONE_PERSONA_NATIVE==='1';
function privateWrite(root,name,value){const bytes=JSON.stringify(value,null,2);assert(Buffer.byteLength(bytes)<=64*1024*1024);
 fs.writeFileSync(path.join(root,name),bytes,{mode:0o600});}
function admission(){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(process.env.LIVE_OLLAMA_TEST,'1');
 assert.equal(process.env.DVAIA_CURRENT_MAIN_WORKSPACE,SOURCE);assert.equal(process.cwd(),SOURCE);
 assert.equal(process.env.LAB_MODE,'vuln');
 const evidence=process.env.SECURESHOP_STANDALONE_PERSONA_EVIDENCE_PATH;
 assert(path.isAbsolute(evidence)&&!path.resolve(evidence).startsWith(SOURCE+path.sep));
 assert.equal(fs.realpathSync(evidence),evidence);assert.equal(fs.statSync(evidence).mode&0o777,0o700);
 const names={IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',COMMERCE:'secureshop'};
 const urls={};let nonce,port;
 for(const [name,store]of Object.entries(names)){urls[name]={};for(const role of ['RUNTIME','MIGRATION']){
  const url=new URL(process.env[PREFIX+name+'_'+role+'_URL']);assert.equal(url.protocol,'postgresql:');
  assert.equal(url.hostname,'127.0.0.1');assert.equal(url.username,'dvaia_'+store+'_'+role.toLowerCase());
  assert.equal(url.password,'');assert.equal(url.search,'');assert.equal(url.hash,'');assert(Number(url.port)>0);
  const match=new RegExp('^/dvaia_test_agent_host_([a-f0-9]{12})_'+store+'$').exec(url.pathname);assert(match);
  nonce??=match[1];port??=url.port;assert.equal(match[1],nonce);assert.equal(url.port,port);urls[name][role]=url.href;
 }}
 return {evidence,urls};
}

test('C31 standalone rendered advisory and enforced Persona Inbox with genuine actor and Judge',
 {skip:!ENABLED,timeout:900000},async()=>{
 const owned=admission(),pools=[];let state={status:'running',actualQualification:false},failure;
 const save=()=>privateWrite(owned.evidence,'result.json',state);const stage=name=>{state.stage=name;save();};
 const pool=(name,role,max=8)=>{const p=new(require('pg').Pool)({connectionString:owned.urls[name][role],max,
  connectionTimeoutMillis:5000,statement_timeout:15000});pools.push(p);return p;};
 const identity=pool('IDENTITY','RUNTIME'),identityProvision=pool('IDENTITY','RUNTIME',1),im=pool('IDENTITY','MIGRATION'),agents=pool('AGENTS','RUNTIME'),am=pool('AGENTS','MIGRATION'),
 review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),lease=pool('IDENTITY','RUNTIME',4);
 try{
  for(const [p,dir]of [[im,'identity-migrations'],[am,'workshop-migrations/secureshop_agents'],[rm,'workshop-migrations/secureshop_review'],[cm,'workshop-migrations/secureshop']]){
   await require('../../db/postgres/migrate').migrate(p,path.join(SOURCE,'db/postgres',dir));
   assert.deepEqual(await require('../../db/postgres/migrate').migrate(p,path.join(SOURCE,'db/postgres',dir)),[]);
  }
  await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
  const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
  const lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,reviewPool:review,leasePool:lease,audit});
  state.result=await qualifyStandalonePersonaActual({owned,state,save,stage,identity,identityProvision,im,agents,am,commerce,review,lease,lifecycle});
  state.status='passed';
 }catch(error){failure=error;state.status='failed';state.failure={name:error.name,code:error.code||null};}
 finally{const closed=await Promise.allSettled(pools.map(p=>p.end()));state.poolsClosed=closed.every(row=>row.status==='fulfilled');
  if(!state.poolsClosed)state.status='failed';
  state.pendingOuterOwnershipVerification=state.status==='passed';save();}
 if(failure)throw failure;assert.equal(state.status,'passed');
});
async function qualifyStandalonePersonaActual({owned,state,save,stage,identity,identityProvision,im,agents,am,
  commerce,review,lease,lifecycle,auth,authority}) {
 const express=require('express');
 const qualification=require('../fixtures/secureshopStandalonePersonaInboxQualification');
 const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
 const suffix=randomUUID().slice(0,8),password='standalone-persona-inbox-only';
 let transport,recorder,browser,context,page,server,mailProduction,composition,primary;
 const close=async()=>{
  const failures=[];
  for(const work of [()=>context?.close(),()=>browser?.close(),()=>mailProduction?.close(),
   ()=>composition?.closeBrowserAssessment(),()=>lifecycle.closeFeatureTransports(),
   ()=>server&&new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}),()=>transport?.close(),()=>recorder?.close()])
   try{await work();}catch(error){failures.push(error);}
  if(transport){const wire=transport.snapshot();privateWrite(owned.evidence,'terminal-wire.json',wire);
   assert.equal(wire.version,'inbox-actual-wire-v1');
   assert.equal(wire.externalAttempts,wire.calls.length+wire.metadataProbes.length);
   assert(wire.metadataProbes.every(row=>row.status==='returned'&&row.role==='tags'
    &&row.path==='/api/tags'&&row.httpStatus===200));
   assert.equal(wire.closed,true);assert.equal(wire.physicalPending,0);
   assert.equal(wire.failed,false);
  }
  assert.equal(failures.length,0,'Owned Persona Inbox resources must close');
 };
 try{
  stage('standalone-persona-registered-actors');
  await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(im);
  await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(im);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
  const standalone=require('../../server/services/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthService({repository:require('../../server/database/postgres/secureshopStandaloneAuthRepository')
    .createSecureShopStandaloneAuthRepository({pool:identity})});
  const registrations={};
  for(const [name,role]of [['merchant','merchant']])registrations[name]=await standalone.register({
    username:`c31_${name}_${suffix}`,email:`c31_${name}_${suffix}@example.invalid`,password,role});
  // Registration enrolls the default tenant. The sibling must be a separate
  // registered execution tenant, not another actor sharing that default owner.
  const peerId=randomUUID(),peerSlug=`c31_peer_${suffix}`;
  const peerName=`c31_sibling_${suffix}`,peerEmail=`${peerName}@example.invalid`;
  const peerHash=await require('bcryptjs').hash(password,12);
  const peerRow=(await im.query(`INSERT INTO secureshop_auth.principals
   (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'merchant')
   RETURNING shop_user_id`,[peerId,peerName,peerEmail,peerHash])).rows[0];
  const peerTenantId=randomUUID();
  await im.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
   [peerTenantId,peerSlug]);
  await im.query(`INSERT INTO secureshop_auth.tenant_memberships
   (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
  [peerTenantId,peerId,peerRow.shop_user_id]);
  assert.equal((await im.query('UPDATE secureshop_auth.tenants SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL',
   [peerTenantId,peerRow.shop_user_id])).rowCount,1);
  const peerAuth=require('../../server/services/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthService({repository:
    require('../../server/database/postgres/secureshopStandaloneAuthRepository')
     .createSecureShopStandaloneAuthRepository({pool:identity,executionTenantSlug:peerSlug})});
  registrations.sibling=await peerAuth.login({username:peerName,password});
  const principals={};for(const name of ['merchant'])
   principals[name]=await standalone.establishTenantContext(registrations[name].context);
  principals.sibling=await peerAuth.establishTenantContext(registrations.sibling.context);
  assert.notEqual(principals.merchant.tenantId,principals.sibling.tenantId);
  const admin=await standalone.login({username:'student_admin',password:'student123'});
  const adminPrincipal=await standalone.establishTenantContext(admin.context);
  assert.equal(adminPrincipal.tenantId,principals.merchant.tenantId);
  const catalog=require('../../server/services/secureshopAssessmentCatalog')
   .createSecureShopAssessmentCatalog({pool:identity,authService:standalone});
  for(const objectiveId of qualification.IDS){
   const beforeCatalog=(await catalog.list(admin.context)).objectives.find(row=>row.objectiveId===objectiveId);
   assert(beforeCatalog && beforeCatalog.enabled===false);
   assert.equal((await catalog.set(admin.context,{objectiveId,enabled:true,expectedRevision:beforeCatalog.revision})).enabled,true);
  }
  const peerAdminId=randomUUID(),peerAdminName=`c31_peer_admin_${suffix}`;
  const peerAdminRow=(await im.query(`INSERT INTO secureshop_auth.principals
   (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')
   RETURNING shop_user_id`,[peerAdminId,peerAdminName,`${peerAdminName}@example.invalid`,peerHash])).rows[0];
  await im.query(`INSERT INTO secureshop_auth.tenant_memberships
   (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,[peerTenantId,peerAdminId,peerAdminRow.shop_user_id]);
  const peerAdmin=await peerAuth.login({username:peerAdminName,password});
  const peerCatalog=require('../../server/services/secureshopAssessmentCatalog')
   .createSecureShopAssessmentCatalog({pool:identity,authService:peerAuth});
  for(const objectiveId of qualification.IDS){
   const setting=(await peerCatalog.list(peerAdmin.context)).objectives.find(row=>row.objectiveId===objectiveId);
   assert(setting&&setting.enabled===false);
   assert.equal((await peerCatalog.set(peerAdmin.context,{objectiveId,enabled:true,expectedRevision:setting.revision})).enabled,true);
  }
  stage('standalone-persona-genuine-model');
  transport=await require('./secureshopMailBrowserJudgeTransport').createInboxTransport({evidence:owned.evidence,profile:'inbox-actual'});
  recorder=qualification.createPersonaRecorder({transport,record:value=>privateWrite(owned.evidence,'actor-judge-captures.json',value)});
  const {provider,judge}=recorder;
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
  const grading=await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({
   identityPool:identity,agentsPool:agents,progress,resetComposition:lifecycle,judge,
   expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),
   expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1)});
  const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({repository:
   require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({
    pool:identity,provisionPool:identityProvision,launches:lifecycle.launches}),reviewPool:review,launches:lifecycle.launches});
  const modeRepository=require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
  const modeAuthority=require('../../server/services/secureshopFeatureModeAuthority')
   .createFeatureModeAuthority({progress:modeRepository,launches:lifecycle.launches});
  const audit=require('../../server/services/secureshopBoundAuditComposition')
   .createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
  const toolPolicyRepository=require('../../server/database/postgres/secureshopBoundAclRepository')
   .createSecureShopBoundAclRepository({personaAuthority:grading.personaAuthority,audit:audit.agents});
  const promptPolicyRepository=require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
   .createBoundPromptPolicyRepository({pool:agents,personaAuthority:grading.personaAuthority,
    audit:audit.agents,checkRunBinding:require('../../server/services/secureshopPromptPolicyRunBinding')
     .createPromptPolicyRunBinding({identityPool:identity})});
  await promptPolicyRepository.checkReadiness();
  let activeMail;
  composition=require('../../server/services/secureshopBoundReviewComposition')
   .createSecureShopBoundReviewComposition({identityPool:identity,agentsPool:agents,
    reviewPool:review,commercePool:commerce,leasePool:lease,resetComposition:lifecycle,
    gradingBootstrap:grading,scenes,modeAuthority,toolPolicyRepository,
    getMailApplication:()=>activeMail?.application||null,fixtures:[],personaInboxFeature:true,requiredObjectives:qualification.IDS,
    jwtSecret:randomBytes(32).toString('hex'),agentRuntime:{provider},judge});
  await composition.repositories.personas.ensureTemplates();
  const bootstrap=require('../../server/services/secureshopStandaloneBootstrap')
   .createSecureShopStandaloneBootstrap({launches:composition.launches,
    personaAuth:composition.personaAuth,authService:standalone});
  const standaloneMode=require('../../server/services/secureshopStandaloneMode')
   .createSecureShopStandaloneMode({authService:standalone,repository:modeRepository});
  const protectedReset=require('../../server/services/secureshopStandaloneReset')
   .createSecureShopStandaloneReset({identityPool:identity,authService:standalone,
    launches:composition.launches,scenes,resetCoordinator:lifecycle.launchResetCoordinator,
    preflight:lifecycle.sceneResetPreflight});
  const publicCatalog=require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
   .createSecureShopStorePublicCatalogRepository({identityPool:identity,reviewPool:review,commercePool:commerce});
  const assessmentObjectives=require('../../server/services/secureshopAssessmentCatalog')
   .createSecureShopAssessmentCatalog({pool:identity,authService:standalone});
  const assessmentRecovery=require('../../server/services/secureshopAssessmentRecovery')
   .createSecureShopAssessmentRecovery({identityPool:identity,authService:standalone,
    bootstrap,launches:composition.launches,personaAuth:composition.personaAuth,
    personaAuthority:grading.personaAuthority,judge});
  mailProduction=await require('../../server/services/secureshopMailProduction').createMailProduction({
   enabled:true,identityPool:identity,agentsPool:agents,resetComposition:lifecycle,
   personaAuthority:grading.personaAuthority,personaRepository:composition.repositories.personas,
   provider,promptPolicyRepository,toolPolicyRepository,modeAuthority,
   mailScenes:composition.mailScenes,authenticatePersona:composition.personaAuth.authenticatePersona,
   assessmentDependencies:{...grading.assessmentDependencies,judge},mode:'vuln'});
  assert.equal(mailProduction.ready,true);activeMail=mailProduction;
  const mounted=Object.freeze({...composition,mail:mailProduction,
   standaloneAuth:Object.freeze({service:standalone,bootstrap,reset:protectedReset,
    mode:standaloneMode,assessmentObjectives,assessmentRecovery}),publicCatalog,
   mcpTrust:Object.freeze({ready:true,router:express.Router()}),
   ssrf:Object.freeze({ready:true,router:express.Router()})});
  const bound=await require('../../server/services/secureshopBoundApplication')
   .createSecureShopBoundApplication({engine:'postgres',shopEnabled:true,
    authenticateToken:(_request,response)=>response.sendStatus(401),audit:async()=>{},
    agentRuntime:{},getComposition:async()=>mounted});
  const app=express();app.use(express.json());let apiRequests=0;
  app.use((req,res,next)=>{if(req.path.startsWith('/api/')&&++apiRequests>128)
   return res.status(503).json({error:'C31 qualification request budget'});next();});
  server=await new Promise(resolve=>{
   const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  const origin=`http://127.0.0.1:${server.address().port}`;
  app.use('/api/secureshop/auth',require('../../server/routes/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthRouter({service:standalone,bootstrap,reset:protectedReset,
    mode:standaloneMode,assessmentObjectives,assessmentRecovery,
    allowedOrigins:[origin],secureCookies:false}));
  app.use('/api/secureshop',require('../../server/middleware/secureshopBoundDispatch')
   .createSecureShopBoundDispatch({getGateway:()=>bound.gateway}));
  app.use('/api/secureshop/public',require('../../server/routes/secureshop/publicCatalog')
   .createSecureShopPublicCatalogRouter({getRepository:()=>publicCatalog,isAvailable:async()=>true}));
  app.use('/api',(req,res)=>res.status(404).json({error:'Outside C31 qualification'}));
  const build=process.env.SECURESHOP_STANDALONE_PERSONA_BUILD;
  assert(path.isAbsolute(build)&&path.resolve(build)===path.join(SOURCE,'client/build'));
  assert.equal(fs.realpathSync(build),build);assert(fs.statSync(path.join(build,'index.html')).isFile());
  app.use(express.static(build,{setHeaders:response=>response.set('Access-Control-Allow-Origin','*')}));
  app.get(/.*/,(req,res)=>res.sendFile(path.join(build,'index.html')));

  const siblingBootstrap=require('../../server/services/secureshopStandaloneBootstrap')
   .createSecureShopStandaloneBootstrap({launches:composition.launches,
    personaAuth:composition.personaAuth,authService:peerAuth});
  const siblingBase=await siblingBootstrap(registrations.sibling.context);
  const siblingScope=await composition.launches.resolveCapability(siblingBase.bearer);
  const siblingActor=await composition.personaAuth.authenticateBoundToken({scope:siblingScope,
   token:siblingBase.persona.token});
  stage('standalone-persona-rendered-inbox');
  fs.mkdirSync(path.join(owned.evidence,'runtime'),{mode:0o700});
  browser=await require('../fixtures/secureshopAnalyticsBrowserOwner')
   .launchOwnedAnalyticsBrowser(path.join(owned.evidence,'runtime'),'browser');
  context=await browser.createBrowserContext();page=await context.newPage();
  await page.setViewport({width:1440,height:1000});await page.setRequestInterception(true);
  page.on('request',request=>{let allowed=false;try{const url=new URL(request.url());
   allowed=url.origin===origin||['data:','blob:','about:'].includes(url.protocol);}catch{}
   void(allowed?request.continue():request.abort()).catch(()=>{});});
  const bootstrapResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/secureshop/auth/bootstrap'
   &&response.request().method()==='POST'&&response.status()===200,{timeout:20000});
  await page.goto(origin+'/secureshop/login',{waitUntil:'domcontentloaded'});
  await page.waitForSelector('#ss-login-user');await page.type('#ss-login-user',principals.merchant.username);
  await page.type('#ss-login-pw',password);await page.click('button[type="submit"]');
  let merchantBase=await(await bootstrapResponse).json();
  const merchantScope=await composition.launches.resolveCapability(merchantBase.bearer);
  const merchantActor=await composition.personaAuth.authenticateBoundToken({scope:merchantScope,
   token:merchantBase.persona.token});
  assert.equal(merchantActor.user.id,principals.merchant.shopUserId);
  const frame=await(await page.waitForSelector('iframe[title="SecureShop"]')).contentFrame();assert(frame);
  await frame.waitForSelector('a[href="/secureshop/merchant/inbox"]');
  await frame.click('a[href="/secureshop/merchant/inbox"]');
  await frame.waitForSelector('[data-testid="persona-inbox-acl"]');
  const merchantContext={scope:merchantScope,persona:{id:merchantActor.user.id,role:'merchant'},
   personaSession:{sessionId:merchantActor.sessionId,authorityVersion:merchantActor.authorityVersion}};
  const siblingContext={scope:siblingScope,persona:{id:siblingActor.user.id,role:'merchant'},
   personaSession:{sessionId:siblingActor.sessionId,authorityVersion:siblingActor.authorityVersion}};
  const mailTarget=await composition.mailScenes.resolve(merchantContext);
  const siblingTarget=await composition.mailScenes.resolve(siblingContext);
  assert.notEqual(mailTarget.targetId,siblingTarget.targetId);
  const subject={tenantId:principals.merchant.tenantId,principalId:principals.merchant.principalId,
   binding:{...createLaunchScope(merchantScope),shopUserId:merchantActor.user.id,role:'merchant'},
   personaSessionId:merchantActor.sessionId,personaAuthorityVersion:merchantActor.authorityVersion,targetId:mailTarget.targetId};
  const messages=await lifecycle.personaInbox.repository.list(mailTarget);
  const message=messages.find(row=>row.ownerShopUserId!==merchantActor.user.id);assert(message);
  const observe=qualification.createStandalonePersonaEvidence({identity,agents,subject,mailScenes:composition.mailScenes,
   inboxRepository:lifecycle.personaInbox.repository,record:value=>recorder.retain('exact-source',value)});
  const read=async(body,who)=>{const credential=who==='sibling'?siblingBase:merchantBase;
   const response=await fetch(origin+'/api/secureshop/v2/persona-inbox/'+(body?'read':'readiness'),{
    method:body?'POST':'GET',headers:{'x-dvaia-secureshop-launch':credential.bearer,authorization:'Bearer '+credential.persona.token,
    ...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(10000)});
   return {status:response.status,value:await response.json(),launchState:response.headers.get('x-dvaia-secureshop-launch-state')};};
  const siblingSnapshot=async()=>({
   messages:(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_messages WHERE target_id=$1 ORDER BY message_id',[siblingTarget.targetId])).rows,
   acl:(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_acl_versions WHERE target_id=$1 ORDER BY version',[siblingTarget.targetId])).rows,
   accesses:(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$1 ORDER BY event_id',[siblingTarget.targetId])).rows,
   judgments:(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id',[principals.sibling.tenantId,principals.sibling.principalId])).rows});
  const api={read,readiness:()=>read(),siblingReadiness:()=>read(undefined,'sibling'),siblingSnapshot,
   async reloadEnforced(){
    const renewed=page.waitForResponse(response=>response.request().frame()===page.mainFrame()
     &&response.request().method()==='POST'&&new URL(response.url()).origin===origin
     &&new URL(response.url()).pathname==='/api/secureshop/auth/bootstrap'&&response.status()===200,{timeout:20000});
    renewed.catch(()=>{});
    const readiness=page.waitForResponse(response=>response.request().frame()===page.mainFrame()
     &&response.request().method()==='GET'&&new URL(response.url()).origin===origin
     &&new URL(response.url()).pathname==='/api/secureshop/v2/persona-inbox/readiness',{timeout:20000});
    readiness.catch(()=>{});await page.reload({waitUntil:'domcontentloaded'});
    const currentFrame=await(await page.waitForSelector('iframe[title="SecureShop"]')).contentFrame();assert(currentFrame);
    await currentFrame.waitForSelector('a[href="/secureshop/merchant/inbox"]');
    await currentFrame.click('a[href="/secureshop/merchant/inbox"]');
    await currentFrame.waitForFunction(()=>document.querySelector('[data-testid="persona-inbox-acl"]')?.textContent.includes('enforced'),{timeout:20000,polling:'mutation'});
    const response=await readiness;assert.equal(response.status(),200);assert.equal((await response.json()).acl.mode,'enforced');
    merchantBase=await(await renewed).json();
    assert.deepEqual(createLaunchScope(await composition.launches.resolveCapability(merchantBase.bearer)),createLaunchScope(merchantScope));
    await page.screenshot({path:path.join(owned.evidence,'enforced-reload.png'),fullPage:true});},
   savedAssessments:()=>page.evaluate(async()=>{const r=await fetch('/api/secureshop/auth/assessments',{credentials:'include'});return{status:r.status,value:await r.json()};}),
   async assertResetPreserved(before,reset){
    const judgments=(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE tenant_id=$1 AND principal_id=$2 ORDER BY created_at,evaluation_id',[subject.tenantId,subject.principalId])).rows;
    const original=before.judgments.map(({credited,user_id,...row})=>row);assert.deepEqual(judgments,original);
    assert.equal((await identity.query('SELECT * FROM secureshop_auth.active_assessment_contributions WHERE tenant_id=$1 AND principal_id=$2',[subject.tenantId,subject.principalId])).rowCount,0);
    const ledger=(await identity.query(`SELECT * FROM identity.secureshop_launch_resets WHERE launch_id=$1 AND from_generation=$2 AND status='committed'`,[merchantScope.launchId,merchantScope.generation])).rows;assert.equal(ledger.length,1);
    const receipts=(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_cleanup_receipts WHERE target_id=$1',[mailTarget.targetId])).rows;
    const targets=(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_targets WHERE target_id=$1',[mailTarget.targetId])).rows;
    assert.equal(receipts.length,1);assert.equal(targets.length,1);const receipt=receipts[0],target=targets[0];
    assert.equal(receipt.operation_id,reset.resetId);assert.equal(ledger[0].reset_id,reset.resetId);
    assert.equal(target.lifecycle,'retired');assert(target.retired_at);
    for(const [column,key]of [['launch_id','launchId'],['scenario_id','scenarioId']])assert.equal(receipt[column],mailTarget[key]);
    for(const [column,key]of [['generation','generation'],['original_platform_owner_id','platformOwnerId'],['original_platform_session_id','platformSessionId']])assert.equal(Number(receipt[column]),mailTarget[key]);
    assert.equal(receipt.deleted_message_count,before.messages.length);assert.equal(receipt.deleted_acl_version_count,before.acls.length);
    assert.equal(receipt.deleted_access_event_count,before.accesses.length);assert.deepEqual(receipt.seed_sha256,target.seed_sha256);
    assert.deepEqual(receipt.receipt_sha256,require('../../server/database/postgres/secureshopPersonaInboxRepository').receiptDigest(receipt));
    const remaining={};for(const name of ['messages','acl_versions','access_events']){
     remaining[name]=(await agents.query(`SELECT * FROM secureshop_agents.persona_inbox_${name} WHERE target_id=$1`,[mailTarget.targetId])).rows;
     assert.deepEqual(remaining[name],[]);
    }
    privateWrite(owned.evidence,'reset-evidence.json',{judgments,ledger,receipts,targets,remaining,reset});
   }};
  const result=await qualification.qualifyStandalonePersonaInbox({page,frame,origin,subject,message,observe,recorder,api,
   resetOwner:()=>lifecycle.launchResetCoordinator.reset({...createLaunchScope(merchantScope),expectedGeneration:merchantScope.generation,idempotencyKey:randomUUID()}),
   record:value=>privateWrite(owned.evidence,'rendered-evidence.json',value),
   screenshot:label=>page.screenshot({path:path.join(owned.evidence,label+'.png'),fullPage:true})});
  assert.equal(result.actualQualification,false);return result;
 }catch(error){primary=error;throw error;}
 finally{try{await close();}catch(error){if(!primary)throw error;primary.cleanupFailure={name:error.name,code:error.code||null};}}
}
module.exports={admission,qualifyStandalonePersonaActual};
