'use strict';
// Database-only pending/default-disabled seed qualification; no browser/model/Judge/credit.
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {createHash,randomUUID}=require('node:crypto');const bcrypt=require('bcryptjs');const {Pool}=require('pg');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
const {seedSecureShopAssessmentDefaults}=require('../../server/database/postgres/secureshopAssessmentSeed');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {seedSecureShopStandaloneDefaults}=require('../../server/database/postgres/secureshopStandaloneSeed');
const {createSecureShopStandaloneAuthRepository}=require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const {createSecureShopStandaloneAuthService}=require('../../server/services/secureshopStandaloneAuth');
const {createSecureShopAssessmentCatalog}=require('../../server/services/secureshopAssessmentCatalog');
const curriculum=require('../../server/config/secureshopCurriculum');
const PREFIX='PG_SECURESHOP_V11_MAIL_AGENT_',ID='ss_mail_agent_cross_persona_read';
const DIRECTORY=path.resolve(__dirname,'../../db/postgres/identity-migrations'),expected=curriculum.OBJECTIVES.find(x=>x.id===ID);
const document=()=>({version:1,id:ID,label:expected.text,defaultEnabled:expected.defaultEnabled,qualification:expected.qualification});
const sha=x=>createHash('sha256').update(x).digest('hex');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&['FRESH','POPULATED'].every(s=>['MIGRATION','RUNTIME'].every(r=>process.env[`${PREFIX}${s}_${r}_URL`]));
function checked(store){const u=['MIGRATION','RUNTIME'].map(r=>new URL(process.env[`${PREFIX}${store}_${r}_URL`]));u.forEach((x,i)=>{
 assert.equal(x.protocol,'postgresql:');assert.equal(x.hostname,'127.0.0.1');assert.equal(x.username,`dvaia_identity_${i?'runtime':'migration'}`);
 assert.equal(x.password,'');assert.equal(x.search,'');assert.equal(x.hash,'');assert.match(x.pathname,new RegExp(`^/dvaia_test_persona_${store.toLowerCase()}_[a-f0-9]{12}$`));});
 assert.equal(u[0].host,u[1].host);assert.equal(u[0].pathname,u[1].pathname);const peer=new URL(process.env[`${PREFIX}${store==='FRESH'?'POPULATED':'FRESH'}_MIGRATION_URL`]);
 assert.equal(u[0].host,peer.host);assert.notEqual(u[0].pathname,peer.pathname);return u;}
async function open(store,t){const [m,r]=checked(store),migration=new Pool({connectionString:m.href,max:2,statement_timeout:15000,lock_timeout:3000}),runtime=new Pool({connectionString:r.href,max:2,statement_timeout:15000,lock_timeout:3000});
 t.after(async()=>assert.equal((await Promise.allSettled([migration.end(),runtime.end()])).filter(x=>x.status==='rejected').length,0));
 const manifest=(await readMigrations(DIRECTORY)).map(({name,checksum})=>({name,checksum}));assert.deepEqual(await migrate(migration,DIRECTORY),manifest.map(x=>x.name));assert.deepEqual(await migrate(migration,DIRECTORY),[]);
 assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
 assert.equal((await runtime.query("SELECT has_table_privilege(current_user,'secureshop_auth.assessment_objectives','UPDATE') allowed")).rows[0].allowed,false);return{migration,runtime,manifest};}
async function row(p){return(await p.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1',[ID])).rows[0];}
async function content(p,id=ID){return(await p.query('SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[curriculum.WORKSHOP_KEY,id])).rows[0];}
async function snapshot(p){const tables=['secureshop_auth.assessment_objectives','secureshop_auth.assessment_configuration','secureshop_auth.assessment_configuration_history','secureshop_auth.assessment_judgments','secureshop_auth.assessment_completions','secureshop_auth.assessment_contributions','secureshop_auth.assessment_retries','workshop_platform.objectives','workshop_platform.catalog_field_defaults','workshop_platform.config_revision'];return Object.fromEntries(await Promise.all(tables.map(async n=>[n,(await p.query(`SELECT to_jsonb(t) row FROM ${n} t ORDER BY to_jsonb(t)::text`)).rows])));}
const protectedTables=['secureshop_auth.assessment_configuration','secureshop_auth.assessment_configuration_history','secureshop_auth.assessment_judgments','secureshop_auth.assessment_completions','secureshop_auth.assessment_contributions','secureshop_auth.assessment_retries'];
async function actor(m,r){await seedSecureShopStandaloneDefaults(m,{hashPassword:x=>bcrypt.hash(x,4)});const auth=createSecureShopStandaloneAuthService({repository:createSecureShopStandaloneAuthRepository({pool:r})}),session=await auth.login({username:'student_admin',password:'student123'});return{auth,session,catalog:createSecureShopAssessmentCatalog({pool:r,authService:auth})};}

test('fresh V11 agent mail read seed is exact pending/default-disabled and second seed is no-op',{skip:!enabled,timeout:120000},async t=>{
 assert.equal(expected.qualification,'pending');assert.equal(expected.defaultEnabled,false);const{migration,runtime,manifest}=await open('FRESH',t);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:curriculum.OBJECTIVES.length});assert.equal((await seedWorkshopPlatform(migration)).changed,true);
 const actual=await row(runtime),lesson=await content(runtime),source=JSON.stringify(document());assert.equal(actual.qualification,'pending');assert.equal(actual.is_enabled,false);assert.equal(actual.catalog_active,true);assert.equal(actual.configuration_source,'checked_in_default');assert.equal(actual.source_sha256,sha(source));assert.deepEqual(actual.source_document,document());
 assert.equal(lesson.is_enabled,false);assert.deepEqual(lesson.hint_content,curriculum.HINTS[ID]);assert.deepEqual(lesson.solution_content,curriculum.SOLUTIONS[ID]);
 const{session,catalog}=await actor(migration,runtime),before=await snapshot(migration);await assert.rejects(catalog.set(session.context,{objectiveId:ID,enabled:true,expectedRevision:'1'}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});assert.deepEqual(await snapshot(migration),before);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),before);assert.deepEqual(await migrate(migration,DIRECTORY),[]);assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
});

test('populated V11 seed preserves instructor, tenant, sibling and immutable evidence state',{skip:!enabled,timeout:120000},async t=>{
 const{migration,runtime,manifest}=await open('POPULATED',t);await seedSecureShopAssessmentDefaults(migration);await seedWorkshopPlatform(migration);const sibling=curriculum.OBJECTIVES.find(x=>x.id!==ID).id;
 await migration.query("UPDATE secureshop_auth.assessment_objectives SET label='Instructor V11 label',configuration_source='instructor',is_enabled=false,catalog_active=false WHERE objective_id=$1",[ID]);
 await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor agent mail read lesson',hint_content=$3::jsonb,solution_content=$4::jsonb,hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2`,[curriculum.WORKSHOP_KEY,ID,JSON.stringify({title:'Custom agent mail read hints',hints:['Retain exact mail guidance']}),JSON.stringify({title:'Custom agent mail read solution',examples:[]})]);
 await migration.query("UPDATE workshop_platform.objectives SET label='Retained sibling lesson' WHERE workshop_key=$1 AND objective_id=$2",[curriculum.WORKSHOP_KEY,sibling]);
 const{auth,session}=await actor(migration,runtime),ctx=await auth.establishTenantContext(session.context),peer=randomUUID();await migration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',[peer,`v11-peer-${peer}`]);
 for(const [tenant,on,rev] of [[ctx.tenantId,false,4],[peer,true,9]]){await migration.query('INSERT INTO secureshop_auth.assessment_configuration(tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,$3,$4,$5)',[tenant,ID,on,rev,ctx.principalId]);await migration.query('INSERT INTO secureshop_auth.assessment_configuration_history(tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id) VALUES($1,$2,$3,$4,$5,$6)',[tenant,ID,rev,on,ctx.principalId,ctx.sessionId]);}
 const evidenceId=randomUUID(),result=JSON.stringify({verdict:'pass',fixture:'controlled-seed-preservation',actualModel:false,actualJudge:false});
 const shopUserId=(await migration.query('SELECT shop_user_id FROM secureshop_auth.principals WHERE principal_id=$1',[ctx.principalId])).rows[0].shop_user_id;
 await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
  (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,rubric_version,
   evidence_digest,run_id,generation,mode,mode_stamp,owner_key,owner_generation,verdict,disposition,result_json,result_digest,evaluated_at)
  VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop','controlled-seed-preservation','fixture-only-v1',$7,$8,0,'vuln',
   'controlled-seed-preservation',$9,0,'pass','awarded',$10::jsonb,$11,clock_timestamp())`,
 [ctx.tenantId,ctx.principalId,evidenceId,shopUserId,JSON.stringify({fixture:'catalog-seed-preservation'}),sibling,
  'a'.repeat(64),randomUUID(),`fixture:${randomUUID()}`,result,sha(result)]);
 await migration.query(`INSERT INTO secureshop_auth.assessment_completions
  (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,0,$4)`,
 [ctx.tenantId,ctx.principalId,sibling,evidenceId]);
 await migration.query(`INSERT INTO secureshop_auth.assessment_contributions
  (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,[ctx.tenantId,ctx.principalId,evidenceId]);
 const beforeFirstReseed=await snapshot(migration);await seedSecureShopAssessmentDefaults(migration);await seedWorkshopPlatform(migration);const retained=await snapshot(migration),actual=await row(runtime),lesson=await content(runtime);for(const table of protectedTables)assert.deepEqual(retained[table],beforeFirstReseed[table],`${table} changed during first reseed`);assert.equal(actual.label,'Instructor V11 label');assert.equal(actual.configuration_source,'instructor');assert.equal(actual.qualification,'pending');assert.equal(actual.catalog_active,false);assert.equal(lesson.label,'Instructor agent mail read lesson');assert.equal((await content(runtime,sibling)).label,'Retained sibling lesson');assert.deepEqual(lesson.hint_content,{hints:['Retain exact mail guidance'],title:'Custom agent mail read hints'});assert.deepEqual(lesson.solution_content,{examples:[],title:'Custom agent mail read solution'});assert.equal(lesson.hint_enabled,false);assert.equal(lesson.solution_enabled,true);
 assert.equal(retained['secureshop_auth.assessment_judgments'].length,1);assert.equal(retained['secureshop_auth.assessment_completions'].length,1);assert.equal(retained['secureshop_auth.assessment_contributions'].length,1);assert.deepEqual(retained['secureshop_auth.assessment_retries'],[]);assert.equal(retained['secureshop_auth.assessment_configuration'].length,2);assert.equal(retained['secureshop_auth.assessment_configuration_history'].length,2);
 assert.deepEqual(await seedSecureShopAssessmentDefaults(migration),{inserted:0});assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(migration),retained);assert.deepEqual(await migrate(migration,DIRECTORY),[]);assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
});

// This controlled provider executes the production graph and persistence path.
// It is not an actual provider/Judge qualification, and may never award credit.
test('V11 native original detail, canonical retry, mode epochs and owned reset',
  {skip: !enabled, timeout: 180000}, async t => {
    const pools = [];
    const roles = {IDENTITY:'identity', AGENTS:'secureshop_agents',
      COMMERCE:'secureshop', REVIEW:'secureshop_review'};
    const pool = (store, kind) => {
      const url = new URL(process.env[`${PREFIX}${store}_${kind}_URL`]);
      assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${roles[store]}_${kind.toLowerCase()}`);
      assert.equal(url.password, '');
      assert.match(url.pathname, new RegExp(`^/dvaia_test_persona_${store.toLowerCase()}_[a-f0-9]{12}$`));
      const value = new Pool({connectionString:url.href, max:8,
        statement_timeout:15000, lock_timeout:3000});
      pools.push(value); return value;
    };
    t.after(async () => {
      const results = await Promise.allSettled(pools.map(value => value.end()));
      assert.deepEqual(results.filter(value => value.status === 'rejected'), []);
    });
    const stores = Object.fromEntries(Object.keys(roles).map(store => [store,
      {runtime:pool(store,'RUNTIME'), migration:pool(store,'MIGRATION')}]));
    for (const [store, value] of Object.entries(stores)) {
      const directory = store === 'IDENTITY' ? 'db/postgres/identity-migrations'
        : `db/postgres/workshop-migrations/${roles[store]}`;
      const manifest = (await readMigrations(directory)).map(({name,checksum}) => ({name,checksum}));
      assert.deepEqual(await migrate(value.migration,directory),manifest.map(row => row.name));
      assert.deepEqual(await migrate(value.migration,directory),[]);
      assert.deepEqual((await value.migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,manifest);
    }
    const identity=stores.IDENTITY.runtime, agents=stores.AGENTS.runtime;
    const commerce=stores.COMMERCE.runtime, review=stores.REVIEW.runtime;
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(stores.COMMERCE.migration);
    await seedWorkshopPlatform(stores.IDENTITY.migration);
    await seedSecureShopAssessmentDefaults(stores.IDENTITY.migration);
    await seedSecureShopStandaloneDefaults(stores.IDENTITY.migration,{hashPassword:value=>bcrypt.hash(value,4)});
    const auth=createSecureShopStandaloneAuthService({repository:createSecureShopStandaloneAuthRepository({pool:identity})});
    let login=await auth.login({username:'student_merchant',password:'student123'});
    const baseAudit=require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
    const leasePool=pool('IDENTITY','RUNTIME');
    const reset=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
      identityPool:identity,agentsPool:agents,reviewPool:review,leasePool,audit:baseAudit});
    t.after(async()=>{await reset.closeFeatureTransports?.();await reset.auditLedger?.close?.();});
    let actorCalls=0, chatCalls=0, finalCalls=0, judgeCalls=0, selected=null, decisionPending=false;
    const judgePackets=[];
    const {prepareJudgeInput,JUDGE_VERSION}=require('../../server/agent-runtime/objectiveJudge');
    const judge=async input=>{
      judgeCalls++;
      const prepared=prepareJudgeInput(input);
      assert.equal(prepared.evidenceError,undefined);
      judgePackets.push(prepared.packet);
      return {family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:ID,
        rubricVersion:input.rubric.version,mode:'vuln',evidenceDigest:prepared.evidenceDigest,
        runId:input.execution.runId,judgeVersion:JUDGE_VERSION,verdict:'unavailable',
        errorCode:'JUDGE_TIMEOUT',criteria:[],provider:null,model:null,
        explanation:'Controlled unavailable Judge; no real model or credit.'};
    };
    // Exact adapter identity exercises production qualification configuration;
    // replacing chat is explicit controlled fixture behavior, never wire proof.
    const provider=new (require('../../server/services/secureshop/providers/openaiProvider').OpenAIProvider)({
      apiKey:'controlled-fixture-not-a-credential',model:'controlled-v11-native',baseUrl:'http://127.0.0.1:1'});
    provider.chat=async()=>{
      actorCalls++;chatCalls++;
      assert.ok(selected && decisionPending,'Exactly one bounded tool decision per turn');
      decisionPending=false;
      return {provider:'openai',model:'controlled-v11-native',mocked:false,stop_reason:'tool_use',
        tool_uses:[{id:`native_${randomUUID()}`,name:selected.name,args:structuredClone(selected.args)}]};
    };
    provider.finalResponse=async input=>{
      actorCalls++;finalCalls++;
      assert.ok(selected && !decisionPending,'Selected mail effect precedes structured final response');
      assert.ok(input.messages.some(message=>message.role==='tool'),'Final model input retains the tool observation');
      return {provider:'openai',model:'controlled-v11-native',mocked:false,
        stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled saved mail observation.'};
    };
    const originalFetch=globalThis.fetch;
    globalThis.fetch=async()=>{throw Error('Network/model calls forbidden in native fixture');};
    t.after(()=>{globalThis.fetch=originalFetch;});
    const grading=await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({
      identityPool:identity,agentsPool:agents,resetComposition:reset,judge,
      progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity),
      expectedIdentityDatabase:new URL(process.env[`${PREFIX}IDENTITY_RUNTIME_URL`]).pathname.slice(1),
      expectedAgentsDatabase:new URL(process.env[`${PREFIX}AGENTS_RUNTIME_URL`]).pathname.slice(1)});
    const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository:require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool:identity,launches:reset.launches}),
      reviewPool:review,launches:reset.launches});
    const modes=require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
    const modeAuthority=require('../../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({launches:reset.launches,progress:modes});
    const policy=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({
      personaAuthority:grading.personaAuthority,audit:baseAudit.agents});
    let mailProduction;
    const composition=require('../../server/services/secureshopBoundReviewComposition').createSecureShopBoundReviewComposition({
      identityPool:identity,agentsPool:agents,reviewPool:review,commercePool:commerce,
      resetComposition:reset,gradingBootstrap:grading,scenes,modeAuthority,
      couponDependencies:await require('../../server/services/secureshopCouponProduction').prepareCommerceDependencies({
        modeAuthority,reviewPool:review,launches:reset.launches,mode:'vuln'}),
      toolPolicyRepository:policy,judge,jwtSecret:'controlled-v11-native-secret-at-least-32-bytes',
      agentRuntime:{provider},getMailApplication:()=>mailProduction?.application || null});
    t.after(()=>composition.closeBrowserAssessment?.());
    const prompts=await require('../../server/services/secureshopAgentSnapshotPolicies').createAgentSnapshotPolicyResolver({
      personaAuthority:grading.personaAuthority,agentsPool:agents,identityPool:identity,auditStore:reset.audit.agents})();
    mailProduction=await require('../../server/services/secureshopMailProduction').createMailProduction({
      enabled:true,identityPool:identity,agentsPool:agents,resetComposition:reset,
      personaAuthority:grading.personaAuthority,personaRepository:composition.repositories.personas,
      provider,promptPolicyRepository:prompts,toolPolicyRepository:policy,modeAuthority,
      mailScenes:composition.mailScenes,authenticatePersona:composition.personaAuth.authenticatePersona,
      assessmentDependencies:{...grading.assessmentDependencies,judge,publicationModes:modes},mode:'vuln'});
    t.after(()=>mailProduction.close());
    await composition.repositories.personas.ensureTemplates();
    const bootstrap=require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
      launches:reset.launches,personaAuth:composition.personaAuth,authService:auth});
    const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
    const openContext=async authenticated=>{
      const ready=await bootstrap(authenticated.context);
      const scope=createLaunchScope(await reset.launches.resolveCapability(ready.bearer));
      const actor=await composition.personaAuth.authenticateBoundToken({scope,token:ready.persona.token});
      return {scope,persona:{id:actor.user.id,role:'merchant'},
        personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion}};
    };
    let context=await openContext(login),scope=context.scope;
    const mail=require('../../server/database/postgres/secureshopBoundMailRepository').createBoundMailRepository({
      pool:agents,personaAuthority:grading.personaAuthority,checkCleanup:input=>reset.cleanupAuthority.checkTarget({
        ...input,targetKind:'persona_inbox',fromGeneration:input.generation})});
    const seedMail=async (context,label)=>{
      const target=await composition.mailScenes.resolve(context);
      const actors=await composition.repositories.personas.listMailActors(context.scope);
      const recipient=actors.find(row=>row.role==='customer'),sender=actors.find(row=>row.id===context.persona.id);
      assert.ok(recipient && sender && recipient.id!==sender.id);
      const body=`Owned synthetic ${label} body, reserved for native provenance controls.`;
      const sent=await mail.send({...context,target,targetId:target.targetId,mode:'vuln',operationId:randomUUID()},
        {from:sender.email,to:recipient.email,subject:`Native ${label}`,body_markdown:body});
      return {target,recipient,sender,body,messageId:sent.email_id};
    };
    const owned=await seedMail(context,'owner');
    const birthContext=context,birthScope=scope;
    assert.equal(owned.target.launchId,birthScope.launchId);
    assert.equal(owned.target.scenarioId,birthScope.scenarioId);
    assert.equal(owned.target.generation,birthScope.generation);
    assert.equal(owned.target.platformSessionId,birthScope.platformSessionId);
    assert.equal(await auth.logout(login.token),true);
    login=await auth.login({username:'student_merchant',password:'student123'});
    context=await openContext(login);scope=context.scope;
    const retained=await composition.mailScenes.resolve(context);
    assert.equal(retained.targetId,owned.target.targetId);
    assert.equal(retained.launchId,birthScope.launchId);
    assert.notEqual(scope.launchId,birthScope.launchId);
    assert.notEqual(scope.platformSessionId,birthScope.platformSessionId);
    const mailSceneBinding=require('../../server/services/secureshopMailSceneBinding');
    const {executionScope}=require('../../server/services/secureshopSceneBinding');
    const birthScene=mailSceneBinding.productScene(owned.target);
    const retainedScene=mailSceneBinding.productScene(retained);
    assert.ok(birthScene?.scene);assert.ok(retainedScene?.scene);
    assert.equal(executionScope(retainedScene).launchId,scope.launchId);
    assert.notEqual(retainedScene.scene.grantId,birthScene.scene.grantId);
    const grants=(await agents.query(`SELECT grant_id,launch_id,scenario_id,generation,
      original_platform_owner_id,original_platform_session_id FROM secureshop_agents.mail_scene_execution_grants
      WHERE scene_id=$1 ORDER BY launch_id`,[retainedScene.scene.sceneId])).rows;
    assert.equal(grants.length,2);
    assert.ok(grants.some(row=>row.grant_id===birthScene.scene.grantId&&row.launch_id===birthScope.launchId));
    assert.ok(grants.some(row=>row.grant_id===retainedScene.scene.grantId&&row.launch_id===scope.launchId));
    // A separate platform owner gives a genuinely distinct sibling target.
    const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
    const passwordHash=await bcrypt.hash('native-only',4),suffix=randomUUID();
    const user=await users.createUser({username:`v11-${suffix.slice(0,8)}`,email:`${suffix}@example.invalid`,passwordHash});
    const expiresAt=new Date(Date.now()+600000).toISOString();
    const session=await users.createSession({userId:user.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});
    const issued=await reset.launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});
    const siblingScope=createLaunchScope(issued.binding);
    const siblingLogin=await composition.personaAuth.login({scope:siblingScope,username:'student_merchant',password:'student123'});
    const siblingActor=await composition.personaAuth.authenticateBoundToken({scope:siblingScope,token:siblingLogin.token});
    const siblingContext={scope:siblingScope,persona:{id:siblingActor.user.id,role:'merchant'},
      personaSession:{sessionId:siblingActor.sessionId,authorityVersion:siblingActor.authorityVersion}};
    const sibling=await seedMail(siblingContext,'sibling');
    assert.notEqual(sibling.target.targetId,owned.target.targetId);
    const snapshot=async targetId=>Object.fromEntries(await Promise.all([
      'lab_mail_targets','lab_mail_messages','lab_mail_operation_receipts'].map(async table=>[table,
      (await stores.AGENTS.migration.query(`SELECT to_jsonb(t) row FROM secureshop_agents.${table} t WHERE target_id=$1 ORDER BY to_jsonb(t)::text`,[targetId])).rows])));
    const siblingBefore=await snapshot(sibling.target.targetId);
    const runtime=composition.roleAssistants.merchant.runtime;
    const assessment=composition.roleAssistants.merchant.mailAgentReadAssessment;
    assert.equal(typeof assessment?.runAttempt,'function');
    const conversation=await runtime.createSession(scope,context.persona,context.personaSession);
    const run=async(name,args,selection)=>{
      selected={name,args};decisionPending=true;
      const input={...context,sessionId:conversation.id,requestId:randomUUID(),message:'Inspect the selected owned synthetic mail.',
        ...(selection?{selection}:{}),signal:AbortSignal.timeout(30000)};
      const before={actor:actorCalls,chat:chatCalls,final:finalCalls};
      try { await runtime.run(input); }
      catch(error) {
        t.diagnostic(JSON.stringify({selectedTool:name,actorCalls,chatCalls,finalCalls,
          error:require('../../server/services/secureshopFailureDiagnostic').projectSecureShopFailure(error)}));
        throw error;
      }
      assert.equal(actorCalls-before.actor,2);
      assert.equal(chatCalls-before.chat,1);
      assert.equal(finalCalls-before.final,1);
      const saved=await runtime.readRequest(scope,context.persona,context.personaSession,input.sessionId,input.requestId);
      assert.equal(saved.status,'completed');assert.equal(saved.hops.at(-1).tool,name);
      return {input,saved};
    };
    const discovery=await run('merchant.mail_recipients',{search:owned.recipient.username});
    const recipientChoice=discovery.saved.cards.find(row=>row.kind==='merchant_mail_recipient'&&row.title===owned.recipient.username);
    assert.ok(recipientChoice);
    const listed=await run('merchant.mail_list',{choiceId:recipientChoice.choiceId},
      {choiceId:recipientChoice.choiceId,intent:'mail_list'});
    const messageChoice=listed.saved.cards.find(row=>row.kind==='merchant_mail_message'&&row.title==='Native owner');
    assert.ok(messageChoice);
    const detail=await run('merchant.mail_detail',{choiceId:messageChoice.choiceId},
      {choiceId:messageChoice.choiceId,intent:'mail_detail'});
    assert.equal(detail.saved.mailRead.result.message.bodyMarkdown,owned.body);
    const a={...context,sessionId:detail.input.sessionId,requestId:detail.input.requestId};
    assert.deepEqual(await assessment.runAttempt(a),{completed:false,status:'ineligible',modelEvaluated:false});
    assert.equal(judgeCalls,0);
    // Disposable fixture-local admission only; the checked-in catalog remains pending.
    await stores.IDENTITY.migration.query("UPDATE secureshop_auth.assessment_objectives SET qualification='native-model',is_enabled=true WHERE objective_id=$1",[ID]);
    try {
      assert.deepEqual(await assessment.readOutcome(a),{completed:false,status:'unconfirmed',modelEvaluated:false});
    } catch (error) {
      // Retain exact controlled original rows before the disposable stores close.
      // This is diagnostic evidence only, never a source or qualification substitute.
      const turn=(await agents.query('SELECT * FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[a.sessionId,a.requestId])).rows;
      const trace=(await agents.query('SELECT * FROM secureshop_agents.agent_trace WHERE session_id=$1 ORDER BY id',[a.sessionId])).rows;
      const session=(await agents.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[a.sessionId])).rows;
      const effects=(await identity.query('SELECT * FROM graph_runtime.effects WHERE owner_key=$1',[JSON.stringify(['SecureShopBoundConversation',a.sessionId])])).rows;
      t.diagnostic(JSON.stringify({originalReadDiagnostic:{saved:detail.saved,turn,trace,session,effects}}));
      throw error;
    }
    const outcome=await assessment.runAttempt(a);
    assert.equal(outcome.completed,false);assert.equal(outcome.judgment.verdict,'unavailable');assert.equal(judgeCalls,1);
    const original=(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1',[outcome.judgment.evaluationId])).rows[0];
    assert.equal(original.packet,judgePackets[0]);assert.equal(original.disposition,'not_pass');
    // Actual repositories must deny owner and credential substitution before grading.
    const deniedBefore={actor:actorCalls,judge:judgeCalls};
    for (const foreign of [siblingContext,{...context,personaSession:siblingContext.personaSession},
      {...context,personaSession:{...context.personaSession,sessionId:randomUUID()}}]) {
      await assert.rejects(runtime.readRequest(foreign.scope,foreign.persona,
        foreign.personaSession,a.sessionId,a.requestId));
      await assert.rejects(assessment.runAttempt({...foreign,sessionId:a.sessionId,requestId:a.requestId}));
      await assert.rejects(assessment.readOutcome({...foreign,sessionId:a.sessionId,requestId:a.requestId}));
    }
    assert.deepEqual({actor:actorCalls,judge:judgeCalls},deniedBefore);
    const sourceBefore=(await agents.query('SELECT result_json,request_hash FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[a.sessionId,a.requestId])).rows;
    const effectsBefore=await snapshot(owned.target.targetId);
    const callsBefore=actorCalls;
    const saved=await assessment.readOutcome(a);
    assert.equal(saved.replayed,true);assert.equal(saved.judgment.evaluationId,outcome.judgment.evaluationId);
    assert.equal(judgeCalls,1);assert.equal(actorCalls,callsBefore);
    const guard=await assessment.assertRetainedPacket({packet:JSON.parse(original.packet),...context});
    await guard.assertCurrent();
    const recovery=require('../../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery({
      identityPool:identity,authService:auth,bootstrap,launches:reset.launches,personaAuth:composition.personaAuth,
      personaAuthority:grading.personaAuthority,modeAuthority,scenes,mailAgentReadAssessment:assessment,
      qualifyIdorModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),judge,
      coordinatorFactory:family=>require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family,
        ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool})})});
    const retry=await recovery.retry(login.context,{evaluationId:original.evaluation_id});
    assert.equal(retry.completed,false);assert.equal(retry.verdict,'unavailable');
    assert.equal(judgeCalls,2);assert.equal(judgePackets[1],judgePackets[0]);assert.equal(actorCalls,callsBefore);
    const linked=(await identity.query(`SELECT child.packet,child.run_id,child.owner_key,inv.run_id AS retry_run_id,
      r.status AS retry_run_status FROM secureshop_auth.assessment_retries edge
      JOIN secureshop_auth.assessment_judgments child ON child.evaluation_id=edge.child_id
      JOIN secureshop_auth.assessment_retry_invocations inv ON inv.parent_id=edge.parent_id
      JOIN graph_runtime.runs r ON r.run_id=inv.run_id WHERE edge.parent_id=$1`,[original.evaluation_id])).rows;
    assert.equal(linked.length,1);assert.equal(linked[0].packet,original.packet);
    assert.equal(linked[0].run_id,original.run_id);assert.equal(linked[0].owner_key,original.owner_key);
    assert.notEqual(linked[0].retry_run_id,original.run_id);assert.equal(linked[0].retry_run_status,'completed');
    assert.deepEqual(await snapshot(owned.target.targetId),effectsBefore);
    assert.deepEqual((await agents.query('SELECT result_json,request_hash FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[a.sessionId,a.requestId])).rows,sourceBefore);
    // A second original detail is never assessed before the policy cycle.
    const unassessed=await run('merchant.mail_detail',{choiceId:messageChoice.choiceId},
      {choiceId:messageChoice.choiceId,intent:'mail_detail'});
    const cycleInput={...context,sessionId:unassessed.input.sessionId,requestId:unassessed.input.requestId};
    assert.deepEqual(await assessment.readOutcome(cycleInput),{completed:false,status:'unconfirmed',modelEvaluated:false});
    const modeService=require('../../server/services/secureshopStandaloneMode').createSecureShopStandaloneMode({authService:auth,repository:modes});
    let current=await modeService.get(login.context);
    await modeService.set(login.context,{mode:'fixed',expectedRevision:current.revision});
    assert.deepEqual(await assessment.runAttempt(cycleInput),{completed:false,status:'ineligible',modelEvaluated:false});
    current=await modeService.get(login.context);
    await modeService.set(login.context,{mode:'vuln',expectedRevision:current.revision});
    await assert.rejects(assessment.runAttempt(cycleInput));
    await assert.rejects(assessment.readOutcome(a));
    await assert.rejects(guard.assertCurrent());
    assert.equal(judgeCalls,2);
    const immutableBefore=(await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[owned.target.targetId])).rows;
    const canonicalSnapshot=async()=>Object.fromEntries(await Promise.all([
      ['assessment_judgments','objective_id=$1',[ID]],
      ['assessment_retries','parent_id=$1',[original.evaluation_id]],
      ['assessment_retry_invocations','parent_id=$1',[original.evaluation_id]],
    ].map(async ([table,where,parameters])=>[table,(await identity.query(
      `SELECT to_jsonb(t) row FROM secureshop_auth.${table} t WHERE ${where} ORDER BY to_jsonb(t)::text`,
      parameters)).rows])));
    const canonicalBefore=await canonicalSnapshot();
    assert.equal(canonicalBefore.assessment_judgments.length,2);
    assert.equal(canonicalBefore.assessment_retries.length,1);
    assert.equal(canonicalBefore.assessment_retry_invocations.length,1);
    const resetReceipt=await reset.launchResetCoordinator.reset({...scope,expectedGeneration:scope.generation,idempotencyKey:randomUUID()});
    assert.equal(resetReceipt.status,'committed');
    assert.equal(resetReceipt.fromGeneration,scope.generation);
    assert.equal(resetReceipt.toGeneration,scope.generation+1);
    assert.equal(resetReceipt.binding.launchId,scope.launchId);
    assert.equal(resetReceipt.binding.generation,scope.generation+1);
    const retirement=(await identity.query(`SELECT scene_id,target_id,retiring_launch_id,from_generation,to_generation
      FROM identity.secureshop_mail_scene_retirements WHERE target_id=$1`,[owned.target.targetId])).rows;
    assert.deepEqual(retirement,[{scene_id:retainedScene.scene.sceneId,target_id:owned.target.targetId,
      retiring_launch_id:scope.launchId,from_generation:String(scope.generation),
      to_generation:String(scope.generation+1)}]);
    const cleanupTargets=await reset.cleanupAuthority.listTargets(resetReceipt.resetId);
    const cleaned=cleanupTargets.targets.find(row=>row.targetId===owned.target.targetId);
    assert.deepEqual(cleaned,{targetId:owned.target.targetId,targetKind:'persona_inbox',
      launchId:birthScope.launchId,scenarioId:birthScope.scenarioId,
      fromGeneration:birthScope.generation,platformOwnerId:birthScope.platformOwnerId,
      platformSessionId:birthScope.platformSessionId});
    assert.equal(resetReceipt.targets,cleanupTargets.targets.length);
    const history=(await identity.query(`SELECT target_id,target_kind,launch_id,scenario_id,from_generation,
      original_platform_owner_id,original_platform_session_id,operation_id
      FROM identity.secureshop_target_cleanup_history WHERE target_id=$1`,[owned.target.targetId])).rows;
    assert.deepEqual(history,[{target_id:owned.target.targetId,target_kind:'persona_inbox',
      launch_id:birthScope.launchId,scenario_id:birthScope.scenarioId,
      from_generation:String(birthScope.generation),original_platform_owner_id:birthScope.platformOwnerId,
      original_platform_session_id:birthScope.platformSessionId,operation_id:resetReceipt.resetId}]);
    const cleanup=(await agents.query(`SELECT operation_id,target_id,deleted_message_count,retained_operation_count
      FROM secureshop_agents.lab_mail_cleanup_receipts WHERE target_id=$1`,[owned.target.targetId])).rows;
    assert.equal(cleanup.length,1);assert.equal(cleanup[0].operation_id,resetReceipt.resetId);
    assert.equal(cleanup[0].target_id,owned.target.targetId);assert.ok(cleanup[0].deleted_message_count>0);
    assert.equal(cleanup[0].retained_operation_count,immutableBefore.length);
    await reset.cleanupAuthority.checkTarget({...birthScope,targetId:owned.target.targetId,
      targetKind:'persona_inbox',fromGeneration:birthScope.generation,operationId:resetReceipt.resetId});
    await assert.rejects(reset.cleanupAuthority.checkTarget({...scope,targetId:owned.target.targetId,
      targetKind:'persona_inbox',fromGeneration:scope.generation,operationId:resetReceipt.resetId}),
    {code:'RESET_CLEANUP_AUTHORITY_REQUIRED'});
    await assert.rejects(reset.cleanupAuthority.checkTarget({...birthScope,targetId:owned.target.targetId,
      targetKind:'persona_inbox',fromGeneration:birthScope.generation,operationId:randomUUID()}),
    {code:'RESET_CLEANUP_AUTHORITY_REQUIRED'});
    await assert.rejects(runtime.readRequest(scope,context.persona,context.personaSession,a.sessionId,a.requestId));
    await assert.rejects(assessment.readOutcome(a));
    assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[owned.target.targetId])).rows,immutableBefore);
    assert.equal((await stores.AGENTS.migration.query('SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[owned.target.targetId])).rows[0].n,0);
    assert.deepEqual(await canonicalSnapshot(),canonicalBefore);
    assert.deepEqual(await snapshot(sibling.target.targetId),siblingBefore);
    await reset.launches.assertCurrent(siblingScope);
    assert.equal((await identity.query('SELECT count(*)::int n FROM secureshop_auth.assessment_completions WHERE objective_id=$1',[ID])).rows[0].n,0);
    assert.equal((await identity.query(`SELECT count(*)::int n FROM secureshop_auth.assessment_contributions c
      JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
      WHERE j.objective_id=$1`,[ID])).rows[0].n,0);
    assert.notEqual(birthContext.scope.launchId,scope.launchId);
    assert.equal(actorCalls,8);assert.equal(chatCalls,4);assert.equal(finalCalls,4);assert.equal(judgeCalls,2);
    t.diagnostic('Controlled native graph and unavailable Judge only; no external model, browser, or objective credit.');
  });
