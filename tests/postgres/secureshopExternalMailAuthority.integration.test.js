'use strict';
// Native authority/storage verification only. SMTP is a bounded controlled
// callback; no external connection, browser, actor, Judge or delivery claim.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {Pool}=require('pg'),express=require('express');
const setup=require('./secureshopManualRagNativeSetup');
const ROOT=path.resolve(__dirname,'../..');
const TITLE='native external test mail preserves parent authority claims and lifecycle fences without SMTP';
const STORES=Object.freeze({IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',COMMERCE:'secureshop'});
const FLAGS=Object.freeze(['realStandaloneReady','parentOnly','preparedCancelNoEffect','concurrentSingleClaim',
  'savedReadOnly','dispatchBeforeLogout','logoutBeforeDispatch','retainedAfterLogin','expiredReadAfterLogin','modeFence','fixedGuarded',
  'personaRevoked','practiceFence','resetFence','unknownRetained','quotaAcrossReset','siblingPreserved','noCredit','fixtureCleaned']);
const LIMITS=Object.freeze({fixtureMs:120000,httpMs:10000,controlledSmtpCalls:10,holdMs:2500,evidenceBytes:2*1024*1024});
const sha=value=>createHash('sha256').update(value).digest('hex');
function ownedUrls(env=process.env) {
  const urls={};let nonce,port;
  for(const [store,name]of Object.entries(STORES))for(const role of ['RUNTIME','MIGRATION']){
    const url=new URL(env[`PG_EXTERNAL_MAIL_${store}_${role}_URL`]);
    const match=/^\/owasp_ai_goat_test_extmail_auth_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
    assert.equal(url.protocol,'postgresql:');assert.equal(url.hostname,'127.0.0.1');
    assert.equal(url.username,`dvaia_${name}_${role.toLowerCase()}`);
    assert.equal(url.password,'');assert.equal(url.search,'');assert.equal(url.hash,'');
    assert.ok(match&&match[2]===name);
    assert.ok(Buffer.byteLength(url.pathname.slice(1),'utf8')<=63,'Exact PostgreSQL database name must not be truncated');
    assert.match(url.port,/^[1-9]\d{0,4}$/);assert.ok(Number(url.port)<=65535);
    nonce??=match[1];port??=url.port;assert.equal(match[1],nonce);assert.equal(url.port,port);
    urls[`${store}_${role}`]=url.href;
  }
  assert.equal(new Set(Object.values(urls)).size,8);return urls;
}
async function json(response) {
  const reader=response.body.getReader(),parts=[];let size=0;
  try{for(;;){const next=await reader.read();if(next.done)break;
    size+=next.value.length;assert.ok(size<=128*1024);parts.push(Buffer.from(next.value));}}
  catch(error){await reader.cancel().catch(()=>{});throw error;}
  return JSON.parse(Buffer.concat(parts).toString('utf8'));
}
async function boundedWait(promise,ms,message) {
  let timer;
  try{return await Promise.race([promise,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(Error(message)),ms);
  })]);}finally{clearTimeout(timer);}
}
const SNAPSHOT_TABLES=Object.freeze({
  IDENTITY_RUNTIME:['secureshop_auth.external_mail_operations','identity.secureshop_scenes',
    'identity.secureshop_scene_execution_grants','identity.secureshop_target_reservations',
    'secureshop_auth.practice_selections','secureshop_auth.tenant_modes',
    'graph_runtime.runs','graph_runtime.effects','secureshop_auth.assessment_judgments',
    'secureshop_auth.assessment_completions','secureshop_auth.assessment_contributions'],
  AGENTS_RUNTIME:['secureshop_agents.turn_requests','secureshop_agents.agent_trace'],
});
async function snapshot(pools) {
  const result={};let bytes=0;
  for(const [store,tables]of Object.entries(SNAPSHOT_TABLES))for(const table of tables){
    const rows=(await pools[store].query(`SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY to_jsonb(t)::text LIMIT 1025`)).rows;
    assert.ok(rows.length<=1024);const encoded=JSON.stringify(rows);bytes+=Buffer.byteLength(encoded);
    assert.ok(bytes<=4*1024*1024);result[table]={count:rows.length,sha256:sha(encoded)};
  }
  return result;
}
function assertEvidence(value) {
  assert.equal(value.schemaVersion,1);assert.equal(value.kind,'external-mail-native-authority');
  assert.equal(value.passed,true);for(const flag of FLAGS)assert.equal(value[flag],true,flag);
  for(const field of ['actualSmtpCalls','modelCalls','judgeCalls','browserCalls'])assert.equal(value[field],0);
  assert.equal(value.transport,'controlled-no-network');assert.equal(value.deliveryConfirmed,false);
  assert.equal(value.controlledSmtpCalls,5);
  assert.deepEqual(value.errors,[]);assert.deepEqual(value.cleanupErrors,[]);
  for(const proof of value.readOnly){assert.deepEqual(Object.keys(proof.before).sort(),Object.values(SNAPSHOT_TABLES).flat().sort());
    assert.deepEqual(proof.after,proof.before);assert.equal(proof.callsAfter,proof.callsBefore);}
  assert.ok(value.readOnly.length>=3);
  assert.equal(value.logoutWait.waitEventType,'Lock');
  assert.equal(value.logoutWait.dispatchState,'dispatching');
  assert.equal(value.logoutWait.logoutCompletedBeforeRelease,false);
  assert.equal(value.logoutDeniedDraft.beforeState,'prepared');
  assert.equal(value.logoutDeniedDraft.afterState,'prepared');
  assert.equal(value.logoutDeniedDraft.claimedAt,null);
  assert.equal(value.logoutDeniedDraft.smtp,null);
  assert.equal(value.logoutDeniedDraft.status,401);
  assert.equal(value.logoutDeniedDraft.callsAfter,value.logoutDeniedDraft.callsBefore);
  assert.equal(value.expiredRecovery.seed,'controlled-historical-prepared-insert');
  assert.equal(value.expiredRecovery.state,'expired');assert.equal(value.expiredRecovery.persistedState,'prepared');
  assert.equal(value.expiredRecovery.claimedAt,null);assert.equal(value.expiredRecovery.smtp,null);
  assert.notEqual(value.expiredRecovery.originalScopeKey,value.expiredRecovery.currentScopeKey);
  assert.equal(value.unknownBeforeReset.state,'unknown');assert.equal(value.unknownAfterReset.state,'unknown');
  assert.deepEqual(value.unknownAfterReset,value.unknownBeforeReset);
  assert.deepEqual(value.quotaAfterReset,value.quotaBeforeReset);
  assert.equal(value.quotaBeforeReset.count,4);assert.match(value.quotaBeforeReset.sha256,/^[a-f0-9]{64}$/);
  assert.deepEqual(value.siblingAfter,value.siblingBefore);assert.ok(value.siblingBefore.operationId);
}
const ENABLED=process.env.PG_EXTERNAL_MAIL_AUTHORITY_NATIVE==='yes'&&process.env.PG_TEST_DISPOSABLE==='yes';
if(require.main===module)test(TITLE,{skip:!ENABLED,timeout:LIMITS.fixtureMs},async t=>{
  assert.equal(process.cwd(),ROOT);assert.equal(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE,ROOT);
  const evidencePath=process.env.PG_EXTERNAL_MAIL_AUTHORITY_EVIDENCE_PATH;
  assert.ok(typeof evidencePath==='string'&&evidencePath.startsWith(`${ROOT}/tasks/qualification/`));
  require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidencePath,
    {root:ROOT,dockerHost:process.env.DOCKER_HOST,basename:'external-mail-authority-evidence.json'});
  const urls=ownedUrls(),pools=Object.fromEntries(Object.entries(urls).map(([key,connectionString])=>[key,
    new Pool({connectionString,max:key.endsWith('RUNTIME')?10:2,connectionTimeoutMillis:1500,
      statement_timeout:8000,lock_timeout:3000,application_name:'external-mail-authority-native'})]));
  const leasePool=new Pool({connectionString:urls.IDENTITY_RUNTIME,max:3,connectionTimeoutMillis:1500,statement_timeout:8000,lock_timeout:3000});
  const evidence={schemaVersion:1,kind:'external-mail-native-authority',passed:false,
    ...Object.fromEntries(FLAGS.map(flag=>[flag,false])),transport:'controlled-no-network',deliveryConfirmed:false,
    actualSmtpCalls:0,modelCalls:0,judgeCalls:0,browserCalls:0,controlledSmtpCalls:0,
    errors:[],cleanupErrors:[],readOnly:[],receipts:[]};
  let stage='setup',failure,lifecycle,server,fileRoot,held=null,failSmtp=false;
  const total=AbortSignal.timeout(110000),pending=new Set();
  const provider={async chat(){evidence.modelCalls++;throw Error('Model forbidden in external mail authority test');},
    async finalResponse(){evidence.modelCalls++;throw Error('Model forbidden in external mail authority test');}};
  const judge=async()=>{evidence.judgeCalls++;throw Error('Judge forbidden in external mail authority test');};
  const track=promise=>{pending.add(promise);promise.finally(()=>pending.delete(promise)).catch(()=>{});return promise;};
  try{
    await setup.migrateManualRagStores(pools);
    const identity=pools.IDENTITY_RUNTIME,agents=pools.AGENTS_RUNTIME,review=pools.REVIEW_RUNTIME;
    for(const [key,name]of Object.entries(STORES))
      assert.equal((await pools[`${key}_RUNTIME`].query('SELECT current_user AS role')).rows[0].role,`dvaia_${name}_runtime`);
    const auth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
      repository:require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity})});
    const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
    const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({
      agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
    fileRoot=await fs.mkdtemp(path.join(path.dirname(evidencePath),'external-mail-files-'));
    const files=require('../../sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({root:fileRoot,maxReadBytes:1024,maxWriteBytes:1024});
    lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
      identityPool:identity,agentsPool:agents,reviewPool:review,leasePool,audit,files});
    const {grading,scenes}=await setup.createManualRagGrading({pools,urls,lifecycle,progress,judge});
    const {composition,bootstrap,standalone,bound}=await setup.createManualRagApplication({
      pools,lifecycle,grading,scenes,auth,provider,judge,audit});
    const transport={isAvailable:()=>true,async send(preview,{signal,deadlineAt}){
      evidence.controlledSmtpCalls++;assert.ok(evidence.controlledSmtpCalls<=LIMITS.controlledSmtpCalls);
      assert.equal(signal.aborted,false);assert.ok(deadlineAt>Date.now()&&deadlineAt<=Date.now()+20000);
      require('../../server/services/secureshopExternalMailContract').validateExternalMailPreview(preview);
      if(held){held.enter();await held.promise;}
      if(failSmtp)throw Error('Controlled remote uncertainty; no external connection');
      return{smtpAccepted:true,deliveryConfirmed:false,messageId:`<controlled-${preview.operationId}@example.invalid>`,
        accepted:[preview.recipient],rejected:[]};
    }};
    const externalMail={launches:composition.launches,personaAuth:composition.personaAuth,
      application:require('../../server/services/secureshopExternalMail').createExternalMailApplication({
        repository:require('../../server/database/postgres/secureshopExternalMailRepository').createExternalMailRepository({pool:identity}),
        authority:require('../../server/database/postgres/secureshopExternalMailAuthority').createExternalMailAuthority({
          pool:identity,personaAuthority:grading.personaAuthority,sender:'synthetic@gmail.com'}),
        transport,sender:'synthetic@gmail.com'})};
    const practices=require('../../server/services/secureshopPracticeAdmission').createSecureShopPracticeAdmission({
      repository:require('../../server/database/postgres/secureshopPracticeAdmissionRepository').createSecureShopPracticeAdmissionRepository({pool:identity}),
      catalog:composition.catalog});
    const app=express();app.use(express.json());server=await new Promise(resolve=>{
      const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
    const origin=`http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth',require('../../server/routes/secureshopStandaloneAuth').createSecureShopStandaloneAuthRouter({
      ...standalone,externalMail,practices,allowedOrigins:[origin]}));
    app.use('/api/secureshop',require('../../server/middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({getGateway:()=>bound.gateway}));
    const request=async(pathname,{headers={},method='GET',body,expected=200}={})=>{
      total.throwIfAborted();
      const response=await fetch(`${origin}/api/secureshop${pathname}`,{method,redirect:'error',
        signal:AbortSignal.any([total,AbortSignal.timeout(LIMITS.httpMs)]),
        headers:{...headers,...(method==='POST'?{Origin:origin,'Content-Type':'application/json'}:{})},
        ...(body===undefined?{}:{body:JSON.stringify(body)})});
      const value=await json(response);assert.equal(response.status,expected,
        `${method} ${pathname}: ${JSON.stringify(value).slice(0,250)}`);
      if(pathname.startsWith('/auth/external-mail'))assert.equal(response.headers.get('cache-control'),'no-store');
      return value;
    };
    const suffix=randomUUID().slice(0,8),password='controlled-external-test';
    const boot=async active=>{
      const value=await bootstrap(active.context),scope=await composition.launches.resolveCapability(value.bearer);
      const headers={cookie:`owasp_ai_goat_shop_session=${active.token}`,authorization:`Bearer ${value.persona.token}`,
        'x-owasp-ai-goat-secureshop-launch':value.bearer};
      await request('/products?limit=1',{headers});
      return{active,boot:value,scope,headers,cookie:{cookie:headers.cookie}};
    };
    const login=async(tag,role='merchant')=>{
      const username=`ext_${suffix}_${tag}`;
      const active=await auth.register({username,password,email:`${username}@example.invalid`,role});
      return{...await boot(active),username};
    };
    const base='/auth/external-mail',owner=await login('owner'),foreign=await login('foreign');
    evidence.realStandaloneReady=true;
    const prepare=async actor=>{
      const ready=await request(`${base}/readiness`,{headers:actor.headers});assert.equal(ready.available,true);
      const result=await request(`${base}/prepare`,{headers:actor.headers,method:'POST',
        body:{version:1,operationId:randomUUID(),recipient:'synthetic@sharklasers.com',scopeKey:ready.scopeKey}});
      assert.equal(result.state,'prepared');evidence.receipts.push(result);return result;
    };
    const confirm=(actor,draft,expected=200)=>request(`${base}/confirm`,{headers:actor.headers,method:'POST',expected,
      body:{version:1,operationId:draft.operationId,requestSha256:draft.requestSha256}});
    const read=(actor,draft,expected=200)=>request(`${base}/operations/${draft.operationId}`,{headers:actor.headers,expected});
    const readOnly=async(actor,draft,label)=>{
      const proof={label,before:await snapshot(pools),callsBefore:evidence.controlledSmtpCalls};
      const value=await read(actor,draft);proof.after=await snapshot(pools);proof.callsAfter=evidence.controlledSmtpCalls;
      evidence.readOnly.push(proof);assert.deepEqual(proof.after,proof.before);assert.equal(proof.callsAfter,proof.callsBefore);
      return value;
    };
    stage='parent-only';const cancelled=await prepare(owner);
    await request(`${base}/confirm`,{headers:{authorization:owner.headers.authorization,
      'x-owasp-ai-goat-secureshop-launch':owner.boot.bearer},method:'POST',expected:401,
      body:{version:1,operationId:cancelled.operationId,requestSha256:cancelled.requestSha256}});
    await read(foreign,cancelled,404);assert.equal(evidence.controlledSmtpCalls,0);evidence.parentOnly=true;
    assert.equal((await request(`${base}/cancel`,{headers:owner.headers,method:'POST',
      body:{version:1,operationId:cancelled.operationId,requestSha256:cancelled.requestSha256}})).state,'cancelled');
    assert.equal((await confirm(owner,cancelled)).state,'cancelled');assert.equal(evidence.controlledSmtpCalls,0);
    evidence.preparedCancelNoEffect=true;

    stage='concurrent-confirm-and-logout';
    const draft=await prepare(owner),unsentDraft=await prepare(owner);let enter,release,rejectHold;
    assert.notEqual(unsentDraft.operationId,draft.operationId);
    // A historical expiry fixture, not a retroactive change to an existing
    // draft or a claim that ten minutes elapsed during this bounded test.
    const contract=require('../../server/services/secureshopExternalMailContract');
    const expiredPreview=contract.makeExternalMailPreview({operationId:randomUUID(),
      sender:unsentDraft.preview.sender,recipient:unsentDraft.preview.recipient});
    await identity.query(`INSERT INTO secureshop_auth.external_mail_operations
      (operation_id,principal_id,auth_session_id,scope_key,binding,request_sha256,preview,sender_key,created_at,expires_at)
      SELECT $2,principal_id,auth_session_id,scope_key,binding,$3,$4,sender_key,
        statement_timestamp()-interval '20 minutes',statement_timestamp()-interval '10 minutes'
      FROM secureshop_auth.external_mail_operations WHERE operation_id=$1`,
    [unsentDraft.operationId,expiredPreview.operationId,
      contract.externalMailRequestSha256(expiredPreview,unsentDraft.scopeKey),expiredPreview]);
    const entered=new Promise(resolve=>{enter=resolve;});
    const holdTimer=setTimeout(()=>rejectHold(Error('Controlled SMTP hold expired')),LIMITS.holdMs);
    held={enter,promise:new Promise((resolve,reject)=>{release=()=>{clearTimeout(holdTimer);resolve();};rejectHold=reject;})};
    held.promise.catch(()=>{});
    const sending=track(confirm(owner,draft));
    await boundedWait(entered,3000,'Dispatch admission did not arrive');
    const durable=(await identity.query(`SELECT state FROM secureshop_auth.external_mail_operations WHERE operation_id=$1`,
      [draft.operationId])).rows[0];assert.equal(durable.state,'dispatching');
    assert.equal(evidence.controlledSmtpCalls,1);
    let logoutFinished=false;
    const logout=track(request('/auth/logout',{headers:owner.cookie,method:'POST',body:{}})
      .then(value=>{logoutFinished=true;return value;}));
    let waiting;
    const waitDeadline=Date.now()+1200;
    while(Date.now()<waitDeadline){
      waiting=(await identity.query(`SELECT wait_event_type FROM pg_stat_activity
        WHERE datname=current_database() AND application_name='external-mail-authority-native'
          AND state='active' AND wait_event_type='Lock'
          AND query LIKE 'UPDATE secureshop_auth.sessions%' LIMIT 1`)).rows[0];
      if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));
    }
    assert.ok(waiting,'Real logout must wait on the live dispatch lifecycle lease');
    evidence.logoutWait={waitEventType:waiting.wait_event_type,dispatchState:durable.state,logoutCompletedBeforeRelease:logoutFinished};
    assert.equal(logoutFinished,false);release();
    const accepted=await sending;held=null;assert.equal(accepted.state,'smtp_accepted');
    await logout;
    evidence.dispatchBeforeLogout=true;
    const deniedCalls=evidence.controlledSmtpCalls;
    await confirm(owner,unsentDraft,401);
    const unsentAfter=(await identity.query(`SELECT state,claimed_at,smtp
      FROM secureshop_auth.external_mail_operations WHERE operation_id=$1`,[unsentDraft.operationId])).rows[0];
    assert.equal(unsentAfter.state,'prepared');assert.equal(unsentAfter.claimed_at,null);assert.equal(unsentAfter.smtp,null);
    evidence.logoutDeniedDraft={operationId:unsentDraft.operationId,beforeState:unsentDraft.state,
      afterState:unsentAfter.state,claimedAt:unsentAfter.claimed_at,smtp:unsentAfter.smtp,status:401,
      callsBefore:deniedCalls,callsAfter:evidence.controlledSmtpCalls};
    assert.equal(evidence.controlledSmtpCalls,deniedCalls);evidence.logoutBeforeDispatch=true;
    const ownerAgain={...await boot(await auth.login({username:owner.username,password})),username:owner.username};
    assert.deepEqual(await readOnly(ownerAgain,draft,'accepted-after-new-login'),accepted);evidence.retainedAfterLogin=true;
    await confirm(ownerAgain,draft,409);
    const expiredReceipt=await readOnly(ownerAgain,expiredPreview,'expired-after-new-login');
    assert.equal(expiredReceipt.state,'expired');assert.equal(expiredReceipt.smtp,null);
    const expiryStored=(await identity.query(`SELECT state,claimed_at,smtp FROM secureshop_auth.external_mail_operations
      WHERE operation_id=$1`,[expiredPreview.operationId])).rows[0];
    const currentReady=await request(`${base}/readiness`,{headers:ownerAgain.headers});
    evidence.expiredRecovery={seed:'controlled-historical-prepared-insert',state:expiredReceipt.state,
      persistedState:expiryStored.state,claimedAt:expiryStored.claimed_at,smtp:expiryStored.smtp,
      originalScopeKey:expiredReceipt.scopeKey,currentScopeKey:currentReady.scopeKey};
    assert.equal(expiryStored.state,'prepared');assert.equal(expiryStored.claimed_at,null);
    assert.notEqual(expiredReceipt.scopeKey,currentReady.scopeKey);evidence.expiredReadAfterLogin=true;
    const duplicateActor=await login('duplicate'),duplicateDraft=await prepare(duplicateActor);
    const countBefore=evidence.controlledSmtpCalls;
    const duplicateReceipts=await Promise.all([confirm(duplicateActor,duplicateDraft),confirm(duplicateActor,duplicateDraft)]);
    assert.equal(evidence.controlledSmtpCalls,countBefore+1);
    assert.ok(duplicateReceipts.every(value=>['dispatching','smtp_accepted'].includes(value.state)));
    assert.equal((await read(duplicateActor,duplicateDraft)).state,'smtp_accepted');
    evidence.concurrentSingleClaim=true;
    const sibling=await prepare(foreign);evidence.siblingBefore=await read(foreign,sibling);

    stage='unknown-and-no-resend';const unknown=await prepare(ownerAgain);failSmtp=true;
    evidence.unknownBeforeReset=await confirm(ownerAgain,unknown);failSmtp=false;
    assert.equal(evidence.unknownBeforeReset.state,'unknown');
    assert.deepEqual(await confirm(ownerAgain,unknown),evidence.unknownBeforeReset);
    assert.deepEqual(await readOnly(ownerAgain,unknown,'unknown-get'),evidence.unknownBeforeReset);
    assert.equal(evidence.controlledSmtpCalls,3);evidence.unknownRetained=true;evidence.savedReadOnly=true;

    stage='mode';const modeActor=await login('mode'),modeDraft=await prepare(modeActor);
    const mode=await request('/auth/mode',{headers:modeActor.cookie});
    await request('/auth/mode',{method:'POST',headers:modeActor.cookie,body:{mode:'fixed',expectedRevision:mode.revision}});
    await confirm(modeActor,modeDraft,409);assert.equal(evidence.controlledSmtpCalls,3);evidence.modeFence=true;
    const fixed=await prepare(modeActor);assert.notEqual(fixed.scopeKey,modeDraft.scopeKey);
    assert.equal((await confirm(modeActor,fixed)).state,'smtp_accepted');evidence.fixedGuarded=true;

    stage='persona-revocation';const personaActor=await login('persona'),personaDraft=await prepare(personaActor);
    await composition.personaAuth.logout({scope:personaActor.scope,token:personaActor.boot.persona.token});
    await confirm(personaActor,personaDraft,401);assert.equal(evidence.controlledSmtpCalls,4);evidence.personaRevoked=true;

    // Shared reset intentionally requires one active scene for the tenant owner.
    // Exercise it before publishing a second practice; do not relax that guard.
    stage='reset';const resetActor=await login('reset'),resetDraft=await prepare(resetActor);
    const retainedQuota=async()=>{
      const rows=(await identity.query(`SELECT operation_id,principal_id,sender_key,claimed_at,state
        FROM secureshop_auth.external_mail_operations WHERE claimed_at IS NOT NULL ORDER BY operation_id`)).rows;
      return{count:rows.length,sha256:sha(JSON.stringify(rows))};
    };
    evidence.quotaBeforeReset=await retainedQuota();
    const admin=await auth.login({username:'student_admin',password:'student123'});
    const adminHeaders={cookie:`owasp_ai_goat_shop_session=${admin.token}`};
    const adminBoot=await request('/auth/bootstrap',{headers:adminHeaders,method:'POST',body:{}});
    const ready=await request('/auth/reset-readiness',{headers:adminHeaders});
    assert.equal(ready.available,true);assert.equal(ready.launchId,adminBoot.launch.launchId);
    await request('/auth/reset',{headers:adminHeaders,method:'POST',body:{launchId:ready.launchId,
      expectedGeneration:ready.generation,idempotencyKey:randomUUID(),sceneId:ready.scene.id,confirmation:'RESET_SHARED_PRACTICE'}});
    await confirm(resetActor,resetDraft,409);assert.equal(evidence.controlledSmtpCalls,4);evidence.resetFence=true;
    const recovered=await boot(await auth.login({username:owner.username,password}));
    evidence.unknownAfterReset=await readOnly(recovered,unknown,'unknown-after-reset');
    assert.deepEqual(evidence.unknownAfterReset,evidence.unknownBeforeReset);
    const newReady=await request(`${base}/readiness`,{headers:recovered.headers});
    const blocked=await request(`${base}/prepare`,{headers:recovered.headers,method:'POST',expected:409,
      body:{version:1,operationId:randomUUID(),recipient:'synthetic@sharklasers.com',scopeKey:newReady.scopeKey}});
    assert.equal(blocked.code,'EXTERNAL_MAIL_RECOVERY_REQUIRED');
    evidence.quotaAfterReset=await retainedQuota();assert.deepEqual(evidence.quotaAfterReset,evidence.quotaBeforeReset);
    evidence.quotaAcrossReset=true;
    // Sibling operation is durable identity evidence, not mutable practice mail.
    const foreignAgain=await boot(await auth.login({username:foreign.username,password}));
    evidence.siblingAfter=await read(foreignAgain,sibling);assert.deepEqual(evidence.siblingAfter,evidence.siblingBefore);
    evidence.siblingPreserved=true;
    stage='practice';const practiceActor=await login('practice'),practiceDraft=await prepare(practiceActor);
    const practice=await request('/auth/practices',{headers:practiceActor.cookie,method:'POST',body:{operationId:randomUUID()}});
    assert.equal(practice.status,'published');
    await confirm(practiceActor,practiceDraft,409);assert.equal(evidence.controlledSmtpCalls,4);evidence.practiceFence=true;
    const practiceAgain={...await boot({context:await auth.authenticate(practiceActor.active.token),token:practiceActor.active.token}),username:practiceActor.username};
    const privateDraft=await prepare(practiceAgain);assert.notEqual(privateDraft.scopeKey,practiceDraft.scopeKey);
    assert.equal((await confirm(practiceAgain,privateDraft)).state,'smtp_accepted');
    assert.equal(evidence.controlledSmtpCalls,5);
    for(const table of ['secureshop_auth.assessment_judgments','secureshop_auth.assessment_completions',
      'secureshop_auth.assessment_contributions','graph_runtime.runs','graph_runtime.effects'])
      assert.equal(Number((await identity.query(`SELECT count(*) AS count FROM ${table}`)).rows[0].count),0,table);
    assert.equal(evidence.modelCalls,0);assert.equal(evidence.judgeCalls,0);evidence.noCredit=true;
  }catch(error){failure=error;evidence.errors.push({stage,name:error.name,code:error.code||null,message:String(error.message).slice(0,500)});
    t.diagnostic(JSON.stringify(evidence.errors[0]));}
  finally{
    // Held stand-in always settles within holdMs; wait for owned work before pools close.
    for(const promise of [...pending])try{await promise;}catch{}
    for(const close of [async()=>{if(server){server.closeAllConnections();await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}},
      ()=>lifecycle?.closeFeatureTransports?.(),()=>lifecycle?.auditLedger?.close?.(),async()=>{
        if(fileRoot){assert.equal(await fs.realpath(fileRoot),fileRoot);assert.equal(path.dirname(fileRoot),path.dirname(evidencePath));
          assert.match(path.basename(fileRoot),/^external-mail-files-[A-Za-z0-9]+$/);
          assert.deepEqual(await fs.readdir(fileRoot),[]);await fs.rmdir(fileRoot);}
      },()=>leasePool.end(),...Object.values(pools).map(pool=>()=>pool.end())]){
      try{await close();}catch(error){evidence.cleanupErrors.push(String(error.message).slice(0,250));}
    }
    evidence.fixtureCleaned=evidence.cleanupErrors.length===0;evidence.passed=!failure&&FLAGS.every(flag=>evidence[flag]);
    if(evidence.passed)try{assertEvidence(evidence);}catch(error){failure=error;evidence.passed=false;evidence.errors.push({stage:'evidence',message:String(error.message).slice(0,250)});}
    const encoded=JSON.stringify(evidence);assert.ok(Buffer.byteLength(encoded)<=LIMITS.evidenceBytes);
    await fs.writeFile(evidencePath,encoded,{mode:0o600,flag:'wx'});
  }
  if(failure)throw failure;assert.equal(evidence.passed,true);
});
module.exports={TITLE,STORES,FLAGS,LIMITS,SNAPSHOT_TABLES,ownedUrls,assertEvidence};
