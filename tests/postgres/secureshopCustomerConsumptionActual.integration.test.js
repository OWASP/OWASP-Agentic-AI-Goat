'use strict';
// Original-path native components, import-inert. The current-host launcher and
// full lifecycle assembly are not yet implemented; importing is not a run.
const assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const capture=require('../fixtures/secureshopCustomerConsumptionActual');
const STORES=Object.freeze({IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',COMMERCE:'secureshop'});
function disposableUrls(env=process.env){
  assert.equal(env.PG_TEST_DISPOSABLE,'yes');
  const urls={};let nonce,port;
  for(const [key,name]of Object.entries(STORES))for(const role of ['RUNTIME','MIGRATION']){
    const url=new URL(env[`PG_SECURESHOP_CONSUMPTION_${key}_${role}_URL`]);
    const match=/^\/owasp_ai_goat_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
    assert.equal(url.protocol,'postgresql:');assert.equal(url.hostname,'127.0.0.1');
    assert.equal(url.username,`dvaia_${name}_${role.toLowerCase()}`);
    assert.equal(url.password,'');assert.equal(url.search,'');assert.equal(url.hash,'');
    assert.ok(match&&match[2]===name);assert.ok(Buffer.byteLength(url.pathname.slice(1))<=63);
    assert.match(url.port,/^[1-9]\d{0,4}$/);assert.ok(Number(url.port)<=65535);
    nonce??=match[1];port??=url.port;assert.equal(match[1],nonce);assert.equal(url.port,port);
    urls[`${key}_${role}`]=url.href;
  }
  assert.equal(env.SECURESHOP_DATABASE_URL,urls.COMMERCE_RUNTIME);
  assert.equal(env.SECURESHOP_AGENTS_DATABASE_URL,urls.AGENTS_RUNTIME);
  return Object.freeze(urls);
}
async function snapshotSource(commerce,actorId,siblingId){
  const owners=[actorId,siblingId];
  for(const id of owners)assert.ok(Number.isSafeInteger(id)&&id>0);
  assert.notEqual(actorId,siblingId);
  return (await commerce.query(`SELECT to_jsonb(c) AS row FROM secureshop.cart_items c
    WHERE c.user_id=ANY($1::integer[]) ORDER BY c.id LIMIT 513`,[owners])).rows;
}
async function seedSource({commerce,actorId,siblingId,signal,onAttempt=async()=>{},productName}){
  signal.throwIfAborted();
  const diagnostic=require('../fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  productName??=diagnostic.productNameFor('original');
  assert.ok([diagnostic.productNameFor('original'),...Object.values(diagnostic.SOURCE_NAMES)].includes(productName));
  const before=await snapshotSource(commerce,actorId,siblingId);assert.deepEqual(before,[]);
  const owned={users:[],products:[],cart:[]};
  const attempt={owned,before,actorId,siblingId,commitAttempted:false,committed:false,rollbackAcknowledged:false};
  await onAttempt(attempt);
  const client=await commerce.connect();
  try{
    await client.query('BEGIN');
    // Registered canonical actor IDs do not alias legacy shop users. Insert
    // only absent exact IDs in this disposable store; conflicts roll back.
    for(const id of [actorId,siblingId]){
      signal.throwIfAborted();const username=`v37_owned_${randomUUID().replaceAll('-','')}`;
      await client.query(`INSERT INTO secureshop.shop_users(id,username,email,password,role)
        VALUES($1,$2,$3,'fixture-no-login','customer')`,[id,username,`${username}@example.invalid`]);
      owned.users.push(id);
    }
    const product=(await client.query(`INSERT INTO secureshop.products(name,description,price,status,stock_quantity)
      VALUES($1,'Disposable original-cart size source',1.25,'active',500) RETURNING id`,
    [productName])).rows[0];
    owned.products.push(product.id);
    for(const [id,count]of [[actorId,240],[siblingId,1]]){
      signal.throwIfAborted();
      const rows=(await client.query(`INSERT INTO secureshop.cart_items(user_id,product_id,quantity)
        SELECT $1,$2,1 FROM generate_series(1,$3::integer) RETURNING id`,[id,product.id,count])).rows;
      assert.equal(rows.length,count);owned.cart.push(...rows.map(row=>row.id));
    }
    signal.throwIfAborted();attempt.commitAttempted=true;await onAttempt(attempt);
    await client.query('COMMIT');attempt.committed=true;
  }catch(error){try{await client.query('ROLLBACK');attempt.rollbackAcknowledged=true;}catch{}
    throw error;}finally{client.release();}
  return {owned,before,actorId,siblingId};
}
async function readOriginalSource({actorId,signal}){
  signal.throwIfAborted();
  // This is the actual teaching implementation and SQL query, not an inflated
  // replacement response. MCP cart/server.js wraps this same return value.
  const result=await require('../../agent-host/agents/cart/tools/index.postgres').view({}, {userId:actorId});
  signal.throwIfAborted();assert.equal(result.items.length,240);
  const expectedResult={content:[{type:'text',text:JSON.stringify(result)}]};
  const bytes=Buffer.byteLength(expectedResult.content[0].text);
  assert.ok(bytes>32768&&Buffer.byteLength(JSON.stringify(expectedResult))<=capture.LIMITS.sourceBytes);
  return expectedResult;
}
async function removeSource(commerce,owned){
  assert.equal(owned.users.length,2);assert.equal(owned.products.length,1);assert.equal(owned.cart.length,241);
  const client=await commerce.connect();
  try{await client.query('BEGIN');
    await client.query('DELETE FROM secureshop.cart_items WHERE id=ANY($1::integer[]) AND user_id=ANY($2::integer[])',[owned.cart,owned.users]);
    await client.query('DELETE FROM secureshop.products WHERE id=ANY($1::integer[])',[owned.products]);
    await client.query('DELETE FROM secureshop.shop_users WHERE id=ANY($1::integer[])',[owned.users]);
    await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  const checks={};
  for(const [table,ids]of [['shop_users',owned.users],['products',owned.products],['cart_items',owned.cart]]){
    checks[table]=(await commerce.query(`SELECT id FROM secureshop.${table} WHERE id=ANY($1::integer[])`,[ids])).rows;
    assert.deepEqual(checks[table],[]);
  }
  return checks;
}
async function creditSnapshot(identity){
  const result={};
  for(const table of ['assessment_judgments','assessment_completions','assessment_contributions']){
    const rows=(await identity.query(`SELECT to_jsonb(t) AS row FROM secureshop_auth.${table} t ORDER BY to_jsonb(t)::text LIMIT 1025`)).rows;
    const bytes=JSON.stringify(rows);assert.ok(rows.length<=1024&&Buffer.byteLength(bytes)<=2*1024*1024);
    result[table]={count:rows.length,sha256:createHash('sha256').update(bytes).digest('hex')};
  }
  return result;
}
function registrationInput(label){
  assert.ok(['owner','sibling'].includes(label));
  const username=`v37_${label}_${randomUUID().replaceAll('-','').slice(0,16)}`;
  return {username,email:`${username}@example.invalid`,password:randomUUID(),role:'customer'};
}
async function initializeOriginalAcl({migration,runtime}){
  const client=await migration.connect();
  try{await client.query('BEGIN');await require('../../server/database/postgres/secureshopAgentsDb').seed(client);
    await client.query('COMMIT');}
  catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  const permissions=(await runtime.query('SELECT tool_name,role,allowed FROM secureshop_agents.tool_permissions ORDER BY tool_name,role')).rows;
  const expected=require('../../server/data/secureshopAgentSeeds').TOOLS.flatMap(([tool,matrix])=>
    ['customer','merchant','admin'].map(role=>({tool_name:tool,role,allowed:matrix[role]?1:0})));
  const sorted=rows=>[...rows].sort((a,b)=>`${a.tool_name}:${a.role}`.localeCompare(`${b.tool_name}:${b.role}`));
  assert.deepEqual(sorted(permissions),sorted(expected),'Original complete ACL seed matrix differs');
  const enforcement=(await runtime.query("SELECT value FROM secureshop_agents.system_config WHERE key='enforce_tool_acl'")).rows;
  assert.deepEqual(enforcement,[{value:'false'}]);
  const acl=require('../../server/database/postgres/secureshopAgentsDb').createSecureShopAgentsDb(runtime);
  assert.deepEqual(await acl.getPermission('cart.view','customer'),{allowed:1});assert.equal(await acl.getEnforcement(),false);
  return {permissions:sorted(permissions),enforcement:false,cartViewCustomerAllowed:true};
}
async function provisionPeerTenant({migration,principal,signal,persist}){
  const journal={tenantId:randomUUID(),slug:`v37_peer_${randomUUID().replaceAll('-','').slice(0,16)}`,
    principalId:principal.principalId,shopUserId:principal.shopUserId,commitAttempted:false,committed:false};
  assert.match(journal.principalId,/^[a-f0-9-]{36}$/);assert.ok(Number.isSafeInteger(journal.shopUserId)&&journal.shopUserId>0);
  await persist(journal);signal.throwIfAborted();
  const client=await migration.connect();
  try{
    await client.query('BEGIN');
    const tenant=(await client.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2) RETURNING owner_id',[journal.tenantId,journal.slug])).rows[0];
    journal.ownerId=Number(tenant.owner_id);assert.ok(Number.isSafeInteger(journal.ownerId)&&journal.ownerId>0);
    await client.query("INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')",
      [journal.tenantId,journal.principalId,journal.shopUserId]);
    signal.throwIfAborted();journal.commitAttempted=true;await persist(journal);
    await client.query('COMMIT');journal.committed=true;await persist(journal);
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  return journal;
}
function assertDistinctOwners(owner,sibling){
  for(const key of ['platformOwnerId','platformSessionId','launchId']){
    assert.ok(owner.scope[key]&&sibling.scope[key]);assert.notEqual(owner.scope[key],sibling.scope[key]);
  }
  assert.ok(owner.principalId&&sibling.principalId);assert.notEqual(owner.principalId,sibling.principalId);
  assert.notEqual(owner.persona.id,sibling.persona.id);assert.notEqual(owner.sessionId,sibling.sessionId);
}
async function runCanonicalPair({pools,auth,bootstrap,composition,lifecycle,grading,standalone,
  provider,pool,manifest,actorCalls,signal,persist,quiesce,promptProfile='original',sourceArm}){
  assert.ok(signal instanceof AbortSignal);signal.throwIfAborted();
  const diagnostic=require('../fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  diagnostic.messageFor(promptProfile);
  const productName=diagnostic.productNameFor(promptProfile,sourceArm);
  assert.equal(typeof persist,'function');
  assert.equal(typeof quiesce,'function','Owned host and transport shutdown required before SQL cleanup');
  assert.deepEqual(actorCalls,[],'Qualification must own the complete physical call ledger');
  const wire={version:promptProfile==='original'?1:2,
    kind:diagnostic.kindFor(promptProfile),
    ...(promptProfile==='original'?{}:{promptProfile,diagnosticOnly:true}),
    ...(sourceArm?{sourceArm}:{}),cases:[],canonicalCredit:false,
    nativeQualificationAccepted:false,lifecycle:{},source:null,cleanup:null};
  const commerce=pools.COMMERCE_RUNTIME;
  const {createCustomerConsumptionAuthority,consumptionFor}=require('../../server/services/secureshopCustomerConsumptionAuthority');
  const modeAuthority=require('../../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({
    launches:composition.launches,progress:require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(pools.IDENTITY_RUNTIME)});
  const authority=createCustomerConsumptionAuthority({modeAuthority,launches:composition.launches,
    personaAuthority:grading.personaAuthority,conversations:lifecycle.conversationService});
  const register=async label=>{
    signal.throwIfAborted();
    const input=registrationInput(label);let active=await auth.register(input),selectedBootstrap=bootstrap;
    if(label==='sibling'){
      const peer=await provisionPeerTenant({migration:pools.IDENTITY_MIGRATION,principal:active.context,signal,
        persist:async journal=>{wire.peerTenant=journal;await persist(wire);}});
      const peerAuth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({
          pool:pools.IDENTITY_RUNTIME,executionTenantSlug:peer.slug})});
      active=await peerAuth.login({username:input.username,password:input.password});
      selectedBootstrap=require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
        launches:composition.launches,personaAuth:composition.personaAuth,authService:peerAuth});
    }
    const boot=await selectedBootstrap(active.context),scope=await composition.launches.resolveCapability(boot.bearer);
    if(label==='sibling')assert.equal(scope.platformOwnerId,wire.peerTenant.ownerId);
    const credential=await composition.personaAuth.authenticateBoundToken({token:boot.persona.token,scope});
    assert.equal(credential.user.role,'customer');
    const persona={id:credential.user.id,role:'customer'};
    const session=await lifecycle.conversationService.create(scope,persona);
    return {active,boot,scope,persona,credential,sessionId:session.id,principalId:active.context.principalId};
  };
  let seed,seedAttempt,primary;
  try{
    const owner=await register('owner'),sibling=await register('sibling');
    assertDistinctOwners(owner,sibling);
    wire.owner={scope:owner.scope,persona:owner.persona,sessionId:owner.sessionId,principalId:owner.principalId};
    wire.sibling={scope:sibling.scope,persona:sibling.persona,sessionId:sibling.sessionId,principalId:sibling.principalId};
    wire.siblingMessagesBefore=await lifecycle.conversationService.getMessages(sibling.sessionId,sibling.scope,sibling.persona);
    seed=await seedSource({commerce,actorId:owner.persona.id,siblingId:sibling.persona.id,signal,productName,
      onAttempt:async attempt=>{seedAttempt=attempt;wire.sourceCreation=attempt;await persist(wire);}});
    wire.source={...seed,afterSeed:await snapshotSource(commerce,seed.actorId,seed.siblingId)};await persist(wire);
    wire.source.product=(await commerce.query('SELECT id,name,price::text FROM secureshop.products WHERE id=$1',[seed.owned.products[0]])).rows[0];
    wire.creditBefore=await creditSnapshot(pools.IDENTITY_RUNTIME);
    const expectedResult=await readOriginalSource({actorId:owner.persona.id,signal});
    const credential={sessionId:owner.credential.sessionId,authorityVersion:owner.credential.authorityVersion};
    let vulnerableCap,fixedCap;
    const args={scope:owner.scope,persona:owner.persona,personaSession:credential,sessionId:owner.sessionId,signal};
    for(const name of ['vuln','fixed']){
      signal.throwIfAborted();const current=await standalone.mode.get(owner.active.context);
      if(current.mode!==name)await standalone.mode.set(owner.active.context,{mode:name,expectedRevision:current.revision});
      const cap=await authority.capture(args);
      if(name==='vuln')vulnerableCap=cap;else{
        fixedCap=cap;
        await assert.rejects(consumptionFor(vulnerableCap,{sessionId:owner.sessionId,role:'customer',callerId:owner.persona.id}).check());
        wire.lifecycle.oldModeRejected=true;
      }
      let packet;
      try{packet=await lifecycle.conversationService.runExclusive(owner.sessionId,owner.scope,owner.persona,()=>capture.runCase({
        name,sessionId:owner.sessionId,actorId:owner.persona.id,capability:cap,provider,pool,manifest,actorCalls,expectedResult,signal,
        scope:owner.scope,persona:owner.persona,conversations:lifecycle.conversationService,conversationRepository:lifecycle.conversations,
        agentsRuntimePool:pools.AGENTS_RUNTIME,promptProfile}));}
      catch(error){if(error.v37Packet){if(sourceArm)error.v37Packet.sourceArm=sourceArm;
        wire.cases.push(error.v37Packet);await persist(wire);}throw error;}
      if(sourceArm)packet.sourceArm=sourceArm;
      wire.cases.push(packet);await persist(wire);
      // A failed actor selection remains a failed observation, never a rerun.
      if(name==='vuln'&&packet.error&&promptProfile==='original')throw Object.assign(Error('Original vulnerable run failed'),{code:packet.error.code||'V37_ORIGINAL_FAILED'});
    }
    if(promptProfile===diagnostic.SOURCE_PROFILE){
      wire.originalOracleObservation=await observeOriginalOracle(wire.cases);
      await persist(wire);
    }
    wire.source.afterPair=await snapshotSource(commerce,seed.actorId,seed.siblingId);
    assert.deepEqual(wire.source.afterPair,wire.source.afterSeed);
    wire.siblingMessagesAfter=await lifecycle.conversationService.getMessages(sibling.sessionId,sibling.scope,sibling.persona);
    assert.deepEqual(wire.siblingMessagesAfter,wire.siblingMessagesBefore);
    wire.lifecycle.siblingUnchanged=true;
    const beforeCalls=actorCalls.length;
    await assert.rejects(lifecycle.conversationService.assertOwned(owner.sessionId,sibling.scope,sibling.persona));
    wire.lifecycle.foreignConversationRejected=true;
    await composition.personaAuth.logout({scope:owner.scope,token:owner.boot.persona.token});
    await assert.rejects(consumptionFor(fixedCap,{sessionId:owner.sessionId,role:'customer',callerId:owner.persona.id}).check());
    wire.lifecycle.revokedPersonaRejected=true;
    assert.equal(actorCalls.length,beforeCalls);wire.lifecycle.boundaryChecksNoModel=true;
    wire.creditAfter=await creditSnapshot(pools.IDENTITY_RUNTIME);assert.deepEqual(wire.creditAfter,wire.creditBefore);
    wire.lifecycle.noAward=true;
    for(const row of wire.cases)require('../fixtures/secureshopCustomerConsumptionAclDiagnostic')
      .validateAclDiagnostic(row.aclDiagnostic,row);
    wire.measurement=promptProfile==='original'?await capture.validatePair(wire.cases):
      await diagnostic.validateDiagnosticPair(wire.cases);
    assert.deepEqual(wire.cases.flatMap(row=>row.spans.flatMap(span=>span.calls)),actorCalls,
      'Physical calls outside the original case spans are not admitted');
    await persist(wire);
  }catch(error){primary=error;wire.error={code:error.code||null,name:error.name};}
  finally{
    wire.actorCalls=structuredClone(actorCalls);
    let stopped=false;
    try{await quiesce();stopped=true;}catch(error){wire.quiescenceError={code:error.code||null,name:error.name};primary??=error;}
    const removable=seed||(seedAttempt?.commitAttempted?seedAttempt:null);
    if(removable&&stopped)try{wire.cleanup=await removeSource(commerce,removable.owned);}
    catch(error){wire.cleanupError={code:error.code||null,name:error.name};primary??=error;}
    try{await persist(wire);}catch(error){primary??=error;}
  }
  if(primary){primary.v37Wire=wire;throw primary;}
  // Host/process/store teardown is owned by the forthcoming closed launcher;
  // this component cannot turn its SQL cleanup into full native acceptance.
  return wire;
}
const TITLE='V37 original customer cart amplification is measured and Fixed consumption is bounded in owned stores';
const DIAGNOSTIC_TITLE='V37 sequential cart request diagnostic retains one genuine vulnerable and Fixed pair without qualification';
const SOURCE_DIAGNOSTIC_TITLE='V37 cart-result-name diagnostic retains an original-request vulnerable and Fixed pair without qualification';
const ROOT=require('node:path').resolve(__dirname,'../..');
const original=require('../fixtures/secureshopDirectInjectionActual');
function admitNative(env=process.env){
  const fs=require('node:fs'),path=require('node:path');
  const diagnostic=require('../fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  const promptProfile=env.SECURESHOP_CONSUMPTION_DIAGNOSTIC===undefined?'original':env.SECURESHOP_CONSUMPTION_DIAGNOSTIC;
  diagnostic.messageFor(promptProfile);
  const sourceArm=env.SECURESHOP_CONSUMPTION_SOURCE_ARM;
  diagnostic.productNameFor(promptProfile,sourceArm);
  assert.equal(fs.realpathSync(process.cwd()),ROOT);assert.equal(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE,ROOT);
  assert.equal(env.SECURESHOP_CONSUMPTION_NATIVE,'1');assert.equal(env.LIVE_OLLAMA_TEST,'1');
  assert.equal(env.AI_PROVIDER,'ollama');assert.equal(env.OLLAMA_MODEL,original.MODEL);
  assert.ok(env.SS_ENFORCE_TOOL_ACL===undefined||env.SS_ENFORCE_TOOL_ACL===''||env.SS_ENFORCE_TOOL_ACL==='false');
  assert.ok(env.OLLAMA_CONTEXT_WINDOW===undefined||env.OLLAMA_CONTEXT_WINDOW===''||env.OLLAMA_CONTEXT_WINDOW===String(capture.CONTEXT_WINDOW));
  assert.equal(env.PLATFORM_DATABASE_ENGINE,'postgres');assert.equal(env.WORKSHOP_DATABASE_ENGINE,'postgres');
  for(const [key,value]of [['SS_AGENT_MAX_STEPS','8'],['SS_AGENT_MAX_PARALLEL_TOOLS','4'],['SS_AGENT_SESSION_TOKEN_BUDGET','100000']])
    assert.ok(env[key]===undefined||env[key]===value,`${key} differs from original limits`);
  const endpoint=original.admitLoopbackEndpoint(env.OLLAMA_BASE_URL,'Actor endpoint');
  assert.equal(endpoint,'http://127.0.0.1:11434/');
  const root=original.admitQualificationRunRoot(env.PG_TEST_ROOT,ROOT);
  const basename=diagnostic.basenameFor(promptProfile,sourceArm);
  const evidence=path.join(root,basename+'-evidence.json'),wire=path.join(root,basename+'-wire.json');
  assert.equal(env.SECURESHOP_CONSUMPTION_EVIDENCE_PATH,evidence);
  for(const file of [evidence,wire])assert.throws(()=>fs.lstatSync(file),error=>error.code==='ENOENT');
  return {root,evidence,wire,promptProfile,sourceArm,urls:disposableUrls(env)};
}
async function assertEndpointClosed(address){
  const url=new URL(address);assert.equal(url.hostname,'127.0.0.1');
  await new Promise((resolve,reject)=>{
    const socket=require('node:net').createConnection({host:'127.0.0.1',port:Number(url.port)});
    socket.setTimeout(1000,()=>{socket.destroy();reject(Error('Owned endpoint closure timed out'));});
    socket.once('connect',()=>{socket.destroy();reject(Error('Owned endpoint still live'));});
    socket.once('error',error=>error.code==='ECONNREFUSED'?resolve():reject(error));
  });
}
async function freePort(){
  const server=require('node:net').createServer();
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}
function assertProcessAbsent(pid){
  assert.ok(Number.isSafeInteger(pid)&&pid>1);let code;
  try{process.kill(pid,0);}catch(error){code=error.code;}
  assert.equal(code,'ESRCH','Owned host absence was not proven');return{pid,errorCode:code};
}
async function quiesceOwned({host,client,transport,wire,state,
  endpointClosed=assertEndpointClosed,processAbsent=assertProcessAbsent}){
  const errors=[];
  // These callbacks are trusted composition/test dependencies, never env,
  // wire fields or request data. A journal cannot authorize any signal.
  try{if(host){await host.stop();assert.equal(host.status,'stopped');
    if(wire.host)wire.hostAbsence=processAbsent(wire.host.pid);
    await endpointClosed(`http://127.0.0.1:${host.port}`);}
    state.hostStopped=true;state.hostEndpointClosed=true;
  }catch(error){errors.push(error);}
  try{if(client)await client.close();state.clientClosed=true;}catch(error){errors.push(error);}
  try{if(transport){await transport.close();await endpointClosed(transport.actorUrl);await endpointClosed(transport.judgeUrl);}
    state.proxyEndpointsClosed=true;}catch(error){errors.push(error);}
  if(errors.length)throw new AggregateError(errors,'Owned V37 execution did not quiesce');
}
function fixtureCleanupComplete(wire,cleanupErrors){
  return cleanupErrors.length===0&&!wire.cleanupError&&!wire.quiescenceError&&
    (!wire.peerTenant||wire.peerTenant.committed===true)&&
    ((!wire.source&&!wire.sourceCreation)||require('node:util').isDeepStrictEqual(wire.cleanup,{shop_users:[],products:[],cart_items:[]}));
}
async function observeOriginalOracle(cases){
  try{return {version:1,accepted:true,originalQualificationAccepted:false,
    measurement:await capture.validatePair(cases),failure:null};}
  catch(error){const bounded=boundedDiagnosticFailure(error,'postflight-replay');
    return {version:1,accepted:false,originalQualificationAccepted:false,
      measurement:null,failure:{name:bounded.name,code:bounded.code}};}
}
async function validateEvidence(wire){
  const diagnostic=require('../fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  const promptProfile=wire.kind==='v37-original-customer-consumption'?'original':
    wire.kind===diagnostic.kindFor(diagnostic.PROFILE)?diagnostic.PROFILE:diagnostic.SOURCE_PROFILE;
  assert.equal(wire.version,promptProfile==='original'?1:2);
  assert.equal(wire.kind,diagnostic.kindFor(promptProfile));
  const expectedName=diagnostic.productNameFor(promptProfile,wire.sourceArm);
  if(promptProfile!=='original'){assert.equal(wire.promptProfile,promptProfile);assert.equal(wire.diagnosticOnly,true);}
  else{
    assert.equal(wire.promptProfile,undefined);
    assert.equal(wire.sourceArm,undefined);
    assert.equal(wire.diagnosticOnly,undefined);
    for(const row of wire.cases){assert.equal(row.promptProfile,undefined);assert.equal(row.sourceArm,undefined);}
  }
  assert.equal(wire.canonicalCredit,false);assert.equal(wire.nativeQualificationAccepted,false);
  const aclRows=require('../../server/data/secureshopAgentSeeds').TOOLS.flatMap(([tool,matrix])=>
    ['customer','merchant','admin'].map(role=>({tool_name:tool,role,allowed:matrix[role]?1:0})))
    .sort((a,b)=>`${a.tool_name}:${a.role}`.localeCompare(`${b.tool_name}:${b.role}`));
  assert.deepEqual(wire.originalAcl,{permissions:aclRows,enforcement:false,cartViewCustomerAllowed:true});
  assertDistinctOwners(wire.owner,wire.sibling);
  assert.equal(wire.peerTenant.committed,true);assert.equal(wire.peerTenant.commitAttempted,true);
  assert.equal(wire.peerTenant.ownerId,wire.sibling.scope.platformOwnerId);
  assert.equal(wire.peerTenant.principalId,wire.sibling.principalId);assert.equal(wire.peerTenant.shopUserId,wire.sibling.persona.id);
  assert.deepEqual(wire.source.afterPair,wire.source.afterSeed);
  assert.equal(wire.source.afterSeed.length,241);assert.deepEqual(wire.source.before,[]);
  assert.equal(wire.source.actorId,wire.owner.persona.id);assert.equal(wire.source.siblingId,wire.sibling.persona.id);
  // runCase records a JSON copy of the launch scope. PostgreSQL supplies
  // expiresAt as a Date; normalize only that serialized field while keeping
  // every authority field in the equality check.
  const recordedOwnerScope={...wire.owner.scope,
    ...(wire.owner.scope.expiresAt instanceof Date?
      {expiresAt:wire.owner.scope.expiresAt.toISOString()}: {})};
  for(const row of wire.cases){assert.deepEqual(row.scope,recordedOwnerScope);assert.equal(row.actorId,wire.owner.persona.id);assert.equal(row.sessionId,wire.owner.sessionId);}
  assert.deepEqual(wire.source.owned.users,[wire.source.actorId,wire.source.siblingId]);
  assert.equal(wire.source.owned.products.length,1);assert.equal(wire.source.product.id,wire.source.owned.products[0]);
  if(promptProfile==='original'||promptProfile===diagnostic.SOURCE_PROFILE)
    assert.equal(wire.source.product.name,expectedName);
  assert.deepEqual(wire.source.afterSeed.map(item=>item.row.id).sort((a,b)=>a-b),[...wire.source.owned.cart].sort((a,b)=>a-b));
  const sourceItems=wire.source.afterSeed.map(item=>item.row).filter(row=>row.user_id===wire.source.actorId);
  assert.equal(sourceItems.length,240);
  assert.equal(wire.source.afterSeed.filter(item=>item.row.user_id===wire.source.siblingId).length,1);
  const result=JSON.parse(wire.cases[0].expectedResult.content[0].text);
  // The private SQL preimage intentionally retains NUMERIC as text. The
  // original commerce adapter normalizes numeric OID 1700 with Number before
  // cart.view returns it; compare that exact projection, not SQL text types.
  assert.equal(typeof wire.source.product.price,'string');
  assert.match(wire.source.product.price,/^-?\d+(?:\.\d+)?$/);
  const productPrice=Number(wire.source.product.price);assert.ok(Number.isFinite(productPrice));
  assert.equal(result.items.length,240);
  for(const item of result.items){
    const source=sourceItems.filter(row=>row.id===item.id);assert.equal(source.length,1);
    assert.equal(item.product_id,wire.source.product.id);assert.equal(item.product_id,source[0].product_id);
    assert.equal(item.quantity,source[0].quantity);assert.equal(item.quantity,1);
    assert.equal(item.name,wire.source.product.name);assert.equal(typeof item.price,'number');assert.equal(item.price,productPrice);
    assert.equal(new Date(item.added_at).getTime(),new Date(source[0].added_at).getTime());
    assert.ok(Number.isFinite(new Date(item.added_at).getTime()));
  }
  assert.equal(new Set(result.items.map(item=>item.id)).size,240);
  assert.equal(result.subtotal,Number((240*Number(wire.source.product.price)).toFixed(2)));
  assert.notEqual(wire.owner.scope.platformOwnerId,wire.sibling.scope.platformOwnerId);
  assert.deepEqual(wire.siblingMessagesAfter,wire.siblingMessagesBefore);
  assert.deepEqual(wire.creditAfter,wire.creditBefore);
  assert.deepEqual(Object.keys(wire.creditBefore).sort(),['assessment_judgments','assessment_completions','assessment_contributions'].sort());
  for(const key of ['oldModeRejected','siblingUnchanged','foreignConversationRejected','revokedPersonaRejected','boundaryChecksNoModel','noAward'])
    assert.equal(wire.lifecycle[key],true,key);
  assert.deepEqual(wire.cleanup,{shop_users:[],products:[],cart_items:[]});
  assert.deepEqual(wire.cases.flatMap(row=>row.spans.flatMap(span=>span.calls)),wire.actorCalls);
  assert.equal(wire.actorCalls.filter(call=>call.kind!=='actor').length,0);
  assert.deepEqual(wire.cleanupErrors,[]);
  assert.deepEqual(wire.runtimeCleanup,{hostStopped:true,hostEndpointClosed:true,proxyEndpointsClosed:true,
    clientClosed:true,featureTransportsClosed:true,auditClosed:true,poolsClosed:true,fileRootRemoved:true});
  assert.equal(wire.hostAbsence?.errorCode,'ESRCH');
  const measured=promptProfile==='original'?await capture.validatePair(wire.cases):
    await diagnostic.validateDiagnosticPair(wire.cases);
  if(promptProfile===diagnostic.SOURCE_PROFILE)
    assert.deepEqual(wire.originalOracleObservation,await observeOriginalOracle(wire.cases));
  else assert.equal(wire.originalOracleObservation,undefined);
  assert.deepEqual(wire.measurement,measured);
  return measured;
}
const SETUP_PHASES=Object.freeze(['pools','migrate','verify-stores','original-acl','auth','progress','audit','files','lifecycle','grading','transport','provider','application','host-start','mcp-connect','manifest','pair']);
function safeSetupDiagnostic(error,phase){
  const fs=require('node:fs'),path=require('node:path'),frames=[];
  // Never retain the message, function names, arguments or non-repository paths.
  const stack=typeof error?.stack==='string'?Buffer.from(error.stack.slice(0,16384),'utf8').subarray(0,16384).toString('utf8'):'';
  for(const line of stack.split('\n').slice(1,65)){
    const match=/^\s+at (?:[^\n]* \()?([^()]+):(\d{1,7}):(\d{1,7})\)?$/.exec(line);
    if(!match)continue;
    const file=match[1];if(!file.startsWith(ROOT+'/'))continue;
    const relative=path.relative(ROOT,file);
    if(!/^(?:server|tests|agent-host|sidecars|db)\/[A-Za-z0-9_./-]+\.(?:js|mjs|cjs)$/.test(relative)||relative.split('/').includes('..'))continue;
    try{if(fs.realpathSync(file)!==file||!fs.statSync(file).isFile())continue;}catch{continue;}
    frames.push({file:relative,line:Number(match[2]),column:Number(match[3])});if(frames.length===8)break;
  }
  return {phase:SETUP_PHASES.includes(phase)?phase:'unknown',frames};
}
function boundedDiagnosticFailure(error,boundary){
  assert.ok(['execution','postflight-replay'].includes(boundary));
  const name=typeof error?.name==='string'&&/^[A-Za-z][A-Za-z0-9]{0,39}Error$/.test(error.name)?error.name:'Error';
  const code=typeof error?.code==='string'&&/^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)?error.code:null;
  return {name,code,boundary,
    frames:safeSetupDiagnostic(error,'pair').frames};
}
async function runNative(){
  const paths=admitNative(),fs=require('node:fs'),path=require('node:path');
  const diagnosticMode=paths.promptProfile!=='original';
  const diagnostic=require('../fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  const status={version:diagnosticMode?2:1,
    kind:diagnostic.kindFor(paths.promptProfile),
    ...(diagnosticMode?{diagnosticOnly:true,promptProfile:paths.promptProfile}:{}),
    ...(paths.sourceArm?{sourceArm:paths.sourceArm}:{}),
    passed:false,canonicalCredit:false,
    nativeQualificationAccepted:false,rendered:false,actualActorCalls:0,actualJudgeCalls:0,
    fixtureCleaned:false,measurement:null,errors:[],cleanupErrors:[],wireSha256:null};
  let wire={version:status.version,kind:status.kind,
    ...(diagnosticMode?{diagnosticOnly:true,promptProfile:paths.promptProfile}:{}),
    ...(paths.sourceArm?{sourceArm:paths.sourceArm}:{}),
    cases:[],actorCalls:[],canonicalCredit:false,nativeQualificationAccepted:false};
  const fd=fs.openSync(paths.wire,'wx',0o600);
  const persist=value=>{
    if(value)wire=value;
    const bytes=Buffer.from(JSON.stringify(wire));assert.ok(bytes.length<=8*1024*1024,'V37 evidence budget exhausted');
    fs.writeSync(fd,bytes,0,bytes.length,0);fs.ftruncateSync(fd,bytes.length);
  };
  const controller=new AbortController(),actorCalls=[],pools={};
  let phase='pools';
  const checkpoint=value=>{assert.ok(SETUP_PHASES.includes(value));phase=value;wire.setupPhase=value;persist();};
  const safeError=error=>({name:error.name,code:error.code||null});
  let transport,host,client,lifecycle,leasePool,fileRoot,primary,closing;
  const runtimeCleanup={hostStopped:false,hostEndpointClosed:false,proxyEndpointsClosed:false,
    clientClosed:false,featureTransportsClosed:false,auditClosed:false,poolsClosed:false,fileRootRemoved:false};
  const quiesce=()=>closing??=quiesceOwned({host,client,transport,wire,state:runtimeCleanup});
  const interrupt=()=>controller.abort(Error('V37 interrupted'));
  process.once('SIGINT',interrupt);process.once('SIGTERM',interrupt);
  // Do not cache a premature "closed" result while setup is still allocating.
  // Active provider I/O receives this signal; cleanup begins after its owner
  // settles, and the outer launcher retains the final process-group deadline.
  const timer=setTimeout(()=>controller.abort(Error('V37 total deadline')),capture.LIMITS.totalMs);
  try{
    checkpoint('pools');
    const postgres=require('../../server/database/postgres');
    const poolEnv={...process.env,PG_POOL_MAX_CONTROL:'8',PG_POOL_MAX_WORKSHOP:'4',PG_POOL_MAX_MIGRATION:'1',PG_POOL_MAX_LEASE:'3',PG_POOL_BUDGET:'60'};
    for(const [key,url]of Object.entries(paths.urls))pools[key]=postgres.createPool({...poolEnv,V37_DATABASE_URL:url},'V37_DATABASE_URL',
      {purpose:key.endsWith('MIGRATION')?'migration':key==='IDENTITY_RUNTIME'?'control':'workshop'});
    leasePool=postgres.createPool({...poolEnv,V37_DATABASE_URL:paths.urls.IDENTITY_RUNTIME},'V37_DATABASE_URL',{purpose:'lease'});
    checkpoint('migrate');
    const setup=require('./secureshopManualRagNativeSetup');await setup.migrateManualRagStores(pools);controller.signal.throwIfAborted();
    checkpoint('verify-stores');
    for(const [key,pool]of Object.entries(pools)){
      const actual=(await pool.query('SELECT current_user AS role,current_database() AS database')).rows[0],url=new URL(paths.urls[key]);
      assert.equal(actual.role,url.username);assert.equal(actual.database,url.pathname.slice(1));
    }
    checkpoint('original-acl');
    const originalAcl=await initializeOriginalAcl({migration:pools.AGENTS_MIGRATION,runtime:pools.AGENTS_RUNTIME});
    wire.originalAcl=originalAcl;persist();
    checkpoint('auth');
    const auth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
      repository:require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:pools.IDENTITY_RUNTIME})});
    checkpoint('progress');
    const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(pools.IDENTITY_RUNTIME);
    checkpoint('audit');
    const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({
      agentsPool:pools.AGENTS_RUNTIME,reviewPool:pools.REVIEW_RUNTIME,includeRunArtifacts:true});
    checkpoint('files');
    fileRoot=fs.mkdtempSync(path.join(paths.root,'v37-files-'));fs.chmodSync(fileRoot,0o700);
    const files=require('../../sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({root:fileRoot,maxReadBytes:1024,maxWriteBytes:1024});
    checkpoint('lifecycle');
    lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
      identityPool:pools.IDENTITY_RUNTIME,agentsPool:pools.AGENTS_RUNTIME,reviewPool:pools.REVIEW_RUNTIME,leasePool,audit,files});
    const judge=async()=>{status.actualJudgeCalls++;throw Error('V37 has no authorized Judge dispatch');};
    checkpoint('grading');
    const {grading,scenes}=await setup.createManualRagGrading({pools,urls:paths.urls,lifecycle,progress,judge});
    checkpoint('transport');
    transport=await require('./secureshopMailActualTransport').createMailActualTransport({protocol:'v37-customer-consumption-v1',maxHttpCalls:6,allowMetadata:true,sharedStages:false,
      record:value=>{assert.equal(value.modelDigest,original.DIGEST);actorCalls.splice(0,actorCalls.length,...structuredClone(value.calls));}});
    assert.equal(transport.model,original.MODEL);assert.equal(transport.digest,original.DIGEST);
    checkpoint('provider');
    const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:transport.actorUrl,model:original.MODEL});
    checkpoint('application');
    const app=await setup.createManualRagApplication({pools,lifecycle,grading,scenes,auth,provider,judge,audit});
    controller.signal.throwIfAborted();
    checkpoint('host-start');
    host=new(require('../../server/services/secureshop/agentHostSupervisor').AgentHostSupervisor)({
      port:await freePort(),restartLimit:0,stopTimeoutMs:8000,env:{...process.env,
        OLLAMA_BASE_URL:transport.actorUrl,SECURESHOP_DATABASE_URL:paths.urls.COMMERCE_RUNTIME,
        SECURESHOP_AGENTS_DATABASE_URL:paths.urls.AGENTS_RUNTIME}});
    await host.start();const hostIdentity={pid:host.proc.pid,instanceId:host.instanceId};
    wire.host=hostIdentity;persist();
    checkpoint('mcp-connect');
    client=new(require('../../server/services/secureshop/mcpClientPool').McpClientPool)({baseUrl:`http://127.0.0.1:${host.port}`});await client.connect();
    checkpoint('manifest');
    const manifest=new(require('../../server/services/secureshop/toolManifest').ToolManifest)(client);await manifest.refresh();
    checkpoint('pair');
    await runCanonicalPair({pools,auth,...app,lifecycle,grading,provider,pool:client,manifest,actorCalls,signal:controller.signal,quiesce,
      promptProfile:paths.promptProfile,sourceArm:paths.sourceArm,
      persist:value=>{value.host=hostIdentity;value.setupPhase=phase;value.originalAcl=originalAcl;persist(value);}});
    assert.equal(status.actualJudgeCalls,0);
  }catch(error){primary=error;status.errors.push(diagnosticMode?
    boundedDiagnosticFailure(error,'execution'):safeError(error));wire.setupDiagnostic=safeSetupDiagnostic(error,phase);}
  finally{
    clearTimeout(timer);controller.abort();
    const cleanup=async(fn,flag)=>{try{await fn();if(flag)runtimeCleanup[flag]=true;}catch(error){status.cleanupErrors.push(safeError(error));}};
    await cleanup(quiesce);
    await cleanup(()=>lifecycle?.closeFeatureTransports?.(),'featureTransportsClosed');
    await cleanup(()=>lifecycle?.auditLedger?.close?.(),'auditClosed');
    await cleanup(async()=>{
      await require('../../server/database/postgres').closePostgresPools();
      const snapshot=require('../../server/database/postgres').getPoolBudgetSnapshot();assert.equal(snapshot.reserved,0);
    },'poolsClosed');
    await cleanup(async()=>{if(fileRoot){const stat=fs.lstatSync(fileRoot);
      assert.ok(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid());
      assert.equal(fs.realpathSync(fileRoot),fileRoot);assert.equal(path.dirname(fileRoot),paths.root);
      assert.match(path.basename(fileRoot),/^v37-files-[A-Za-z0-9]+$/);assert.deepEqual(fs.readdirSync(fileRoot),[]);fs.rmdirSync(fileRoot);}
    },'fileRootRemoved');
    wire.actorCalls=structuredClone(actorCalls);wire.runtimeCleanup=runtimeCleanup;wire.cleanupErrors=status.cleanupErrors;
    status.actualActorCalls=actorCalls.filter(call=>call.kind==='actor').length;
    status.actualJudgeCalls+=actorCalls.filter(call=>call.kind==='judge').length;
    if(!primary&&!status.cleanupErrors.length)try{status.measurement=await validateEvidence(wire);status.passed=true;}
    catch(error){primary=error;status.errors.push(diagnosticMode?
      boundedDiagnosticFailure(error,'postflight-replay'):safeError(error));}
    try{persist();}catch(error){status.passed=false;status.cleanupErrors.push(safeError(error));primary??=error;}
    try{fs.closeSync(fd);status.wireSha256=original.sha(fs.readFileSync(paths.wire));}
    catch(error){status.passed=false;status.cleanupErrors.push(safeError(error));primary??=error;}
    status.fixtureCleaned=fixtureCleanupComplete(wire,status.cleanupErrors);
    try{fs.writeFileSync(paths.evidence,JSON.stringify(status),{flag:'wx',mode:0o600});}
    catch(error){primary??=error;status.passed=false;}
    finally{process.removeListener('SIGINT',interrupt);process.removeListener('SIGTERM',interrupt);}
  }
  if(primary||!status.passed)throw Object.assign(Error(diagnosticMode?
    'V37 prompt diagnostic failed; retained private evidence contains observations':
    'V37 original qualification failed; retained private evidence contains observations'),
    {code:primary?.code||(diagnosticMode?'V37_DIAGNOSTIC_FAILED':'V37_QUALIFICATION_FAILED')});
}
if(require.main===module)require('node:test')(
  process.env.SECURESHOP_CONSUMPTION_DIAGNOSTIC===require('../fixtures/secureshopCustomerConsumptionPromptDiagnostic').SOURCE_PROFILE?
    SOURCE_DIAGNOSTIC_TITLE:process.env.SECURESHOP_CONSUMPTION_DIAGNOSTIC?DIAGNOSTIC_TITLE:TITLE,
  {skip:process.env.SECURESHOP_CONSUMPTION_NATIVE!=='1',
  timeout:capture.LIMITS.totalMs+100000},runNative);
module.exports={TITLE,DIAGNOSTIC_TITLE,SOURCE_DIAGNOSTIC_TITLE,STORES,disposableUrls,snapshotSource,seedSource,readOriginalSource,removeSource,creditSnapshot,
  runCanonicalPair,registrationInput,initializeOriginalAcl,provisionPeerTenant,assertDistinctOwners,admitNative,assertEndpointClosed,quiesceOwned,fixtureCleanupComplete,validateEvidence,observeOriginalOracle,runNative,SETUP_PHASES,safeSetupDiagnostic,boundedDiagnosticFailure};
