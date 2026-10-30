'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const STORES = ['IDENTITY', 'FRESH', 'REVIEW', 'COMMERCE'];
const WORKSHOP = 'secureshop_agent_security';
const enabled = process.env.PERSONA_ASSEMBLED_EXTERNAL_ACTUAL === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && STORES.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`PERSONA_${store}_${role}_URL`]));

function checked(store, role) {
  const value = new URL(process.env[`PERSONA_${store}_${role}_URL`]);
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname,
    /^\/owasp_ai_goat_test_persona_[a-f0-9]+_(commerce|fresh|review|identity|identityfresh)$/);
  return value.href;
}

test('assembled MCP and SSRF actual actor and Judge retain startup persona authority', {
  skip: !enabled,
  timeout: 600000,
}, async t => {
  const workspace = fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || '');
  assert.equal(fs.realpathSync(process.cwd()), workspace);
  const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const pool = new Pool({ connectionString: checked(store, role), max: 3,
      statement_timeout: 10000, application_name: `assembled-core-${store.toLowerCase()}-${role.toLowerCase()}` });
    return [`${store}_${role}`, pool];
  })));
  const leasePool = new Pool({ connectionString: checked('IDENTITY', 'RUNTIME'), max: 3,
    statement_timeout: 10000, application_name: 'assembled-core-leases' });
  t.after(async () => {
    const settled = await Promise.allSettled([...Object.values(pools), leasePool].map(pool => pool.end()));
    const failures = settled.filter(row => row.status === 'rejected').map(row => row.reason);
    if (failures.length) throw new AggregateError(failures, 'assembled-core pool shutdown failed');
  });

  const { migrate } = require('../../db/postgres/migrate');
  await migrate(pools.IDENTITY_MIGRATION, path.join(workspace, 'db/postgres/identity-migrations'));
  await migrate(pools.FRESH_MIGRATION,
    path.join(workspace, 'db/postgres/workshop-migrations/secureshop_agents'));
  await migrate(pools.REVIEW_MIGRATION,
    path.join(workspace, 'db/postgres/workshop-migrations/secureshop_review'));
  await migrate(pools.COMMERCE_MIGRATION,
    path.join(workspace, 'db/postgres/workshop-migrations/secureshop'));
  await require('../../server/database/postgres/workshopPlatformSeed')
    .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
  const seedClient = await pools.COMMERCE_MIGRATION.connect();
  await seedClient.query('BEGIN');
  try {
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
    await seedClient.query('COMMIT');
  } catch (error) {
    await seedClient.query('ROLLBACK');
    throw error;
  } finally { seedClient.release(); }

  const evidence={status:'running',actorRequests:0,judgeRequests:0,cases:[]};
  const evidenceFile=path.join(path.dirname(process.cwd()),'persona-assembled-external-actual-result.json');
  const save=()=>fs.writeFileSync(evidenceFile,JSON.stringify(evidence,null,2),{mode:0o600});save();
 const http=require('node:http'),sockets=new Set(),upstreams=new Set();
 assert.equal(process.env.OLLAMA_BASE_URL,'http://127.0.0.1:11434');assert.equal(process.env.OLLAMA_MODEL,'llama3.1:8b');
 // Transparent bounded actor transport; actual worker/provider and model qualification are unchanged.
 const proxy=http.createServer((req,res)=>{if(req.method!=='POST'||!['/api/chat','/api/generate'].includes(req.url)||++evidence.actorRequests>32){res.writeHead(503);res.end();save();return;}save();
  let bytes=0;req.on('data',chunk=>{bytes+=chunk.length;if(bytes>2*1024*1024){req.destroy();}});
  let wallTimer;const upstream=http.request({hostname:'127.0.0.1',port:11434,path:req.url,method:'POST',headers:{'content-type':'application/json'},timeout:60000},response=>{res.writeHead(response.statusCode,{'content-type':response.headers['content-type']||'application/json'});response.pipe(res);});upstreams.add(upstream);wallTimer=setTimeout(()=>upstream.destroy(Error('Actor hard wall deadline')),60000);upstream.on('close',()=>{clearTimeout(wallTimer);upstreams.delete(upstream);});upstream.on('timeout',()=>upstream.destroy(Error('Actor transport deadline')));upstream.on('error',()=>{if(!res.headersSent)res.writeHead(503);res.end();});res.on('close',()=>upstream.destroy());req.pipe(upstream);
 });proxy.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});await new Promise(resolve=>proxy.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const req of upstreams)req.destroy();for(const socket of sockets)socket.destroy();await new Promise(resolve=>proxy.close(resolve));});
 const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL});
 const boundedModel={...model,async chat(messages,tools,options={}){if(++evidence.judgeRequests>12)throw Error('Judge attempt budget exceeded');save();return model.chat(messages,tools,{...options,signal:options.signal?AbortSignal.any([options.signal,AbortSignal.timeout(60000)]):AbortSignal.timeout(60000)});}};
 const actualJudge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:boundedModel});let initialTransportFault=false;
 const judge=async packet=>{if(packet.rubric.objectiveId==='ss_controlled_ssrf'&&initialTransportFault)throw Object.assign(Error('Explicit initial Judge transport-failure fixture'),{code:'ECONNRESET'});return actualJudge(packet);};

  const identity=pools.IDENTITY_RUNTIME, agents=pools.FRESH_RUNTIME;
  const {createSecureShopCleanupComposition,createDefaultMcpTrustBundle}=require('../../server/services/secureshopCleanupComposition');
  const {createSecureShopSsrfRepositoryBundle}=require('../../server/services/secureshopSsrfProduction');
  const root=fs.mkdtempSync(path.join(workspace,'assembled-external-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  // Target factories create per-target children, never the configured parent.
  for (const name of ['mcp','ssrf']) fs.mkdirSync(path.join(root,name),{mode:0o700});
  const resetComposition=createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,
    reviewPool:pools.REVIEW_RUNTIME,leasePool,mcpTrustFactory:createDefaultMcpTrustBundle,
    mcpTrustFixtureRoot:path.join(root,'mcp'),ssrfFactory:createSecureShopSsrfRepositoryBundle,ssrfFixtureRoot:path.join(root,'ssrf')});
  t.after(async()=>{await resetComposition.closeFeatureTransports();});
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool});
  const gradingBootstrap=await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({
    identityPool:identity,agentsPool:agents,progress,resetComposition,judge:actualJudge,
    expectedIdentityDatabase:new URL(checked('IDENTITY','RUNTIME')).pathname.slice(1),
    expectedAgentsDatabase:new URL(checked('FRESH','RUNTIME')).pathname.slice(1),
    coordinatorFactory:family=>require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family,ledger})});
  const [{Client},{InMemoryTransport}]=await Promise.all([import('@modelcontextprotocol/sdk/client/index.js'),import('@modelcontextprotocol/sdk/inMemory.js')]);
  // The actual summarizer also imports its commerce tools. Bind that eager
  // singleton only to this disposable commerce store, with an explicit one-slot
  // budget, even though this cohort invokes only the owned HTTP tool.
  process.env.SECURESHOP_DATABASE_URL=checked('COMMERCE','RUNTIME');
  process.env.PG_POOL_MAX_WORKSHOP='1';
  process.env.PG_POOL_BUDGET='1';
  t.after(()=>require('../../server/database/postgres/secureshopPools').closeSecureShopPools());
  const server=require('../../agent-host/agents/summarizer/server').createServer();
  const client=new Client({name:'assembled-owned-summarizer',version:'1'}),[a,b]=InMemoryTransport.createLinkedPair();
  await server.connect(b);await client.connect(a);t.after(async()=>{await client.close();await server.close();});
  const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:`http://127.0.0.1:${proxy.address().port}`,model:'llama3.1:8b'});
  const composition=require('../../server/services/secureshopBoundReviewComposition').createSecureShopBoundReviewComposition({
    identityPool:identity,agentsPool:agents,reviewPool:pools.REVIEW_RUNTIME,commercePool:pools.COMMERCE_RUNTIME,
    leasePool,gradingBootstrap,resetComposition,judge,mcpTrustFeature:true,ssrfFeature:true,
    agentRuntime:{provider,pool:{callTool:(_agent,tool,args)=>client.callTool({name:tool,arguments:args})}},
    jwtSecret:'owned-assembled-external-secret-at-least-32-bytes',
    reviewCardRenderer:{sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64),async renderReviewCard(){throw Error('Browser outside scope');}},
    browserQualification:{async qualify(){throw Error('Browser outside scope');},async close(){}}});
  t.after(()=>composition.closeBrowserAssessment());
  await composition.repositories.personas.ensureTemplates();
  await pools.IDENTITY_MIGRATION.query("UPDATE workshop_platform.exercises SET catalog_active=true,is_visible=true WHERE workshop_key=$1",[WORKSHOP]);
  await pools.IDENTITY_MIGRATION.query("UPDATE workshop_platform.objectives SET catalog_active=true,is_enabled=true WHERE workshop_key=$1",[WORKSHOP]);
  const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
  const createOwner=async()=>{const passwordHash=await bcrypt.hash('owned-only',4),id=randomUUID();
    const user=await users.createUser({username:'assembled-'+id.slice(0,8),email:id+'@example.invalid',passwordHash});
    const expiresAt=new Date(Date.now()+1200000).toISOString(),session=await users.createSession({userId:user.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});
    const issued=await composition.launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});
    const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);
    const login=await composition.personaAuth.login({scope,username:'student_admin',password:'student123'});
    const verified=await composition.personaAuth.authenticateBoundToken({scope,token:login.token});
    return{scope,persona:login.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};
  try{
    const owner=await createOwner(),sibling=await createOwner();initialTransportFault=true;
    await require('../fixtures/secureshopAssembledExternalGrading').qualifyAssembledExternalGrading({composition,gradingBootstrap,identityPool:identity,owner,sibling,
      beforeCalls:()=>[evidence.actorRequests,evidence.judgeRequests],
      revoke:value=>composition.repositories.personas.revokeOwnedSession({scope:value.scope,shopUserId:value.persona.id,sessionId:value.personaSession.sessionId}),
      save:(cases,retry)=>{evidence.cases=cases;evidence.retry=retry;save();}});
    evidence.status='passed';save();
  }catch(error){evidence.status='failed';evidence.error={name:error.name,code:error.code,message:error.message};
    evidence.causes=[];for(let cause=error.cause;cause&&evidence.causes.length<4;cause=cause.cause){evidence.causes.push({name:String(cause.name||'Error').slice(0,80),code:typeof cause.code==='string'?cause.code.slice(0,80):null,syscall:typeof cause.syscall==='string'?cause.syscall.slice(0,80):null});}
    save();throw error;}
});
