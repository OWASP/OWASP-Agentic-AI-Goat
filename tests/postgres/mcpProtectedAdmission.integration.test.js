'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {Pool}=require('pg');
test('candidate graph/SDK admits immutable intent before real socket under current owned lifecycle',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_MCP_RUNTIME_URL,timeout:60000},async t=>{
 assert.equal(await fs.realpath(process.cwd()),await fs.realpath(path.resolve(__dirname,'../..')));
 const pairs=[['PG_GRAPH_TEST_RUNTIME_URL','PG_GRAPH_TEST_MIGRATION_URL','identity'],['PG_MCP_RUNTIME_URL','PG_MCP_MIGRATION_URL','mcp']];
 const admitted=new Map();let port,nonce;const databases=new Set();
 for(const [runtimeKey,migrationKey,family] of pairs){
  const urls=[new URL(process.env[runtimeKey]),new URL(process.env[migrationKey])];
  for(const [index,url] of urls.entries()){
   assert.equal(url.protocol,'postgresql:');assert.equal(url.hostname,'127.0.0.1');assert.equal(url.password,'');assert.equal(url.search,'');assert.equal(url.hash,'');
   assert.ok(Number(url.port)>0&&Number(url.port)<=65535);if(port===undefined)port=url.port;else assert.equal(url.port,port);
   assert.equal(decodeURIComponent(url.username),`dvaia_${family}_${index===0?'runtime':'migration'}`);
   const match=url.pathname.match(new RegExp(`^/dvaia_test_mcp_protected_${family==='identity'?'identity':'resource'}_([a-f0-9]{12})$`));assert.ok(match);
   if(nonce===undefined)nonce=match[1];else assert.equal(match[1],nonce);
   admitted.set(index===0?runtimeKey:migrationKey,url.href);
  }
  assert.equal(urls[0].pathname,urls[1].pathname);assert.ok(!databases.has(urls[0].pathname));databases.add(urls[0].pathname);
 }
 const pools=[];function pool(key,extra={}){assert.ok(admitted.has(key));const p=new Pool({connectionString:admitted.get(key),...extra});pools.push(p);return p;}
 const identity=pool('PG_GRAPH_TEST_RUNTIME_URL'),migration=pool('PG_GRAPH_TEST_MIGRATION_URL'),resource=pool('PG_MCP_RUNTIME_URL'),resourceMigration=pool('PG_MCP_MIGRATION_URL'),lease=pool('PG_MCP_RUNTIME_URL',{max:2,connectionTimeoutMillis:1000});t.after(()=>Promise.all(pools.map(p=>p.end())));
 const canonical=require('../../db/postgres/migrate'),view=require('../helpers/xssBoundedMigrationView').createXssBoundedMigrationView({identity:96});
 const directory=view.directories.identity,manifest=await canonical.readMigrations(directory);
 const ledger=async()=>(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
 const expected=ceiling=>manifest.filter(row=>Number(row.name.slice(0,4))<=ceiling).map(({name,checksum})=>({name,checksum}));
 assert.deepEqual(await view.initializeIdentityRepository(identity,migration),expected(96).map(row=>row.name));
 const prior=await ledger();assert.deepEqual(prior,expected(96));assert.deepEqual(await view.initializeIdentityRepository(identity,migration),[]);
 view.setCeiling('identity',97);assert.deepEqual(await view.initializeIdentityRepository(identity,migration),['0097_mcp_protected_reconciliation.sql']);
 const stage97=await ledger();assert.deepEqual(stage97,expected(97));assert.deepEqual(stage97.slice(0,prior.length),prior);assert.deepEqual(await view.initializeIdentityRepository(identity,migration),[]);
 // Current repository lifecycle runs only after a separately asserted canonical tail.
 assert.deepEqual(await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity,migration),manifest.filter(row=>Number(row.name.slice(0,4))>97).map(row=>row.name));
 const full=manifest.map(({name,checksum})=>({name,checksum}));assert.deepEqual(await ledger(),full);assert.deepEqual((await ledger()).slice(0,stage97.length),stage97);
 assert.deepEqual(await canonical.migrate(migration,directory),[]);assert.deepEqual(await ledger(),full);
 await require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(resource).initialize(resourceMigration);
 const repo=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),auth=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:repo,jwtSecret:'protected-owned-native-only-signature'});
 async function owner(){const password=await require('bcryptjs').hash('fixture',4);const user=await repo.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:password});const session=await auth.createSession({...user,password},{});return{id:user.id,request:{headers:{authorization:'Bearer '+session.token}}};}
 const a=await owner(),b=await owner();let sockets=0,mode='drop',held,release;
 const realState=require('../../sidecars/sandbox-runner/mcpProtectedState').createMcpProtectedState();let rotations=0;
 const pythonExecutable=process.env.MCP_PROTECTED_PYTHON_EXECUTABLE;
 assert.ok(typeof pythonExecutable==='string'&&path.isAbsolute(pythonExecutable)&&!/[\r\n]/.test(pythonExecutable),'Owned launcher must select an absolute Python executable');
 const f=await require('../helpers/mcpProtectedTargetFixture').fixture(t,{pythonExecutable,protectedState:{...realState,async rotateKeys(input){const v=await realState.rotateKeys(input);rotations++;return v;}}});
 const token=crypto.randomBytes(32).toString('base64url');const api=require('../../sidecars/sandbox-runner/ownedTargetApi').createOwnedTargetApi({token,store:{...f.store,checkReadiness:async()=>({ready:true})},expectedSupervisorProfile:'dvaia-mcp-sandbox',readSupervisorProfile:async()=> 'dvaia-mcp-sandbox (enforce)'});
 let serverFailure;
 const server=http.createServer(async(req,res)=>{try{let bytes='';for await(const c of req)bytes+=c;const body=bytes?JSON.parse(bytes):undefined;
  if(req.url==='/owned-targets/protected-operation'){
   sockets++;const row=(await identity.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE operation_id=$1',[body.operationId])).rows[0];assert.ok(row,'central intent committed BEFORE target dispatch');assert.equal(row.run_id,body.runId);assert.ok(row.ledger_effect_key.endsWith(':'+row.sdk_effect_key));
  }
  const reply=await api.handle({method:req.method,path:req.url,token:(req.headers.authorization||'').replace(/^Bearer /,''),body});
  if(req.url==='/owned-targets/protected-operation'&&mode==='hold'){held();await new Promise(r=>release=r);}
  if(req.url==='/owned-targets/protected-operation'&&mode==='drop'){req.socket.destroy();return;}
  if(req.url==='/owned-targets/protected-operation'&&mode==='timeout')return;
  res.statusCode=reply.status;res.setHeader('content-type','application/json');res.end(JSON.stringify(reply.body));
 }catch(e){serverFailure=e;res.statusCode=500;res.end(JSON.stringify({error:'fixture failure'}));}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
 const client=require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({baseURL:'http://127.0.0.1:'+server.address().port,token,timeoutMs:3000});
 const q=require('../../server/services/mcp/ownedQualification'),qualification=q.createOwnedQualification(true,{protectedStateCapability:q.PROTECTED_STATE_CAPABILITY});
 const app=require('../../server/services/mcp/ownedResourceComposition').createMcpOwnedResourceComposition({validateSession:t=>auth.validateSession(t),resourcePool:resource,identityPool:identity,protectedResourceLeasePool:lease,targets:client,qualification,authorizeTool:q.createOwnedToolAuthorizer(qualification),listMessages:async()=>({ok:true,messages:[]}),deleteMessages:async()=>({ok:true}),sendMail:async()=>{throw Error('unexpected mail');}});
 const resources=require('../../server/database/postgres/mcpResourceRepository').createMcpResourceRepository(resource);
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'MCP',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity),defaultTimeoutMs:15000});let scopeA,scopeB;
 async function run(o,key,{graph=false}={}){return coordinator.run(o.id,{idempotencyKey:key},async execution=>{const admitted=await app.admitChat(o.request,execution);if(o===a)scopeA=admitted.scope;else scopeB=admitted.scope;
  if(!graph)return admitted.protocol.callTool('mcp_'+o.id,'admin_rotate_keys',{}, {execution:admitted.execution,surface:'inspector',effectKey:'manual_rotate'});
  return require('../../server/agent-runtime/mcpWorkshopGraph').runMcpWorkshopGraph({message:'Rotate the synthetic key',sandbox:admitted.sandbox},{execution:admitted.execution,model:{provider:'controlled-native',chatWithTools:async()=>({content:JSON.stringify({tool:'admin_rotate_keys',params:{}}),provider:'controlled-native',model:'fixture-no-llm'})},listTools:()=>admitted.protocol.listTools('mcp_'+o.id,{execution:admitted.execution,surface:'chat'}),detectIntent:()=>{throw Error('scripted dispatch not allowed');},resolveInjectionIntent:async()=>null,executeTool:(tool,args,s,opts)=>admitted.protocol.callTool('mcp_'+o.id,tool,args,{...opts,execution:admitted.execution,surface:'chat'}),detectObjectives:()=>[],phraseReply:async()=>'',phraseRecon:async()=>'',formatCatalog:()=>''});
 });}
 await assert.rejects(run(a,'graph-lostack',{graph:true}),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});if(serverFailure)throw serverFailure;
 assert.equal(rotations,1);let intent=(await identity.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1',[a.id])).rows[0];assert.equal(intent.origin,'controlled');assert.equal(intent.decision_digest,null);assert.equal(intent.ledger_effect_key,'graph-lostack:mcp_tool_0_admin_rotate_keys');assert.equal((await identity.query('SELECT status FROM graph_runtime.effects WHERE run_id=$1',[intent.run_id])).rows[0].status,'uncertain');
 await assert.rejects(run(a,'graph-lostack',{graph:true}),/already attempted|replay/i);assert.equal(rotations,1);
 mode='success';await run(b,'manual-success');assert.equal((await identity.query('SELECT origin FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1',[b.id])).rows[0].origin,'manual');
 const sibling=await fs.readFile(path.join(f.root,'targets',scopeB.targetId,'protected-state/current.json'));
 // Hold an acknowledged effect while canonical reset fences generation. Reset
 // waits for the run/row lease; cancellation rejects publication after draining.
 mode='hold';const reached=new Promise(r=>held=r);const running=run(a,'reset-race',{graph:true});const settled=running.then(()=>({ok:true}),error=>({error}));await reached;
 const resetting=coordinator.reset(a.id,execution=>app.reset(a.request,{check:()=>execution.check()}));release();const outcome=await settled;assert.ok(outcome.error);await resetting;
 await resources.assertOwnerResourcesRetired({platformOwnerId:a.id});await assert.rejects(fs.stat(path.join(f.root,'targets',scopeA.targetId)),{code:'ENOENT'});assert.deepEqual(await fs.readFile(path.join(f.root,'targets',scopeB.targetId,'protected-state/current.json')),sibling);
 mode='timeout';const started=Date.now();await assert.rejects(run(b,'timeout-race'),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});assert.ok(Date.now()-started<7000);assert.equal(lease.totalCount-lease.idleCount,0);
 assert.equal((await identity.query("SELECT status FROM graph_runtime.effects WHERE effect_key='timeout-race:manual_rotate'")).rows[0].status,'uncertain');
 // Revocation during the network turn must not publish success; immutable
 // effect/intent remain available to future explicit reconciliation.
 mode='hold';const ready=new Promise(r=>held=r);const revoking=run(b,'revocation-race');const revokedOutcome=revoking.then(()=>({ok:true}),error=>({error}));await ready;await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE user_id=$1',[b.id]);release();assert.ok((await revokedOutcome).error);
 assert.equal((await identity.query("SELECT status FROM graph_runtime.effects WHERE effect_key='revocation-race:manual_rotate'")).rows[0].status,'uncertain');
 await app.retireOwner({platformOwnerId:b.id,check:async()=>{}});await resources.assertOwnerResourcesRetired({platformOwnerId:b.id});assert.equal(lease.totalCount-lease.idleCount,0);if(serverFailure)throw serverFailure;
 t.diagnostic(JSON.stringify({intentBeforeSocket:true,actualGraph:true,actualSDK:true,actualSocket:true,actualResourceRepository:true,actualJWT:true,controlledModel:true,actualModel:false,lostAckUncertain:true,resetDrained:true,timeoutBoundedAndLeaseReleased:true,revocationUncertain:true,manualOrigin:true,siblingPreserved:true,rotations,sockets,leaseActive:0,limitation:'macOS controlled Linux readiness fixture; candidate not installed'}));
});
