'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {Pool}=require('pg');
test('fresh recovery process reads exact original durable receipt under current real lifecycle without effect replay',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_MCP_RUNTIME_URL,timeout:60000},async t=>{
 const pools=[];function pool(key,extra={}){const url=process.env[key];assert.match(new URL(url).pathname,/^\/dvaia_test_/);const p=new Pool({connectionString:url,...extra});pools.push(p);return p;}
 const identity=pool('PG_GRAPH_TEST_RUNTIME_URL'),migration=pool('PG_GRAPH_TEST_MIGRATION_URL'),resource=pool('PG_MCP_RUNTIME_URL'),resourceMigration=pool('PG_MCP_MIGRATION_URL'),lease=pool('PG_MCP_RUNTIME_URL',{max:2,connectionTimeoutMillis:1000});t.after(()=>Promise.all(pools.map(p=>p.end())));
 await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity,migration);await require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(resource).initialize(resourceMigration);
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'protected-admission-migration-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));await fs.cp('db/postgres/identity-migrations',dir,{recursive:true});await fs.copyFile('docs/modernization/drafts/mcp-protected-recovery/protected_reconciliation.candidate.sql',path.join(dir,'0097_mcp_protected_reconciliation.sql'));await require('../../db/postgres/migrate').migrate(migration,dir);
 const repo=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),auth=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:repo,jwtSecret:'protected-owned-native-only-signature'});
 async function owner(){const password=await require('bcryptjs').hash('fixture',4);const user=await repo.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:password});const session=await auth.createSession({...user,password},{});return{id:user.id,request:{headers:{authorization:'Bearer '+session.token}}};}
 const a=await owner(),b=await owner();let sockets=0,mode='drop',held,release;
 const realState=require('../../sidecars/sandbox-runner/mcpProtectedState').createMcpProtectedState();let rotations=0;
 const f=await require('../helpers/mcpProtectedTargetFixture').fixture(t,{protectedState:{...realState,async rotateKeys(input){const v=await realState.rotateKeys(input);rotations++;return v;}}});
 const token=crypto.randomBytes(32).toString('base64url');const api=require('../../sidecars/sandbox-runner/ownedTargetApi').createOwnedTargetApi({token,store:{...f.store,checkReadiness:async()=>({ready:true})},expectedSupervisorProfile:'dvaia-mcp-sandbox',readSupervisorProfile:async()=> 'dvaia-mcp-sandbox (enforce)'});
 let serverFailure;
 const server=http.createServer(async(req,res)=>{try{let bytes='';for await(const c of req)bytes+=c;const body=bytes?JSON.parse(bytes):undefined;
  if(req.url==='/owned-targets/protected-operation'){
   sockets++;const row=(await identity.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE operation_id=$1',[body.operationId])).rows[0];assert.ok(row,'central intent committed BEFORE target dispatch');assert.equal(row.run_id,body.runId);assert.ok(row.ledger_effect_key.endsWith(':'+row.sdk_effect_key));
  }
  const reply=await api.handle({method:req.method,path:req.url,token:(req.headers.authorization||'').replace(/^Bearer /,''),body});
  if(req.url==='/owned-targets/protected-receipt'&&mode==='receipt-conflict'&&reply.body.state==='completed'){const value={...reply.body.result,keyVersionBefore:20,keyVersionAfter:21};delete value.receiptSha256;reply.body={...reply.body,result:{...value,receiptSha256:require('../../server/services/mcp/protocolContext').canonicalDigest(value)}};}
  if(req.url==='/owned-targets/protected-operation'&&mode==='hold'){held();await new Promise(r=>release=r);}
  if(req.url==='/owned-targets/protected-operation'&&mode==='drop'){req.socket.destroy();return;}
  if(req.url==='/owned-targets/protected-operation'&&mode==='timeout')return;
  res.statusCode=reply.status;res.setHeader('content-type','application/json');res.end(JSON.stringify(reply.body));
 }catch(e){serverFailure=e;res.statusCode=500;res.end(JSON.stringify({error:'fixture failure'}));}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
 async function recover(o,operationId,body){
  const child=require('node:child_process').fork(path.resolve('tests/fixtures/mcpProtectedRecoveryChild.js'),[],{execPath:process.execPath,stdio:['ignore','ignore','pipe','ipc'],env:process.env});
  let received;const result=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('recovery child timeout'));},10000);child.on('message',v=>received=v);child.once('error',reject);child.once('exit',code=>{clearTimeout(timer);if(code!==0||!received)reject(Error('recovery child exited '+code));else resolve(received);});child.send({operationId,body,authorization:o.request.headers.authorization,baseURL:'http://127.0.0.1:'+server.address().port,privateToken:token});});
  return result;
 }
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
 mode='success';if(process.env.PROTECTED_FULL_APP==='1'){const rendered=await require('../fixtures/mcpProtectedRecoveryFullApp').qualifyProtectedRecoveryFullApp({identity,migration,auth,identityRepository:repo,targets:client,owner:a,sibling:b,intent,runtimeRoot:process.env.PROTECTED_RENDER_ROOT});t.diagnostic(JSON.stringify(rendered));}
 const recovered=await recover(a,intent.operation_id);assert.equal(recovered.ok,true,JSON.stringify(recovered));assert.equal(recovered.result.outcome,'completed');assert.equal(recovered.result.creditGranted,false);assert.equal(recovered.result.originalEffectStatus,'uncertain');assert.equal(recovered.result.origin,'controlled');
 assert.deepEqual(await recover(a,intent.operation_id),recovered);
 assert.equal((await recover(a,intent.operation_id,{operationId:intent.operation_id,ownerId:a.id})).status,400);
 assert.equal((await recover({...a,request:{headers:{authorization:'Bearer invalid'}}},intent.operation_id)).status,401);
 assert.ok(!('targetId' in recovered.result));assert.ok(!('runId' in recovered.result));assert.ok(!('result' in recovered.result));assert.equal(rotations,1);assert.equal(sockets,1);
 const authUser=(await migration.query('SELECT * FROM identity.users WHERE id=$1',[a.id])).rows[0];const otherSession=await auth.createSession(authUser,{});assert.equal((await recover({id:a.id,request:{headers:{authorization:'Bearer '+otherSession.token}}},intent.operation_id)).status,404);
 const foreign=await recover(b,intent.operation_id);assert.equal(foreign.ok,false);assert.equal(foreign.code,'PROTECTED_OPERATION_UNAVAILABLE');
 mode='receipt-conflict';const conflict=await recover(a,intent.operation_id);assert.equal(conflict.ok,false);assert.equal(conflict.code,'MCP_PROTECTED_RECOVERY_UNAVAILABLE');assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_conversations.mcp_protected_reconciliations WHERE operation_id=$1',[intent.operation_id])).rows[0].n,1);
 assert.equal((await identity.query('SELECT status FROM graph_runtime.effects WHERE run_id=$1',[intent.run_id])).rows[0].status,'uncertain');
 
 mode='success';await run(b,'manual-success');assert.equal((await identity.query('SELECT origin FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1',[b.id])).rows[0].origin,'manual');
 const sibling=await fs.readFile(path.join(f.root,'targets',scopeB.targetId,'protected-state/current.json'));
 // Hold an acknowledged effect while canonical reset fences generation. Reset
 // waits for the run/row lease; cancellation rejects publication after draining.
 mode='hold';const reached=new Promise(r=>held=r);const running=run(a,'reset-race',{graph:true});const settled=running.then(()=>({ok:true}),error=>({error}));await reached;
 const resetting=coordinator.reset(a.id,execution=>app.reset(a.request,{check:()=>execution.check()}));release();const outcome=await settled;assert.ok(outcome.error);await resetting;
 assert.equal((await recover(a,intent.operation_id)).ok,false);await resources.assertOwnerResourcesRetired({platformOwnerId:a.id});await assert.rejects(fs.stat(path.join(f.root,'targets',scopeA.targetId)),{code:'ENOENT'});assert.deepEqual(await fs.readFile(path.join(f.root,'targets',scopeB.targetId,'protected-state/current.json')),sibling);
 mode='timeout';const started=Date.now();await assert.rejects(run(b,'timeout-race'),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});assert.ok(Date.now()-started<7000);assert.equal(lease.totalCount-lease.idleCount,0);
 assert.equal((await identity.query("SELECT status FROM graph_runtime.effects WHERE effect_key='timeout-race:manual_rotate'")).rows[0].status,'uncertain');
 // Revocation during the network turn must not publish success; immutable
 // effect/intent remain available to future explicit reconciliation.
 mode='hold';const ready=new Promise(r=>held=r);const revoking=run(b,'revocation-race');const revokedOutcome=revoking.then(()=>({ok:true}),error=>({error}));await ready;await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE user_id=$1',[b.id]);release();assert.ok((await revokedOutcome).error);
 assert.equal((await identity.query("SELECT status FROM graph_runtime.effects WHERE effect_key='revocation-race:manual_rotate'")).rows[0].status,'uncertain');
 const revokedIntent=(await identity.query("SELECT operation_id FROM workshop_conversations.mcp_protected_intents WHERE ledger_effect_key='revocation-race:manual_rotate'")).rows[0];assert.equal((await recover(b,revokedIntent.operation_id)).ok,false);
 await app.retireOwner({platformOwnerId:b.id,check:async()=>{}});await resources.assertOwnerResourcesRetired({platformOwnerId:b.id});assert.equal(lease.totalCount-lease.idleCount,0);if(serverFailure)throw serverFailure;
 t.diagnostic(JSON.stringify({mountedAuthenticatedHandler:true,forgedBodyRejected:true,invalidJwtDenied:true,metadataOnly:true,freshCallerProcess:true,exactCompletedReadback:true,appendOnlyReconciliation:true,foreignDenied:true,sameOwnerDifferentSessionDenied:true,conflictingReceiptDenied:true,postResetReadbackDenied:true,revokedReadbackDenied:true,intentBeforeSocket:true,actualGraph:true,actualSDK:true,actualSocket:true,actualResourceRepository:true,actualJWT:true,controlledModel:true,actualModel:false,lostAckUncertain:true,resetDrained:true,timeoutBoundedAndLeaseReleased:true,revocationUncertain:true,manualOrigin:true,siblingPreserved:true,rotations,sockets,leaseActive:0,limitation:'macOS controlled Linux readiness fixture; candidate not installed'}));
});
