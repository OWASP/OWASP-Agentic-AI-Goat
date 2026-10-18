'use strict';
// Model-free qualification: real PostgreSQL ledger + SDK + socket + filesystem.
// The HTTP admission wrapper is controlled, not production capability isolation.
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),http=require('node:http');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createPostgresRunLedger}=require('../../server/agent-runtime/postgresRunLedger');
const {createRunCoordinator}=require('../../server/agent-runtime/runCoordinator');
const {fixture:createTargetFixture}=require('../helpers/mcpProtectedTargetFixture');
const {createMcpProtectedState}=require('../../sidecars/sandbox-runner/mcpProtectedState');
const {createMcpOwnedTargetClient}=require('../../server/services/mcp/ownedTargetClient');
const {McpSandboxShell}=require('../../server/services/mcp/sandboxShell');
const {createMcpServer}=require('../../server/services/mcp/sdk/vulnerableMcpServer');
const {createMcpProtocolSessionManager}=require('../../server/services/mcp/sdk/sessionManager');
const observation=require('../../server/services/mcp/protectedStateObservation');
const canonical=v=>JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a],[b])=>a.localeCompare(b))));
test('protected rotation lost acknowledgement stays uncertain; known rejection and success stay distinct',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_GRAPH_TEST_RUNTIME_URL},async t=>{
 for(const key of ['PG_GRAPH_TEST_MIGRATION_URL','PG_GRAPH_TEST_RUNTIME_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-protected-lostack-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const pool=createPool(process.env,'PG_GRAPH_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_GRAPH_TEST_MIGRATION_URL');t.after(()=>Promise.all([pool.end(),migration.end()]));await initializeIdentityRepository(pool,migration);
 const scope={targetId:crypto.randomUUID(),platformOwnerId:7,platformSessionId:71,generation:0};
 const sibling={...scope,targetId:crypto.randomUUID(),platformOwnerId:8,platformSessionId:81};
 let store=createMcpProtectedState(),commits=0,mode='drop';
 const targetFixture=await createTargetFixture(t);const target=await targetFixture.store.provisionTarget({targetId:scope.targetId,ownerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId,generation:0},{authorize:async()=>true});
 let returnFenceRejected=false;
 for(const binding of [scope,sibling]){const dir=path.join(root,binding.targetId);await fs.mkdir(path.join(dir,'rootfs/opt/app/config'),{recursive:true,mode:0o700});await fs.writeFile(path.join(dir,'control.json'),canonical({version:1,targetId:binding.targetId,ownerId:binding.platformOwnerId,platformSessionId:binding.platformSessionId,generation:0})+'\n',{mode:0o600});await fs.writeFile(path.join(dir,'rootfs/opt/app/config/.env'),'DB_PASSWORD=PUBLIC_SYNTHETIC\n',{mode:0o600});await store.initializeTarget({targetDirectory:dir,scope:binding});}
 const token=crypto.randomBytes(32).toString('base64url'),capability='mcp-target-'+crypto.randomBytes(32).toString('hex');
 const server=http.createServer(async(req,res)=>{try{assert.equal(req.headers.authorization,'Bearer '+token);let raw='';for await(const b of req)raw+=b;const body=JSON.parse(raw);if(req.url==='/owned-targets/admit'){assert.deepEqual(body.scope,scope);res.setHeader('content-type','application/json');res.end(JSON.stringify({version:'mcp-owned-target-http.v1',scope,capability}));return;}assert.equal(req.url,'/owned-targets/protected-operation');assert.equal(body.capability,capability);assert.equal(body.operation,'rotate_keys');if(mode==='authority'){
 try{await targetFixture.store.executeProtectedOperation(target.capability,async binding=>{
   if(binding.phase==='return'){returnFenceRejected=true;return false;}return true;
 },{operation:'rotate_keys',runId:body.runId,arguments:body.arguments});assert.fail('return fence should reject');}
 catch(error){assert.equal(error.code,'TARGET_AUTHORITY_REVOKED');res.statusCode=503;res.setHeader('content-type','application/json');res.end(JSON.stringify({error:error.code,message:error.message}));return;}
 }if(mode==='reject'){res.statusCode=409;res.setHeader('content-type','application/json');res.end(JSON.stringify({error:'TARGET_LOCKED',message:'Owned target already in use'}));return;}const receipt=await store.rotateKeys({targetDirectory:path.join(root,scope.targetId),scope,runId:body.runId,...body.arguments});commits++;if(mode==='drop')req.socket.destroy();else{res.setHeader('content-type','application/json');res.end(JSON.stringify(receipt));}}catch(error){res.statusCode=500;res.end(JSON.stringify({error:error.message}));}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
 const client=createMcpOwnedTargetClient({baseURL:'http://127.0.0.1:'+server.address().port,token});
 let shell;const manager=createMcpProtocolSessionManager({createServer:id=>createMcpServer(id,{sandbox:shell})});t.after(()=>manager.retireSession('mcp_7'));
 const coordinator=()=>createRunCoordinator({family:'MCP',ledger:createPostgresRunLedger(pool)});const a=coordinator();
 const invoke=async execution=>{if(!shell){const admitted=await client.admit({scope,execution});shell=new McpSandboxShell('mcp_7',{runner:admitted.runner});}return manager.callTool('mcp_7','admin_rotate_keys',{}, {execution,surface:'chat',effectKey:'rotation',actor:{labRole:'operator'}});};
 await assert.rejects(a.run(7,{idempotencyKey:'same-request'},invoke),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});
 assert.equal(commits,1);
 const effects=(await pool.query('SELECT status FROM graph_runtime.effects')).rows;assert.deepEqual(effects,[{status:'uncertain'}]);
 
 await assert.rejects(coordinator().run(7,{idempotencyKey:'same-request'},invoke),/already attempted|replay/i);assert.equal(commits,1);
 store=createMcpProtectedState();const current=JSON.parse(await fs.readFile(path.join(root,scope.targetId,'protected-state/current.json'),'utf8'));assert.equal(current.keyVersion,2);
 mode='reject';const rejected=await a.run(7,{idempotencyKey:'known-rejection'},invoke);assert.equal(rejected.errorCode,'PROTECTED_STATE_UNAVAILABLE');assert.equal(commits,1);
 mode='success';const success=await a.run(7,{idempotencyKey:'known-success'},invoke);assert.equal(success.real,true);assert.equal(success.achieved,true);assert.equal(commits,2);
 const statuses=(await pool.query('SELECT status FROM graph_runtime.effects ORDER BY status')).rows.map(x=>x.status);assert.deepEqual(statuses,['completed','completed','uncertain']);
 mode='authority';await assert.rejects(a.run(7,{idempotencyKey:'return-revoked'},invoke),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});assert.equal(returnFenceRejected,true);
 const returnState=()=>fs.readFile(path.join(targetFixture.root,'targets',scope.targetId,'protected-state/current.json'),'utf8').then(JSON.parse);
 assert.equal((await returnState()).keyVersion,2);await assert.rejects(coordinator().run(7,{idempotencyKey:'return-revoked'},invoke),/already attempted|replay/i);assert.equal((await returnState()).keyVersion,2);
 assert.equal((await pool.query("SELECT count(*)::int n FROM graph_runtime.effects WHERE status='uncertain'")).rows[0].n,2);
 const siblingBefore=await fs.readFile(path.join(root,sibling.targetId,'protected-state/current.json'));
 await a.reset(7,async()=>{await fs.rm(path.join(root,scope.targetId),{recursive:true,force:true});});
 assert.deepEqual(await fs.readFile(path.join(root,sibling.targetId,'protected-state/current.json')),siblingBefore);
 t.diagnostic(JSON.stringify({actualModel:false,commits,afterRecoveryKeyVersion:current.keyVersion,effectStatus:effects[0].status,resultCode:'MCP_PROTECTED_OPERATION_UNCERTAIN',replayBlocked:true,actualReturnAuthorityFence:true,returnFenceCommittedKeyVersion:2,siblingPreserved:true,limitation:'controlled HTTP authority; real SDK/socket/state/ledger; not production target retirement qualification'}));
});

test('connected protected journal readback recovers exact committed result without rewriting uncertain ledger',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_GRAPH_TEST_RUNTIME_URL},async t=>{
 const pool=createPool(process.env,'PG_GRAPH_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_GRAPH_TEST_MIGRATION_URL');t.after(()=>Promise.all([pool.end(),migration.end()]));await initializeIdentityRepository(pool,migration);
 const realState=createMcpProtectedState();let faultAfterCommit=false,rotations=0;
 const protectedState={...realState,async rotateKeys(input){const value=await realState.rotateKeys(input);rotations++;if(faultAfterCommit)throw Error('controlled publication loss');return value;}};
 const f=await createTargetFixture(t,{protectedState});
 const binding={targetId:crypto.randomUUID(),ownerId:19,platformSessionId:191,generation:0};
 const scope={targetId:binding.targetId,platformOwnerId:19,platformSessionId:191,generation:0};
 const sibling={...binding,targetId:crypto.randomUUID(),ownerId:20,platformSessionId:201};
 await f.store.provisionTarget(sibling,{authorize:async()=>true});
 const {createOwnedTargetApi}=require('../../sidecars/sandbox-runner/ownedTargetApi');const protocol=require('../../server/services/mcp/protocolContext');
 const token=crypto.randomBytes(32).toString('base64url');
 // Native macOS fixture cannot attest Linux AppArmor/bwrap. Only readiness is
 // controlled; target/API/journal/client/SDK/PG behavior below is production code.
 const api=createOwnedTargetApi({token,store:{...f.store,checkReadiness:async()=>({ready:true})},expectedSupervisorProfile:'dvaia-mcp-sandbox',readSupervisorProfile:async()=> 'dvaia-mcp-sandbox (enforce)'});
 let dropAck=true;const httpServer=http.createServer(async(req,res)=>{let bytes='';for await(const chunk of req)bytes+=chunk;const reply=await api.handle({method:req.method,path:req.url,token:(req.headers.authorization||'').replace(/^Bearer /,''),body:bytes?JSON.parse(bytes):undefined});if(dropAck&&req.url==='/owned-targets/protected-operation'&&reply.body.state==='completed'){dropAck=false;req.socket.destroy();return;}res.statusCode=reply.status;res.setHeader('content-type','application/json');res.end(JSON.stringify(reply.body));});
 await new Promise(r=>httpServer.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{httpServer.closeAllConnections();httpServer.close(r);}));
 const client=createMcpOwnedTargetClient({baseURL:'http://127.0.0.1:'+httpServer.address().port,token});assert.equal((await client.readiness()).protectedJournalCapability,'mcp-owned-protected-operation-journal.v1');
 let shell,runner;const manager=createMcpProtocolSessionManager({createServer:id=>createMcpServer(id,{sandbox:shell})});t.after(()=>manager.retireSession('mcp_19'));
 const coordinator=createRunCoordinator({family:'MCP',ledger:createPostgresRunLedger(pool)});let original,readback;
 await assert.rejects(coordinator.run(19,{idempotencyKey:'journal-lostack'},async execution=>{
  original=execution;runner=(await client.admit({scope,execution})).runner;shell=new McpSandboxShell('mcp_19',{runner});
  const context={sessionId:'mcp_19',execution,surface:'chat',effectKey:'rotation',actor:{labRole:'operator'}};
  try{await manager.callTool('mcp_19','admin_rotate_keys',{},context);assert.fail('must lose ack');}
  catch(error){assert.equal(error.code,'MCP_PROTECTED_OPERATION_UNCERTAIN');
   readback=(await protocol.withProtocolInvocation(context,()=>runner.readProtectedOperation('mcp_19','rotate_keys',{enforceAuthorization:false}))).value;
   assert.equal(readback.state,'completed');assert.equal(readback.result.keyVersionAfter,2);assert.equal(rotations,1);
   const replay=(await protocol.withProtocolInvocation(context,()=>runner.protectedOperation('mcp_19','rotate_keys',{enforceAuthorization:false}))).value;
   assert.deepEqual(replay,readback.result);assert.equal(rotations,1);
   await assert.rejects(protocol.withProtocolInvocation({...context,actor:{labRole:'privileged'}},()=>runner.readProtectedOperation('mcp_19','rotate_keys',{enforceAuthorization:false})),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});
   const second=(await protocol.withProtocolInvocation({...context,effectKey:'rotation-2'},()=>runner.protectedOperation('mcp_19','rotate_keys',{enforceAuthorization:false}))).value;assert.equal(second.keyVersionAfter,3);assert.equal(rotations,2);
   throw error;
  }
 }),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});
 assert.deepEqual((await pool.query('SELECT status FROM graph_runtime.effects WHERE run_id=$1',[original.runId])).rows,[{status:'uncertain'}]);
 faultAfterCommit=true;
 await assert.rejects(coordinator.run(19,{idempotencyKey:'journal-pending'},async execution=>{
  const context={sessionId:'mcp_19',execution,surface:'chat',effectKey:'pending',actor:{labRole:'operator'}};
  try{await manager.callTool('mcp_19','admin_rotate_keys',{},context);assert.fail('must remain pending');}
  catch(error){assert.equal(error.code,'MCP_PROTECTED_OPERATION_UNCERTAIN');
   const pending=(await protocol.withProtocolInvocation(context,()=>runner.readProtectedOperation('mcp_19','rotate_keys',{enforceAuthorization:false}))).value;assert.equal(pending.state,'uncertain');const count=rotations;
   await assert.rejects(protocol.withProtocolInvocation(context,()=>runner.protectedOperation('mcp_19','rotate_keys',{enforceAuthorization:false})),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});assert.equal(rotations,count);throw error;}
 }),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});
 const siblingBefore=await fs.readFile(path.join(f.root,'targets',sibling.targetId,'protected-state/current.json'));
 const receipt=await f.store.retireTarget(binding,{operationId:crypto.randomUUID(),authorize:async()=>true});assert.equal(receipt.status,'completed');
 await assert.rejects(fs.stat(path.join(f.root,'targets',binding.targetId)),{code:'ENOENT'});assert.deepEqual(await fs.readFile(path.join(f.root,'targets',sibling.targetId,'protected-state/current.json')),siblingBefore);
 assert.equal((await pool.query("SELECT count(*)::int n FROM graph_runtime.effects WHERE owner_key=$1 AND status='uncertain'",['["MCP","19"]'])).rows[0].n,2);
 t.diagnostic(JSON.stringify({protectedJournalCapability:'mcp-owned-protected-operation-journal.v1',actualSDK:true,actualSocket:true,completedReadback:true,exactReplay:true,sameRunDistinctEffects:true,pendingNoReexecution:true,centralEffectsRemainUncertain:2,targetRetirementRemovesJournal:true,siblingPreserved:true,rotations,model:false,readiness:'controlled macOS fixture; no Linux AppArmor/bwrap claim'}));
});
