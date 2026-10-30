'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {createSqlReturnSuppression}=require('../helpers/mcpSqlReturnSuppression');
function createTargetDiagnostics(t){
 const state={requests:0,lastPhase:'not-started',lastStatus:null,serverFailed:false};
 t.after(()=>t.diagnostic(JSON.stringify({targetDiagnostics:state,clientTimeoutMs:3000})));
 return Object.freeze({received(){state.requests=Math.min(1000,state.requests+1);state.lastPhase='request-received';},pending(){state.lastPhase='api-pending';},returned(status){state.lastPhase='api-returned';state.lastStatus=Number.isInteger(status)&&status>=100&&status<=599?status:null;},failed(){state.serverFailed=true;state.lastPhase='server-exception';}});
}
module.exports={createTargetDiagnostics};
test('central SQL post-success return suppression preserves unavailable or uncertain outcomes without target replay',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||process.env.PG_MCP_CENTRAL_ACK!=='yes',timeout:120000},async t=>{
 const {environment,driver:{Pool}}=require('../helpers/mcpCentralSqlAdmission').admitCentralSql(process.env,()=>require('pg'));
 const pythonExecutable=process.env.MCP_FIXTURE_PYTHON;assert.ok(typeof pythonExecutable==='string'&&path.isAbsolute(pythonExecutable));assert.match(process.env.MCP_FIXTURE_PYTHON_SHA256||'',/^[a-f0-9]{64}$/);assert.equal(crypto.createHash('sha256').update(await fs.readFile(pythonExecutable)).digest('hex'),process.env.MCP_FIXTURE_PYTHON_SHA256);
 const pools=[];function pool(key,extra={}){const url=environment[key];assert.match(new URL(url).pathname,/^\/owasp_ai_goat_test_/);const p=new Pool({connectionString:url,max:4,connectionTimeoutMillis:5000,query_timeout:5000,...extra});pools.push(p);return p;}
 const identity=pool('PG_GRAPH_TEST_RUNTIME_URL'),migration=pool('PG_GRAPH_TEST_MIGRATION_URL'),resource=pool('PG_MCP_RUNTIME_URL'),resourceMigration=pool('PG_MCP_MIGRATION_URL'),lease=pool('PG_MCP_RUNTIME_URL',{max:2,connectionTimeoutMillis:1000});t.after(async()=>{let timer;try{const outcomes=await Promise.race([Promise.allSettled(pools.map(p=>p.end())),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Pool cleanup deadline')),30000);})]);assert.ok(outcomes.every(x=>x.status==='fulfilled'));}finally{clearTimeout(timer);}});
 await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity,migration);await require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(resource).initialize(resourceMigration);
 const repo=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),auth=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:repo,jwtSecret:'protected-owned-native-only-signature'});
 async function owner(){const password=await require('bcryptjs').hash('fixture',4);const user=await repo.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:password});const session=await auth.createSession({...user,password},{});return{id:user.id,request:{headers:{authorization:'Bearer '+session.token}}};}
 const a=await owner(),b=await owner();let sockets=0,mode='drop',held,release;
 const realState=require('../../sidecars/sandbox-runner/mcpProtectedState').createMcpProtectedState();let rotations=0;
 const f=await require('../helpers/mcpProtectedTargetFixture').fixture(t,{pythonExecutable,protectedState:{...realState,async rotateKeys(input){const v=await realState.rotateKeys(input);rotations++;return v;}}});
 const token=crypto.randomBytes(32).toString('base64url');const api=require('../../sidecars/sandbox-runner/ownedTargetApi').createOwnedTargetApi({token,store:{...f.store,checkReadiness:async()=>({ready:true})},expectedSupervisorProfile:'owasp-ai-goat-mcp-sandbox',readSupervisorProfile:async()=> 'owasp-ai-goat-mcp-sandbox (enforce)'});
 let serverFailure,receiptReads=0;const diagnostics=createTargetDiagnostics(t);

 const server=http.createServer(async(req,res)=>{diagnostics.received();try{let bytes='';for await(const c of req)bytes+=c;const body=bytes?JSON.parse(bytes):undefined;
  if(req.url==='/owned-targets/protected-operation'){
   sockets++;const row=(await identity.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE operation_id=$1',[body.operationId])).rows[0];assert.ok(row,'central intent committed BEFORE target dispatch');assert.equal(row.run_id,body.runId);assert.ok(row.ledger_effect_key.endsWith(':'+row.sdk_effect_key));
  }
  if(req.url==='/owned-targets/protected-receipt')receiptReads++;
  diagnostics.pending();const reply=await api.handle({method:req.method,path:req.url,token:(req.headers.authorization||'').replace(/^Bearer /,''),body});
  diagnostics.returned(reply.status);
  if(req.url==='/owned-targets/protected-operation'&&mode==='hold'){held();await new Promise(r=>release=r);}
  if(req.url==='/owned-targets/protected-operation'&&mode==='drop'){req.socket.destroy();return;}
  if(req.url==='/owned-targets/protected-operation'&&mode==='timeout')return;
  res.statusCode=reply.status;res.setHeader('content-type','application/json');res.end(JSON.stringify(reply.body));
 }catch(e){diagnostics.failed();serverFailure=e;res.statusCode=500;res.end(JSON.stringify({error:'fixture failure'}));}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
 const client=require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({baseURL:'http://127.0.0.1:'+server.address().port,token,timeoutMs:3000});
 const q=require('../../server/services/mcp/ownedQualification'),qualification=q.createOwnedQualification(true,{protectedStateCapability:q.PROTECTED_STATE_CAPABILITY});
 const admissionSql='SELECT workshop_conversations.admit_mcp_protected($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS value';
 const admissionLoss=createSqlReturnSuppression(admissionSql);
 const admissionPool=new Proxy(identity,{get(target,key){if(key==='query')return admissionQuery;const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value;}});
 const admissionQuery=admissionLoss.wrapQuery(identity.query.bind(identity));
 const app=require('../../server/services/mcp/ownedResourceComposition').createMcpOwnedResourceComposition({validateSession:t=>auth.validateSession(t),resourcePool:resource,identityPool:admissionPool,protectedResourceLeasePool:lease,targets:client,qualification,authorizeTool:q.createOwnedToolAuthorizer(qualification),listMessages:async()=>({ok:true,messages:[]}),deleteMessages:async()=>({ok:true}),sendMail:async()=>{throw Error('unexpected mail');}});
 const resources=require('../../server/database/postgres/mcpResourceRepository').createMcpResourceRepository(resource);
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'MCP',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity),defaultTimeoutMs:15000});let scopeA,scopeB;
 async function run(o,key,{graph=false}={}){return coordinator.run(o.id,{idempotencyKey:key},async execution=>{const admitted=await app.admitChat(o.request,execution);if(o===a)scopeA=admitted.scope;else scopeB=admitted.scope;
  if(!graph)return admitted.protocol.callTool('mcp_'+o.id,'admin_rotate_keys',{}, {execution:admitted.execution,surface:'inspector',effectKey:'manual_rotate'});
  return require('../../server/agent-runtime/mcpWorkshopGraph').runMcpWorkshopGraph({message:'Rotate the synthetic key',sandbox:admitted.sandbox},{execution:admitted.execution,model:{provider:'controlled-native',chatWithTools:async()=>({content:JSON.stringify({tool:'admin_rotate_keys',params:{}}),provider:'controlled-native',model:'fixture-no-llm'})},listTools:()=>admitted.protocol.listTools('mcp_'+o.id,{execution:admitted.execution,surface:'chat'}),detectIntent:()=>{throw Error('scripted dispatch not allowed');},resolveInjectionIntent:async()=>null,executeTool:(tool,args,s,opts)=>admitted.protocol.callTool('mcp_'+o.id,tool,args,{...opts,execution:admitted.execution,surface:'chat'}),detectObjectives:()=>[],phraseReply:async()=>'',phraseRecon:async()=>'',formatCatalog:()=>''});
 });}

 // Establish a nonempty sibling before the failed owner operation.
 mode='success';await run(b,'sibling-success');
 const sibling=await fs.readFile(path.join(f.root,'targets',scopeB.targetId,'protected-state/current.json'));
 const siblingRows=JSON.stringify((await identity.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1 ORDER BY operation_id',[b.id])).rows);
 const beforeSockets=sockets,beforeRotations=rotations;
 admissionLoss.arm();
 const unavailable=await run(a,'central-admission-loss',{graph:true});
 assert.equal(unavailable.toolUsed,'admin_rotate_keys');assert.equal(unavailable.toolResult.errorCode,'PROTECTED_STATE_UNAVAILABLE');assert.equal(unavailable.toolResult.blocked,true);assert.equal(unavailable.toolResult.achieved,false);assert.equal(unavailable.toolResult.real,false);assert.deepEqual(unavailable.objectivesHit,[]);
 assert.equal(require('../../server/services/mcp/protectedStateObservation').witnessFor({objectiveId:'mcp_broken_authz',result:unavailable.toolResult,scope:scopeA}),null);
 assert.equal(admissionLoss.snapshot().suppressed,1);
 assert.equal(sockets,beforeSockets);assert.equal(rotations,beforeRotations);
 const admissionIntent=(await migration.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1',[a.id])).rows;
 assert.equal(admissionIntent.length,1);const absentIntent=admissionIntent[0];
 // Tool invocation completed with an unavailable result; no target execution occurred.
 const admissionEffects=(await migration.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1',[absentIntent.run_id])).rows;assert.equal(admissionEffects.length,1);assert.equal(admissionEffects[0].status,'completed');
 await assert.rejects(run(a,'central-admission-loss',{graph:true}),{name:'McpError',code:-32603,message:'MCP error -32603: Effect already attempted; automatic replay is forbidden'});
 assert.deepEqual((await migration.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1',[absentIntent.run_id])).rows,admissionEffects);assert.equal(admissionLoss.snapshot().suppressed,1);assert.equal(sockets,beforeSockets);assert.equal(rotations,beforeRotations);
 assert.equal((await migration.query('SELECT count(*)::int n FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1',[a.id])).rows[0].n,1);
 const identityLease=pool('PG_GRAPH_TEST_RUNTIME_URL',{max:2}),recoveryLease=pool('PG_MCP_RUNTIME_URL',{max:2});
 const appendSql='SELECT workshop_conversations.append_mcp_protected_reconciliation($1,$2,$3,$4,$5) AS value';
 let failure=createSqlReturnSuppression(appendSql);
 const wrappedLease={options:identityLease.options,query:identityLease.query.bind(identityLease),async connect(){
  const raw=await identityLease.connect();const query=failure.wrapQuery(raw.query.bind(raw));
  return new Proxy(raw,{get(target,key){if(key==='query')return query;const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value;}});
 }};
 const service=require('../../server/services/mcp/protectedReconciliationService').createProtectedReconciliationService({validateSession:t=>auth.validateSession(t),identityLeasePool:wrappedLease,resourceLeasePool:recoveryLease,targets:client});
 const admissionReceiptReads=receiptReads;await assert.rejects(service.reconcile(a.request,absentIntent.operation_id),{code:'PROTECTED_RECONCILIATION_STALE'});assert.equal(receiptReads,admissionReceiptReads);assert.equal(sockets,beforeSockets);
 assert.equal((await migration.query('SELECT count(*)::int n FROM workshop_conversations.mcp_protected_reconciliations WHERE operation_id=$1',[absentIntent.operation_id])).rows[0].n,0);
 // A second operation genuinely reaches the target and loses only its target response.
 mode='drop';await assert.rejects(run(a,'target-return-loss',{graph:true}),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN'});
 const intent=(await migration.query("SELECT * FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1 AND ledger_effect_key LIKE 'target-return-loss:%'",[a.id])).rows[0];assert.ok(intent);
 const durableBefore=JSON.stringify((await migration.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1',[intent.run_id])).rows);
 const targetCount=sockets,rotationCount=rotations;assert.equal(targetCount,beforeSockets+1);
 failure.arm();await assert.rejects(service.reconcile(a.request,intent.operation_id),{code:'TEST_SQL_RETURN_SUPPRESSED'});
 assert.equal(failure.snapshot().suppressed,1);
 const reconciliations=()=>migration.query('SELECT * FROM workshop_conversations.mcp_protected_reconciliations WHERE operation_id=$1 ORDER BY reconciliation_id',[intent.operation_id]);
 assert.equal((await reconciliations()).rowCount,0,'append SELECT return suppression rolls the service transaction back');
 failure=createSqlReturnSuppression('COMMIT');failure.arm();
 await assert.rejects(service.reconcile(a.request,intent.operation_id),{code:'TEST_SQL_RETURN_SUPPRESSED'});
 assert.equal(failure.snapshot().suppressed,1);
 const committed=(await reconciliations()).rows;assert.equal(committed.length,1);assert.equal(committed[0].outcome,'completed');
 const recovered=await service.reconcile(a.request,intent.operation_id);
 assert.equal(recovered.creditGranted,false);assert.equal(recovered.originalEffectStatus,'uncertain');
 assert.equal(String(recovered.reconciliation_id),String(committed[0].reconciliation_id));
 assert.deepEqual((await reconciliations()).rows,committed);
 assert.equal(JSON.stringify((await migration.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1',[intent.run_id])).rows),durableBefore);
 await assert.rejects(service.reconcile(b.request,intent.operation_id));
 await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE user_id=$1',[a.id]);
 const readsBefore=receiptReads;await assert.rejects(service.reconcile(a.request,intent.operation_id));assert.equal(receiptReads,readsBefore);
 assert.equal(sockets,targetCount);assert.equal(rotations,rotationCount);
 assert.equal(JSON.stringify((await identity.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE user_id=$1 ORDER BY operation_id',[b.id])).rows),siblingRows);
 assert.deepEqual(await fs.readFile(path.join(f.root,'targets',scopeB.targetId,'protected-state/current.json')),sibling);
 assert.equal((await migration.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=ANY($1::int[])',[[a.id,b.id]])).rows[0].n,0);
 assert.ok(receiptReads<=5);if(serverFailure)throw serverFailure;
 await app.retireOwner({platformOwnerId:a.id,check:async()=>{}});await app.retireOwner({platformOwnerId:b.id,check:async()=>{}});
 await resources.assertOwnerResourcesRetired({platformOwnerId:a.id});await resources.assertOwnerResourcesRetired({platformOwnerId:b.id});
 assert.equal(lease.totalCount-lease.idleCount,0);
 t.diagnostic(JSON.stringify({actualModel:false,controlledGraph:true,admissionReturnLoss:true,actualAdmissionEffectStatus:'completed',admissionToolUnavailable:true,admissionRetryReplayBlocked:true,appendReturnLossRolledBack:true,commitReturnLossDurable:true,retrySameReconciliation:true,targetReplay:false,creditGranted:false,siblingPreserved:true,sockets,rotations,receiptReads,limitation:'Delegated successful SQL return suppression; controlled local target fixture, not network-loss or installed qualification'}));
});
