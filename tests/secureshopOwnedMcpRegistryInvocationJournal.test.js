'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const C=require('../server/services/secureshopOwnedMcpInvocationContract');
const P=require('../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
const {mcpSchemaDigest}=require('../server/services/secureshopMcpSchemaDigest');
const {withEffectAdmission}=require('../server/agent-runtime/effectAdmissionContext');
const {createRegistryInvocationJournal,validateEnvelope}=require('../server/database/postgres/secureshopOwnedMcpRegistryInvocationJournal');
const {createRegistryInvocationBridge,createRegistryInvocationRetirer}=require('../server/services/secureshopOwnedMcpRegistryInvocationBridge');
function fixture(){
 const binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8,shopUserId:9,role:'admin'};
 const tools=[{name:'lookup',description:'Teaching description',inputSchema:{type:'object',properties:{'10':{type:'string'},'2':{type:'string'}}}}];
 const request={version:1,instanceId:randomUUID(),operationId:randomUUID(),entry:{entryId:randomUUID(),registryVersion:'1',transport:'sse',endpoint:'http://owned.invalid/mcp',schemaSha256:mcpSchemaDigest(tools),tools},toolName:'lookup',args:{key:'fixture','10':'ten','2':'two'}};
 const execution={runId:randomUUID(),ownerKey:'owner',durableGeneration:'1',async check(){}};
 const state={order:[],stored:null,settled:null};let locked=false;
 const pool={async query(sql,args){if(sql.startsWith('SELECT invocation_id FROM')){if(state.queryFailure)throw Error('database unavailable');return{rows:state.stored?[{invocation_id:request.operationId}]:[]};}if(sql.includes('SELECT invocation_id,request_json'))return{rows:state.stored?[{invocation_id:request.operationId,request_json:state.stored,receipt_json:state.settled,request_sha256:Buffer.from(state.stored.requestSha256,'hex'),run_id:execution.runId,effect_key:'owned/effect',manager_instance_id:request.instanceId,runtime_sha256:Buffer.from(identity.runtimeDigest,'hex'),state:state.settled?.state,drained:state.settled?.drained}]:[]};if(sql.includes('admit_owned')){assert.equal(locked,false);state.order.push('admit');state.stored=JSON.parse(args[0]);return{rows:[{invocation_id:request.operationId,request_sha256:Buffer.from(state.stored.requestSha256,'hex'),state:'admitted'}]};}
 if(sql.includes('settle_owned')){assert.equal(locked,false);state.order.push('settle');state.settled=JSON.parse(args[3]);return{rows:[{invocation_id:request.operationId,request_sha256:Buffer.from(state.stored.requestSha256,'hex'),state:args[2]}]};}return{rows:[]};}};
 const journal=createRegistryInvocationJournal({pool,personaAuthority:{capture({scope,...rest}){return{binding:{...scope,...rest},withPersonaEffect:work=>work(pool)};}}});
 const identity={version:1,instanceId:request.instanceId,runtimeDigest:'a'.repeat(64)},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const result={content:[{type:'text',text:'owned result'}]};
 const receipt={version:1,instanceId:request.instanceId,operationId:request.operationId,entryId:request.entry.entryId,registryVersion:'1',requestSha256:P.digest(request),schemaSha256:request.entry.schemaSha256,endpointSha256:P.digest(request.entry.endpoint),argumentsSha256:P.digest(request.args),resultSha256:P.digest(result),result,isolation:'owned-mcp-registry-v1'};
 const client={async invoke(){assert.equal(locked,true);state.order.push('invoke');return receipt;},async invocationState(q){state.order.push('drain');return{version:1,...q,state:'retired',drained:true};}};
 const bridge=createRegistryInvocationBridge({journal,launches:{admitOwnedMcpInvocation:h=>journal.admitPrepared(h)},client,executorIdentity:identity,personaSession,policy:{mode:'vuln',approved:false}});
 const packet={request,binding,execution,requestId:randomUUID(),callId:'call1',effect:{ledgerEffectKey:'owned/effect'},mode:'vuln',approved:false,entry:request.entry,snapshots:{async withCurrentEntry(entry,work){locked=true;try{return await work();}finally{locked=false;}}}};
 return{state,client,journal,bridge,packet,identity,receipt};
}
test('real journal maps both request digests and admits before locked invoke, settles after release',async()=>{
 const f=fixture();await assert.rejects(f.bridge.dispatch(f.packet),{code:'PROTECTED_EFFECT_ADMISSION_REQUIRED'});
 const result=await withEffectAdmission(f.packet.execution,'owned/effect',()=>f.bridge.dispatch(f.packet));
 assert.deepEqual(result,f.receipt);assert.deepEqual(f.state.order,['admit','invoke','settle']);
 assert.notEqual(f.state.stored.requestSha256,f.state.stored.executorMapping.requestSha256);
 assert.notEqual(C.digest(f.packet.request),P.digest(f.packet.request));
 assert.equal(f.state.stored.executorMapping.requestSha256,P.digest(f.packet.request));
 assert.equal(f.state.settled.state,'completed');assert.equal(f.state.settled.drained,true);
 for(const mutate of [v=>v.executorMapping.request.entry.endpoint='http://other.invalid',v=>v.executorMapping.request.args.key='other',v=>v.executorMapping.instanceId=randomUUID(),v=>v.request.args.key='other']){
  const bad=structuredClone(f.state.stored);mutate(bad);assert.throws(()=>validateEnvelope(bad));
 }
});
test('lost response is drained and journaled uncertain, never retried or called completed',async()=>{
 const f=fixture();let calls=0;f.client.invoke=async()=>{calls++;throw Error('lost response');};
 await assert.rejects(withEffectAdmission(f.packet.execution,'owned/effect',()=>f.bridge.dispatch(f.packet)),{code:'MCP_INVOCATION_OUTCOME_UNCERTAIN'});
 assert.equal(calls,1);assert.equal(f.state.settled.state,'uncertain');assert.equal(f.state.settled.drained,true);
});
test('unreachable drain remains an explicit unresolved obligation',async()=>{
 const f=fixture();f.client.invoke=async()=>{throw Error('offline');};f.client.invocationState=async()=>{throw Error('offline');};
 await assert.rejects(withEffectAdmission(f.packet.execution,'owned/effect',()=>f.bridge.dispatch(f.packet)));
 assert.equal(f.state.settled.state,'uncertain');assert.equal(f.state.settled.drained,false);assert.equal(f.state.settled.executorProof.state,'unknown');
});
test('failed identity admission cannot reach remote invocation',async()=>{
 const f=fixture();const bridge=createRegistryInvocationBridge({journal:f.journal,launches:{async admitOwnedMcpInvocation(){throw Error('identity rollback');}},client:f.client,executorIdentity:f.identity,personaSession:{sessionId:randomUUID(),authorityVersion:'1'},policy:{mode:'vuln'}});
 await assert.rejects(withEffectAdmission(f.packet.execution,'owned/effect',()=>bridge.dispatch(f.packet)),/identity rollback/);assert.deepEqual(f.state.order,[]);
});
test('retirement skips durable drained rows, denies unknown/restarted identities, and never invokes',async()=>{
 const f=fixture(),q=f.packet.request;let drained=false,calls=0,unknown=false,restarted=false;
 const row={invocation_id:q.operationId,manager_instance_id:q.instanceId,runtime_sha256:f.identity.runtimeDigest,mapping:{instanceId:q.instanceId,runtimeSha256:f.identity.runtimeDigest,requestSha256:P.digest(q)}};
 const retirer=createRegistryInvocationRetirer({journal:{async mappings(){return[{...row,drained}];}},client:{async invocationHealth(){return{...f.identity,instanceId:restarted?randomUUID():q.instanceId};},async invocationState(input){calls++;return{version:1,...input,state:unknown?'unknown':'retired',drained:!unknown};},async invoke(){throw Error('must not replay');}}});
 const request={version:'owned-mcp-invocation-fence-v1',kind:'retirement',fenceId:randomUUID(),...f.packet.binding,managerInstanceId:q.instanceId,runtimeSha256:f.identity.runtimeDigest,invocationIds:[q.operationId]};
 assert.equal((await retirer.retire(request)).drained,true);assert.equal(calls,1);
 unknown=true;await assert.rejects(retirer.retire(request));restarted=true;await assert.rejects(retirer.retire(request));
 drained=true;assert.equal((await retirer.retire(request)).drained,true);assert.equal(calls,2);
});
test('forward migration retains legacy entry and makes its bypass private; endpoint and mapping bind in SQL',()=>{
 const sql=require('node:fs').readFileSync('db/postgres/workshop-migrations/secureshop_agents/0044_owned_mcp_registry_executor_mapping.sql','utf8');
 for(const text of ['RENAME TO admit_owned_mcp_invocation_legacy','RENAME TO settle_owned_mcp_invocation_legacy','e.endpoint_text IS DISTINCT FROM',"q->'args' IS DISTINCT FROM v->'request'->'args'",'FROM PUBLIC,dvaia_secureshop_agents_runtime','RETURN QUERY SELECT * FROM secureshop_agents.admit_owned_mcp_invocation_legacy'])assert.ok(sql.includes(text));
 // Source contract only; native migration application is intentionally separate.
});

test('completed readback joins exact durable request and receipt, rejects uncertain or foreign scope',async()=>{
 const f=fixture();await withEffectAdmission(f.packet.execution,'owned/effect',()=>f.bridge.dispatch(f.packet));
 const scope=require('../server/services/secureshopConversationBinding').createLaunchScope(f.packet.binding);
 const query={scope,invocationId:f.packet.request.operationId};
 assert.deepEqual((await f.journal.readCompleted(query)).receipt,f.receipt);
 await assert.rejects(f.journal.readCompleted({...query,scope:{...scope,platformOwnerId:77}}));
 f.state.settled.executorProof.result={content:[]};await assert.rejects(f.journal.readCompleted(query));
 f.state.settled.state='uncertain';await assert.rejects(f.journal.readCompleted(query));
});

test('agents commit followed by identity failure settles only local existing obligation',async()=>{
 const f=fixture();const bridge=createRegistryInvocationBridge({journal:f.journal,launches:{async admitOwnedMcpInvocation(h){await f.journal.admitPrepared(h);throw Error('identity commit failed');}},client:f.client,executorIdentity:f.identity,personaSession:{sessionId:randomUUID(),authorityVersion:'1'},policy:{mode:'vuln'}});
 await assert.rejects(withEffectAdmission(f.packet.execution,'owned/effect',()=>bridge.dispatch(f.packet)),/identity commit failed/);
 assert.deepEqual(f.state.order,['admit','settle']);assert.equal(f.state.settled.state,'failed_before_effect');assert.equal(f.state.settled.drained,true);assert.equal(f.state.settled.executorProof,undefined);
});
test('pre-dispatch revoked execution settles locally; unavailable database stays unresolved',async()=>{
 for(const queryFailure of [false,true]){
 const f=fixture();f.state.queryFailure=queryFailure;f.packet.execution.check=async()=>{throw Error('revoked');};
 await assert.rejects(withEffectAdmission(f.packet.execution,'owned/effect',()=>f.bridge.dispatch(f.packet)));
 assert.equal(f.state.order.includes('invoke'),false);assert.equal(f.state.order.includes('drain'),false);
 if(queryFailure)assert.equal(f.state.settled,null);else assert.equal(f.state.settled.state,'failed_before_effect');
 }
});

test('real client health failure is request-bound local settlement without invoke or drain',async()=>{
 const f=fixture(),paths=[];
 f.packet.snapshots.withCurrentEntry=async(entry,work)=>{try{return await work();}catch(cause){throw Object.assign(Error('Persona effect uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',cause});}};
 const client=require('../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({baseURL:'http://owned.invalid',token:'x'.repeat(43),fetchImpl:async url=>{paths.push(url.pathname);throw Error('health unavailable');}});
 const bridge=createRegistryInvocationBridge({journal:f.journal,launches:{admitOwnedMcpInvocation:h=>f.journal.admitPrepared(h)},client,executorIdentity:f.identity,personaSession:{sessionId:randomUUID(),authorityVersion:'1'},policy:{mode:'vuln'}});
 await assert.rejects(withEffectAdmission(f.packet.execution,'owned/effect',()=>bridge.dispatch(f.packet)));
 assert.deepEqual(paths,['/secureshop/mcp-registry/invoke/health']);assert.equal(f.state.settled.state,'failed_before_effect');assert.equal(f.state.settled.executorProof,undefined);
});
