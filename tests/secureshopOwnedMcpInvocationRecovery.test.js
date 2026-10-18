'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID:id}=require('node:crypto');
const C=require('../server/services/secureshopOwnedMcpInvocationContract');
const {mcpSchemaDigest}=require('../server/services/secureshopMcpSchemaDigest');
const {createInvocationRecoveryRepository}=require('../server/database/postgres/secureshopOwnedMcpInvocationRecovery');
const {createInvocationRecovery}=require('../server/services/secureshopOwnedMcpInvocationRecovery');
const {createInvocationSupervisorChannel}=require('../server/services/secureshopOwnedMcpInvocationSupervisorChannel');
function fixture(){const scope={launchId:id(),scenarioId:id(),generation:1,platformOwnerId:7,platformSessionId:9},tools=[{name:'lookup',description:'Untrusted poison\r\n😀',inputSchema:{type:'object'}}],snapshot={binding:{...scope,shopUserId:11,role:'admin'},entryId:id(),registryVersion:'1',schemaSha256:mcpSchemaDigest(tools),tools};const request=C.request({snapshot,runId:id(),requestId:id(),callId:'call1',toolIndex:0,args:{},mode:'vuln'}),stored={snapshot,request,invocationId:id(),requestSha256:C.digest(request),personaSession:{sessionId:id(),authorityVersion:'1'},managerInstanceId:id(),runtimeSha256:'a'.repeat(64),policySha256:'b'.repeat(64),effectKey:'owned/tool/call1'};
 const row={invocation_id:stored.invocationId,platform_launch_id:scope.launchId,platform_scenario_id:scope.scenarioId,platform_launch_generation:'1',original_platform_owner_id:7,original_platform_session_id:9,worker_token:id(),redacted_at:null,request_json:stored,request_sha256:Buffer.from(stored.requestSha256,'hex'),manager_instance_id:stored.managerInstanceId,runtime_sha256:Buffer.from(stored.runtimeSha256,'hex'),effect_key:stored.effectKey,run_id:request.runId,entry_id:request.entryId,registry_version:'1',persona_id:11,persona_session_id:stored.personaSession.sessionId,authority_version:'1',state:'admitted'};
 const state={queries:[],allowed:true,failSettlement:false};const pool={async query(sql,args){state.queries.push(sql);if(sql.includes('read_owned'))return{rows:[row]};assert(sql.includes('settle_owned'));if(state.failSettlement)throw Error('settlement unavailable');assert.equal(args[1],row.worker_token);return{rows:[{...row,state:args[2]}]};}};
 const repository=createInvocationRecoveryRepository({pool,recoveryAuthority:{async assertCurrent(q){assert.deepEqual(q.scope,scope);if(!state.allowed)throw Error('authority denied');}}});const query={invocationId:stored.invocationId,scope};return{scope,stored,row,state,repository,query,identity:{invocationId:stored.invocationId,requestSha256:stored.requestSha256,managerInstanceId:stored.managerInstanceId,runtimeSha256:stored.runtimeSha256}};
}
test('restart status recovery settles exact existing obligation without any claim API',async()=>{const f=fixture();let statusCalls=0;const manager={get claim(){throw Error('must not retain claim capability');},async status(q){statusCalls++;assert.deepEqual(q,f.identity);return{...q,state:'completed',drained:true,result:{owned:'value'},resultSha256:C.digest({owned:'value'})};}};const service=createInvocationRecovery({repository:f.repository,manager});assert.equal((await service.reconcile(f.query)).state,'completed');assert.equal(statusCalls,1);assert(f.state.queries.every(q=>!q.includes('admit_owned')));assert.equal(JSON.stringify(await f.repository.prepare(f.query)),'{}');});
test('orphan absent and running readback never dispatch or settle; SQL failure repeats status only',async()=>{const f=fixture();let mode='absent',calls=0;const service=createInvocationRecovery({repository:f.repository,manager:{async status(q){calls++;return{...q,state:mode,drained:mode==='completed',...(mode==='completed'?{result:{},resultSha256:C.digest({})}:{})};}}});assert.equal((await service.reconcile(f.query)).needsCanonicalRetirement,true);mode='running';assert.equal((await service.reconcile(f.query)).settled,false);assert(!f.state.queries.some(q=>q.includes('settle_owned')));mode='completed';f.state.failSettlement=true;await assert.rejects(service.reconcile(f.query),/settlement unavailable/);f.state.failSettlement=false;assert.equal((await service.reconcile(f.query)).settled,true);assert.equal(calls,4);});
test('wrong stored original authority, redaction and receipt identity are rejected',async()=>{for(const mutate of [r=>r.original_platform_session_id++,r=>r.platform_launch_generation++,r=>r.original_platform_owner_id++,r=>r.manager_instance_id=id(),r=>r.request_sha256=Buffer.alloc(32),r=>r.redacted_at=new Date(),r=>r.persona_session_id=id()]){const f=fixture();mutate(f.row);await assert.rejects(f.repository.prepare(f.query));assert(!f.state.queries.some(q=>q.includes('settle_owned')));}const f=fixture(),handle=await f.repository.prepare(f.query);await assert.rejects(f.repository.settle({},{}));await assert.rejects(f.repository.settle(handle,{...f.identity,requestSha256:'c'.repeat(64),state:'completed',drained:true}));f.state.allowed=false;await assert.rejects(f.repository.settle(handle,{...f.identity,state:'completed',drained:true}),/authority denied/);});
function channelFixture(mutate=()=>{}){const f=fixture(),identity={managerInstanceId:f.stored.managerInstanceId,volumeId:id(),supervisorEpoch:id(),runtimeSha256:f.stored.runtimeSha256,peerUid:10001,peerPid:123},intent={invocationId:f.stored.invocationId,workerId:id(),bootId:id()},messages=[];const adapter=createInvocationSupervisorChannel({identity,channel:{async exchange(q){messages.push(q);const response={peer:identity,body:{version:q.version,requestId:q.requestId,operation:q.operation,intent:q.intent,state:'completed',drained:true,result:{owned:true}}};mutate(response);return response;}}});const claim={invocationId:f.stored.invocationId,snapshot:f.stored.snapshot,request:f.stored.request,personaSession:f.stored.personaSession,managerInstanceId:f.stored.managerInstanceId,runtimeSha256:f.stored.runtimeSha256,policySha256:f.stored.policySha256,effectKey:f.stored.effectKey,assetId:'catalog-read'};return{adapter,intent,claim,messages,identity};}
test('supervisor channel binds exact volume/epoch/OS peer and worker identity; recovery never starts',async()=>{const f=channelFixture();assert.deepEqual(await f.adapter.reconcile(f.intent),{...f.intent,drained:true});assert.deepEqual(f.messages.map(x=>x.operation),['status']);const worker=f.adapter.start({intent:f.intent,claim:f.claim});assert.equal((await worker.completion).state,'completed');assert.deepEqual(await worker.stop(),{...f.intent,drained:true});assert.deepEqual(f.messages.map(x=>x.operation),['status','start','drain']);});
test('stale peer epoch/PID/volume, worker identity or unproved drain cannot authorize recovery',async()=>{for(const mutate of [r=>r.peer={...r.peer,supervisorEpoch:id()},r=>r.peer={...r.peer,peerPid:124},r=>r.peer={...r.peer,peerUid:0},r=>r.peer={...r.peer,volumeId:id()},r=>r.body.intent={...r.body.intent,workerId:id()},r=>r.body.drained=false,r=>r.body.requestId=id()]){const f=channelFixture(mutate);await assert.rejects(f.adapter.reconcile(f.intent),{code:'MCP_INVOCATION_SUPERVISOR_UNAVAILABLE'});assert.deepEqual(f.messages.map(x=>x.operation),['status']);}});
test('supervisor exchange deadline aborts without treating silence as worker death',async()=>{const f=channelFixture();let signal;const adapter=createInvocationSupervisorChannel({identity:f.identity,timeoutMs:5,channel:{exchange(_q,opts){signal=opts.signal;return new Promise(()=>{});}}});await assert.rejects(adapter.reconcile(f.intent));assert.equal(signal.aborted,true);});
function composedFixture({exclusiveIdentityPool=false}={}){
 const f=fixture(),events=[],state={platform:true,persona:true,failCommit:false,settlements:0},future=new Date(Date.now()+600000);
 const launch={launch_id:f.scope.launchId,scenario_id:f.scope.scenarioId,generation:1,platform_session_id:9,platform_owner_id:7,status:'active',expires_at:future,credential_version:1};
 const iq=async(sql,args)=>{events.push('identity:'+sql);if(sql==='COMMIT'&&state.failCommit)throw Error('identity commit lost');
  if(sql.includes('FROM identity.secureshop_authority_owners'))return{rows:[{id:7,is_active:true}]};
  if(sql.includes('FROM identity.secureshop_authority_sessions'))return{rows:[{id:9,user_id:7,is_active:state.platform,expires_at:future}]};
  if(sql.includes('clock_timestamp() AS now'))return{rows:[{now:new Date()}]};
  if(sql.includes('FROM identity.secureshop_launches'))return{rows:state.platform?[launch]:[]};return{rows:[]};};
 const aq=async(sql,args)=>{events.push('agents:'+sql);
  if(sql.includes('read_owned_mcp_invocation'))return{rows:[f.row]};
  if(sql.includes('FROM secureshop_agents.bound_actor_identities'))return{rows:state.persona?[{id:11,role:'admin',authority_version:'1',banned_at:null}]:[]};
  if(sql.includes('FROM secureshop_agents.bound_persona_sessions'))return{rowCount:state.persona?1:0,rows:[]};
  if(sql.includes('settle_owned_mcp_invocation')){state.settlements++;assert.equal(args[1],f.row.worker_token);return{rows:[{...f.row,state:args[2]}]};}return{rows:[]};};
 const acquisition={held:false,nested:0};
 const identityPool={async query(...args){if(exclusiveIdentityPool&&acquisition.held){acquisition.nested++;throw Error('identity pool exhausted: nested acquisition');}return iq(...args);},async connect(){if(acquisition.held)throw Error('identity pool exhausted');acquisition.held=true;return{query:iq,release(){acquisition.held=false;}};}},agentsPool={query:aq,async connect(){return{query:aq,release(){}};}};
 let onStatus=()=>{};const service=require('../server/services/secureshopOwnedMcpRecoveryComposition').createOwnedMcpRecoveryComposition({identityPool,agentsPool,manager:{async status(q){events.push('HTTP status');onStatus();return{...q,state:'completed',drained:true,result:{},resultSha256:C.digest({})};}}});
 return{...f,events,state,service,acquisition,onStatus(fn){onStatus=fn;}};
}
test('canonical recovery composition locks original identity before persona settlement; HTTP is outside transactions',async()=>{
 const f=composedFixture();assert.equal((await f.service.reconcile(f.query)).settled,true);
 const status=f.events.indexOf('HTTP status'),owner=f.events.findIndex((s,i)=>i>status&&s.includes('FROM identity.secureshop_authority_owners')),session=f.events.findIndex((s,i)=>i>owner&&s.includes('FROM identity.secureshop_authority_sessions')),launch=f.events.findIndex((s,i)=>i>session&&s.includes('FOR UPDATE OF l')),agentLock=f.events.findIndex((s,i)=>i>launch&&s.includes('pg_advisory_xact_lock')),settle=f.events.findIndex(s=>s.includes('settle_owned'));
 assert(status>=0&&owner>status&&session>owner&&launch>session&&agentLock>launch&&settle>agentLock);assert.equal(f.state.settlements,1);
});
test('original platform or persona revocation after status prevents settlement despite retained replacement context',async()=>{
 for(const key of ['platform','persona']){const f=composedFixture();f.onStatus(()=>{f.state[key]=false;});await assert.rejects(f.service.reconcile(f.query),e=>['SESSION_UNAVAILABLE','MCP_RECOVERY_SETTLEMENT_UNCERTAIN'].includes(e.code));assert.equal(f.state.settlements,0);}
});
test('identity commit loss after agents settlement reports uncertainty and only status reconciles',async()=>{
 const f=composedFixture();f.state.failCommit=true;await assert.rejects(f.service.reconcile(f.query),{code:'MCP_RECOVERY_SETTLEMENT_UNCERTAIN'});assert.equal(f.state.settlements,1);f.state.failCommit=false;assert.equal((await f.service.reconcile(f.query)).settled,true);assert.equal(f.events.filter(x=>x==='HTTP status').length,2);assert(!f.events.some(x=>x.includes('admit_owned')));
});

test('canonical recovery completes with a one-client identity pool without nested acquisition', {timeout:1000}, async()=>{
 const f=composedFixture({exclusiveIdentityPool:true});
 assert.equal((await f.service.reconcile(f.query)).settled,true);
 assert.equal(f.acquisition.nested,0);assert.equal(f.acquisition.held,false);
 assert.equal(f.state.settlements,1);
});
test('held recovery identity contexts isolate concurrent owners and expire for delayed descendants', {timeout:1000}, async()=>{
 const {createSecureShopLaunchRepository}=require('../server/database/postgres/secureshopLaunchRepository');
 const scopes=[fixture().scope,fixture().scope];scopes[1]={...scopes[1],platformOwnerId:8,platformSessionId:10};
 const handles=scopes.map(()=>Object.freeze({})),clients=[],future=new Date(Date.now()+60000);
 let releaseBoth,releaseDelayed,entered=0,delayed;
 const both=new Promise(r=>releaseBoth=r),afterRelease=new Promise(r=>releaseDelayed=r);
 const pool={async query(){throw Error('nested identity acquisition');},async connect(){
  const client={owner:null,released:false,reads:0,async query(sql,args){assert.equal(this.released,false);
   if(sql.includes('FROM identity.secureshop_authority_owners')){this.owner=args[0];return{rows:[{id:args[0],is_active:true}]};}
   if(sql.includes('FROM identity.secureshop_authority_sessions'))return{rows:[{id:args[0],user_id:this.owner,is_active:true,expires_at:future}]};
   if(sql.includes('clock_timestamp() AS now'))return{rows:[{now:new Date()}]};
   if(sql.includes('FROM identity.secureshop_launches')){const scope=scopes.find(x=>x.platformOwnerId===this.owner);assert.equal(args[0],scope.launchId);this.reads++;return{rows:[{launch_id:scope.launchId,scenario_id:scope.scenarioId,platform_session_id:scope.platformSessionId,platform_owner_id:scope.platformOwnerId,generation:1,credential_version:1,status:'active',expires_at:future}]};}
   return{rows:[]};},release(){this.released=true;}};clients.push(client);return client;
 }};
 let launches;
 launches=createSecureShopLaunchRepository(pool,{ownedMcpInvocationRecovery:{scopeOf(h){return scopes[handles.indexOf(h)];},async settlePrepared(h){
  const i=handles.indexOf(h),scope=scopes[i];entered++;if(entered===2)releaseBoth();await both;
  await launches.assertCurrent(scope);
  await assert.rejects(launches.assertCurrent(scopes[1-i]),{code:'STALE_LAUNCH'});
  if(i===0)delayed=(async()=>{await afterRelease;await assert.rejects(launches.assertCurrent(scope),{code:'STALE_LAUNCH'});})();
  return{state:'completed'};
 }}});
 await Promise.all(handles.map(h=>launches.settleOwnedMcpRecovery(h,{})));
 assert(clients.every(c=>c.released&&c.reads===2));releaseDelayed();await delayed;
 assert(clients.every(c=>c.reads===2));
});
