'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createOwnedMcpInvocationLifecycle}=require('../server/services/secureshopOwnedMcpInvocationLifecycle');
const {createSecureShopLaunchRepository}=require('../server/database/postgres/secureshopLaunchRepository');
function fixture(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:9},id=randomUUID();
 const row={invocation_id:randomUUID(),manager_instance_id:randomUUID(),runtime_sha256:'a'.repeat(64),drained:false,state:'admitted'};
 const state={rows:[row],events:[],status:'fenced'};
 const journal={async existing(s){assert.equal(s.platformOwnerId,7);state.events.push('read');return state.rows;},async recordFence(r){state.events.push('persist');state.receipt=r;}};
 const cleanupAuthority={async getOperation(){return{resetId:id,status:state.status,binding:scope};}};
 const manager={async retire(request){state.events.push('retire');return{...request,retired:true,drained:true};}};
 return{scope,id,row,state,journal,cleanupAuthority,manager};
}
test('legacy no-grant cleanup needs no manager; minted grants require it even when serving disabled',async()=>{
 const f=fixture(),l=createOwnedMcpInvocationLifecycle(f);f.state.rows=[];await l.beforeRetirement(f.id);assert.deepEqual(f.state.events,['read']);
 f.state.rows=[f.row];await assert.rejects(createOwnedMcpInvocationLifecycle({...f,manager:undefined}).beforeRetirement(f.id),{code:'MCP_INVOCATION_DRAIN_REQUIRED'});
});
test('exact manager tombstone persisted before caller may retire SQL generation; terminal grants still fenced',async()=>{
 const f=fixture();f.row.drained=true;f.row.state='completed';await createOwnedMcpInvocationLifecycle(f).beforeRetirement(f.id);
 assert.deepEqual(f.state.events,['read','retire','persist']);assert.deepEqual(f.state.receipt.invocationIds,[f.row.invocation_id]);
});
test('wrong manager, omitted invocation and undrained receipts fail without persistence',async()=>{
 for(const mutate of [r=>({...r,managerInstanceId:randomUUID()}),r=>({...r,invocationIds:[]}),r=>({...r,drained:false})]){
 const f=fixture();f.manager.retire=async r=>mutate({...r,retired:true,drained:true});await assert.rejects(createOwnedMcpInvocationLifecycle(f).beforeRetirement(f.id));assert(!f.state.events.includes('persist'));
 }
});
test('manager timeout and changed canonical cleanup authority cannot become successful drain',async()=>{
 const f=fixture();f.manager.retire=()=>new Promise(()=>{});await assert.rejects(createOwnedMcpInvocationLifecycle({...f,timeoutMs:5}).beforeRetirement(f.id));assert(!f.state.events.includes('persist'));
 const g=fixture();g.manager.retire=async r=>{g.state.status='unknown';return{...r,retired:true,drained:true};};await assert.rejects(createOwnedMcpInvocationLifecycle(g).beforeRetirement(g.id));assert(!g.state.events.includes('persist'));
});
test('owner deletion uses canonical check and owner-wide tombstone, not revoked live-session authorization',async()=>{
 const f=fixture();let checks=0;await createOwnedMcpInvocationLifecycle(f).beforeDeletion({jobId:f.id,subjectId:7,check:async()=>{checks++;}});
 assert(checks>=3);assert.equal(f.state.receipt.kind,'owner_deletion');assert.equal(f.state.receipt.launchId,undefined);
});
function admissionFixture({commitFails=false,revoked=false,resetWon=false}={}){
 const f=fixture(),events=[];const now=new Date(),later=new Date(Date.now()+60000);let commitResolve;
 const commitGate=new Promise(resolve=>{commitResolve=resolve;});
 const client={async query(sql){events.push(sql);if(sql.includes('FROM identity.secureshop_authority_owners'))return{rows:[{id:7,realm:'platform',is_active:1,account_locked_until:null}]};
 if(sql.includes('FROM identity.secureshop_authority_sessions'))return{rows:[{id:9,user_id:7,realm:'platform',is_active:revoked?0:1,expires_at:later}]};
 if(sql.includes('clock_timestamp'))return{rows:[{now}]};
 if(sql.includes('FROM identity.secureshop_launches'))return{rows:[{launch_id:f.scope.launchId,platform_session_id:9,scenario_id:f.scope.scenarioId,status:resetWon?'resetting':'active',generation:resetWon?2:1,expires_at:later}]};
 if(sql==='COMMIT'){await commitGate;if(commitFails)throw Error('commit failed');}return{rows:[]};},release(){events.push('release');}};
 const pool={query:client.query,connect:async()=>client};const handle={};const journal={scopeOf(h){assert.equal(h,handle);return f.scope;},async admitPrepared(){events.push('agents grant');return{invocationId:f.row.invocation_id};}};
 return{events,commitResolve,handle,repo:createSecureShopLaunchRepository(pool,{ownedMcpInvocationJournal:journal})};
}
test('identity user/session/launch locks precede agents grant; no result dispatch before identity commit',async()=>{
 const f=admissionFixture();let dispatched=false;const pending=f.repo.admitOwnedMcpInvocation(f.handle).then(()=>{dispatched=true;});
 pending.catch(()=>{});
 try{await new Promise(setImmediate);assert.equal(dispatched,false);const idx=x=>f.events.findIndex(s=>s.includes(x));
  assert(idx('identity.secureshop_authority_owners')<idx('identity.secureshop_authority_sessions'));
  assert(idx('identity.secureshop_authority_sessions')<idx('identity.secureshop_launches'));
  assert(idx('identity.secureshop_launches')<idx('agents grant'));assert(idx('agents grant')<idx('COMMIT'));
 }finally{f.commitResolve();}
 await pending;assert.equal(dispatched,true);
});
test('failed identity commit never returns grant; revoked original session never reaches agents',async()=>{
 const f=admissionFixture({commitFails:true});const p=f.repo.admitOwnedMcpInvocation(f.handle);f.commitResolve();await assert.rejects(p,/commit failed/);assert(f.events.includes('ROLLBACK'));
 const g=admissionFixture({revoked:true});await assert.rejects(g.repo.admitOwnedMcpInvocation(g.handle),{code:'SESSION_UNAVAILABLE'});assert(!g.events.includes('agents grant'));
});

test('reset winning identity admission denies agents grant, without remote dispatch',async()=>{
 const f=admissionFixture({resetWon:true});await assert.rejects(f.repo.admitOwnedMcpInvocation(f.handle),{code:'STALE_GENERATION'});assert(!f.events.includes('agents grant'));
});
test('real registry decorator drains before base retirement insert and stops on manager failure',async()=>{
 const {createOwnedMcpRegistryLifecycle}=require('../server/services/secureshopOwnedMcpRegistryLifecycle');
 const f=fixture();const invocationLifecycle=createOwnedMcpInvocationLifecycle(f);
 const registry=createOwnedMcpRegistryLifecycle({cleanupAuthority:f.cleanupAuthority,invocationLifecycle,pool:{async query(){f.state.events.push('verify');return{rows:[{verified:true}]};}}});
 const decorated=registry.decorateConversation({async retireGeneration(){f.state.events.push('retirement insert');return{retired:true};}});
 assert.deepEqual(await decorated.retireGeneration(f.id),{retired:true});assert.deepEqual(f.state.events,['read','retire','persist','retirement insert','verify']);
 f.state.events=[];f.manager.retire=async()=>{throw Error('manager unavailable');};await assert.rejects(decorated.retireGeneration(f.id));assert(!f.state.events.includes('retirement insert'));
});
