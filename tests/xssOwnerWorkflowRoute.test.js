'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createXssOwnerWorkflowRoute}=require('../server/agent-runtime/xssOwnerWorkflowRoute');
const request=()=>({owner:42,user:{id:42},identitySession:{id:7},headers:{authorization:'Bearer owned-token'}});
const response=()=>({statusCode:200,status(n){this.statusCode=n;return this;},json(value){this.payload=value;this.headersSent=true;}});
function fixture(options={}){
 const calls=[];const route=createXssOwnerWorkflowRoute({coordinator:{run:async(owner,_options,work)=>{calls.push(['run',owner]);return work({check:async()=>{}});},reset:async(owner,work)=>{calls.push(['reset',owner]);return work({check:async()=>{}});}},ownerFor:req=>req.owner,
  postgres:true,validateSession:async token=>{assert.equal(token,'owned-token');return {user:{id:42},session:{id:7,user_id:42}};},admit:async(owner,work)=>{calls.push(['admit',owner]);return work({ownerId:Number(owner),check:async()=>{}});},
  pendingProfileReset:async(owner,guard)=>{assert.equal(guard.ownerId,Number(owner));calls.push(['pending',owner]);},...options});
 return{calls,route};
}
test('authenticated PostgreSQL run and reset both use outer lifecycle admission',async()=>{
 const f=fixture();for(const reset of [false,true]){
  const out=response();await f.route((_req,res)=>res.json({ok:true}),{reset})(request(),out);assert.equal(out.payload.ok,true);
 }
 assert.deepEqual(f.calls,[['admit',42],['run',42],['admit',42],['pending',42],['reset',42]]);
});
test('pending child reset denies reset before coordinator invalidation',async()=>{
 const pending=Object.assign(new Error('pending'),{code:'XSS_PROFILE_RESET_PENDING',statusCode:503});
 const f=fixture({pendingProfileReset:async()=>{f.calls.push(['pending',42]);throw pending;}});
 const out=response();await f.route((_req,res)=>res.json({ok:true}),{reset:true})(request(),out);
 assert.deepEqual(f.calls,[['admit',42],['pending',42]]);assert.equal(out.statusCode,503);
 assert.match(out.payload.error,/pending profile reset/);
});
test('ordinary runs never query child reset state',async()=>{
 const f=fixture({pendingProfileReset:async()=>assert.fail('run must not query profile reset journal')});
 await f.route((_req,res)=>res.json({ok:true}),{reset:false})(request(),response());
 assert.deepEqual(f.calls,[['admit',42],['run',42]]);
});
test('explicit anonymous workshop path retains teaching behavior without platform authority',async()=>{
 const f=fixture({allowAnonymous:true});await f.route((_req,res)=>res.json({ok:true}))({owner:'anon_fixture'},response());
 assert.deepEqual(f.calls,[['run','anon_fixture']]);
});
test('legacy fixture route does not provision PostgreSQL admission',async()=>{
 const f=fixture({postgres:false});await f.route((_req,res)=>res.json({ok:true}))(request(),response());
 assert.deepEqual(f.calls,[['run',42]]);
});

for(const phase of ['admission','effect','finalization'])test(`exact session revocation during ${phase} prevents late XSS publication`,async()=>{
 let valid=true,toolCalls=0;
 const execution={check:async()=>{},effect:async(_key,work)=>{if(phase==='effect')valid=false;return work();}};
 const f=fixture({validateSession:async()=>valid?{user:{id:42},session:{id:7,user_id:42}}:null,
  admit:async(_owner,work)=>{if(phase==='admission')valid=false;return work({ownerId:42,check:async()=>{}});},
  coordinator:{run:async(_owner,_options,work)=>{await work(execution);if(phase==='finalization')valid=false;}}});
 const out=response();await f.route(async(_req,res)=>{await require('../server/agent-runtime/ownerWorkflowRoutes').getOwnerExecution().effect('owned',async()=>{toolCalls++;});res.json({privateResult:'must not publish'});})(request(),out);
 assert.equal(out.statusCode,401);assert.equal(out.payload.code,'SESSION_REVOKED');assert.equal(out.payload.privateResult,undefined);assert.equal(toolCalls,phase==='finalization'?1:0);
});
test('resolved owner cannot substitute another platform owner or anonymous authority',async()=>{
 const f=fixture({allowAnonymous:true});
 for(const owner of [43,'anon_fixture']){const out=response();await f.route((_req,res)=>res.json({ok:true}))({...request(),owner},out);assert.equal(out.statusCode,401);}
 assert.deepEqual(f.calls,[]);
});
test('current session must match original admitted session before lifecycle admission',async()=>{
 const f=fixture({validateSession:async()=>({user:{id:42},session:{id:8,user_id:42}})}),out=response();await f.route((_req,res)=>res.json({ok:true}))(request(),out);assert.equal(out.statusCode,401);assert.deepEqual(f.calls,[]);
});
