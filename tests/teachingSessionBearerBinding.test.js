'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createTeachingSessionBearerBinding}=require('../server/services/teachingSessionBearerBinding');
const {createTeachingSessionAuthority}=require('../server/services/teachingSessionAuthority');
const stale=()=>Object.assign(new Error('private storage details'),{code:'55000'});
function fixture({fields={userId:7,platformOwnerId:7,platformSessionId:11},stored=true,username}={}){
 const state={valid:true,rows:new Set(stored?['old']:[]),tombstones:new Set(),calls:[],tokens:[],outage:false,afterRegenerate:()=>{},afterSave:()=>{}};
 const req={headers:{authorization:'Bearer verified'},sessionID:'old'};
 const makeSession=(sid,fields)=>({...fields,cookie:{maxAge:1000},regenerate(callback){state.calls.push('regenerate');state.rows.delete(sid);state.tombstones.add(sid);req.sessionID='new';req.session=makeSession('new',{});state.afterRegenerate();callback();},save(callback){state.calls.push('save');if(state.tombstones.has(sid))return callback(stale());state.rows.add(sid);state.afterSave();callback();},destroy(callback){state.calls.push('destroy');state.rows.delete(sid);state.tombstones.add(sid);delete req.session;callback();}});
 req.session=makeSession('old',fields);
 const assertCookieBinding=async(sid,binding)=>{state.calls.push('assert:'+sid);assert.deepEqual(binding,{ownerId:7,sessionId:11});if(state.outage)throw Object.assign(new Error('private outage'),{code:'ECONNRESET'});if(!state.rows.has(sid))throw stale();};
 const resolveAuthority=createTeachingSessionAuthority({validateSession:async token=>{state.tokens.push(token);return state.valid&&token==='verified'?{user:{id:7,username:'trusted'},session:{id:11,user_id:7}}:null;},assertBinding:async()=>{state.calls.push('authority');if(!state.valid)throw stale();},assertCookieBinding});
 const bind=createTeachingSessionBearerBinding({resolveAuthority,assertCookieBinding,...(username===undefined?{}:{readTrustedUsername:async binding=>{assert.deepEqual(binding,{ownerId:7,sessionId:11});return username;}})});
 return{req,state,bind};
}
test('matching durable cookie is rechecked without rotation or save',async()=>{
 const f=fixture(),original=f.req.session;const result=await f.bind(f.req);assert.equal(result.rotated,false);assert.equal(f.req.session,original);assert.equal(Object.isFrozen(result),true);assert.ok(!f.state.calls.includes('save'));assert.ok(!f.state.calls.includes('regenerate'));await result.check();assert.ok(f.state.calls.filter(c=>c==='assert:old').length>=2);
});
for(const [label,options] of [['anonymous',{fields:{},stored:false}],['missing persisted row',{stored:false}],['different owner',{fields:{userId:8,platformOwnerId:8,platformSessionId:12}}],['new canonical session',{fields:{userId:7,platformOwnerId:7,platformSessionId:10}}],['partial legacy binding',{fields:{userId:7}}]])test(`${label} rotates and saves complete canonical binding`,async()=>{
 const f=fixture(options),old=f.req.session;const result=await f.bind(f.req);assert.equal(result.rotated,true);assert.equal(f.req.sessionID,'new');assert.deepEqual([f.req.session.userId,f.req.session.platformOwnerId,f.req.session.platformSessionId],[7,7,11]);assert.equal(f.req.session.role,undefined);assert.equal(f.req.session.adminLevel,undefined);assert.equal(f.req.session.username,undefined);assert.ok(f.state.tombstones.has('old'));assert.ok(f.state.rows.has('new'));await assert.rejects(new Promise((resolve,reject)=>old.save(e=>e?reject(e):resolve())),{code:'55000'});
});
test('explicit invalid or absent authorization never repairs or falls back to cookie',async()=>{
 for(const authorization of [undefined,'Bearer invalid','Basic invalid','Bearer one, Bearer two']){const f=fixture();f.req.headers={...(authorization?{authorization}:{})};await assert.rejects(f.bind(f.req),e=>e.statusCode===401);assert.ok(!f.state.calls.includes('regenerate'));}
});
test('database outage on matching cookie fails closed without rotation',async()=>{
 const f=fixture();f.state.outage=true;await assert.rejects(f.bind(f.req),e=>e.statusCode===503&&!e.message.includes('private'));assert.ok(!f.state.calls.includes('regenerate'));
});
test('only trusted username callback can add optional opaque username',async()=>{
 const f=fixture({fields:{},stored:false,username:'trusted-display-name'});f.req.user={username:'untrusted',role:'super_admin'};await f.bind(f.req);assert.equal(f.req.session.username,'trusted-display-name');assert.equal(f.req.session.role,undefined);
});
test('revocation during regeneration destroys new binding before save',async()=>{
 const f=fixture({fields:{},stored:false});f.state.afterRegenerate=()=>{f.state.valid=false;};await assert.rejects(f.bind(f.req),e=>e.statusCode===401);assert.ok(f.state.tombstones.has('new'));assert.equal(f.req.session,undefined);assert.ok(!f.state.calls.includes('save'));
});
test('revocation after save retires new cookie and returns no authority',async()=>{
 const f=fixture({fields:{},stored:false});f.state.afterSave=()=>{f.state.valid=false;};await assert.rejects(f.bind(f.req),e=>e.statusCode===401);assert.equal(f.req.session,undefined);assert.ok(!f.state.rows.has('new'));assert.ok(f.state.tombstones.has('new'));
});
test('later checks capture authority and SID, never silently adopt changed request',async()=>{
 const f=fixture();const result=await f.bind(f.req);f.req.headers.authorization='Bearer replaced';await result.check();assert.ok(f.state.tokens.every(t=>t==='verified'));f.req.sessionID='replacement';await assert.rejects(result.check(),{code:'TEACHING_SESSION_BINDING_UNAVAILABLE'});
});
test('missing express middleware fails closed rather than manufacturing a session',async()=>{
 const f=fixture();delete f.req.session;await assert.rejects(f.bind(f.req),e=>e.statusCode===503);assert.equal(f.req.session,undefined);
});
test('failed durable save destroys new SID and prevents automatic resave',async()=>{
 const f=fixture({fields:{},stored:false});f.state.afterRegenerate=()=>{f.req.session.save=callback=>callback(new Error('private outage'));};await assert.rejects(f.bind(f.req),e=>e.statusCode===503&&!e.message.includes('private'));assert.equal(f.req.session,undefined);assert.ok(f.state.tombstones.has('new'));
});
