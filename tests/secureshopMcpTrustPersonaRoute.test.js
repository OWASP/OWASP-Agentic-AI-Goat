'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {createBoundMcpTrustRouter}=require('../server/routes/secureshop/boundMcpTrust');
const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:8};
const session=Object.freeze({sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'4',expiresAt:'2026-10-01T00:00:00Z'});
const requestId='40000000-0000-4000-8000-000000000001';
const actions=[['status','readiness',null],['discover','discover',{scenario:'rogue_registration'}],['rotate','rotate',{}],['run','run',{scenario:'rug_pull',request_id:requestId}]];
async function mount(t,code){
 const calls=[],app=express();app.use(express.json());
 const application=Object.fromEntries(actions.map(([name])=>[name,async input=>{calls.push({name,input});if(code)throw Object.assign(new Error('PRIVATE_CAUSE'),{code,cause:new Error('PRIVATE_SECRET')});return{ok:true};}]));
 app.use(createBoundMcpTrustRouter({launches:{resolveCapability:async()=>scope},authenticatePersona(req,_res,next){req.ssUser={id:13,role:'admin'};req.ssPersonaSession=session;next();},application}));
 const server=await new Promise(resolve=>{const server=app.listen(0,'127.0.0.1',()=>resolve(server));});
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 return{calls,async request(path,body){return fetch(`http://127.0.0.1:${server.address().port}/v2/mcp-trust/${path}`,{method:body===null?'GET':'POST',headers:{'x-dvaia-secureshop-launch':'p'.repeat(43),'content-type':'application/json'},...(body===null?{}:{body:JSON.stringify(body)})});}};
}
test('all four MCP contexts forward the exact authenticated persona session only',async t=>{
 const f=await mount(t);
 for(const [name,path,body]of actions){assert.equal((await f.request(path,body)).status,200);const call=f.calls.at(-1);assert.equal(call.name,name);assert.equal(call.input.personaSession,session);assert.deepEqual(call.input.persona,{id:13,role:'admin'});assert.deepEqual(call.input.scope,scope);}
 const count=f.calls.length;
 for(const [,path,body]of actions){assert.equal((await f.request(body===null?`${path}?personaSession=forged`:path,body===null?null:{...body,personaSession:{sessionId:'forged',authorityVersion:'99'}})).status,400);}
 assert.equal(f.calls.length,count);
});
test('persona loss is 401 without falsely invalidating the platform launch',async t=>{
 const f=await mount(t,'SHOP_AUTH_INVALID'),r=await f.request('rotate',{});
 assert.equal(r.status,401);assert.equal(r.headers.get('x-dvaia-secureshop-launch-state'),null);
 assert.deepEqual(await r.json(),{error:'Shop authentication required'});
});
test('post-effect uncertainty exposes only safe nonretry metadata',async t=>{
 const f=await mount(t,'PERSONA_EFFECT_OUTCOME_UNCERTAIN'),r=await f.request('rotate',{});
 assert.equal(r.status,503);assert.equal(r.headers.get('x-dvaia-secureshop-launch-state'),null);
 assert.deepEqual(await r.json(),{error:'MCP operation outcome is unknown; do not automatically retry',code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',outcome:'unknown',automaticRetry:false});
});
test('platform launch loss still invalidates launch and unknown errors stay private',async t=>{
 const stale=await mount(t,'STALE_LAUNCH'),r=await stale.request('readiness',null);
 assert.equal(r.status,401);assert.equal(r.headers.get('x-dvaia-secureshop-launch-state'),'unavailable');
 const unknown=await mount(t,'PRIVATE_INTERNAL_CODE'),other=await unknown.request('readiness',null);
 assert.equal(other.status,503);assert.deepEqual(await other.json(),{error:'MCP trust exercise unavailable'});
});
