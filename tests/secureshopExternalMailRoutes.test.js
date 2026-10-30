'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {once}=require('node:events');
const {createExternalMailRouter}=require('../server/routes/secureshopExternalMail');
const launch={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',
  generation:1,platformOwnerId:1,platformSessionId:2};
async function fixture(t) {
  const calls=[],cookie='a'.repeat(43),bearer='b'.repeat(43);
  const application=Object.fromEntries(['readiness','read','prepare','confirm','cancel'].map(name=>[name,async(...args)=>{
    calls.push({name,args});return{version:1,controlled:true};
  }]));
  const app=express();app.use(express.json({limit:'1mb'})); // Existing app parser must not bypass narrow body bound.
  app.use('/api/secureshop/auth/external-mail',createExternalMailRouter({application,
    authService:{authenticate:async token=>token===cookie?{role:'merchant',principalId:'owner'}:null},
    launches:{resolveCapability:async token=>token===bearer?launch:null},
    personaAuth:{authenticatePersona:(req,res,next)=>{
      if(req.get('Authorization')!=='Bearer persona')return res.status(401).json({error:'no persona'});
      req.ssUser={id:3,role:'merchant'};req.ssPersonaSession={sessionId:'session'};next();
    }},allowedOrigins:['http://parent.test']}));
  const server=app.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  const base=`http://127.0.0.1:${server.address().port}/api/secureshop/auth/external-mail`;
  const headers={Cookie:`owasp_ai_goat_shop_session=${cookie}`,'X-OWASP-AI-GOAT-SecureShop-Launch':bearer,Authorization:'Bearer persona'};
  return{calls,base,headers};
}
test('parent GET without Origin works, no-store; explicit opaque/foreign origin denied before dispatch',async t=>{
  const f=await fixture(t);
  for(const origin of [undefined,'null','https://foreign.test']){
    const response=await fetch(`${f.base}/readiness`,{headers:{...f.headers,...(origin?{Origin:origin}:{})}});
    assert.equal(response.status,origin?403:200);assert.equal(response.headers.get('cache-control'),'no-store');
    await response.json();
  }
  assert.equal(f.calls.length,1);assert.equal(f.calls[0].args[0].principal.principalId,'owner');
});
test('child persona/bearer alone never grants external send; duplicate cookies rejected',async t=>{
  const f=await fixture(t);
  for(const Cookie of ['',`${f.headers.Cookie}; ${f.headers.Cookie}`]){
    const response=await fetch(`${f.base}/confirm`,{method:'POST',
      headers:{...f.headers,Cookie,Origin:'http://parent.test','Content-Type':'application/json'},body:'{}'});
    assert.equal(response.status,401);await response.json();
  }
  assert.equal(f.calls.length,0);
});
test('POST requires exact parent origin and JSON; no query/descriptors or oversized parsed body',async t=>{
  const f=await fixture(t);
  const cases=[
    {headers:{'Content-Type':'application/json'},body:'{}',status:403},
    {headers:{Origin:'http://parent.test','Content-Type':'text/plain'},body:'{}',status:415},
    {headers:{Origin:'http://parent.test','Content-Type':'application/json'},body:JSON.stringify({x:'x'.repeat(2100)}),status:400},
    {headers:{Origin:'http://parent.test','Content-Type':'application/json'},body:'{}',query:'?recipient=secret',status:400},
  ];
  for(const v of cases){const response=await fetch(`${f.base}/prepare${v.query||''}`,
    {method:'POST',headers:{...f.headers,...v.headers},body:v.body});assert.equal(response.status,v.status);await response.json();}
  assert.equal(f.calls.length,0);
});
test('accepted parent mutation passes only authenticated context and abort signal to application',async t=>{
  const f=await fixture(t);const body={version:1,operationId:'fixed',requestSha256:'digest'};
  const response=await fetch(`${f.base}/confirm`,{method:'POST',headers:{...f.headers,
    Origin:'http://parent.test','Content-Type':'application/json'},body:JSON.stringify(body)});
  assert.equal(response.status,200);await response.json();
  assert.equal(f.calls.length,1);assert.deepEqual(f.calls[0].args[1],body);
  assert.deepEqual(f.calls[0].args[0].scope,launch);assert.ok(f.calls[0].args[2].signal instanceof AbortSignal);
});
