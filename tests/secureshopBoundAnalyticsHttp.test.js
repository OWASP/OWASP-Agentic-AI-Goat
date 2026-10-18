'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express'),{randomUUID}=require('node:crypto');
const {createBoundAnalyticsRouter}=require('../server/routes/secureshop/boundAnalytics');
test('Analytics routes keep POST execution separate from read-only recovery/history/chart and reject overrides',async t=>{
 const calls=[],scope={launchId:randomUUID()},persona={id:3,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1',expiresAt:'2026-09-21T00:00:00.000Z'};
 const application=Object.fromEntries(['describe','query','recover','history','topProducts'].map(method=>[method,async input=>{calls.push({method,input});return method==='recover'?{status:'uncertain'}:{rows:[],ok:true};}]));
 const app=express();app.use(express.json());app.use(createBoundAnalyticsRouter({application,authenticate:(req,_res,next)=>{req.ssLaunch=scope;req.boundPersona=persona;req.ssPersonaSession=personaSession;next();}}));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));const base='http://127.0.0.1:'+server.address().port;
 assert.equal((await fetch(base+'/')).status,200);
 const requestId=randomUUID();assert.equal((await fetch(base+'/query',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId,question:'count products'})})).status,200);
 assert.equal((await fetch(base+'/requests/'+requestId)).status,202);assert.equal((await fetch(base+'/history?limit=20')).status,200);assert.equal((await fetch(base+'/top-products?limit=8')).status,200);
 assert.deepEqual(calls.map(c=>c.method),['describe','query','recover','history','topProducts']);for(const call of calls){assert.equal(call.input.scope,scope);assert.deepEqual(call.input.personaSession,{sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion});}
 for(const body of [{requestId,question:'count',targetId:randomUUID()},{question:'count'},{requestId,question:'\0'}])assert.equal((await fetch(base+'/query',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})).status,400);
 for(const url of ['/top-products?limit=26','/top-products?sql=SELECT1','/history?limit=51','/requests/'+requestId+'?execute=true'])assert.equal((await fetch(base+url)).status,400);
 assert.equal(calls.length,5);
});
