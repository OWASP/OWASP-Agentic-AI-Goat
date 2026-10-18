'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { createBoundSystemHealthService } = require('../server/services/secureshopBoundSystemHealthService');
const { createBoundSystemHealthRouter } = require('../server/routes/secureshop/boundSystemHealth');
const good = { version:'secureshop-owned-system-metrics.v1', ok:true, hostname:'listener', platform:'linux', node:'node-v26', uptime_s:3, loadavg:null, freemem_mb:2, totalmem_mb:4, ts:'2026-09-20T00:00:00.000Z', metricsSource:'owned-system-listener', memorySource:'cgroup-v2', uptimeSource:'listener-process', loadSource:'unavailable' };
const context = { scope:{ launchId:1 }, persona:{ id:2, role:'admin' }, personaSession:{ sessionId:'s', authorityVersion:'1' } };
function request(s, path='/admin/system/health') { return new Promise((resolve,reject)=>{const r=http.get({host:'127.0.0.1',port:s.address().port,path},res=>{let b='';res.setEncoding('utf8');res.on('data',x=>b+=x);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:b?JSON.parse(b):null}));});r.on('error',reject);}); }

test('health brackets owned metrics with original authority and preserves null fields', async () => {
  const calls=[]; const service=createBoundSystemHealthService({ repository:{ async administration(){ calls.push('authority'); return {scopeKey:'a'.repeat(64)}; } }, metrics:{ async snapshot(){ calls.push('metrics'); return good; } } });
  assert.deepEqual(await service.health(context), good); assert.deepEqual(calls,['authority','metrics','authority']);
});
test('health rejects revocation after remote metrics and aborts before/after work', async () => {
  let n=0; const service=createBoundSystemHealthService({ repository:{ async administration(){ n++; if(n===2) return {scopeKey:'b'.repeat(64)}; return {scopeKey:'a'.repeat(64)}; } }, metrics:{ snapshot(){ return good; } } });
  await assert.rejects(service.health(context), e=>e.code==='STALE_AUTHORITY');
  const c=new AbortController(); c.abort(); await assert.rejects(service.health(context,{signal:c.signal}), /aborted/i);
});
test('health rejects wrong source and malformed metrics', async () => {
  const repository={async administration(){return {scopeKey:'a'.repeat(64)};}};
  for (const change of [{metricsSource:'host'}, {uptime_s:null}, {loadavg:0}, {ts:'9999-99-99T00:00:00.000Z'}]) {
    await assert.rejects(createBoundSystemHealthService({repository,metrics:{snapshot:async()=>({...good,...change})}}).health(context), e=>e.code==='SYSTEM_HEALTH_INVALID');
  }
});
test('health aborts while owned metrics are pending and freezes one context snapshot', async () => {
  const controller=new AbortController(); let seen; let release;
  const pending=new Promise(resolve=>{release=resolve;});
  const service=createBoundSystemHealthService({repository:{async administration(input){seen ??= input; return {scopeKey:'a'.repeat(64)};}},metrics:{async snapshot(){await pending; return good;}}});
  const original=structuredClone(context); const work=service.health(context,{signal:controller.signal}); context.persona.id=999; controller.abort(); release(); await assert.rejects(work,/aborted/i); assert.deepEqual(seen,original);
});
test('bound health route rejects query parameters and requires admin while setting no-store', async () => {
  const app=express(); const service={health:async()=>good}; app.use(createBoundSystemHealthRouter({service,authenticatePersona(req,_res,next){if(req.headers['x-auth']==='missing') return next(); req.ssLaunch={launchId:1}; req.ssUser={id:1,role:req.headers['x-role']||'admin'}; req.ssPersonaSession={sessionId:'s',authorityVersion:'1'}; next();}}));
  const s=await new Promise(resolve=>{const x=app.listen(0,'127.0.0.1',()=>resolve(x));});
  try { const q=await request(s,'/admin/system/health?x=1'); assert.equal(q.status,400); assert.equal(q.headers['cache-control'],'no-store'); const ok=await request(s); assert.equal(ok.status,200); assert.equal(ok.body.version,good.version); const missing=await new Promise((resolve,reject)=>{const r=http.get({host:'127.0.0.1',port:s.address().port,path:'/admin/system/health',headers:{'x-auth':'missing'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});r.on('error',reject);}); assert.equal(missing,401); const denied=await new Promise((resolve,reject)=>{const r=http.get({host:'127.0.0.1',port:s.address().port,path:'/admin/system/health',headers:{'x-role':'customer'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});r.on('error',reject);}); assert.equal(denied,403); } finally { s.close(); }
});
test('bound health route maps authority/admin failures without exposing error details', async () => {
  for (const [code, expected] of [['SHOP_AUTH_INVALID',401], ['SESSION_UNAVAILABLE',401], ['STALE_AUTHORITY',401], ['SYSTEM_HEALTH_AUTH_INVALID',401], ['ADMIN_REQUIRED',403], ['PRIVATE_DATABASE_DETAIL',503]]) {
    const app=express(); app.use(createBoundSystemHealthRouter({service:{health:async()=>{throw Object.assign(new Error('private detail'),{code});}},authenticatePersona(req,_res,next){req.ssLaunch={launchId:1};req.ssUser={id:1,role:'admin'};req.ssPersonaSession={sessionId:'s',authorityVersion:'1'};next();}}));
    const s=await new Promise(resolve=>{const x=app.listen(0,'127.0.0.1',()=>resolve(x));});
    try { const result=await request(s); assert.equal(result.status,expected); assert.deepEqual(result.body,{ok:false,error:'Bound System health unavailable'}); } finally { s.close(); }
  }
});
