'use strict';
const test=require('node:test'); const assert=require('node:assert/strict'); const http=require('node:http'); const crypto=require('node:crypto');
const {createSystemConfigHttpHandler}=require('../sidecars/sandbox-runner/owned-system/http-handler');
const {createSecureShopSystemConfigClient}=require('../server/services/secureshopSystemConfigClient');
const token=crypto.randomBytes(32).toString('base64url');
const metrics={version:'secureshop-owned-system-metrics.v1',ok:true,hostname:'listener',platform:'linux',node:'node-v26',uptime_s:2,loadavg:null,freemem_mb:null,totalmem_mb:null,ts:'2026-09-20T00:00:00.000Z',metricsSource:'owned-system-listener',memorySource:'unavailable',uptimeSource:'listener-process',loadSource:'unavailable'};
test('owned handler and client expose authenticated strict metrics snapshot',async()=>{
 const handler=createSystemConfigHttpHandler({enabled:true,token,executor:{assertReady(){return true;},read(){throw Error('unused');}},metrics:{snapshot(){return metrics;}}});
 const server=http.createServer((req,res)=>handler.handle(req,res).then(ok=>{if(!ok){res.writeHead(404);res.end();}})); await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 try { const client=createSecureShopSystemConfigClient({baseURL:`http://127.0.0.1:${server.address().port}`,token}); assert.deepEqual(await client.metrics(),metrics); const bad=await fetch(`http://127.0.0.1:${server.address().port}/secureshop/system/metrics`); assert.equal(bad.status,401); } finally {await handler.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('owned handler rejects asynchronous metrics providers instead of escaping active bounds',async()=>{
 const handler=createSystemConfigHttpHandler({enabled:true,token,executor:{assertReady(){return true;},read(){throw Error('unused');}},metrics:{snapshot:async()=>metrics}}); const server=http.createServer((req,res)=>handler.handle(req,res)); await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {const response=await fetch(`http://127.0.0.1:${server.address().port}/secureshop/system/metrics`,{headers:{authorization:`Bearer ${token}`}}); assert.equal(response.status,503); assert.deepEqual(await response.json(),{error:'SYSTEM_METRICS_UNAVAILABLE'});} finally {await handler.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('owned handler absorbs rejected asynchronous metrics providers',async()=>{
 const handler=createSystemConfigHttpHandler({enabled:true,token,executor:{assertReady(){return true;},read(){throw Error('unused');}},metrics:{snapshot:async()=>{throw Error('private metrics failure');}}}); const server=http.createServer((req,res)=>handler.handle(req,res)); await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {const response=await fetch(`http://127.0.0.1:${server.address().port}/secureshop/system/metrics`,{headers:{authorization:`Bearer ${token}`}}); assert.equal(response.status,503); assert.deepEqual(await response.json(),{error:'SYSTEM_METRICS_UNAVAILABLE'});} finally {await handler.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
