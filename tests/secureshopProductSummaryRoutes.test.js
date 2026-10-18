'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const http = require('node:http');
const { randomUUID } = require('node:crypto');
const { createSecureShopBoundGateway } = require('../server/routes/secureshop/boundGateway');

const launch = 'l'.repeat(43);
const scope = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 3,
  platformOwnerId: 71, platformSessionId: 72 });
const personaSession = Object.freeze({ sessionId: randomUUID(), authorityVersion: '2' });
const authHeaders = () => ({ 'x-dvaia-secureshop-launch': launch,
  authorization: 'Bearer customer-41' });
const getWithBody = (url, headers, body) => new Promise((resolve, reject) => {
  const request = http.request(url, { method: 'GET', headers: { ...headers,
    'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, response => {
    response.resume(); response.once('end', () => resolve(response.statusCode));
  });
  request.once('error', reject); request.end(body);
});

function summaryResult(productId,sessionId,requestId){return {product_id:productId,name:'Owned',price:10,category:'Home',stock_quantity:1,
 description:'untrusted original',description_html:null,summary:'Original model answer',provider:'ollama',model:'controlled',sessionId,requestId,privateTrace:'omit'};}

async function fixture(t, productAssist) {
  const calls = []; let legacyCalls = 0;
  const record = (name, value) => { calls.push([name, value]); return value; };
  const personaAuth = {
    login: async()=>{},renew:async()=>{},logout:async()=>{},listSessions:async()=>[],
    revokeOwnedSession:async()=>true,changePassword:async()=>({}),listApiKey:async()=>({}),
    rotateApiKey:async()=>({}),authenticateApiKey:async()=>({}),
  };
  const catalog = {
    listProducts:async()=>({products:[],count:0,total:0}),getProduct:async()=>({}),
    listMerchantProducts:async()=>({products:[],total:0,categories:[]}),
    createMerchantProduct:async()=>({productId:1}),updateMerchantProduct:async()=>({productId:1}),
    archiveMerchantProduct:async()=>true,categories:async()=>({categories:[]}),
  };
  const commerce = Object.fromEntries(['cart','add','update','remove','summary','checkout','orders','order']
    .map(name=>[name,async()=>name==='orders'?[]:{}]));
  const account = Object.fromEntries(['profile','updateProfile','addresses','createAddress','updateAddress','deleteAddress']
    .map(name=>[name,async()=>name==='addresses'?[]:{}]));
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', createSecureShopBoundGateway({
    launches:{async resolveCapability(value){return value===launch?scope:null;}},
    authenticatePersona(req,res,next){
      const match=/^Bearer (customer|merchant|admin)-(\d+)$/.exec(req.get('authorization')||'');
      if(!match)return res.status(401).json({error:'Shop authentication required'});
      req.ssUser={id:Number(match[2]),role:match[1]};req.ssPersonaSession=personaSession;next();
    },personaAuth,reviewsRouter:express.Router(),browserRouter:express.Router(),catalog,commerce,account,
    productAssist,
  }));
  app.use('/api/secureshop',(req,res)=>{legacyCalls++;res.json({legacy:true,path:req.path});});
  const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
  return {base:`http://127.0.0.1:${server.address().port}/api/secureshop`,calls,record,
    legacyCalls:()=>legacyCalls};
}

test('summary session/run/saved routes preserve exact original identity and expose no private provenance',async t=>{
 const sessionId=randomUUID(),requestId=randomUUID();let status='completed';
 const f=await fixture(t,{summary:async input=>summaryResult(input.productId),similar:async()=>{},
  createSummarySession:async input=>{f.record('session',input);return {sessionId,recoveryKey:'a'.repeat(64),private:'omit'};},
  runSummary:async input=>{f.record('run',input);return summaryResult(input.productId,input.sessionId,input.requestId);},
  readSummary:async input=>{f.record('read',input);return status==='completed'?{status,result:summaryResult(input.productId,input.sessionId,input.requestId)}:{status,sessionId,requestId};}});
 const base=`${f.base}/products/7/summary`,headers={...authHeaders(),'content-type':'application/json'};
 const session=await fetch(`${base}/session`,{method:'POST',headers,body:'{}'});assert.equal(session.status,200);assert.deepEqual(await session.json(),{sessionId,recoveryKey:'a'.repeat(64)});
 const run=await fetch(base,{method:'POST',headers,body:JSON.stringify({sessionId,requestId})});assert.equal(run.status,200);
 const result=await run.json();assert.equal(result.sessionId,sessionId);assert.equal(result.requestId,requestId);assert.equal(result.privateTrace,undefined);
 const url=`${base}/sessions/${sessionId}/requests/${requestId}`;
 const read=await fetch(url,{headers});assert.equal(read.status,200);assert.equal(read.headers.get('cache-control'),'no-store');assert.deepEqual(await read.json(),{status:'completed',result});
 for(const value of ['pending','not_found']){status=value;const response=await fetch(url,{headers});assert.equal(response.status,value==='pending'?202:404);assert.deepEqual(await response.json(),{status:value,sessionId,requestId});}
 for(const [,input]of f.calls){assert.deepEqual(input.scope,scope);assert.deepEqual(input.persona,{id:41,role:'customer'});assert.deepEqual(input.personaSession,personaSession);assert.equal(input.productId,7);}
 assert.equal(f.legacyCalls(),0);
});
test('summary lifecycle rejects malformed or caller-supplied authority before dispatch and preserves old empty POST',async t=>{
 let calls=0,legacy=0;const unused=async()=>{calls++;throw Error('unexpected');};
 const f=await fixture(t,{summary:async input=>{legacy++;return summaryResult(input.productId);},similar:unused,
  createSummarySession:unused,runSummary:unused,readSummary:unused});
 const sessionId=randomUUID(),requestId=randomUUID(),base=`${f.base}/products/7/summary`,headers={...authHeaders(),'content-type':'application/json'};
 for(const body of [{sessionId},{requestId},{sessionId,requestId,mode:'vuln'},{sessionId,requestId,source:{}},{sessionId:'bad',requestId}])
  assert.equal((await fetch(base,{method:'POST',headers,body:JSON.stringify(body)})).status,400);
 assert.equal((await fetch(`${base}/session?owner=7`,{method:'POST',headers,body:'{}'})).status,400);
 assert.equal((await fetch(`${base}/sessions/${sessionId}/requests/${requestId}?owner=7`,{headers})).status,400);
 assert.equal(await getWithBody(`${base}/sessions/${sessionId}/requests/${requestId}`,headers,'{}'),400);
 assert.equal((await fetch(base,{method:'POST',headers:{...headers,authorization:'Bearer merchant-41'},body:JSON.stringify({sessionId,requestId})})).status,403);
 assert.equal(calls,0);assert.equal(legacy,0);
 const old=await fetch(base,{method:'POST',headers,body:'{}'});assert.equal(old.status,200);assert.equal((await old.json()).requestId,undefined);assert.equal(legacy,1);assert.equal(f.legacyCalls(),0);
});
test('summary saved projection rejects crossed original IDs without leaking source and missing adapters stay unavailable',async t=>{
 const sessionId=randomUUID(),requestId=randomUUID();
 const f=await fixture(t,{summary:async()=>{},similar:async()=>{},readSummary:async()=>({status:'completed',result:summaryResult(7,sessionId,randomUUID())})});
 const read=await fetch(`${f.base}/products/7/summary/sessions/${sessionId}/requests/${requestId}`,{headers:authHeaders()});assert.equal(read.status,503);
 const missing=await fetch(`${f.base}/products/7/summary/session`,{method:'POST',headers:authHeaders()});assert.equal(missing.status,503);assert.equal(f.legacyCalls(),0);
});
