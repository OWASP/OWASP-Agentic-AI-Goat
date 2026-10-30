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
const authHeaders = () => ({ 'x-owasp-ai-goat-secureshop-launch': launch,
  authorization: 'Bearer customer-41' });
const getWithBody = (url, headers, body) => new Promise((resolve, reject) => {
  const request = http.request(url, { method: 'GET', headers: { ...headers,
    'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, response => {
    response.resume(); response.once('end', () => resolve(response.statusCode));
  });
  request.once('error', reject); request.end(body);
});

function similarResult(productId, sessionId, requestId) {
  return { results: [{ id: 8, name: 'Public result', description: 'Owned description', price: 12,
    category: 'Home', image_url: '/public.png', images: ['/public.png'], stock_quantity: 4,
    avg_rating: 5, review_count: 2, privateVector: [1, 2] }], count: 1, mode: 'products',
  recommendation: 'A bounded recommendation.', seed: { id: productId, name: 'Seed', private: true },
  retrieved_context: [{ source: 'owned manual', score: 0.8 }], provider: 'ollama',
  model: 'llama3.1:8b', modeCapability: { effectiveMode: 'vuln' }, sessionId, requestId,
  privateTrace: 'omit' };
}

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

test('bounded similar lifecycle projects public DTOs and binds product, session and request IDs',async t=>{
  const sessionId=randomUUID(),requestId=randomUUID();let readState='completed';
  const f=await fixture(t,{
    async summary(){throw Error('unused');},
    async similar(input){f.record('legacy',input);return similarResult(input.productId);},
    async createSimilarSession(input){f.record('create',input);return {sessionId,private:'omit'};},
    async runSimilar(input){f.record('run',input);return similarResult(input.productId,input.sessionId,input.requestId);},
    async readSimilar(input){f.record('read',input);return readState==='completed'
      ?{status:'completed',result:similarResult(input.productId,input.sessionId,input.requestId),private:'omit'}
      :{status:readState,sessionId:input.sessionId,requestId:input.requestId,private:'omit'};},
  });
  const created=await fetch(`${f.base}/products/7/similar/session`,{method:'POST',headers:authHeaders()});
  assert.equal(created.status,200);assert.equal(created.headers.get('cache-control'),'no-store');
  assert.deepEqual(await created.json(),{sessionId});
  const run=await fetch(`${f.base}/products/7/similar`,{method:'POST',headers:{...authHeaders(),
    'content-type':'application/json'},body:JSON.stringify({sessionId,requestId})});
  assert.equal(run.status,200);const runBody=await run.json();
  assert.deepEqual(Object.keys(runBody).sort(),['count','mode','modeCapability','model','provider',
    'recommendation','requestId','results','retrieved_context','seed','sessionId']);
  assert.deepEqual(runBody.seed,{id:7,name:'Seed'});assert.equal(runBody.results[0].privateVector,undefined);
  assert.equal(runBody.sessionId,sessionId);assert.equal(runBody.requestId,requestId);
  const readUrl=`${f.base}/products/7/similar/sessions/${sessionId}/requests/${requestId}`;
  const completed=await fetch(readUrl,{headers:authHeaders()});
  assert.equal(completed.status,200);assert.deepEqual(await completed.json(),{status:'completed',result:runBody});
  readState='pending';const pending=await fetch(readUrl,{headers:authHeaders()});
  assert.equal(pending.status,202);assert.deepEqual(await pending.json(),{status:'pending',sessionId,requestId});
  readState='not_found';const missing=await fetch(readUrl,{headers:authHeaders()});
  assert.equal(missing.status,404);assert.deepEqual(await missing.json(),{status:'not_found',sessionId,requestId});
  const legacy=await fetch(`${f.base}/products/7/similar`,{headers:authHeaders()});
  assert.equal(legacy.status,200);const legacyBody=await legacy.json();
  assert.equal(legacyBody.sessionId,undefined);assert.equal(legacyBody.requestId,undefined);
  for(const [name,input] of f.calls){assert.deepEqual(input.scope,scope);assert.deepEqual(input.persona,{id:41,role:'customer'});
    assert.deepEqual(input.personaSession,personaSession);assert.equal(input.productId,7);
    assert.ok(input.signal instanceof AbortSignal,name);}
  assert.equal(f.legacyCalls(),0);
});

test('similar lifecycle rejects caller authority, malformed IDs, query and body before service dispatch',async t=>{
  let calls=0;const unused=async()=>{calls++;throw Error('invalid request reached service');};
  const f=await fixture(t,{summary:unused,similar:unused,createSimilarSession:unused,
    runSimilar:unused,readSimilar:unused});
  const sessionId=randomUUID(),requestId=randomUUID();
  for(const [path,options] of [
    ['/products/0/similar/session',{method:'POST',headers:authHeaders()}],
    ['/products/7/similar/session?owner=41',{method:'POST',headers:authHeaders()}],
    ['/products/7/similar/session',{method:'POST',headers:{...authHeaders(),'content-type':'application/json'},body:'{"owner":41}'}],
    ['/products/7/similar',{method:'POST',headers:{...authHeaders(),'content-type':'application/json'},body:JSON.stringify({sessionId,requestId,owner:41})}],
    ['/products/7/similar',{method:'POST',headers:authHeaders(),body:JSON.stringify({sessionId,requestId})}],
    [`/products/7/similar/sessions/${sessionId.toUpperCase()}/requests/${requestId}`,{headers:authHeaders()}],
    [`/products/7/similar/sessions/${sessionId}/requests/${requestId}?retry=true`,{headers:authHeaders()}],
  ])assert.equal((await fetch(f.base+path,options)).status,400,path);
  assert.equal(await getWithBody(`${f.base}/products/7/similar/sessions/${sessionId}/requests/${requestId}`,
    authHeaders(),'{}'),400);
  assert.equal((await fetch(`${f.base}/products/7/similar/session`,{method:'POST',headers:{
    ...authHeaders(),authorization:'Bearer merchant-41'}})).status,403);
  assert.equal((await fetch(`${f.base}/products/7/similar/session`,{method:'POST',headers:{
    'x-owasp-ai-goat-secureshop-launch':launch}})).status,401);
  assert.equal(calls,0);assert.equal(f.legacyCalls(),0);
});

test('every saved-similar lifecycle route requires a customer and rejects projected product mismatches',async t=>{
  const sessionId=randomUUID(),requestId=randomUUID(); let reads=0, runs=0, creates=0;
  const f=await fixture(t,{summary:async()=>({}),similar:async()=>similarResult(7),
    async createSimilarSession(){creates++;return {sessionId};},
    async runSimilar(input){runs++;return similarResult(input.productId,input.sessionId,input.requestId);},
    async readSimilar(input){reads++;return {status:'completed',result:similarResult(input.productId+1,input.sessionId,input.requestId)};}});
  const saved=`/products/7/similar/sessions/${sessionId}/requests/${requestId}`;
  const requests=[
    ['/products/7/similar/session',{method:'POST'}],
    ['/products/7/similar',{method:'POST',body:JSON.stringify({sessionId,requestId})}],
    [saved,{method:'GET'}],
  ];
  for(const [path,options] of requests){
    const response=await fetch(f.base+path,{...options,headers:{...authHeaders(),authorization:'Bearer merchant-41',
      ...(options.method==='POST'?{'content-type':'application/json'}:{})}});
    assert.equal(response.status,403,path);
  }
  for(const [path,options] of requests){
    const response=await fetch(f.base+path,{...options,headers:{'x-owasp-ai-goat-secureshop-launch':launch,
      ...(options.method==='POST'?{'content-type':'application/json'}:{})}});
    assert.equal(response.status,401,path);
  }
  const read=await fetch(f.base+saved,{headers:authHeaders()});
  assert.equal(read.status,503);
  assert.deepEqual(await read.json(),{error:'Bound SecureShop operation unavailable'});
  assert.equal(creates,0);assert.equal(runs,0);assert.equal(reads,1);assert.equal(f.legacyCalls(),0);
});

test('missing lifecycle methods return 503 while the legacy similar GET remains available',async t=>{
  const f=await fixture(t,{summary:async()=>({}),similar:async input=>similarResult(input.productId)});
  const sessionId=randomUUID(),requestId=randomUUID();
  for(const [path,method] of [['/products/7/similar/session','POST'],['/products/7/similar','POST'],
    [`/products/7/similar/sessions/${sessionId}/requests/${requestId}`,'GET']]){
    const response=await fetch(f.base+path,{method,headers:{...authHeaders(),
      ...(method==='POST'?{'content-type':'application/json'}:{})},
      ...(path.endsWith('/similar')?{body:JSON.stringify({sessionId,requestId})}:{})});
    assert.equal(response.status,503,path);
    assert.deepEqual(await response.json(),{error:'Bound SecureShop operation unavailable'});
  }
  assert.equal((await fetch(`${f.base}/products/7/similar`,{headers:authHeaders()})).status,200);
  assert.equal(f.legacyCalls(),0);
});

test('similar lifecycle rejects service responses for another product or request without leaking them',async t=>{
  const sessionId=randomUUID(),requestId=randomUUID();let mode='run',readMode='wrong-request';
  const f=await fixture(t,{summary:async()=>({}),similar:async input=>similarResult(input.productId),
    createSimilarSession:async()=>({sessionId}),
    runSimilar:async input=>mode==='run'
      ?similarResult(input.productId+1,input.sessionId,input.requestId)
      :similarResult(input.productId,input.sessionId,randomUUID()),
    readSimilar:async input=>readMode==='null'?null:readMode==='missing-result'
      ?{status:'completed'}:{status:'completed',result:
        similarResult(input.productId,input.sessionId,randomUUID())},
  });
  const options={method:'POST',headers:{...authHeaders(),'content-type':'application/json'},
    body:JSON.stringify({sessionId,requestId})};
  for(const next of ['run','request']){
    mode=next;const response=await fetch(`${f.base}/products/7/similar`,options);
    assert.equal(response.status,503);assert.deepEqual(await response.json(),
      {error:'Bound SecureShop operation unavailable'});
  }
  for(const next of ['wrong-request','null','missing-result']){
    readMode=next;
    const read=await fetch(`${f.base}/products/7/similar/sessions/${sessionId}/requests/${requestId}`,
      {headers:authHeaders()});
    assert.equal(read.status,503);assert.deepEqual(await read.json(),
      {error:'Bound SecureShop operation unavailable'});
  }
  assert.equal(f.legacyCalls(),0);
});

test('client disconnect aborts an admitted similar run',async t=>{
  let entered,stopped;const started=new Promise(resolve=>{entered=resolve;});
  const aborted=new Promise(resolve=>{stopped=resolve;});
  const f=await fixture(t,{summary:async()=>({}),similar:async()=>similarResult(7),
    createSimilarSession:async()=>({sessionId:randomUUID()}),readSimilar:async()=>({}),
    async runSimilar({signal}){entered();return new Promise((_resolve,reject)=>signal.addEventListener(
      'abort',()=>{stopped();reject(signal.reason);},{once:true}));}});
  const controller=new AbortController(),sessionId=randomUUID(),requestId=randomUUID();
  const pending=fetch(`${f.base}/products/7/similar`,{method:'POST',signal:controller.signal,
    headers:{...authHeaders(),'content-type':'application/json'},body:JSON.stringify({sessionId,requestId})});
  const rejected=assert.rejects(pending,{name:'AbortError'});await started;controller.abort();
  await rejected;await aborted;assert.equal(f.legacyCalls(),0);
});
