'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { createApplicationCors } = require('../server/middleware/applicationCors');

test('real opaque frame uses closed bridge for HTTP/SSE without receiving launch or platform credentials', { timeout: 30000 }, async t => {
  let browser, server, profile;
  let phase="setup";const failedModules=new Set();
  t.after(()=>t.diagnostic(JSON.stringify({phase,failedModules:[...failedModules].slice(0,20)})));
  t.after(()=>retireFixture(browser,server,profile));
  const app = express();
  const modules = require('./fixtures/secureshopBridgeBrowserModules').loadModules();
  app.use((req,res,next)=>{const source=modules.get(req.path);if(source!==undefined)return res.set('Access-Control-Allow-Origin','*').type('js').send(source);next();});
  app.get('/', (req, res) => res.type('html').send(`<!doctype html><body><script type="module">
    import {mountShopFrame} from '/handshake.mjs';
    import {compileBridgeOperation as compileOperation} from '/compiler.mjs';
    import {createScopedShopStateStore} from '/stateStore.mjs';
    window.prepare = launch => {
      const target = document.createElement('iframe');target.id='target';
      const stateStore=createScopedShopStateStore({storage:localStorage,scenarioId:'11111111-1111-4111-8111-111111111111',generation:1,isCurrent:()=>true});
      window.hostSession=mountShopFrame({frame:target,url:'/frame',origin:location.origin,compileOperation,getLaunchBearer:()=>launch,stateStore});
      window.hostSession.ready.then(transport=>window.hostTransport=transport);
      const sibling = document.createElement('iframe');sibling.id='sibling';sibling.sandbox='allow-scripts';sibling.src=target.src;
      window.rejected=0;
      window.addEventListener('message',event=>{if(event.source===sibling.contentWindow && event.data?.type==='ready')window.rejected++;});
      document.body.append(target,sibling);
    };
  </script></body>`));
  app.get('/frame', (req, res) => res.type('html').send(`<!doctype html><body>Opaque frame fixture<script type="module">
    import {startShopFrame} from '/runtime.mjs';
    import {shopStorage,flushShopStorage} from '/utils/shopStorage.mjs';
    window.nativeProbeFetch=window.fetch.bind(window);
    startShopFrame({origin:location.origin,render:()=>{
      window.bridge=true;window.shopState=shopStorage;window.flushShopState=flushShopStorage;window.shopFetch=(...args)=>window.fetch(...args);
      return()=>{window.bridge=false;};
    }}).then(runtime=>window.frameRuntime=runtime).catch(()=>{});
  </script></body>`));
  let applicationCors;
  app.use((req, res, next) => applicationCors(req, res, next));app.use(express.json());
  const launch = crypto.randomBytes(32).toString('base64url');
  const platform = crypto.randomBytes(16).toString('hex');
  const observed = [];
  app.use('/api/secureshop', (req, res, next) => {
    observed.push({ launch: req.get('X-DVAIA-SecureShop-Launch'), auth: req.get('Authorization'), cookie: req.get('Cookie') });
    if (req.get('X-DVAIA-SecureShop-Launch') !== launch) return res.sendStatus(403);next();
  });
  app.get('/api/secureshop/products', (req, res) => res.set('X-Private', 'do-not-forward').json({ products: [{ id: 1, name: 'Synthetic teaching item' }] }));
  const transcript = 'event: assistant_message\ndata: {"text":"synthetic observation"}\n\nevent: done\ndata: {"stopReason":"completed"}\n\n';
  let resolveStreamClosed;
  const streamClosed = new Promise(resolve => { resolveStreamClosed = resolve; });
  app.post('/api/secureshop/agents/customer/chat', (req, res) => {
    res.type('text/event-stream');res.write(transcript.slice(0, 17));
    if (req.body.message === 'hold-until-navigation') { res.once('close', resolveStreamClosed);return; }
    setImmediate(() => res.end(transcript.slice(17)));
  });
  let uploaded;
  app.post('/api/secureshop/uploads', require('multer')({storage:require('multer').memoryStorage(),limits:{fileSize:20*1024*1024}}).single('file'), (req,res)=>{
    uploaded={filename:req.file.originalname,mime:req.file.mimetype,bytes:[...req.file.buffer],fields:{...req.body}};
    res.json({ok:true,size:req.file.size});
  });
  let platformEffects=0;app.post('/api/auth/probe', (req, res) => { platformEffects++;res.json({ ok:true }); });
  server=http.createServer(app);await bounded(new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);}),10000);
  const origin=`http://127.0.0.1:${server.address().port}`;
  applicationCors=createApplicationCors({secureShopOrigins:[origin]});
  profile=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-shop-bridge-browser-'));
  browser=await require('puppeteer').launch({headless:true,timeout:15000,protocolTimeout:15000,userDataDir:profile,...(process.env.PUPPETEER_EXECUTABLE_PATH?{executablePath:process.env.PUPPETEER_EXECUTABLE_PATH}:{})});
  const page=await browser.newPage();page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);await page.setRequestInterception(true);
  page.on('request',r=>r.url().startsWith(origin+'/')?r.continue():r.abort());
  page.on('response',r=>{const u=new URL(r.url());if(u.origin===origin&&u.pathname.endsWith('.mjs')&&r.status()>=400)failedModules.add(u.pathname.slice(0,160));});
  phase='parent-module-ready';await page.goto(origin);await page.waitForFunction(()=>typeof window.prepare==='function');
  await page.evaluate(({launch,platform})=>{localStorage.setItem('platform_token',platform);document.cookie='platformCookie=synthetic; SameSite=Strict';window.prepare(launch);},{launch,platform});
  phase='sibling-handshake';await page.waitForFunction(()=>window.rejected>=1);
  const target=await (await page.$('#target')).contentFrame();const sibling=await (await page.$('#sibling')).contentFrame();
  phase='target-ready';await target.waitForFunction(()=>Boolean(window.bridge));
  assert.equal(await sibling.evaluate(()=>Boolean(window.bridge)),false);
  await target.evaluate(async()=>{shopState.setItem('secureshop_v2_token','learner-crafted');shopState.setItem('ss_guest_cart','[{"id":7}]');await flushShopState();});
  const persisted=await page.evaluate(()=>JSON.parse(localStorage.getItem('dvaia:secureshop:11111111-1111-4111-8111-111111111111:1')));
  assert.deepEqual(persisted,{secureshop_v2_token:'learner-crafted',ss_guest_cart:'[{"id":7}]'});
  const result=await target.evaluate(async()=>{
    let denied=false;try{parent.localStorage.getItem('platform_token');}catch(e){denied=e.name==='SecurityError';}
    const response=await shopFetch('/api/secureshop/products');
    const products=await response.json();const headers=[...response.headers.keys()];
    const stream=await shopFetch('/api/secureshop/agents/customer/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sessionId:'synthetic-session',message:'hello'})});
    let unknownRejected=false;try{await shopFetch('/api/auth/probe');}catch{unknownRejected=true;}
    let directRejected=false;try{await nativeProbeFetch('/api/auth/probe',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});}catch{directRejected=true;}
    return {denied,products,headers,stream:await stream.text(),unknownRejected,directRejected};
  });
  assert.equal(result.denied,true);assert.equal(result.unknownRejected,true);assert.equal(result.directRejected,true);
  assert.equal(result.products.products[0].name,'Synthetic teaching item');assert.deepEqual(result.headers,['content-type']);assert.equal(result.stream,transcript);
  assert.equal(platformEffects,0);assert.equal(observed.length,2);
  for(const request of observed){assert.equal(request.launch,launch);assert.equal(request.auth,'Bearer learner-crafted');assert.equal(request.cookie,undefined);}
  assert.ok(!JSON.stringify(result).includes(launch));assert.ok(!JSON.stringify(result).includes(platform));
  assert.equal(await page.evaluate(()=>localStorage.getItem('platform_token')),platform);
  const uploadResult=await target.evaluate(async()=>{
    const form=new FormData();form.append('file',new Blob([new Uint8Array([0,255,1,60,62])],{type:'text/html'}),'lesson.html');
    for(const [key,value] of Object.entries({kind:'product_manual',scope_id:'7',mime:'text/html',public:'true'}))form.append(key,value);
    return (await shopFetch('/api/secureshop/uploads',{method:'POST',body:form})).json();
  });
  assert.deepEqual(uploadResult,{ok:true,size:5});
  assert.deepEqual(uploaded,{filename:'lesson.html',mime:'text/html',bytes:[0,255,1,60,62],fields:{kind:'product_manual',scope_id:'7',mime:'text/html',public:'true'}});
  assert.equal(observed[2].launch,launch);assert.equal(observed[2].auth,'Bearer learner-crafted');assert.equal(observed[2].cookie,undefined);
  assert.equal(await target.evaluate(async() => (await shopFetch('/api/secureshop/agents/customer/chat', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sessionId:'synthetic-session',message:'hold-until-navigation'})})).status), 200);
  await page.evaluate(() => { const frame=document.querySelector('#target');const url=new URL(frame.src);url.search='navigation=1';frame.src=url.href; });
  phase='navigation-stream-close';await bounded(streamClosed,10000);
  await page.evaluate(launch=>{hostSession.close();document.querySelectorAll('iframe').forEach(frame=>frame.remove());window.prepare(launch);},launch);
  const renewed=await (await page.$('#target')).contentFrame();await renewed.waitForFunction(()=>Boolean(window.bridge));
  const restored=await renewed.evaluate(async()=>({token:shopState.getItem('secureshop_v2_token'),cart:shopState.getItem('ss_guest_cart'),status:(await shopFetch('/api/secureshop/products')).status}));
  assert.deepEqual(restored,{token:'learner-crafted',cart:'[{"id":7}]',status:200});
  assert.equal(await page.evaluate(()=>localStorage.getItem('platform_token')),platform);
  await page.evaluate(()=>hostSession.close());phase='completed';
});

async function bounded(work, ms=5000) {
  let timer;
  try { return await Promise.race([work, new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned fixture deadline; retain data for outer retirement')),ms);})]); }
  finally { clearTimeout(timer); }
}
async function retireFixture(browser, server, root) {
  const results=await Promise.allSettled([
    bounded(Promise.resolve().then(()=>browser?.close())),
    bounded(Promise.resolve().then(()=>{server?.closeAllConnections();return server?.listening?new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())):undefined;})),
  ]);
  const failures=results.filter(r=>r.status==='rejected').map(r=>r.reason);
  if(failures.length)throw new AggregateError(failures,'Owned cleanup uncertain; fixture retained');
  if(root)await fs.rm(root,{recursive:true,force:true});
}
