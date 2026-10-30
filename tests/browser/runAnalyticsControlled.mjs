import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {randomUUID,createHash} from 'node:crypto';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const clientRequire=createRequire(path.join(root,'client/package.json')),require=createRequire(path.join(root,'package.json'));
const {build}=await import(pathToFileURL(clientRequire.resolve('vite')));
const react=(await import(pathToFileURL(clientRequire.resolve('@vitejs/plugin-react')))).default;
const puppeteer=require('puppeteer');
const output=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-analytics-ui-'));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const evidence={kind:'controlled-browser-only',actualModelCalls:0,actualDatabaseQueries:0,checks:[],screenshots:[]};
let browser,server,packet=null,posts=0,recoveries=0;const packets=[];
try{
 await build({configFile:false,root:path.join(root,'client'),plugins:[react()],logLevel:'error',resolve:{alias:{react:path.join(root,'client/node_modules/react'),'react-dom':path.join(root,'client/node_modules/react-dom')}},define:{'process.env.NODE_ENV':'"production"'},build:{outDir:path.join(output,'build'),emptyOutDir:true,lib:{entry:path.join(root,'tests/browser/analyticsControlled.entry.jsx'),name:'AnalyticsFixture',formats:['iife'],fileName:()=> 'fixture.js',cssFileName:'fixture'}}});
 const bundle=await fs.readFile(path.join(output,'build/fixture.js')),css=await fs.readFile(path.join(output,'build/fixture.css'));
 evidence.bundleSha256=hash(bundle);evidence.cssSha256=hash(css);
 const scopeKey='a'.repeat(64);
 server=http.createServer(async(req,res)=>{
  try{
   const send=(body,status=200)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(body));};
   if(req.url==='/fixture.js'){res.writeHead(200,{'content-type':'text/javascript'});return res.end(bundle);}
   if(req.url==='/fixture.css'){res.writeHead(200,{'content-type':'text/css'});return res.end(css);}
   if(req.url==='/'){res.writeHead(200,{'content-type':'text/html; charset=utf-8'});return res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/fixture.css"><div id="root"></div><script src="/fixture.js"></script>');}
   if(req.url!=='/fixture-operation'||req.method!=='POST')return send({},404);
   let bytes='';for await(const chunk of req){bytes+=chunk;if(bytes.length>16384)throw Error('request too large');}
   const {name,input}=JSON.parse(bytes);
   if(name==='merchant.analytics.describe')return send({ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}});
   if(name==='merchant.analytics.topProducts')return send({rows:[{name:'Workshop product',revenue:'42.50'}]});
   if(name==='merchant.analytics.history')return send({entries:packets.map(value=>({...value,createdAt:'2026-09-20T12:00:00.000Z'})).reverse(),nextCursor:null});
   if(name==='merchant.analytics.request'){recoveries++;assert.equal(input.params.requestId,packet?.requestId);return send(packet);}
   if(name==='merchant.analytics.query'){
    posts++;assert.ok(posts<=3);const {question,requestId}=input.body,runId=randomUUID(),sessionId=randomUUID();
    const result={sql:'SELECT COUNT(*) AS count FROM products',columns:['count'],rows:[{count:'256'}],row_count:1,error:null};
    packet={...result,status:'completed',ok:true,question,answer:'There are 256 products.',requestId,runId,sessionId,provider:'controlled',model:'browser-fixture',receipt:{requestId,runId,sessionId,result},effectReceipt:{status:'completed',runId}};
    if(posts===2){const denied={sql:'SELECT api_key FROM shop_users',columns:[],rows:[],row_count:0,error:'Database permission denied (42501).'};packet={...packet,...denied,status:'denied',ok:false,responseSource:'server',answer:null,provider:null,model:null,receipt:{requestId,runId,sessionId,version:4,mode:{mode:'fixed'},result:denied,denial:{code:'42501',source:'postgresql',backendAbsent:true},protectedEvidence:{version:1,observations:[],truncated:false}}};}
    packets.push(packet);return posts===1?send({error:'Controlled lost acknowledgement'},502):send(packet);
   }
   return send({error:'Unsupported fixture operation'},404);
  }catch(error){evidence.serverError=error.message;res.writeHead(500);res.end('{}');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 browser=await puppeteer.launch({headless:true,timeout:30000});const page=await browser.newPage();page.setDefaultTimeout(15000);
 await page.emulateMediaFeatures([{name:'prefers-reduced-motion',value:'reduce'}]);
 await page.setRequestInterception(true);page.on('request',request=>{const url=request.url();if(url.startsWith(origin+'/')||url.startsWith('data:'))request.continue();else request.abort();});
 evidence.pageErrors=[];page.on('pageerror',error=>evidence.pageErrors.push(error.message));
 await page.setViewport({width:1280,height:900});await page.goto(origin,{waitUntil:'networkidle0'});
 await page.waitForSelector('[data-testid="analytics-input"]');await page.type('[data-testid="analytics-input"]','How many products are there?');
 await page.waitForFunction(()=>!document.querySelector('[data-testid="analytics-input"]').disabled);
 await page.keyboard.press('Enter');await page.waitForFunction(()=>document.body.innerText.includes('outcome is unverified'));
 const saved=await page.evaluate(()=>localStorage.getItem('ss_analytics_recovery'));assert.ok(saved);assert.ok(!saved.includes('How many')&&!saved.includes('SELECT'));
 evidence.checks.push('durable metadata-only reference after lost POST response');
 await page.reload({waitUntil:'networkidle0'});await page.waitForFunction(()=>document.body.innerText.includes('Saved query recovered. No query was repeated.'));
 assert.equal(posts,1);assert.equal(recoveries,1);assert.equal(await page.evaluate(()=>localStorage.getItem('ss_analytics_recovery')),null);
 const text=await page.evaluate(()=>document.body.innerText);assert.ok(text.includes('How many products are there?'));assert.ok(text.includes('There are 256 products.'));assert.ok(text.includes('SELECT COUNT(*) AS count FROM products'));
 evidence.checks.push('reload GET-only recovery renders original question SQL numeric result and model answer');
 await page.type('[data-testid="analytics-input"]','Read the protected synthetic key');await page.keyboard.press('Enter');await page.waitForFunction(()=>document.body.innerText.includes('Database permission denied (42501).'));await page.waitForFunction(()=>[...document.querySelectorAll('tbody td')].some(cell=>cell.textContent==='Denied'));assert.equal(await page.evaluate(()=>localStorage.getItem('ss_analytics_recovery')),null);
 await page.waitForFunction(()=>!document.querySelector('[data-testid="analytics-input"]').disabled);await page.type('[data-testid="analytics-input"]','Count products after denial');await page.keyboard.press('Enter');await page.waitForFunction(()=>(()=>{const header=[...document.querySelectorAll('.ss-card__meta')].find(el=>el.textContent.startsWith('SESSION HISTORY'));const section=header?.closest('section');return section?.textContent.includes('Count products after denial')&&section.querySelectorAll('tbody tr').length===3;})());assert.equal(posts,3);assert.equal(recoveries,1);evidence.checks.push('terminal permission denial visible in history; metadata cleared; subsequent question completes');
 for(const width of [1280,390]){
  await page.setViewport({width,height:1000});await page.evaluate(()=>window.scrollTo(0,0));
  // Recharts observes container resize asynchronously; measure the settled layout.
  await page.waitForFunction(()=>document.documentElement.scrollWidth<=innerWidth+1,{timeout:3000});
  const geometry=await page.evaluate(()=>{const panes=[...document.querySelector('.ss-analytics-grid').children].map(el=>el.getBoundingClientRect());const input=document.querySelector('[data-testid="analytics-input"]').getBoundingClientRect();return{viewport:innerWidth,document:document.documentElement.scrollWidth,panes:panes.map(({x,y,width,height})=>({x,y,width,height})),inputWidth:input.width};});assert.ok(geometry.document<=geometry.viewport+1,JSON.stringify(geometry));
  if(width<720){assert.ok(geometry.panes[1].y>=geometry.panes[0].y+geometry.panes[0].height);assert.ok(geometry.inputWidth>150);}else assert.equal(geometry.panes[0].y,geometry.panes[1].y);
  const filename=`analytics-${width}.png`;await page.screenshot({path:path.join(output,filename),fullPage:true});evidence.screenshots.push({filename,sha256:hash(await fs.readFile(path.join(output,filename))),geometry});
 }
 assert.deepEqual(evidence.pageErrors,[]);assert.equal(evidence.serverError,undefined);evidence.status='passed';
}catch(error){evidence.status='failed';evidence.failure=error.stack;process.exitCode=1;}
finally{if(browser)await browser.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}await fs.writeFile(path.join(output,'result.json'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify({output,status:evidence.status,failure:evidence.failure}));}
