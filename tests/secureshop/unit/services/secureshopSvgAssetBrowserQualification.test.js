'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createHash } = require('node:crypto');
const { createSecureShopSvgAssetBrowserQualification } = require('../../../../server/services/secureshopSvgAssetBrowserQualification');
const URL = 'http://127.0.0.2:43191/assets/abc_DEF-123';
const ORIGIN = 'http://127.0.0.2:43191';
const marker = 'owasp-ai-goat-v08-7bb6c3f5';
const body = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg"><script>console.log('${marker}')</script></svg>`);
const sha = value => createHash('sha256').update(value).digest('hex');
function environment({bytes=body,contentType='image/svg+xml',csp='sandbox allow-scripts',count=1,consoleContext=7,scriptContext=7,consoleScriptId='s1',source=`console.log('${marker}')`,subresource=false,repeatNavigation=false,closeFails=false,pageCloseHangs=false,gotoHangs=false,teardownHangs=false,flood=false}={}) {
  const state={browserCreates:0,aborted:[],continued:0,pageClosed:0,contextClosed:0,browserClosed:0};
  class Cdp extends EventEmitter {
    async send(method,args){
      if(teardownHangs&&method==='Runtime.disable')return new Promise(()=>{});
      if(method==='Profiler.takePreciseCoverage')return{result:[{scriptId:'s1',functions:[{ranges:[{count}]}]}]};
      if(method==='Debugger.getScriptSource'){assert.equal(args.scriptId,'s1');return{scriptSource:source};}
      return{};
    }
    async detach(){}
  }
  class Page extends EventEmitter {
    constructor(){super();this.cdp=new Cdp();this.frame={};}
    mainFrame(){return this.frame;}
    async createCDPSession(){return this.cdp;}
    async setRequestInterception(value){assert.equal(value,true);}
    async goto(url){
      if(gotoHangs)return new Promise(()=>{});
      const req=(value,navigation=true)=>({url:()=>value,method:()=> 'GET',frame:()=>this.frame,isNavigationRequest:()=>navigation,headers:()=>({accept:'image/svg+xml'}),resourceType:()=>navigation?'document':'image',continue:async()=>{state.continued++;},abort:async()=>{state.aborted.push(value);}});
      this.emit('request',req(url));
      if(repeatNavigation)this.emit('request',req(url));
      if(subresource)this.emit('request',req('https://untrusted.invalid/a.png',false));
      this.cdp.emit('Debugger.scriptParsed',{scriptId:'s1',url,executionContextId:scriptContext});
      this.cdp.emit('Runtime.consoleAPICalled',{executionContextId:consoleContext,args:[{value:marker}],stackTrace:{callFrames:[{scriptId:consoleScriptId}]}});
      if(flood)for(let i=0;i<65;i++)this.cdp.emit('Runtime.consoleAPICalled',{executionContextId:7,args:[{value:'flood'}],stackTrace:{callFrames:[{scriptId:'s1'}]}});
      return{url:()=>url,status:()=>200,headers:()=>({'content-type':contentType,'content-security-policy':csp}),buffer:async()=>bytes};
    }
    async cookies(){return[];}
    async close(){state.pageClosed++;if(pageCloseHangs)return new Promise(()=>{});}
  }
  const context={async newPage(){return new Page();},async cookies(){return[];},async close(){state.contextClosed++;if(closeFails)throw Error('controlled close failure');}};
  const browser={async createBrowserContext(){state.browserCreates++;return context;},async disconnect(){state.browserClosed++;}};
  return{state,connectBrowser:async()=>browser};
}
function input(overrides={}){return{assetUrl:URL,expected:{byteCount:body.length,bodySha256:sha(body),contentType:'image/svg+xml',contentSecurityPolicy:'sandbox allow-scripts',marker,...overrides}};}
async function run(options={},expectedOverrides={}){
  const env=environment(options),q=createSecureShopSvgAssetBrowserQualification({assetOrigin:ORIGIN,connectBrowser:env.connectBrowser,timeoutMs:500,startupTimeoutMs:500,idleCloseMs:100,retirementTimeoutMs:500});
  try{return{result:await q.qualify(input(expectedOverrides)),state:env.state};}finally{await q.close();}
}
test('exact actual SVG response bytes execute an attributed script and effect',async()=>{
  const {result,state}=await run({subresource:true});
  assert.equal(result.executed,true);assert.equal(result.asset.bodySha256,sha(body));assert.equal(result.asset.byteCount,body.length);
  assert.equal(result.script.sourceSha256,sha(`console.log('${marker}')`));assert.equal(result.script.markerObserved,true);
  assert.deepEqual(result.blockedRequests,[{url:'https://untrusted.invalid/a.png',resourceType:'image',reason:'subresource'}]);
  assert.deepEqual(state.aborted,['https://untrusted.invalid/a.png']);assert.equal(state.continued,1);
});
test('serve, load and onload without covered inline script cannot qualify',async()=>{
  const inert=Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" onload="console.log('${marker}')"/>`);
  const {result}=await run({bytes:inert,source:'',count:0},{byteCount:inert.length,bodySha256:sha(inert)});
  assert.equal(result.executed,false);assert.equal(result.reason,'svg_inline_script_unavailable');
});
test('changed response bytes fail before execution evidence',async()=>{
  const changed=Buffer.from(body);changed[changed.length-2]^=1;
  const {result}=await run({bytes:changed});assert.equal(result.executed,false);assert.equal(result.reason,'asset_bytes_mismatch');
});
test('HTML MIME or missing exact sandbox policy fails closed',async()=>{
  assert.equal((await run({contentType:'text/html'})).result.reason,'asset_headers_mismatch');
  assert.equal((await run({csp:'sandbox allow-scripts allow-same-origin'})).result.reason,'asset_headers_mismatch');
});
test('uncovered script and marker from another execution context cannot qualify',async()=>{
  assert.equal((await run({count:0})).result.reason,'svg_script_not_executed');
  assert.equal((await run({consoleContext:8})).result.reason,'svg_effect_not_observed');
  assert.equal((await run({consoleScriptId:'foreign'})).result.reason,'svg_effect_not_observed');
});
test('substituted script source and marker claim cannot qualify',async()=>{
  assert.equal((await run({source:`console.log('${marker}');console.log('extra')`})).result.reason,'svg_script_not_executed');
});

test('ambiguous XML representations fail unavailable',async()=>{
  for(const text of [
    `<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[console.log('${marker}')]]></script></svg>`,
    `<svg xmlns="http://www.w3.org/2000/svg"><script>console.log(&quot;${marker}&quot;)</script></svg>`,
    `<svg xmlns="http://www.w3.org/2000/svg"><script>console.log('${marker}')</script><script>console.log('${marker}')</script></svg>`,
  ]){const value=Buffer.from(text),{result}=await run({bytes:value},{byteCount:value.length,bodySha256:sha(value)});assert.equal(result.executed,false);assert.equal(result.reason,'svg_inline_script_unavailable');}
});



test('only one exact main-frame navigation is admitted and observation floods fail closed',async()=>{
  const repeated=await run({repeatNavigation:true});assert.equal(repeated.result.executed,true);assert.equal(repeated.state.continued,1);assert.deepEqual(repeated.state.aborted,[URL]);
  const flooded=await run({flood:true});assert.equal(flooded.result.executed,false);assert.equal(flooded.result.reason,'browser_observation_overflow');
});
test('hung CDP teardown is bounded and still closes the owned context',async()=>{
  const env=environment({teardownHangs:true}),q=createSecureShopSvgAssetBrowserQualification({assetOrigin:ORIGIN,connectBrowser:env.connectBrowser,timeoutMs:500,startupTimeoutMs:500,idleCloseMs:100,retirementTimeoutMs:100});
  await assert.rejects(q.qualify(input()),error=>error.code==='BROWSER_RETIREMENT_INCOMPLETE'&&error.phase==='cdp_teardown');
  assert.equal(env.state.pageClosed,1);assert.equal(env.state.contextClosed,1);await q.close();
});


test('hung page close still attempts context close and poisons queued work',async()=>{
  const env=environment({pageCloseHangs:true}),q=createSecureShopSvgAssetBrowserQualification({assetOrigin:ORIGIN,connectBrowser:env.connectBrowser,timeoutMs:500,startupTimeoutMs:500,idleCloseMs:100,retirementTimeoutMs:100});
  await assert.rejects(q.qualify(input()),error=>error.code==='BROWSER_RETIREMENT_INCOMPLETE'&&error.phase==='page_close');
  assert.equal(env.state.contextClosed,1);await assert.rejects(q.qualify(input()),error=>error.code==='BROWSER_RETIREMENT_INCOMPLETE');await q.close();
});
test('expired in-flight work has a hard retirement bound and terminates browser ownership',async()=>{
  const env=environment({gotoHangs:true}),q=createSecureShopSvgAssetBrowserQualification({assetOrigin:ORIGIN,connectBrowser:env.connectBrowser,timeoutMs:500,startupTimeoutMs:500,idleCloseMs:100,retirementTimeoutMs:100});
  await assert.rejects(q.qualify(input()),error=>error.code==='BROWSER_RETIREMENT_INCOMPLETE'&&error.phase==='expired_work');
  assert.ok(env.state.browserClosed>=1);await assert.rejects(q.qualify(input()),error=>error.code==='BROWSER_RETIREMENT_INCOMPLETE');await q.close();
});

test('physical context retirement failure poisons subsequent work',async()=>{
  const env=environment({closeFails:true}),q=createSecureShopSvgAssetBrowserQualification({assetOrigin:ORIGIN,connectBrowser:env.connectBrowser,timeoutMs:500,startupTimeoutMs:500,idleCloseMs:100,retirementTimeoutMs:500});
  await assert.rejects(q.qualify(input()),error=>error.code==='BROWSER_RETIREMENT_INCOMPLETE'&&error.phase==='context_close');
  await assert.rejects(q.qualify(input()),error=>error.code==='BROWSER_RETIREMENT_INCOMPLETE');
  await q.close();
});

test('foreign URLs are rejected before browser creation',async()=>{
  const env=environment(),q=createSecureShopSvgAssetBrowserQualification({assetOrigin:ORIGIN,connectBrowser:env.connectBrowser});
  assert.throws(()=>q.qualify({...input(),assetUrl:'http://127.0.0.3:43191/assets/abc'}),/Exact SVG qualification input/);
  assert.equal(env.state.browserCreates,0);await q.close();
});
