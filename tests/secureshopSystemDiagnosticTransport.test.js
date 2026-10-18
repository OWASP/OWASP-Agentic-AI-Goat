'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const http=require('node:http');const {createHash}=require('node:crypto');
const {createSystemDiagnosticHttpHandler}=require('../sidecars/sandbox-runner/owned-system/diagnostic-http-handler');
const {createSecureShopSystemDiagnosticClient,isSystemDiagnosticOutcomeUncertain}=require('../server/services/secureshopSystemDiagnosticClient');
const {bindDiagnosticResult,validateBoundDiagnosticResult,normalizeDiagnosticWire,diagnosticHostname}=require('../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const {VERSION,diagnosticRequestDigest,diagnosticCommand,normalizeDiagnosticRequest}=require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const {buildDiagnosticArgv}=require('../sidecars/sandbox-runner/owned-system/diagnostic-executor');
const token='x'.repeat(43),wire={targetId:'00000000-0000-4000-8000-000000000003',request:{operationId:'00000000-0000-4000-8000-000000000004',cmd_template:'printf',args:'training'}};
// Controlled transport result, not an actual executor/model provenance claim.
function result(input=wire){const digest=createHash('sha256').update('').digest('hex');return bindDiagnosticResult(input,{version:VERSION,isolation:'bwrap-system-diagnostic-v1',operationId:input.request.operationId,requestSha256:diagnosticRequestDigest(input.request),command:diagnosticCommand(input.request),executed:true,exitCode:70,signal:null,drained:true,stdout:'',stderr:'',encoding:'base64',stdoutBytes:0,stderrBytes:0,stdoutSha256:digest,stderrSha256:digest,timedOut:false,truncated:false});}
async function fixture(executor,options={}){const handler=createSystemDiagnosticHttpHandler({enabled:true,token,executor,...options});const server=http.createServer((req,res)=>handler.handle(req,res).then(handled=>{if(!handled){res.writeHead(404);res.end();}}));await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));return{origin:'http://127.0.0.1:'+server.address().port,close:async()=>{await handler.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}};}
test('real loopback: authenticated readiness separate from one bound dispatch and three authority checks',async()=>{
 let probes=0,calls=0,checks=0;const f=await fixture({assertReady:async()=>{probes++;},executeBound:async value=>{calls++;assert.deepEqual(value,wire);return result(value);}});
 try{const client=createSecureShopSystemDiagnosticClient({baseURL:f.origin,token});const receipt=await client.execute(wire,{assertCurrent:async()=>checks++});assert.equal(receipt.targetId,wire.targetId);assert.equal(receipt.result.exitCode,70);assert.equal(calls,1);assert.equal(probes,2);assert.equal(checks,3);}finally{await f.close();}
});
test('closed public request rejects target authority; private target binds hostname and wrapper',()=>{
 assert.throws(()=>normalizeDiagnosticRequest({...wire.request,targetId:wire.targetId}));assert.throws(()=>normalizeDiagnosticWire({...wire,root:'/private'}));
 const argv=buildDiagnosticArgv(wire.request,['/usr'],wire.targetId);assert.equal(argv[argv.indexOf('--hostname')+1],diagnosticHostname(wire.targetId));
 for(const change of [{targetId:'00000000-0000-4000-8000-000000000005'},{hostname:'forged'},{bindingSha256:'0'.repeat(64)}])assert.throws(()=>validateBoundDiagnosticResult(wire,{...result(),...change}));
});
test('wrong bearer and malformed body do not execute',async()=>{let calls=0;const f=await fixture({assertReady:async()=>{},executeBound:async()=>{calls++;return result();}});try{
 const bad=await fetch(f.origin+'/secureshop/system/diagnostic',{method:'POST',headers:{authorization:'Bearer wrong','content-type':'application/json'},body:JSON.stringify(wire)});assert.equal(bad.status,401);
 const malformed=await fetch(f.origin+'/secureshop/system/diagnostic',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({...wire,argv:['bad']})});assert.equal(malformed.status,400);assert.equal(calls,0);
 }finally{await f.close();}});
test('mismatched result becomes branded unknown with no retry',async()=>{let calls=0;const f=await fixture({assertReady:async()=>{},executeBound:async()=>{calls++;return {...result(),targetId:'00000000-0000-4000-8000-000000000005'};}});try{const client=createSecureShopSystemDiagnosticClient({baseURL:f.origin,token});await assert.rejects(client.execute(wire,{assertCurrent:async()=>{}}),e=>isSystemDiagnosticOutcomeUncertain(e)&&e.automaticRetry===false);assert.equal(calls,1);}finally{await f.close();}});
test('pre-dispatch authority and unavailable readiness are not uncertain',async()=>{let fetches=0;const client=createSecureShopSystemDiagnosticClient({baseURL:'http://127.0.0.1:1',token,fetchImpl:async()=>{fetches++;throw Error('unavailable');}});const stale=Error('stale');await assert.rejects(client.execute(wire,{assertCurrent:async()=>{throw stale;}}),e=>e===stale);assert.equal(fetches,0);await assert.rejects(client.execute(wire,{assertCurrent:async()=>{}}),e=>!isSystemDiagnosticOutcomeUncertain(e));assert.equal(fetches,1);});
test('held readiness consumes concurrency slot before execution',async()=>{let release,started;const ready=new Promise(r=>started=r);const f=await fixture({assertReady:async()=>{started();await new Promise(r=>release=r);},executeBound:async()=>result()},{maxConcurrent:1});try{
 const first=fetch(f.origin+'/secureshop/system/diagnostic-health',{headers:{authorization:'Bearer '+token}});await ready;const second=await fetch(f.origin+'/secureshop/system/diagnostic-health',{headers:{authorization:'Bearer '+token}});assert.equal(second.status,503);release();assert.equal((await first).status,200);
 }finally{release?.();await f.close();}});
test('stream stall after POST is unknown and cancels body without retry',async()=>{
 let posts=0,cancelled=false;const client=createSecureShopSystemDiagnosticClient({baseURL:'http://127.0.0.1:1',token,timeoutMs:100,fetchImpl:async(_url,options)=>{
  if(options.method==='GET')return new Response(JSON.stringify({version:'secureshop-owned-system-diagnostic-http.v1',ready:true,isolation:'bwrap-system-diagnostic-v1',diagnosticCapability:'secureshop-owned-system-diagnostic.v1'}));
  posts++;return new Response(new ReadableStream({cancel(){cancelled=true;}}));
 }});await assert.rejects(client.execute(wire,{assertCurrent:async()=>{}}),isSystemDiagnosticOutcomeUncertain);assert.equal(posts,1);assert.equal(cancelled,true);
});
test('oversized response cancels body and rejects target publication',async()=>{
 let cancelled=false;const client=createSecureShopSystemDiagnosticClient({baseURL:'http://127.0.0.1:1',token,fetchImpl:async(_url,options)=>{
  if(options.method==='GET')return new Response(JSON.stringify({version:'secureshop-owned-system-diagnostic-http.v1',ready:true,isolation:'bwrap-system-diagnostic-v1',diagnosticCapability:'secureshop-owned-system-diagnostic.v1'}));
  return new Response(new ReadableStream({cancel(){cancelled=true;}}),{headers:{'content-length':'99999999'}});
 }});await assert.rejects(client.execute(wire,{assertCurrent:async()=>{}}),isSystemDiagnosticOutcomeUncertain);assert.equal(cancelled,true);
});
test('shutdown aborts and joins active controlled executor',async()=>{
 let started,joined=false;const running=new Promise(r=>started=r);const handler=createSystemDiagnosticHttpHandler({enabled:true,token,executor:{assertReady:async()=>{},executeBound:async(_wire,{signal})=>{started();await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));joined=true;throw Error('private executor context');}}});
 const server=http.createServer((req,res)=>void handler.handle(req,res));await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{const response=fetch('http://127.0.0.1:'+server.address().port+'/secureshop/system/diagnostic',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(wire)});await running;await handler.close();assert.equal(joined,true);const result=await response;assert.equal(result.status,503);assert.ok(!(await result.text()).includes('private executor context'));}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('default transport permits bounded command beyond the previous3second timeout',async()=>{
 const f=await fixture({assertReady:async()=>{},executeBound:async()=>{await new Promise(resolve=>setTimeout(resolve,3100));return result();}});
 try{const client=createSecureShopSystemDiagnosticClient({baseURL:f.origin,token});assert.equal((await client.execute(wire,{assertCurrent:async()=>{}})).result.exitCode,70);}finally{await f.close();}
});
test('shutdown aborts and joins readiness before any admitted command',async()=>{
 let started,joined=false,calls=0;const running=new Promise(r=>started=r);
 const handler=createSystemDiagnosticHttpHandler({enabled:true,token,executor:{assertReady:async({signal})=>{started();await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));joined=true;signal.throwIfAborted();},executeBound:async()=>{calls++;return result();}}});
 const server=http.createServer((req,res)=>void handler.handle(req,res));await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{const response=fetch('http://127.0.0.1:'+server.address().port+'/secureshop/system/diagnostic-health',{headers:{authorization:'Bearer '+token}});await running;await handler.close();assert.equal(joined,true);assert.equal(calls,0);const res=await response;assert.equal(res.status,503);assert.match(await res.text(),/SYSTEM_DIAGNOSTIC_SHUTDOWN/);}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('disconnect aborts and joins readiness without dispatch',async()=>{
 let started,joined,executions=0;const active=new Promise(r=>started=r),drained=new Promise(r=>joined=r);
 const f=await fixture({assertReady:async({signal})=>{started();await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));joined();signal.throwIfAborted();},executeBound:async()=>{executions++;return result();}});
 try{const controller=new AbortController();const response=fetch(f.origin+'/secureshop/system/diagnostic-health',{signal:controller.signal,headers:{authorization:'Bearer '+token}}).catch(()=>{});await active;controller.abort();await response;await drained;assert.equal(executions,0);}finally{await f.close();}
});
