'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID,createHash}=require('node:crypto');
const {createBoundSystemDiagnosticService}=require('../server/services/secureshopBoundSystemDiagnosticService');
const {createSecureShopSystemDiagnosticClient}=require('../server/services/secureshopSystemDiagnosticClient');
const {VERSION,diagnosticRequestDigest,diagnosticCommand}=require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const {bindDiagnosticResult}=require('../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const raw={operationId:randomUUID(),cmd_template:'printf',args:'test',scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},persona:{id:3,role:'admin'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
const targetId=randomUUID(),request={operationId:raw.operationId,cmd_template:raw.cmd_template,args:raw.args},base={operationId:raw.operationId,requestSha256:diagnosticRequestDigest(request),targetId};
function receipt(){const empty=createHash('sha256').update('').digest('hex');return bindDiagnosticResult({targetId,request},{version:VERSION,isolation:'bwrap-system-diagnostic-v1',operationId:request.operationId,requestSha256:diagnosticRequestDigest(request),command:diagnosticCommand(request),executed:true,exitCode:0,signal:null,drained:true,stdout:'',stderr:'',encoding:'base64',stdoutBytes:0,stderrBytes:0,stdoutSha256:empty,stderrSha256:empty,timedOut:false,truncated:false});}
function fixture(state='admitted'){const calls=[];const repository={administration:async()=>({scopeKey:'a'.repeat(64)}),begin:async()=>{calls.push('begin');return{...base,state,...(state==='completed'?{receipt:receipt()}: {})};},assertCurrent:async(input,target)=>{assert.equal(target,targetId);assert.deepEqual(input,raw);calls.push('authority');},complete:async input=>{calls.push('complete');return{...base,state:'completed',receipt:input.receipt};},markUnknown:async()=>calls.push('unknown'),markNotExecuted:async()=>calls.push('not_executed'),operation:async()=>({state:'pending',...base})};const client={execute:async(wire,{assertCurrent})=>{assert.deepEqual(wire,{targetId,request});calls.push('dispatch');await assertCurrent();return receipt();}};return{calls,repository,client};}
test('only admitted original repository target dispatches and completes',async()=>{const f=fixture();const service=createBoundSystemDiagnosticService(f);assert.equal((await service.execute(raw)).state,'completed');assert.deepEqual(f.calls,['begin','dispatch','authority','complete']);});
test('pending/unknown/notexecuted/completed replay never contacts executor',async()=>{for(const state of ['pending','unknown','not_executed','completed']){const f=fixture(state);assert.equal((await createBoundSystemDiagnosticService(f).execute(raw)).state,state);assert.deepEqual(f.calls,['begin']);}});
test('pre-dispatch failure consumes notexecuted, post-dispatch uncertainty consumes unknown',async()=>{const f=fixture();f.client.execute=async()=>{throw Error('readiness unavailable');};await assert.rejects(createBoundSystemDiagnosticService(f).execute(raw));assert.deepEqual(f.calls,['begin','not_executed']);const g=fixture();g.client=createSecureShopSystemDiagnosticClient({baseURL:'http://127.0.0.1:1',token:'x'.repeat(43),fetchImpl:async(_url,options)=>{if(options.method==='GET')return new Response(JSON.stringify({version:'secureshop-owned-system-diagnostic-http.v1',ready:true,isolation:'bwrap-system-diagnostic-v1',diagnosticCapability:'secureshop-owned-system-diagnostic.v1'}));throw Error('lost response');}});await assert.rejects(createBoundSystemDiagnosticService(g).execute(raw),{code:'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN'});assert.ok(g.calls.includes('unknown'));assert.ok(!g.calls.includes('not_executed'));});
test('wrong target after returned result and lost completion are unknown, never auto-retried',async()=>{for(const mode of ['target','commit']){const f=fixture();if(mode==='target')f.client.execute=async()=>({...receipt(),targetId:randomUUID()});else f.repository.complete=async()=>{throw Error('commit ack lost');};await assert.rejects(createBoundSystemDiagnosticService(f).execute(raw),{code:'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN'});assert.equal(f.calls.filter(x=>x==='begin').length,1);assert.equal(f.calls.at(-1),'unknown');}});
test('capacity refusal happens before second durable admission',async()=>{const f=fixture();let release,started;const entered=new Promise(r=>started=r);f.client.execute=async()=>{started();await new Promise(r=>release=r);return receipt();};const service=createBoundSystemDiagnosticService({...f,maxConcurrent:1});const work=service.execute(raw);await entered;await assert.rejects(service.execute(raw),{code:'SYSTEM_DIAGNOSTIC_BUSY'});assert.equal(f.calls.filter(x=>x==='begin').length,1);release();await work;});
test('system_diagnostic mode is captured from authority; fixed denies direct admission',async()=>{
 const f=fixture();let mode='fixed',captures=0;
 const token={snapshot:{mode,featureId:'system_diagnostic',policyVersion:'owned-system-diagnostic-shell-v1',version:1,generation:2,modeStamp:'first',scope:raw.scope},async assertCurrent(){if(mode!=='fixed')throw Error('epoch drift');}};
 const authority={async capture(scope,feature){assert.deepEqual(scope,raw.scope);assert.equal(feature,'system_diagnostic');captures++;return token;},assertToken:value=>{assert.equal(value,token);return value;}};
 const service=createBoundSystemDiagnosticService({...f,modeAuthority:authority});
 const admin=await service.administration(raw);
 assert.equal(admin.modeCapability.effectiveMode,'fixed');
 assert.equal(admin.modeCapability.featureId,'system_diagnostic');
 assert.equal(Object.hasOwn(admin,'execution'),false);
 assert.equal((await service.administration(raw,{includeExecution:true})).execution.modeStamp,'first');
 await assert.rejects(service.execute(raw),{code:'SYSTEM_DIAGNOSTIC_FIXED_DENIED'});
 assert.equal(captures,3);assert.equal(f.calls.includes('begin'),false);
});
test('mode drift after admission consumes not-executed, and post-dispatch drift is uncertain',async()=>{
 for(const phase of ['admission','dispatch']){
  const f=fixture();let stamp='first';
  const token={snapshot:{mode:'vuln'},async assertCurrent(){if(stamp!=='first')throw Object.assign(Error('mode drift'),{code:'ANALYTICS_MODE_STALE'});}};
  const authority={capture:async()=>token,assertToken:value=>value};
  if(phase==='admission'){
   const begin=f.repository.begin;f.repository.begin=async input=>{const result=await begin(input);stamp='second';return result;};
  }else{
   f.client.execute=async(_wire,{assertCurrent})=>{await assertCurrent();stamp='second';return receipt();};
  }
  const service=createBoundSystemDiagnosticService({...f,modeAuthority:authority});
  await assert.rejects(service.execute(raw),phase==='admission'
   ? {code:'ANALYTICS_MODE_STALE'}:{code:'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN'});
  assert.equal(f.calls.filter(x=>x==='begin').length,1);
  assert.equal(f.calls.includes(phase==='admission'?'not_executed':'unknown'),true);
 }
});
test('trusted chat effect callback runs before admission and around the isolated dispatch',async()=>{
 const f=fixture();let checks=0;
 const service=createBoundSystemDiagnosticService(f);
 await assert.rejects(service.execute(raw,{beforeEffect:async()=>{
  checks++;throw Object.assign(Error('selected scene changed'),{code:'SHOP_SCENE_STALE'});
 }}),{code:'SHOP_SCENE_STALE'});
 assert.equal(checks,1);assert.deepEqual(f.calls,[]);
 const result=await service.execute(raw,{beforeEffect:async()=>{checks++;}});
 assert.equal(result.state,'completed');
 assert.equal(checks,5);
 assert.deepEqual(f.calls,['begin','dispatch','authority','complete']);
});
