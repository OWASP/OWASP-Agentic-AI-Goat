'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPricingHttpListener}=require('../sidecars/sandbox-runner/owned-pricing-http/http-listener');
const {createPricingHttpClient}=require('../server/services/secureshopPricingHttpClient');
const token='a'.repeat(43);
test('prospective startup diagnostics do not inherit historical install qualification',()=>{
 const {qualifiedSource}=require('../scripts/install/secureshop-owned-pricing');
 assert.throws(()=>qualifiedSource(require('node:path').resolve(__dirname,'..')),{code:'PRICING_PACKAGE_SOURCE_CHANGED'});
});
const options=executor=>({enabled:true,token,host:'127.0.0.1',port:0,executor});
test('standalone listener is opt-in and refuses false readiness before binding',async()=>{
 assert.throws(()=>createPricingHttpListener({enabled:false}),{code:'PRICING_LISTENER_DISABLED'});
 const listener=createPricingHttpListener(options({assertReady:async()=>({ready:false}),checkReadiness:async()=>({ready:true}),execute:async()=>assert.fail('execution')}));
 await assert.rejects(listener.start(),{code:'PRICING_LISTENER_NOT_READY'});assert.equal(listener.address(),null);await listener.close();
});
test('actual loopback listener uses private authenticated health; readiness is not command dispatch',async t=>{
 let checks=0,commands=0;
 const listener=createPricingHttpListener(options({async assertReady(){checks++;return{ready:true};},async checkReadiness(){return{ready:true};},async execute(){commands++;return{drained:true,result:{controlled:true}};}}));
 t.after(()=>listener.close());const address=await listener.start();const client=createPricingHttpClient({baseURL:`http://127.0.0.1:${address.port}`,token});
 assert.deepEqual(await client.assertReady(),{ready:true});assert.equal(checks,2);assert.equal(commands,0);
 await listener.close();assert.equal(listener.address(),null);
});
test('held readiness cannot produce false successful drain after startup timeout',async()=>{
 let resolve;const held=new Promise(r=>{resolve=r;});
 const listener=createPricingHttpListener({...options({assertReady:()=>held,checkReadiness:async()=>({ready:true}),execute:async()=>({})}),readinessTimeoutMs:10,closeTimeoutMs:10});
 await assert.rejects(listener.start(),{code:'PRICING_LISTENER_NOT_READY'});
 await assert.rejects(listener.close(),{code:'PRICING_LISTENER_DRAIN_FAILED'});assert.equal(listener.address(),null);resolve({ready:true});
});
test('startup-v1 preserves original failure status and emits only closed readiness cause fields',async()=>{
 const {runPricingHttpListener}=require('../sidecars/sandbox-runner/owned-pricing-http/http-listener'),{EventEmitter}=require('node:events');
 for(const code of ['HTTP_ASSET_UNTRUSTED','HTTP_ASSET_CHANGED','HTTP_ASSET_REGISTRY_INVALID','HTTP_PLATFORM_UNAVAILABLE','HTTP_PROFILE_UNAVAILABLE','HTTP_SUPERVISOR_CAPABILITIES','HTTP_NAMESPACE_UNAVAILABLE','HTTP_CHILD_FAILED','EACCES','ENOENT','EPERM','untrusted bearer']){
  for(const enabled of [false,true]){
   const output=[],signals=new EventEmitter(),error=Object.assign(Error('secret path/token'),{code,exitCode:70,diagnostic:'secret stderr'});
   const listener=createPricingHttpListener(options({assertReady:async()=>{throw error;},checkReadiness:async()=>({ready:true}),execute:async()=>assert.fail('no request')}));
   const env={SECURESHOP_PRICING_ENABLED:'true',SECURESHOP_PRICING_PORT:'8093',...(enabled?{SECURESHOP_PRICING_DIAGNOSTICS:'startup-v1'}:{})};
   const status=await runPricingHttpListener({env,signals,createListener:()=>listener,write:s=>output.push(s)});
   assert.equal(status,1);assert.equal(listener.address(),null);assert.equal(signals.listenerCount('SIGTERM'),0);
   assert.equal(output.at(-1),'PRICING_LISTENER_FAILED\n');assert.equal(output.length,enabled?2:1);
   if(enabled){const line=output[0];assert(line.startsWith('PRICING_STARTUP_DIAGNOSTIC_V1:'));
    assert.deepEqual(JSON.parse(line.slice('PRICING_STARTUP_DIAGNOSTIC_V1:'.length)),{version:1,code:code==='untrusted bearer'?'UNKNOWN':code,childExit:code==='HTTP_CHILD_FAILED'?70:null});
   }
   assert(!output.join('').includes('secret'));assert(!output.join('').includes('bearer'));
  }
 }
});
test('startup-v1 never accepts diagnostic strings or invalid child exits and unknown opt-in stays silent',async()=>{
 const {runPricingHttpListener}=require('../sidecars/sandbox-runner/owned-pricing-http/http-listener'),{EventEmitter}=require('node:events');
 for(const exitCode of [true,-1,256,'70',null]){
  const output=[];const status=await runPricingHttpListener({env:{SECURESHOP_PRICING_ENABLED:'true',SECURESHOP_PRICING_PORT:'8093',SECURESHOP_PRICING_DIAGNOSTICS:'startup-v1'},signals:new EventEmitter(),
   createListener:()=>{throw Object.assign(Error('secret'),{code:'HTTP_CHILD_FAILED',exitCode,startupDiagnostic:{code:'injected'}});},write:s=>output.push(s)});
  assert.equal(status,1);assert.equal(JSON.parse(output[0].slice('PRICING_STARTUP_DIAGNOSTIC_V1:'.length)).childExit,null);
 }
 const output=[];await runPricingHttpListener({env:{SECURESHOP_PRICING_DIAGNOSTICS:'unrecognized'},signals:new EventEmitter(),write:s=>output.push(s)});
 assert.deepEqual(output,['PRICING_LISTENER_FAILED\n']);
});
