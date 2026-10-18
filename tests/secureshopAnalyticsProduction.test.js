'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{createHash}=require('node:crypto');
const {_internals:{createRuntime,validateContainer}}=require('../server/services/secureshopOwnedAnalyticsProduction');
const {authorityDigest}=require('../scripts/local-docker-authority');
function fixture(enabled=true,appliedVersion=enabled?2:1,hooks={}){
 const authority={version:1,workspaceId:'abcdef123456',host:'unix:///owned.sock',daemonId:'owned-daemon'};
 const config={enabled,port:19096,password:'a'.repeat(64),identity:{controlDatabase:'dvaia_analytics_control_abcdef123456'},containerId:'b'.repeat(64),imageId:'sha256:'+'c'.repeat(64),containerName:'dvaia-analytics-abcdef123456',volumeName:'dvaia-analytics-abcdef123456-data',workspaceId:'abcdef123456',ownerId:'owned',dockerAuthoritySha256:authorityDigest(authority),controlSchemaSha256:createHash('sha256').update(fs.readFileSync(require.resolve('../sidecars/analytics-sql-target/control-migrations/0001_control.sql'))).digest('hex')};
 const container={Id:config.containerId,Image:config.imageId,Name:'/'+config.containerName,NetworkSettings:{Ports:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(config.port)}]}},State:{Running:true},Config:{Labels:{'dvaia.workspace':config.workspaceId,'dvaia.purpose':'owned-analytics','dvaia.owner':config.ownerId}},Mounts:[{Type:'volume',Name:config.volumeName,Destination:'/var/lib/postgresql'}],HostConfig:{PortBindings:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(config.port)}]},Privileged:false,NetworkMode:'bridge',Memory:536870912,MemorySwap:536870912,NanoCpus:1000000000,PidsLimit:128}};
 const record={config,sha256:'record'},calls={service:0,verify:0,closed:0,created:0};let current=record;const pool=new(require('node:events').EventEmitter)();pool.end=async()=>{calls.closed++;};
 const runtime=createRuntime({record,readRecord:async()=>current,readAuthority:async()=>authority,verifyAuthority:async()=>{calls.verify++;},inspectContainer:async()=>container,makePool:()=>pool,makeService:options=>{calls.fixed=options.fixedCapabilities;calls.created++;return Object.fromEntries(['resolve','provision','prepareFixed','topProducts','execute','lookupCoupon','readCouponReceipt','lookupCouponProbe','readCouponProbeReceipt','readCouponProbeReference','searchProducts','readProductSearchReceipt','readProductSearchReference','lookupOrderStatus','readOrderStatusReceipt','readOrderStatusReference','retire'].map(key=>[key,async()=>{calls.service++;await hooks.effect?.(pool);return {retired:true};}]));},checkSchema:async({requiredVersion})=>{calls.requiredVersion=requiredVersion;await hooks.verify?.(pool);return {appliedVersion};}});
 return {runtime,calls,config,container,pool,replaceRecord:value=>{current=value;}};
}
test('disabled Analytics retains exact owned cleanup while denying admissions',async()=>{
 const f=fixture(false);try{
  assert.equal(f.runtime.admissions,false);assert.equal(f.calls.verify,0);
  await assert.rejects(f.runtime.service.provision({}),{code:'ANALYTICS_ADMISSIONS_DISABLED'});assert.equal(f.calls.service,0);
  assert.deepEqual(await f.runtime.service.retire({}),{retired:true});assert.equal(f.calls.service,1);assert.equal(f.calls.verify,1);
 }finally{await f.runtime.close();await f.runtime.close();}assert.equal(f.calls.closed,1);
});
test('shared runtime verification is coalesced and changed private state stops new effects',async()=>{
 const f=fixture();try{
  await Promise.all([f.runtime.service.resolve({}),f.runtime.service.resolve({})]);assert.equal(f.calls.created,1);assert.equal(f.calls.verify,1);
  f.replaceRecord(null);await assert.rejects(f.runtime.service.execute({}),{code:'ANALYTICS_MANAGED_CONFIGURATION_CHANGED'});assert.equal(f.calls.service,2);
 }finally{await f.runtime.close();}
});
test('SELECT-only coupon receipt entry keeps owned runtime admission and readiness fences',async()=>{
 const f=fixture();try{
  assert.deepEqual(await f.runtime.service.readCouponReceipt({}),{retired:true});
  assert.equal(f.calls.service,1);
  f.replaceRecord(null);
  await assert.rejects(f.runtime.service.readCouponReceipt({}),{code:'ANALYTICS_MANAGED_CONFIGURATION_CHANGED'});
  assert.equal(f.calls.service,1);
 }finally{await f.runtime.close();}
 const disabled=fixture(false);try{
  await assert.rejects(disabled.runtime.service.readCouponReceipt({}),{code:'ANALYTICS_ADMISSIONS_DISABLED'});
  assert.equal(disabled.calls.service,0);
 }finally{await disabled.runtime.close();}
});
test('coupon probe methods remain private runtime forwards behind the same readiness fence',async()=>{
 const f=fixture();try{
  for(const method of ['lookupCouponProbe','readCouponProbeReceipt','readCouponProbeReference'])assert.deepEqual(await f.runtime.service[method]({}),{retired:true});
  assert.equal(f.calls.service,3);
 }finally{await f.runtime.close();}
 const disabled=fixture(false);try{
  await assert.rejects(disabled.runtime.service.readCouponProbeReference({}),{code:'ANALYTICS_ADMISSIONS_DISABLED'});
  assert.equal(disabled.calls.service,0);
 }finally{await disabled.runtime.close();}
});
test('foreign mounts, external ports and unbounded containers never pass runtime identity checks',()=>{
 const f=fixture();try{
  assert.equal(validateContainer(f.container,f.config),true);
  for(const mutate of [v=>{v.Mounts.push({Type:'bind',Source:'/private'});},v=>{v.HostConfig.PortBindings['5432/tcp'][0].HostIp='0.0.0.0';},v=>{v.HostConfig.Memory=0;},v=>{v.Image='sha256:'+'f'.repeat(64);}]){
   const value=structuredClone(f.container);mutate(value);assert.throws(()=>validateContainer(value,f.config),{code:'ANALYTICS_CONTAINER_MISMATCH'});
  }
 }finally{f.runtime.close();}
});

test('checked upgraded disabled runtime retains both-role cleanup and enabled legacy schema fails closed',async()=>{const upgraded=fixture(false,2);try{await upgraded.runtime.service.retire({});assert.equal(upgraded.calls.fixed,true);assert.equal(upgraded.calls.requiredVersion,2);assert.equal(upgraded.runtime.fixedCapabilities,true);}finally{await upgraded.runtime.close();}const legacy=fixture(true,1);try{await assert.rejects(legacy.runtime.assertReady(),{code:'ANALYTICS_CONTROL_SCHEMA_CHANGED'});assert.equal(legacy.calls.created,0);}finally{await legacy.runtime.close();}});

test('idle pool errors invalidate cached readiness and cannot publish across verification loss',async()=>{
 const f=fixture();try{await f.runtime.service.resolve({});const before=f.calls.verify;f.pool.emit('error',Error('private details must not be logged'));await f.runtime.service.resolve({});assert.equal(f.calls.verify,before+1);assert.equal(f.calls.created,1);}finally{await f.runtime.close();}
 let first=true;const bad=fixture(true,2,{verify:pool=>{if(first){first=false;pool.emit('error',Error('lost'));}}});try{await assert.rejects(bad.runtime.service.resolve({}),{code:'ANALYTICS_CONTROL_CONNECTION_LOST'});assert.equal(bad.calls.service,0);await bad.runtime.service.resolve({});assert.equal(bad.calls.service,1);}finally{await bad.runtime.close();}
 const active=fixture(true,2,{effect:pool=>pool.emit('error',Error('lost during effect'))});try{await assert.rejects(active.runtime.service.resolve({}),{code:'ANALYTICS_CONTROL_CONNECTION_LOST'});}finally{await active.runtime.close();}
});


test('named product SQL methods share managed readiness and disabled-admission fences',async()=>{
 const methods=['searchProducts','readProductSearchReceipt','readProductSearchReference'];
 const f=fixture();try{
  for(const method of methods)assert.deepEqual(await f.runtime.service[method]({}),{retired:true});
  assert.equal(f.calls.service,3);f.replaceRecord(null);
  for(const method of methods)await assert.rejects(f.runtime.service[method]({}),{code:'ANALYTICS_MANAGED_CONFIGURATION_CHANGED'});
  assert.equal(f.calls.service,3);
 }finally{await f.runtime.close();}
 const disabled=fixture(false);try{
  for(const method of methods)await assert.rejects(disabled.runtime.service[method]({}),{code:'ANALYTICS_ADMISSIONS_DISABLED'});
  assert.equal(disabled.calls.service,0);
 }finally{await disabled.runtime.close();}
});


test('order status named forwards retain managed configuration and disabled-admission fences',async()=>{
 const methods=['lookupOrderStatus','readOrderStatusReceipt','readOrderStatusReference'];const f=fixture();
 try{
  for(const method of methods)assert.deepEqual(await f.runtime.service[method]({}),{retired:true});
  assert.equal(f.calls.service,3);f.replaceRecord(null);
  for(const method of methods)await assert.rejects(f.runtime.service[method]({}),{code:'ANALYTICS_MANAGED_CONFIGURATION_CHANGED'});
  assert.equal(f.calls.service,3);
 }finally{await f.runtime.close();}
 const disabled=fixture(false);try{
  for(const method of methods)await assert.rejects(disabled.runtime.service[method]({}),{code:'ANALYTICS_ADMISSIONS_DISABLED'});
  assert.equal(disabled.calls.service,0);
 }finally{await disabled.runtime.close();}
});
