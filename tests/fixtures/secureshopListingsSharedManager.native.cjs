'use strict';
const assert=require('node:assert/strict');
const {createOwnedListingsExecutor}=require('../../sidecars/sandbox-runner/owned-listings/namespace-executor');
const {createListingsTargetManager}=require('../../sidecars/sandbox-runner/owned-listings/target-manager');
const {createListingsManagerHttp}=require('../../sidecars/sandbox-runner/owned-listings/manager-http');
(async()=>{
 const executor=createOwnedListingsExecutor({expectedProfile:process.env.LISTINGS_PROFILE});let active=0,maxActive=0,calls=0;
 const namespace={checkReadiness:()=>executor.checkReadiness(),async execute(...args){active++;calls++;maxActive=Math.max(maxActive,active);try{return await executor.execute(...args);}finally{active--;}}};
 const origin='http://127.0.0.1:8095',control='m'.repeat(43),manager=await createListingsTargetManager({directory:'/journal',origin,namespace}),server=createListingsManagerHttp({manager,controlToken:control,host:'127.0.0.1',port:8095});
 const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'10000000-0000-4000-8000-000000000002',generation:1,platformOwnerId:1,platformSessionId:2};
 const a={scope,targetId:'10000000-0000-4000-8000-000000000003',mode:'vuln'},b={scope:{...scope,platformOwnerId:3,platformSessionId:4},targetId:'10000000-0000-4000-8000-000000000004',mode:'fixed'};
 await server.start();
 const http=async(path,token,body)=>{const response=await fetch(origin+path,{method:body?'POST':'GET',headers:{authorization:'Bearer '+token,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});return{status:response.status,body:await response.json()};};
 try{
  assert.equal((await http('/manager/health','wrong')).status,401);const health=(await http('/manager/health',control)).body;assert.equal(health.capability,'owned-listings-manager.v1');
  const ca=(await http('/targets',control,a)).body,cb=(await http('/targets',control,b)).body;assert.notEqual(ca.token,cb.token);assert.notEqual(ca.runtimeIdentity,cb.runtimeIdentity);
  const targetHealth=(await http('/health',ca.token)).body;assert.equal(targetHealth.identity,ca.runtimeIdentity);assert.equal(targetHealth.runtimeDigest,health.runtimeDigest);
  const op={version:1,action:'import',operationId:'10000000-0000-4000-8000-000000000005',json_url:'http://10.0.1.100:8080/catalog.json',xml_url:null};
  const internal=(await http('/operations',ca.token,op)).body;assert.equal(internal.status,'completed');assert.equal(internal.result.products[0].name,'Internal synthetic catalog');
  const siblingRead=await http('/operations/'+op.operationId,cb.token);
  if(siblingRead.status===200){assert.equal(siblingRead.body.identity,cb.runtimeIdentity);assert.equal(siblingRead.body.status,'failed');assert.equal(Object.hasOwn(siblingRead.body,'result'),false);}else assert.equal(siblingRead.status,404);
  const denied=(await http('/operations',cb.token,op)).body;assert.equal(denied.status,'failed');
  const clean={...op,operationId:'10000000-0000-4000-8000-000000000006',json_url:'http://192.0.2.10/catalog.json'};
  const prior=await http('/operations/'+clean.operationId,cb.token),before=calls;
  const existingReceipt=prior.status===200;
  const completed=(await http('/operations',cb.token,clean)).body;assert.equal(completed.status,'completed');if(existingReceipt)assert.equal(calls,before);
  const retirement={...a,operationId:'10000000-0000-4000-8000-000000000007',canonicalReceiptSha256:'f'.repeat(64)};
  const retired=(await http('/targets/retire',control,retirement)).body;assert.equal(retired.retired,true);assert.equal(retired.operationCount,1);
  assert.equal((await http('/health',ca.token)).status,503);assert.equal((await http('/operations/'+clean.operationId,cb.token)).body.status,'completed');
  const forgotten=(await http('/targets/forget',control,retirement)).body;assert.equal(forgotten.forgotten,true);assert.equal(forgotten.replayed,false);
  assert.equal((await http('/targets/forget',control,retirement)).body.replayed,true);
  assert.equal(maxActive,1);
  process.stdout.write(JSON.stringify({status:'passed',modelCalls:0,existingReceipt,maximumActualNamespaces:maxActive,actualNamespaceCalls:calls,runtimeDigest:health.runtimeDigest,canonicalCleanup:'controlled proof; no platform DB',checks:['shared-authenticated-manager','fixed-vuln-isolation','target-token-isolation','real-internal-HTTP','restart-replay','retire-redact','canonical-ack-compaction','sibling-preservation']})+'\n');
 }finally{await server.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
