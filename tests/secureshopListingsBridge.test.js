'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const operationId='11111111-1111-4111-8111-111111111111';
test('Listings bridge carries durable request IDs and read-only recovery',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 for(const [name,body] of [['assistWrite',{operationId,title:'Example',description:'Source'}],['importBulk',{operationId,json_url:'http://owned.test/feed',xml_url:''}]]){
  const request=compileOperation('merchant.listings.'+name,{body});
  assert.deepEqual(request.body,body);
  assert.equal(matchOperationRequest({pathname:request.path,method:request.method,body}).name,'merchant.listings.'+name);
 }
 assert.equal(compileOperation('merchant.listings.readiness').method,'GET');
 const read=compileOperation('merchant.listings.operation',{params:{operationId}});
 assert.equal(read.method,'GET');assert.equal(Object.hasOwn(read,'body'),false);
 const resume=compileOperation('merchant.listings.resume',{params:{operationId},body:{}});
 assert.equal(resume.method,'POST');assert.deepEqual(resume.body,{});
 assert.throws(()=>compileOperation('merchant.listings.resume',{params:{operationId},body:{force:true}}));
 assert.throws(()=>compileOperation('merchant.listings.operation',{params:{operationId:'../other'}}));
});
test('Listings save bridge rejects injected authority and generated HTML while retaining full product snapshot',async()=>{
 const {compileOperation}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const body={rewriteOperationId:operationId,saveOperationId:'22222222-2222-4222-8222-222222222222',productId:null,item:{name:'Example',description:'Source',price:10,category:null,images:[],templateSource:null}};
 assert.deepEqual(compileOperation('merchant.listings.rewriteSave',{body}).body,body);
 for(const field of ['scope','persona','token','ownerId'])assert.throws(()=>compileOperation('merchant.listings.rewriteSave',{body:{...body,[field]:'injected'}}));
 for(const field of ['generatedHTML','description_html','ownerId'])assert.throws(()=>compileOperation('merchant.listings.rewriteSave',{body:{...body,item:{...body.item,[field]:'injected'}}}));
 assert.throws(()=>compileOperation('merchant.listings.readiness',{query:{ownerId:1}}));
});
test('saved browser attempt roundtrips through the closed fetch matcher',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const body={requestId:operationId,rewriteOperationId:'22222222-2222-4222-8222-222222222222',saveOperationId:'33333333-3333-4333-8333-333333333333'};
 const result=compileOperation('merchant.listings.browserAttempt',{body});
 assert.equal(matchOperationRequest({pathname:result.path,method:result.method,body}).name,'merchant.listings.browserAttempt');
 for(const key of ['html','scope','completed','productId'])assert.throws(()=>compileOperation('merchant.listings.browserAttempt',{body:{...body,[key]:'injected'}}));
});
test('Judge retry crosses only the closed retained-evidence operation',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const body={requestId:operationId,rewriteOperationId:operationId,saveOperationId:operationId,evaluationId:operationId};
 const request=compileOperation('merchant.listings.browserRetry',{body});
 assert.equal(request.method,'POST');assert.equal(request.path,'/api/secureshop/merchant/listings/browser-retry');
 assert.equal(matchOperationRequest({pathname:request.path,method:'POST',body}).name,'merchant.listings.browserRetry');
 for(const key of ['evidence','rubric','ownerId','html','verdict'])assert.throws(()=>compileOperation('merchant.listings.browserRetry',{body:{...body,[key]:'forged'}}));
});
test('template rendering crosses only product ID and opaque operation ID with read-only recovery',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const readiness=compileOperation('merchant.listings.templateReadiness');
 assert.equal(readiness.method,'GET');assert.equal(readiness.path,'/api/secureshop/merchant/listings/template-readiness');
 const body={operationId,productId:7};
 const run=compileOperation('merchant.listings.templateRender',{body});
 assert.equal(run.method,'POST');assert.deepEqual(run.body,body);
 assert.equal(matchOperationRequest({pathname:run.path,method:'POST',body}).name,'merchant.listings.templateRender');
 const read=compileOperation('merchant.listings.templateOperation',{params:{operationId}});
 assert.equal(read.method,'GET');assert.equal(Object.hasOwn(read,'body'),false);
 assert.equal(matchOperationRequest({pathname:read.path,method:'GET'}).name,'merchant.listings.templateOperation');
 for(const field of ['templateSource','html','ownerId','scope','persona','mode'])
  assert.throws(()=>compileOperation('merchant.listings.templateRender',{body:{...body,[field]:'forged'}}));
 assert.throws(()=>compileOperation('merchant.listings.templateReadiness',{query:{force:true}}));
});
