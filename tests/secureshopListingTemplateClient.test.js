'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {randomUUID,createHash} = require('node:crypto');
const {createListingTemplateClient} = require('../server/services/secureshopListingTemplateClient');
const {listingTemplateExecutionDigest,ISOLATION} = require('../server/services/secureshopListingTemplateExecutorContract');

const hash = value => createHash('sha256').update(value).digest('hex');
const request = () => ({version:1,operationId:randomUUID(),productId:7,
  sourceSha256:hash('Hello {{ title }}'),templateSource:'Hello {{ title }}',
  title:'Test',description:'',price:3.5});
const result = (r,rendered) => ({version:1,operationId:r.operationId,productId:r.productId,
  requestSha256:listingTemplateExecutionDigest(r),sourceSha256:r.sourceSha256,
  isolation:ISOLATION,rendered,renderedSha256:hash(rendered),exitCode:0,
  timedOut:false,truncated:false,drained:true,workerAttested:true,
  commandEffectObserved:false,effectSha256:null});

test('template client accepts a valid large escaped render inside its bounded stream',async()=>{
  const r=request(), rendered='\u0001'.repeat(60000);
  let calls=0;
  const client=createListingTemplateClient({baseUrl:'http://127.0.0.1:8109',
    fetchImpl:async()=>{calls++;return new Response(JSON.stringify(result(r,rendered)),
      {headers:{'content-type':'application/json'}});}});
  assert.deepEqual(await client.execute(r),result(r,rendered));
  assert.equal(calls,1);
});

test('template client stops reading oversized executor response before buffering the tail',async()=>{
  const r=request();
  let reads=0,cancelled=false;
  const body=new ReadableStream({pull(controller){reads++;
    controller.enqueue(new Uint8Array(300000));
    if(reads>4)controller.error(Error('unbounded read'));
  },cancel(){cancelled=true;}});
  const client=createListingTemplateClient({baseUrl:'http://127.0.0.1:8109',
    fetchImpl:async()=>new Response(body,{headers:{'content-type':'application/json'}})});
  await assert.rejects(client.execute(r),{code:'LISTING_TEMPLATE_OUTCOME_UNCERTAIN'});
  assert.ok(reads<=3);
  assert.equal(cancelled,true);
});
