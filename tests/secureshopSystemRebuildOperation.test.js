'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const id='11111111-1111-4111-8111-111111111111';
test('rebuild request digest matches canonical server encoding; unsupported corpus rejected',async()=>{
 const m=await import('../client/src/pages/secureshop/pages/admin/systemRebuildOperation.mjs');
 for(const corpus of ['products','reviews','manuals','policies']) {
  assert.equal(await m.rebuildRequestDigest(id,corpus),createHash('sha256').update(JSON.stringify({version:1,operationId:id,corpus})).digest('hex'));
 }
 for(const corpus of ['unknown','../policies','Policies','']) assert.throws(()=>m.rebuildRequest(id,corpus));
 assert.throws(()=>m.rebuildRequest('invalid','products'));
});
test('completed rebuild requires exact operation, committed revision and digest; projects no source content',async()=>{
 const m=await import('../client/src/pages/secureshop/pages/admin/systemRebuildOperation.mjs');
 const v={ok:true,state:'completed',operationId:id,operationMode:'initialize',revisionId:id,targetId:id,corpus:'products',generation:1,documentCount:4,replayed:false,
 requestSha256:await m.rebuildRequestDigest(id,'products'),bindingSha256:'a'.repeat(64),sourceSetDigest:'b'.repeat(64),runtimeSha256:'c'.repeat(64),vectorDigest:'d'.repeat(64)};
 assert.deepEqual(await m.validateCompletedRebuild({...v,sourceText:'not renderable'},id,'products'),v);
 for(const patch of [{state:'running'},{operationMode:'other'},{revisionId:'22222222-2222-4222-8222-222222222222'},{documentCount:0},{requestSha256:'f'.repeat(64)},{corpus:'reviews'}])await assert.rejects(m.validateCompletedRebuild({...v,...patch},id,'products'));
});
