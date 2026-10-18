'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('manual receipt verifies current execution envelope and immutable distinct birth binding',async()=>{
 const values=new Map();global.localStorage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
 const m=await import('../client/src/pages/secureshop/utils/manualReviewOperation.mjs');
 const p={scopeKey:JSON.stringify(['12345678-1234-4123-8123-123456789abd',2,1,20,7,'12345678-1234-4123-8123-123456789abe']),operationId:'12345678-1234-4123-8123-123456789abc',reviewId:4,action:'reject',reason:'exact'};
 const receipt={operationId:p.operationId,kind:'manual',moderatorKind:'manual',reviewId:4,decision:'rejected',notes:'exact',applied:true,resultStatus:'rejected',scope:{targetId:'12345678-1234-4123-8123-123456789abf',launchId:'12345678-1234-4123-8123-123456789ac0',scenarioId:'12345678-1234-4123-8123-123456789ac1',generation:1,platformOwnerId:1,platformSessionId:10},actor:{id:7,role:'merchant',personaSessionId:'12345678-1234-4123-8123-123456789abe'}};
 assert.equal(m.verifyManualReceipt(receipt,p,p.scopeKey),receipt);
 for(const change of [{notes:'other'},{decision:'approved'},{reviewId:5},{resultStatus:'approved'},{actor:{id:7,role:'merchant',personaSessionId:'12345678-1234-4123-8123-123456789ac2'}},{scope:{...receipt.scope,platformOwnerId:2}},{scope:{...receipt.scope,targetId:'bad'}}])assert.throws(()=>m.verifyManualReceipt({...receipt,...change},p,p.scopeKey));
 assert.throws(()=>m.verifyManualReceipt(receipt,p));
 assert.throws(()=>m.verifyManualReceipt(receipt,p,JSON.stringify(['12345678-1234-4123-8123-123456789ac3',2,1,20,7,'12345678-1234-4123-8123-123456789abe'])));
 await m.saveManualPending(p);assert.deepEqual(m.readManualPending(p.scopeKey),p);assert.equal(m.readManualPending('other'),null);
 const next={...p,operationId:'12345678-1234-4123-8123-123456789abd'};await m.saveManualPending(next);await assert.rejects(m.clearManualPending(p));assert.deepEqual(m.readManualPending(p.scopeKey),next);
 await m.clearManualPending(next);assert.equal(m.readManualPending(p.scopeKey),null);
 await assert.rejects(m.recoverManualPending(p,async()=>({status:404})),{code:'NOT_OBSERVED'});
});
