'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('inventory qualification constructs genuine adapters without calling a model and restores transport',async()=>{
 const original=global.fetch;let tags=0;global.fetch=async url=>{assert.equal(url,'http://127.0.0.1:11434/api/tags');tags++;return new Response(JSON.stringify({models:[{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}]}));};
 const tagFixture=global.fetch;let actual;
 try{
  actual=await require('./fixtures/secureshopInventoryActualProvider').createActualInventoryProvider({maxCalls:12,maxHttpCalls:20,writeEvidence:()=>{}});
  assert.equal(Object.getPrototypeOf(actual.provider),require('../server/services/secureshop/providers/ollamaProvider').OllamaProvider.prototype);
  const qualify=require('../server/services/secureshopModelQualification').createSecureShopModelQualifier(actual.provider);
  assert.equal(qualify({provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false}),true);
  assert.equal(qualify({provider:'ollama',model:'llama3.1:8b',mocked:true}),false);
  const judge=require('./fixtures/secureshopInventoryActualJudge').createActualInventoryJudge({actual,record:()=>{}});
  assert.equal(typeof judge.judge,'function');assert.equal(judge.calls.length,0);assert.equal(actual.evidence.calls.length,0);assert.equal(actual.evidence.httpCalls.length,0);assert.equal(tags,1);
  actual.close();assert.equal(global.fetch,tagFixture);
 }finally{actual?.close();global.fetch=original;}
});
test('reviewed inventory eligibility staging is a strict no-op with complete defaults and remains disabled',()=>{
 const fs=require('node:fs'),vm=require('node:vm'),file=require.resolve('../server/config/secureshopCurriculum'),original=fs.readFileSync(file,'utf8');
 const helper=require('./fixtures/secureshopInventoryCandidateCatalog'),source=helper.stageInventoryCandidateCatalog(original),sandbox={module:{exports:{}}};vm.runInNewContext(source,sandbox);
 // Normalize cross-realm prototypes before using the same canonical serializer.
 const catalog=sandbox.module.exports;helper.validateInventoryCandidateCatalog({...catalog,HINTS:structuredClone(catalog.HINTS),SOLUTIONS:structuredClone(catalog.SOLUTIONS)});
 assert.equal(require(file).isQualifiedObjective('ss_inventory_cross_merchant_stock'),true);
 assert.equal(catalog.OBJECTIVES.find(row=>row.id==='ss_inventory_cross_merchant_stock').defaultEnabled,false);
 assert.equal(catalog.CHALLENGE.defaultVisible,false);
 assert.equal(source,original);assert.equal(helper.stageInventoryCandidateCatalog(source),source);
 assert.equal(fs.readFileSync(file,'utf8'),original);
 // Already-eligible sources still require the exact reviewed teaching contract.
 assert.throws(()=>helper.stageInventoryCandidateCatalog(original.replace(helper.HINT,helper.HINT+' Changed.')));
 assert.throws(()=>helper.stageInventoryCandidateCatalog(original.replace("{ id: 'ss_inventory_cross_merchant_stock', text:","{ id: 'unreviewed_inventory_identity', text:"))); 
});
