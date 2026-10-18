'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCsrfDurableRagResources}=require('../server/services/csrfDurableRagResources');
async function fixture(tab={}){
 const docs={clean:null,poison:null},calls=[],receipts=[];
 const authority={ownerId:11,read:async({slot})=>({documentId:docs[slot]?.id||null,document:docs[slot]}),bind:async(_, {slot})=>({ingestAndSelect:async input=>{calls.push(input);docs[slot]={id:input.documentId};return{documentId:input.documentId};},search:async input=>{calls.push(input);return{chunks:[{text:'real source'}],receipt:{documentId:input.documentId}};}})};
 return{tab,docs,calls,receipts,resources:await createCsrfDurableRagResources({composition:{resolveRequest:async()=>authority},request:{},execution:{runId:'run'},tab,cleanText:'Exact canonical clean source',noteReceipt:r=>receipts.push(r)})};
}
test('missing durable poison preserves saved text/flags and blocks retrieval until explicit upload or reset',async()=>{const f=await fixture({ragDocText:'untrusted original',ragPoisoned:true,ragSessionId:'legacy'});await f.resources.ensureClean();await assert.rejects(f.resources.assertPoisonAvailable(),{code:'CSRF_RAG_RESOURCE_UNAVAILABLE'});assert.equal(f.tab.ragDocText,'untrusted original');assert.equal(f.tab.ragSessionId,'legacy');assert.equal((await f.resources.state()).available,false);assert.equal(f.calls.length,1);assert.equal(f.calls[0].sourceBuffer.toString(),'Exact canonical clean source');assert.equal(f.calls[0].ingestionKind,'canonical_clean');});
test('durable selected document is restored and its exact retrieval receipt accompanies observed chunks',async()=>{const f=await fixture();f.docs.clean={id:'clean'};f.docs.poison={id:'poison'};await f.resources.ensureClean();await f.resources.assertPoisonAvailable();assert.equal(f.tab.ragSessionId,'poison');assert.equal((await f.resources.state()).available,true);assert.deepEqual(await f.resources.store.similaritySearch('11','poison','question',3),[{text:'real source'}]);assert.deepEqual(f.receipts,[{type:'rag_retrieval',receipts:[{documentId:'poison'}]}]);await assert.rejects(f.resources.store.similaritySearch('12','poison','question',3),{code:'CSRF_RAG_RESOURCE_UNAVAILABLE'});});
test('upload preserves exact source bytes, and old selected context cannot masquerade as a replaced document',async()=>{const f=await fixture({ragSessionId:'old'});await f.resources.uploadPoison('\uFEFF  exact poison\n');assert.equal(f.calls[0].sourceBuffer.toString(),'\uFEFF  exact poison\n');await assert.rejects(f.resources.store.similaritySearch('11','old','question',3),{code:'CSRF_RAG_RESOURCE_UNAVAILABLE'});assert.equal(f.receipts.length,0);});

test('retrieval operation identity retains exact arguments and distinguishes changed result limits',async()=>{
 const f=await fixture();f.docs.clean={id:'clean'};await f.resources.ensureClean();
 await f.resources.store.similaritySearch('11','clean','same question',3);
 await f.resources.store.similaritySearch('11','clean','same question',5);
 await f.resources.store.similaritySearch('11','clean','same question',3);
 assert.notEqual(f.calls[0].operationId,f.calls[1].operationId);
 assert.equal(f.calls[0].operationId,f.calls[2].operationId);
 assert.equal(f.calls[0].question,'same question');assert.equal(f.calls[1].limit,5);
});
