'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createListingImportReceiptAdapter}=require('../server/services/secureshopListingImportReceiptAdapter');
const {prepareListingAdmission,hash}=require('../server/services/secureshopListingJournalContract');
function setup({mode='vuln',xml=false,change=()=>{},contextChange=()=>{}}={}){
 const admission=prepareListingAdmission({scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode,catalogRevision:'0',
 request:{version:1,action:'import',operationId:randomUUID(),json_url:'http://supplier.invalid/catalog',xml_url:xml?'http://supplier.invalid/catalog.xml':null}});
 const raw={version:1,operationId:admission.request.operationId,requestSha256:admission.requestSha256,mode,
 products:[JSON.parse('{"name":"Teaching item","price":"5.25","description":"<img src=x onerror=owned()>","__proto__":{"ownedMarker":true}}')],
 sources:[{kind:'json',uri:admission.request.json_url,byteCount:100,sourceSha256:'a'.repeat(64),prototypeEffect:{observed:mode==='vuln',inheritedProperties:mode==='vuln'?[{name:'ownedMarker',valueSha256:hash('true')}]:[]}}]};
 if(xml){raw.products.push({name:'XML item',price:'12',description:'synthetic secret'});raw.sources.push({kind:'xml',uri:admission.request.xml_url,byteCount:100,sourceSha256:'b'.repeat(64),entityReads:[{name:'secret',uri:'file:///fixtures/secret.txt',byteCount:16,sha256:'c'.repeat(64)}]});}
 change(raw);const bytes=Buffer.from(JSON.stringify(raw)),handle=randomUUID(),calls=[];
 const attestations={async readVerifiedResult(receiptHandle,expected){calls.push({receiptHandle,expected});const context={...expected,receiptHandle,executorId:randomUUID(),packageSha256:'d'.repeat(64),isolation:'owned-listings.v1'};contextChange(context);return{bytes,context};}};
 return{admission,raw,bytes,handle,calls,adapter:createListingImportReceiptAdapter({attestations})};
}
test('trusted byte envelope normalizes products while retaining prototype and entity evidence',async()=>{
 const f=setup({xml:true}),result=await f.adapter.normalize(f.handle,f.admission);
 assert.equal(result.products.length,2);assert.equal(result.products[0].price,5.25);
 assert.equal(result.products[0].description,'<img src=x onerror=owned()>');
 assert.equal(Object.hasOwn(result.products[0],'__proto__'),false);assert.equal(({}).ownedMarker,undefined);
 assert.equal(result.sources[0].prototypeEffect.observed,true);assert.equal(result.sources[1].entityReads[0].uri,'file:///fixtures/secret.txt');
 assert.equal(result.executorReceiptSha256,hash(f.bytes));assert.equal(result.sources[0].parserEvidenceSha256,hash(JSON.stringify(f.raw.sources[0])));
 assert.deepEqual(Object.keys(f.calls[0].expected),['operationId','requestSha256','bindingSha256','targetId','mode']);
 assert.ok(Object.isFrozen(result.products[0]));
});
test('caller raw result cannot replace an attested opaque handle; mismatched attested scope denied',async()=>{
 const f=setup();await assert.rejects(f.adapter.normalize(f.raw,f.admission),{code:'LISTING_IMPORT_ATTESTATION_REQUIRED'});assert.equal(f.calls.length,0);
 for(const key of ['targetId','bindingSha256','operationId','mode','receiptHandle','isolation']){
  const bad=setup({contextChange:c=>{c[key]='wrong';}});
  await assert.rejects(bad.adapter.normalize(bad.handle,bad.admission),{code:'LISTING_IMPORT_ATTESTATION_MISMATCH'});
 }
});
test('exact admitted source set rejects missing, duplicate, reordered or substituted sources',async()=>{
 const changes=[r=>r.sources.pop(),r=>r.sources.reverse(),r=>r.sources.push(r.sources[0]),r=>{r.sources[0].uri='http://other.invalid';},r=>{r.sources[0].error='partial';},r=>{r.mode='fixed';}];
 for(const change of changes){const f=setup({xml:true,change});await assert.rejects(f.adapter.normalize(f.handle,f.admission));}
});
test('product normalization rejects authority fields, ambiguous aliases and malformed prices',async()=>{
 const patches=[{retailer_id:9},{id:99},{targetId:randomUUID()},{price:'1e8'},{price:'NaN'},{price:-1},{price:null},{price:1.005},{price:0.001},{templateSource:'x',template_source:'y'},{images:[],image_url:'x'},{name:''}];
 for(const patch of patches){const f=setup({change:r=>Object.assign(r.products[0],patch)});await assert.rejects(f.adapter.normalize(f.handle,f.admission));}
});
test('valid numeric cent prices are preserved exactly through normalization',async()=>{
 for(const price of [0,0.01,1.01,5.25,99999999.99]){
  const f=setup({change:r=>{r.products[0].price=price;}});
  assert.equal((await f.adapter.normalize(f.handle,f.admission)).products[0].price,price);
 }
});
test('aggregate source/entity and published row bounds fail instead of truncating',async()=>{
 for(const change of [r=>{r.sources[0].byteCount=1048577;},r=>{r.products=Array.from({length:101},()=>({name:'item'}));},r=>{r.products[0].description='x'.repeat(65537);}]){
  const f=setup({change});await assert.rejects(f.adapter.normalize(f.handle,f.admission));
 }
});
test('fixed mode cannot claim a prototype effect or external entity read',async()=>{
 const clean=setup({mode:'fixed'});assert.equal((await clean.adapter.normalize(clean.handle,clean.admission)).sources[0].prototypeEffect.observed,false);
 const polluted=setup({mode:'fixed',change:r=>{r.sources[0].prototypeEffect={observed:true,inheritedProperties:[{name:'polluted',valueSha256:'e'.repeat(64)}]};}});
 await assert.rejects(polluted.adapter.normalize(polluted.handle,polluted.admission));
 const external=setup({mode:'fixed',xml:true});await assert.rejects(external.adapter.normalize(external.handle,external.admission));
});
test('server admission is captured before awaiting attestation',async()=>{
 const f=setup(),prepared=JSON.parse(JSON.stringify(f.admission));let resume;
 const gate=new Promise(resolve=>{resume=resolve;});
 const adapter=createListingImportReceiptAdapter({attestations:{async readVerifiedResult(handle,expected){await gate;return{bytes:f.bytes,context:{...expected,receiptHandle:handle,executorId:randomUUID(),packageSha256:'f'.repeat(64),isolation:'owned-listings.v1'}};}}});
 const pending=adapter.normalize(f.handle,prepared);prepared.binding.mode='fixed';prepared.request.json_url='http://other.invalid';resume();
 assert.equal((await pending).sources[0].url,f.admission.request.json_url);
});
test('actual disposable import output crosses the receipt adapter without repeating its prototype effect',async()=>{
 const {executeOwnedListingImport}=require('../sidecars/sandbox-runner/owned-listings/import-executor');
 const f=setup();
 const raw=await executeOwnedListingImport({request:f.admission.request,mode:'vuln',
  readResource:async()=>Buffer.from('{"name":"Actual worker product","price":5.25,"__proto__":{"adapterLesson":"owned"}}')});
 // Controlled attestation seam: this checks component interoperability, not
 // managed namespace/channel attestation or model provenance.
 const adapter=createListingImportReceiptAdapter({attestations:{async readVerifiedResult(handle,expected){
  return{bytes:Buffer.from(JSON.stringify(raw)),context:{...expected,receiptHandle:handle,
   executorId:randomUUID(),packageSha256:'f'.repeat(64),isolation:'owned-listings.v1'}};
 }}});
 const normalized=await adapter.normalize(f.handle,f.admission);
 assert.equal(normalized.products[0].name,'Actual worker product');
 assert.equal(normalized.sources[0].prototypeEffect.observed,true);
 assert.equal(normalized.sources[0].prototypeEffect.inheritedProperties[0].name,'adapterLesson');
 assert.equal(Object.hasOwn(normalized.products[0],'__proto__'),false);
 assert.equal(({}).adapterLesson,undefined);
});
test('the two-source supplier JSON and HTTP entity shape crosses the import receipt adapter',async()=>{
 const {executeOwnedListingImport}=require('../sidecars/sandbox-runner/owned-listings/import-executor');
 const f=setup({xml:true});
 const entity='http://10.0.1.100:8080/entity.txt';
 const raw=await executeOwnedListingImport({request:f.admission.request,mode:'vuln',
  readResource:async uri=>Buffer.from(uri===f.admission.request.json_url
   ? JSON.stringify({products:[{name:'Supplier lamp',price:12,description:'Public supplier product'}]})
   : uri===f.admission.request.xml_url
     ? `<!DOCTYPE products [<!ENTITY owned SYSTEM "${entity}">]><products><product><name>Entity lamp</name><price>12</price><description>&owned;</description></product></products>`
     : uri===entity ? 'Owned HTTP entity' : (()=>{throw Error('Unexpected source');})())});
 const adapter=createListingImportReceiptAdapter({attestations:{async readVerifiedResult(handle,expected){
  return{bytes:Buffer.from(JSON.stringify(raw)),context:{...expected,receiptHandle:handle,
   executorId:randomUUID(),packageSha256:'f'.repeat(64),isolation:'owned-listings.v1'}};
 }}});
 const normalized=await adapter.normalize(f.handle,f.admission);
 assert.deepEqual(normalized.products.map(product=>product.name),['Supplier lamp','Entity lamp']);
 assert.equal(normalized.products[1].description,'Owned HTTP entity');
 assert.equal(normalized.sources[1].entityReads[0].uri,entity);
});
