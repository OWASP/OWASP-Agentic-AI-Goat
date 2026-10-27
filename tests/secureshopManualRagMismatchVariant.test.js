'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const filename=path.join(__dirname,'postgres/secureshopManualRagRendered.integration.test.js');
const source=fs.readFileSync(filename,'utf8'),root=path.resolve(__dirname,'..');
function load(env={}){
 const real=require('node:module').createRequire(filename),module={exports:{}};
 vm.compileFunction(source,['require','module','process','__dirname'],{filename})(name=>{
  if(name==='node:test')return()=>{};
  if(name==='pg')return{Pool:class{constructor(){throw Error('No native allocation');}}};
  return real(name);
 },module,{env,cwd:()=>root,getuid:()=>process.getuid()},path.dirname(filename));
 return module.exports;
}
const variant='manual-similarity-mismatch-v1',marker='V26_'+'a'.repeat(32);
test('new variant requires existing paired selector and rejects unknown selection',()=>{
 assert.throws(()=>load({SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT:variant}));
 const env={SECURESHOP_MANUAL_RAG_PAIRED:'1',SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT:variant};
 assert.equal(load(env).payloadVariant(env),variant);
 assert.throws(()=>load({...env,SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT:'unknown'}));
 assert.equal(load().payloadVariant({}),null);
});
test('bounded manual retains original marker/demand and targets conditional mismatch',()=>{
 const h=load(),old=h.buildManualPayload(marker),candidate=h.buildManualPayload(marker,variant);
 assert.equal(candidate.demanded,old.demanded);assert.ok(candidate.bytes.length<1024);
 assert.ok(candidate.text.startsWith(old.text.slice(0,old.text.indexOf('Product comparison instruction:'))));
 assert.ok(candidate.text.includes('If product-search.similar returns that kind of list'));
 assert.ok(candidate.text.endsWith(candidate.demanded+'\n'));
 assert.notEqual(candidate.text,h.buildManualPayload(marker,'completion-record-v1').text);
 assert.notEqual(candidate.text,h.buildManualPayload(marker,'role-spoof-v1').text);
});
test('Fixed-only transport remains unallocated',async()=>{
 const h=load();let allocated=0;
 const x=await h.createDiagnosticJudge({fixedOnly:true,createTransport:()=>{allocated++;throw Error('unexpected');}});
 assert.equal(allocated,0);assert.equal(x.transport,null);await assert.rejects(x.judge());
});
