'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const ROOT=path.resolve(__dirname,'..');
const P={
 loadGuard:()=>require('./../server/services/secureshopProtectedSourceDecision'),
 loadFixture:()=>require('./fixtures/secureshopCustomerDisclosureActual'),
 transform:file=>fs.readFileSync(path.join(ROOT,file),'utf8'),
 loadControlledSetup(){
  const filename=path.join(__dirname,'secureshopCustomerDisclosure.test.js');
  const source=fs.readFileSync(filename,'utf8'),m=new Module(filename);m.filename=filename;m.paths=Module._nodeModulePaths(__dirname);
  m._compile(source.slice(0,source.indexOf("test('source-derived"))+'\nmodule.exports={setup,scope,sessionId,requestId,persona,personaSession,full,POLICY,disclosureFor};',filename);
  return m.exports;
 }
};
const {buildBasePrompt}=require('../server/services/secureshop/supervisors/basePrompt');
const source=buildBasePrompt('customer');
const names=['summarizer.summarize_product','summarizer.explain_return_policy','uploads.upload_return_evidence','product-search.personalized_feed'];
const make=name=>({stop_reason:'tool_use',tool_uses:[{id:'controlled',name,args:{}}]});
const blocked=fn=>assert.throws(fn,{code:'CUSTOMER_DISCLOSURE_BLOCKED'});
test('actual public customer names: original false positive, decision route only',()=>{
 const old=require('../server/services/secureshopProtectedSourceDecision').createProtectedSourceDecision(source);
 const guard=P.loadGuard().createProtectedSourceDecision(source,{publicToolNames:names});
 for(const name of names){blocked(()=>old.inspect(make(name)));assert.deepEqual(guard.inspectDecision(make(name)),make(name));blocked(()=>guard.inspect(make(name)));}
});
test('source cannot authorize itself and catalog snapshot cannot be extended',()=>{
 const catalog=[names[0]],guard=P.loadGuard().createProtectedSourceDecision(source,{publicToolNames:catalog});catalog.push(names[1]);
 blocked(()=>guard.inspectDecision(make(names[1])));
 blocked(()=>P.loadGuard().createProtectedSourceDecision(source).inspectDecision(make(names[0])));
});
test('arguments, text, ids, nested name and malformed envelopes remain protected',()=>{
 const guard=P.loadGuard().createProtectedSourceDecision(source,{publicToolNames:names});
 for(const mutate of [x=>{x.tool_uses[0].args={name:names[0]};},x=>{x.text=names[0];},x=>{x.tool_uses[0].id=names[0];},x=>{x.tool_uses[0].extra=true;},x=>{x.stop_reason='end_turn';},x=>{x.tool_uses[0].args=[];},x=>{x.tool_uses[0].name+=' suffix';}]){const x=make(names[0]);mutate(x);blocked(()=>guard.inspectDecision(x));}
 const x=make(names[0]);x.tool_uses[0].args={content:source};blocked(()=>guard.inspectDecision(x));
});
test('actual authority captures trusted tools and changes provider boundary only',()=>{
 const s=P.transform('server/services/secureshopCustomerDisclosureAuthority.js');
 assert.ok(s.includes('publicToolNames:tools.map(tool=>`${tool.agent}.${tool.tool}`)'));
 assert.ok(s.includes('r.fixed?r.guard.inspectDecision(response):response'));
 assert.ok(s.includes('inspect:value=>r.fixed?r.guard.inspect(value):value'));
});
test('executed authority captures catalog once; provider route only; tool results stay strict',async t=>{
 const C=P.loadControlledSetup(),f=C.setup(t),catalog=[{agent:'summarizer',tool:'summarize_product'}];let reads=0;
 f.manifest.getForRole=()=>{reads++;return catalog;};
 const cap=await f.authority.capture(f.input),b=C.disclosureFor(cap,{sessionId:C.sessionId,role:'customer',callerId:3});
 catalog.push({agent:'uploads',tool:'upload_return_evidence'});
 let response=make(names[0]);const provider=b.provider({async chat(){return response;}}),input={role:'customer',ownerId:3,system:C.full(C.POLICY)};
 assert.deepEqual(await provider.chat(input),response);assert.equal(reads,1);
 response=make(names[2]);await assert.rejects(provider.chat(input),{code:'CUSTOMER_DISCLOSURE_BLOCKED'});
 blocked(()=>b.inspect(make(names[0])));assert.equal(b.metadata.decisionRevision,'trusted-public-tool-name-v1');
});
test('actual runtime denies old completed stamp and filters old Fixed history',async t=>{
 const C=P.loadControlledSetup(),f=C.setup(t,{tool:true});
 await f.runtime.run(f.input);
 const completed=f.claims.get(C.requestId);delete completed.result.taskMetadata.customerDisclosure.authority.decisionRevision;
 const count=f.calls.length;
 await assert.rejects(f.runtime.run(f.input),{code:'CUSTOMER_DISCLOSURE_REPLAY_STALE'});assert.equal(f.calls.length,count);
 // Fresh request uses the actual Fixed history filter, not an invented predicate.
 for(const row of f.messages)delete row.customerDisclosure.decisionRevision;
 const marker='obsolete-history-marker';f.messages.push({role:'assistant',content:marker,customerDisclosure:completed.result.taskMetadata.customerDisclosure.authority});
 await f.runtime.run({...f.input,requestId:'77777777-7777-4777-8777-777777777777'});
 const latest=f.calls.filter(x=>x.kind==='model').at(-1);
 assert.equal(JSON.stringify(latest.input).includes(marker),false);
});
test('actual source validator requires private decision revision',async t=>{
 const C=P.loadControlledSetup(),f=C.setup(t),original=require('./fixtures/secureshopDirectInjectionActual');
 f.manifest.getForRole=()=>original.originalCustomerTools();
 const cap=await f.authority.capture(f.input),b=C.disclosureFor(cap,{sessionId:C.sessionId,role:'customer',callerId:3});
 const policyBlock=await b.buildPolicyBlock('customer');
 const packet={version:1,system:C.full(C.POLICY),policyBlock,externalMcpBlock:'',tools:b.manifest.getForRole('customer'),authority:b.metadata};
 const fixture=P.loadFixture();assert.equal(fixture.validateSource(packet),packet);
 for(const value of [undefined,'wrong-revision']){const bad=structuredClone(packet);if(value===undefined)delete bad.authority.decisionRevision;else bad.authority.decisionRevision=value;assert.throws(()=>fixture.validateSource(bad));}

});
