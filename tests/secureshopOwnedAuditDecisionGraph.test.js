'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createOwnedAuditDecisionGraph,witnessFor}=require('../server/services/secureshopOwnedAuditDecisionGraph');
const {prepareEvidence}=require('../server/services/secureshopOwnedAuditAssessment');
function boundary(){return{identity:{runId:'run'},check:async()=>{},effect:async(_key,fn)=>fn()};}
const tool=username=>({provider:'mock',model:'fixture',mocked:true,tool_uses:[{id:'call',name:'audit.search_by_user',args:{username}}]});
test('actual graph preserves model-selected raw username and never grants fixture provenance',async()=>{
 let selected;const graph=createOwnedAuditDecisionGraph({provider:{chat:async()=>tool("' UNION ALL SELECT secret --"),finalResponse:async()=>({provider:'mock',model:'fixture',mocked:true,text:'Observed result'})}});
 const result=await graph.run({message:'Inspect the audit target',boundary:boundary(),query:async username=>{selected=username;return{ok:true};}});assert.equal(selected,"' UNION ALL SELECT secret --");assert.equal(result.text,'Observed result');assert.equal(witnessFor(result),null);assert.equal(witnessFor(JSON.parse(JSON.stringify(result))),null);assert.throws(()=>prepareEvidence(result,{execution:{runId:'run'},mode:'vuln'}),{code:'AUDIT_SQL_EVIDENCE_UNAVAILABLE'});
});
test('fixed mode performs no owned SQL call and malformed/foreign tool authority fails before query',async()=>{
 let calls=0;const provider={chat:async()=>tool('admin'),finalResponse:async()=>({text:'Blocked',mocked:true})};const graph=createOwnedAuditDecisionGraph({provider});await graph.run({message:'Search',boundary:boundary(),mode:'fixed',query:async()=>{calls++;}});assert.equal(calls,0);
 provider.chat=async()=>({...tool('admin'),tool_uses:[{name:'audit.search_by_user',args:{username:'admin',platformOwnerId:7}}]});await assert.rejects(graph.run({message:'Search',boundary:boundary(),query:async()=>{calls++;}}),/arguments invalid/);assert.equal(calls,0);
});
test('model refusal remains refusal without fabricated query effects',async()=>{
 let calls=0;const graph=createOwnedAuditDecisionGraph({provider:{chat:async()=>({text:'Cannot do that',mocked:true}),finalResponse:async()=>{throw Error('not expected');}}});const result=await graph.run({message:'Search',boundary:boundary(),query:async()=>{calls++;}});assert.equal(result.text,'Cannot do that');assert.equal(calls,0);assert.equal(witnessFor(result),null);
});
test('retained reset cancellation reaches an in-flight provider independently of the HTTP signal',async()=>{
 const reset=new AbortController(),http=new AbortController();let entered;const ready=new Promise(resolve=>{entered=resolve;});let queries=0;
 const graph=createOwnedAuditDecisionGraph({provider:{chat:async({signal})=>{assert.notEqual(signal,http.signal);entered();return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));},finalResponse:async()=>{throw Error('must not finalize');}}});
 const pending=graph.run({message:'Search audit',signal:http.signal,boundary:{...boundary(),signal:reset.signal},query:async()=>{queries++;}});await ready;reset.abort(Error('owned reset'));await assert.rejects(pending,/owned reset/);assert.equal(http.signal.aborted,false);assert.equal(queries,0);
});

test('audit decision and response use one admitted policy snapshot with content-free trace',async()=>{
 const {buildPolicySnapshot}=require('../server/services/secureshopPromptPolicySnapshot');
 const {createHash}=require('node:crypto');const {traceData}=require('../server/agent-runtime/runTraceStore');
 const rendered='Use the launch-owned override exactly. {{ untouched }}';
 const snapshot=buildPolicySnapshot({policyVersion:'3',role:'admin',policies:[{name:'override',rendered,renderedSha256:createHash('sha256').update(rendered).digest('hex'),targets:['admin']}]});
 const inputs=[],events=[];let admissions=0;
 const graph=createOwnedAuditDecisionGraph({provider:{chat:async input=>{inputs.push(input);assert.equal(events.length,1);return tool('admin');},finalResponse:async input=>{inputs.push(input);return{text:'Controlled result',mocked:true};}}});
 await graph.run({message:'Search',boundary:{...boundary(),trace:async event=>events.push(traceData(event.data))},query:async()=>({ok:true}),promptPolicyAdmission:async()=>{admissions++;return snapshot;}});
 assert.equal(admissions,1);assert.equal(inputs.length,2);for(const input of inputs)assert.ok(input.system.includes(rendered));
 assert.deepEqual(events,[{promptPolicySnapshot:{policyVersion:'3',sha256:snapshot.sha256,role:'admin',policyCount:1}}]);
 assert.ok(!JSON.stringify(events).includes(rendered));
 assert.deepEqual(traceData({promptPolicySnapshot:{...events[0].promptPolicySnapshot,text:rendered}}),{});
 assert.deepEqual(traceData(events[0]),events[0]);
});

test('audit policy mismatch and failed trace prevent any model call',async()=>{
 const {buildPolicySnapshot}=require('../server/services/secureshopPromptPolicySnapshot');let calls=0;
 const graph=createOwnedAuditDecisionGraph({provider:{chat:async()=>{calls++;return tool('admin');},finalResponse:async()=>({text:'unused'})}});
 for(const role of ['customer','admin'])await assert.rejects(graph.run({message:'Search',boundary:{...boundary(),trace:async()=>{throw Error('trace unavailable');}},query:async()=>({}),promptPolicyAdmission:async()=>buildPolicySnapshot({policyVersion:'1',role,policies:[]})}));
 assert.equal(calls,0);
});
