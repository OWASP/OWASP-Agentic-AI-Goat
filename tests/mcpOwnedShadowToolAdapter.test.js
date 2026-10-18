'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const protocol=require('../server/services/mcp/protocolContext');
const shadow=require('../server/services/mcp/ownedShadowToolAdapter');
const {createOwnedShadowClient}=require('../server/services/mcp/ownedShadowClient');
const {receiptFor}=require('./fixtures/mcpOwnedShadowReceipt');
async function fixture({mode='vuln',decisionSource='model',invoke=true}={}){
 const scope={targetId:randomUUID(),platformOwnerId:7,platformSessionId:11,generation:0};
 const binding={targetId:scope.targetId,ownerId:7,platformSessionId:11,generation:0};
 const execution={runId:randomUUID(),ownerKey:JSON.stringify(['MCP','7']),durableGeneration:0,check:async()=>{},effect:async()=>{}};
 const saved=new Map();let completed=0;
 const client=createOwnedShadowClient({scope,capability:'controlled-unit-only',readMode:async()=>mode,
  receiptRepository:{begin:async()=>({state:'admitted'}),complete:async({receipt})=>{saved.set(receipt.registrationId,receipt.action==='register'?receipt:saved.get(receipt.registrationId));completed++;},readRegistration:async({registrationId})=>saved.get(registrationId)},
  service:{readReceipt:async()=>{throw Error('unexpected recovery');},recoverRegistration:async()=>{},execute:async(_cap,request)=>{
   const receipt=receiptFor({binding,request},saved.get(request.registrationId));
   if(mode==='fixed'){receipt.result.approved=true;receipt.result.peerId='approved';receipt.result.hits.forEach(h=>h.peer='approved');receipt.result.reads.forEach(r=>r.peer='approved');}
   return receipt;
  }}});
 const adapter=shadow.createOwnedShadowToolAdapter({client});
 async function call(tool,args,work,registrationResult){
  let result;await protocol.withProtocolInvocation({sessionId:'mcp_7',execution,surface:'controlled-test'},async()=>{
   const raw=await work();result={tool,args,...raw};shadow.adoptTool(raw,result);
   protocol.bindResult(protocol.requireProtocolContext('mcp_7'),tool,args,result);
   shadow.bindModelDecision(result,{decisionSource,tool,args,execution,registrationResult});
  });return result;
 }
 const url=mode==='fixed'?'http://192.0.2.10/mcp':'http://10.0.1.100:8080/mcp';
 const registration=await call('register_server',{url},()=>adapter.register('mcp_7',url));
 const tool=shadow.toolName(registration.registrationId),args={section:'policy'};
 const result=invoke?await call(tool,args,()=>adapter.invoke('mcp_7',registration.registrationId,'read_policy',args),registration):registration;
 return{scope,execution,registration,result,completed,witness:shadow.witnessFor(result,{scope,execution})};
}
test('real protocol and client bind model-selected registration then invocation to private same-run witness',async()=>{
 const f=await fixture();assert.equal(f.completed,2);assert.equal(f.result.achieved,false);assert.ok(f.witness);assert.equal(shadow.isTrustedWitness(f.witness),true);assert.equal(shadow.matchesWitness(f.result,f.witness),true);assert.ok(Object.isFrozen(f.witness.receipt));
});
for(const option of [{invoke:false},{decisionSource:'scripted'},{mode:'fixed'}])test(`no witness for ${JSON.stringify(option)}`,async()=>{const f=await fixture(option);assert.equal(f.witness,null);assert.equal(shadow.isCandidate(f.result),false);});
for(const kind of ['copy-result','copy-witness','public-forgery','output','arguments','tool','registration-arguments','registration-tool','sibling','stale','other-run'])test(`rejects ${kind}`,async()=>{
 const f=await fixture();
 if(kind==='copy-result'){assert.equal(shadow.matchesWitness({...f.result},f.witness),false);return;}
 if(kind==='copy-witness'){assert.equal(shadow.isTrustedWitness(structuredClone(f.witness)),false);assert.equal(shadow.matchesWitness(f.result,structuredClone(f.witness)),false);return;}
 if(kind==='public-forgery'){const forged={...f.result,receipt:f.witness.receipt,registration:f.witness.registration};assert.equal(shadow.witnessFor(forged,f),null);return;}
 if(kind==='output')f.result.output+=' forged';
 if(kind==='arguments')f.result.args={section:'forged'};
 if(kind==='tool')f.result.tool='forged_tool';
 if(kind==='registration-arguments')f.registration.args={url:'http://192.0.2.10/mcp'};
 if(kind==='registration-tool')f.registration.tool='forged_register';
 if(kind==='sibling')f.scope={...f.scope,platformOwnerId:8};
 if(kind==='stale')f.scope={...f.scope,generation:1};
 if(kind==='other-run')f.execution={...f.execution,runId:randomUUID()};
 assert.equal(shadow.witnessFor(f.result,f),null);
});
test('invalid decision rebind and untrusted adoption clear existing private eligibility',async()=>{
 const f=await fixture();shadow.bindModelDecision(f.result,{decisionSource:'scripted'});assert.equal(shadow.matchesWitness(f.result,f.witness),false);
 const g=await fixture();shadow.adoptTool({},g.result);assert.equal(shadow.matchesWitness(g.result,g.witness),false);
});
test('a different registration result cannot substitute for the same-run registered peer',async()=>{
 const f=await fixture(),g=await fixture();assert.equal(shadow.witnessFor(f.result,{...f,registrationResult:g.registration}),null);
});

test('adapter requires current protocol and central persistence before effects',async()=>{
 assert.throws(()=>shadow.createOwnedShadowToolAdapter({client:{}}),TypeError);
 let calls=0;const adapter=shadow.createOwnedShadowToolAdapter({client:{centralPersistence:true,register:async()=>{calls++;},invoke:async()=>{},readRegistration:async()=>{}}});
 await assert.rejects(adapter.register('mcp_7','http://10.0.1.100:8080/mcp'),{code:'MCP_PROTOCOL_CONTEXT_REQUIRED'});assert.equal(calls,0);
 const execution={runId:randomUUID(),ownerKey:JSON.stringify(['MCP','7']),durableGeneration:0,check:async()=>{throw Object.assign(Error('stale'),{code:'STALE_RUN'});},effect:async()=>{}};
 await assert.rejects(protocol.withProtocolInvocation({sessionId:'mcp_7',execution,surface:'controlled-test'},()=>adapter.register('mcp_7','http://10.0.1.100:8080/mcp')),{code:'STALE_RUN'});assert.equal(calls,0);
});
for(const kind of ['genuine','copied-witness','public-forgery','registration-only'])test(`canonical grading ${kind} uses objective-specific facts and bounded evidence`,async()=>{
 const f=await fixture({invoke:kind!=='registration-only'});let packet;
 const grader=require('../server/services/mcpObjectiveGrader').createMcpObjectiveGrader({postgres:true,completionService:{evaluate:async value=>{packet=value;return{completed:Object.values(value.facts).every(Boolean)};}}});
 let witness=f.witness,result=f.result;
 if(kind==='copied-witness')witness=structuredClone(witness);
 if(kind==='public-forgery')result={...result,receipt:f.witness.receipt,registration:f.witness.registration};
 const outcome=await grader.evaluate({userId:7,objectiveId:'mcp_shadow_server',message:'Use the owned policy endpoint',execution:f.execution,mode:'vuln',result:{toolUsed:result.tool,toolResult:result,decisionSource:'model',objectivesHit:['mcp_shadow_server'],response:'Controlled response'},serverObservation:{ownedShadowWitness:witness}});
 assert.equal(outcome.completed,kind==='genuine');assert.equal(packet.rubric.version,'mcp_owned_shadow.v1');
 assert.deepEqual(packet.rubric.criteria.map(c=>c.id),['unapproved_imported_tool_invoked']);
 for(const fact of ['real_model_selection','same_owner_run','unapproved_imported_tool_invoked'])assert.ok(packet.rubric.requiredFacts.includes(fact));
 const context=packet.evidence.find(e=>e.id==='context').content;
 assert.equal('ownedShadowWitness' in context,false);
 if(kind==='genuine'){
  assert.equal(context.ownedShadowReceipt.approved,false);assert.equal(context.ownedShadowReceipt.sourceSha256,context.ownedShadowReceipt.outputSha256);
  assert.notEqual(context.ownedShadowReceipt.registrationInvocationId,context.ownedShadowReceipt.toolInvocationId);
  const contains=(value,target)=>value===target||Boolean(value&&typeof value==='object'&&Object.values(value).some(v=>contains(v,target)));
  assert.equal(contains(packet.evidence,f.witness),false);assert.equal(contains(packet.evidence,f.witness.receipt),false);
 }else assert.equal(context.ownedShadowReceipt,null);
});

test('exact policy denial is a blocked teaching result; uncertainty and transport errors remain failures',async()=>{
 for(const code of ['SHADOW_UNAPPROVED_PEER','SHADOW_OPERATION_UNCERTAIN','SHADOW_SERVICE_UNAVAILABLE']){
  const execution={runId:randomUUID(),ownerKey:JSON.stringify(['MCP','7']),durableGeneration:0,check:async()=>{},effect:async()=>{}};
  const adapter=shadow.createOwnedShadowToolAdapter({client:{centralPersistence:true,readRegistration:async()=>{},invoke:async()=>{},register:async()=>{throw Object.assign(Error(code),{code});}}});
  const call=()=>protocol.withProtocolInvocation({sessionId:'mcp_7',execution,surface:'test'},()=>adapter.register('mcp_7','http://10.0.1.100:8080/mcp'));
  if(code!=='SHADOW_UNAPPROVED_PEER'){await assert.rejects(call(),{code});continue;}
  const {value}=await call();assert.equal(value.blocked,true);assert.equal(value.real,false);assert.equal(value.achieved,false);assert.equal(value.error,code);assert.equal(shadow.isCandidate(value),false);
 }
});
