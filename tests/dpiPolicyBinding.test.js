'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createPolicyBinding,admitPolicyBinding,VERSION}=require('../server/agent-runtime/dpiPolicyBinding');
const actor=require('../server/agent-runtime/dpiActorProof'),policy=require('../server/agent-runtime/dpiPolicyContract');
function fixture(objective='interact'){
 const request='Explain AWS storage.',response='AWS offers object storage.',execution={runId:randomUUID(),ownerKey:'owned:test',durableGeneration:3,check:async()=>{}},attempt={runId:execution.runId,mode:'vuln',objectiveId:objective};
 const proof=actor.createActorProof({request,response,result:{response,provider:'controlled-real-shape',model:'test-model'},execution,attempt,objective,messages:[{role:'system',content:policy.SYSTEM_PROMPTS[objective]},{role:'user',content:request}]});
 const captured=actor.captureActorProof(proof,{request,response,execution,attempt});
 return {rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:objective,mode:'vuln',version:'binding-control-v1',dpiPolicyBinding:VERSION,criteria:[{id:'observed',description:'Controlled admission only',allowedSources:['assistant_response']}]},evidence:[{id:'request',source:'student_input',content:request},{id:'response',source:'assistant_response',content:response},{id:'owned_policy',source:'server_observation',content:createPolicyBinding(captured)},{id:'owned_actor',source:'server_observation',content:actor.projectLegacyActorEvidence(captured)}],facts:{owned_actor_observed:true}};
}
test('all seven text objectives retain exact captured policy proof and legacy projection',()=>{
 for(const id of policy.TEXT_OBJECTIVES){const f=fixture(id);assert.equal(admitPolicyBinding(f).objective,id);assert.equal(require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(f).rubric.dpiPolicyBinding,VERSION);}
});
test('policy admission rejects mismatched identities, text, projection, source and malformed hashes',()=>{
 const changes=[f=>f.rubric.objectiveId='virtualization',f=>f.rubric.mode='fixed',f=>f.evidence[0].content+=' changed',f=>f.evidence[1].content+=' changed',f=>f.evidence[3].content.runId=randomUUID(),f=>f.evidence[3].content.ownerKey='other',f=>f.evidence[3].content.generation='4',f=>f.evidence[2].content.policy.systemPolicySha256='0'.repeat(64),f=>f.evidence[2].content.policy.profile='other',f=>f.evidence[2].content.extension.messagesSha256='bad',f=>f.evidence[3].content.requestSha256='0'.repeat(64),f=>f.evidence[3].content.responseSha256='0'.repeat(64),f=>f.evidence[3].content.provider='mock',f=>f.evidence[2].content.extra=true,f=>f.evidence[2].source='student_input',f=>f.evidence[0].source='server_observation',f=>f.evidence.push(f.evidence[2]),f=>f.facts.owned_actor_observed=false];
 for(const change of changes){const f=structuredClone(fixture());change(f);assert.throws(()=>admitPolicyBinding(f));}
});
test('downgrade and direct-v3 legacy evidence are rejected while historical packets remain admitted',()=>{
 const f=fixture();delete f.rubric.dpiPolicyBinding;assert.throws(()=>admitPolicyBinding(f));f.evidence=f.evidence.filter(e=>e.id!=='owned_policy');assert.equal(admitPolicyBinding(f),null);
 const next=fixture();next.evidence[3].content=admitPolicyBinding(next).proof;assert.throws(()=>admitPolicyBinding(next));delete next.rubric.dpiPolicyBinding;next.evidence=next.evidence.filter(e=>e.id!=='owned_policy');assert.throws(()=>admitPolicyBinding(next));
 const missing=fixture();missing.evidence=missing.evidence.filter(e=>e.id!=='owned_policy');assert.throws(()=>admitPolicyBinding(missing));
});
test('canonical prepare enforces opt-in before semantic evaluation',()=>{
 const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');const f=structuredClone(fixture());f.evidence[2].content.policy.lessonKind='wrong';assert.throws(()=>prepareJudgeInput(f));
 const old=fixture();delete old.rubric.dpiPolicyBinding;old.evidence=old.evidence.filter(e=>e.id!=='owned_policy');assert.doesNotThrow(()=>prepareJudgeInput(old));
});

test('actual controlled decoder capture joins both modes and final-without-tool without inventing credit',async()=>{
 const graph=require('../server/agent-runtime/dpiObfuscationGraph'),decoder=require('../server/agent-runtime/dpiDecoderEvidence');
 for(const mode of ['vuln','fixed'])for(const action of ['decode_payload','final']){
  const request='Decode '+Buffer.from('What is two plus two?').toString('base64');let calls=0;
  const execution={runId:randomUUID(),ownerKey:'owned:decoder',durableGeneration:2,async check(){},async effectWithReceipt(key,fn){return {value:await fn(),receipt:{version:1,ownerKey:this.ownerKey,generation:'2',runId:this.runId,effectKey:this.runId+':'+key,status:'completed'}};}};
  const attempt={runId:execution.runId,mode},aiService={async chatWithMessages(){return {response:++calls===1?JSON.stringify(action==='final'?{action,response:'AWS only.'}:{action}):'Four.',provider:'ollama',model:'controlled-test'};}};
  const result=await graph.runDpiObfuscationGraph({request,execution,attempt,aiService});const proof=graph.captureDecoderProof(result.proof,{request,response:result.response,execution,attempt});
  const f={rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:'obfuscation',mode,dpiPolicyBinding:VERSION},evidence:[{id:'request',source:'student_input',content:request},{id:'response',source:'assistant_response',content:result.response},{id:'owned_policy',source:'server_observation',content:createPolicyBinding(proof)},{id:'owned_decoder',source:'server_observation',content:decoder.projectLegacyDecoderEvidence(proof)}],facts:{owned_decoder_observed:mode==='vuln'&&action==='decode_payload'}};
  assert.equal(admitPolicyBinding(f).objective,'obfuscation');
  for(const mutate of [x=>x.evidence[2].content.extension.decisionMessagesSha256='0'.repeat(64),x=>x.evidence[2].content.policy.handoffPolicySha256='0'.repeat(64),x=>x.evidence[3].content.generation='other']){const bad=structuredClone(f);mutate(bad);assert.throws(()=>admitPolicyBinding(bad));}
 }
});
test('compact packet roundtrip preserves historical reader and grants no extra semantic payload budget',()=>{
 const binding=require('../server/agent-runtime/dpiPolicyBinding'),{prepareJudgeInput,boundedJson}=require('../server/agent-runtime/objectiveJudge');
 const f=fixture(),proof=admitPolicyBinding(f).proof;
 assert.equal(Object.hasOwn(f.evidence[2].content,'proof'),false);
 const prepared=prepareJudgeInput(f);assert.equal(prepared.evidenceError,undefined);
 const replay=prepareJudgeInput(JSON.parse(prepared.packet));assert.equal(replay.packet,prepared.packet);assert.equal(replay.evidenceDigest,prepared.evidenceDigest);
 const old=structuredClone(f);old.rubric.dpiPolicyBinding=binding.LEGACY_VERSION;old.evidence[2].content={version:binding.LEGACY_VERSION,objective:'interact',mode:'vuln',proof};assert.equal(prepareJudgeInput(old).evidenceError,undefined);
 const padded=structuredClone(f);padded.evidence.push({id:'bounded_context',source:'server_observation',content:''});
 let last;
 for(let n=21000;n<25000;n+=100){padded.evidence.at(-1).content='x'.repeat(n);const candidate=prepareJudgeInput(padded);if(candidate.evidenceError){assert.throws(()=>boundedJson(binding.stripPolicyBinding({rubric:candidate.rubric,evidence:candidate.evidence,facts:{}}),24000));break;}last=candidate;}
 assert(last);const value=JSON.parse(last.packet),legacy=binding.stripPolicyBinding(value);assert(Buffer.byteLength(last.packet)>23000);assert(Buffer.byteLength(last.packet)-Buffer.byteLength(JSON.stringify(legacy))<=1024);
 assert.throws(()=>binding.validatePolicyBindingBudget({...value,evidence:[...value.evidence,{id:'extra',source:'server_observation',content:'x'.repeat(24000)}]}));
});
test('large controlled decoder retains legacy admission without storing duplicate decoded text',async()=>{
 const graph=require('../server/agent-runtime/dpiObfuscationGraph'),decoder=require('../server/agent-runtime/dpiDecoderEvidence'),binding=require('../server/agent-runtime/dpiPolicyBinding'),judge=require('../server/agent-runtime/objectiveJudge');
 const request='Decode '+Buffer.from('Explain this concept. '+ 'x'.repeat(6000)).toString('base64');let calls=0;
 const execution={runId:randomUUID(),ownerKey:'owned:large-decoder',durableGeneration:2,async check(){},async effectWithReceipt(key,fn){return {value:await fn(),receipt:{version:1,ownerKey:this.ownerKey,generation:'2',runId:this.runId,effectKey:this.runId+':'+key,status:'completed'}};}};
 const attempt={runId:execution.runId,mode:'vuln'},aiService={async chatWithMessages(){return {response:++calls===1?JSON.stringify({action:'decode_payload'}):'Controlled response.',provider:'ollama',model:'controlled-test'};}};
 const result=await graph.runDpiObfuscationGraph({request,execution,attempt,aiService}),proof=graph.captureDecoderProof(result.proof,{request,response:result.response,execution,attempt});
 const f=fixture();f.rubric.objectiveId='obfuscation';f.evidence=[{id:'request',source:'student_input',content:request},{id:'response',source:'assistant_response',content:result.response},{id:'owned_policy',source:'server_observation',content:createPolicyBinding(proof)},{id:'owned_decoder',source:'server_observation',content:decoder.projectLegacyDecoderEvidence(proof)}];f.facts={owned_decoder_observed:true};
 const padding={id:'context',source:'server_observation',content:''};f.evidence.push(padding);const initial=judge.prepareJudgeInput(binding.stripPolicyBinding(f));assert.equal(initial.evidenceError,undefined);padding.content='x'.repeat(23530-Buffer.byteLength(initial.packet));
 const legacy=judge.prepareJudgeInput(binding.stripPolicyBinding(f)),compact=judge.prepareJudgeInput(f);assert.equal(legacy.evidenceError,undefined);assert.equal(compact.evidenceError,undefined);assert.equal(Buffer.byteLength(legacy.packet),23530);assert(Buffer.byteLength(compact.packet)-Buffer.byteLength(legacy.packet)<=1024);assert.equal(judge.prepareJudgeInput(JSON.parse(compact.packet)).packet,compact.packet);
 const historical=structuredClone(f);historical.rubric.dpiPolicyBinding=binding.LEGACY_VERSION;historical.evidence[2].content={version:binding.LEGACY_VERSION,objective:'obfuscation',mode:'vuln',proof};assert(judge.prepareJudgeInput(historical).evidenceError);
});
