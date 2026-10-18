'use strict';
const assert=require('node:assert/strict'),C=require('./dpiCurrentOwnedContractV2');
function wireMessages(messages){return messages.map(m=>({role:m.role,content:m.content,...(m.tool_calls?.length?{tool_calls:m.tool_calls.map(c=>({id:c.id,type:'function',function:{name:c.function.name,arguments:typeof c.function.arguments==='string'?JSON.parse(c.function.arguments):c.function.arguments}}))}:{})}));}
function bindTranscript(transcript,rows,record){
 assert(transcript.complete,'Incomplete diagnostic cannot establish Judge provenance');
 const packet=typeof record.packet==='string'?JSON.parse(record.packet):record.packet;
 assert.deepEqual(JSON.parse(transcript.header.packet),packet);
 const wire=rows.filter(x=>x.kind==='judge');assert.equal(wire.length,transcript.calls.length);
 for(const [i,call]of transcript.calls.entries()){
  const row=wire[i];assert.equal(row.terminal,'returned');assert.equal(C.sha(row.request),row.requestSha256);
  const req=JSON.parse(row.request),out=C.responseText(row);
  assert.equal(call.request.method,'chat');assert.deepEqual(req.messages,call.request.input);assert.deepEqual(req.format,call.request.schema);
  assert.equal(req.options.temperature,call.request.options.temperature);assert.equal(req.options.num_ctx,call.request.options.num_ctx);assert.equal(req.options.num_predict,call.request.options.num_predict??call.request.options.max_tokens);
  assert.equal(call.response,out.text);assert.equal(call.responseSha256,C.sha(out.text));assert.equal(call.metadata.provider,'ollama');assert.equal(call.metadata.model,C.MODEL);assert.notEqual(call.metadata.mocked,true);assert.notEqual(call.metadata.fallback,true);
 }
 return {judgeCalls:wire.length,transcriptSha256:transcript.transcriptSha256};
}
function bindActor(capture,rows,packet,effects,{requirePolicyBinding=false}={}){
 assert.equal(typeof requirePolicyBinding,'boolean');
 const mode=capture.mode??'vuln';assert(['vuln','fixed'].includes(mode),'Closed captured mode required');
 if(capture.objective==='obfuscation')assert.equal(mode,'vuln','Fixed decoder uses the publication binder');
 const required=capture.objective==='obfuscation'?'owned_decoder':['virtualization','jailbreak','role_playing','side_stepping'].includes(capture.objective)?'owned_actor':null;
 if(required){const matches=packet.evidence.filter(x=>x.id===required);assert.equal(matches.length,1,'Exact required owned evidence');assert(matches[0].content,'Missing owned evidence cannot establish actor qualification');}
 const actors=rows.filter(x=>x.kind==='actor');assert.equal(actors.length,capture.actor.length);assert(actors.length>=1);
 for(const [i,observed]of capture.actor.entries()){
  const row=actors[i],req=JSON.parse(row.request),raw=C.responseText(row);assert.equal(row.terminal,'returned');assert.equal(C.sha(row.request),row.requestSha256);
  assert.deepEqual(req.messages,wireMessages(observed.messages));assert.equal(raw.text,observed.result.response);assert.equal(observed.result.provider,'ollama');assert.equal(observed.result.model,C.MODEL);assert.notEqual(observed.result.mocked,true);assert.notEqual(observed.result.fallback,true);
 }
 assert.equal(capture.actor[0].messages.at(-1).content,capture.message);
 assert.equal(packet.evidence.find(x=>x.id==='request').content,capture.message);assert.equal(packet.evidence.find(x=>x.id==='response').content,capture.body.response);
 const ownerKey=JSON.stringify(['DPI',capture.ownerId]);
 for(const evidence of packet.evidence.filter(x=>['owned_actor','owned_decoder'].includes(x.id)&&x.content)){
  assert.equal(evidence.source,'server_observation');const p=evidence.content;assert.equal(p.ownerKey,ownerKey);assert.equal(p.runId,capture.runId);assert.equal(p.generation,capture.generation);assert.equal(p.mode,mode);assert.equal(p.requestSha256,C.sha(capture.message));assert.equal(p.responseSha256,C.sha(capture.body.response));
  if(evidence.id==='owned_actor'){assert.equal(p.model,C.MODEL);assert.equal(p.provider,'ollama');assert.equal(p.modelResponseSha256,C.sha(capture.actor.at(-1).result.response));}
  else{
   assert.equal(p.selectedModel.responseSha256,C.sha(capture.actor[0].result.response));assert.equal(p.finalModel.responseSha256,C.sha(capture.actor.at(-1).result.response));
   for(const model of [p.selectedModel,p.finalModel]){assert.equal(model.provider,'ollama');assert.equal(model.model,C.MODEL);}
   if(p.receipt){const matching=effects.filter(x=>x.effect_key===p.receipt.effectKey);assert.equal(matching.length,1);assert.equal(matching[0].status,'completed');assert.equal(matching[0].owner_key,ownerKey);assert.equal(matching[0].run_id,capture.runId);assert.equal(String(matching[0].generation),capture.generation);assert.equal(require('../../server/agent-runtime/dpiDecoderEvidence').validateDecoderEvidence(p,capture.message,capture.body.response,mode),true);}
  }
 }
 if(requirePolicyBinding){
  const binding=require('../../server/agent-runtime/dpiPolicyBinding'),policy=require('../../server/agent-runtime/dpiPolicyContract');
  assert.equal(packet.rubric.dpiPolicyBinding,binding.VERSION);assert.equal(packet.rubric.objectiveId,capture.objective);assert.equal(packet.rubric.mode,mode);
  const envelope=binding.admitPolicyBinding(packet),proof=envelope.proof;
  assert.equal(proof.runId,capture.runId);assert.equal(proof.ownerKey,ownerKey);assert.equal(proof.generation,capture.generation);
  assert.deepEqual(proof.policy,policy.selectPolicy({objectiveId:capture.objective,mode}));
  if(capture.objective==='obfuscation'){
   const graph=require('../../server/agent-runtime/dpiObfuscationGraph');
   assert.deepEqual(capture.actor[0].messages,[{role:'system',content:policy.DECISION_POLICY},{role:'user',content:capture.message}]);
   assert.equal(proof.decisionMessagesSha256,C.sha(JSON.stringify(capture.actor[0].messages)));
   assert.equal(proof.decisionRaw,capture.actor[0].result.response);
   assert.equal(capture.actor.length,proof.decision.action==='decode_payload'?2:1);
   if(proof.decision.action==='decode_payload'){
    const messages=graph.finalMessages(capture.message,proof.output,mode,proof.decisionRaw);
    assert.deepEqual(capture.actor[1].messages,messages);
    assert.equal(proof.finalMessagesSha256,C.sha(JSON.stringify(capture.actor[1].messages)));
    assert.deepEqual(proof.assembly,graph.assemblyProof(capture.message,proof.output,mode,proof.decisionRaw));
   }
  }else{
   assert.equal(capture.actor.length,1);
   assert.equal(proof.messagesSha256,policy.validateActorMessages(capture.actor[0].messages,capture.message,proof.policy));
   assert.equal(proof.modelResponseSha256,C.sha(capture.actor[0].result.response));
  }
 }
 assert.equal(effects.length,packet.evidence.find(x=>x.id==='owned_decoder')?.content?.receipt?1:0);
 return {actorCalls:actors.length,effects:effects.length};
}
module.exports={bindTranscript,bindActor,wireMessages};
