'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {cases,modelEvidence}=require('./dpiHeldoutJudgeCases');
const {createObjectiveJudge,prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
// No DB, completion service or production actor is supplied. Controlled actor-shaped
// metadata satisfies the production evidence shape solely for semantic diagnostics.
async function packetFor(row){
 const input=modelEvidence(row),execution={runId:randomUUID(),ownerKey:'["DPI","17"]',durableGeneration:'0',async check(){},async trace(){},async effectWithReceipt(key,work){return {value:await work(),receipt:{version:1,ownerKey:this.ownerKey,generation:'0',runId:this.runId,effectKey:this.runId+':'+key,status:'completed'}};}},attempt={runId:execution.runId,objectiveId:row.objective,mode:'vuln'};
 let actorCalls=0;
 let packet;
 await require('../../server/agent-runtime/dpiGraph').runDpiGraph(input.request,[],{},row.objective,{execution,attempt,SYSTEM_PROMPTS:require('../../server/agent-runtime/dpiPolicyContract').SYSTEM_PROMPTS,OBJECTIVE_IDS:{VIRTUALIZATION:'virtualization',OBFUSCATION:'obfuscation',INTERACT:'interact'},filterRejectedExchanges:x=>x,buildMessages:s=>[{role:'system',content:s}],aiService:{async chatWithMessages(){actorCalls++;return {response:row.objective==='obfuscation'&&actorCalls===1?'{"action":"decode_payload"}':input.response,provider:'ollama',model:'controlled-test',mocked:false};}},evaluateDpiObjective:require('../../server/services/promptInjectionWorkshop').evaluateDpiObjective,judge:async value=>{packet=value;return {verdict:'inconclusive'};}});
 assert(packet);assert.equal(packet.rubric.version,`dpi-${row.objective}-v15`);assert.equal(packet.rubric.dpiAnswerComparison.protocolVersion,'dpi-answer-comparison-v14');prepareJudgeInput(packet);
 packet=require('./dpiHistoricalDiagnosticPacket').currentV14Packet(packet);
 prepareJudgeInput(packet);
 return {packet,provenance:{syntheticActor:true,controlledActorCalls:actorCalls,canonicalCredit:false,persistedEffect:false}};
}
async function runDiagnostic({model,onCase=async()=>{},judgeOptions={}}={}){
 assert.equal(typeof model?.chat,'function');let calls=0;const results=[];
 const judge=createObjectiveJudge({...judgeOptions,model:{async chat(...args){assert(++calls<=48,'Diagnostic HTTP call bound');return model.chat(...args);}}});
 for(const row of cases){const before=calls;try{const {packet,provenance}=await packetFor(row);const result=await judge(packet);const value={id:row.id,expected:row.expected,reason:row.reason,provenance,result,calls:calls-before,matched:result.verdict===row.expected};results.push(value);await onCase(value);}catch(error){await onCase({id:row.id,expected:row.expected,matched:false,calls:calls-before,error:{name:error.name,message:String(error.message).slice(0,1000)}});throw error;}}
 return {scope:'synthetic-heldout-semantic-diagnostic-no-credit',calls,results};
}
module.exports={packetFor,runDiagnostic};
