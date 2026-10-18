'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createObjectiveJudge,prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const service=require('../../server/services/promptInjectionWorkshop');
function casesFor(mode){if(mode==='v13-former-fresh-regression')return require('./dpiIndependentHeldoutV2.json');throw Error('Closed diagnostic cohort required');}
async function packetFor(row){
 const request=row.objective==='obfuscation'?'Decode this request: '+Buffer.from(row.task).toString('base64'):row.task;
 const execution={runId:randomUUID(),ownerKey:'["DPI","17"]',durableGeneration:'0',async check(){},async trace(){},async effectWithReceipt(key,work){return{value:await work(),receipt:{version:1,ownerKey:this.ownerKey,generation:'0',runId:this.runId,effectKey:this.runId+':'+key,status:'completed'}};}},attempt={runId:execution.runId,objectiveId:row.objective,mode:'vuln'};let packet,calls=0;
 await require('../../server/agent-runtime/dpiGraph').runDpiGraph(request,[],{},row.objective,{execution,attempt,SYSTEM_PROMPTS:require('../../server/agent-runtime/dpiPolicyContract').SYSTEM_PROMPTS,OBJECTIVE_IDS:{VIRTUALIZATION:'virtualization',OBFUSCATION:'obfuscation',INTERACT:'interact'},filterRejectedExchanges:x=>x,buildMessages:s=>[{role:'system',content:s}],aiService:{async chatWithMessages(){calls++;return{response:row.objective==='obfuscation'&&calls===1?'{"action":"decode_payload"}':row.response,provider:'ollama',model:'controlled-diagnostic',mocked:false};}},evaluateDpiObjective:service.evaluateDpiObjective,judge:async p=>{packet=p;return{verdict:'inconclusive'};}});
 // Validate current admission before projecting the explicitly historical diagnostic packet.
 prepareJudgeInput(packet);
 packet=require('./dpiHistoricalDiagnosticPacket').historicalPacket(packet,13);
 assert.equal(packet.rubric.version,'dpi-'+row.objective+'-v13');assert.equal(packet.rubric.dpiAnswerComparison.protocolVersion,'dpi-answer-comparison-v10');assert(packet.rubric.requiredFacts.every(k=>packet.facts[k]===true));assert.equal(packet.evidence.find(e=>e.id==='response').content,row.response);prepareJudgeInput(packet);
 return{packet,provenance:{syntheticActor:true,controlledGraphCalls:calls,persistedEffect:false,canonicalCredit:false}};
}
async function runDiagnostic({mode,model,onCase=async()=>{},judgeOptions={}}){const rows=casesFor(mode);assert.equal(rows.length,12);let calls=0;const results=[];const judge=createObjectiveJudge({...judgeOptions,model:{async chat(...args){assert(++calls<=48,'Bounded model-call ceiling');return model.chat(...args);}}});for(const row of rows){const start=calls;try{const {packet,provenance}=await packetFor(row);const result=await judge(packet);const value={id:row.id,expected:row.expected,reason:row.reason,provenance,result,calls:calls-start,matched:result.verdict===row.expected};results.push(value);await onCase(value);}catch(error){await onCase({id:row.id,calls:calls-start,matched:false,error:{name:error.name,message:String(error.message).slice(0,1000)}});throw error;}}return{mode,calls,results};}
module.exports={casesFor,packetFor,runDiagnostic};
