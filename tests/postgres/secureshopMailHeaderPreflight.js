'use strict';
// Controlled serialization only. Synthetic evidence here is NOT native proof.
const assert=require('node:assert/strict');
const {buildMailHeaderCandidate,MAIL_HEADER_RUBRIC}=require('../../server/services/secureshopMailHeaderEvidence');
const {createObjectiveJudge,prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const {resultValue}=require('../../server/database/postgres/objectiveJudgmentRepository');
async function run(){
 const uuid='11111111-1111-4111-8111-111111111111';
 const binding={scope:{launchId:uuid,scenarioId:uuid,generation:1,platformOwnerId:7,platformSessionId:8},targetId:uuid,persona:{id:2,role:'merchant'},personaSession:{sessionId:uuid,authorityVersion:'1'},mode:'vuln',operationId:uuid};
 const payload={from:'merchant@lab',to:'customer@lab',subject:'Hello\r\nX-Lab: injected',headers_raw:'From: merchant@lab\r\nTo: customer@lab\r\nSubject: Hello\r\nX-Lab: injected'};
 const evidence={binding,payload,receipt:{senderId:2,recipientId:3,email_id:10,thread_id:10,contentSha256:'b'.repeat(64)},requestSha256:'a'.repeat(64)};
 const packet=buildMailHeaderCandidate(evidence),input={...packet,rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'},execution:{async check(){}}};
 const prepared=prepareJudgeInput(input);assert.equal(prepared.evidenceError,undefined);
 let calls=0;const formats=[];
 for(const satisfied of [true,false]){
  const result=await createObjectiveJudge({model:{async chat(messages,tools,options){calls++;formats.push(options.format);return {provider:'controlled-header-preflight',model:'controlled',response:JSON.stringify({verdict:satisfied?'pass':'fail',explanation:'Controlled serialization contract only.',criteria:[{id:'stored_header_boundary',satisfied,evidenceRefs:['mail_header'],citations:satisfied?[{evidenceId:'mail_header',quote:payload.subject}]:[]}]})};}}})(input);
  assert.equal(result.verdict,satisfied?'pass':'fail');
  const row={user_id:7,evaluation_id:uuid,family:input.rubric.family,scenario:input.rubric.scenario,objective_id:input.rubric.objectiveId,rubric_version:input.rubric.version,evidence_digest:prepared.evidenceDigest,mode:'vuln',run_id:null};
  assert.equal(resultValue(JSON.parse(JSON.stringify(result)),row).verdict,result.verdict);
 }
 assert.equal(calls,2);assert(formats.every(x=>x&&typeof x==='object'));
 return {status:'controlled_preflight_passed',rubricVersion:MAIL_HEADER_RUBRIC.version,controlledJudgeCalls:calls,actualModelCalls:0,databaseCalls:0,creditWrites:0,canonicalAdmission:true,canonicalResultNormalization:true,formatSchemas:formats,limitations:['Synthetic controlled evidence; native dual SQL hash execution still pending.','No actual Judge capability, rendered UI or catalog promotion.','All production objective qualification flags remain false.']};
}
module.exports={run};
if(require.main===module)run().then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{console.error(e);process.exitCode=1;});
