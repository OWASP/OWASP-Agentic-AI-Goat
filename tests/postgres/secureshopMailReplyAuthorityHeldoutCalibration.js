'use strict';
// Actual Judge diagnostic only when launched explicitly; all packets are synthetic.
const fs=require('node:fs'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {GROUPS,buildHeldoutCases}=require('../fixtures/secureshopMailAuthorityHeldoutCases');
const {MAIL_REPLY_RUBRIC:CURRENT_RUBRIC}=require('../../server/services/secureshopMailReplyAssessment');
const MAIL_REPLY_RUBRIC={...CURRENT_RUBRIC,version:'secureshop-mail-reply-v14',mailReplyComparison:{primary:true,protocolVersion:'mail-recipient-authority-comparison-v11'}};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
function prepare(bytes,expectedSha){assert.equal(hash(bytes),expectedSha);assert.deepEqual(JSON.parse(bytes),GROUPS);assert.equal(MAIL_REPLY_RUBRIC.version,'secureshop-mail-reply-v14');return {status:'prepared',scope:'Synthetic independently authored recipient-authority held-out diagnostic',inputSha256:expectedSha,cases:buildHeldoutCases().map(c=>({...c,result:null})),actualActorCalls:0,databaseWrites:0,creditWrites:0,maxHttp:8,wholeJudgeMilliseconds:90000,http:[]};}
async function main(){
 const state=prepare(fs.readFileSync(process.env.MAIL_CALIBRATION_INPUT),process.env.MAIL_CALIBRATION_INPUT_SHA),record=()=>fs.writeFileSync(process.env.MAIL_CALIBRATION_RESULT,JSON.stringify(state,null,2));record();if(process.env.MAIL_CALIBRATION_PREFLIGHT_ONLY==='1')return;
 const transport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:8,record:value=>{state.http=value.calls;state.modelDigest=value.modelDigest;record();}});
 try{const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:transport.model,baseURL:transport.judgeUrl}),timeoutMs:90000,contextTokens:32768});
  for(const c of state.cases){const before=transport.calls.length;c.result=await judge({rubric:{...MAIL_REPLY_RUBRIC,mode:'vuln'},facts:Object.fromEntries(MAIL_REPLY_RUBRIC.requiredFacts.map(k=>[k,true])),evidence:c.evidence,execution:{async check(){}}});c.actualCalls=transport.calls.length-before;assert(c.actualCalls<=2);const o=c.result.mailReplyComparison?.observation;c.matched=c.result.verdict===c.expectedVerdict&&o?.classification?.authorizationRelation===c.expectedRelation&&o.selectedRecipientId===JSON.parse(c.wire.messages[1].content).selectedAction.recipientId;record();}
  assert.equal(transport.calls.filter(c=>c.kind==='actor').length,0);state.status=state.cases.every(c=>c.matched)?'passed':'observed_negative';record();
 }finally{await transport.close();state.transportClosed=true;record();}
}
module.exports={prepare};if(require.main===module)main().catch(error=>{console.error(error);process.exitCode=1;});
