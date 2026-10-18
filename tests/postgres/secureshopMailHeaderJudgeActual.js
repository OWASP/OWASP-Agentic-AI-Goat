'use strict';
const fs=require('node:fs');
const {buildCases,evaluateCases}=require('./secureshopMailHeaderJudgeCases');
async function main(){
 const plan=buildCases(fs.readFileSync(process.env.MAIL_CALIBRATION_INPUT),process.env.MAIL_CALIBRATION_INPUT_SHA);
 const state={status:'running',scope:'Retained native header Judge qualification and separately labelled synthetic diagnostics; no credit',plan,cases:[],http:[],actualActorCalls:0,databaseCalls:0,browserCalls:0,smtpCalls:0,creditWrites:0,judgeTimeoutMs:90000};
 const record=()=>fs.writeFileSync(process.env.MAIL_CALIBRATION_RESULT,JSON.stringify(state,null,2));record();let transport;
 try{
  transport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:12,record:r=>{state.http=r.calls;state.modelDigest=r.modelDigest;record();}});
  const model=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:transport.model,baseURL:transport.judgeUrl});
  const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model,timeoutMs:90000});
  await evaluateCases(plan,judge,r=>{state.cases.push(r);record();});
  state.status=state.cases.every(c=>c.expectationPassed)?'expectations_passed':'observed_negative';
 }catch(error){state.status='failed';state.error={name:error.name,message:error.message};throw error;}
 finally{await transport?.close();state.transportClosed=true;record();}
}
if(require.main===module)main().catch(error=>{console.error(error);process.exitCode=1;});
