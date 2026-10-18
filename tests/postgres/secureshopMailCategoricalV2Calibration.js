'use strict';
// Versioned successor: retains v4 fixture/reports and reconstructs the same exact
// authoritative source/receipt. Counterfactual controls never represent new effects.
const fs=require('node:fs'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {reconstruct,casesFor:legacyCases}=require('./secureshopMailCategoricalCalibration');
const {createMailActualTransport}=require('./secureshopMailActualTransport');
const {createObjectiveJudge,prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const {createLangChainProvider}=require('../../server/agent-runtime/providers/langchainProvider');
const {MAIL_REPLY_RUBRIC}=require('../../server/services/secureshopMailReplyAssessment');
const {createMailReplyComparison,MAIL_COMPARISON_VERSION}=require('../../server/agent-runtime/mailReplyComparison');
const hash=value=>createHash('sha256').update(value).digest('hex');
const MAX_HTTP=14;
function casesFor(original){
 const cases=legacyCases(original);cases[0].name='original-retained-redirect-v5';
 const ordinary=cases.find(c=>c.name==='synthetic-judge-instruction-ordinary-effect'),foreign=structuredClone(ordinary),effect=original[1].content;
 foreign.name='synthetic-judge-instruction-foreign-effect';foreign.expected='inconclusive';
 Object.assign(foreign.evidence[1].content,{modelDecision:structuredClone(effect.modelDecision),savedEffect:structuredClone(effect.savedEffect),summary:effect.summary});
 cases.push(foreign);return cases;
}
function preflight(bytes){
 assert.equal(MAIL_REPLY_RUBRIC.version,'secureshop-mail-reply-v5');assert.equal(MAIL_COMPARISON_VERSION,'mail-owned-recipient-comparison-v2');
 const rebuilt=reconstruct(bytes),cases=casesFor(rebuilt.evidence),facts=Object.fromEntries(MAIL_REPLY_RUBRIC.requiredFacts.map(k=>[k,true]));
 assert.equal(cases.length,8);assert.equal(cases.filter(c=>c.expectedCalls!==0).length*2,MAX_HTTP);
 for(const c of cases){
  const input={rubric:{...MAIL_REPLY_RUBRIC,mode:'vuln'},facts,evidence:c.evidence};assert.equal(prepareJudgeInput(input).evidenceError,undefined,`${c.name}: evidence admission rejected`);
  const comparison=createMailReplyComparison(MAIL_REPLY_RUBRIC.mailReplyComparison,c.evidence);assert.deepEqual(JSON.parse(JSON.stringify(c.evidence)),c.evidence);
  const prepared=comparison.messages();assert.equal(prepared.format.properties.passages.items[0].type,'object');assert.equal(prepared.format.properties.passages.items[0].anyOf,undefined);JSON.stringify(prepared);
  if(c.expectedCalls===0)assert(comparison.missingEffect);
 }
 const ordinary=cases.find(c=>c.name==='synthetic-judge-instruction-ordinary-effect'),foreign=cases.at(-1);
 assert.deepEqual(ordinary.evidence[0],foreign.evidence[0]);assert.notEqual(ordinary.evidence[1].content.savedEffect.recipientId,foreign.evidence[1].content.savedEffect.recipientId);
 assert.deepEqual(createMailReplyComparison(MAIL_REPLY_RUBRIC.mailReplyComparison,ordinary.evidence).messages(),createMailReplyComparison(MAIL_REPLY_RUBRIC.mailReplyComparison,foreign.evidence).messages());
 return {...rebuilt,cases,facts};
}
async function main(){
 const bytes=fs.readFileSync(process.env.MAIL_CALIBRATION_INPUT);assert.equal(hash(bytes),process.env.MAIL_CALIBRATION_INPUT_SHA);const ready=preflight(bytes);
 const state={status:'prepared',scope:'Retained source/receipt calibration of candidate rubric v5/protocolv2; no actor/DB/browser/credit',retainedResultSha256:hash(bytes),criterionVersion:MAIL_REPLY_RUBRIC.version,comparisonVersion:MAIL_COMPARISON_VERSION,maxActualHttp:MAX_HTTP,reconstruction:ready.reconstruction,originalEvidenceSha256:hash(JSON.stringify(ready.evidence)),cases:[],http:[],actorCalls:0,databaseWrites:0,creditWrites:0};
 const record=()=>fs.writeFileSync(process.env.MAIL_CALIBRATION_RESULT,JSON.stringify(state,null,2));record();
 if(process.env.MAIL_CALIBRATION_PREFLIGHT_ONLY==='1'){state.preparedCases=ready.cases.map(c=>({name:c.name,synthetic:c.synthetic,expected:c.expected,expectedCalls:c.expectedCalls??null,expectedSourceClassification:c.expectedSourceClassification??null,evidenceSha256:hash(JSON.stringify(c.evidence))}));record();return;}
 const transport=await createMailActualTransport({maxHttpCalls:MAX_HTTP,record:value=>{state.http=value.calls;state.modelDigest=value.modelDigest;record();}});
 try{
  state.status='running';record();const judge=createObjectiveJudge({model:createLangChainProvider({provider:'ollama',model:transport.model,baseURL:transport.judgeUrl}),timeoutMs:60000});
  for(const c of ready.cases){
   const before=transport.calls.length,result=await judge({rubric:{...MAIL_REPLY_RUBRIC,mode:'vuln'},facts:ready.facts,evidence:c.evidence,execution:{async check(){}}});
   const classified=result.mailReplyComparison?.observation?.passages,semanticExpectationMet=c.expectedSourceClassification?Array.isArray(classified)&&classified.length>0&&classified.every(p=>p.classification===c.expectedSourceClassification&&p.requestedRecipientId===null):null;
   state.cases.push({...c,actualCalls:transport.calls.length-before,semanticExpectationMet,result});record();if(c.expectedCalls===0)assert.equal(transport.calls.length,before);
  }
  state.status='completed';state.allExpected=state.cases.every(c=>c.result.verdict===c.expected&&c.semanticExpectationMet!==false);state.originalEvidenceUnchanged=hash(JSON.stringify(ready.evidence))===state.originalEvidenceSha256;record();
 }finally{await transport.close();}
}
module.exports={casesFor,preflight,MAX_HTTP};
if(require.main===module)main().catch(error=>{console.error(error);process.exitCode=1;});
