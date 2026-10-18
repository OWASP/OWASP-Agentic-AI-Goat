'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {buildCases,evaluateCases}=require('./secureshopMailHeaderV3Cases');
const {createObjectiveJudge}=require('../../server/agent-runtime/objectiveJudge');
async function run(){
 const report=process.env.MAIL_CALIBRATION_INPUT?null:JSON.parse(fs.readFileSync(path.resolve('tasks/secureshop-mail-header-native-2026-09-26.json'))),bytes=fs.readFileSync(process.env.MAIL_CALIBRATION_INPUT||path.join(report.evidenceDirectory,'candidate-result.json')),plan=buildCases(bytes,process.env.MAIL_CALIBRATION_INPUT_SHA||report.runtimeResultSha256);
 let index=0;const admitted=plan.cases.filter(c=>c.packet),wire=[];
 const judge=createObjectiveJudge({model:{async chat(messages,tools,options){const c=admitted[index++];assert(c);wire.push({name:c.name,messages,format:options.format,options});const positive=c.kind==='retained_native';return {provider:'controlled-header-preflight',model:'controlled',response:JSON.stringify({satisfied:positive,citations:positive?[{evidenceId:'header_boundary',quote:c.packet.evidence.find(e=>e.id==='header_boundary').content.boundaries[0].description}]:[]})};}}});
 const results=await evaluateCases(plan,judge);assert(results.every(r=>r.expectationPassed));assert.equal(index,2);assert(wire.every(w=>w.format&&w.messages[0].role==='system'&&w.messages[1].role==='user'));assert(wire.every(w=>w.options.timeout===90000));
 const offlineReplay=require('./secureshopMailHeaderV3Cases').replayPrior(fs.readFileSync(process.env.MAIL_PRIOR_INPUT),process.env.MAIL_PRIOR_SHA);
 assert.deepEqual(offlineReplay.map(r=>[r.name,r.originalVerdict,r.selection.rawSatisfied,r.selection.validationReason]),[['retained_new_thread','pass',true,'VALID'],['retained_explicit_thread','pass',true,'VALID'],...['ordinary_headers','body_only_newline','literal_backslashes','evaluator_instruction'].map(n=>[n+'_semantic_diagnostic','pass',true,'INVALID_BOUNDARY_SUPPORT'])]);
 return {offlineReplay,status:'controlled_preflight_passed',retainedInputSha256:plan.retainedSha256,scope:'Two retained native positives; seven production guards have zero calls. Historical 18119 support replay is offline and separate; no semantic classifier qualification or credit.',bounds:{parentSeconds:360,childSeconds:300,httpSeconds:60,judgeSeconds:90,maximumHttpCalls:4,maximumCallsPerCase:2},actualModelCalls:0,databaseCalls:0,creditWrites:0,plan,results,controlledOutgoingRequests:wire};
}
module.exports={run};
if(require.main===module)run().then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{console.error(e);process.exitCode=1;});
