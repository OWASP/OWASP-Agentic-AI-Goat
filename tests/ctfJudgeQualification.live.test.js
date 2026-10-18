'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)(authDb|ctfDb|sensitiveInfoDb)(?:\.js)?$/.test(r))throw Error('Database initializer forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {cases,stages}=require('./fixtures/ctfJudgeCases');
const {stageDigest,judgeCtfStage}=require('../server/agent-runtime/ctfStageJudge');
const {normalizedContains}=require('../server/services/ctfDefenseLayers');
test('CTF qualification covers all10 actual default policies with20 post-defense evidence fixtures',()=>{
 assert.equal(stages.length,10);assert.equal(cases.length,20);
 for(const item of cases){assert.equal(item.stage.stage_number,Number(item.id.split(':')[0].slice(6)));assert.equal(normalizedContains(item.processedResponse,item.stage.success_criteria),item.label==='positive');assert.match(stageDigest(item.stage),/^[a-f0-9]{64}$/);assert.equal(item.provenance,'synthetic_post_defense_observation');}
});
test('Local8B CTF10 stage20 verdict qualification (evidence-only; no guardian/tools)',{skip:process.env.RUN_LIVE_JUDGE!=='1',timeout:600000},async t=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge'),{createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
 const judge=createObjectiveJudge({model:createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'})});const failures=[];
 for(const item of cases){
  const verdict=await judgeCtfStage({stage:item.stage,processedResponse:item.processedResponse,realModel:true,observedSecret:normalizedContains(item.processedResponse,item.stage.success_criteria)},judge);
  const diagnostic={family:'CTF',verdict:verdict.verdict,durationMs:verdict.durationMs??null,attempts:verdict.attempts??null,case:item.id,stageName:item.stage.stage_name,expected:item.expected,actual:verdict.verdict,explanation:verdict.explanation,criteria:verdict.criteria,provider:verdict.provider,model:verdict.model,judgeVersion:verdict.judgeVersion,judgePolicyDigest:verdict.judgePolicyDigest,stageDigest:stageDigest(item.stage),rubricVersion:verdict.rubricVersion,provenance:item.provenance};
  console.log(`[CTF qualification] ${item.id}: ${verdict.verdict}`);t.diagnostic(JSON.stringify(diagnostic));
  if(verdict.verdict!==item.expected||verdict.provider!=='ollama'||verdict.model!=='llama3.1:8b')failures.push(diagnostic);
 }
 assert.deepEqual(failures,[]);
});
