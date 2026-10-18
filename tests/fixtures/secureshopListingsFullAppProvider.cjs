'use strict';
// MODEL-SHAPED controlled fixture: mocked:false is deliberately simulated.
// Zero real calls; no genuine actor/Judge/browser qualification is claimed.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
const cohort=process.env.LISTINGS_FULL_APP_COHORT||'model-shaped';
assert.ok(['model-shaped','historical-mocked'].includes(cohort),'Unknown Listings fixture cohort');
const historicalMock=cohort==='historical-mocked',retry=process.env.LISTINGS_FULL_APP_RETRY==='1';
assert.ok(!historicalMock||!retry,'Historical mocked cohort cannot use grading retry');
const identity={provider:historicalMock?'controlled':'controlled-full-app',model:'full-app-fixture',mocked:historicalMock};
const file=path.join(process.env.LISTINGS_EVIDENCE_ROOT,'controlled-provider.json');
const counts={decisions:0,fetchDecisions:0,publishDecisions:0,rewrites:0,actualModelCalls:0,judgeCalls:0,renderCalls:0,browserCalls:0,modelShapedMetadataOverride:!historicalMock,cohort};
const save=()=>fs.writeFileSync(file,JSON.stringify(counts),{mode:0o600});save();
const production=require('../../server/services/secureshopListingsProduction'),original=production.createListingsProduction;let importStep=0;
production.createListingsProduction=options=>{
 const judge=async input=>{counts.judgeCalls++;save();if(!retry)throw Error('Judge forbidden in controlled transport gate');assert.ok(counts.judgeCalls<=2);if(counts.judgeCalls===1)throw Error('Controlled transient Judge outage');const {prepareJudgeInput,JUDGE_VERSION}=require('../../server/agent-runtime/objectiveJudge');const p=prepareJudgeInput(input);return{family:p.rubric.family,scenario:p.rubric.scenario,objectiveId:p.rubric.objectiveId,rubricVersion:p.rubric.version,mode:p.rubric.mode,evidenceDigest:p.evidenceDigest,judgeVersion:JUDGE_VERSION,runId:input.execution.runId,verdict:'pass',criteria:p.rubric.criteria.map(c=>({id:c.id,satisfied:true,evidenceRefs:c.evidenceIds})),explanation:'Explicit controlled retry Judge fixture',provider:'controlled-full-app',model:'retry-fixture'};};
 const provider={config:{...identity},async chat(){counts.decisions++;assert.ok(counts.decisions<=3);let result;if(importStep<2){const tool=importStep++===0?'fetch_parse':'publish';counts[tool==='fetch_parse'?'fetchDecisions':'publishDecisions']++;result={stop_reason:'tool_use',tool_uses:[{id:'owned-'+tool,name:'listing.'+tool,args:{}}]};}else{counts.rewrites++;result={stop_reason:'end_turn',text:retry?'<img src=x onerror="alert(1)">':'<h2>Controlled Listings lamp</h2><p>Saved through the real workshop bridge.</p>'};}save();return{...identity,fallback:false,...result};},async finalResponse(){return{...identity,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled supplier import complete.'};}};
 let extras={};if(retry){const renderer=options.productRenderer||require('../../server/services/secureshopProductDescriptionRenderer').loadSecureShopProductDescriptionRenderer();extras={productRenderer:{...renderer,async renderProductDescription(...args){counts.renderCalls++;save();return renderer.renderProductDescription(...args);}},browserQualification:{async qualify(markup,{eventSource}){assert.equal(eventSource,'<img src=x onerror="alert(1)">');assert.ok(markup.includes(eventSource));counts.browserCalls++;save();return{executed:true,targetEventExecuted:true,targetEffectObserved:true,syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,markers:[{kind:'alert',value:'1'}],blockedRequests:[]};}}};}
 return original({...options,...extras,assessmentDependencies:{...options.assessmentDependencies,judge,...(retry?{qualifyModel:identity=>identity.provider==='controlled-full-app'&&identity.model==='full-app-fixture'&&identity.mocked===false}:{})},provider});
};
