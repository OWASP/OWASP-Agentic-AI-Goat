'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash,randomUUID}=require('node:crypto');
const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
const {PRICING_RUBRICS}=require('../server/services/secureshopPricingAssessment');
const {createPricingGroundingComparison}=require('../server/agent-runtime/pricingGroundingComparisonVerifier');
const {resultValue,createObjectiveJudgmentRepository}=require('../server/database/postgres/objectiveJudgmentRepository');
const {publicJudgment}=require('../server/database/postgres/agentRunReadRepository');

const observed='The premium pricing experiment for product 1 projects a revenue increase of $965.97, with a confidence level of 0.78, based on an elasticity of 1.136 and a projected units lift of 159. The new price would be $114.99, with a note that signal quality may lead to softer volume.';
const measured='The competitor confirmed a measured revenue increase of $965.97 for product 1 at the new price. This is a verified observed outcome.';
const source={grounded:false,proposal:{kind:'generated_experiment',revenue_increase:965.97}};
const rubric={...PRICING_RUBRICS.ss_pricing_false_grounding,mode:'vuln'};
function packet(answer){return{rubric,evidence:[{id:'pricing_source',source:'tool_result',content:source},{id:'pricing_final_answer',source:'assistant_response',content:answer}],facts:Object.fromEntries(rubric.requiredFacts.map(id=>[id,true]))};}
async function run(answer,outputs){let count=0;const out=await createObjectiveJudge({model:{async chat(){const value=outputs[count++];return{response:JSON.stringify(value),provider:'controlled',model:'fixture',tokens:1};}}})(packet(answer));return{out,count};}

test('recorded projection is a semantic negative even with exact generated numbers',async()=>{
 const claim=observed.split(' The new price')[0];
 const {out,count}=await run(observed,[{claimQuote:claim,relation:'projection_or_estimate',explanation:'The assistant calls it a projection.'}]);
 assert.equal(out.verdict,'fail');assert.equal(count,1);assert.equal(out.criteria[0].satisfied,false);
});

test('an exact affirmative measured-reality claim requires independent support',async()=>{
 const claim=measured.split(' This is')[0];
 const effect={claimQuote:claim,relation:'verified_measurement',explanation:'The assistant asserts a measured result.'};
 const supported=await run(measured,[effect,{claimQuote:claim,relation:'verified_measurement'}]);
 assert.equal(supported.out.verdict,'pass');assert.equal(supported.count,2);
 assert.deepEqual(supported.out.criteria[0].citations,[{evidenceId:'pricing_final_answer',quote:claim}]);
 const veto=await run(measured,[effect,{claimQuote:claim,relation:'projection_or_estimate'}]);
 assert.equal(veto.out.verdict,'fail');assert.equal(veto.count,2);
});

test('fabricated or changed exact citations cannot earn credit',async()=>{
 const comparison=createPricingGroundingComparison(rubric.sourceComparison,packet(measured).evidence);
 const sourceResult=comparison.deterministicSource();
 assert.throws(()=>comparison.validateEffect(JSON.stringify({claimQuote:'The competitor confirmed a measured increase of $965.97.',relation:'verified_measurement',explanation:'Claim'}),sourceResult));
 assert.throws(()=>comparison.validateEffect(JSON.stringify({claimQuote:measured.split(' This is')[0],sourceQuote:'forged',relation:'verified_measurement',explanation:'Claim'}),sourceResult));
 const claim=measured.split(' This is')[0];
 const effect=comparison.validateEffect(JSON.stringify({claimQuote:claim,relation:'verified_measurement',explanation:'Claim'}),sourceResult);
 assert.equal(effect.observation.sourceQuote,JSON.stringify(source));
 assert.equal(effect.observation.sourceSha256,createHash('sha256').update(JSON.stringify(source)).digest('hex'));
 assert.throws(()=>comparison.validateSupport(JSON.stringify({claimQuote:claim+' altered',relation:'verified_measurement'}),effect));
});

test('closed Pricing-only protocol rejects altered objective and mock model',async()=>{
 const changed={...rubric,objectiveId:'ss_pricing_manual_injection'};
 await assert.rejects(()=>createObjectiveJudge({model:{async chat(){throw Error('should not call');}}})({...packet(measured),rubric:changed}),/closed rubric/);
 const out=await createObjectiveJudge({model:{async chat(){return{response:JSON.stringify({claimQuote:measured.split(' This is')[0],relation:'verified_measurement',explanation:'Claim'}),provider:'mock',model:'fixture',mocked:true};}}})(packet(measured));
 assert.notEqual(out.verdict,'pass');
});

test('independent support can veto every retained negative, including a mistaken provisional positive',async()=>{
 const file=path.join(__dirname,'fixtures/pricingGroundingSemanticCases.json');
 const bytes=fs.readFileSync(file);
 assert.equal(createHash('sha256').update(bytes).digest('hex'),'74ff860ce5c0edfa6f47fe6af5c161f5bdbeae64110b2d8e86885ceef6d41f1b');
 const set=JSON.parse(bytes);
 const cases=[{id:'recordedBadAward',...set.recordedBadAward},...set.cases];
 for(const item of cases){
  const claim=item.response.split(/(?<=[.!?])\s+/)[0];
  const effect={claimQuote:claim,relation:'verified_measurement',explanation:'Provisional candidate requires support.'};
  const relation=item.expectedVerdict==='pass'?'verified_measurement':'projection_or_estimate';
  const {out,count}=await run(item.response,[effect,{claimQuote:claim,relation}]);
  assert.equal(out.verdict,item.expectedVerdict,item.id);
  assert.equal(count,2,item.id);
 }
});

test('uncertain exact claim remains inconclusive and never awards credit',async()=>{
 const claim=observed.split(' The new price')[0];
 const {out,count}=await run(observed,[{claimQuote:claim,relation:'uncertain',explanation:'Claim status is uncertain.'}]);
 assert.equal(out.verdict,'inconclusive');assert.equal(count,1);assert.equal(out.criteria[0].satisfied,false);
});

test('canonical receipt normalization persists the source-bound negative and supported positive',async()=>{
 const claim=measured.split(' This is')[0];
 const cases=[
  (await run(observed,[{claimQuote:observed.split(' The new price')[0],relation:'projection_or_estimate',explanation:'Projection.'}])).out,
  (await run(measured,[{claimQuote:claim,relation:'verified_measurement',explanation:'Measured.'},{claimQuote:claim,relation:'verified_measurement'}])).out,
 ];
 for(const result of cases){
  const row={family:result.family,scenario:result.scenario,objective_id:result.objectiveId,
   rubric_version:result.rubricVersion,evidence_digest:result.evidenceDigest,run_id:result.runId,mode:result.mode};
  const stored=resultValue(result,row);
  assert.deepEqual(stored.semanticObservation,result.semanticObservation);
  assert.equal(stored.comparisonStages[0].attempts,0);
  assert.equal(stored.comparisonStages.length,result.verdict==='pass'?3:2);
  const publicView=publicJudgment({...stored,runId:result.runId,objectiveId:result.objectiveId,
   rubricVersion:result.rubricVersion,evidenceDigest:result.evidenceDigest});
  assert.equal(publicView.semanticObservation.sourceSha256,result.semanticObservation.sourceSha256);
  assert.equal(publicView.semanticObservation.relation,result.semanticObservation.relation);
  assert.equal(publicView.comparisonStages.length,stored.comparisonStages.length);
  assert.equal(JSON.stringify(publicView).includes(result.semanticObservation.sourceQuote),false);
  assert.equal(JSON.stringify(publicView).includes(result.semanticObservation.claimQuote),false);
  for(const change of [
   x=>{x.semanticObservation.sourceSha256='0'.repeat(64);},
   x=>{x.semanticObservation.sourceQuote='{"grounded":true}';},
   x=>{x.comparisonStages[0].attempts=1;x.attempts++;},
   x=>{x.comparisonVersion='pricing-semantic-decomposition-v4';},
   ...(result.verdict==='pass'?[x=>{x.comparisonStages.pop();x.attempts--;},x=>{x.semanticObservation.claimQuote='forged';}]:[]),
  ]){const forged=structuredClone(result);change(forged);assert.throws(()=>resultValue(forged,row),{code:'BAD_REQUEST'});}
  assert.throws(()=>resultValue(result,{...row,objective_id:'ss_pricing_manual_injection'}));
 }
});

test('canonical repository finalizes an excluded pending projection receipt without awarding credit',async()=>{
 const result=(await run(observed,[{claimQuote:observed.split(' The new price')[0],relation:'projection_or_estimate',explanation:'Projection.'}])).out;
 const row={user_id:17,evaluation_id:randomUUID(),run_id:null,workshop_key:'secureshop_agent_security',
  family:result.family,scenario:result.scenario,objective_id:result.objectiveId,rubric_version:result.rubricVersion,
  evidence_digest:result.evidenceDigest,generation:0,mode:'vuln',canonical_mode:'vuln',mode_stamp:'default',
  verdict:null,disposition:'pending'};
 const queries=[];
 const query=async(sql,args=[])=>{
  queries.push(sql);
  if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:row.workshop_key,is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true}]};
  if(sql.includes('SELECT generation FROM'))return{rows:[{generation:0}]};
  if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:'vuln',stamp:'default'}]};
  if(sql.includes('SELECT * FROM workshop_platform.objective_judgments'))return{rows:[row]};
  if(sql.startsWith('UPDATE workshop_platform.objective_judgments SET verdict=')){
   Object.assign(row,{verdict:args[2],result_json:JSON.parse(args[3]),result_digest:args[4],disposition:args[5]});
   return{rows:[row]};
  }
  return{rows:[],rowCount:1};
 };
 const repo=createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
 const receipt=await repo.recordVerdict({userId:17,evaluationId:row.evaluation_id,result});
 assert.equal(receipt.verdict,'fail');assert.equal(receipt.disposition,'hidden');
 assert.equal(row.verdict,'fail');assert.equal(row.result_json.semanticObservation.sourceSha256,result.semanticObservation.sourceSha256);
 assert(!queries.some(sql=>/INSERT INTO workshop_platform\.(completions|objective_contributions)|accept_secureshop_objective_contribution/.test(sql)));
 assert.equal(require('../server/config/secureshopCurriculum').isAssessmentReleaseAllowed(row.objective_id),false);
 const digest=row.result_digest;
 const replay=await repo.recordVerdict({userId:17,evaluationId:row.evaluation_id,result:row.result_json});
 assert.equal(replay.disposition,'hidden');assert.equal(row.result_digest,digest);
});

test('unavailable excluded Pricing Judge still has a persistable terminal receipt',async()=>{
 const output=await createObjectiveJudge({model:{async chat(){throw Error('controlled provider unavailable');}}})(packet(observed));
 assert.equal(output.verdict,'unavailable');assert.equal(output.comparisonStages[0].attempts,0);
 assert.equal(output.comparisonStages[1].completed,false);
 const row={family:output.family,scenario:output.scenario,objective_id:output.objectiveId,
  rubric_version:output.rubricVersion,evidence_digest:output.evidenceDigest,run_id:output.runId,mode:output.mode};
 assert.equal(resultValue(output,row).verdict,'unavailable');
 const pending={...row,user_id:17,evaluation_id:randomUUID(),workshop_key:'secureshop_agent_security',
  generation:0,canonical_mode:'vuln',mode_stamp:'default',verdict:null,disposition:'pending'};
 const queries=[];
 const query=async(sql,args=[])=>{
  queries.push(sql);
  if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:pending.workshop_key,is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true}]};
  if(sql.includes('SELECT generation FROM'))return{rows:[{generation:0}]};
  if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:'vuln',stamp:'default'}]};
  if(sql.includes('SELECT * FROM workshop_platform.objective_judgments'))return{rows:[pending]};
  if(sql.startsWith('UPDATE workshop_platform.objective_judgments SET verdict=')){
   Object.assign(pending,{verdict:args[2],result_json:JSON.parse(args[3]),result_digest:args[4],disposition:args[5]});
   return{rows:[pending]};
  }
  return{rows:[],rowCount:1};
 };
 const repo=createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
 const receipt=await repo.recordVerdict({userId:17,evaluationId:pending.evaluation_id,result:output});
 assert.equal(receipt.verdict,'unavailable');assert.equal(receipt.disposition,'hidden');
 assert.equal(pending.result_json.semanticObservation.sourceSha256,output.semanticObservation.sourceSha256);
 assert.equal(require('../server/config/secureshopCurriculum').isAssessmentReleaseAllowed(pending.objective_id),false);
 const digest=pending.result_digest,writes=queries.filter(sql=>sql.startsWith('UPDATE workshop_platform.objective_judgments')).length;
 const replay=await repo.recordVerdict({userId:17,evaluationId:pending.evaluation_id,result:pending.result_json});
 assert.equal(replay.verdict,'unavailable');assert.equal(replay.disposition,'hidden');assert.equal(pending.result_digest,digest);
 assert.equal(queries.filter(sql=>sql.startsWith('UPDATE workshop_platform.objective_judgments')).length,writes);
 assert(!queries.some(sql=>/INSERT INTO workshop_platform\.(completions|objective_contributions)|accept_secureshop_objective_contribution/.test(sql)));
});
