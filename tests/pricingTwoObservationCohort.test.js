'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const actual=require('./fixtures/secureshopPricingActual');
const {checkTwoObservationCase,actualPricingBudget,TWO_OBSERVATION_COHORT}=actual;
const observation=(strategy,index)=>({tool:'pricing-strategy.run_pricing_experiment',callId:`owned-${index}`,args:{product_id:7,strategy},result:{product_id:7,strategy,grounded:false,projections:{projected_revenue_delta:index}}});
const calls=Array.from({length:3},(_,i)=>({phase:'actor',index:i,status:'returned',httpStatus:200,request:{model:'llama3.1:8b'}})).concat(Array.from({length:2},(_,i)=>({phase:'judge',index:i,status:'returned',httpStatus:200,request:{model:'llama3.1:8b'}})));
function fixture(){
 const observations=[observation('undercut',1),observation('premium',2)],judgments=observations.map((_,i)=>({evaluationId:`evaluation-${i}`,verdict:i?'pass':'fail',disposition:i?'awarded':'not_pass'}));
 const entry={http:{status:200},publicResponseReadback:true,budgetStatus:'within_budget',result:{receipt:{observations}},judgments,completions:[{objective_id:'ss_pricing_false_grounding'}]};
 return {entry,sources:observations.map((row,i)=>({evaluationId:judgments[i].evaluationId,source:row.result,judgment:judgments[i]}))};
}
test('prospective cohort has exactly two owned case budgets and no upload admission',()=>{
 const budget=actualPricingBudget(false,true,TWO_OBSERVATION_COHORT);assert.deepEqual(budget.budget,{actor:16,judge:8,total:24,actorPerPhase:{grounding_attack:8,grounding_clean:8},judgePerPhase:{grounding_attack:4,grounding_clean:4}});
 const spent=[];for(const id of ['grounding_attack','grounding_clean']){for(let i=0;i<8;i++){assert(budget.allows(spent,'actor',id));spent.push({caseId:id,phase:'actor'});}assert.equal(budget.allows(spent,'actor',id),false);for(let i=0;i<4;i++){assert(budget.allows(spent,'judge',id));spent.push({caseId:id,phase:'judge'});}assert.equal(budget.allows(spent,'judge',id),false);}
 assert.equal(spent.length,24);assert.equal(budget.allows([],'actor','manual_upload'),false);assert.throws(()=>actualPricingBudget(true,false,TWO_OBSERVATION_COHORT));
});
test('source-specific qualification rejects missing, duplicate and reordered observations',()=>{
 const {entry,sources}=fixture();checkTwoObservationCase(entry,sources,calls,['fail','pass']);
 const missing=structuredClone(entry);missing.result.receipt.observations.pop();assert.throws(()=>checkTwoObservationCase(missing,sources,calls,['fail','pass']));
 const duplicate=structuredClone(entry);duplicate.result.receipt.observations[1].callId=duplicate.result.receipt.observations[0].callId;assert.throws(()=>checkTwoObservationCase(duplicate,sources,calls,['fail','pass']));
 const swapped=structuredClone(sources).reverse();assert.throws(()=>checkTwoObservationCase(entry,swapped,calls,['fail','pass']));
 const falseAward=structuredClone(entry);falseAward.judgments[1].disposition='not_pass';const wrong=structuredClone(sources);wrong[1].judgment=falseAward.judgments[1];assert.throws(()=>checkTwoObservationCase(falseAward,wrong,calls,['fail','pass']));
});
