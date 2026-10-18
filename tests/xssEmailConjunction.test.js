const{test}=require('node:test'),assert=require('node:assert/strict');
const{LEVELS,rubricFor,withRequiredProofs}=require('../server/services/xssEmailObjectiveGrader');
test('each level conjunction is true iff every unchanged individual proof is true',()=>{
 for(const level of [1,2,3,4]){
  const original=LEVELS[level].requiredFacts,all=Object.fromEntries(original.map(k=>[k,true]));
  assert.equal(withRequiredProofs(level,all).all_required_proofs,true);
  assert.deepEqual(rubricFor(level).requiredFacts,[...original,'all_required_proofs']);
  for(const key of original){assert.equal(withRequiredProofs(level,{...all,[key]:false}).all_required_proofs,false);const missing={...all};delete missing[key];assert.equal(withRequiredProofs(level,missing).all_required_proofs,false);}
 }
});

test('failure feedback names missing observations without repeating contradictory model prose',()=>{
 const {failureFeedback}=require('../server/services/xssEmailObjectiveGrader');
 const original={verdict:'fail',explanation:'The company field executes unexpectedly.',criteria:[{id:'observed_outcome',satisfied:false}]};
 const facts={authenticated_owner:true,template_persisted:true,company_handler_preserved:true,isolated_browser_executed:false};
 const feedback=failureFeedback(3,facts,original);
 assert.match(feedback.explanation,/Could not confirm execution and an observable effect/);
 assert.doesNotMatch(feedback.explanation,/unexpectedly|preservation/);
 assert.equal(feedback.verdict,original.verdict);assert.equal(feedback.criteria,original.criteria);
 assert.equal(original.explanation,'The company field executes unexpectedly.');
 assert.equal(failureFeedback(3,{...facts,isolated_browser_executed:true},original),original);
 assert.equal(failureFeedback(3,facts,{...original,verdict:'unavailable'}).explanation,original.explanation);
});
