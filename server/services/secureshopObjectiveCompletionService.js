'use strict';
const {createObjectiveCompletionService: createCanonical}=require('./objectiveCompletionService');
const {createObjectiveJudge}=require('../agent-runtime/objectiveJudge');
// Select the persistence realm before canonical beginAttempt reads progress.
// Every selection is private to one protected execution; no ambient owner state.
function createObjectiveCompletionService(options={}) {
  const {resolveExecutionStores,...canonical}=options;
  const legacy=createCanonical(canonical);
  if(resolveExecutionStores===undefined)return legacy;
  if(typeof resolveExecutionStores!=='function')throw TypeError('Protected assessment resolver required');
  const executions=new WeakMap(),attempts=new WeakMap();
  async function selected(execution){
    if(typeof execution?.check!=='function')throw TypeError('Protected assessment execution required');
    await execution.check();
    if(!executions.has(execution))executions.set(execution,(async()=>{
      const stores=await resolveExecutionStores(execution);
      if(stores===null)return {service:legacy,shop:false};
      if(!stores?.subject||!stores.receipts||!stores.progress||typeof stores.observeJudge!=='function')throw TypeError('Shop assessment stores unavailable');
      const judge=canonical.judge||createObjectiveJudge();
      const observed=async input=>stores.observeJudge(input,judge);
      return {shop:true,service:createCanonical({...canonical,receipts:stores.receipts,progress:stores.progress,
        capturePersonaEvaluation:async()=>stores.subject,judge:observed})};
    })());
    return executions.get(execution);
  }
  function outcome(value,shop){return shop&&value?.judgment?{...value,judgment:{...value.judgment,canRetry:false}}:value;}
  return Object.freeze({
    async beginAttempt(input){const entry=await selected(input.execution);const attempt=await entry.service.beginAttempt(input);attempts.set(attempt,{entry,execution:input.execution});return attempt;},
    async hasPrerequisite(input){const found=attempts.get(input.attempt);if(!found||found.execution!==input.execution)throw TypeError('Matching assessment attempt required');return found.entry.service.hasPrerequisite(input);},
    async evaluate(input){const found=attempts.get(input.attempt);if(!found||found.execution!==input.execution)throw TypeError('Matching assessment attempt required');return outcome(await found.entry.service.evaluate(input),found.entry.shop);},
    async retry(input){const entry=await selected(input.execution);if(entry.shop)throw Object.assign(Error('Shop assessment retry is not yet available'),{code:'RETRY_NOT_ALLOWED'});return entry.service.retry(input);},
  });
}
module.exports={createObjectiveCompletionService};
