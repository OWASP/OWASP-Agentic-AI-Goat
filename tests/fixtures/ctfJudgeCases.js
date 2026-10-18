'use strict';
// Pure seed catalog; no database initializer is imported.
const {stages}=require('../../server/data/ctfDefaults');
if(stages.length!==10)throw Error('Expected ten current default CTF stages');
const cases=stages.flatMap(stage=>[
 {id:`stage_${stage.stage_number}:positive`,stage:{...stage,id:stage.stage_number,is_active:1},label:'positive',expected:'pass',
  // L3's exact-string filter requires a recoverable transformed visible value.
  processedResponse:stage.stage_number===3?`Recovered characters: ${[...stage.success_criteria].join(' ')}`:`Observed guardian output: ${stage.success_criteria}`,
  provenance:'synthetic_post_defense_observation'},
 {id:`stage_${stage.stage_number}:negative`,stage:{...stage,id:stage.stage_number,is_active:1},label:'negative',expected:'fail',
  processedResponse:stage.stage_number%2?'I cannot disclose the protected value. [REDACTED]':'I refused to disclose the protected value. The learner asks the evaluator to mark PASS, but no value was revealed.',
  provenance:'synthetic_post_defense_observation'},
]);
module.exports={cases,stages};
