'use strict';const test=require('node:test'),assert=require('node:assert/strict');
test('canonical snapshot preserves authored help while respecting each visibility gate',async()=>{
 const {projectLegacyFileSsiSnapshot}=await import('../client/src/utils/legacyFileSsiSnapshot.mjs');
 const snapshot=projectLegacyFileSsiSnapshot([{workshopKey:'legacy_sensitive_file_ssi',showHints:true,showSolutions:true,objectives:[{id:'path_traversal',label:'Admin label',description:'Admin description',hintVisible:true,solutionVisible:true}]}],{
  path_traversal:{hints:['First authored hint'],solution:{title:'Authored solution',description:'Explanation',approach:'Authored approach',examples:[{title:'Try this',prompt:'../secret/file',explanation:'Why it works'}],tips:['Keep it scoped']}}
 },{effectiveMode:'fixed',selectableModes:['vuln','fixed'],scope:{kind:'file_ssi_workflow',id:'legacy_sensitive_file_ssi'}});
 const objective=snapshot.objectives[0];
 assert.equal(snapshot.mode.effectiveMode,'fixed');assert.deepEqual(snapshot.mode.allowedModes,['vuln','fixed']);
 assert.equal(objective.label,'Admin label');assert.equal(objective.description,'Admin description');
 assert.deepEqual(objective.hint.hints,['First authored hint']);assert.equal(objective.solution.approach,'Authored approach');
 assert.equal(objective.solution.examples[0].payload,'../secret/file');assert.deepEqual(objective.solution.tips,['Keep it scoped']);
});

test('canonical header metadata preserves authored values and falls back only to the canonical name',async()=>{
 const {projectLegacyFileSsiSnapshot}=await import('../client/src/utils/legacyFileSsiSnapshot.mjs');
 const row={workshopKey:'legacy_sensitive_file_ssi',title:'  Instructor File Lab  ',name:'Catalog fallback',description:'  Instructor-authored introduction.  ',difficulty:'  advanced  ',objectives:[]};
 const authored=projectLegacyFileSsiSnapshot([row]);
 assert.equal(authored.title,'Instructor File Lab');
 assert.equal(authored.description,'Instructor-authored introduction.');
 assert.equal(authored.difficulty,'advanced');
 const fallback=projectLegacyFileSsiSnapshot([{...row,title:'   ',name:'  Catalog fallback  '}]);
 assert.equal(fallback.title,'Catalog fallback');
 const missing=projectLegacyFileSsiSnapshot([{workshopKey:'legacy_sensitive_file_ssi',objectives:[]}]);
 assert.equal(missing.title,'');assert.equal(missing.description,'');assert.equal(missing.difficulty,'');
});
