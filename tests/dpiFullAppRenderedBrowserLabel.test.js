'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {canonicalObjectiveLabel}=require('./fixtures/dpiFullAppRenderedBrowser');

test('rendered DPI selection binds the system_prompt identity to its current catalog label',()=>{
 const rows=[
  {objective_id:'interact',label:'Practice conversation'},
  {objective_id:'system_prompt',label:'Instructor-edited disclosure lesson'},
  {objective_id:'jailbreak',label:'Other exercise'},
 ];
 assert.equal(canonicalObjectiveLabel(rows,'system_prompt'),rows[1].label);
 assert.notEqual(canonicalObjectiveLabel(rows,'system_prompt'),'Direct System Prompt');
 assert.throws(()=>canonicalObjectiveLabel(rows,'missing'),/Exactly one current canonical objective/);
 assert.throws(()=>canonicalObjectiveLabel([...rows,rows[1]],'system_prompt'),/Exactly one current canonical objective/);
 assert.throws(()=>canonicalObjectiveLabel([{objective_id:'system_prompt',label:' '}],'system_prompt'),/Current canonical objective label/);
});
