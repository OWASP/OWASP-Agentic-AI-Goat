'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const prior=require('./fixtures/dpiTeachingDefaults.pre-decoder.json');
const {solutions}=require('../server/data/promptInjectionSolutions');
const hints=require('../server/data/workshopHints').direct_prompt_injection;
const p=require('../server/database/postgres/catalogDefaultProvenance');
const hash=v=>p.hashDocument(p.document(v));
function client(current,old,state){const calls=[];return {calls,async query(sql,args){calls.push({sql,args});if(/SELECT revision/.test(sql))return {rows:[{revision:1}],rowCount:1};if(/ AS value FROM/.test(sql))return {rows:[{value:current}],rowCount:1};if(/SELECT \* FROM workshop_platform.catalog_field_defaults/.test(sql))return {rows:state==='absent'?[]:[{provenance_state:state,applied_default_hash:hash(old)}],rowCount:state==='absent'?0:1};return {rows:[],rowCount:1};}};}
test('retained historical defaults remain available for current DPI content reconciliation',()=>{
 assert.equal(Object.keys(prior.solutions).length,7);
 for(const id of Object.keys(prior.solutions)) {
  assert.ok(solutions[id],id);
  assert.notEqual(hash(prior.solutions[id]),hash(solutions[id]),id);
 }
 for(const id of Object.keys(prior.hints)) assert.notEqual(hash(prior.hints[id]),hash(hints[id]),id);
 assert.equal(prior.provenance.sourceSha256['server/data/promptInjectionSolutions.js'],'fdba969aac4667b5dd9d0cb373bf3b6fef82119399930dd91e0eb952fa91ccdc');
});
for(const [id,current] of Object.entries(solutions).filter(([id])=>Object.hasOwn(prior.solutions,id)).map(([id,v])=>[id,v]).concat(['obfuscation','system_prompt','jailbreak','virtualization'].map(id=>[id+':hint',hints[id]])))test(`exact prior content reconciliation: ${id}`,async()=>{const hint=id.endsWith(':hint'),objectiveId=id.split(':')[0],old=hint?prior.hints[objectiveId]:prior.solutions[id],fieldName=hint?'hint_content':'solution_content';for(const [value,state,expected] of [[old,'managed','upgrade'],[{...old,title:'Instructor content'},'custom','preserve'],[{...old,title:'Unmarked instructor edit'},'managed','mark_custom'],[old,'legacy_unknown','preserve'],[null,'custom','preserve'],[old,'absent','preserve_unknown'],[current,'managed','record']]){const c=client(value,expected==='record'?current:old,state);const r=await p.reconcileField(c,{entityKind:'objective',workshopKey:'direct_prompt_injection',objectiveId,fieldName,sourceValue:current,sourceVersion:'dpi-teaching-decoder-alignment-v1'});assert.equal(r.decision,expected);assert.equal(c.calls.some(v=>v.sql.startsWith('UPDATE workshop_platform.objectives SET')),expected==='upgrade');}});
