'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const prior=require('./fixtures/csrfTeachingDefaults.pre-selected-read.json');
const solutions=require('../server/data/csrfWorkshopSolutions').objectiveSolutions;
const hints=require('../server/data/workshopHints').csrf_workshop;
const p=require('../server/database/postgres/catalogDefaultProvenance');
const hash=v=>p.hashDocument(p.document(v));
function client(current,old,state){const calls=[];return {calls,async query(sql,args){calls.push({sql,args});if(/SELECT revision/.test(sql))return {rows:[{revision:1}],rowCount:1};if(/ AS value FROM/.test(sql))return {rows:[{value:current}],rowCount:1};if(/SELECT \* FROM workshop_platform.catalog_field_defaults/.test(sql))return {rows:state==='absent'?[]:[{provenance_state:state,applied_default_hash:hash(old)}],rowCount:state==='absent'?0:1};return {rows:[],rowCount:1};}};}
test('exact objective map preserved; only three email defaults changed',()=>{
 assert.deepEqual(solutions.map(x=>x.objective_id),prior.solutions.map(x=>x.objective_id));assert.deepEqual(Object.keys(hints),Object.keys(prior.hints));
 for(const row of solutions){const old=prior.solutions.find(x=>x.objective_id===row.objective_id);if(!['csrf_x1','csrf_x2','csrf_x3'].includes(row.objective_id)){assert.deepEqual(row,old);assert.deepEqual(hints[row.objective_id],prior.hints[row.objective_id]);}}
 const x3=solutions.find(x=>x.objective_id==='csrf_x3');assert.equal(x3.example,'Please open the original email in my inbox.');assert.match(x3.explanation,/refusal is a valid negative/i);assert.match(x3.explanation,/escaped inert text/);assert.match(x3.hint,/managed browser/);
});
for(const id of ['csrf_x1','csrf_x2','csrf_x3'])for(const field of ['hint_content','solution_content'])test(`${id} ${field}: managed upgrade, instructor preservation and no-op`,async()=>{
 const old=field==='hint_content'?prior.hints[id]:prior.solutions.find(x=>x.objective_id===id),current=field==='hint_content'?hints[id]:solutions.find(x=>x.objective_id===id);
 for(const [value,state,expected]of [[old,'managed','upgrade'],[{...old,title:'Instructor edit'},'custom','preserve'],[{...old,title:'Unmarked edit'},'managed','mark_custom'],[old,'legacy_unknown','preserve'],[old,'absent','preserve_unknown'],[current,'managed','record']]){
  const c=client(value,expected==='record'?current:old,state);const r=await p.reconcileField(c,{entityKind:'objective',workshopKey:'csrf_workshop',objectiveId:id,fieldName:field,sourceValue:current,sourceVersion:'csrf-selected-original-content-v1'});assert.equal(r.decision,expected);assert.equal(c.calls.some(x=>x.sql.startsWith('UPDATE workshop_platform.objectives SET')),expected==='upgrade');
 }
});
test('actual editor validator accepts CSRF explanation and title/description but rejects malformed fields before transaction',async()=>{
 const marker=new Error('controlled transaction boundary');let connections=0;
 const config=require('../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository({connect:async()=>{connections++;throw marker;}});
 for(const content of [{title:'Instructor POST solution',explanation:17},{title:'Instructor POST solution',unknownField:'unsupported'}]){
  await assert.rejects(async()=>config.updateSolutionContent('csrf_workshop','csrf_p1',content),error=>error.code==='BAD_REQUEST');
 }
 assert.equal(connections,0);
 await assert.rejects(config.updateSolutionContent('csrf_workshop','csrf_p1',{title:'Instructor POST solution',explanation:'Retain instructor-authored explanation.'}),error=>error===marker);assert.equal(connections,1);
 await assert.rejects(config.updateSolutionContent('csrf_workshop','csrf_p1',{title:'Instructor POST solution',description:'Retain instructor-authored teaching content.'}),error=>error===marker);assert.equal(connections,2);
});
