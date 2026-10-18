'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfDb,createCtfMutationAdapter}=require('../server/database/postgres/ctfDb');

test('ordered teaching update writes only stage teaching fields and the keyed content row',async()=>{
 const calls=[];
 const client={release(){},query:async(sql,args=[])=>{
  calls.push({sql,args});
  if(sql.startsWith('SELECT stage_number'))return{rows:[{stage_number:3}]};
  if(sql.startsWith('SELECT objective_text'))return{rows:[{objective_text:'Prior objective',solution_text:'Prior solution'}]};
  return{rows:[],rowCount:1};
 }};
 const adapter=createCtfMutationAdapter(client,{occurredAt:'2026-10-07T00:00:00.000Z'});
 assert.equal(await adapter.updateStage(9,{
  stage_name:'Learner title',stage_description:'Learner description',hints:'["one"]',
  teaching_objective:'Learner objective',solution_content:'Instructor solution',
 }),true);
 const stageUpdate=calls.find(call=>call.sql.startsWith('UPDATE ctf.ctf_stages SET'));
 assert(stageUpdate);
 assert.match(stageUpdate.sql,/stage_name=\$1,stage_description=\$2,hints=\$3/);
 assert.deepEqual(stageUpdate.args,['Learner title','Learner description','["one"]',9]);
 const contentWrite=calls.find(call=>call.sql.startsWith('INSERT INTO ctf.ctf_stage_teaching_content'));
 assert(contentWrite);
 assert.deepEqual(contentWrite.args,[9,'Learner objective','Instructor solution']);
 assert(!contentWrite.sql.includes('system_prompt'));
});

test('student stage projection omits solution text while admin stage projection retains it',async()=>{
 const calls=[];
 const pool={query:async(sql,args=[])=>{calls.push({sql,args});return{rows:[]};}};
 const db=createCtfDb(pool);
 await db.listStudentStages();
 await db.getAllStages();
 const [student,admin]=calls;
 assert.match(student.sql,/objective_text/);
 assert.doesNotMatch(student.sql,/solution_text/);
 assert.match(admin.sql,/solution_text/);
});
