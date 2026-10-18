'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopConfigRepository}=require('../server/database/postgres/workshopConfigRepository');
const {createWorkshopConfigService}=require('../server/services/workshopConfigService');
function fixture(){
 const row={workshop_key:'direct_prompt_injection',challenge_key:'direct_prompt_injection',is_visible:true,show_hints:true,show_solutions:false,objective_id:'jailbreak',label:'Instructor label',description:'Instructor description',is_enabled:true,hint_enabled:true,solution_enabled:true,hint_content:{hints:['owned hint']},solution_content:{title:'owned solution'}};
 const calls=[];const client={release(){},async query(sql){calls.push(sql);if(sql.includes('SELECT revision'))return{rows:[{revision:7}]};if(sql.startsWith('SELECT w.*'))return{rows:[row]};if(sql.startsWith('SELECT * FROM workshop_platform.exercises'))return{rows:[row]};return{rows:[]};}};
 return{row,calls,service:createWorkshopConfigRepository({connect:async()=>client,query:(...args)=>client.query(...args)})};
}
test('canonical config projects independent hint/solution gates and preserves instructor content only when visible',async()=>{
 const f=fixture();let s=await f.service.getSnapshot({includeRaw:true}),o=s.exercises.direct_prompt_injection.objectives.jailbreak;
 assert.equal(s.revision,7);assert.equal(o.label,'Instructor label');assert.equal(o.description,'Instructor description');assert.equal(o.hintVisible,true);assert.equal(o.solutionVisible,false);assert.equal(o.raw.solution,undefined);
 f.row.show_hints=false;f.row.show_solutions=true;s=await f.service.getSnapshot({includeRaw:true});o=s.exercises.direct_prompt_injection.objectives.jailbreak;
 assert.equal(o.hintVisible,false);assert.equal(o.solutionVisible,true);assert.deepEqual(o.raw.solution,{title:'owned solution'});assert.equal(o.raw.hint,undefined);
 f.row.is_enabled=false;o=(await f.service.getSnapshot()).exercises.direct_prompt_injection.objectives.jailbreak;assert.equal(o.isVisible,false);assert.equal(o.solutionVisible,false);
});
test('missing content and hidden exercise deny help regardless of enabled gates',async()=>{
 const f=fixture();f.row.hint_content=null;assert.equal(await f.service.isHintVisible('direct_prompt_injection','jailbreak'),false);
 f.row.show_solutions=true;f.row.is_visible=false;assert.equal(await f.service.isSolutionVisible('direct_prompt_injection','jailbreak'),false);
 assert.equal(await f.service.isSolutionVisible('direct_prompt_injection','foreign'),false);
});
test('legacy config injection is explicitly rejected without selecting a registry or database',()=>{
 for(const options of [{authDb:{}},{solutionRegistry:{}},null,[]])assert.throws(()=>createWorkshopConfigService(options),/PostgreSQL/);
});

test('student content response follows effective gates and default snapshot omits raw content',async()=>{
 const f=fixture();assert.equal((await f.service.getSnapshot()).exercises.direct_prompt_injection.objectives.jailbreak.raw,undefined);
 assert.deepEqual(await f.service.getStudentContent('direct_prompt_injection','jailbreak','hint'),{hints:['owned hint']});
 await assert.rejects(f.service.getStudentContent('direct_prompt_injection','jailbreak','solution'),{code:'FORBIDDEN'});
 f.row.show_solutions=true;assert.deepEqual(await f.service.getStudentContent('direct_prompt_injection','jailbreak','solution'),{title:'owned solution'});
 f.row.is_enabled=false;await assert.rejects(f.service.getStudentContent('direct_prompt_injection','jailbreak','hint'),{code:'FORBIDDEN'});
 await assert.rejects(f.service.getStudentContent('direct_prompt_injection','jailbreak','unknown'),{code:'BAD_REQUEST'});
});
