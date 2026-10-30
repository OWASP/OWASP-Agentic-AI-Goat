'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopConfigRepository}=require('../server/database/postgres/workshopConfigRepository');
function fixture(){
 let state={revision:0,is_visible:true,show_hints:true,show_solutions:false,hint_enabled:true,solution_enabled:false},saved,fail=false;const calls=[];
 const row=()=>({...state,workshop_key:'direct_prompt_injection',challenge_key:'direct_prompt_injection',objective_id:'jailbreak',label:'Owned',is_enabled:true,catalog_active:true,hint_content:{hints:['owned']},solution_content:{title:'owned'}});
 const client={release(){},async query(sql,args=[]){calls.push({sql,args});
  if(sql==='BEGIN'){saved=structuredClone(state);return{rows:[]};}if(sql==='ROLLBACK'){state=saved;return{rows:[]};}if(sql==='COMMIT')return{rows:[]};
  if(sql.includes('SELECT revision'))return{rows:[{revision:state.revision}]};
  if(sql.startsWith('SELECT * FROM workshop_platform.exercises')||sql.startsWith('SELECT * FROM workshop_platform.objectives'))return{rows:[row()]};
  if(sql.startsWith('SELECT w.*'))return{rows:[row()]};
  if(sql.startsWith('SELECT EXISTS'))return{rows:[{enabled:sql.includes('solution_enabled')?state.solution_enabled:state.hint_enabled}]};
  if(sql.startsWith('UPDATE workshop_platform.config_revision')){if(fail)throw Error('Controlled revision failure');state.revision++;return{rowCount:1,rows:[]};}
  if(sql.startsWith('INSERT INTO workshop_platform.revisions'))return{rows:[{revision:state.revision}]};
  if(sql.startsWith('UPDATE workshop_platform.')){const field=sql.match(/SET (\w+)=\$1/)[1],changed=state[field]!==args[0];state[field]=args[0];return{rowCount:Number(changed),rows:[]};}
  throw Error('Unexpected controlled query: '+sql);
 }};
 return{service:createWorkshopConfigRepository({connect:async()=>client}),calls,state:()=>state,failRevision(){fail=true;}};
}
test('master help mutations keep independent gates and duplicate state is revision no-op',async()=>{
 const f=fixture();assert.equal((await f.service.setMasterSolutionVisibility('direct_prompt_injection',true,71)).changed,true);
 assert.equal(f.state().revision,1);assert.equal(f.state().show_hints,true);assert.equal(f.state().hint_enabled,true);assert.equal(f.state().solution_enabled,true);
 assert.equal((await f.service.setMasterSolutionVisibility('direct_prompt_injection',true,71)).changed,false);assert.equal(f.state().revision,1);
 await f.service.setMasterHintVisibility('direct_prompt_injection',false,71);assert.equal(f.state().show_solutions,true);assert.equal(f.state().solution_enabled,true);assert.equal(f.state().revision,2);
 assert(f.calls.filter(c=>c.sql.startsWith('UPDATE workshop_platform.exercises SET show_')).every(c=>c.args[1]===71));
});
test('per-objective gate derives only its own master and exercise visibility stays independent',async()=>{
 const f=fixture();await f.service.setObjectiveSolutionVisibility('direct_prompt_injection','jailbreak',true,71);
 assert.equal(f.state().show_solutions,true);assert.equal(f.state().hint_enabled,true);
 await f.service.setExerciseVisibility('direct_prompt_injection',false,71);assert.equal(f.state().is_visible,false);assert.equal(f.state().solution_enabled,true);
});
test('global hint and solution mutation updates both database gates atomically',async()=>{
 const f=fixture();const enabled=await f.service.setAllHintAndSolutionVisibility(true,71);
 assert.equal(enabled.changed,true);assert.equal(f.state().show_hints,true);assert.equal(f.state().show_solutions,true);
 assert.equal(f.state().hint_enabled,true);assert.equal(f.state().solution_enabled,true);assert.equal(f.state().revision,1);
 const disabled=await f.service.setAllHintAndSolutionVisibility(false,71);
 assert.equal(disabled.changed,true);assert.equal(f.state().show_hints,false);assert.equal(f.state().show_solutions,false);
 assert.equal(f.state().hint_enabled,false);assert.equal(f.state().solution_enabled,false);assert.equal(f.state().revision,2);
 assert(f.calls.filter(c=>c.sql.startsWith('UPDATE workshop_platform.')&&c.sql.includes('updated_by=$2')).every(c=>c.args[1]===71));
});
test('revision failure rolls back controlled transaction and never reports commit',async()=>{
 const f=fixture(),before=structuredClone(f.state());f.failRevision();
 await assert.rejects(f.service.setMasterSolutionVisibility('direct_prompt_injection',true,71),/Controlled revision failure/);
 assert.deepEqual(f.state(),before);assert(f.calls.some(c=>c.sql==='ROLLBACK'));assert(!f.calls.some(c=>c.sql==='COMMIT'));
});
test('malformed mutation and retired SQLite options fail before transactions',()=>{
 const f=fixture();assert.throws(()=>f.service.setMasterHintVisibility('direct_prompt_injection','true'),{code:'BAD_REQUEST'});assert.deepEqual(f.calls,[]);
 const retired=require('../server/services/workshopConfigMutationService');assert.throws(()=>retired.createWorkshopConfigMutationService({authDb:{}}),/PostgreSQL/);assert.equal(retired.mutateAndBump,undefined);assert.equal(retired.PROMPT_INJECTION_SOLUTION_ADAPTERS,undefined);
});
