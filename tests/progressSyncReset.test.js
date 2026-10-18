'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopProgressRepository}=require('../server/database/postgres/workshopProgressRepository');
function fixture(){
 let state={completions:[{owner:1,id:'rag_upload'},{owner:1,id:'email_send'},{owner:2,id:'rag_upload'}],activity:[{owner:1,id:'rag_upload'},{owner:1,id:'email_send'},{owner:2,id:'rag_upload'}],time:[1,2],generation:4,revisions:[]},saved,fail=false;const calls=[];
 const client={release(){},async query(sql,args=[]){calls.push({sql,args});if(sql==='BEGIN'){saved=structuredClone(state);return{rows:[]};}if(sql==='ROLLBACK'){state=saved;return{rows:[]};}if(sql==='COMMIT')return{rows:[]};
  if(sql.startsWith('SELECT * FROM workshop_platform.exercises'))return{rows:[{workshop_key:'indirect_prompt_injection'}]};
  if(sql.startsWith('INSERT INTO workshop_platform.user_state'))return{rows:[]};
  if(sql.startsWith('SELECT * FROM workshop_platform.user_state'))return{rows:[{generation:state.generation}]};
  if(sql.startsWith('SELECT objective_id'))return{rows:args[1].filter(id=>['rag_upload','email_send'].includes(id)).map(objective_id=>({objective_id})),rowCount:args[1].filter(id=>['rag_upload','email_send'].includes(id)).length};
  if(sql.startsWith('DELETE FROM workshop_platform.completions')||sql.startsWith('DELETE FROM workshop_platform.activity_counters')){const field=sql.includes('completions')?'completions':'activity';state[field]=state[field].filter(r=>r.owner!==args[0]||args[2]&&!args[2].includes(r.id));return{rows:[]};}
  if(sql.startsWith('DELETE FROM workshop_platform.time_tracking')){state.time=state.time.filter(owner=>owner!==args[0]);return{rows:[]};}
  if(sql.startsWith('UPDATE workshop_platform.user_state')){state.generation++;return{rows:[{generation:state.generation}]};}
  if(sql.startsWith('INSERT INTO workshop_platform.revisions')){if(fail)throw Error('Controlled revision failure');state.revisions.push(args);return{rows:[{revision:1}]};}
  assert.fail('Unexpected query: '+sql);
 }};
 return{service:createWorkshopProgressRepository({connect:async()=>client}),calls,state:()=>state,fail(){fail=true;}};
}
test('scenario reset preserves sibling objectives/activities, sibling owner and time while advancing owner generation',async()=>{
 const f=fixture();assert.deepEqual(await f.service.resetWorkshopProgress(1,'indirect_prompt_injection',{objectiveIds:['rag_upload'],expectedGeneration:4}),{generation:5});
 assert.deepEqual(f.state().completions,[{owner:1,id:'email_send'},{owner:2,id:'rag_upload'}]);assert.deepEqual(f.state().activity,f.state().completions);assert.deepEqual(f.state().time,[1,2]);assert.deepEqual(f.state().revisions,[['user','1','workshop_progress']]);
 const deletion=f.calls.find(c=>c.sql.startsWith('DELETE FROM workshop_platform.completions'));assert.match(deletion.sql,/user_id=\$1 AND workshop_key=\$2 AND objective_id=ANY\(\$3::text\[\]\)/);assert.deepEqual(deletion.args,[1,'indirect_prompt_injection',['rag_upload']]);
});
test('full owner reset clears canonical objectives/activity/time and advances progress plus time revisions',async()=>{
 const f=fixture();await f.service.resetWorkshopProgress(1,'indirect_prompt_injection');assert.deepEqual(f.state().completions,[{owner:2,id:'rag_upload'}]);assert.deepEqual(f.state().activity,[{owner:2,id:'rag_upload'}]);assert.deepEqual(f.state().time,[2]);assert.equal(f.state().generation,5);assert.deepEqual(f.state().revisions,[['user','1','workshop_progress'],['user','1','workshop_time']]);assert.equal(f.calls.at(-1).sql,'COMMIT');
});
test('revision failure rolls back controlled reset changes and reports no committed generation',async()=>{
 const f=fixture(),before=structuredClone(f.state());f.fail();await assert.rejects(f.service.resetWorkshopProgress(1,'indirect_prompt_injection'),/Controlled revision failure/);assert.deepEqual(f.state(),before);assert(f.calls.some(c=>c.sql==='ROLLBACK'));assert(!f.calls.some(c=>c.sql==='COMMIT'));
});
test('stale generation and unknown subset deny destructive effects',async()=>{
 const f=fixture();await assert.rejects(f.service.resetWorkshopProgress(1,'indirect_prompt_injection',{expectedGeneration:3}),{code:'STALE_GENERATION'});await assert.rejects(f.service.resetWorkshopProgress(1,'indirect_prompt_injection',{objectiveIds:['foreign']}),{code:'NOT_FOUND'});assert(!f.calls.some(c=>c.sql.startsWith('DELETE')));
});
