'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopProgressRepository}=require('../server/database/postgres/workshopProgressRepository');
function fixture(){
 const calls=[],rows=[];let failure;
 const config={workshop_key:'direct_prompt_injection',challenge_key:'direct_prompt_injection',is_visible:true,catalog_active:true,show_hints:true,show_solutions:false,objective_id:'jailbreak',label:'Instructor label',description:'Instructor objective description',is_enabled:true,hint_enabled:true,solution_enabled:true,hint_content:{hints:['owned']},solution_content:{title:'owned'}};
 const client={release(){},async query(sql,args=[]){calls.push({sql,args});if(failure)throw failure;
  if(sql.includes('to_regclass'))return{rows:[{}]};
  if(sql.includes('CROSS JOIN'))return{rows:rows.filter(r=>args[0].includes(r.user_id))};
  if(sql.includes('SELECT revision'))return{rows:[{revision:19}]};
  if(sql.startsWith('SELECT w.*'))return{rows:[config,{...config,workshop_key:'secureshop_agent_security',challenge_key:'secureshop_agent_security'}]};
  if(sql.startsWith('SELECT * FROM workshop_platform.exercises'))return{rows:[{...config,workshop_key:args[0]}]};
  if(sql.startsWith('SET TRANSACTION')||sql.startsWith('BEGIN')||sql==='COMMIT'||sql==='ROLLBACK')return{rows:[]};
  throw Error('Unexpected controlled query: '+sql);
 }};
 const add=(owner,overrides={})=>rows.push({user_id:owner,workshop_key:'direct_prompt_injection',challenge_key:'direct_prompt_injection',challenge_name:'Instructor title',is_visible:true,total:2,done:1,seconds:43,completed_at:'2026-10-06T00:00:00Z',objectives:[{id:'jailbreak',label:'Instructor label',description:'Instructor objective description',completed:true}],...overrides});
 return{service:createWorkshopProgressRepository({connect:async()=>client,query:client.query}),add,calls,fail(error){failure=error;}};
}
test('canonical projection preserves owner counts, time and completed timestamps',async()=>{
 const f=fixture();f.add(7);f.add(8,{done:2,seconds:91});
 const seven=(await f.service.getUserProgress(7))[0],eight=(await f.service.getUserProgress(8))[0];
 assert.equal(seven.status,'in_progress');assert.equal(seven.completedAt,null);assert.equal(seven.timeSpentSeconds,43);assert.equal(seven.objectiveCount,2);assert.equal(seven.completedObjectiveCount,1);
 assert.equal(eight.status,'completed');assert.equal(eight.completed,true);assert.equal(eight.completedAt,'2026-10-06T00:00:00Z');assert.equal(eight.timeSpentSeconds,91);
 const query=f.calls.find(c=>c.sql.includes('CROSS JOIN'));assert.match(query.sql,/c.user_id=u.user_id/);assert.match(query.sql,/o.catalog_active=true AND o.is_enabled=true/);assert.deepEqual(query.args,[[7]]);
});
test('single and batched owner views agree, deduplicate owners and preserve canonical hidden progress',async()=>{
 const f=fixture();f.add(7);f.add(8,{is_visible:false});const batch=await f.service.getUsersProgress([7,8,7,null]);
 assert.deepEqual([...batch.keys()],[7,8]);assert.deepEqual(batch.get(7),await f.service.getUserProgress(7));assert.equal(batch.get(8).length,1);assert.deepEqual(await f.service.getVisibleUserProgress(8),[]);
 assert.deepEqual(await f.service.getWorkshopProgress(7,'direct_prompt_injection'),batch.get(7)[0]);
});
test('learner view preserves instructor content, independent help gates, revision and locked empty catalog',async()=>{
 const f=fixture();f.add(7);let view=(await f.service.getVisibleUserProgress(7))[0];
 assert.equal(view.name,'Instructor title');assert.equal(view.objectives[0].text,'Instructor label');assert.equal(view.objectives[0].description,'Instructor objective description');assert.equal(view.objectives[0].hintVisible,true);assert.equal(view.objectives[0].solutionVisible,false);assert.equal(view.configRevision,19);assert.equal(view.canonicalStatus,'in_progress');
 assert.match(f.calls.find(c=>c.sql.includes('CROSS JOIN')).sql,/'description',o.description/);
 f.add(9,{total:0,done:0,objectives:[]});view=(await f.service.getVisibleUserProgress(9))[0];assert.equal(view.status,'locked');assert.equal(view.canonicalStatus,'not_started');
});
test('invalid owners and repository failures are not converted into empty successful progress',async()=>{
 const f=fixture();await assert.rejects(f.service.getUserProgress(-1),{code:'AUTH_REQUIRED'});assert.deepEqual(f.calls,[]);
 f.fail(Error('Controlled read failure'));await assert.rejects(f.service.getUserProgress(7),/Controlled read failure/);
 assert.throws(()=>require('../server/services/workshopProgressService').createWorkshopProgressService({all(){}}),/PostgreSQL/);
});

test('standalone app progress stays direct while workshop learner, instructor and batch totals exclude it',async()=>{
 const f=fixture();f.add(7);f.add(7,{workshop_key:'secureshop_agent_security',challenge_key:'secureshop_agent_security',total:20,done:20,seconds:9000});
 f.add(8,{workshop_key:'secureshop_agent_security',challenge_key:'secureshop_agent_security',is_visible:false});
 for(const method of ['getUserProgress','getVisibleUserProgress','getInstructorProgress']){
  const rows=await f.service[method](7);assert.deepEqual(rows.map(row=>row.workshopKey),['direct_prompt_injection']);
  assert.equal(rows.reduce((sum,row)=>sum+row.objectiveCount,0),2);assert.equal(rows.reduce((sum,row)=>sum+row.timeSpentSeconds,0),43);
 }
 for(const method of ['getUsersProgress','getVisibleUsersProgress'])assert.deepEqual((await f.service[method]([7,8])).get(7).map(row=>row.workshopKey),['direct_prompt_injection']);
 const app=await f.service.getWorkshopProgress(7,'secureshop_agent_security');assert.equal(app.objectiveCount,20);assert.equal(app.timeSpentSeconds,9000);assert.equal(app.completed,true);assert(Array.isArray(app.exerciseGroups));
 assert.equal((await f.service.getVisibleWorkshopProgress(7,'secureshop_agent_security')).name,'Instructor title');
 assert.equal(await f.service.getVisibleWorkshopProgress(8,'secureshop_agent_security'),null);
 assert.equal((await f.service.getWorkshopProgress(8,'secureshop_agent_security')).workshopKey,'secureshop_agent_security');
});
