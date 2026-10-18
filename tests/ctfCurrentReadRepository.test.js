'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfCurrentReadRepository:create}=require('../server/database/postgres/ctfCurrentReadRepository');
function fixture(){const state={sequence:'4',ctfSequence:'4',revision:'2',actor:{id:'7',role:'student',admin_level:0},members:true,stageReady:true,stageRevision:'1',reads:0,config:{ctf_enabled:'true',ctf_visible_to_students:'true',student_leaderboard_visible:'true',public_leaderboard_visible:'false'}},trace=[];
 const pool=store=>({connect:async()=>({release(){trace.push(store+':release');},query:async(sql,args=[])=>{trace.push(store+':'+sql);if(store==='identity'){
 if(sql.startsWith('SELECT u.id'))return{rows:state.actor?[state.actor]:[]};
 if(sql.includes("scope_key='global'")){state.reads++;return{rows:[{revision:state.revision,applied_sequence:state.sequence,lifecycle_state:'ready'}]};}
 if(sql.startsWith('SELECT p.participant_id'))return{rows:state.members?[{participant_id:'9',owner_id:'7'}]:[]};
 if(sql.startsWith('SELECT substring'))return{rows:state.stageReady?[{stage_id:'1',revision:state.stageRevision}]:[]};
 }else{
 if(sql.includes('FROM ctf.projection_cursor'))return{rows:[{initialized:true,applied_sequence:state.ctfSequence}]};
 if(sql.includes('SELECT value FROM ctf.ctf_config'))return{rows:[{value:state.config[args[0]]??'0'}]};
 if(sql.startsWith('SELECT s.*,COALESCE(tc.objective_text')){state.onAdminSelection?.();return{rows:[{id:1,is_active:0,system_prompt:'instructor secret',success_criteria:'answer',solution_content:'instructor solution'}]};}
 if(sql.startsWith('SELECT a.*,p.username'))return{rows:[{id:1,stage_id:1,payload:'retained',judgment_metadata:'admin only'}]};
 if(sql.startsWith('SELECT p.*,(SELECT COUNT'))return{rows:[{id:9,user_id:7,is_active:0,started_at:null,total_attempts:3}]};
 if(sql.startsWith('SELECT COUNT(*)::integer'))return{rows:[{count:1}]};
 if(sql.startsWith('SELECT COUNT(*) as total'))return{rows:[{total:'1',completed:'0'}]};
 if(sql.startsWith('SELECT s.id, s.stage_number'))return{rows:[{id:1,stage_name:'One',teaching_objective:'Learner objective',completion_count:'0'}]};
 if(sql.startsWith('SELECT s.stage_name'))return{rows:[{stage_name:'One',attempts:'0'}]};
 if(sql.startsWith('SELECT technique_tag'))return{rows:[{technique_tag:'other',count:'1'}]};
 if(sql.startsWith('SELECT id::text FROM ctf.ctf_stages'))return{rows:[{id:'1'}]};
 if(sql.startsWith('SELECT * FROM ctf.ctf_participants'))return{rows:[{id:9,user_id:7,username:'learner'}]};
 if(sql.startsWith('SELECT p.*, s.stage_number'))return{rows:[{stage_id:1,status:'completed'}]};
 if(sql.startsWith('SELECT * FROM ctf.ctf_leaderboard'))return{rows:[{participant_id:9,total_score:10}]};
 if(sql.startsWith('SELECT l.*'))return{rows:[{participant_id:9,username:'learner',total_score:10}]};
 if(sql.startsWith('SELECT e.*'))return{rows:state.events||[{participant_id:9,stage_id:1,event_type:'stage_complete'}]};
 if(sql.startsWith('SELECT id::text')){state.onSelection?.();return{rows:[{participantId:'9',ownerId:'7'}]};}
 }return{rows:[]};}})});
 return{state,trace,repo:create({identityPool:pool('identity'),ctfPool:pool('ctf'),readiness:async()=>state.readiness!==false}),session:{actorId:'7',sessionId:'8',rawToken:'private'}};
}
test('status preserves helper shape with sequential release and acknowledged snapshot',async()=>{const f=fixture(),r=await f.repo.read({kind:'status',session:f.session});assert.equal(r.registered,true);assert.equal(r.progress[0].status,'completed');assert.equal(r.leaderboardEntry.total_score,10);assert.equal(f.state.reads,2);assert(f.trace.indexOf('identity:release')<f.trace.indexOf('ctf:SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'));});
test('unacknowledged projection, changed epoch, pending membership and stage deny',async()=>{for(const change of [s=>s.ctfSequence='5',s=>s.onSelection=()=>{s.revision='3';},s=>s.members=false,s=>s.stageReady=false]){const f=fixture();change(f.state);await assert.rejects(f.repo.read({kind:'status',session:f.session}),{code:'CTF_READ_UNAVAILABLE'});}});
test('public leaderboard masks names while authenticated student switch remains independent',async()=>{const f=fixture();f.state.actor=null;const r=await f.repo.read({kind:'leaderboard'});assert.equal(r.leaderboard[0].username,'lea***');const g=fixture();g.state.config.student_leaderboard_visible='false';await assert.rejects(g.repo.read({kind:'leaderboard',session:g.session}),{code:'LEADERBOARD_HIDDEN'});});
test('revocation at final publication and malformed bearer reject; events preserve shape',async()=>{const f=fixture();f.state.onSelection=()=>{f.state.actor=null;};await assert.rejects(f.repo.read({kind:'status',session:f.session}),{code:'SESSION_REVOKED'});const g=fixture();await assert.rejects(g.repo.read({kind:'status',session:{...g.session,rawToken:'\ud800'}}));assert.equal(g.trace.length,0);assert.equal((await g.repo.read({kind:'events'})).events[0].event_type,'stage_complete');});

test('aggregate modes retain established helper counts and bounded keyset membership checks',async()=>{
 const f=fixture();f.state.actor.role='admin';f.state.actor.admin_level=1;const config=await f.repo.read({kind:'config',session:f.session});assert.equal(config.config.current_participants,1);
 const stages=await f.repo.read({kind:'stages',session:f.session});assert.equal(stages.stages[0].completion_count,0);
 const analytics=await f.repo.read({kind:'analytics',session:f.session});assert.deepEqual(analytics.analytics.participants,{total:1,completed:0});assert.equal(analytics.analytics.topTechniques[0].count,1);assert(f.trace.some(x=>x.includes('id>$1 ORDER BY id LIMIT 256')));
 f.state.members=false;await assert.rejects(f.repo.read({kind:'analytics',session:f.session}),{code:'CTF_READ_UNAVAILABLE'});
});
test('analytics requires canonical admin; malformed limits rejected and read cancellation settles',async()=>{
 const f=fixture();await assert.rejects(f.repo.read({kind:'analytics',session:f.session}),{code:'ADMIN_REQUIRED'});await assert.rejects(f.repo.read({kind:'events',limit:201}),TypeError);const controller=new AbortController();controller.abort();await assert.rejects(f.repo.read({kind:'events'},{signal:controller.signal}),{code:'CTF_READ_UNAVAILABLE'});
});

test('mixed stage-less events never borrow event IDs as stage authority IDs',async()=>{
 const f=fixture();f.state.events=[{id:999,participant_id:9,stage_id:null,event_type:'new_participant'},{id:998,participant_id:null,stage_id:null,event_type:'global_reset'},{id:997,participant_id:9,stage_id:1,event_type:'stage_complete'}];
 const r=await f.repo.read({kind:'events'});assert.equal(r.events.length,3);
 const stages=f.trace.filter(x=>x.startsWith('identity:SELECT substring'));assert.equal(stages.length,1);
 // Mock exposes only stage1: event IDs999/998/997 would make guard cardinality fail.
 assert.equal(r.events[0].stage_id,null);
});

test('retained public events and historical stage counts survive inactive owner membership',async()=>{
 const f=fixture();f.state.members=false;f.state.events=[{id:999,participant_id:9,stage_id:null,event_type:'new_participant'}];
 assert.equal((await f.repo.read({kind:'events'})).events[0].participant_id,9);
 assert.equal((await f.repo.read({kind:'stages'})).stages[0].completion_count,0);
 assert(!f.trace.some(x=>x.startsWith('identity:SELECT p.participant_id')));
 assert(!f.trace.some(x=>x.includes('id>$1 ORDER BY id LIMIT 256')));
 await assert.rejects(f.repo.read({kind:'config'}),{code:'CTF_READ_UNAVAILABLE'}); // active-count scope still checked
});

test('closed admin modes retain spoilers and historical inactive roster while disabled, and final role loss denies',async()=>{
 const f=fixture();for(const kind of ['adminStages','adminAttempts','adminParticipants'])await assert.rejects(f.repo.read({kind,session:f.session}),{code:'ADMIN_REQUIRED'});
 f.state.actor.role='admin';f.state.actor.admin_level=1;f.state.config.ctf_enabled='false';f.state.config.ctf_visible_to_students='false';f.state.members=false;
  assert.equal((await f.repo.read({kind:'adminStages',session:f.session})).stages[0].system_prompt,'instructor secret');
 assert.equal((await f.repo.read({kind:'adminStages',session:f.session})).stages[0].solution_content,'instructor solution');
 assert.equal((await f.repo.read({kind:'adminAttempts',session:f.session})).attempts[0].judgment_metadata,'admin only');
 assert.equal((await f.repo.read({kind:'adminParticipants',session:f.session})).participants[0].is_active,0);
 f.state.onAdminSelection=()=>{f.state.actor={...f.state.actor,role:'student'};};await assert.rejects(f.repo.read({kind:'adminStages',session:f.session}),{code:'CTF_READ_UNAVAILABLE'});
});

test('preview uses live canonical read across inference: transport tick allowed, edit-revert and revocation denied',async()=>{
 const {createCtfAdminPreviewSnapshot}=require('../server/services/ctfAdminPreviewSnapshot');
 const f=fixture();f.state.actor.role='admin';f.state.actor.admin_level=1;const preview=createCtfAdminPreviewSnapshot({current:f.repo});
 const captured=await preview.capture({stageId:1,session:f.session});
 f.state.sequence='5';f.state.ctfSequence='5';assert.equal(await preview.revalidate(captured.lease),true);
 f.state.stageRevision='3';await assert.rejects(preview.revalidate(captured.lease),{code:'CTF_PREVIEW_STALE'});
 const fresh=await preview.capture({stageId:1,session:f.session});f.state.actor=null;await assert.rejects(preview.revalidate(fresh.lease),{code:'SESSION_REVOKED'});
});
test('preview final reader rejects pending stage, readiness loss and caller cancellation',async()=>{
 const {createCtfAdminPreviewSnapshot}=require('../server/services/ctfAdminPreviewSnapshot');
 const f=fixture();f.state.actor.role='admin';f.state.actor.admin_level=1;const preview=createCtfAdminPreviewSnapshot({current:f.repo}),captured=await preview.capture({stageId:1,session:f.session});
 f.state.stageReady=false;await assert.rejects(preview.revalidate(captured.lease),{code:'CTF_READ_UNAVAILABLE'});
 f.state.stageReady=true;f.state.readiness=false;await assert.rejects(preview.revalidate(captured.lease),{code:'CTF_READ_UNAVAILABLE'});f.state.readiness=true;const abort=new AbortController();abort.abort();await assert.rejects(preview.revalidate(captured.lease,{signal:abort.signal}),{code:'CTF_READ_UNAVAILABLE'});
});

test('all nine role/level pairs share canonical admin and leaderboard policy',async()=>{
 for(const role of ['student','admin','super_admin'])for(const admin_level of [0,1,2]){
  const f=fixture();Object.assign(f.state.actor,{role,admin_level});f.state.config.student_leaderboard_visible='false';
  const allowed=['admin','super_admin'].includes(role)&&admin_level>=1;
  if(allowed){assert.equal((await f.repo.read({kind:'adminStages',session:f.session})).stages[0].system_prompt,'instructor secret');await f.repo.read({kind:'leaderboard',session:f.session});}
  else {await assert.rejects(f.repo.read({kind:'adminStages',session:f.session}),{code:'ADMIN_REQUIRED'});await assert.rejects(f.repo.read({kind:'leaderboard',session:f.session}),{code:'LEADERBOARD_HIDDEN'});}
 }
});
test('role-only and level-only demotion during current read prohibit publication',async()=>{
 for(const change of [s=>s.actor={...s.actor,role:'student'},s=>s.actor={...s.actor,admin_level:0}]){
  const f=fixture();Object.assign(f.state.actor,{role:'super_admin',admin_level:1});f.state.onAdminSelection=()=>change(f.state);
  await assert.rejects(f.repo.read({kind:'adminStages',session:f.session}),{code:'CTF_READ_UNAVAILABLE'});
 }
});
