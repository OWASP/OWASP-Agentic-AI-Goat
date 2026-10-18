'use strict';
const {hasAdminLevel}=require('../../middleware/postgresAdminAuth');
// Unmounted read composition; existing CTF helpers own response row shapes.
// Valid only after exclusive ordered-writer activation. No bootstrap/DDL/write.
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {createCtfDb}=require('./ctfDb');
const adminQueries=require('./ctfAdminReadQueries');
const fail=(code='CTF_READ_UNAVAILABLE',statusCode=503)=>{throw Object.assign(Error(code),{code,statusCode});};
const kinds=new Set(['config','stages','status','leaderboard','events','analytics','adminStages','adminAttempts','adminParticipants']);
const configKeys=['ctf_enabled','ctf_visible_to_students','student_leaderboard_visible','public_leaderboard_visible','ctf_registration_open','ctf_max_participants','ctf_time_limit','leaderboard_update_interval','ctf_nav_visible','ctf_show_technique_feedback','ctf_show_attempt_counter','ctf_hint_gating_attempts','ctf_hint_cost_1','ctf_hint_cost_2','ctf_hint_cost_3'];
function createCtfCurrentReadRepository({identityPool,ctfPool,readiness}){
 if(!identityPool||!ctfPool||typeof readiness!=='function')throw TypeError('CTF activated read dependencies required');
 async function ready(signal){let listener;const abort=new Promise((_,reject)=>{listener=()=>reject(Object.assign(Error('CTF_READ_UNAVAILABLE'),{code:'CTF_READ_UNAVAILABLE',statusCode:503}));signal.addEventListener('abort',listener,{once:true});if(signal.aborted)listener();});try{return await Promise.race([Promise.resolve().then(()=>readiness({signal})),abort]);}finally{signal.removeEventListener('abort',listener);}}
 async function checkpoint(session,signal,members=[],stages=[]){return withCtfTransaction(identityPool,async c=>{
  await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
  let actor=null;
  if(session){actor=(await c.query(`SELECT u.id::text AS id,u.role,COALESCE(u.admin_level,0) AS admin_level FROM identity.users u JOIN identity.user_sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2 AND s.session_token_hash=$3 AND u.is_active=1 AND s.is_active=1 AND s.expires_at>clock_timestamp() AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id) AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key='["CTF","'||u.id||'"]')`,[session.actorId,session.sessionId,createHash('sha256').update(session.rawToken).digest('hex')])).rows[0];if(!actor)fail('SESSION_REVOKED',401);}
  const global=(await c.query("SELECT revision::text,applied_sequence::text,lifecycle_state FROM identity.ctf_authority WHERE scope_key='global'")).rows[0];
  if(!global||global.lifecycle_state!=='ready')fail();
  if(members.length){
   const current=(await c.query(`SELECT p.participant_id::text,p.owner_id::text FROM identity.ctf_participant_bindings p JOIN identity.ctf_authority a ON a.scope_key='owner:'||p.owner_id JOIN graph_runtime.owners g ON g.owner_key='["CTF","'||p.owner_id||'"]' WHERE p.participant_id=ANY($1::bigint[]) AND p.active AND a.lifecycle_state='ready' AND a.owner_generation=p.owner_generation AND g.generation=p.owner_generation AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=p.owner_id) AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key=g.owner_key)`,[members.map(x=>x.participantId)])).rows;
   const valid=new Map(current.map(x=>[x.participant_id,x.owner_id]));if(members.some(x=>valid.get(x.participantId)!==x.ownerId))fail();
  }
  let stageRevisions={};
  if(stages.length){const ready=(await c.query("SELECT substring(scope_key from 7) AS stage_id,revision::text AS revision FROM identity.ctf_authority WHERE scope_key=ANY($1::text[]) AND lifecycle_state='ready'",[stages.map(id=>'stage:'+id)])).rows;if(new Set(ready.map(x=>x.stage_id)).size!==stages.length||ready.some(x=>typeof x.revision!=='string'||!/^(0|[1-9][0-9]*)$/.test(x.revision)))fail();stageRevisions=Object.fromEntries(ready.map(x=>[x.stage_id,x.revision]));}
  return {actor,global,stageRevisions};
 },{signal});}
 async function readInternal({kind,session=null,limit=50,filters={}},{signal}={},snapshot=false){
  signal=signal?AbortSignal.any([signal,AbortSignal.timeout(10000)]):AbortSignal.timeout(10000);
  if(!kinds.has(kind)||!Number.isInteger(limit)||limit<1||limit>200)throw TypeError('Invalid CTF read request');
  filters=adminQueries.validateFilters(filters);
  if(kind!=='adminAttempts'&&Object.keys(filters).length)throw TypeError('Unexpected CTF filters');
  if(session&&(!/^[1-9][0-9]*$/.test(session.actorId)||!/^[1-9][0-9]*$/.test(session.sessionId)||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384))fail('SESSION_REVOKED',401);
  // Snapshot caller credentials before any await; caller objects are not leases.
  session=session?Object.freeze({...session}):null;
  if(signal?.aborted)fail();if(await ready(signal)!==true)fail();
  const before=await checkpoint(session,signal),admin=hasAdminLevel(before.actor);
  if(kind==='status'&&!before.actor)fail('AUTHENTICATION_REQUIRED',401);
  if((kind==='analytics'||kind.startsWith('admin'))&&!admin)fail('ADMIN_REQUIRED',403);
  const selected=await withCtfTransaction(ctfPool,async c=>{
   await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
   const cursor=(await c.query('SELECT initialized,applied_sequence::text FROM ctf.projection_cursor WHERE singleton')).rows[0];
   if(!cursor?.initialized||cursor.applied_sequence!==before.global.applied_sequence)fail();
   const db=createCtfDb(c),config={};for(const key of configKeys)config[key]=await db.getConfig(key);
   if(!admin&&config.ctf_enabled!=='true')fail('CTF_DISABLED',403);
   if(['stages','status','events'].includes(kind)&&!admin&&config.ctf_visible_to_students!=='true')fail('CTF_HIDDEN',403);
   let body;
   if(kind==='config'){const count=await db.countParticipants();config.current_participants=count;config.registration_available=config.ctf_registration_open==='true'&&(config.ctf_max_participants==='-1'||count<Number(config.ctf_max_participants));body={config};}
   if(kind==='adminStages')body={stages:await db.getAllStages()};
   if(kind==='adminAttempts')body={attempts:await adminQueries.attempts(c,filters,limit)};
   if(kind==='adminParticipants')body={participants:await adminQueries.participants(c)};
   if(kind==='stages')body={stages:await db.listStudentStages()};
   if(kind==='analytics')body={analytics:{participants:await db.participantAnalytics(),stages:await db.stageAnalytics(),topTechniques:await db.techniqueAnalytics(),blockRates:await db.blockAnalytics(),recent_activity:await db.recentActivity()}};
   if(kind==='status'){const participant=await db.findActiveParticipant(before.actor.id);body=participant?{registered:true,participant,progress:await db.listProgress(participant.id),leaderboardEntry:await db.getLeaderboardEntry(participant.id)}:{registered:false};}
   if(kind==='leaderboard'){
    // Preserve existing policy: authenticated non-admin-role users need the
    // student switch; public switch controls name masking, not endpoint access.
    if(before.actor&&!admin&&config.student_leaderboard_visible!=='true')fail('LEADERBOARD_HIDDEN',403);
    const leaderboard=await db.getLeaderboard(limit);if(!admin&&config.public_leaderboard_visible!=='true')for(const row of leaderboard)row.username=row.username.substring(0,3)+'***';body={leaderboard};
   }
   if(kind==='events')body={events:await db.listEvents(limit)};
   const participantIds=[...new Set(kind==='status'?(body.registered?[String(body.participant.id)]:[]):(body.leaderboard||[]).map(x=>x.participant_id).filter(x=>x!==null&&x!==undefined).map(String))];
   const members=participantIds.length?(await c.query('SELECT id::text AS "participantId",user_id::text AS "ownerId" FROM ctf.ctf_participants WHERE id=ANY($1::bigint[]) AND is_active=1',[participantIds])).rows:[];
   if(members.length!==participantIds.length)fail();
   if(kind==='adminParticipants')members.push(...body.participants.filter(p=>p.is_active===1).map(p=>({participantId:String(p.id),ownerId:String(p.user_id)})));
   if(['config','analytics'].includes(kind)){
    // Config/analytics expose active participant counts; validate precisely
    // that population. Stage completion counts and public events are historical
    // aggregates, not assertions of current participant membership.
    // Keyset pages cover current members only, never all historical owners.
    // This bounded request budget is not a registration/lifetime owner cap.
    let after='0',finished=false;
    for(let page=0;page<64;page++){
     const rows=(await c.query('SELECT id::text AS "participantId",user_id::text AS "ownerId" FROM ctf.ctf_participants WHERE is_active=1 AND id>$1 ORDER BY id LIMIT 256',[after])).rows;
     members.push(...rows);if(rows.length<256){finished=true;break;}after=rows.at(-1).participantId;
    }
    if(!finished)fail();
   }
   let stages=[...new Set((body.progress||body.events||body.stages||body.attempts||[]).map(x=>['stages','adminStages'].includes(kind)?x.id:x.stage_id).filter(x=>x!==null&&x!==undefined).map(String))];
   if(kind==='analytics')stages=(await c.query('SELECT id::text FROM ctf.ctf_stages WHERE is_active=1 ORDER BY id LIMIT 1001')).rows.map(x=>x.id);
   if(stages.length>1000)fail();
   return{body,members,stages};
  },{signal});
  const {body,members,stages}=selected;
  if(Buffer.byteLength(JSON.stringify(body))>8*1024*1024)fail();
  const after=await checkpoint(session,signal,members,stages);if(JSON.stringify({actor:before.actor,global:before.global})!==JSON.stringify({actor:after.actor,global:after.global}))fail();
  if(signal?.aborted||await ready(signal)!==true)fail();return snapshot?{body,stageRevisions:after.stageRevisions,checkpoint:JSON.stringify({actor:before.actor,globalRevision:before.global.revision})}:body;
 }
 return Object.freeze({read:(input,options)=>readInternal(input,options),readAdminSnapshot:(session,options)=>readInternal({kind:'adminStages',session},options,true)});
}
module.exports={createCtfCurrentReadRepository};
