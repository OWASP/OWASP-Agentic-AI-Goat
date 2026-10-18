'use strict';
const {createPool,withTransaction}=require('./index');
const {initialize,singleton}=require('./workshopSupport');
const {configs,stages}=require('../../data/ctfDefaults');
const {stageDigest}=require('../../agent-runtime/ctfStageJudge');
const {MANAGED_FIELDS,reconcileStageField,markStageFieldsCustom}=require('./ctfStageDefaultProvenance');
const lock=client=>client.query('SELECT pg_advisory_xact_lock(1886610804, 44)');
const normalize=row=>row&&Object.fromEntries(Object.entries(row).map(([key,value])=>[key,value instanceof Date?value.toISOString():typeof value==='string'&&['count','total','completed','completion_count','attempts','completions','avg_completion_time','avg_attempts','blocked_count','total_attempts'].includes(key)?Number(value):value]));
async function seed(client){
 for(const row of configs)await client.query('INSERT INTO ctf.ctf_config(key,value,description) VALUES($1,$2,$3) ON CONFLICT(key) DO NOTHING',[row.key,row.value,row.description]);
 for(const row of stages){
  const keys=Object.keys(row),inserted=(await client.query(`INSERT INTO ctf.ctf_stages(${keys.join(',')}) VALUES(${keys.map((_,i)=>'$'+(i+1)).join(',')}) ON CONFLICT(stage_number) DO NOTHING RETURNING stage_number`,Object.values(row))).rowCount===1;
  const current=inserted?row:(await client.query(`SELECT ${MANAGED_FIELDS.join(',')} FROM ctf.ctf_stages WHERE stage_number=$1 FOR UPDATE`,[row.stage_number])).rows[0];
  for(const fieldName of MANAGED_FIELDS)await reconcileStageField(client,{stageNumber:row.stage_number,fieldName,currentValue:current[fieldName],sourceValue:row[fieldName],inserted});
 }
}
// Supported startup seed policy. Raw seed remains available to explicit owned
// fixtures/operator maintenance; this guard never establishes paired readiness.
async function seedForInitialization(client){
 await lock(client);
 const bootstrap=(await client.query('SELECT * FROM ctf.bootstrap_control WHERE singleton FOR UPDATE')).rows[0];
 const control=(await client.query('SELECT activation_id FROM ctf.delivery_control WHERE singleton')).rows[0];
 const cursor=(await client.query('SELECT initialized,applied_sequence::text,last_operation_id FROM ctf.projection_cursor WHERE singleton')).rows[0];
 const deny=()=>{throw Object.assign(Error('CTF initialization requires explicit authority maintenance'),{code:'CTF_SEED_MAINTENANCE_REQUIRED'});};
 if(!bootstrap||!control||!cursor)deny();
 if(control.activation_id!==null){
  const active=(await client.query('SELECT * FROM ctf.delivery_activations WHERE activation_id=$1',[control.activation_id])).rows[0];
  if(!active||bootstrap.state!=='prepared'||active.protocol_version!==1||cursor.initialized!==true
   ||active.ctf_store_id!==bootstrap.store_id||active.identity_store_id!==bootstrap.identity_store_id
   ||active.bootstrap_operation_id!==bootstrap.operation_id||String(active.source_revision)!==String(bootstrap.revision)
   ||active.manifest_sha256!==bootstrap.manifest_sha256||! /^[a-f0-9]{64}$/.test(active.manifest_sha256)||! /^[a-f0-9]{64}$/.test(active.authority_sha256))deny();
  return Object.freeze({seeded:false,reason:'active_authority'});
 }
 const history=(await client.query('SELECT EXISTS(SELECT 1 FROM ctf.delivery_activations) OR EXISTS(SELECT 1 FROM ctf.projection_scopes) OR EXISTS(SELECT 1 FROM ctf.projection_receipts) AS present')).rows[0];
 if(bootstrap.state!=='open'||bootstrap.operation_id!==null||bootstrap.identity_store_id!==null||bootstrap.manifest_sha256!==null
  ||cursor.initialized!==false||cursor.applied_sequence!=='0'||cursor.last_operation_id!==null||history?.present!==false)deny();
 // Revision can be nonzero from earlier pre-bootstrap default seeds. No imported
 // authority or delivery history exists; ordinary reseed preserves custom fields.
 await seed(client);return Object.freeze({seeded:true,reason:'pre_bootstrap'});
}
const stageFields=['stage_number','stage_name','stage_description','difficulty_level','ai_guardian_name','ai_guardian_personality','system_prompt','success_criteria','hints','stage_order','difficulty','defense_style','adaptive_mode','level_score','time_bonus_seconds','feedback_mode','is_active','max_attempts'];
const teachingContentFields=['teaching_objective','solution_content'];
function createCtfDb(pool){
 return createCtfStore(pool,fn=>withTransaction(pool,async client=>{await lock(client);return fn(client);}));
}
// Internal composition seam: the caller already owns BEGIN/COMMIT and the CTF
// serialization lock. This adapter never opens a pool connection or transaction.
function createCtfMutationAdapter(client,{occurredAt=null}={}){
 if(occurredAt!==null&&(typeof occurredAt!=='string'||!Number.isFinite(Date.parse(occurredAt))||new Date(occurredAt).toISOString()!==occurredAt))throw new TypeError('Canonical event timestamp required');
 if(typeof client?.query!=='function'||typeof client?.release!=='function')throw new TypeError('Checked-out PostgreSQL client required');
 const store=createCtfStore(client,fn=>fn(client),occurredAt);
 const names=['updateConfig','admitParticipant','createSession','recordRegistration','startStage','recordStageStart',
  'updateParticipantActivity','incrementAttempts','logAttempt','incrementPayloadHitCount','purchaseHint','createStage','updateStage','deleteStage',
  'banUser','unbanUser','clearTechniqueBlocklist','clearPayloadBlocklist','reset','updateLeaderboard'];
 const adapter=Object.fromEntries(names.map(name=>[name,store[name]]));
 adapter.commitAttempt=async()=>{throw new Error('CTF_DECISION_DELIVERY_NOT_ENABLED');};
 adapter.destroyOwner=async()=>{throw new Error('CTF_AUTHORITY_DELETION_POLICY_REQUIRED');};
 return Object.freeze(adapter);
}
function createCtfStore(pool,mutate,eventTime=null){
 const rows=async(sql,args=[]) => (await pool.query(sql,args)).rows.map(normalize);
 const first=async(sql,args=[]) => (await rows(sql,args))[0];
 const store={engine:'postgres',initialize:migration=>initialize(pool,migration,'ctf',seedForInitialization),
  countParticipants: async (...args)=>(await first("SELECT COUNT(*)::integer as count FROM ctf.ctf_participants WHERE is_active = 1",args)).count,
  listStudentStages: async (...args)=>rows("SELECT s.id, s.stage_number, s.stage_name, s.stage_description, s.difficulty_level,\n               s.ai_guardian_name, s.ai_guardian_personality, s.stage_order, s.difficulty,\n               s.adaptive_mode, s.level_score, s.feedback_mode,\n               COALESCE(tc.objective_text, '') AS teaching_objective,\n               (SELECT COUNT(*) FROM ctf.ctf_progress WHERE stage_id = s.id AND status = 'completed') as completion_count\n        FROM ctf.ctf_stages s LEFT JOIN ctf.ctf_stage_teaching_content tc ON tc.stage_id=s.id\n        WHERE s.is_active = 1 ORDER BY s.stage_order ASC",args),
  createSession: async (...args)=>mutate(async client=>(await client.query("INSERT INTO ctf.ctf_sessions (participant_id, session_token, client_ip, user_agent) VALUES ($1, $2, $3, $4) ON CONFLICT(session_token) DO UPDATE SET participant_id=EXCLUDED.participant_id,client_ip=EXCLUDED.client_ip,user_agent=EXCLUDED.user_agent",args)).rowCount),
  recordRegistration: async (...args)=>mutate(async client=>(await client.query("INSERT INTO ctf.ctf_events (event_type, participant_id, event_data,timestamp) VALUES ('new_participant', $1, $2,COALESCE($3::timestamptz,now()))",[...args,eventTime])).rowCount),
  findActiveParticipant: async (...args)=>first("SELECT * FROM ctf.ctf_participants WHERE user_id = $1 AND is_active = 1",args),
  listProgress: async (...args)=>rows("SELECT p.*, s.stage_number, s.stage_name, s.difficulty_level, s.difficulty, s.adaptive_mode, s.level_score\n        FROM ctf.ctf_progress p JOIN ctf.ctf_stages s ON p.stage_id = s.id\n        WHERE p.participant_id = $1 ORDER BY s.stage_order ASC",args),
  getLeaderboardEntry: async (...args)=>first("SELECT * FROM ctf.ctf_leaderboard WHERE participant_id = $1",args),
  getActiveStage: async (...args)=>first("SELECT * FROM ctf.ctf_stages WHERE id = $1 AND is_active = 1",args),
  getStageByOrder: async (...args)=>first("SELECT id FROM ctf.ctf_stages WHERE stage_order = $1 AND is_active = 1",args),
  getPreviousActiveStage: async (...args)=>first("SELECT id FROM ctf.ctf_stages WHERE stage_order < $1 AND is_active = 1 ORDER BY stage_order DESC, id DESC LIMIT 1",args),
  getProgressStatus: async (...args)=>first("SELECT status FROM ctf.ctf_progress WHERE participant_id = $1 AND stage_id = $2",args),
  getProgress: async (...args)=>first("SELECT * FROM ctf.ctf_progress WHERE participant_id = $1 AND stage_id = $2",args),
  recordStageStart: async (...args)=>mutate(async client=>(await client.query("INSERT INTO ctf.ctf_events (event_type, participant_id, stage_id, event_data,timestamp) VALUES ('stage_start', $1, $2, $3,COALESCE($4::timestamptz,now()))",[...args,eventTime])).rowCount),
  getStageHints: async (...args)=>first("SELECT hints, level_score FROM ctf.ctf_stages WHERE id = $1",args),
  setHintUsage: async (...args)=>mutate(async client=>(await client.query("UPDATE ctf.ctf_progress SET hints_used = $1, hint_penalty_total = $2, updated_at = CURRENT_TIMESTAMP WHERE participant_id = $3 AND stage_id = $4",args)).rowCount),
  listEvents: async (...args)=>rows("SELECT e.*, p.username, s.stage_name, s.stage_number\n        FROM ctf.ctf_events e LEFT JOIN ctf.ctf_participants p ON e.participant_id = p.id\n        LEFT JOIN ctf.ctf_stages s ON e.stage_id = s.id\n        WHERE e.is_public = 1 ORDER BY e.timestamp DESC LIMIT $1",args),
  heartbeat: async (...args)=>mutate(async client=>(await client.query("UPDATE ctf.ctf_sessions s SET last_heartbeat = CURRENT_TIMESTAMP, total_active_time = total_active_time + 1000 FROM ctf.ctf_participants p WHERE s.session_token = $1 AND s.is_active = 1 AND p.id = s.participant_id AND p.user_id = $2",args)).rowCount),
  participantAnalytics: async (...args)=>first("SELECT COUNT(*) as total, COUNT(CASE WHEN completed_at IS NOT NULL THEN 1 END) as completed FROM ctf.ctf_participants WHERE is_active = 1",args),
  stageAnalytics: async (...args)=>rows("SELECT s.stage_name, s.stage_number, s.difficulty, s.adaptive_mode, s.level_score,\n          COUNT(p.id) as attempts, COUNT(CASE WHEN p.status = 'completed' THEN 1 END) as completions,\n          AVG(p.completion_time) as avg_completion_time, AVG(p.attempts_count) as avg_attempts\n        FROM ctf.ctf_stages s LEFT JOIN ctf.ctf_progress p ON s.id = p.stage_id\n        WHERE s.is_active = 1 GROUP BY s.id ORDER BY s.stage_order",args),
  techniqueAnalytics: async (...args)=>rows("SELECT technique_tag, COUNT(*) as count FROM ctf.ctf_attempts WHERE technique_tag IS NOT NULL GROUP BY technique_tag ORDER BY count DESC LIMIT 10",args),
  blockAnalytics: async (...args)=>rows("SELECT s.stage_name, COUNT(CASE WHEN a.blocked = 1 THEN 1 END) as blocked_count, COUNT(*) as total_attempts\n        FROM ctf.ctf_attempts a JOIN ctf.ctf_stages s ON a.stage_id = s.id GROUP BY s.id ORDER BY s.stage_order",args),
  recentActivity: async (...args)=>rows("SELECT e.*, p.username, s.stage_name FROM ctf.ctf_events e\n        LEFT JOIN ctf.ctf_participants p ON e.participant_id = p.id\n        LEFT JOIN ctf.ctf_stages s ON e.stage_id = s.id ORDER BY e.timestamp DESC LIMIT 25",args),
  findParticipant: async (...args)=>first("SELECT * FROM ctf.ctf_participants WHERE user_id = $1",args),
  getConfig:async key=>(await first('SELECT value FROM ctf.ctf_config WHERE key=$1',[key]))?.value??null,
  updateConfig:(key,value)=>mutate(async c=>(await c.query('UPDATE ctf.ctf_config SET value=$1,updated_at=now() WHERE key=$2',[value,key])).rowCount>0),
  registerParticipant:(userId,username,email,teamName=null)=>mutate(async c=>(await c.query('INSERT INTO ctf.ctf_participants(user_id,username,email,team_name) VALUES($1,$2,$3,$4) ON CONFLICT(user_id) DO UPDATE SET username=EXCLUDED.username,email=EXCLUDED.email,team_name=EXCLUDED.team_name,is_active=1,last_activity=now() RETURNING id',[userId,username,email,teamName])).rows[0].id),
  admitParticipant:(userId,username,email,teamName=null)=>mutate(async c=>{
   const settings=(await c.query(`SELECT key,value FROM ctf.ctf_config
     WHERE key IN ('ctf_registration_open','ctf_max_participants') FOR UPDATE`)).rows;
   const config=Object.fromEntries(settings.map(row=>[row.key,row.value]));
   if(config.ctf_registration_open!=='true')return{admitted:false,reason:'registration_closed'};
   const existing=(await c.query('SELECT id,is_active FROM ctf.ctf_participants WHERE user_id=$1 FOR UPDATE',[userId])).rows[0];
   if(existing?.is_active){
    const participant=(await c.query(`UPDATE ctf.ctf_participants SET username=$2,email=$3,team_name=$4,last_activity=now()
      WHERE user_id=$1 RETURNING id`,[userId,username,email,teamName])).rows[0];
    return{admitted:true,participantId:participant.id,recovered:true};
   }
   const maximum=config.ctf_max_participants;
   if(maximum!=='-1'){
    if(!/^(?:0|[1-9][0-9]*)$/.test(maximum||''))throw new Error('Invalid CTF participant capacity');
    const count=Number((await c.query('SELECT COUNT(*)::integer AS count FROM ctf.ctf_participants WHERE is_active=1')).rows[0].count);
    if(count>=Number(maximum))return{admitted:false,reason:'capacity_reached'};
   }
   const participant=(await c.query(`INSERT INTO ctf.ctf_participants(user_id,username,email,team_name,started_at)
     VALUES($1,$2,$3,$4,COALESCE($5::timestamptz,now())) ON CONFLICT(user_id) DO UPDATE SET username=EXCLUDED.username,email=EXCLUDED.email,
     team_name=EXCLUDED.team_name,is_active=1,last_activity=now() RETURNING id`,[userId,username,email,teamName,eventTime])).rows[0];
   return{admitted:true,participantId:participant.id,recovered:!!existing};
  }),
  updateParticipantActivity:id=>mutate(async c=>(await c.query('UPDATE ctf.ctf_participants SET last_activity=now() WHERE id=$1',[id])).rowCount>0),
  startStage:(participantId,stageId)=>mutate(async c=>(await c.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at) VALUES($1,$2,'in_progress',COALESCE($3::timestamptz,now())) ON CONFLICT(participant_id,stage_id) DO UPDATE SET status=CASE WHEN ctf.ctf_progress.status='not_started' THEN 'in_progress' ELSE ctf.ctf_progress.status END,started_at=CASE WHEN ctf.ctf_progress.status='not_started' THEN COALESCE($3::timestamptz,now()) ELSE ctf.ctf_progress.started_at END,updated_at=now() RETURNING id",[participantId,stageId,eventTime])).rows[0].id),
  // Completion is exclusively performed by commitAttempt after mandatory judging.
  completeStage:async()=>{throw new Error('JUDGED_ATTEMPT_REQUIRED');},
  logAttempt:(participantId,stageId,attemptNumber,payload,aiResponse,wasSuccessful,responseTime,sessionId,techniqueTag,techniqueConfidence,blocked,blockReason,payloadHash)=>mutate(async c=>{
   if(wasSuccessful)throw new Error('JUDGED_ATTEMPT_REQUIRED');
   return (await c.query('INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response,was_successful,response_time,session_id,technique_tag,technique_confidence,blocked,block_reason,payload_hash,attempt_timestamp) VALUES($1,$2,$3,$4,$5,0,$6,$7,$8,$9,$10,$11,$12,COALESCE($13::timestamptz,now())) RETURNING id',[participantId,stageId,attemptNumber,payload,aiResponse,responseTime,sessionId,techniqueTag||null,techniqueConfidence??null,blocked?1:0,blockReason||null,payloadHash||null,eventTime])).rows[0].id;
  }),
  getLeaderboard:(limit=50)=>rows('SELECT l.*,p.team_name,p.started_at AS participant_started_at,p.completed_at AS participant_completed_at FROM ctf.ctf_leaderboard l JOIN ctf.ctf_participants p ON p.id=l.participant_id WHERE p.is_active=1 ORDER BY l.rank_position,l.total_completion_time LIMIT $1',[limit]),
  updateLeaderboard:()=>mutate(updateLeaderboard),
  istechniqueBlocked:async(p,s,t)=>!!await first('SELECT id FROM ctf.ctf_technique_blocklist WHERE participant_id=$1 AND stage_id=$2 AND technique_tag=$3',[p,s,t]),
  addTechniqueBlock:(p,s,t)=>mutate(c=>c.query('INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[p,s,t])),
  getUserTechniques:(p,s)=>rows('SELECT technique_tag,first_used_at FROM ctf.ctf_technique_blocklist WHERE participant_id=$1 AND stage_id=$2',[p,s]),
  isPayloadBlocked:async(s,h)=>!!await first('SELECT id FROM ctf.ctf_payload_blocklist WHERE stage_id=$1 AND payload_hash=$2',[s,h]),
  getPayloadBlocklist:s=>rows('SELECT payload_hash,normalized_snippet FROM ctf.ctf_payload_blocklist WHERE stage_id=$1',[s]),
  addPayloadBlock:(s,h,n,p)=>mutate(c=>c.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[s,h,n,p])),
  incrementPayloadHitCount:(s,h)=>mutate(async c=>(await c.query('UPDATE ctf.ctf_payload_blocklist SET hit_count=hit_count+1 WHERE stage_id=$1 AND payload_hash=$2',[s,h])).rowCount>0),
  isBanned:async u=>!!await first('SELECT id FROM ctf.ctf_bans WHERE user_id=$1',[u]),
  banUser:(u,r,b)=>mutate(c=>c.query('INSERT INTO ctf.ctf_bans(user_id,reason,banned_by) VALUES($1,$2,$3) ON CONFLICT(user_id) DO NOTHING',[u,r,b])),
  unbanUser:u=>mutate(async c=>(await c.query('DELETE FROM ctf.ctf_bans WHERE user_id=$1',[u])).rowCount>0),
  getStage:id=>first('SELECT * FROM ctf.ctf_stages WHERE id=$1',[id]),
  getAllStages:()=>rows("SELECT s.*,COALESCE(tc.objective_text, '') AS teaching_objective,COALESCE(tc.solution_text, '') AS solution_content\n    FROM ctf.ctf_stages s LEFT JOIN ctf.ctf_stage_teaching_content tc ON tc.stage_id=s.id ORDER BY s.stage_order"),
  createStage:data=>mutate(async c=>{const keys=stageFields.filter(k=>data[k]!==undefined);return (await c.query(`INSERT INTO ctf.ctf_stages(${keys.join(',')}) VALUES(${keys.map((_,i)=>'$'+(i+1)).join(',')}) RETURNING id`,keys.map(k=>data[k]))).rows[0].id;}),
  updateStage:(id,data)=>mutate(async c=>{
   const stageKeys=stageFields.filter(k=>k!=='stage_number'&&data[k]!==undefined);
   const contentKeys=teachingContentFields.filter(k=>data[k]!==undefined);
   if(!stageKeys.length&&!contentKeys.length)return false;
   const stage=(await c.query('SELECT stage_number FROM ctf.ctf_stages WHERE id=$1 FOR UPDATE',[id])).rows[0];
   if(!stage)return false;
   if(stageKeys.length){
    await markStageFieldsCustom(c,stage.stage_number,stageKeys);
    await c.query(`UPDATE ctf.ctf_stages SET ${stageKeys.map((k,i)=>k+'=$'+(i+1)).join(',')} WHERE id=$${stageKeys.length+1}`, [...stageKeys.map(k=>data[k]),id]);
   }
   if(contentKeys.length){
    const current=(await c.query('SELECT objective_text,solution_text FROM ctf.ctf_stage_teaching_content WHERE stage_id=$1 FOR UPDATE',[id])).rows[0];
    const objective=Object.hasOwn(data,'teaching_objective')?data.teaching_objective:(current?.objective_text||'');
    const solution=Object.hasOwn(data,'solution_content')?data.solution_content:(current?.solution_text||'');
    await c.query("INSERT INTO ctf.ctf_stage_teaching_content(stage_id,objective_text,solution_text,updated_at) VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(stage_id) DO UPDATE SET objective_text=EXCLUDED.objective_text,solution_text=EXCLUDED.solution_text,updated_at=EXCLUDED.updated_at",[id,objective,solution]);
   }
   return true;
  }),
  deleteStage:id=>mutate(async c=>(await c.query('DELETE FROM ctf.ctf_stages WHERE id=$1',[id])).rowCount>0),
  getAttempts:(f={})=>{const args=[],conditions=[];for(const [key,col] of Object.entries({participantId:'participant_id',stageId:'stage_id',blocked:'blocked',techniqueTag:'technique_tag',wasSuccessful:'was_successful'})){if(f[key]!==undefined){args.push(['blocked','wasSuccessful'].includes(key)?(f[key]?1:0):f[key]);conditions.push(`a.${col}=$${args.length}`);}}let sql='SELECT a.*,p.username,s.stage_name,s.stage_number,j.verdict AS judgment_verdict,j.accepted AS judgment_accepted,j.metadata AS judgment_metadata FROM ctf.ctf_attempts a JOIN ctf.ctf_participants p ON p.id=a.participant_id JOIN ctf.ctf_stages s ON s.id=a.stage_id LEFT JOIN ctf.ctf_judgments j ON j.attempt_id=a.id';if(conditions.length)sql+=' WHERE '+conditions.join(' AND ');sql+=' ORDER BY a.attempt_timestamp DESC';if(f.limit){args.push(f.limit);sql+=` LIMIT $${args.length}`;}if(f.offset){args.push(f.offset);sql+=` OFFSET $${args.length}`;}return rows(sql,args);},
  getParticipants:()=>rows("SELECT p.*,(SELECT COUNT(*)::integer FROM ctf.ctf_progress pr WHERE pr.participant_id=p.id AND pr.status='completed') AS stages_completed,(SELECT SUM(pr.attempts_count)::integer FROM ctf.ctf_progress pr WHERE pr.participant_id=p.id) AS total_attempts FROM ctf.ctf_participants p ORDER BY p.started_at DESC"),
  listOwners:()=>rows('SELECT user_id FROM ctf.ctf_participants'),
  resetParticipant:participantId=>store.reset({participantId}),
  clearTechniqueBlocklist:stageId=>mutate(async c=>(await c.query('DELETE FROM ctf.ctf_technique_blocklist'+(stageId?' WHERE stage_id=$1':''),stageId?[stageId]:[])).rowCount),
  clearPayloadBlocklist:stageId=>mutate(async c=>(await c.query('DELETE FROM ctf.ctf_payload_blocklist'+(stageId?' WHERE stage_id=$1':''),stageId?[stageId]:[])).rowCount),
  incrementAttempts:(p,s,failed=false,progressId=null)=>mutate(async c=>{const result=await c.query('UPDATE ctf.ctf_progress SET attempts_count=attempts_count+1,failed_attempts=failed_attempts+$1,updated_at=COALESCE($5::timestamptz,now()) WHERE participant_id=$2 AND stage_id=$3 AND ($4::integer IS NULL OR id=$4) RETURNING attempts_count',[failed?1:0,p,s,progressId,eventTime]);if(!result.rowCount){const e=new Error('CTF progress changed');e.name='AbortError';throw e;}return result.rows[0].attempts_count;}),
  purchaseHint:(progressId,expectedHints,cost)=>mutate(async c=>{const result=await c.query('UPDATE ctf.ctf_progress SET hints_used=hints_used+1,hint_penalty_total=hint_penalty_total+$1,updated_at=COALESCE($4::timestamptz,now()) WHERE id=$2 AND hints_used=$3 RETURNING id',[cost,progressId,expectedHints,eventTime]);if(!result.rowCount){const e=new Error('CTF hint progress changed');e.name='AbortError';throw e;}return true;}),
  reset:options=>mutate(c=>reset(c,options)),
  destroyOwner:userId=>mutate(async c=>{
   const id=Number(userId);if(!Number.isSafeInteger(id)||id<1||id>2147483647)throw new TypeError('Valid CTF owner required');
   const participant=(await c.query('SELECT id FROM ctf.ctf_participants WHERE user_id=$1 FOR UPDATE',[id])).rows[0];
   const banned=await c.query('DELETE FROM ctf.ctf_bans WHERE user_id=$1',[id]);
   if(!participant)return{removed:banned.rowCount};
   const judgments=await c.query('DELETE FROM ctf.ctf_judgments WHERE participant_id=$1',[participant.id]);
   await reset(c,{participantId:participant.id,userId:id,remove:true});
   return{removed:banned.rowCount+judgments.rowCount+1};
  }),
  commitAttempt:input=>mutate(c=>commitAttempt(c,input)),

 };
 return store;
}
module.exports={createCtfDb,seed};

async function updateLeaderboard(c){
 // Forward-compatible canonical scoring: legacy schemas retain the original
 // query; upgraded stores preserve authorized score snapshots on every refresh.
 const canonical=(await c.query("SELECT to_regprocedure('ctf.refresh_authorized_leaderboard(timestamp with time zone)') IS NOT NULL AS available")).rows[0];
 if(canonical?.available===true){await c.query('SELECT ctf.refresh_authorized_leaderboard(clock_timestamp())');return true;}
 await c.query(`INSERT INTO ctf.ctf_leaderboard(participant_id,username,team_name,total_stages_completed,total_completion_time,average_stage_time,total_attempts,success_rate,total_score,last_updated)
 SELECT p.id,p.username,p.team_name,COALESCE(x.cnt,0),COALESCE(x.elapsed,0),COALESCE(x.average,0),COALESCE(a.attempts,0),CASE WHEN COALESCE(a.attempts,0)>0 THEN a.successes::double precision/a.attempts*100 ELSE 0 END,COALESCE(x.score,0),now()
 FROM ctf.ctf_participants p LEFT JOIN (SELECT pr.participant_id,COUNT(*) cnt,SUM(pr.completion_time) elapsed,AVG(pr.completion_time) average,SUM(GREATEST(0,s.level_score-COALESCE(pr.hint_penalty_total,0))) score FROM ctf.ctf_progress pr JOIN ctf.ctf_stages s ON s.id=pr.stage_id WHERE pr.status='completed' GROUP BY pr.participant_id) x ON x.participant_id=p.id
 LEFT JOIN (SELECT participant_id,SUM(attempts_count) attempts,SUM(successful_attempts) successes FROM ctf.ctf_progress GROUP BY participant_id) a ON a.participant_id=p.id WHERE p.is_active=1
 ON CONFLICT(participant_id) DO UPDATE SET username=EXCLUDED.username,team_name=EXCLUDED.team_name,total_stages_completed=EXCLUDED.total_stages_completed,total_completion_time=EXCLUDED.total_completion_time,average_stage_time=EXCLUDED.average_stage_time,total_attempts=EXCLUDED.total_attempts,success_rate=EXCLUDED.success_rate,total_score=EXCLUDED.total_score,last_updated=now()`);
 await c.query('WITH ranks AS (SELECT participant_id,rank() OVER(ORDER BY total_stages_completed DESC,total_score DESC,total_completion_time ASC) position FROM ctf.ctf_leaderboard) UPDATE ctf.ctf_leaderboard l SET rank_position=r.position FROM ranks r WHERE r.participant_id=l.participant_id');
 return true;
}
async function reset(c,{participantId,userId,remove=false,all=false}={}){
 if(!all&&!Number.isInteger(Number(participantId)))throw new TypeError('Participant required');
 for(const table of ['ctf_attempts','ctf_progress','ctf_technique_blocklist','ctf_leaderboard',...(all||remove?['ctf_events','ctf_sessions']:[])])await c.query(`DELETE FROM ctf.${table}${all?'':' WHERE participant_id=$1'}`,all?[]:[participantId]);
 if(all)await c.query('DELETE FROM ctf.ctf_payload_blocklist');
 if(remove)await c.query('DELETE FROM ctf.ctf_bans WHERE user_id=$1',[userId]);
 if(all||remove)await c.query(`DELETE FROM ctf.ctf_participants${all?'':' WHERE id=$1'}`,all?[]:[participantId]);
 await updateLeaderboard(c);
}
async function commitAttempt(c,input){
 const {runId,participant,stage,progress,judgment,execution}=input;
 const prior=(await c.query('SELECT * FROM ctf.ctf_judgments WHERE run_id=$1',[runId])).rows[0];
 const current=(await c.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=$1 AND stage_id=$2 FOR UPDATE',[participant.id,stage.id])).rows[0];
 const currentStage=normalize((await c.query('SELECT * FROM ctf.ctf_stages WHERE id=$1 FOR UPDATE',[stage.id])).rows[0]);
 const active=(await c.query('SELECT is_active FROM ctf.ctf_participants WHERE id=$1 AND user_id=$2 FOR UPDATE',[participant.id,participant.user_id])).rows[0];
 const stillCurrent=!!(current&&current.id===progress.id&&currentStage&&stageDigest(currentStage)===input.stageDigest&&active?.is_active);
 const valid=stillCurrent&&current.status==='in_progress';
 await execution?.check?.();
 if(prior){const sameAttempt=prior.participant_id===participant.id&&prior.stage_id===stage.id&&prior.progress_id===progress.id&&prior.stage_digest===input.stageDigest;return{accepted:stillCurrent&&sameAttempt&&!!prior.accepted,stale:!stillCurrent||!sameAttempt,replayed:true,verdict:prior.verdict};}
 const accepted=valid&&judgment.verdict==='pass'&&input.realModel===true&&input.observedSecret===true;
 let attemptId=null,categoryConsumed=false;
 if(valid){
  attemptId=(await c.query('INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response,was_successful,response_time,session_id,technique_tag,technique_confidence,blocked,payload_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11) RETURNING id',[participant.id,stage.id,input.attemptNumber,input.payload,input.studentResponse,accepted?1:0,input.responseTime,input.sessionToken,input.techniqueTag,input.techniqueConfidence,input.payloadHash])).rows[0].id;
  if(accepted){
   const elapsed=Math.max(0,Date.now()-new Date(current.started_at).getTime());
   const techniques=JSON.parse(current.techniques_used||'[]');if(!techniques.includes(input.techniqueTag))techniques.push(input.techniqueTag);
   await c.query("UPDATE ctf.ctf_progress SET status='completed',completed_at=now(),completion_time=$1,final_payload=$2,successful_attempts=successful_attempts+1,techniques_used=$3,updated_at=now() WHERE id=$4",[elapsed,input.payload,JSON.stringify(techniques),current.id]);
   if(input.techniqueTag!==input.otherTechnique)categoryConsumed=(await c.query('INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING participant_id',[participant.id,stage.id,input.techniqueTag])).rowCount===1;
   if(['payload','hybrid'].includes(input.adaptiveMode))await c.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[stage.id,input.payloadHash,input.normalizedSnippet,participant.id]);
   await c.query("INSERT INTO ctf.ctf_events(event_type,participant_id,stage_id,event_data,is_public) VALUES('stage_complete',$1,$2,$3,1)",[participant.id,stage.id,JSON.stringify({stage_name:stage.stage_name,username:participant.username,completion_time:elapsed,attempts:input.attemptNumber})]);
  }else{
   await c.query('UPDATE ctf.ctf_progress SET failed_attempts=failed_attempts+1 WHERE id=$1',[current.id]);
   if(input.realModel===true&&judgment.verdict==='fail'&&['technique','hybrid'].includes(input.adaptiveMode)&&input.techniqueTag!==input.otherTechnique)categoryConsumed=(await c.query('INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING participant_id',[participant.id,stage.id,input.techniqueTag])).rowCount===1;
  }
  await c.query('UPDATE ctf.ctf_participants SET last_activity=now() WHERE id=$1',[participant.id]);
  await updateLeaderboard(c);
 }
 const metadata={rubricVersion:judgment.rubricVersion,judgeVersion:judgment.judgeVersion,provider:judgment.provider,model:judgment.model,evidenceSummary:judgment.evidenceSummary,guardian:input.guardianEvidence||null,stale:!valid};
 await c.query('INSERT INTO ctf.ctf_judgments(run_id,attempt_id,participant_id,stage_id,progress_id,stage_digest,verdict,accepted,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[runId,attemptId,participant.id,stage.id,progress.id,input.stageDigest,judgment.verdict,accepted?1:0,JSON.stringify(metadata)]);
 await execution?.check?.();
 return{accepted,stale:!valid,replayed:false,verdict:judgment.verdict,categoryConsumed};
}
const lazy=singleton(createCtfDb,'CTF_DATABASE_URL');
async function initializeCtfDb(){const migration=createPool(process.env,'CTF_MIGRATION_DATABASE_URL');try{await lazy('initialize')(migration);}finally{await migration.end();}}
const methodNames=Object.keys(createCtfDb({})).filter(name=>!['engine','initialize'].includes(name));
module.exports={getCtfPool:lazy.getPool,createCtfDb,createCtfMutationAdapter,seed,seedForInitialization,initializeCtfDb,engine:'postgres',CTFHelpers:Object.fromEntries(methodNames.map(name=>[name,lazy(name)]))};
