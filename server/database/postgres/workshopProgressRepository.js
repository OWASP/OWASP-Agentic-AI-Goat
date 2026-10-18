'use strict';
const {randomUUID}=require('node:crypto');
const {withTransaction}=require('./index');
const {error,userId,exercise,bump,ownerTransaction,consistentRead}=require('./workshopPlatformSupport');
const {readConfig}=require('./workshopConfigRepository');
const {timestamp}=require('./identityValidation');
const {WORKSHOP_OBJECTIVES,isWorkshopSurfaceEligible}=require('../../config/workshopCatalog');
const secureShopCurriculum=require('../../config/secureshopCurriculum');
const {liveWorkshopTimeCondition}=require('./workshopProgressTimePredicate');
const SECURESHOP_WORKSHOP_KEY=secureShopCurriculum.WORKSHOP_KEY;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
async function rowsForUsers(client,ids,instanceProgressReady=false){
 const timePredicate=instanceProgressReady?`AND ${liveWorkshopTimeCondition('t')}`:'';
 return (await client.query(`SELECT u.user_id,w.workshop_key,w.challenge_key,w.challenge_name,w.challenge_description,w.category,w.difficulty,w.route,w.is_visible,
  COUNT(o.objective_id)::integer AS total,COUNT(c.objective_id)::integer AS done,MAX(c.completed_at) AS completed_at,
  COALESCE((SELECT SUM(t.duration_seconds)::integer FROM workshop_platform.time_tracking t WHERE t.user_id=u.user_id AND t.workshop_key=w.workshop_key ${timePredicate}),0) AS seconds,
  COALESCE(jsonb_agg(jsonb_build_object('id',o.objective_id,'label',o.label,'description',o.description,'completed',c.objective_id IS NOT NULL,'completedAt',c.completed_at) ORDER BY o.ordinal) FILTER(WHERE o.objective_id IS NOT NULL),'[]'::jsonb) AS objectives
  FROM unnest($1::integer[]) AS u(user_id) CROSS JOIN workshop_platform.exercises w
  LEFT JOIN workshop_platform.objectives o ON o.workshop_key=w.workshop_key AND o.catalog_active=true AND o.is_enabled=true
  LEFT JOIN workshop_platform.completions c ON c.workshop_key=o.workshop_key AND c.objective_id=o.objective_id AND c.user_id=u.user_id
  WHERE w.catalog_active=true GROUP BY u.user_id,w.workshop_key ORDER BY w.ordinal`,[ids])).rows;
}
function project(row,snapshot,visible){
 const status=row.done===0?'not_started':row.total>0&&row.done===row.total?'completed':'in_progress';
 const base={workshopKey:row.workshop_key,challengeKey:row.challenge_key,objectives:row.objectives,objectiveCount:row.total,completedObjectiveCount:row.done,timeSpentSeconds:row.seconds,status,completed:status==='completed',completedAt:status==='completed'?row.completed_at:null};
 if(row.workshop_key===SECURESHOP_WORKSHOP_KEY)base.exerciseGroups=secureShopCurriculum.projectExerciseGroups(row.objectives);
 if(!visible)return base;
 const config=snapshot.exercises[row.workshop_key];
 const projected={...base,canonicalStatus:status,status:row.total===0?'locked':status==='not_started'?'unlocked':status,id:row.challenge_key,name:row.challenge_name,title:row.challenge_name,description:row.challenge_description,difficulty:row.difficulty,category:row.category,route:row.route,completed_at:base.completedAt,completedObjectives:row.done,totalObjectives:row.total,enabled:row.is_visible,showHints:config.showHints,showSolutions:config.showSolutions,configRevision:snapshot.revision,objectives:row.objectives.map(o=>({...o,text:o.label,hintVisible:config.objectives[o.id]?.hintVisible===true,solutionVisible:config.objectives[o.id]?.solutionVisible===true}))};
 if(row.workshop_key===SECURESHOP_WORKSHOP_KEY)projected.exerciseGroups=secureShopCurriculum.projectExerciseGroups(projected.objectives);
 return projected;
}
function createWorkshopProgressRepository(pool){
 let readiness;
 async function hasInstanceProgressSchema(client=pool){
  if(readiness!==undefined)return readiness;
  const row=(await client.query(`SELECT to_regclass('workshop_platform.instance_activity_contributions') IS NOT NULL AS activity,
    to_regclass('identity.secureshop_progress_cleanup_history') IS NOT NULL AS history,
    EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='workshop_platform.time_tracking'::regclass
      AND attname='platform_launch_id' AND NOT attisdropped) AS time_scope`)).rows[0];
  readiness=!!(row?.activity&&row?.history&&row?.time_scope);return readiness;
 }
 function launchScope(value,uid){
  if(!value||typeof value!=='object'||Array.isArray(value)||!UUID.test(value.launchId||'')
    ||!UUID.test(value.scenarioId||'')||!Number.isSafeInteger(value.generation)||value.generation<1
    ||value.platformOwnerId!==uid||!Number.isInteger(value.platformSessionId)||value.platformSessionId<1)
    throw error('INSTANCE_SCOPE_REQUIRED','Trusted SecureShop launch scope is required');
  return {launchId:value.launchId.toLowerCase(),scenarioId:value.scenarioId.toLowerCase(),generation:value.generation,
   platformOwnerId:uid,platformSessionId:value.platformSessionId};
 }
 async function instanceOwnerTransaction(id,workshopKey,expectedGeneration,instanceScope,work){
  const uid=userId(id);if(workshopKey!==SECURESHOP_WORKSHOP_KEY)throw error('BAD_REQUEST','Instance progress is reserved for SecureShop');
  const binding=launchScope(instanceScope,uid);
  return withTransaction(pool,async client=>{
   if(!await hasInstanceProgressSchema(client))throw error('GRADE_STORE_NOT_READY','SecureShop instance progress storage is unavailable');
   const owner=await client.query(`SELECT id FROM identity.users WHERE id=$1 AND is_active=1
     AND (account_locked_until IS NULL OR account_locked_until<=clock_timestamp()) FOR SHARE`,[uid]);
   if(owner.rowCount!==1)throw error('STALE_GENERATION','SecureShop owner is no longer active');
   const session=await client.query(`SELECT id FROM identity.user_sessions WHERE id=$1 AND user_id=$2
     AND is_active=1 AND expires_at>clock_timestamp() FOR SHARE`,[binding.platformSessionId,uid]);
   if(session.rowCount!==1)throw error('STALE_GENERATION','SecureShop session is no longer active');
   const launch=(await client.query(`SELECT launch_id FROM identity.secureshop_launches
     WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3 AND original_platform_owner_id=$4
       AND platform_session_id=$5 AND status='active' AND expires_at>clock_timestamp() FOR SHARE`,
    [binding.launchId,binding.scenarioId,binding.generation,uid,binding.platformSessionId])).rows[0];
   if(!launch)throw error('STALE_GENERATION','SecureShop launch is no longer current');
   const w=await exercise(client,workshopKey);
   await client.query('INSERT INTO workshop_platform.user_state(user_id,workshop_key) VALUES($1,$2) ON CONFLICT DO NOTHING',[uid,w.workshop_key]);
   const state=(await client.query('SELECT * FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key=$2 FOR UPDATE',[uid,w.workshop_key])).rows[0];
   if(expectedGeneration!==undefined&&expectedGeneration!==state.generation)throw error('STALE_GENERATION','Workshop was reset while work was running');
   return work(client,w,state,uid,binding);
  });
 }
 async function getMany(ids,visible=false,instructor=false,workshopSurfaceOnly=true){
  const original=[...new Set(ids.filter(id=>id!==null&&id!==undefined))];if(!original.length)return new Map();
  const normalized=original.map(userId);
  return consistentRead(pool,async client=>{
   const rows=await rowsForUsers(client,[...new Set(normalized)],await hasInstanceProgressSchema(client)),snapshot=(visible||instructor)?await readConfig(client):null;
   return new Map(original.map(id=>[id,rows.filter(row=>row.user_id===userId(id)&&(!visible||row.is_visible)&&(!workshopSurfaceOnly||isWorkshopSurfaceEligible(row.workshop_key))).map(row=>instructor?{...project(row,snapshot,true),...project(row,snapshot,false)}:project(row,snapshot,visible))]));
  });
 }
 const api={
  getInstructorProgress:async id=>(await getMany([id],false,true)).get(id)||[],
  getUsersProgress:ids=>getMany(ids),getVisibleUsersProgress:ids=>getMany(ids,true),
  getUserProgress:async id=>(await getMany([id])).get(id)||[],getVisibleUserProgress:async id=>(await getMany([id],true)).get(id)||[],
  async getWorkshopProgress(id,key){const w=await exercise(pool,key);return (await getMany([id],false,false,false)).get(id)?.find(row=>row.workshopKey===w.workshop_key)||null;},
  async getVisibleWorkshopProgress(id,key){const w=await exercise(pool,key);return (await getMany([id],true,false,false)).get(id)?.find(row=>row.workshopKey===w.workshop_key)||null;},
  async getEvaluationScope(id,key){
   return ownerTransaction(pool,id,key,undefined,async(client,w,state,uid)=>{
    const row=(await client.query('SELECT mode,updated_at::text AS stamp FROM workshop_platform.user_modes WHERE user_id=$1 AND workshop_key=$2',[uid,w.workshop_key])).rows[0];
    const mode=row?.mode ?? require('../../services/workshopModeService').WORKSHOP_MODE_CATALOG[w.workshop_key]?.defaultMode ?? null;
    return {generation:state.generation,mode:mode==='vulnerable'?'vuln':mode,modeStamp:row?.stamp || 'default'};
   });
  },
  async getObjectiveCompletionState(id,key,objectiveId,{expectedGeneration}={}){
   if(!Number.isSafeInteger(expectedGeneration)||expectedGeneration<0)throw error('BAD_REQUEST','Expected generation is invalid');
   if(typeof objectiveId!=='string'||!objectiveId.length||Buffer.byteLength(objectiveId)>100)throw error('BAD_REQUEST','Objective ID is invalid');
   return ownerTransaction(pool,id,key,expectedGeneration,async(client,w,state,uid)=>{
    const canonical=WORKSHOP_OBJECTIVES[w.workshop_key];
    if(!canonical||!canonical.some(objective=>objective.id===objectiveId))throw error('NOT_FOUND','Unknown objective');
    const completed=(await client.query(`SELECT 1 FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3`,[uid,w.workshop_key,objectiveId])).rowCount>0;
    return {completed,generation:state.generation};
   });
  },
  async getCanonicalWorkshopCompletions(id,key,{expectedGeneration}={}){
   if(!Number.isSafeInteger(expectedGeneration)||expectedGeneration<0)throw error('BAD_REQUEST','Expected generation is invalid');
   return ownerTransaction(pool,id,key,expectedGeneration,async(client,w,state,uid)=>{
    const rows=(await client.query(`SELECT objective_id FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id`,[uid,w.workshop_key])).rows;
    return {objectiveIds:rows.map(row=>row.objective_id),generation:state.generation};
   });
  },
  async getGeneration(id,key){const w=await exercise(pool,key);return (await pool.query('SELECT generation FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key=$2',[userId(id),w.workshop_key])).rows[0]?.generation||0;},
  syncWorkshopStarted:(id,key)=>ownerTransaction(pool,id,key,undefined,async(client,w,state,uid)=>{
   if(w.workshop_key===SECURESHOP_WORKSHOP_KEY)throw error('INSTANCE_SCOPE_REQUIRED','SecureShop progress requires launch-scoped evidence');
   const result=await client.query('UPDATE workshop_platform.user_state SET started_at=now(),updated_at=now() WHERE user_id=$1 AND workshop_key=$2 AND started_at IS NULL',[uid,w.workshop_key]);
   if(result.rowCount)await bump(client,{scopeType:'user',scopeKey:String(uid),category:'workshop_progress'});
  }),
  syncObjectiveComplete(id,key,objectiveId,_label='',_category='',{expectedGeneration}={}){
   return ownerTransaction(pool,id,key,expectedGeneration,async(client,w,state,uid)=>{
    if(w.workshop_key===SECURESHOP_WORKSHOP_KEY)throw error('INSTANCE_SCOPE_REQUIRED','SecureShop progress requires launch-scoped evidence');
    const objective=(await client.query('SELECT is_enabled FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2 AND catalog_active=true',[w.workshop_key,objectiveId])).rows[0];
    if(!objective)throw error('NOT_FOUND','Unknown objective');if(!objective.is_enabled)throw error('OBJECTIVE_DISABLED','Objective is disabled');
    const result=await client.query('INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING completed_at',[uid,w.workshop_key,objectiveId]);
    await client.query('UPDATE workshop_platform.user_state SET started_at=COALESCE(started_at,now()),updated_at=now() WHERE user_id=$1 AND workshop_key=$2',[uid,w.workshop_key]);
    if(result.rowCount)await bump(client,{scopeType:'user',scopeKey:String(uid),category:'workshop_progress'});
    return {changed:result.rowCount>0,generation:state.generation};
   });
  },
  // Caller-provided totals are intentionally ignored: enabled objective rows are authoritative.
  async checkAndMarkWorkshopComplete(id,key,_legacyTotal){return (await api.getWorkshopProgress(id,key))?.completed||false;},
  resetWorkshopProgress(id,key,{objectiveIds,expectedGeneration}={}){
   if(objectiveIds!==undefined&&(!Array.isArray(objectiveIds)||!objectiveIds.length||objectiveIds.some(id=>typeof id!=='string'||!id)))throw error('BAD_REQUEST','Nonempty objective IDs required');
   return ownerTransaction(pool,id,key,expectedGeneration,async(client,w,state,uid)=>{
    if(w.workshop_key===SECURESHOP_WORKSHOP_KEY)throw error('INSTANCE_SCOPE_REQUIRED','SecureShop progress reset requires launch retirement');
    if(objectiveIds){const valid=await client.query('SELECT objective_id FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=ANY($2::text[]) AND catalog_active=true',[w.workshop_key,[...new Set(objectiveIds)]]);if(valid.rowCount!==new Set(objectiveIds).size)throw error('NOT_FOUND','Unknown reset objective');}
    await client.query('DELETE FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2'+(objectiveIds?' AND objective_id=ANY($3::text[])':''),[uid,w.workshop_key,...(objectiveIds?[objectiveIds]:[])]);
    await client.query('DELETE FROM workshop_platform.activity_counters WHERE user_id=$1 AND workshop_key=$2'+(objectiveIds?' AND activity_key=ANY($3::text[])':''),[uid,w.workshop_key,...(objectiveIds?[objectiveIds]:[])]);
    if(!objectiveIds)await client.query('DELETE FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2',[uid,w.workshop_key]);
    const result=(await client.query('UPDATE workshop_platform.user_state SET generation=generation+1,started_at=NULL,updated_at=now() WHERE user_id=$1 AND workshop_key=$2 RETURNING generation',[uid,w.workshop_key])).rows[0];
    await bump(client,{scopeType:'user',scopeKey:String(uid),category:'workshop_progress'});
    if(!objectiveIds)await bump(client,{scopeType:'user',scopeKey:String(uid),category:'workshop_time'});
    return result;
   });
  },
  async getUserWorkshopProgress(id){return (await pool.query('SELECT c.workshop_key,c.objective_id,o.label AS objective_label,o.category AS objective_category,1 AS completed,c.completed_at FROM workshop_platform.completions c JOIN workshop_platform.objectives o USING(workshop_key,objective_id) WHERE c.user_id=$1 AND o.is_enabled=true AND o.catalog_active=true ORDER BY c.workshop_key,c.objective_id',[userId(id)])).rows;},
  recordHeartbeat({userId:id,workshopKey,now,expectedGeneration,instanceScope}){
   if(workshopKey===SECURESHOP_WORKSHOP_KEY){
    return instanceOwnerTransaction(id,workshopKey,expectedGeneration,instanceScope,async(client,w,state,uid,binding)=>{
     const recorded=(await client.query(`SELECT * FROM workshop_platform.record_secureshop_heartbeat(
       $1,$2,$3,$4,$5)`,[uid,binding.launchId,binding.scenarioId,
       binding.generation,state.generation])).rows[0];
     const result={added:Number(recorded.added),newSession:recorded.new_session===true};
     if(result.added>0||result.newSession)await bump(client,{scopeType:'user',scopeKey:String(uid),category:'workshop_time'});
     return result;
    });
   }
   return ownerTransaction(pool,id,workshopKey,expectedGeneration,async(client,w,state,uid)=>{
    let nowIso;
    if(now===undefined)nowIso=(await client.query('SELECT clock_timestamp() AS now')).rows[0].now.toISOString();
    else nowIso=typeof now==='number'?timestamp(new Date(now<1e12?now*1000:now),false):timestamp(now,false);
    const row=(await client.query('SELECT * FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2 ORDER BY id DESC LIMIT 1',[uid,w.workshop_key])).rows[0];
    const elapsed=row?Math.round((Date.parse(nowIso)-row.last_heartbeat.getTime())/1000):120;
    if(elapsed<=0)return {added:0,newSession:false};
    if(row&&elapsed<120)await client.query('UPDATE workshop_platform.time_tracking SET last_heartbeat=$1,duration_seconds=duration_seconds+$2 WHERE id=$3',[nowIso,elapsed,row.id]);
    else await client.query('INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat) VALUES($1,$2,$3,$3)',[uid,w.workshop_key,nowIso]);
    await bump(client,{scopeType:'user',scopeKey:String(uid),category:'workshop_time'});
    return {added:row&&elapsed<120?elapsed:0,newSession:!row||elapsed>=120};
   });
  },
  recordSecureShopActivity({userId:id,workshopKey=SECURESHOP_WORKSHOP_KEY,activityKey,
    activityDelta=1,contributionId=randomUUID(),expectedGeneration,instanceScope}={}){
   if(typeof activityKey!=='string'||!/^[a-z][a-z0-9_-]{0,99}$/.test(activityKey)
      ||!Number.isSafeInteger(activityDelta)||activityDelta<1||activityDelta>1000000
      ||typeof contributionId!=='string'||!UUID.test(contributionId))throw error('BAD_REQUEST','Invalid activity contribution');
   return instanceOwnerTransaction(id,workshopKey,expectedGeneration,instanceScope,async(client,w,state,uid,binding)=>{
    let recorded;
    try{recorded=(await client.query(`SELECT * FROM workshop_platform.record_secureshop_activity_contribution(
      $1,$2,$3,$4,$5,$6,$7,$8)`,[uid,contributionId.toLowerCase(),activityKey,activityDelta,
      binding.launchId,binding.scenarioId,binding.generation,state.generation])).rows[0];}
    catch(cause){if(/idempotency scope changed/i.test(cause?.message||''))throw error('IDEMPOTENCY_CONFLICT','Activity contribution scope changed');throw cause;}
    await bump(client,{scopeType:'user',scopeKey:String(uid),category:'workshop_progress'});
    return {changed:recorded.changed===true,activityCount:Number(recorded.activity_count),generation:state.generation,
      contributionId:contributionId.toLowerCase()};
   });
  },
 };
 return api;
}
module.exports={createWorkshopProgressRepository};
