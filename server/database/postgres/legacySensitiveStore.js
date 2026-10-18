'use strict';
const {withTransaction}=require('./index');
function owner(id){if(!Number.isSafeInteger(Number(id))||Number(id)<=0)throw new TypeError('Authenticated owner required');return Number(id);}
function createLegacySensitiveStore(pool){return {
 engine:'postgres',
 async getGeneration(userId){return(await pool.query('SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1',[owner(userId)])).rows[0]?.generation??0;},
 async recordJudgment({userId,objectiveId,runId,flagFound,exploitUsed,completed,judgment,generation}){
  const metadata=Object.fromEntries(['verdict','judgeVersion','rubricVersion','evidenceDigest','provider','model','evidenceSummary'].filter(k=>judgment[k]!==undefined).map(k=>[k,judgment[k]]));
  await withTransaction(pool,async client=>{
   const uid=owner(userId);await client.query('INSERT INTO legacy_sensitive.owner_state(user_id) VALUES($1) ON CONFLICT DO NOTHING',[uid]);
   const current=(await client.query('SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1 FOR UPDATE',[uid])).rows[0].generation;
   if(generation!==current)throw Object.assign(new Error('Legacy evidence invalidated by reset'),{code:'STALE_GENERATION'});
   await client.query('INSERT INTO legacy_sensitive.judgments(user_id,generation,challenge_type,flag_found,exploit_used,success,run_id,judgment) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(user_id,run_id,challenge_type) DO NOTHING',[uid,current,objectiveId,flagFound,exploitUsed,completed?1:0,runId,metadata]);
  });
 },
 logFileAccess:(userId,filePath,accessType,status,ipAddress,userAgent)=>pool.query('INSERT INTO legacy_sensitive.access_logs(user_id,file_path,access_type,status,ip_address,user_agent) VALUES($1,$2,$3,$4,$5,$6)',[owner(userId),filePath,accessType,status,ipAddress,userAgent]),
 async getPublicDocuments(){return(await pool.query("SELECT id,filename,category,description FROM legacy_sensitive.documents WHERE category='public' ORDER BY id")).rows;},
 async getAccessLogs(userId,limit=50){if(!Number.isInteger(limit)||limit<1||limit>100)throw new TypeError('Invalid limit');return(await pool.query('SELECT * FROM legacy_sensitive.access_logs WHERE user_id=$1 ORDER BY timestamp DESC,id DESC LIMIT $2',[owner(userId),limit])).rows;},
 async getChallengeStats(userId){return(await pool.query("SELECT challenge_type,count(*)::int AS attempts,sum(success)::int AS successful_attempts,string_agg(DISTINCT flag_found,',') AS flags_found FROM legacy_sensitive.judgments j JOIN legacy_sensitive.owner_state s USING(user_id,generation) WHERE user_id=$1 GROUP BY challenge_type",[owner(userId)])).rows;},
 async reset(userId){await withTransaction(pool,async client=>{const uid=owner(userId);await client.query('INSERT INTO legacy_sensitive.owner_state(user_id,generation) VALUES($1,1) ON CONFLICT(user_id) DO UPDATE SET generation=legacy_sensitive.owner_state.generation+1',[uid]);await client.query('DELETE FROM legacy_sensitive.access_logs WHERE user_id=$1',[uid]);});}
};}
module.exports={createLegacySensitiveStore};
