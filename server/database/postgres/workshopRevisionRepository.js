'use strict';
const {WORKSHOP_MODE_CATALOG}=require('../../services/workshopModeService');
const {error,userId,key,exercise,bump,ownerTransaction}=require('./workshopPlatformSupport');
const ADMIN_PROGRESS_REVISION_SQL=`SELECT md5(
  COALESCE((SELECT string_agg(r.scope_key || ':' || r.category || ':' || r.revision::text, ',' ORDER BY r.scope_key,r.category)
    FROM workshop_platform.revisions r
    WHERE r.scope_type='user' AND r.category IN ('workshop_progress','workshop_time')), '')
  || '|' ||
  COALESCE((SELECT string_agg(u.id::text || ':' || u.role || ':' || u.is_active::text, ',' ORDER BY u.id)
    FROM identity.users u WHERE u.role IN ('student','user')), '')
) AS digest`;
function createWorkshopRevisionStore(pool){
 return {
  initialize:async()=>{await pool.query('SELECT 1 FROM workshop_platform.revisions LIMIT 0');},
  bump:change=>bump(pool,change),
  async getSnapshot({userId:uid,workshopKeys=[],includeAdminProgress=false}){
   const includeAll=workshopKeys.includes('*'),keys=[...new Set(workshopKeys.filter(k=>k!=='*'))];keys.forEach(key);
   const rows=(await pool.query(`SELECT scope_type,scope_key,category,revision FROM workshop_platform.revisions
    WHERE (scope_type='global' AND scope_key='*') OR (scope_type='user' AND scope_key=$1)
    OR (scope_type='workshop' AND ($2::boolean OR scope_key=ANY($3::text[])))`,[uid==null?null:String(userId(uid)),includeAll,keys])).rows;
   const snapshot={global:Object.create(null),workshops:Object.create(null),user:Object.create(null)};
   for(const row of rows){if(row.scope_type==='global')snapshot.global[row.category]=row.revision;else if(row.scope_type==='user')snapshot.user[row.category]=row.revision;else(snapshot.workshops[row.scope_key] ||= Object.create(null))[row.category]=row.revision;}
   if(includeAdminProgress)snapshot.adminProgress=(await pool.query(ADMIN_PROGRESS_REVISION_SQL)).rows[0].digest;
   return snapshot;
  },
 };
}
function createWorkshopModeRepository(pool){
 return {
  initialize:async()=>{await pool.query('SELECT 1 FROM workshop_platform.user_modes LIMIT 0');},
  async getMode({userId:uid,workshopKey,defaultMode}){
   const w=await exercise(pool,workshopKey),config=WORKSHOP_MODE_CATALOG[w.workshop_key];if(!config)throw error('BAD_REQUEST','Workshop has no mode configuration');
   return (await pool.query('SELECT mode FROM workshop_platform.user_modes WHERE user_id=$1 AND workshop_key=$2',[userId(uid),w.workshop_key])).rows[0]?.mode||defaultMode||config.defaultMode;
  },
  setMode({userId:uid,workshopKey,mode}){
   return ownerTransaction(pool,uid,workshopKey,undefined,async(client,w,state,id)=>{
    const config=WORKSHOP_MODE_CATALOG[w.workshop_key];if(!config?.allowedModes.includes(mode))throw error('BAD_REQUEST','Invalid mode for workshop');
    const current=(await client.query('SELECT mode FROM workshop_platform.user_modes WHERE user_id=$1 AND workshop_key=$2',[id,w.workshop_key])).rows[0]?.mode||config.defaultMode;
    if(current===mode)return {mode,changed:false};
    await client.query('INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,$2,$3) ON CONFLICT(user_id,workshop_key) DO UPDATE SET mode=EXCLUDED.mode,updated_at=now()',[id,w.workshop_key,mode]);
    await bump(client,{scopeType:'user',scopeKey:String(id),category:'workshop_mode'});
    return {mode,changed:true};
   });
  },
 };
}
module.exports={createWorkshopRevisionStore,createWorkshopModeRepository};
