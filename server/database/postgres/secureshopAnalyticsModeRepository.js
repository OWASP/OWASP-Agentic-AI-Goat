'use strict';
const {createHash}=require('node:crypto');
const {ownerTransaction}=require('./workshopPlatformSupport');
const WORKSHOP='secureshop_agent_security';
function snapshot(state,row,revision){
 if(!state||!Number.isSafeInteger(state.generation)||!/^(0|[1-9][0-9]{0,18})$/.test(revision)||BigInt(revision)>9223372036854775807n)throw Error('Canonical mode revision unavailable');
 const mode=row?.mode??require('../../services/workshopModeService').WORKSHOP_MODE_CATALOG[WORKSHOP].defaultMode;
 return Object.freeze({generation:state.generation,mode:mode==='vulnerable'?'vuln':mode,modeStamp:createHash('sha256').update(JSON.stringify(['analytics-mode-v1',revision,row?.stamp||'default'])).digest('hex')});
}
function createAnalyticsModeRepository(pool){
 if(typeof pool?.connect!=='function')throw TypeError('Canonical identity pool required');
 return Object.freeze({async getEvaluationScopeAtEffect(userId,key){
  if(key!==WORKSHOP)throw TypeError('Analytics mode scope required');
  // One statement gives a consistent snapshot without reacquiring the identity
  // owner lock from inside a held agents-store effect transaction.
  const row=(await pool.query(`SELECT s.generation,m.mode,m.updated_at::text AS stamp,COALESCE(r.revision,0)::text AS revision
   FROM workshop_platform.user_state s JOIN workshop_platform.exercises e ON e.workshop_key=s.workshop_key AND e.catalog_active=true
   LEFT JOIN workshop_platform.user_modes m ON m.user_id=s.user_id AND m.workshop_key=s.workshop_key
   LEFT JOIN workshop_platform.revisions r ON r.scope_type='user' AND r.scope_key=s.user_id::text AND r.category='workshop_mode'
   WHERE s.user_id=$1 AND s.workshop_key=$2`,[userId,WORKSHOP])).rows[0];
  return snapshot(row,row,row?.revision);
 },async getEvaluationScope(userId,key){if(key!==WORKSHOP)throw TypeError('Analytics mode scope required');
  return ownerTransaction(pool,userId,WORKSHOP,undefined,async(client,_workshop,state,uid)=>{
   const row=(await client.query("SELECT mode,updated_at::text AS stamp FROM workshop_platform.user_modes WHERE user_id=$1 AND workshop_key=$2",[uid,WORKSHOP])).rows[0];
   const revision=(await client.query("SELECT revision::text AS revision FROM workshop_platform.revisions WHERE scope_type='user' AND scope_key=$1 AND category='workshop_mode'",[String(uid)])).rows[0]?.revision||'0';
   return snapshot(state,row,revision);
  });
 }});
}
module.exports={createAnalyticsModeRepository};
