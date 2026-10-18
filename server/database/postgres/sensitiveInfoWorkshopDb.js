'use strict';
const {createPool,withTransaction}=require('./index');
const {initialize,singleton}=require('./workshopSupport');
const {solutions}=require('../../data/sensitiveInfoSolutions');
const OBJECTIVE_IDS=Object.keys(solutions);
function owner(value){if(typeof value!=='string'||!value.length||value.length>200)throw new TypeError('FinFlow owner required');return value;}
async function seed(client){for(const [ordinal,id] of OBJECTIVE_IDS.entries())await client.query('INSERT INTO finflow.objectives(objective_id,ordinal) VALUES($1,$2) ON CONFLICT(objective_id) DO UPDATE SET ordinal=EXCLUDED.ordinal',[id,ordinal]);}
function createFinflowWorkshopDb(pool){return {
 ...Object.fromEntries(Object.entries(require('./legacySensitiveStore').createLegacySensitiveStore(pool)).filter(([key])=>key!=='engine').map(([key,value])=>['legacy_'+key,value])),
 engine:'postgres',initialize:migration=>initialize(pool,migration,'finflow',seed),
 async ensureObjectives(userId){await pool.query('INSERT INTO finflow.progress(user_id,objective_id) SELECT $1,objective_id FROM finflow.objectives ON CONFLICT DO NOTHING',[owner(userId)]);},
 async getProgress(userId){return(await pool.query('SELECT p.objective_id,p.completed,p.completed_at FROM finflow.progress p JOIN finflow.objectives o USING(objective_id) WHERE user_id=$1 ORDER BY o.ordinal',[owner(userId)])).rows;},
 async completeObjective(userId,objectiveId){if(!OBJECTIVE_IDS.includes(objectiveId))throw new TypeError('Unknown FinFlow objective');const result=await pool.query('INSERT INTO finflow.progress(user_id,objective_id,completed,completed_at) VALUES($1,$2,true,now()) ON CONFLICT(user_id,objective_id) DO UPDATE SET completed=true,completed_at=now() WHERE NOT finflow.progress.completed',[owner(userId),objectiveId]);return{changes:result.rowCount};},
 async logToolCall(userId,tool){await pool.query('INSERT INTO finflow.tool_log(user_id,tool_name,params,result_summary,security_flag,mode) VALUES($1,$2,$3,$4,$5,$6)',[owner(userId),tool.name,JSON.stringify(tool.params??{}),String(typeof tool.result==='string'?tool.result:JSON.stringify(tool.result??{})).slice(0,500),tool.securityFlag??null,tool.mode]);},
 async resetUser(userId){await withTransaction(pool,async client=>{const id=owner(userId);await client.query('DELETE FROM finflow.progress WHERE user_id=$1',[id]);await client.query('DELETE FROM finflow.tool_log WHERE user_id=$1',[id]);});}
};}
const lazy=singleton(createFinflowWorkshopDb,'FINFLOW_WORKSHOP_DATABASE_URL');
async function initializeFinflowWorkshopDb(){const migration=createPool(process.env,'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL');try{await lazy('initialize')(migration);}finally{await migration.end();}}
module.exports={getFinflowPool:lazy.getPool,engine:'postgres',createFinflowWorkshopDb,initializeFinflowWorkshopDb,OBJECTIVE_IDS,...Object.fromEntries(['ensureObjectives','getProgress','completeObjective','logToolCall','resetUser','legacy_getGeneration','legacy_recordJudgment','legacy_logFileAccess','legacy_getPublicDocuments','legacy_getAccessLogs','legacy_getChallengeStats','legacy_reset'].map(name=>[name,lazy(name)]))};
