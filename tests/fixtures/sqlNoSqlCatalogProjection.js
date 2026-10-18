'use strict';
// Disposable projection data only. Never creates Judge, model or effect evidence.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const FAMILIES=Object.freeze([
 Object.freeze({key:'sql_injection_workshop',prefix:'sqli_',family:'ARIA',schema:'aria',route:'/workshop/sql',api:'/api/workshop/sql',solution:'sql-injection',reset:'Reset conversation, cart, and progress'}),
 Object.freeze({key:'nosql_injection_workshop',prefix:'nosqli_',family:'NOVA',schema:'nova',route:'/workshop/nosql',api:'/api/workshop/nosql',solution:'nosql-injection',reset:'Reset conversation, reading list, and progress'}),
]);
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function assertCatalog(snapshot){
 for(const f of FAMILIES){const row=snapshot.exercises[f.key];assert.ok(row);assert.deepEqual(Object.keys(row.objectives).sort(),Array.from({length:10},(_,i)=>f.prefix+(i+1)).sort());for(const o of Object.values(row.objectives))assert.ok(typeof o.label==='string'&&o.label.length);}
 return snapshot;
}
function assertSeedPreserved(before,after){assert.deepEqual(after,before,'Instructor content and sibling flags must survive reseed');}
function assertReset(before,after,key,{nonzero=true}={}){
 assert.ok(Number.isSafeInteger(before.ownerId)&&before.ownerId>0);assert.equal(after.ownerId,before.ownerId,'Reset snapshot owner changed');assert.ok(FAMILIES.some(f=>f.key===key));
 for(const family of FAMILIES){const a=before[family.key],b=after[family.key];if(family.key!==key){assert.deepEqual(b,a,'Sibling family changed');continue;}
 if(nonzero){assert.equal(a.completions.length,10);assert.ok(a.seconds>0);assert.ok(a.history.length>0);}
 assert.equal(b.completions.length,0);assert.equal(b.seconds,0);assert.equal(b.history.length,0);assert.ok(b.generation>a.generation);assert.ok(b.graphGeneration>a.graphGeneration);assert.deepEqual(b.judgments,a.judgments);assert.deepEqual(b.effects,a.effects);
 }
}
function createSqlNoSqlCatalogProjection({identity,migration,stores,owners}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(owners.length,2);assert.notEqual(owners[0],owners[1]);
 const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(identity);
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
 const inserted=[];
 async function catalog(){return assertCatalog(await config.getSnapshot({includeRaw:true}));}
 async function snapshot(owner){
 assert.ok(owners.includes(owner),'Snapshot must belong to controlled display owner');const result={ownerId:owner};for(const f of FAMILIES){
 const args=[owner,f.key],ownerKey=JSON.stringify([f.family,String(owner)]);
 const completions=(await identity.query('SELECT objective_id,completed_at FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id',args)).rows;
 const state=(await identity.query('SELECT generation FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key=$2',args)).rows[0];
 const seconds=Number((await identity.query('SELECT COALESCE(sum(duration_seconds),0) AS n FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2',args)).rows[0].n);
 const graph=(await identity.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0];
 const effects=(await identity.query('SELECT * FROM graph_runtime.effects WHERE owner_key=$1 ORDER BY run_id,effect_key',[ownerKey])).rows;
 const judgments=(await identity.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 AND workshop_key=$2 ORDER BY evaluation_id',args)).rows;
 const history=(await stores[f.schema].query(`SELECT * FROM ${f.schema}.chat_history WHERE user_id=$1 ORDER BY id`,[String(owner)])).rows;
 result[f.key]={completions,seconds,generation:Number(state?.generation||0),graphGeneration:Number(graph?.generation||0),effects,judgments,history};}
 return result;
 }
 return {catalog,snapshot,inserted,
 async seedProjection(){const c=await catalog();for(const owner of owners)for(const f of FAMILIES){for(const id of Object.keys(c.exercises[f.key].objectives)){const r=await progress.syncObjectiveComplete(owner,f.key,id);assert.equal(r.changed,true);inserted.push({owner,workshopKey:f.key,objectiveId:id,generation:r.generation});}
 await identity.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING',[JSON.stringify([f.family,String(owner)])]);
 await stores[f.schema].query(`INSERT INTO ${f.schema}.chat_history(user_id,message_type,message) VALUES($1,'user',$2)`,[String(owner),'Controlled display history; no model invocation']);}
 return {controlledProjectionOnly:true,genuineCredit:false,inserted};},
 async reseedPreserving(){const before=await catalog();const rawBefore=(await identity.query("SELECT workshop_key,objective_id,hint_content,solution_content,hint_enabled,solution_enabled,is_enabled FROM workshop_platform.objectives WHERE workshop_key=ANY($1) ORDER BY workshop_key,objective_id",[FAMILIES.map(f=>f.key)])).rows;
 await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
 const after=await catalog();const rawAfter=(await identity.query("SELECT workshop_key,objective_id,hint_content,solution_content,hint_enabled,solution_enabled,is_enabled FROM workshop_platform.objectives WHERE workshop_key=ANY($1) ORDER BY workshop_key,objective_id",[FAMILIES.map(f=>f.key)])).rows;
 assertSeedPreserved(rawBefore,rawAfter);assert.deepEqual(after.exercises,before.exercises);return{beforeSha256:hash(rawBefore),afterSha256:hash(rawAfter),passes:2};},
 };
}
module.exports={FAMILIES,assertCatalog,assertReset,assertSeedPreserved,createSqlNoSqlCatalogProjection};
