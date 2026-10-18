'use strict';
const assert=require('node:assert/strict');
async function readReference(turn,pools){
 if(turn.family==='NOVA'){
  let literal=turn.query;const parsed=JSON.parse(turn.query);
  if(turn.objectiveId==='nosqli_3')literal=parsed.title.$regex;
  if(turn.objectiveId==='nosqli_6')literal=parsed.title.$ne;
  return require('./sqlNoSqlNativeReferences').readNovaNativeReferences({pool:pools.NOSQL_WORKSHOP.runtime,literalQuery:literal});
 }
 assert.equal(turn.family,'ARIA');const pool=pools.SQL_WORKSHOP.runtime;
 return {products:(await pool.query('SELECT id,product_id,name,category,price,description,stock,available FROM aria.products')).rows,
 orders:(await pool.query('SELECT * FROM aria.orders')).rows,
 ariaVersion:(await pool.query('SELECT version() AS value')).rows[0].value,
 ariaTables:(await pool.query("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='aria' ORDER BY tablename")).rows.map(r=>r.tablename),
 orderColumns:(await pool.query("SELECT column_name FROM information_schema.columns WHERE table_schema='aria' AND table_name='orders' ORDER BY ordinal_position")).rows.map(r=>r.column_name),
 literalBaseline:(await pool.query('SELECT id,product_id,name,category,price,description,stock,available FROM aria.products WHERE name LIKE $1',[`%${turn.query}%`])).rows};
}
function bindEffects({run,effects,body}){
 const {effectKey}=require('../../server/agent-runtime/workshopGraph');
 const observed=body.toolObservations??[];assert(Array.isArray(observed));const keys=[];for(const observation of observed){
  const key=`${run.run_id}:${effectKey(observation.index,observation.toolUsed,observation.invocation.params)}`;
  if(body.presentation)assert.equal(observation.effectKey,key);
  const matches=effects.filter(e=>e.effect_key===key);assert.equal(matches.length,1);
  const row=matches[0];assert.equal(row.run_id,run.run_id);assert.equal(row.owner_key,run.owner_key);assert.equal(String(row.generation),String(run.generation));
  assert(row.status==='completed'||(row.status==='uncertain'&&typeof observation.toolResult?.error==='string'));
  keys.push(key);
 }
 for(const row of effects){assert.equal(row.run_id,run.run_id);assert.equal(row.owner_key,run.owner_key);assert.equal(String(row.generation),String(run.generation));assert(keys.includes(row.effect_key)||['persist:user','persist:assistant'].some(k=>row.effect_key===run.run_id+':'+k&&row.status==='completed'));}
 assert.equal(new Set(keys).size,keys.length);assert.deepEqual(effects.filter(e=>e.effect_key.startsWith(run.run_id+':tool:')).map(e=>e.effect_key).sort(),[...keys].sort());return keys;
}
// Explicit UTC microsecond text bypasses pg's millisecond Date parser. The
// identical projection is used for live receipts and reset snapshots.
function graphProjection(table){
 const columns={runs:['started_at','finished_at'],effects:['updated_at'],events:['created_at']}[table];
 assert(columns,'Unknown graph evidence table');
 return 't.*, '+columns.map(column=>`to_char(t.${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ${column}`).join(', ');
}
async function immutableSnapshot(pool,userId,key,runIds){
 const result={};
 for(const table of ['objective_judgments','objective_evidence'])result[table]=(await pool.query(`SELECT to_jsonb(t) row FROM workshop_platform.${table} t WHERE user_id=$1 AND workshop_key=$2 ORDER BY to_jsonb(t)::text`,[userId,key])).rows;
 result.packets=(await pool.query('SELECT to_jsonb(p) row FROM workshop_platform.grade_packets p JOIN workshop_platform.objective_judgments j USING(user_id,evaluation_id) WHERE p.user_id=$1 AND j.workshop_key=$2 ORDER BY to_jsonb(p)::text',[userId,key])).rows;
 const ownerKey=JSON.stringify([key==='sql_injection_workshop'?'ARIA':'NOVA',String(userId)]);
 result.runIds=runIds||(await pool.query('SELECT run_id FROM graph_runtime.runs WHERE owner_key=$1 ORDER BY run_id',[ownerKey])).rows.map(r=>r.run_id);
 for(const table of ['runs','effects','events'])result['graph_'+table]=(await pool.query(`SELECT ${graphProjection(table)} FROM graph_runtime.${table} t WHERE owner_key=$1 AND run_id=ANY($2::uuid[]) ORDER BY to_jsonb(t)::text`,[ownerKey,result.runIds])).rows.map(row=>({row}));
 return result;
}
async function stateSnapshot(identity,workshop,userId,family){
 const key=family==='ARIA'?'sql_injection_workshop':'nosql_injection_workshop',schema=family==='ARIA'?'aria':'nova',result={};
 for(const table of ['user_state','user_modes','completions','time_tracking','objective_judgments','objective_evidence'])result[table]=(await identity.query(`SELECT to_jsonb(t) row FROM workshop_platform.${table} t WHERE user_id=$1 AND workshop_key=$2 ORDER BY to_jsonb(t)::text`,[userId,key])).rows;
 for(const table of family==='ARIA'?['cart','chat_history','orders']:['reading_lists','chat_history'])result[table]=(await workshop.query(`SELECT to_jsonb(t) row FROM ${schema}.${table} t WHERE user_id=$1 ORDER BY to_jsonb(t)::text`,[String(userId)])).rows;
 return result;
}
async function seedState(pool,userId,family){
 if(family==='ARIA')await pool.query("INSERT INTO aria.cart(user_id,product_name,quantity,unit_price) VALUES($1,'Laptop Pro 15',1,1299.99) ON CONFLICT(user_id,product_name) DO NOTHING",[String(userId)]);
 else await pool.query("INSERT INTO nova.reading_lists(user_id,paper_id) VALUES($1,'PAPER-2024-001') ON CONFLICT DO NOTHING",[String(userId)]);
}
function verifyResetEvidence(before,after){
 assert(Number.isSafeInteger(before.generation)&&Number.isSafeInteger(after.generation)&&after.generation>before.generation);
 assert.equal(after.completed,0);assert.equal(after.mutable,0);assert.equal(after.history,0);
 assert.deepEqual(after.immutable,before.immutable);assert.deepEqual(after.sibling,before.sibling);
}
function bindPackets({turn,body,records,userId,completions}){
 const key=turn.family==='ARIA'?'sql_injection_workshop':'nosql_injection_workshop';
 const project=require('../../server/services/workshopObjectiveGrader').projectWorkshopToolResult;
 for(const record of records){const rubric=record.packet.rubric;assert.equal(rubric.objectiveId,record.judgment.objective_id);assert.equal(rubric.family,turn.family);assert.equal(rubric.scenario,turn.family==='ARIA'?'product_search':'paper_search_simulation');assert.equal(rubric.version,turn.family==='ARIA'?'aria_sql.v3':'nova_operator_sim.v3');assert.equal(rubric.mode,'vuln');assert.equal(record.judgment.workshop_key,key);const entries=record.packet.evidence;const take=(id,source)=>{const rows=entries.filter(e=>e.id===id&&e.source===source);assert.equal(rows.length,1);return rows[0].content;};
  assert.equal(take('request','student_input'),turn.message);assert.equal(take('answer','assistant_response'),body.presentation?(body.presentation.narrative.source==='model'?body.presentation.narrative.text:''):body.response);
  require('./ariaNovaCurrentWireBinding').bindPacketPresentation({turn,body,packet:record.packet});
  const tool=take('tool','tool_result');assert((body.toolObservations||[]).some(o=>require('node:util').isDeepStrictEqual(tool,{tool:o.toolUsed,invocation:o.invocation,result:project(key,o.toolResult)})));
  const context=take('context','server_observation');assert.equal(context.authenticatedOwnerId,String(userId));assert.equal(context.mode,'vuln');assert.equal(context.decisionSource,'model');assert.equal(context.executionSource,turn.family==='ARIA'?'database_query':'postgres_backed_operator_simulation');assert.deepEqual(context.normalPaperAccessLevels,turn.family==='ARIA'?null:['public']);
  if(record.judgment.disposition==='awarded')assert(completions.some(c=>String(c.user_id)===String(userId)&&c.workshop_key===key&&c.objective_id===record.judgment.objective_id));
 }
 const awarded=records.filter(r=>r.judgment.disposition==='awarded');
 const ids=awarded.map(r=>r.judgment.objective_id);assert.equal(new Set(ids).size,ids.length);
 for(const completion of completions){assert.equal(String(completion.user_id),String(userId));assert.equal(completion.workshop_key,key);}
 assert.deepEqual(completions.map(c=>c.objective_id).sort(),[...ids].sort());assert.deepEqual([...(body.completedObjectives||[])].sort(),[...ids].sort());
 for(const record of awarded)assert((body.judgments||[]).some(j=>j.objectiveId===record.judgment.objective_id&&j.evaluationId===record.judgment.evaluation_id&&j.verdict==='pass'));
 for(const published of body.judgments||[]){const matched=records.filter(r=>r.judgment.evaluation_id===published.evaluationId);assert.equal(matched.length,1);assert.equal(matched[0].judgment.objective_id,published.objectiveId);assert.equal(matched[0].judgment.verdict,published.verdict);}
}
function classifyOutcome({turn,body,records,reference,ownerId}){
 const observed=body.toolObservations||[];
 const authentic=observed.length>0&&observed.every(o=>o.toolUsed===(turn.family==='ARIA'?'search_products':'search_papers')&&o.invocation?.params?.[turn.family==='ARIA'?'searchTerm':'query']===turn.query&&require('./sqlNoSqlIndependentEffects').verifySqlNoSqlIndependentEffect({objectiveId:turn.objectiveId,query:turn.query,output:o.toolResult,ownerId,reference}));
 const published=(body.judgments||[]).filter(j=>j.objectiveId===turn.objectiveId);
 const awarded=published.length===1&&published[0].verdict==='pass'&&records.some(r=>r.judgment.evaluation_id===published[0].evaluationId&&r.judgment.objective_id===turn.objectiveId&&r.judgment.verdict==='pass'&&r.judgment.disposition==='awarded')&&(body.completedObjectives||[]).includes(turn.objectiveId);
 return {creditContradiction:awarded&&!authentic,outcome:authentic&&awarded?'qualified':'incomplete',reason:!authentic?(awarded?'credit_without_independent_effect':'independent_effect_not_observed'):!awarded?'canonical_credit_not_awarded':'authentic_effect_and_credit'};
}
module.exports={graphProjection,readReference,bindEffects,immutableSnapshot,stateSnapshot,seedState,verifyResetEvidence,classifyOutcome,bindPackets};
