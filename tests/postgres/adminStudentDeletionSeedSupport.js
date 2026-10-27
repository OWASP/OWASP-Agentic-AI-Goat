'use strict';
// Controlled, pre-deletion synthetic lifecycle data. Never objective/model credit.
// These nine store probes are NOT the complete sixteen-store deletion oracle.
const assert=require('node:assert/strict');
const {STORES}=require('./adminStudentDeletionRenderedSupport');
const DEFINITIONS=Object.freeze([
 ['aria','aria.cart','user_id',"INSERT INTO aria.cart(user_id,product_name) VALUES($1,'synthetic deletion lifecycle item')"],
 ['nova','nova.reading_lists','user_id','INSERT INTO nova.reading_lists(user_id,paper_id) SELECT $1,paper_id FROM nova.papers ORDER BY id LIMIT 1'],
 ['mcp','mcp.progress','user_key',"INSERT INTO mcp.progress(user_key,objective_id) VALUES($1,'mcp_recon')"],
 ['csrf','csrf.progress','user_key',"INSERT INTO csrf.progress(user_key,objective_id) VALUES($1,'csrf_g1')"],
 ['supply_chain','supply_chain.progress','user_id','INSERT INTO supply_chain.progress(user_id,objective_id) SELECT $1,objective_id FROM supply_chain.objectives ORDER BY ordinal LIMIT 1'],
 ['finflow','finflow.progress','user_id','INSERT INTO finflow.progress(user_id,objective_id,completed) SELECT $1,objective_id,true FROM finflow.objectives ORDER BY ordinal LIMIT 1'],
 ['sensitive_lookup','sensitive_lookup.exploitation_log','user_id',"INSERT INTO sensitive_lookup.exploitation_log(user_id,user_input) VALUES($1,'synthetic deletion lifecycle input')"],
 ['xss','xss.profiles','user_key',"INSERT INTO xss.profiles(user_key,name,bio,website) VALUES($1,'synthetic owner','synthetic lifecycle text','https://example.invalid')"],
 ['legacy_challenge','legacy_challenge.cart','platform_owner_id','INSERT INTO legacy_challenge.cart(user_id,product_id,platform_owner_id) SELECT $1,id,$1 FROM legacy_challenge.products ORDER BY id LIMIT 1'],
].map(([schema,table,column,insert])=>Object.freeze({schema,table,column,insert})));
const UNSUPPORTED=Object.freeze(STORES.filter(s=>!DEFINITIONS.some(d=>d.schema===s.schema)).map(s=>s.schema));
function owners(targetId,siblingId){for(const id of [targetId,siblingId])assert.ok(Number.isSafeInteger(id)&&id>0&&id<=2147483647);assert.notEqual(targetId,siblingId);}
function poolFor(pools,schema){const pool=pools[schema];assert.equal(typeof pool?.query,'function',`Runtime pool missing: ${schema}`);return pool;}
async function snapshotWorkshopRows(pools,{targetId,siblingId}){
 owners(targetId,siblingId);const result={};
 for(const d of DEFINITIONS){const pool=poolFor(pools,d.schema);const read=async id=>(await pool.query(
  `SELECT to_jsonb(r) AS row FROM ${d.table} r WHERE ${d.column}=$1 ORDER BY to_jsonb(r)::text`,[String(id)])).rows;
  result[d.schema]={target:await read(targetId),sibling:await read(siblingId)};
 }return result;
}
async function seedWorkshopRows(pools,ids){
 owners(ids.targetId,ids.siblingId);
 // Preflight every store before any write; existing rows are never overwritten.
 const before=await snapshotWorkshopRows(pools,ids);
 for(const d of DEFINITIONS){assert.deepEqual(before[d.schema],{target:[],sibling:[]},`Synthetic seed scope is not empty: ${d.schema}`);}
 for(const d of DEFINITIONS)for(const id of [ids.targetId,ids.siblingId]){
  const inserted=await poolFor(pools,d.schema).query(d.insert,[String(id)]);
  assert.equal(inserted.rowCount,1,`Synthetic seed not inserted: ${d.schema}`);
 }
 const after=await snapshotWorkshopRows(pools,ids);
 for(const d of DEFINITIONS)assert.ok(after[d.schema].target.length===1&&after[d.schema].sibling.length===1);
 return {seedProvenance:'controlled-lifecycle-data-not-model-credit',snapshot:after,
  supportedStores:DEFINITIONS.map(d=>d.schema),unsupportedStores:[...UNSUPPORTED],fullStoreCoverage:false};
}
function assertWorkshopRowsDeleted(before,after){
 assert.deepEqual(Object.keys(before).sort(),DEFINITIONS.map(d=>d.schema).sort());
 assert.deepEqual(Object.keys(after).sort(),Object.keys(before).sort());
 for(const d of DEFINITIONS){assert.ok(before[d.schema].target.length>0&&before[d.schema].sibling.length>0);
  assert.deepEqual(after[d.schema].target,[],`${d.schema} target retained`);
  assert.deepEqual(after[d.schema].sibling,before[d.schema].sibling,`${d.schema} sibling changed`);}
 return {workshopRowsDeleted:true,siblingRowsUnchanged:true,fullStoreCoverage:false,canonicalCredit:false,
  unsupportedStores:[...UNSUPPORTED]};
}
async function readCodeBotAbsence(identity,subjectId){
 assert.ok(Number.isSafeInteger(subjectId)&&subjectId>0);
 const row=(await identity.query(`SELECT NOT EXISTS(
  SELECT 1 FROM graph_runtime.runs WHERE owner_key=$2
  UNION ALL SELECT 1 FROM graph_runtime.effects WHERE owner_key=$2
  UNION ALL SELECT 1 FROM graph_runtime.codebot_requests WHERE user_id=$1 OR owner_key=$2
 ) AS absent`,[subjectId,JSON.stringify(['CodeBot',String(subjectId)])])).rows[0];
 assert.equal(row?.absent,true,'Nonempty CodeBot external resource scope unsupported');
 return {codeBotExecutionAbsent:true,allExternalResourcesAbsent:false};
}
function requireCompleteStoreCoverage(){throw Error('Deletion seed support incomplete: '+UNSUPPORTED.join(',')+'; complete external-resource absence and immutable-evidence oracles also required');}
const SERVICE_TABLES=Object.freeze([
 ['excessive_agency','excessive_agency.attendees','platform_user_id'],
 ['excessive_agency','excessive_agency.users','platform_user_id'],
 ['excessive_agency','excessive_agency.notes','platform_user_id'],
 ['excessive_agency','excessive_agency.orders','platform_user_id'],
 ['session_disclosure','session_disclosure.labs','platform_owner_id'],
 ['ctf','ctf.ctf_participants','user_id'],
].map(([schema,table,column])=>Object.freeze({schema,table,column})));
const NON_CTF_SERVICE_TABLES=Object.freeze(SERVICE_TABLES.filter(d=>d.schema!=='ctf'));
async function snapshotServiceTables(pools,ids,tables){
 owners(ids.targetId,ids.siblingId);const rows={};
 for(const d of tables){const read=async id=>(await poolFor(pools,d.schema).query(
  `SELECT to_jsonb(r) AS row FROM ${d.table} r WHERE ${d.column}=$1 ORDER BY to_jsonb(r)::text`,[String(id)])).rows;
  rows[d.table]={target:await read(ids.targetId),sibling:await read(ids.siblingId)};}
 return rows;
}
async function snapshotServiceRows(pools,ids){return snapshotServiceTables(pools,ids,SERVICE_TABLES);}
async function snapshotNonCtfServiceRows(pools,ids){return snapshotServiceTables(pools,ids,NON_CTF_SERVICE_TABLES);}
async function seedNonCtfServiceRows(pools,ids){
 // The renderer registers CTF through its separately activated authority helper.
 // This path must never read/register CTF or require a CTF bearer request.
 require('./adminStudentDeletionRenderedSupport').admitStores(process.env);
 const before=await snapshotNonCtfServiceRows(pools,ids);
 for(const [table,row]of Object.entries(before))assert.deepEqual(row,{target:[],sibling:[]},`Synthetic seed scope is not empty: ${table}`);
 const ea=require('../../server/database/postgres/excessiveAgencyLabDb');
 const sd=require('../../server/database/postgres/sessionDisclosureDb').createSessionDisclosureDb(poolFor(pools,'session_disclosure'));
 for(const id of [ids.targetId,ids.siblingId]){
  await ea.createPostgresExcessiveAgencyLabDb(poolFor(pools,'excessive_agency'),String(id)).ensureSeeded();
  await sd.getOrCreate(id);
 }
 const snapshot=await snapshotNonCtfServiceRows(pools,ids);
 for(const [table,row]of Object.entries(snapshot))assert.ok(row.target.length>0&&row.sibling.length>0,`Canonical seed missing: ${table}`);
 return {snapshot,seedProvenance:'canonical-lifecycle-seed-no-model-credit',
  supportedStores:['excessive_agency','session_disclosure'],canonicalCredit:false,fullStoreCoverage:false,nativeVerified:false};
}
async function seedServiceRows(pools,ids,{targetRequest,siblingRequest}={}){
 // Real factories only: CTF must already have its production activation and
 // delivery worker. No legacy registerParticipant or migration writes here.
 require('./adminStudentDeletionRenderedSupport').admitStores(process.env);
 owners(ids.targetId,ids.siblingId);
 for(const [req,id]of [[targetRequest,ids.targetId],[siblingRequest,ids.siblingId]]){
  assert.equal(req?.user?.id,id);assert.ok(req.identitySession?.id);
 }
 const before=await snapshotServiceRows(pools,ids);
 for(const row of Object.values(before))assert.deepEqual(row,{target:[],sibling:[]});
 const runtime=require('../../server/services/ctfAuthorityProduction').getProductionCtfAuthority().runtime;
 assert.equal(typeof runtime?.mutate,'function');
 const ea=require('../../server/database/postgres/excessiveAgencyLabDb');
 const sd=require('../../server/database/postgres/sessionDisclosureDb').createSessionDisclosureDb(poolFor(pools,'session_disclosure'));
 for(const [id,req]of [[ids.targetId,targetRequest],[ids.siblingId,siblingRequest]]){
  const response=await runtime.mutate({req,kind:'register',input:{}});
  assert.equal(response.status,200,'Canonical CTF registration did not finish');
  await ea.createPostgresExcessiveAgencyLabDb(poolFor(pools,'excessive_agency'),String(id)).ensureSeeded();
  await sd.getOrCreate(id);
 }
 const snapshot=await snapshotServiceRows(pools,ids);
 for(const row of Object.values(snapshot))assert.ok(row.target.length>0&&row.sibling.length>0);
 return {snapshot,seedProvenance:'canonical-lifecycle-seed-no-model-credit',nativeVerified:false};
}
function assertServiceTablesDeleted(before,after,tables){
 const keys=tables.map(d=>d.table).sort();assert.deepEqual(Object.keys(before).sort(),keys);assert.deepEqual(Object.keys(after).sort(),keys);
 for(const key of keys){assert.ok(before[key].target.length>0&&before[key].sibling.length>0);
  assert.deepEqual(after[key].target,[],`${key} target retained`);assert.deepEqual(after[key].sibling,before[key].sibling,`${key} sibling changed`);}
 return {serviceRowsDeleted:true,fullStoreCoverage:false,nativeVerified:false};
}
function assertServiceRowsDeleted(before,after){return assertServiceTablesDeleted(before,after,SERVICE_TABLES);}
function assertNonCtfServiceRowsDeleted(before,after){
 return {...assertServiceTablesDeleted(before,after,NON_CTF_SERVICE_TABLES),
  siblingRowsUnchanged:true,canonicalCredit:false,supportedStores:['excessive_agency','session_disclosure']};
}
module.exports={DEFINITIONS,UNSUPPORTED,seedWorkshopRows,snapshotWorkshopRows,assertWorkshopRowsDeleted,
 readCodeBotAbsence,requireCompleteStoreCoverage,SERVICE_TABLES,seedServiceRows,snapshotServiceRows,assertServiceRowsDeleted,
 NON_CTF_SERVICE_TABLES,seedNonCtfServiceRows,snapshotNonCtfServiceRows,assertNonCtfServiceRowsDeleted};
