'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {canonicalCtfJson}=require('../../services/ctfLifecycleCommands');
const TABLES=Object.freeze(['ctf_config','ctf_stages','ctf_participants','ctf_progress','ctf_bans','ctf_technique_blocklist','ctf_payload_blocklist','ctf_attempts','ctf_judgments','ctf_events','ctf_sessions','ctf_leaderboard','stage_default_fields','import_provenance']);
const hash=s=>createHash('sha256').update(s).digest('hex');
const bad=()=>{throw new Error('CTF_BOOTSTRAP_CHECKPOINT_MISMATCH');};
function createCtfAuthorityBootstrapRepository({identityPool,ctfPool}){
 const tx=(store,work,options)=>withCtfTransaction(store==='identity'?identityPool:ctfPool,async c=>{const role=(await c.query('SELECT current_user AS role,session_user AS login')).rows[0];if(role.role!==`dvaia_${store}_migration`||role.login!==role.role)throw new Error('CTF_BOOTSTRAP_MIGRATION_ROLE_REQUIRED');return work(c);},options);
 const control=async(c,op,revision,exclusive=false)=>{const r=(await c.query('SELECT * FROM ctf.bootstrap_control WHERE singleton FOR '+(exclusive?'UPDATE':'SHARE'))).rows[0];if(!r||r.operation_id!==op||!['fenced','prepared'].includes(r.state)||(revision!==undefined&&String(r.revision)!==revision))bad();return r;};
 const ownersCurrent=async c=>{
   // Lock every imported owner, including ban-only owners, in the same
   // user-before-graph order as identity lifecycle validation.
   const ownerQuery="SELECT substring(scope_key from 7)::integer AS id FROM identity.ctf_authority WHERE scope_key LIKE 'owner:%'";
   await c.query(`SELECT u.id FROM identity.users u WHERE u.id IN (${ownerQuery}) ORDER BY u.id FOR SHARE`);
   await c.query(`SELECT g.owner_key FROM graph_runtime.owners g WHERE g.owner_key IN (SELECT '["CTF","'||id||'"]' FROM (${ownerQuery}) owners) ORDER BY g.owner_key FOR SHARE`);
   const drift=(await c.query(`SELECT EXISTS(SELECT 1 FROM identity.ctf_authority a LEFT JOIN identity.users u ON u.id=CASE WHEN a.scope_key LIKE 'owner:%' THEN substring(a.scope_key from 7)::integer END LEFT JOIN graph_runtime.owners g ON g.owner_key='["CTF","'||u.id||'"]' WHERE a.scope_key LIKE 'owner:%' AND (u.id IS NULL OR g.generation IS DISTINCT FROM a.owner_generation OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs j WHERE j.subject_user_id=u.id) OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key=g.owner_key))) AS drift`)).rows[0];return drift?.drift===false;
 };
 return Object.freeze({
 async fence(operationId,options){
  const identityStore=await tx('identity',async c=>(await c.query('SELECT store_id FROM identity.ctf_bootstrap_store WHERE singleton')).rows[0]?.store_id,options);if(!identityStore)bad();
  return tx('ctf',async c=>{
  await c.query('SELECT pg_advisory_xact_lock(1886610804,44)');const r=(await c.query('SELECT * FROM ctf.bootstrap_control WHERE singleton FOR UPDATE')).rows[0];
  if(!r)bad();
  if(r.state==='open'){
   const used=(await c.query('SELECT initialized OR EXISTS(SELECT 1 FROM ctf.projection_receipts) AS used FROM ctf.projection_cursor WHERE singleton')).rows[0];if(!used||used.used)bad();
   await c.query("UPDATE ctf.bootstrap_control SET state='fenced',operation_id=$1,identity_store_id=$2 WHERE singleton",[operationId,identityStore]);
  }else if(r.operation_id!==operationId||r.identity_store_id!==identityStore)bad();return String(r.revision);
 },options);},
 async begin(operationId,revision,options){
  const source=await tx('ctf',c=>control(c,operationId,revision),options);
  return tx('identity',async c=>{
  const local=(await c.query('SELECT store_id FROM identity.ctf_bootstrap_store WHERE singleton')).rows[0];if(!local||local.store_id!==source.identity_store_id)bad();
  const g=(await c.query("SELECT * FROM identity.ctf_authority WHERE scope_key='global' FOR UPDATE")).rows[0];
  if(!g||g.lifecycle_state!=='uninitialized')bad();
  const prior=(await c.query('SELECT * FROM identity.ctf_bootstrap_sessions WHERE operation_id=$1',[operationId])).rows[0];
  if(prior){if(String(prior.source_revision)!==revision||prior.source_store_id!==source.store_id)bad();return;}
  const occupied=(await c.query("SELECT EXISTS(SELECT 1 FROM identity.ctf_decisions UNION ALL SELECT 1 FROM identity.ctf_outbox UNION ALL SELECT 1 FROM identity.ctf_decision_inputs UNION ALL SELECT 1 FROM identity.ctf_bootstrap_sessions UNION ALL SELECT 1 FROM identity.ctf_participant_bindings UNION ALL SELECT 1 FROM identity.ctf_progress_bindings UNION ALL SELECT 1 FROM identity.ctf_stage_bindings UNION ALL SELECT 1 FROM identity.ctf_config_binding UNION ALL SELECT 1 FROM identity.ctf_adaptive_memory UNION ALL SELECT 1 FROM identity.ctf_authority WHERE scope_key<>'global') AS used")).rows[0];if(occupied.used)bad();
  await c.query('INSERT INTO identity.ctf_bootstrap_sessions(operation_id,source_revision,source_store_id) VALUES($1,$2,$3)',[operationId,revision,source.store_id]);
 },options);},
 async sourcePage(operationId,revision,table,after,options){if(!TABLES.includes(table))throw TypeError('Invalid bootstrap table');return tx('ctf',async c=>{
  // Relation lock first also agrees with TRUNCATE's implicit relation lock.
  await c.query(`LOCK TABLE ctf.${table} IN ACCESS SHARE MODE`);
  await control(c,operationId,revision);
  const keys=table==='stage_default_fields'?['stage_number','field_name']:table==='ctf_judgments'?['run_id']:table==='import_provenance'?['archive_sha256']:['id'];
  const types=keys.map(k=>['id','stage_number'].includes(k)?'integer':'text');
  const lhs=keys.length===1?keys[0]:`(${keys.join(',')})`;
  const rhs=keys.map((_,i)=>`($1::jsonb->>${i})::${types[i]}`);const comparison=keys.length===1?rhs[0]:`(${rhs.join(',')})`;
  const wide=table==='ctf_progress'?"||jsonb_build_object('completion_time',t.completion_time::text)":table==='ctf_leaderboard'?"||jsonb_build_object('total_completion_time',t.total_completion_time::text)":'';
  const rows=(await c.query(`SELECT (to_jsonb(t)${wide})::text AS encoded,jsonb_build_array(${keys.map(k=>k+'::text').join(',')})::text AS cursor FROM ctf.${table} t WHERE ($1::text IS NULL OR ${lhs}>${comparison}) ORDER BY ${keys.join(',')} LIMIT 128`,[after])).rows;
  const selected=[];let canonical='[]';for(const row of rows){const next=canonicalCtfJson([...selected,JSON.parse(row.encoded)]);if(Buffer.byteLength(next)>262144){if(!selected.length)throw new Error('CTF_BOOTSTRAP_ROW_TOO_LARGE');break;}selected.push(JSON.parse(row.encoded));canonical=next;}
  return {canonical,hash:hash(canonical),after:selected.length?rows[selected.length-1].cursor:after,done:selected.length===rows.length&&rows.length<128};
 },options);},
 async stagePage(operationId,revision,table,page,document,options){if(!TABLES.includes(table)||!Number.isInteger(page)||page<0||Buffer.byteLength(document.canonical)>262144||hash(document.canonical)!==document.hash)bad();return tx('identity',async c=>{
  const s=(await c.query('SELECT * FROM identity.ctf_bootstrap_sessions WHERE operation_id=$1 FOR UPDATE',[operationId])).rows[0];if(!s||String(s.source_revision)!==revision)bad();
  const prior=(await c.query('SELECT page_sha256,canonical_rows FROM identity.ctf_bootstrap_pages WHERE operation_id=$1 AND table_name=$2 AND page_number=$3',[operationId,table,page])).rows[0];
  if(prior){if(prior.page_sha256!==document.hash||prior.canonical_rows!==document.canonical)bad();return;}
  if(s.state!=='staging'||Number((await c.query('SELECT count(*) AS count FROM identity.ctf_bootstrap_pages WHERE operation_id=$1 AND table_name=$2',[operationId,table])).rows[0].count)!==page)bad();
  await c.query('INSERT INTO identity.ctf_bootstrap_pages VALUES($1,$2,$3,$4,$5)',[operationId,table,page,document.canonical,document.hash]);
 },options);},
 async importAndPrepare({operationId,revision,manifest,manifestSha256},options){
  const {importBootstrapRow,importBootstrapConfig}=require('./ctfAuthorityBootstrapImport');
  for(const entry of manifest){await tx('identity',async c=>{
   const session=(await c.query('SELECT * FROM identity.ctf_bootstrap_sessions WHERE operation_id=$1 FOR UPDATE',[operationId])).rows[0];if(!session||String(session.source_revision)!==revision)bad();
   const page=(await c.query('SELECT * FROM identity.ctf_bootstrap_pages WHERE operation_id=$1 AND table_name=$2 AND page_number=$3',[operationId,entry.table,entry.page])).rows[0];if(!page||page.page_sha256!==entry.hash)bad();
   if((await c.query('SELECT 1 FROM identity.ctf_bootstrap_imports WHERE operation_id=$1 AND table_name=$2 AND page_number=$3',[operationId,entry.table,entry.page])).rows.length)return;
   if(session.state!=='staging')bad();
   for(const row of JSON.parse(page.canonical_rows))await importBootstrapRow(c,entry.table,row,operationId);
   await c.query('INSERT INTO identity.ctf_bootstrap_imports VALUES($1,$2,$3)',[operationId,entry.table,entry.page]);
  },options);}
  await tx('ctf',async c=>{await control(c,operationId,revision,true);await c.query("UPDATE ctf.bootstrap_control SET state='prepared',manifest_sha256=$2 WHERE singleton AND operation_id=$1",[operationId,manifestSha256]);},options);
  await tx('identity',async c=>{
   const session=(await c.query('SELECT * FROM identity.ctf_bootstrap_sessions WHERE operation_id=$1 FOR UPDATE',[operationId])).rows[0];
   if(!session||String(session.source_revision)!==revision)bad();
   if(!await ownersCurrent(c))bad();
   if(session.state==='prepared'){if(session.manifest_sha256!==manifestSha256)bad();return;}
   const pages=(await c.query('SELECT table_name,page_number,page_sha256 FROM identity.ctf_bootstrap_pages WHERE operation_id=$1 ORDER BY table_name,page_number',[operationId])).rows;
   const ordered=manifest.map(x=>({table_name:x.table,page_number:x.page,page_sha256:x.hash})).sort((a,b)=>a.table_name.localeCompare(b.table_name)||a.page_number-b.page_number);
   if(canonicalCtfJson(pages)!==canonicalCtfJson(ordered))bad();
   await importBootstrapConfig(c,operationId);
   await c.query("UPDATE identity.ctf_bootstrap_sessions SET state='prepared',manifest_sha256=$2 WHERE operation_id=$1",[operationId,manifestSha256]);
  },options);
  // A second source read catches a migration writer between the two commits.
  // Runtime remains fenced; readiness independently compares both checkpoints.
  await tx('ctf',async c=>{const r=await control(c,operationId,revision);if(r.state!=='prepared'||r.manifest_sha256!==manifestSha256)bad();},options);
  return Object.freeze({operationId,revision,manifestSha256,prepared:true,runtimeReady:false,reason:'writer_cutover_required'});
 },
 async preparationStatus(operationId,options){
  // Sequential store reads; this is diagnostic preparation, never activation.
  const source=await tx('ctf',async c=>(await c.query('SELECT * FROM ctf.bootstrap_control WHERE singleton')).rows[0],options);
  const target=await tx('identity',async c=>{
   const session=(await c.query('SELECT * FROM identity.ctf_bootstrap_sessions WHERE operation_id=$1 FOR SHARE',[operationId])).rows[0];
   const local=(await c.query('SELECT store_id FROM identity.ctf_bootstrap_store WHERE singleton')).rows[0];
   return session?{...session,identityStoreId:local?.store_id,ownersCurrent:await ownersCurrent(c)}:null;
  },options);
  const latest=await tx('ctf',async c=>(await c.query('SELECT * FROM ctf.bootstrap_control WHERE singleton')).rows[0],options);
  const prepared=Boolean(source&&target&&latest&&source.operation_id===operationId&&latest.operation_id===operationId&&target.ownersCurrent&&target.identityStoreId===source.identity_store_id&&latest.identity_store_id===target.identityStoreId&&source.store_id===target.source_store_id&&latest.store_id===source.store_id&&source.state==='prepared'&&target.state==='prepared'&&latest.state==='prepared'&&String(source.revision)===String(target.source_revision)&&String(latest.revision)===String(source.revision)&&source.manifest_sha256===target.manifest_sha256&&latest.manifest_sha256===source.manifest_sha256);
  return Object.freeze({prepared,runtimeReady:false,reason:prepared?'writer_cutover_required':'bootstrap_checkpoint_unavailable'});
 },
 async verifySource(operationId,revision,options){return tx('ctf',c=>control(c,operationId,revision),options);},
 });
}
module.exports={createCtfAuthorityBootstrapRepository,TABLES};
