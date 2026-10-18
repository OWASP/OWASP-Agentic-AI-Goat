'use strict';
const{createHash}=require('node:crypto');
const{withTransaction}=require('../../server/database/postgres');
const{readVerifiedLegacyArchive}=require('./read-platform-archive');
const{mapCsrfArchive}=require('./map-csrf-archive');
function reject(code){throw Object.assign(new Error(code),{code});}
function verifiedOwnerBinding(raw,ownerProof){
 if(!raw||!raw.ownerBinding)reject('OWNER_BINDING_REQUIRED');
 if(!ownerProof)reject('OWNER_PROOF_REQUIRED');
 const api=require('./archive-owner-binding'),binding=api.normalizeArchiveOwnerBinding(raw.ownerBinding);
 api.assertVerifiedArchiveOwnerBinding(ownerProof,binding);
 return binding;
}
async function readCsrfArchive({archive,naiveTimestamps='reject'}){
 const verified=await readVerifiedLegacyArchive({archive});
 return{sources:Object.fromEntries(Object.entries(verified.sources).filter(([key])=>['csrf_workshop.db','users_auth.db'].includes(key))),archiveDigest:verified.archiveDigest,naiveTimestamps};
}
async function importCsrfArchive(pool,raw,{apply=false,ownerProof}={}){
 if(typeof apply!=='boolean')throw new TypeError('Invalid apply option');
 const captured=structuredClone(raw),binding=verifiedOwnerBinding(captured,ownerProof);
 captured.ownerBinding=binding;
 const{snapshot,provenance,report}=mapCsrfArchive(captured);
 return withTransaction(pool,async client=>{
  await client.query('SELECT pg_advisory_xact_lock(1886610804,2)');
  const tables=[...Object.keys(snapshot),'import_provenance','import_batches'];
  await client.query(`LOCK TABLE ${tables.map(table=>'csrf.'+table).join(',')} IN ACCESS EXCLUSIVE MODE`);
  for(const table of tables)if((await client.query(`SELECT EXISTS(SELECT 1 FROM csrf.${table}) AS populated`)).rows[0].populated)throw Object.assign(new Error('CSRF_IMPORT_REQUIRES_EMPTY_TARGET'),{code:'CSRF_IMPORT_REQUIRES_EMPTY_TARGET'});
  await client.query('SAVEPOINT csrf_archive_import');
  for(const[table,rows]of Object.entries(snapshot))for(const row of rows){
   const columns=Object.keys(row);
   await client.query(`INSERT INTO csrf.${table}(${columns.join(',')}) ${columns.includes('id')?'OVERRIDING SYSTEM VALUE ':''}VALUES(${columns.map((_,i)=>'$'+(i+1)).join(',')})`,Object.values(row));
  }
  for(const row of provenance)await client.query('INSERT INTO csrf.import_provenance(archive_sha256,source_file,source_table,source_id,source_row) VALUES($1,$2,$3,$4,$5::jsonb)',[captured.archiveDigest,row.source,row.table,row.key,JSON.stringify(row.row)]);
  const hash=value=>createHash('sha256').update(value).digest('hex');
  const metadata={naiveTimestamps:captured.naiveTimestamps||'reject',missingVictimState:captured.review.missingVictimState,retainedTables:report.retainedTables.map(row=>({source:row.source,tableSha256:hash(row.table),policy:row.policy}))};
  await client.query('INSERT INTO csrf.import_batches(archive_sha256,identity_map_sha256,counts,review_metadata) VALUES($1,$2,$3::jsonb,$4::jsonb)',[captured.archiveDigest,binding.identityMapSha256,JSON.stringify(report.counts),JSON.stringify(metadata)]);
  const next=snapshot.tool_log.reduce((max,row)=>Math.max(max,row.id),0)+1;
  await client.query(`ALTER TABLE csrf.tool_log ALTER COLUMN id RESTART WITH ${next}`);
  if(!apply)await client.query('ROLLBACK TO SAVEPOINT csrf_archive_import');
  return{archiveDigest:captured.archiveDigest,counts:report.counts,applied:apply,canonicalProgressImported:false,provenanceRows:provenance.length};
 });
}
module.exports={readCsrfArchive,importCsrfArchive};
