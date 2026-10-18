'use strict';
const {createHash}=require('node:crypto');
const {withTransaction}=require('../../server/database/postgres');
const {readVerifiedLegacyArchive}=require('./read-platform-archive');
const {TABLES,mapXssArchive}=require('./map-xss-archive');
const DEFAULT_EMAILS=[
 {id:1,subject:'Your account security update',sender:'support@secureshop.com',body:'Dear Customer, your account settings have been updated. Please review your profile.',user_key:null},
 {id:2,subject:'Order confirmation #12345',sender:'orders@secureshop.com',body:'Your order #12345 has been confirmed and will ship within 2 business days.',user_key:null},
 {id:3,subject:'Weekly Security Newsletter',sender:'newsletter@dvaia.local',body:'This week: patch Tuesday updates, new CVEs, and best practices for input sanitization.',user_key:null},
];
function reject(code){throw Object.assign(new Error(code),{code});}
function verifiedOwnerBinding(raw,ownerProof){
 if(!raw||!raw.ownerBinding)reject('OWNER_BINDING_REQUIRED');
 if(!ownerProof)reject('OWNER_PROOF_REQUIRED');
 const api=require('./archive-owner-binding'),binding=api.normalizeArchiveOwnerBinding(raw.ownerBinding);
 api.assertVerifiedArchiveOwnerBinding(ownerProof,binding);
 return binding;
}
async function readXssArchive({archive,naiveTimestamps='reject'}){
 const verified=await readVerifiedLegacyArchive({archive});
 return{sources:Object.fromEntries(Object.entries(verified.sources).filter(([source])=>['xss_email_challenge.db','xss_challenge.db','challenge.db'].includes(source))),archiveDigest:verified.archiveDigest,naiveTimestamps};
}
async function importXssArchive(pool,raw,{apply=false,ownerProof}={}){
 if(typeof apply!=='boolean')reject('INVALID_APPLY_OPTION');
 const captured=structuredClone(raw),binding=verifiedOwnerBinding(captured,ownerProof);
 captured.ownerBinding=binding;
 const{snapshot,provenance,report}=mapXssArchive(captured);
 return withTransaction(pool,async client=>{
  await client.query('SELECT pg_advisory_xact_lock(1886610804,2)');
  const tables=[...Object.keys(snapshot),'import_provenance','import_batches'];
  await client.query(`LOCK TABLE ${tables.map(table=>'xss.'+table).join(',')} IN ACCESS EXCLUSIVE MODE`);
  for(const table of tables.filter(table=>table!=='emails'))if((await client.query(`SELECT EXISTS(SELECT 1 FROM xss.${table}) AS populated`)).rows[0].populated)reject('XSS_IMPORT_REQUIRES_EMPTY_TARGET');
  const emails=(await client.query('SELECT id,subject,sender,body,user_key FROM xss.emails ORDER BY id')).rows;
  const sequence=(await client.query('SELECT last_value,is_called FROM xss.emails_id_seq')).rows[0];
  const times=(await client.query('SELECT count(DISTINCT received_at)::int n,count(received_at)::int present FROM xss.emails')).rows[0];
  if(JSON.stringify(emails)!==JSON.stringify(DEFAULT_EMAILS)||Number(sequence.last_value)!==3||!sequence.is_called||times.n!==1||times.present!==3)reject('XSS_IMPORT_REQUIRES_MIGRATION_EMAIL_DEFAULTS');
  await client.query('SAVEPOINT xss_archive_import');
  await client.query('DELETE FROM xss.emails');
  for(const config of Object.values(TABLES)){
   const target=config.target;
   for(const row of snapshot[target]){
    const columns=Object.keys(row);
    await client.query(`INSERT INTO xss.${target}(${columns.join(',')}) ${columns.includes('id')?'OVERRIDING SYSTEM VALUE ':''}VALUES(${columns.map((_,i)=>'$'+(i+1)).join(',')})`,Object.values(row));
   }
   if(config.columns.split(' ').includes('id')&&!config.omit?.includes('id')){
    const next=snapshot[target].reduce((max,row)=>Math.max(max,row.id),0)+1;
    await client.query(`ALTER TABLE xss.${target} ALTER COLUMN id RESTART WITH ${next}`);
   }
  }
  for(const row of provenance)await client.query('INSERT INTO xss.import_provenance(archive_sha256,source_file,source_table,source_id,source_row) VALUES($1,$2,$3,$4,$5::jsonb)',[captured.archiveDigest,row.source,row.table,row.id,JSON.stringify(row.row)]);
  const hash=value=>createHash('sha256').update(value).digest('hex');
  const metadata={workshopSource:captured.review.workshopSource,naiveTimestamps:captured.naiveTimestamps||'reject',retained:report.retainedTables.map(row=>({source:row.source,tableSha256:hash(row.table),policy:row.policy})),missing:report.missingTables};
  await client.query('INSERT INTO xss.import_batches(archive_sha256,identity_map_sha256,counts,review_metadata) VALUES($1,$2,$3::jsonb,$4::jsonb)',[captured.archiveDigest,binding.identityMapSha256,JSON.stringify(report.counts),JSON.stringify(metadata)]);
  if(!apply)await client.query('ROLLBACK TO SAVEPOINT xss_archive_import');
  return{archiveDigest:captured.archiveDigest,applied:apply,counts:report.counts,provenanceRows:provenance.length,canonicalProgressImported:false};
 });
}
module.exports={DEFAULT_EMAILS,readXssArchive,importXssArchive};
