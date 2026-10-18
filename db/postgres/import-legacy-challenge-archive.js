'use strict';
const {withTransaction}=require('../../server/database/postgres');
const {readVerifiedLegacyArchive}=require('./read-platform-archive');
const {COLUMNS,mapLegacyChallengeArchive}=require('./map-legacy-challenge-archive');
async function readLegacyChallengeArchive({archive,naiveTimestamps='reject'}){
 const verified=await readVerifiedLegacyArchive({archive});
 if(!verified.sources['dvaia.db'])throw Object.assign(new Error('MISSING_LEGACY_CHALLENGE_SOURCE'),{code:'MISSING_LEGACY_CHALLENGE_SOURCE'});
 return {tables:verified.sources['dvaia.db'].tables,archiveDigest:verified.archiveDigest,naiveTimestamps};
}
async function importLegacyChallengeArchive(pool,raw,{apply=false}={}){
 if(typeof apply!=='boolean')throw new TypeError('Invalid apply option');
 const {snapshot,provenance,report}=mapLegacyChallengeArchive(structuredClone(raw));
 return withTransaction(pool,async client=>{
  await client.query('SELECT pg_advisory_xact_lock(1886610804,2)');
  const tables=[...Object.keys(COLUMNS),'import_provenance','import_batches'];
  await client.query(`LOCK TABLE ${tables.map(t=>`legacy_challenge.${t}`).join(',')} IN ACCESS EXCLUSIVE MODE`);
  for(const table of tables)if((await client.query(`SELECT EXISTS(SELECT 1 FROM legacy_challenge.${table}) AS populated`)).rows[0].populated)throw Object.assign(new Error('LEGACY_CHALLENGE_IMPORT_REQUIRES_EMPTY_TARGET'),{code:'LEGACY_CHALLENGE_IMPORT_REQUIRES_EMPTY_TARGET'});
  await client.query('SAVEPOINT legacy_challenge_import');
  for(const [table,columns]of Object.entries(COLUMNS)){
   const keys=columns.split(' ');
   for(const row of snapshot[table])await client.query(`INSERT INTO legacy_challenge.${table}(${keys.join(',')}) VALUES(${keys.map((_,i)=>`$${i+1}`).join(',')})`,keys.map(k=>row[k]));
   if(keys.includes('id'))await client.query(`ALTER TABLE legacy_challenge.${table} ALTER COLUMN id RESTART WITH ${snapshot[table].reduce((max,row)=>Math.max(max,row.id),0)+1}`);
  }
  for(const row of provenance)await client.query('INSERT INTO legacy_challenge.import_provenance(archive_sha256,source_table,source_id,source_row) VALUES($1,$2,$3,$4::jsonb)',[report.archiveDigest,row.table,row.id,JSON.stringify(row.row)]);
  await client.query('INSERT INTO legacy_challenge.import_batches(archive_sha256,report) VALUES($1,$2::jsonb)',[report.archiveDigest,JSON.stringify(report)]);
  if(!apply)await client.query('ROLLBACK TO SAVEPOINT legacy_challenge_import');
  return {...report,applied:apply,provenanceRows:provenance.length};
 });
}
module.exports={readLegacyChallengeArchive,importLegacyChallengeArchive};
