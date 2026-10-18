'use strict';
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
async function initializeControl({pool,database}){
 if(!/^dvaia_audit_control_[a-f0-9]+$/.test(database))throw Error('Dedicated control database required');
 const migrations=['schema.sql','migrations/0002_query_receipts.sql','migrations/0003_query_destruction_tombstones.sql'].map((file,index)=>{const source=fs.readFileSync(path.join(__dirname,file),'utf8');return{version:index+1,source,hash:createHash('sha256').update(source).digest('hex')};});
 const client=await pool.connect();
 try{
  await client.query('BEGIN');await client.query("SELECT pg_advisory_xact_lock(824099102)");
  await client.query(`REVOKE ALL ON DATABASE ${database} FROM PUBLIC`);
  await client.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
  await client.query('CREATE TABLE IF NOT EXISTS audit_service_migrations(version integer PRIMARY KEY,sha256 text NOT NULL); REVOKE ALL ON audit_service_migrations FROM PUBLIC');
  const versions=(await client.query('SELECT version FROM audit_service_migrations ORDER BY version')).rows;
  if(versions.some((row,index)=>row.version!==index+1)||versions.length>migrations.length)throw Error('Unknown service migration chain');
  const applied=[];
  for(const migration of migrations){
   const previous=(await client.query('SELECT sha256 FROM audit_service_migrations WHERE version=$1',[migration.version])).rows[0];
   if(previous&&previous.sha256!==migration.hash)throw Error('Service schema checksum mismatch');
   if(!previous){await client.query(migration.source);await client.query('INSERT INTO audit_service_migrations VALUES($1,$2)',[migration.version,migration.hash]);applied.push(migration.version);}
  }
  await client.query('COMMIT');return{schemaSha256:migrations[0].hash,applied:applied.length>0,appliedVersions:applied};
 }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}
module.exports={initializeControl};
