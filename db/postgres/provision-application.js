'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const {repositories}=require('./initialize-application');
const {provisioningExtension}=require('./provisioning-extension');
const repositoryRoot=path.resolve(__dirname,'../..');
// SQL role names are immutable migration contracts; fresh database names use the new brand.
function provisioningPlan(){return repositories.map(([schema,prefix])=>({schema,database:`owasp_ai_goat_${schema}`,runtimeRole:`dvaia_${schema}_runtime`,migrationRole:`dvaia_${schema}_migration`,runtimeVariable:`${prefix}_DATABASE_URL`,migrationVariable:`${prefix}_MIGRATION_DATABASE_URL`}));}
function failure(code){const error=new Error(code);error.code=code;return error;}
function identifier(value){if(!/^(?:owasp_ai_goat_[a-z_]+|dvaia_[a-z_]+_(?:runtime|migration))$/.test(value))throw failure('INVALID_PROVISIONING_IDENTIFIER');return '"'+value+'"';}
function credentialUrl(adminUrl,role,password,database){const url=new URL(adminUrl);url.username=role;url.password=password;url.pathname='/'+database;return url.href;}
async function privateDestination(outputPath,{platform=process.platform,fileSystem=fs,repositoryDirectory=repositoryRoot}={}){
 if(platform==='win32'){
  if(!outputPath)throw failure('PRIVATE_OUTPUT_PATH_REQUIRED');
  try{
   const {normalizePrivatePath}=require('../../scripts/lib/windows-private-state');
   const absolute=normalizePrivatePath(outputPath),parent=normalizePrivatePath(await fileSystem.realpath(path.win32.dirname(absolute)));
   const resolved=path.win32.join(parent,path.win32.basename(absolute));
   const repository=normalizePrivatePath(await fileSystem.realpath(repositoryDirectory));
   if(resolved.toUpperCase()===repository.toUpperCase()||resolved.toUpperCase().startsWith(repository.toUpperCase()+'\\'))throw failure('OUTPUT_MUST_BE_OUTSIDE_REPOSITORY');
   return resolved;
  }catch(error){throw failure(error.code==='OUTPUT_MUST_BE_OUTSIDE_REPOSITORY'?error.code:'MANIFEST_NOT_PRIVATE');}
 }
 if(!outputPath)throw failure('PRIVATE_OUTPUT_PATH_REQUIRED');
 const absolute=path.resolve(outputPath),parent=await fs.realpath(path.dirname(absolute));
 const resolved=path.join(parent,path.basename(absolute));
 if(resolved===repositoryRoot||resolved.startsWith(repositoryRoot+path.sep))throw failure('OUTPUT_MUST_BE_OUTSIDE_REPOSITORY');
 return resolved;
}
async function clusterIdentity(client){const {rows}=await client.query('SELECT system_identifier::text FROM pg_control_system()');return rows[0].system_identifier;}
async function requirePostgres18(client){
 const {rows}=await client.query("SELECT current_setting('server_version_num') AS server_version_num");
 const value=rows[0]?.server_version_num;
 if(value===undefined||value===null||value==='')throw failure('POSTGRES_VERSION_UNAVAILABLE');
 if(typeof value!=='string'||!/^\d{6}$/.test(value))throw failure('POSTGRES_VERSION_INVALID');
 if(Math.trunc(Number(value)/10000)!==18)throw failure('POSTGRES_VERSION_UNSUPPORTED');
}
async function verifyOwned(client,manifest,plan,cluster,adminUrl){
 if(manifest.version!==1||manifest.status!=='complete'||manifest.cluster!==cluster||JSON.stringify(manifest.plan)!==JSON.stringify(plan))throw failure('MANIFEST_OWNERSHIP_MISMATCH');
 const keys=plan.flatMap(item=>[item.runtimeVariable,item.migrationVariable]).sort();
 if(!manifest.configuration||JSON.stringify(Object.keys(manifest.configuration).sort())!==JSON.stringify(keys))throw failure('MANIFEST_CONFIGURATION_MISMATCH');
 const admin=new URL(adminUrl);
 for(const item of plan){
  for(const kind of ['runtime','migration']){
   let url;try{url=new URL(manifest.configuration[item[kind+'Variable']]);}catch{throw failure('MANIFEST_CONFIGURATION_MISMATCH');}
   if(!['postgres:','postgresql:'].includes(url.protocol)||url.hostname!==admin.hostname||url.port!==admin.port
      ||decodeURIComponent(url.username)!==item[kind+'Role']||!url.password||url.pathname!=='/'+item.database||url.search||url.hash)throw failure('MANIFEST_CONFIGURATION_MISMATCH');
  }
  const {rows}=await client.query('SELECT d.datname,r.rolname AS owner FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname=$1',[item.database]);
  if(rows[0]?.owner!==item.migrationRole)throw failure('DATABASE_OWNERSHIP_MISMATCH');
  const roles=await client.query('SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname=ANY($1::text[])',[[item.runtimeRole,item.migrationRole]]);
  if(roles.rows.length!==2||roles.rows.some(r=>r.rolsuper||r.rolcreatedb||r.rolcreaterole||r.rolreplication||r.rolbypassrls||!r.rolcanlogin))throw failure('ROLE_OWNERSHIP_MISMATCH');
  const memberships=await client.query('SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member OR r.oid=m.roleid WHERE r.rolname=ANY($1::text[]) LIMIT 1',[[item.runtimeRole,item.migrationRole]]);
  if(memberships.rows.length)throw failure('ROLE_OWNERSHIP_MISMATCH');
 }
}
// The original manifest remains authoritative until every new resource exists.
// An interrupted journal is deliberately not replayed: DDL may have committed
// before its acknowledgement. Operators must inspect it rather than adopt names.
async function extendOwnedProvisioning(client,{previous,previousBytes,plan,additions,destination,adminUrl},{platform=process.platform,privateJournal,fileSystem=fs}={}) {
 const fs=fileSystem;
 const legacyJournal=destination+'.upgrade';
 if(platform==='win32'){
  try{await fs.lstat(legacyJournal);throw failure('PROVISIONING_UPGRADE_PENDING');}
  catch(error){if(error.code!=='ENOENT')throw error;}
 }
 // Retain Windows journals per admitted original. A failed upgrade selects the
 // same journal and blocks replay; a later expansion gets a distinct binding.
 const journal=platform==='win32'?destination+'.upgrade-'+crypto.createHash('sha256').update(previousBytes).digest('hex'):legacyJournal;
 try{await fs.lstat(journal);throw failure('PROVISIONING_UPGRADE_PENDING');}
 catch(error){if(error.code!=='ENOENT')throw error;}
 if(!additions.length)return{status:'existing',outputPath:destination,configuration:previous.configuration,plan};
 const names=additions.flatMap(row=>[row.runtimeRole,row.migrationRole]);
 const collisions=await client.query('SELECT rolname AS name FROM pg_roles WHERE rolname=ANY($1::text[]) UNION ALL SELECT datname AS name FROM pg_database WHERE datname=ANY($2::text[])',[names,additions.map(row=>row.database)]);
 if(collisions.rows.length)throw failure('PROVISIONING_NAME_COLLISION');
 const configuration={...previous.configuration},secrets=new Map();
 for(const row of additions)for(const kind of ['runtime','migration']){
  const role=row[kind+'Role'],password=crypto.randomBytes(32).toString('hex');
  secrets.set(role,password);configuration[row[kind+'Variable']]=credentialUrl(adminUrl,role,password,row.database);
 }
 const manifest={...previous,status:'incomplete',plan,configuration,created:[...(previous.created||[])],upgradeFrom:previous.plan};
 let handle;
 try{
  if(platform!=='win32')handle=await fs.open(journal,'wx',0o600);
  let journalBytes;
  const persist=async()=>{
   const resultBytes=Buffer.from(JSON.stringify(manifest,null,2)+'\n');
   if(platform==='win32'){
    if(journalBytes)privateJournal.updateJournal({filePath:journal,originalBytes:journalBytes,resultBytes});
    else privateJournal.createJournal({filePath:journal,bytes:resultBytes});
    journalBytes=resultBytes;
   }else{await handle.truncate(0);await handle.write(JSON.stringify(manifest,null,2)+'\n',0,'utf8');await handle.sync();}
  };
  await persist();
  // Persist the journal directory entry before any external DDL can commit.
  if(platform!=='win32'){const journalDirectory=await fs.open(path.dirname(destination),'r');
  try{await journalDirectory.sync();}finally{await journalDirectory.close();}}
  for(const row of additions){
   for(const role of [row.migrationRole,row.runtimeRole]){
    await client.query(`CREATE ROLE ${identifier(role)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${secrets.get(role)}'`);
    manifest.created.push({role});await persist();
   }
   await client.query(`CREATE DATABASE ${identifier(row.database)} OWNER ${identifier(row.migrationRole)}`);
   manifest.created.push({database:row.database});await persist();
   await client.query(`REVOKE CONNECT,TEMPORARY ON DATABASE ${identifier(row.database)} FROM PUBLIC`);
   await client.query(`GRANT CONNECT ON DATABASE ${identifier(row.database)} TO ${identifier(row.runtimeRole)},${identifier(row.migrationRole)}`);
  }
  manifest.status='complete';delete manifest.upgradeFrom;await persist();
  if(platform==='win32'){
   // Keep the per-effect journal and its native originals. Only the exact
   // previously admitted manifest can be promoted after all DDL acknowledges.
   privateJournal.updateJournal({filePath:destination,originalBytes:previousBytes,resultBytes:journalBytes});
  }else{
   await handle.close();handle=null;
   await fs.rename(journal,destination);
   const directory=await fs.open(path.dirname(destination),'r');try{await directory.sync();}finally{await directory.close();}
  }
  return{status:'upgraded',outputPath:destination,configuration,plan};
 }finally{if(handle)await handle.close();}
}
function createApplicationProvisioner({platform=process.platform,fileSystem=fs,repositoryDirectory=repositoryRoot,privateJournal}={}){
 const fs=fileSystem;
 if(platform==='win32'&&!privateJournal)privateJournal=require('../../scripts/lib/windows-provisioning-journal').createWindowsProvisioningJournal({platform});
/** Fresh-only provisioning. Credentials are returned only in memory and written to a private manifest, never logged. */
async function provisionApplication({adminUrl=process.env.PG_ADMIN_DATABASE_URL,outputPath,manifestPath,clientFactory,env=process.env,upgrade=false}={}){
 if(!adminUrl)throw failure('PG_ADMIN_DATABASE_URL_REQUIRED');
 let parsed;try{parsed=new URL(adminUrl);if(!['postgres:','postgresql:'].includes(parsed.protocol))throw Error();}catch{throw failure('INVALID_ADMIN_DATABASE_URL');}
 if(parsed.search||parsed.hash)throw failure('ADMIN_URL_OPTIONS_NOT_SUPPORTED');
 if(env.PG_TLS&&!['require','disable'].includes(env.PG_TLS))throw failure('INVALID_PG_TLS');
 const ssl=env.PG_TLS==='require'?{rejectUnauthorized:true}:false;
 if(!ssl&&!['localhost','127.0.0.1','[::1]'].includes(parsed.hostname))throw failure('REMOTE_POSTGRES_REQUIRES_TLS');
 const destination=await privateDestination(outputPath||manifestPath,{platform,fileSystem,repositoryDirectory}),plan=provisioningPlan();
 let previous,previousBytes,exists=false;
 try{const stat=await fs.lstat(destination);exists=true;if(!stat.isFile()||stat.isSymbolicLink()||(platform!=='win32'&&(stat.mode&0o077)!==0))throw failure('MANIFEST_NOT_PRIVATE');}
 catch(error){if(error.code!=='ENOENT')throw failure(platform==='win32'?'MANIFEST_NOT_PRIVATE':error.code||'INVALID_MANIFEST');}
 if(platform==='win32'){try{privateJournal.inspectDestination({filePath:destination});}catch{throw failure('MANIFEST_NOT_PRIVATE');}}
 if(exists){
  try{previousBytes=platform==='win32'?privateJournal.readJournal({filePath:destination}):await fs.readFile(destination);if(!Buffer.isBuffer(previousBytes)||platform==='win32'&&previousBytes.length>1024*1024)throw Error();previous=JSON.parse(previousBytes.toString('utf8'));if(platform==='win32'&&(!previous||typeof previous!=='object'||Array.isArray(previous)))throw Error();}
  catch(error){throw failure(platform==='win32'?'MANIFEST_NOT_PRIVATE':error.code||'INVALID_MANIFEST');}
 }
 const client=clientFactory?clientFactory({connectionString:adminUrl,ssl}):new(require('pg').Client)({connectionString:adminUrl,ssl,application_name:'owasp-ai-goat-provision',connectionTimeoutMillis:10000});
 let handle,locked=false;
 try{
  await client.connect();
  await requirePostgres18(client);
  await client.query('SELECT pg_advisory_lock(1886610804, 41)');locked=true;
  const cluster=await clusterIdentity(client);
  if(previous){
   if(upgrade){
    await verifyOwned(client,previous,previous.plan,cluster,adminUrl);
    const additions=provisioningExtension(previous.plan,plan);
    return await extendOwnedProvisioning(client,{previous,previousBytes,plan,additions,destination,adminUrl},{platform,privateJournal,fileSystem});
   }
   await verifyOwned(client,previous,plan,cluster,adminUrl);return{status:'existing',outputPath:destination,configuration:previous.configuration,plan};
  }
  if(upgrade)throw failure('EXISTING_MANIFEST_REQUIRED');
  const names=plan.flatMap(row=>[row.runtimeRole,row.migrationRole]);
  const collisions=await client.query('SELECT rolname AS name FROM pg_roles WHERE rolname=ANY($1::text[]) UNION ALL SELECT datname AS name FROM pg_database WHERE datname=ANY($2::text[])',[names,plan.map(row=>row.database)]);
  if(collisions.rows.length)throw failure('PROVISIONING_NAME_COLLISION');
  if(platform!=='win32')handle=await fs.open(destination,'wx',0o600);
  const configuration={},secrets=new Map();
  for(const row of plan){for(const kind of ['runtime','migration']){const password=crypto.randomBytes(32).toString('hex'),role=row[kind+'Role'];secrets.set(role,password);configuration[row[kind+'Variable']]=credentialUrl(adminUrl,role,password,row.database);}}
  const manifest={version:1,status:'incomplete',cluster,plan,configuration,created:[]};
  let journalBytes;
  const persist=async()=>{
   const resultBytes=Buffer.from(JSON.stringify(manifest,null,2)+'\n');
   if(platform==='win32'){
    if(journalBytes)privateJournal.updateJournal({filePath:destination,originalBytes:journalBytes,resultBytes});
    else privateJournal.createJournal({filePath:destination,bytes:resultBytes});
    journalBytes=resultBytes;
   }else{await handle.truncate(0);await handle.write(JSON.stringify(manifest,null,2)+'\n',0,'utf8');await handle.sync();}
  };
  await persist();
  // Credentials must have a durable directory entry before external DDL can
  // commit. A file fsync alone does not persist its newly created name.
  if(platform!=='win32'){const manifestDirectory=await fs.open(path.dirname(destination),'r');
  try{await manifestDirectory.sync();}finally{await manifestDirectory.close();}}
  for(const row of plan){
   for(const role of [row.migrationRole,row.runtimeRole]){
    // Generated hexadecimal passwords cannot contain SQL delimiters. Never include query text in errors.
    await client.query(`CREATE ROLE ${identifier(role)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${secrets.get(role)}'`);
    manifest.created.push({role});await persist();
   }
   await client.query(`CREATE DATABASE ${identifier(row.database)} OWNER ${identifier(row.migrationRole)}`);
   manifest.created.push({database:row.database});await persist();
   await client.query(`REVOKE CONNECT,TEMPORARY ON DATABASE ${identifier(row.database)} FROM PUBLIC`);
   await client.query(`GRANT CONNECT ON DATABASE ${identifier(row.database)} TO ${identifier(row.runtimeRole)},${identifier(row.migrationRole)}`);
  }
  manifest.status='complete';await persist();
  return{status:'created',outputPath:destination,configuration,plan};
 }catch(error){throw failure(/^[A-Z0-9_]+$/.test(error.code||'')?error.code:'PROVISIONING_FAILED');}
 finally{if(handle)await handle.close();if(locked)await client.query('SELECT pg_advisory_unlock(1886610804, 41)').catch(()=>{});await client.end().catch(()=>{});}
}
return Object.freeze({provisionApplication});
}
const {provisionApplication}=createApplicationProvisioner();
if(require.main===module){
 const args=process.argv.slice(2);
 if(args.length===1&&args[0]==='--plan')console.log(JSON.stringify(provisioningPlan(),null,2));
 else if(args.length===2&&['--output','--upgrade'].includes(args[0]))provisionApplication({outputPath:args[1],upgrade:args[0]==='--upgrade'}).then(result=>console.log(JSON.stringify({status:result.status,databases:result.plan.length,credentialsFile:result.outputPath}))).catch(error=>{console.error('PostgreSQL provisioning failed:',error.code);process.exitCode=1;});
 else{console.error('Usage: node db/postgres/provision-application.js --plan | --output /private/path/credentials.json | --upgrade /private/path/credentials.json');process.exitCode=1;}
}
module.exports={createApplicationProvisioner,provisioningPlan,provisionApplication,verifyOwned,clusterIdentity,requirePostgres18};
