'use strict';
// Add one credential to the existing owned CTF database; never adopt a foreign role.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {provisioningPlan}=require('./provision-application');
const ROLE='dvaia_ctf_delivery',KEY='CTF_DELIVERY_DATABASE_URL';
function fail(code){return Object.assign(new Error(code),{code});}
async function privateJson(file){const stat=await fs.lstat(file);if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077)||(typeof process.getuid==='function'&&stat.uid!==process.getuid()))throw fail('CTF_DELIVERY_MANIFEST_NOT_PRIVATE');return JSON.parse(await fs.readFile(file,'utf8'));}
function validateBase(base,admin){
 const plan=provisioningPlan();if(base.version!==1||base.status!=='complete'||JSON.stringify(base.plan)!==JSON.stringify(plan)||typeof base.cluster!=='string')throw fail('CTF_DELIVERY_BASE_INVALID');
 const ctf=plan.find(row=>row.schema==='ctf');
 for(const kind of ['runtime','migration']){let u;try{u=new URL(base.configuration[ctf[kind+'Variable']]);}catch{throw fail('CTF_DELIVERY_BASE_INVALID');}if(u.host!==admin.host||u.pathname!=='/'+ctf.database||decodeURIComponent(u.username)!==ctf[kind+'Role']||!u.password||u.search||u.hash||!['postgres:','postgresql:'].includes(u.protocol))throw fail('CTF_DELIVERY_BASE_INVALID');}
 return ctf;
}
function createCtfDeliveryProvisioner({platform=process.platform,fileSystem=fs,repositoryDirectory=path.resolve(__dirname,'../..'),privateJournal}={}){
 const fs=fileSystem;
 if(platform==='win32'&&!privateJournal)privateJournal=require('../../scripts/lib/windows-provisioning-journal').createWindowsProvisioningJournal({platform});
 const nativeJson=filePath=>{
  try{const bytes=privateJournal.readJournal({filePath});if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024)throw Error();const doc=JSON.parse(bytes.toString('utf8'));if(!doc||typeof doc!=='object'||Array.isArray(doc))throw Error();return doc;}
  catch{throw fail('CTF_DELIVERY_MANIFEST_NOT_PRIVATE');}
 };
async function provisionCtfDelivery({adminUrl,manifestPath,outputPath,clientFactory,deliveryClientFactory,completionWriter,env=process.env}={}){
 let admin;try{admin=new URL(adminUrl);}catch{throw fail('CTF_DELIVERY_ADMIN_URL_INVALID');}
 if(!['postgres:','postgresql:'].includes(admin.protocol)||admin.search||admin.hash)throw fail('CTF_DELIVERY_ADMIN_URL_INVALID');
 if(env.PG_TLS&&!['require','disable'].includes(env.PG_TLS))throw fail('CTF_DELIVERY_TLS_INVALID');
 const ssl=env.PG_TLS==='require'?{rejectUnauthorized:true}:false;if(!ssl&&!['localhost','127.0.0.1','[::1]'].includes(admin.hostname))throw fail('CTF_DELIVERY_TLS_REQUIRED');
 let base,parent,destination,prior,ctf;
 if(platform==='win32'){
  try{
   const {normalizePrivatePath}=require('../../scripts/lib/windows-private-state');
   const source=normalizePrivatePath(manifestPath),output=normalizePrivatePath(outputPath);
   const baseParent=normalizePrivatePath(await fs.realpath(path.win32.dirname(source)));
   const basePath=path.win32.join(baseParent,path.win32.basename(source));
   parent=normalizePrivatePath(await fs.realpath(path.win32.dirname(output)));
   destination=path.win32.join(parent,path.win32.basename(output));
   const repo=normalizePrivatePath(await fs.realpath(repositoryDirectory));
   if(destination.toUpperCase()===repo.toUpperCase()||destination.toUpperCase().startsWith(repo.toUpperCase()+'\\')||destination.toUpperCase()===basePath.toUpperCase())throw Error();
   base=nativeJson(basePath);
  }catch(error){throw fail(error.code==='CTF_DELIVERY_MANIFEST_NOT_PRIVATE'?error.code:'CTF_DELIVERY_PRIVATE_DESTINATION_REQUIRED');}
  ctf=validateBase(base,admin);
  try{privateJournal.inspectDestination({filePath:destination});privateJournal.inspectDestination({filePath:destination+'.pending'});}
  catch{throw fail('CTF_DELIVERY_PRIVATE_PARENT_REQUIRED');}
  // Named existence is advisory. Once observed, a denied native read is never
  // reinterpreted as absence or permission to create a replacement.
  let exists=false;try{await fs.lstat(destination);exists=true;}catch(error){if(error.code!=='ENOENT')throw fail('CTF_DELIVERY_MANIFEST_NOT_PRIVATE');}
  if(exists)prior=nativeJson(destination);
  if(!prior){
   try{await fs.lstat(destination+'.pending');throw fail('CTF_DELIVERY_PROVISION_PENDING');}
   catch(error){if(error.code!=='ENOENT')throw fail(error.code==='CTF_DELIVERY_PROVISION_PENDING'?error.code:'CTF_DELIVERY_MANIFEST_NOT_PRIVATE');}
  }
 }else{
  base=await privateJson(manifestPath);ctf=validateBase(base,admin);
  parent=await fs.realpath(path.dirname(outputPath));destination=path.join(parent,path.basename(outputPath));const repo=path.resolve(__dirname,'../..');
  const parentStat=await fs.stat(parent);if(!parentStat.isDirectory()||(parentStat.mode&0o077)||(typeof process.getuid==='function'&&parentStat.uid!==process.getuid()))throw fail('CTF_DELIVERY_PRIVATE_PARENT_REQUIRED');
  if(destination===repo||destination.startsWith(repo+path.sep)||destination===path.resolve(manifestPath))throw fail('CTF_DELIVERY_PRIVATE_DESTINATION_REQUIRED');
 }
 const fingerprint=crypto.createHash('sha256').update(JSON.stringify({cluster:base.cluster,ctf})).digest('hex');
 const client=clientFactory?clientFactory({connectionString:adminUrl,ssl}):new(require('pg').Client)({connectionString:adminUrl,ssl,application_name:'dvaia-ctf-delivery-provision',connectionTimeoutMillis:10000});
 let locked=false,handle;
 const authenticate=async configuration=>{const connectionString=configuration[KEY];const delivery=deliveryClientFactory?deliveryClientFactory({connectionString,ssl}):new(require('pg').Client)({connectionString,ssl,application_name:'dvaia-ctf-delivery-verify',connectionTimeoutMillis:5000,statement_timeout:2000});try{await delivery.connect();const row=(await delivery.query('SELECT session_user AS login,current_user AS effective,current_database() AS database')).rows[0];if(row?.login!==ROLE||row.effective!==ROLE||row.database!==ctf.database)throw fail('CTF_DELIVERY_LOGIN_MISMATCH');}finally{await delivery.end().catch(()=>{});}};
 try{
  await client.connect();await client.query("SELECT set_config('lock_timeout','1000ms',false),set_config('statement_timeout','5000ms',false)");await client.query('SELECT pg_advisory_lock(1886610804,41)');locked=true;
  const facts=(await client.query("SELECT system_identifier::text AS cluster,current_setting('server_version_num')::integer AS version FROM pg_control_system()")).rows[0];
  if(facts?.cluster!==base.cluster||Math.floor(facts.version/10000)!==18)throw fail('CTF_DELIVERY_CLUSTER_MISMATCH');
  const owner=(await client.query('SELECT r.rolname AS owner FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname=$1',[ctf.database])).rows[0];if(owner?.owner!==ctf.migrationRole)throw fail('CTF_DELIVERY_DATABASE_MISMATCH');
  if(platform!=='win32'){try{prior=await privateJson(destination);}catch(error){if(error.code!=='ENOENT')throw error;}}
  const roles=(await client.query('SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=$1',[ROLE])).rows;
  if(prior){
   if(prior.version!==1||prior.status!=='complete'||prior.baseFingerprint!==fingerprint||prior.cluster!==base.cluster||prior.database!==ctf.database||prior.role!==ROLE)throw fail('CTF_DELIVERY_MANIFEST_MISMATCH');
   let u;try{u=new URL(prior.configuration?.[KEY]);}catch{throw fail('CTF_DELIVERY_MANIFEST_MISMATCH');}
   if(u.host!==admin.host||u.pathname!=='/'+ctf.database||decodeURIComponent(u.username)!==ROLE||!u.password||u.search||u.hash||!['postgres:','postgresql:'].includes(u.protocol)||Object.keys(prior.configuration).join()!==KEY)throw fail('CTF_DELIVERY_MANIFEST_MISMATCH');
   if(roles.length!==1||!roles[0].rolcanlogin||['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls'].some(k=>roles[0][k]))throw fail('CTF_DELIVERY_ROLE_MISMATCH');
   if((await client.query('SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member OR r.oid=m.roleid WHERE r.rolname=$1 LIMIT 1',[ROLE])).rows.length)throw fail('CTF_DELIVERY_ROLE_MISMATCH');
   await authenticate(prior.configuration);
   return {status:'existing',configuration:prior.configuration,outputPath:destination};
  }
  try{await fs.lstat(destination+'.pending');throw fail('CTF_DELIVERY_PROVISION_PENDING');}catch(error){if(error.code!=='ENOENT')throw error;}
  if(roles.length)throw fail('CTF_DELIVERY_ROLE_COLLISION');
  const password=crypto.randomBytes(32).toString('hex'),url=new URL(admin);url.username=ROLE;url.password=password;url.pathname='/'+ctf.database;
  const manifest={version:1,status:'incomplete',baseFingerprint:fingerprint,cluster:base.cluster,database:ctf.database,role:ROLE,configuration:{[KEY]:url.href}};
  // An incomplete journal is never replayed: role creation may have committed.
  if(platform==='win32')privateJournal.createJournal({filePath:destination+'.pending',bytes:Buffer.from(JSON.stringify(manifest,null,2)+'\n')});
  else{
   handle=await fs.open(destination+'.pending','wx',0o600);
   const persist=async()=>{await handle.truncate(0);await handle.write(JSON.stringify(manifest,null,2)+'\n',0,'utf8');await handle.sync();};await persist();
   const journalDirectory=await fs.open(parent,'r');try{await journalDirectory.sync();}finally{await journalDirectory.close();}
  }
  await client.query(`CREATE ROLE ${ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`);
  await client.query(`GRANT CONNECT ON DATABASE "${ctf.database}" TO ${ROLE}`);
  await authenticate(manifest.configuration);
  manifest.status='complete';
  // The original private pending journal is never truncated after DDL.
  const atomicComplete=async()=>{
   if(platform==='win32'){privateJournal.createJournal({filePath:destination,bytes:Buffer.from(JSON.stringify(manifest,null,2)+'\n')});return;}
   const temporary=destination+'.complete-'+crypto.randomBytes(12).toString('hex');let result;try{result=await fs.open(temporary,'wx',0o600);await result.writeFile(JSON.stringify(manifest,null,2)+'\n');await result.sync();await result.close();result=null;try{await fs.lstat(destination);throw fail('CTF_DELIVERY_DESTINATION_COLLISION');}catch(error){if(error.code!=='ENOENT')throw error;}await fs.rename(temporary,destination);const dir=await fs.open(parent,'r');try{await dir.sync();}finally{await dir.close();}}finally{if(result)await result.close();await fs.unlink(temporary).catch(error=>{if(error.code!=='ENOENT')throw error;});}};
  if(completionWriter)await completionWriter(atomicComplete);else await atomicComplete();
  return {status:'created',configuration:manifest.configuration,outputPath:destination};
 }catch(error){throw fail(/^[A-Z0-9_]+$/.test(error.code||'')?error.code:'CTF_DELIVERY_PROVISION_FAILED');}
 finally{if(handle)await handle.close();if(locked)await client.query('SELECT pg_advisory_unlock(1886610804,41)').catch(()=>{});await client.end().catch(()=>{});}
}
return Object.freeze({provisionCtfDelivery});
}
const {provisionCtfDelivery}=createCtfDeliveryProvisioner();
module.exports={createCtfDeliveryProvisioner,provisionCtfDelivery};
