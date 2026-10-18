'use strict';
// Supported activation requires exact applied migration and live capability checks.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const config=require('../../server/services/mcp/ownedHttpManagedConfiguration');
const {createOwnedHttpServiceClient}=require('../../server/services/mcp/ownedHttpServiceClient');
function createOwnedHttpActivator({filesystemPlatform=process.platform,privateState=require('../lib/windows-private-state'),privateJournal=require('../lib/windows-provisioning-journal'),fileSystem=require('node:fs'),configuration}={}){
 const nativePath=require('../lib/windows-private-state');
 configuration ||= config.createManagedConfiguration({filesystemPlatform,privateState,fileSystem});
async function activateOwnedHttpCandidate({file,identityPool,resourcePool,identityMigrationPool,resourceMigrationPool,cli,http}={}){
 if(!file||![identityPool,resourcePool,identityMigrationPool,resourceMigrationPool].every(p=>typeof p?.query==='function')||typeof cli?.readiness!=='function')throw TypeError('Explicit candidate stores and CLI readiness required');
 const windows=filesystemPlatform==='win32';let lock,temporary,lockSnapshot,directorySnapshot;
 const storageFailure=()=>Object.assign(Error('MCP_HTTP_CONFIGURATION_UNTRUSTED'),{code:'MCP_HTTP_CONFIGURATION_UNTRUSTED'});
 const validIdentity=value=>Number.isInteger(value?.volumeSerial)&&value.volumeSerial>=0&&value.volumeSerial<=0xffffffff&&typeof value.fileId==='string'&&/^[a-f0-9]{16}$/.test(value.fileId);
 const identityEqual=(a,b)=>validIdentity(a)&&validIdentity(b)&&a.volumeSerial===b.volumeSerial&&a.fileId===b.fileId;
 const lockPath=windows?nativePath.normalizePrivatePath(file+'.activation-lock'):file+'.activation-lock';
 const parent=windows?path.win32.dirname(nativePath.normalizePrivatePath(file)):path.dirname(file);
 const verifyDirectory=()=>{try{const current=privateState.inspectPrivateDirectory(parent);if(current?.path!==parent||!identityEqual(current.identity,directorySnapshot.identity))throw storageFailure();}catch{throw storageFailure();}};
 const checkLock=()=>{try{verifyDirectory();const current=privateState.readAndFlushPrivateFileSnapshot(lockPath);if(current?.path!==lockPath||!Buffer.isBuffer(current.bytes)||!current.bytes.equals(lockSnapshot.bytes)||!identityEqual(current.identity,lockSnapshot.identity))throw storageFailure();verifyDirectory();}catch{throw storageFailure();}};
 if(windows){
  try{
   privateJournal.inspectDestination({filePath:file});directorySnapshot=privateState.inspectPrivateDirectory(parent);
   if(directorySnapshot?.path!==parent||!Number.isInteger(directorySnapshot.identity?.volumeSerial)||directorySnapshot.identity.volumeSerial<0||directorySnapshot.identity.volumeSerial>0xffffffff||!/^[a-f0-9]{16}$/.test(directorySnapshot.identity?.fileId))throw storageFailure();
   const bytes=Buffer.from(JSON.stringify({version:1,nonce:crypto.randomBytes(32).toString('hex')})+'\n');
   // Strict CREATE_NEW is exclusion. Never adopt an identical retained lock;
   // uncertain acquisition stays retained, with no pathname deletion fallback.
   const created=privateState.createPrivateFile(lockPath,bytes),observed=privateState.readAndFlushPrivateFileSnapshot(lockPath);
   if(created?.path!==lockPath||created.size!==bytes.length||observed?.path!==lockPath||observed.size!==bytes.length||!Buffer.isBuffer(observed.bytes)||!observed.bytes.equals(bytes)||!identityEqual(created.identity,observed.identity))throw storageFailure();
   lockSnapshot=Object.freeze({bytes:Buffer.from(bytes),identity:Object.freeze({...observed.identity})});checkLock();
  }catch{throw storageFailure();}
 }else lock=await fs.open(lockPath,'wx',0o600);
 try{
  const captured=windows?configuration.loadSnapshot({file,flush:true}):null;
  const original=windows?captured?.value:configuration.load({file});if(!original)throw Error('MCP_HTTP_CONFIGURATION_REQUIRED');
  const source=windows?captured.bytes:await fs.readFile(file);
  for(const [pool,name,draft] of [[identityMigrationPool,'0083_mcp_http_operations.sql','identity-migrations/0083_mcp_http_operations.sql'],[resourceMigrationPool,'0005_mcp_http_child_leases.sql','workshop-migrations/mcp/0005_mcp_http_child_leases.sql']]){
   const bytes=await fs.readFile(path.resolve(__dirname,'../../db/postgres',draft));
   const row=(await pool.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[name])).rows[0];
   if(row?.checksum!==crypto.createHash('sha256').update(bytes).digest('hex'))throw Error('MCP_HTTP_MIGRATION_MISMATCH');
  }
  await require('../../server/database/postgres/mcpHttpReceiptRepository').createMcpHttpReceiptRepository(identityPool).checkReadiness();
  await require('../../server/database/postgres/mcpHttpLeaseRepository').createMcpHttpLeaseRepository(resourcePool).checkReadiness();
  const runner=await cli.readiness();if(runner?.ready!==true||runner.runnerReady!==true||runner.isolation!=='bwrap-seccomp-v1')throw Error('MCP_HTTP_CLI_NOT_READY');
  http ||=createOwnedHttpServiceClient({baseUrl:original.url,token:original.token});
  const status=await http.readiness();const manifest=await fs.readFile(path.resolve(__dirname,'../../sidecars/sandbox-runner/owned-http/network-manifest.json'));
  if(status?.ready!==true||status.manifestSha256!==crypto.createHash('sha256').update(manifest).digest('hex'))throw Error('MCP_HTTP_SERVICE_NOT_READY');
  if(windows){checkLock();const current=configuration.loadSnapshot({file,flush:true});if(!current||!current.bytes.equals(source)||!identityEqual(current.identity,captured.identity))throw Error('MCP_HTTP_CONFIGURATION_CHANGED');checkLock();}
  else{configuration.load({file});if(!(await fs.readFile(file)).equals(source))throw Error('MCP_HTTP_CONFIGURATION_CHANGED');}
  if(!original.enabled){
   if(windows){
    checkLock();
    try{privateJournal.updateJournal({filePath:file,originalBytes:source,resultBytes:Buffer.from(JSON.stringify({...original,enabled:true})+'\n')});}catch{throw Object.assign(Error('MCP_HTTP_CONFIGURATION_PUBLICATION_UNCERTAIN'),{code:'MCP_HTTP_CONFIGURATION_PUBLICATION_UNCERTAIN'});}
    checkLock();
   }else{
   temporary=file+'.activation-'+crypto.randomBytes(6).toString('hex');const handle=await fs.open(temporary,'wx',0o600);
   try{await handle.writeFile(JSON.stringify({...original,enabled:true})+'\n');await handle.sync();}finally{await handle.close();}
   await fs.rename(temporary,file);temporary=null;
   const dir=await fs.open(path.dirname(file),'r');try{await dir.sync();}finally{await dir.close();}
   }
  }
  return Object.freeze({ok:true,candidateOnly:false,activationEnabled:true,managedPath:file,objectiveRelease:true});
 }finally{
  if(windows){
   // File flush + exact held-handle removal are the bounded Windows protocol.
   // No directory-fsync equivalence or cleanup of uncertain publication intent.
   checkLock();
   try{privateState.deleteMatchingPrivateFile(lockPath,lockSnapshot.bytes,lockSnapshot.identity);verifyDirectory();
    try{fileSystem.lstatSync(lockPath);throw storageFailure();}catch(error){if(error.code!=='ENOENT')throw error;}
    verifyDirectory();
   }catch{throw storageFailure();}
  }else{await lock.close();await fs.unlink(lockPath);if(temporary)await fs.unlink(temporary).catch(()=>{});}
 }
}
 return Object.freeze({activateOwnedHttpCandidate});
}
const {activateOwnedHttpCandidate}=createOwnedHttpActivator();
async function provisionOwnedHttpCandidateForSetup({candidate=false,provisionOptions,activationOptions}={}){
 if(candidate!==true)return Object.freeze({available:false,candidateOnly:true,activationEnabled:false});
 const provisioned=await require('./mcp-owned-http').provision(provisionOptions);
 if(provisioned.ok!==true)throw Error('MCP_HTTP_PROVISION_FAILED');
 return activateOwnedHttpCandidate({...activationOptions,file:provisioned.managedPath});
}
module.exports={createOwnedHttpActivator,activateOwnedHttp:activateOwnedHttpCandidate,activateOwnedHttpCandidate,provisionOwnedHttpCandidateForSetup};
