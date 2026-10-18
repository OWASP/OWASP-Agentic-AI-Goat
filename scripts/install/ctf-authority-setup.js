'use strict';
// Installer-only. Existing exclusive maintenance scope is mandatory; never recovers a dirty epoch.
const fs=require('node:fs/promises'),path=require('node:path'),{constants}=require('node:fs'),{createHash}=require('node:crypto');
const scopeTools=require('../lib/application-maintenance-scope');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {provisioningPlan}=require('../../db/postgres/provision-application');
const {withCtfTransaction}=require('../../server/database/postgres/ctfLifecycleRepository');
const {createCtfAuthorityBootstrapRepository}=require('../../server/database/postgres/ctfAuthorityBootstrapRepository');
const {createCtfAuthorityBootstrap}=require('../../server/services/ctfAuthorityBootstrap');
const {createCtfDeliveryActivationOperator}=require('../../server/database/postgres/ctfDeliveryActivationOperator');
const {createCtfDeliveryActivation}=require('../../server/database/postgres/ctfDeliveryActivation');
const {withCtfAuthorityJournal}=require('./ctf-authority-journal');
const hash=x=>createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(Error(code),{code});
function createCtfAuthoritySetup({filesystemPlatform=process.platform,privateState}={}){
 const storagePath=filesystemPlatform==='win32'?path.win32:path;
 const native=()=>privateState||require('../lib/windows-private-state');
 const parseManifest=bytes=>{try{return JSON.parse(bytes);}catch(error){if(filesystemPlatform==='win32')throw fail('CTF_SETUP_MANIFEST_CONFLICT');throw error;}};
 async function privateBytes(file){
 if(filesystemPlatform==='win32'){try{const bytes=native().readPrivateFile(file);if(!Buffer.isBuffer(bytes)||bytes.length>262144)throw Error();return bytes;}catch{throw fail('CTF_SETUP_PRIVATE_PATH');}}
 if(await fs.realpath(path.dirname(file))!==path.dirname(file))throw fail('CTF_SETUP_PRIVATE_PATH');
 const h=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const s=await h.stat();if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.nlink!==1||s.size>262144)throw fail('CTF_SETUP_PRIVATE_PATH');const buffer=Buffer.alloc(262145);let length=0;while(length<buffer.length){const r=await h.read(buffer,length,buffer.length-length,length);if(!r.bytesRead)break;length+=r.bytesRead;}const after=await h.stat();const linked=await fs.lstat(file);if(!after.isFile()||after.uid!==process.getuid()||(after.mode&0o777)!==0o600||after.nlink!==1||!linked.isFile()||linked.isSymbolicLink()||linked.uid!==process.getuid()||(linked.mode&0o777)!==0o600||linked.nlink!==1||length!==s.size||length>262144||after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||linked.dev!==s.dev||linked.ino!==s.ino)throw fail('CTF_SETUP_PRIVATE_PATH');return buffer.subarray(0,length);}finally{await h.close();}
}
async function prepareCtfAuthority({root,directory,environment,maintenanceScope}){
 const env=Object.freeze({...environment});scopeTools.assertApplicationMaintenanceScope(maintenanceScope,env);
 const signal=AbortSignal.any([AbortSignal.timeout(120000),...(maintenanceScope.signal?[maintenanceScope.signal]:[])]);
 const check=()=>{signal.throwIfAborted();scopeTools.assertApplicationMaintenanceScope(maintenanceScope,env);};
 const owned=[];let primary,result;
 try{
  if(!storagePath.isAbsolute(root)||!storagePath.isAbsolute(directory))throw fail('CTF_SETUP_PRIVATE_PATH');
  if(filesystemPlatform==='win32'){try{const normalized=native().normalizePrivatePath(directory),observed=native().inspectPrivateDirectory(directory);if(normalized!==directory||observed?.path!==directory)throw Error();}catch{throw fail('CTF_SETUP_PRIVATE_PATH');}}
  else if(await fs.realpath(directory)!==directory)throw fail('CTF_SETUP_PRIVATE_PATH');
  const baseBytes=await privateBytes(storagePath.join(directory,'provisioning.json')),base=parseManifest(baseBytes);
  const delivery=parseManifest(await privateBytes(storagePath.join(directory,'ctf-delivery.json')));
  if(base.version!==1||base.status!=='complete'||JSON.stringify(base.plan)!==JSON.stringify(provisioningPlan())||delivery.version!==1||delivery.status!=='complete'||delivery.cluster!==base.cluster||delivery.role!=='dvaia_ctf_delivery'||delivery.configuration?.CTF_DELIVERY_DATABASE_URL!==env.CTF_DELIVERY_DATABASE_URL)throw fail('CTF_SETUP_MANIFEST_CONFLICT');
  for(const key of ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL','CTF_DATABASE_URL','CTF_MIGRATION_DATABASE_URL'])if(typeof env[key]!=='string'||env[key]!==base.configuration?.[key])throw fail('CTF_SETUP_CONFIGURATION_CONFLICT');
  const identityPool=createPool(env,'IDENTITY_MIGRATION_DATABASE_URL');owned.push(identityPool);
  const ctfPool=createPool(env,'CTF_MIGRATION_DATABASE_URL');owned.push(ctfPool);
  // Existing stores need ledger-aware pending migrations too. No seed, reset or history replacement.
  for(const [pool,dir] of [[identityPool,'identity-migrations'],[ctfPool,'workshop-migrations/ctf']]){check();const schema=dir==='identity-migrations'?'identity':'ctf';
   await withCtfTransaction(pool,async client=>{const r=(await client.query('SELECT current_user AS role,session_user AS login')).rows[0];if(r?.role!==`dvaia_${schema}_migration`||r.login!==r.role)throw fail('CTF_SETUP_ROLE_REQUIRED');},{signal});
   await migrate(pool,path.join(__dirname,'../../db/postgres',dir));check();}
  const tx=(pool,work)=>withCtfTransaction(pool,work,{signal});
  const inspect=async(pool,schema)=>tx(pool,async c=>{
   const role=(await c.query('SELECT current_user AS role,session_user AS login')).rows[0];if(role?.role!==`dvaia_${schema}_migration`||role.login!==role.role)throw fail('CTF_SETUP_ROLE_REQUIRED');
   const store=(await c.query(`SELECT store_id::text FROM ${schema}.${schema==='ctf'?'bootstrap_control':'ctf_bootstrap_store'} WHERE singleton`)).rows[0];
   const pointer=(await c.query(`SELECT activation_id::text FROM ${schema}.${schema==='ctf'?'delivery_control':'ctf_delivery_control'} WHERE singleton`)).rows[0];
   if(!store?.store_id||!pointer)throw fail('CTF_SETUP_STATE_UNAVAILABLE');return{storeId:store.store_id,activationId:pointer.activation_id};
  });
  check();const i=await inspect(identityPool,'identity'),c=await inspect(ctfPool,'ctf');check();
  const binding={workspaceId:hash(await fs.realpath(root)),provisioningSha256:hash(baseBytes),identityStoreId:i.storeId,ctfStoreId:c.storeId};
  const verifier=createCtfDeliveryActivation({identityPool,ctfPool});
  // Do not mint a new journal for an already-active database pair.
  if(i.activationId||c.activationId)await privateBytes(storagePath.join(directory,'ctf-authority.json'));
  result=await withCtfAuthorityJournal({directory,binding,...(scopeTools.hasPreparedMaintenanceScope(maintenanceScope)?scopeTools.preparedMaintenanceJournalOptions(maintenanceScope):{})},async journal=>{
   let saved=await journal.read();check();
   const bind=t=>{if(t.activation_id!==saved.activationId||t.bootstrap_operation_id!==saved.bootstrapId||t.identity_store_id!==i.storeId||t.ctf_store_id!==c.storeId)throw fail('CTF_SETUP_ACTIVATION_CONFLICT');return t;};
   if(i.activationId&&c.activationId){const active=bind(await verifier.loadCurrent({signal}));check();await journal.advance({phase:'complete',checkpoint:{sourceRevision:active.source_revision,manifestSha256:active.manifest_sha256,authoritySha256:active.authority_sha256}});return{state:'active',changed:false,trafficStarted:false};}
   if((i.activationId&&i.activationId!==saved.activationId)||(c.activationId&&c.activationId!==saved.activationId)||saved.phase==='complete')throw fail('CTF_SETUP_ACTIVATION_CONFLICT');
   const repository=createCtfAuthorityBootstrapRepository({identityPool,ctfPool});
   if(!i.activationId&&!c.activationId&&['initialized','preparing'].includes(saved.phase)){
    await journal.advance({phase:'preparing',checkpoint:saved.checkpoint});check();
    const prepared=await createCtfAuthorityBootstrap({repository}).prepare({operationId:saved.bootstrapId,signal});check();
    if(!prepared.prepared)throw fail('CTF_SETUP_NOT_PREPARED');
    saved=await journal.advance({phase:'prepared',checkpoint:{sourceRevision:prepared.revision,manifestSha256:prepared.manifestSha256,authoritySha256:null}});
   }
   if(!(await repository.preparationStatus(saved.bootstrapId,{signal})).prepared)throw fail('CTF_SETUP_NOT_PREPARED');check();
   saved=await journal.advance({phase:'activating',checkpoint:saved.checkpoint});
   const operator=createCtfDeliveryActivationOperator({identityMigrationPool:identityPool,ctfMigrationPool:ctfPool});let activated;
   do{check();activated=await operator.activate({activationId:saved.activationId,bootstrapOperationId:saved.bootstrapId,pageBudget:16},{signal});check();}while(activated.staged===true);
   const active=bind(await verifier.verify(activated.activation,{signal}));check();
   await journal.advance({phase:'complete',checkpoint:{sourceRevision:active.source_revision,manifestSha256:active.manifest_sha256,authoritySha256:active.authority_sha256}});
   return{state:'active',changed:true,trafficStarted:false};
  });check();
 }catch(error){primary=error;scopeTools.invalidateApplicationMaintenanceScope(maintenanceScope);}
 const cleanup=await Promise.allSettled(owned.map(pool=>pool.end()));const errors=cleanup.filter(x=>x.status==='rejected').map(x=>x.reason);
 if(primary||errors.length)throw new AggregateError([...(primary?[primary]:[]),...errors],'CTF setup unavailable');
 check();return Object.freeze(result);
}
 return Object.freeze({prepareCtfAuthority});
}
module.exports={...createCtfAuthoritySetup(),createCtfAuthoritySetup};
