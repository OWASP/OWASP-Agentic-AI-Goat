'use strict';
// Opaque prospective original-writer capability. Plain observations are never admission.
const fs=require('node:fs'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto');
const prepared=new WeakMap(),admitted=new WeakMap(),consumed=new WeakMap(),execution=new WeakMap();
const failure=()=>Object.assign(Error('In-process maintenance admission unavailable'),{code:'APPLICATION_MAINTENANCE_PREPARATION_INVALID'});
const hash=x=>createHash('sha256').update(x).digest('hex');
const CURRENT_MANIFEST=require('./applicationMaintenanceInprocessSources-v342.json');
const RECOVERY_FILES=Object.freeze(Array.isArray(CURRENT_MANIFEST.recoveryFiles)?CURRENT_MANIFEST.recoveryFiles.slice():[]);
function readWithPolicy(file,workspace){
 if(process.platform==='win32'){
  // Preserve named absence only before opening the native durability handle.
  // A later native denial remains unknown, even if the name then disappears.
  try{fs.lstatSync(file);}catch(observation){if(observation.code==='ENOENT')throw Object.assign(failure(),{code:'ENOENT'});throw failure();}
  try{
   const native=require('../../scripts/lib/windows-private-state');
   const bytes=workspace?native.readAndFlushPrivateWorkspaceFile(file):native.readAndFlushPrivateFile(file);
   if(!Buffer.isBuffer(bytes)||bytes.length>1048576)throw failure();return bytes;
  }catch{throw failure();}
 }
 if(fs.realpathSync(path.dirname(file))!==path.dirname(file))throw failure();
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const a=fs.fstatSync(fd);if(!a.isFile()||a.uid!==process.getuid()||(a.mode&511)!==384||a.nlink!==1||a.size>1048576)throw failure();const bytes=Buffer.alloc(1048577);let n=0;while(n<bytes.length){const count=fs.readSync(fd,bytes,n,bytes.length-n,n);if(!count)break;n+=count;}const b=fs.fstatSync(fd),c=fs.lstatSync(file);if(n!==a.size||n>1048576||!c.isFile()||c.isSymbolicLink()||['dev','ino','size','mode','uid','nlink','mtimeMs','ctimeMs'].some(k=>a[k]!==b[k]||a[k]!==c[k]))throw failure();fs.fsyncSync(fd);return bytes.subarray(0,n);}finally{fs.closeSync(fd);}
}
// A workspace .env may have an ordinary readable parent; retained state files
// always require the strict private-parent policy. Both Windows reads flush
// the validated held native handle; POSIX reads retain their original fsync.
function privateRead(file){return readWithPolicy(file,false);}
function workspacePrivateRead(file){return readWithPolicy(file,true);}
function optionalPrivateRead(file){
 try{return privateRead(file);}catch(cause){if(cause.code==='ENOENT')return undefined;throw cause;}
}
function immutable(value){if(value&&typeof value==='object'){for(const v of Object.values(value))immutable(v);Object.freeze(value);}return value;}
function projection(value){return Object.freeze({...value,clean:Object.freeze({...value.clean}),binding:Object.freeze({...value.binding}),owner:immutable(structuredClone(value.owner)),stores:immutable(structuredClone(value.stores)),artifacts:immutable(structuredClone(value.artifacts)),retained:new Map([...value.retained].map(([k,b])=>[k,Buffer.from(b)])),originalBytes:Buffer.from(value.originalBytes),publicationBytes:Buffer.from(value.publicationBytes)});}
function sourceBinding(root){
 const manifest=require('./applicationMaintenanceInprocessSources-v342.json');
 if(manifest.version!==1||manifest.profile!=='canonical16-ctf-inprocess-v1'||!Array.isArray(manifest.recoveryFiles)||JSON.stringify(manifest.recoveryFiles)!==JSON.stringify([...new Set(manifest.recoveryFiles)].sort())||manifest.recoveryFiles.some(name=>!Object.hasOwn(manifest.files,name)))throw failure();
 const actual=[];function scan(directory){for(const entry of fs.readdirSync(directory,{withFileTypes:true})){const file=path.join(directory,entry.name);if(entry.isSymbolicLink())throw failure();if(entry.isDirectory())scan(file);else if(entry.name.endsWith('.sql'))actual.push(path.relative(root,file).split(path.sep).join('/'));}}scan(path.join(root,'db/postgres'));
 const expected=Object.keys(manifest.files).filter(p=>p.startsWith('db/postgres/')&&p.endsWith('.sql')).sort();if(JSON.stringify(actual.sort())!==JSON.stringify(expected))throw failure();
 for(const [name,expected]of Object.entries(manifest.files)){const file=path.join(root,name);if(!file.startsWith(root+path.sep)||fs.realpathSync(file)!==file||hash(fs.readFileSync(file))!==expected)throw failure();}
 return hash(JSON.stringify(manifest));
}
function recoverySourceBinding(root,admittedSha256){
 const current=CURRENT_MANIFEST,admitted=hash(JSON.stringify(current))===admittedSha256?current:null;
 if(!admitted)throw failure();
 for(const name of RECOVERY_FILES){const expected=current.files[name];if(!expected||admitted.files[name]!==expected)throw failure();const file=path.join(root,name);if(!file.startsWith(root+path.sep)||fs.realpathSync(file)!==file||hash(fs.readFileSync(file))!==expected)throw failure();}
 return hash(JSON.stringify(RECOVERY_FILES.map(name=>[name,current.files[name]])));
}
function state(token,identity,map=prepared){const value=map.get(token);if(!value||value.identity!==identity||value.used)throw failure();value.lease.assertHeld();value.lease.signal.throwIfAborted();execution.get(token)?.assertCurrent();return value;}
async function prepareInprocessAdmissionInternal({lease,root,homeDirectory,adminUrl}={},launch){
 // The accessor rejects arbitrary look-alike lease objects before reading configuration.
 const identity=require('./applicationMaintenanceLease').inprocessLeaseIdentity(lease);
 if(launch){await lease.assertExecutionReady();launch.assertCurrent();}
 require('../../scripts/application-node-runtime').assertSupportedApplicationNodeVersion(process.versions.node);
 if(require('../database/postgres').getPoolBudgetSnapshot().reserved!==1)throw failure();
 const canonical=fs.realpathSync(root);if(canonical!==path.resolve(__dirname,'../..')||root!==canonical)throw failure();
 const sourceRoot=root;if(launch){root=launch.installation.installationRoot;homeDirectory=launch.installation.homeDirectory;launch.assertCurrent();}
 const directory=path.join(fs.realpathSync(homeDirectory),'.dvaia',hash(root).slice(0,12));
 const sourceManifestSha256=sourceBinding(sourceRoot),config=require('../../scripts/lib/application-maintenance-plan-configuration').loadMaintenancePlanConfiguration({root,homeDirectory,adminUrl});
 if(!config.deliveryManifestPath)throw failure();
 const files=['administrator.json','provisioning.json','ctf-delivery.json'];const retained=new Map(files.map(name=>[name,privateRead(path.join(directory,name))]));
 const originalBytes=workspacePrivateRead(path.join(root,'.env'));const env=Object.freeze({...require('dotenv').parse(originalBytes),...config.environment});
 // Initializers still read process.env; deny mismatch instead of changing global credentials.
 for(const [key,value]of Object.entries(env))if(key!=='PG_ADMIN_DATABASE_URL'&&process.env[key]!==value)throw failure();
 const admin=require('../../scripts/lib/setup-administrator-journal').validateAdministratorJournal(retained.get('administrator.json'));
 const clean=await lease.assertClean();const operationId=randomUUID(),publicationId=randomUUID(),nonce=randomUUID();
 const observation=await require('../database/postgres/applicationMaintenanceStoreInspection').createApplicationMaintenanceStoreInspection({...config,environment:env,lease}).inspect();
 launch?.assertCurrent();
 if(observation.stores.length!==16||!observation.recordedBackendsAbsent)throw failure();
 for(const [name,bytes]of retained)if(!privateRead(path.join(directory,name)).equals(bytes))throw failure();
 if(!workspacePrivateRead(path.join(root,'.env')).equals(originalBytes)||sourceBinding(sourceRoot)!==sourceManifestSha256)throw failure();
 let saved;const savedBytes=optionalPrivateRead(path.join(directory,'ctf-authority.json'));
 if(savedBytes!==undefined){try{saved=require('../../scripts/install/ctf-authority-journal').validateCtfAuthorityJournal(JSON.parse(savedBytes));}catch{throw failure();}}
 if(saved?.version===1&&(!launch||saved.phase!=='complete'))throw failure();
 const owned=[];let ids,pointers,primary,legacyActivation;
 try{const pg=require('../database/postgres');for(const key of ['IDENTITY_MIGRATION_DATABASE_URL','CTF_MIGRATION_DATABASE_URL'])owned.push(pg.createPool(env,key));
  const read=async(pool,sql)=>{const r=await pool.query(sql);if(r.rows.length!==1)throw failure();return r.rows[0];};
  const account=(await owned[0].query('SELECT username,email,role,admin_level,password,is_active FROM identity.users WHERE username=$1',[admin.username])).rows;if(account.length!==1||account[0].email!==admin.email||account[0].role!=='super_admin'||account[0].admin_level!==2||account[0].is_active!==1||!await require('bcryptjs').compare(admin.password,account[0].password))throw failure();
  const identityStore=await read(owned[0],'SELECT store_id::text,(SELECT activation_id::text FROM identity.ctf_delivery_control WHERE singleton) AS activation_id FROM identity.ctf_bootstrap_store WHERE singleton'),ctfStore=await read(owned[1],'SELECT store_id::text,(SELECT activation_id::text FROM ctf.delivery_control WHERE singleton) AS activation_id FROM ctf.bootstrap_control WHERE singleton');
  ids={identityStoreId:identityStore.store_id,ctfStoreId:ctfStore.store_id};pointers=[identityStore.activation_id,ctfStore.activation_id];
  if(saved?.version===1)legacyActivation=await require('../database/postgres/ctfDeliveryActivation')
    .createCtfDeliveryActivation({identityPool:owned[0],ctfPool:owned[1]}).loadCurrent({signal:lease.signal});
 }catch(e){primary=e;}finally{const results=await Promise.allSettled(owned.map(async p=>{let timer;try{await Promise.race([p.end(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(failure()),3000);})]);}finally{clearTimeout(timer);}}));if(results.some(r=>r.status==='rejected'))throw Object.assign(Error('Owned maintenance preparation drain unknown'),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});}if(primary)throw failure();
 launch?.assertCurrent();
 if(pointers.some(id=>id&&(!saved||id!==saved.activationId)))throw failure();
 const binding={workspaceId:hash(root),provisioningSha256:hash(retained.get('provisioning.json')),...ids};
 if(saved&&JSON.stringify(saved.binding)!==JSON.stringify(binding))throw failure();
 if(saved?.version===1){
  if(!pointers.every(id=>id===saved.activationId))throw failure();
  const adopted=await require('../../scripts/install/ctf-authority-clean-adoption').adoptLegacyCtfAuthorityJournal({
    directory,originalBytes:savedBytes,binding,activation:legacyActivation,launch,lease});
  saved=require('../../scripts/install/ctf-authority-journal').validateCtfAuthorityJournal(JSON.parse(adopted.resultBytes));
 }
 if(saved&&saved.version!==2)throw failure();
 const bootstrapId=saved?.bootstrapId||randomUUID(),activationId=saved?.activationId||randomUUID();
 const ctf=require('../database/postgres/applicationMaintenanceReplayEncoding').encodeCtfReplayBinding({...binding,bootstrapId,activationId});
 // First profile makes no credential changes. It still durably journals exact original/result bytes.
 const publication=require('../../scripts/lib/setup-additive-environment-publication').prepareAdditiveEnvironmentPublication({root,directory,id:hash(root).slice(0,12),operationId:publicationId,originalBytes,encodedAdditions:''});
 const publicationBytes=privateRead(path.join(directory,`additive-environment-${publicationId}.json`));
 const artifacts=files.map(name=>({kind:name==='ctf-delivery.json'?'delivery':name.slice(0,-5),relativePath:name,schemaVersion:1,bindingSha256:hash(retained.get(name)),contentSha256:hash(retained.get(name)),artifactId:null}));
 artifacts.push({kind:'ctf-authority',relativePath:'ctf-authority.json',schemaVersion:2,bindingSha256:ctf.sha256,contentSha256:null,artifactId:activationId},{kind:'environment-publication',relativePath:`additive-environment-${publicationId}.json`,schemaVersion:1,bindingSha256:hash(publicationBytes),contentSha256:hash(publicationBytes),artifactId:publicationId});
 const encoded=require('../database/postgres/applicationMaintenanceReplayEncoding').encodeReplayArtifacts(artifacts);
 const processIdentity=require('../../scripts/lib/setup-local-process-identity'),owner=processIdentity.captureLocalAncestorBinding({workspaceRoot:root,installationId:clean.installationId,operationId});
 if(!processIdentity.isSupportedLocalAncestorBinding(owner)||owner.ancestors[0].pid!==process.pid)throw failure();
 const token=Object.freeze({});prepared.set(token,{identity,lease,root,sourceRoot,directory,env,clean,operationId,publicationId,nonce,binding,bootstrapId,activationId,owner,stores:observation.stores,sourceManifestSha256,artifacts,artifactManifestSha256:encoded.sha256,publicationSha256:hash(publicationBytes),publication,publicationBytes,retained,originalBytes,preparedAt:Date.now(),used:false});if(launch)execution.set(token,launch);return token;
}
async function prepareInprocessAdmission(options){try{if(!options||Object.getPrototypeOf(options)!==Object.prototype||Reflect.ownKeys(options).some(k=>!['lease','root','homeDirectory','adminUrl'].includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(options,k),'value')))throw failure();return await prepareInprocessAdmissionInternal(options);}catch(e){if(e?.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT')throw e;throw failure();}}
async function prepareProspectiveInprocessAdmission(options){
 const launch=await require('./applicationMaintenanceExecutionAdmission').admitOwnedLaunch(options);
 return prepareInprocessAdmissionInternal(options,launch);
}
function consumePrepared(token,identity){const value=state(token,identity);if(Date.now()-value.preparedAt>5000||sourceBinding(value.sourceRoot||value.root)!==value.sourceManifestSha256||!workspacePrivateRead(path.join(value.root,'.env')).equals(value.originalBytes)||!privateRead(path.join(value.directory,`additive-environment-${value.publicationId}.json`)).equals(value.publicationBytes))throw failure();for(const [name,bytes]of value.retained)if(!privateRead(path.join(value.directory,name)).equals(bytes))throw failure();const launch=execution.get(token);if(launch)launch.assertCurrent();value.used=true;const view=projection(value);consumed.set(view,value);if(launch)execution.set(view,launch);return view;}
function executionBinding(value){const launch=execution.get(value);if(!launch)return null;if(!consumed.has(value))throw failure();launch.assertCurrent();return launch.binding;}
function bindAdmitted(value,epoch){const original=consumed.get(value);if(!original)throw failure();consumed.delete(value);const token=Object.freeze({});admitted.set(token,{...original,epoch,used:false});const launch=execution.get(value);if(launch){launch.assertCurrent();execution.set(token,launch);}return token;}
function admittedState(token,identity){return projection(state(token,identity,admitted));}
function completedJournalSnapshot(token,identity){
 const a=state(token,identity,admitted),file=path.join(a.directory,'ctf-authority.json'),lock=file+'.lock';
 const absent=()=>{try{fs.lstatSync(lock);}catch(e){if(e.code==='ENOENT')return;throw failure();}throw failure();};
 absent();const bytes=privateRead(file),saved=require('../../scripts/install/ctf-authority-journal').validateCtfAuthorityJournal(JSON.parse(bytes));
 if(saved.version!==2||saved.phase!=='complete'||saved.bootstrapId!==a.bootstrapId||saved.activationId!==a.activationId||JSON.stringify(saved.binding)!==JSON.stringify(a.binding)||bytes.toString('utf8')!==JSON.stringify(saved,null,2)+'\n')throw failure();
 return Object.freeze({assertCurrent(){state(token,identity,admitted);absent();if(!privateRead(file).equals(bytes))throw failure();}});
}
function invalidateAdmitted(token){const value=admitted.get(token);if(value)value.used=true;}
module.exports={prepareProspectiveInprocessAdmission,executionBinding,prepareInprocessAdmission,consumePrepared,bindAdmitted,admittedState,invalidateAdmitted,completedJournalSnapshot,privateRead,workspacePrivateRead,optionalPrivateRead,sourceBinding,recoverySourceBinding,RECOVERY_FILES};
