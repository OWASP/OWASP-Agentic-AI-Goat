'use strict';
// Installed-data preservation entry. This holds the canonical maintenance
// exclusion lease around the existing read-only backup and publishes separate
// evidence; it never changes the backup manifest's deliberately limited claim.
const fs=require('node:fs'),path=require('node:path'),net=require('node:net'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {provisioningPlan}=require('../../db/postgres/provision-application');
const ROOT=path.resolve(__dirname,'../..');
const PORTS=Object.freeze([3000,8081,8082]),HOSTS=Object.freeze(['127.0.0.1','::1']);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function privateFile(file,limit=1024*1024){
 assert(path.isAbsolute(file)&&fs.realpathSync(file)===file,'Private canonical file required');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const before=fs.fstatSync(fd);assert(before.isFile()&&before.uid===process.getuid()&&(before.mode&511)===384&&before.nlink===1&&before.size<=limit,'Private file required');const bytes=Buffer.alloc(before.size+1);let length=0,count;while(length<bytes.length&&(count=fs.readSync(fd,bytes,length,bytes.length-length,length)))length+=count;const after=fs.fstatSync(fd),named=fs.lstatSync(file);assert.equal(length,before.size);for(const key of ['dev','ino','size','mode','uid','nlink','mtimeMs','ctimeMs'])assert.equal(after[key],before[key]);assert(named.isFile()&&!named.isSymbolicLink()&&named.dev===before.dev&&named.ino===before.ino&&named.nlink===1);return bytes.subarray(0,length);}finally{fs.closeSync(fd);}
}
function portOpen(host,port,{createConnection=net.createConnection}={}){
 return new Promise((resolve,reject)=>{let settled=false,socket;const finish=(fn,value)=>{if(settled)return;settled=true;try{socket?.destroy();}catch{}fn(value);};
  try{socket=createConnection({host,port});socket.setTimeout(250);socket.once('connect',()=>finish(resolve,{status:'open'}));socket.once('timeout',()=>finish(reject,Object.assign(Error('A21_LISTENER_PROBE_TIMEOUT'),{code:'A21_LISTENER_PROBE_TIMEOUT'})));socket.once('error',error=>{
   if(error?.code==='ECONNREFUSED')finish(resolve,{status:'absent',reason:'ECONNREFUSED'});
   else if(host==='::1'&&['EAFNOSUPPORT','EADDRNOTAVAIL','ENETUNREACH'].includes(error?.code))finish(resolve,{status:'unsupported',reason:error.code});
   else finish(reject,Object.assign(Error('A21_LISTENER_PROBE_FAILED'),{code:'A21_LISTENER_PROBE_FAILED'}));
  });}catch{finish(reject,Object.assign(Error('A21_LISTENER_PROBE_FAILED'),{code:'A21_LISTENER_PROBE_FAILED'}));}
 });
}
async function absentListeners({probe=portOpen}={}){
 const checked=[];for(const host of HOSTS)for(const port of PORTS){const result=await probe(host,port);if(result?.status==='open')throw Object.assign(Error('A21_APPLICATION_LISTENER_PRESENT'),{code:'A21_APPLICATION_LISTENER_PRESENT'});if(result?.status==='unsupported'){assert.equal(host,'::1');assert(['EAFNOSUPPORT','EADDRNOTAVAIL','ENETUNREACH'].includes(result.reason));}else{assert.equal(result?.status,'absent');assert.equal(result.reason,'ECONNREFUSED');}checked.push({host,port,status:result.status,reason:result.reason});}
 return Object.freeze({observedAt:new Date().toISOString(),checked:Object.freeze(checked)});
}
function listenerEvidence(value){
 assert(Number.isFinite(Date.parse(value?.observedAt)));assert(Array.isArray(value.checked)&&value.checked.length===HOSTS.length*PORTS.length);const seen=new Set();
 for(const row of value.checked){const key=`${row.host}\0${row.port}`;assert(HOSTS.includes(row.host)&&PORTS.includes(row.port)&&!seen.has(key));seen.add(key);if(row.status==='absent')assert.equal(row.reason,'ECONNREFUSED');else{assert.equal(row.host,'::1');assert.equal(row.status,'unsupported');assert(['EAFNOSUPPORT','EADDRNOTAVAIL','ENETUNREACH'].includes(row.reason));}}
 for(const host of HOSTS)for(const port of PORTS)assert(seen.has(`${host}\0${port}`));return value;
}
function optionalPrivateDigest(file){try{return sha(privateFile(file));}catch(error){if(error.code==='ENOENT')return null;throw error;}}
function configurationBinding({root=ROOT,environment,manifestPath,deliveryManifestPath}){
 const envPath=path.join(root,'.env'),bytes=privateFile(envPath),parsed=require('dotenv').parse(bytes),keys=provisioningPlan().flatMap(row=>[row.runtimeVariable,row.migrationVariable]).concat(['PG_TLS','CTF_DELIVERY_DATABASE_URL']),selected={};
 for(const key of keys)if(Object.hasOwn(environment,key)){assert.equal(parsed[key],environment[key],`Inspected configuration differs: ${key}`);selected[key]=environment[key];}else assert(!Object.hasOwn(parsed,key),`Uninspected configuration present: ${key}`);
 assert.equal(typeof environment.PG_ADMIN_DATABASE_URL,'string');assert.equal(typeof manifestPath,'string');const directory=path.dirname(manifestPath);
 return Object.freeze({workspaceEnvSha256:sha(bytes),selectedConfigurationSha256:sha(Buffer.from(JSON.stringify(selected))),adminConfigurationSha256:sha(Buffer.from(environment.PG_ADMIN_DATABASE_URL)),provisioningManifestSha256:sha(privateFile(manifestPath)),deliveryManifestSha256:deliveryManifestPath?sha(privateFile(deliveryManifestPath)):null,localPostgresManifestSha256:optionalPrivateDigest(path.join(directory,'local-postgres.json'))});
}
function inspectionEvidence(value){
 assert.equal(value?.recordedBackendsAbsent,true);assert.equal(value?.recoveryAuthorized,false);assert.equal(value?.stores?.length,16);
 const inventory=value.stores.map(row=>({storeKey:row.storeKey,clusterIdentifier:String(row.clusterIdentifier),databaseOid:Number(row.databaseOid),databaseName:row.databaseName,runtimeRole:row.runtimeRole,migrationRole:row.migrationRole,deliveryRole:row.deliveryRole,endpointPolicySha256:row.endpointPolicySha256}));
 assert.equal(new Set(inventory.map(row=>row.storeKey)).size,16);
 return Object.freeze({observedAt:value.observedAt,storeCount:16,recordedBackendsAbsent:true,storeInventorySha256:sha(Buffer.from(JSON.stringify(inventory)))});
}
function assertReceiptTimeline(value){const order=[value.leaseInterval.acquiredAt,value.listeners.before.observedAt,value.inspections.before.observedAt,value.leaseInterval.backupStartedAt,value.leaseInterval.backupFinishedAt,value.inspections.after.observedAt,value.listeners.after.observedAt,value.leaseInterval.releasedAt].map(Date.parse);assert(order.every(Number.isFinite));for(let i=1;i<order.length;i++)assert(order[i]>=order[i-1],'A21 receipt timeline is outside lease order');}
function publishReceipt(file,value){
 const parent=fs.realpathSync(path.dirname(file)),expected=path.join(parent,path.basename(file));assert.equal(file,expected);const directoryStat=fs.lstatSync(parent);assert(directoryStat.isDirectory()&&!directoryStat.isSymbolicLink()&&directoryStat.uid===process.getuid()&&(directoryStat.mode&511)===448);
 const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');assert(bytes.length<=1024*1024);const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,384);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}const directory=fs.openSync(parent,fs.constants.O_RDONLY);try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}return Object.freeze({path:file,sha256:sha(bytes)});
}
async function createQuietBackup({output,root=ROOT,homeDirectory},api={}){
 const load=api.load||require('../../scripts/lib/application-maintenance-plan-configuration').loadMaintenancePlanConfiguration;
 const acquire=api.acquire||require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease;
 const createInspection=api.createInspection||require('../../server/database/postgres/applicationMaintenanceStoreInspection').createApplicationMaintenanceStoreInspection;
 const backup=api.backup||require('../../scripts/backup-installed-application').backup;
 const listeners=api.listeners||absentListeners;
 const bindConfiguration=api.configurationBinding||configurationBinding;
 assert.equal(root,ROOT,'A21 main workspace required');assert(path.isAbsolute(output)&&path.dirname(output)===path.join(ROOT,'backups','private-recovery')&&!fs.existsSync(output),'A21 new private backup destination required');
 const config=load({root,homeDirectory}),configuration=bindConfiguration({root,...config});let acquiredAt,lease,primary,closed;
 const receiptPath=path.join(output,'a21-quiet-backup.json');let before,after,beforeListeners,afterListeners,backupStartedAt,backupFinishedAt,backupResult;
 try{
  lease=await acquire({mode:'maintenance',env:config.environment});acquiredAt=new Date().toISOString();lease.assertHeld();await lease.assertClean();lease.assertHeld();
  beforeListeners=listenerEvidence(await listeners());lease.assertHeld();before=inspectionEvidence(await createInspection({...config,lease}).inspect());lease.assertHeld();
  backupStartedAt=new Date().toISOString();backupResult=await backup({output,excludeHistoricalArchives:true});backupFinishedAt=new Date().toISOString();lease.assertHeld();const reloaded=load({root,homeDirectory});assert.equal(reloaded.manifestPath,config.manifestPath);assert.equal(reloaded.deliveryManifestPath,config.deliveryManifestPath);assert.deepEqual(bindConfiguration({root,...reloaded}),configuration);
  after=inspectionEvidence(await createInspection({...reloaded,lease}).inspect());lease.assertHeld();assert.equal(after.storeInventorySha256,before.storeInventorySha256,'A21 store identity changed during backup');afterListeners=listenerEvidence(await listeners());lease.assertHeld();
 }catch(error){primary=error;
 }finally{if(lease)try{closed=await lease.close();}catch(error){primary=primary?new AggregateError([primary,error],'A21 quiet backup and lease cleanup failed'):error;}}
 if(primary)throw primary;
 assert.deepEqual(closed,{closed:true,lost:false});
 const manifestPath=path.join(output,'manifest.json'),manifestBytes=privateFile(manifestPath,16*1024*1024),manifest=JSON.parse(manifestBytes);
 assert.equal(manifest.status,'backed-up-not-restored');assert.equal(manifest.crossStoreConsistent,false);assert.equal(manifest.activationReady,false);assert.equal(Object.keys(manifest.stores||{}).length,16);assert.deepEqual(backupResult,{status:'backed-up-not-restored',stores:16,activationReady:false});
 const receipt={version:1,scope:'a21-supported-writer-quiescent-backup',status:'passed',workspace:ROOT,
  observedScope:{writerAuthority:'supported-application',exclusion:'canonical-exclusive-application-maintenance-lease',stores:16,unsupportedTransientClients:'pre-and-post-observation-only',listenerPolicy:'refused-or-documented-ipv6-unsupported'},
  leaseInterval:{acquiredAt,backupStartedAt,backupFinishedAt,releasedAt:new Date().toISOString(),heldThroughPostInspection:true,closed:true,lost:false},
  configuration,listeners:{ports:[...PORTS],hosts:[...HOSTS],before:beforeListeners,after:afterListeners},inspections:{before,after},
  backup:{manifestPath,manifestSha256:sha(manifestBytes),manifestBytes:manifestBytes.length,status:manifest.status,stores:16,activationReady:false,crossStoreConsistent:false},
  originalManifestClaimPreserved:true};assertReceiptTimeline(receipt);
 return Object.freeze({...publishReceipt(receiptPath,receipt),value:Object.freeze(receipt)});
}
function parseArgs(argv){if(argv.length!==2||argv[0]!=='--output'||!path.isAbsolute(argv[1]))throw TypeError('Usage: populated16-quiet-backup.cjs --output <new absolute main/backups/private-recovery/directory>');return{output:argv[1]};}
if(require.main===module){let options;try{options=parseArgs(process.argv.slice(2));}catch(error){process.stderr.write(error.message+'\n');process.exitCode=1;}if(options)createQuietBackup(options).then(result=>process.stdout.write(JSON.stringify({status:'passed',receipt:result.path,receiptSha256:result.sha256})+'\n'),()=>{process.stderr.write('A21_QUIET_BACKUP_FAILED\n');process.exitCode=1;});}
module.exports={privateFile,portOpen,absentListeners,listenerEvidence,configurationBinding,inspectionEvidence,assertReceiptTimeline,publishReceipt,createQuietBackup,parseArgs};
