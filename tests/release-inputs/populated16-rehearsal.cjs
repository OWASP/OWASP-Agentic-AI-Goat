'use strict';
// Main-only work adapter. Resource ownership belongs to the existing native launcher.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const MAIN=path.resolve(__dirname,'../..');
let currentStage='entry', admittedEvidence=null;
const comparisonFailures=new WeakMap();
const FAILURE_CODES=new Set(['ERR_ASSERTION','ENOENT','EEXIST','EACCES','ETIMEDOUT','CHILD_FAILED','CHILD_TIMEOUT','SETUP_PHASE_FAILED','SETUP_PHASE_REQUEST_INVALID','SETUP_PHASE_PUBLICATION_MISSING','SETUP_PHASE_PUBLICATION_INVALID','SETUP_PHASE_TERMINATION_UNCERTAIN','SETUP_PHASE_CANCELLED','SETUP_PHASE_SPAWN_FAILED','ANALYTICS_UPGRADE_FLAG_REQUIRED','UPGRADE_ENV_RECOVERY_REQUIRED','UPGRADE_PRIVATE_STATE_INVALID','EXISTING_ENV_REQUIRED','EXISTING_MANIFEST_REQUIRED','UPGRADE_ENV_MANIFEST_MISMATCH','UPGRADE_ENV_CONFLICT','INVALID_APPLICATION_DATA_ROOT','LOCAL_DOCKER_UNAVAILABLE','LOCAL_DOCKER_AUTHORITY_INVALID','23505','23503','23514','42501','42P01','42703','25P02']);
// Literal categories from the delivery provisioner/setup adapter only. Do not
// publish arbitrary wrapped codes or diagnostic messages from PostgreSQL.
const DELIVERY_FAILURE_CODES=new Set([
 'CTF_DELIVERY_ADMIN_URL_INVALID','CTF_DELIVERY_BASE_INVALID','CTF_DELIVERY_CLUSTER_MISMATCH',
 'CTF_DELIVERY_CONFIGURATION_CONFLICT','CTF_DELIVERY_CONFIGURATION_INVALID','CTF_DELIVERY_DATABASE_MISMATCH',
 'CTF_DELIVERY_DESTINATION_COLLISION','CTF_DELIVERY_LOGIN_MISMATCH','CTF_DELIVERY_MANIFEST_MISMATCH',
 'CTF_DELIVERY_MANIFEST_NOT_PRIVATE','CTF_DELIVERY_PRIVATE_DESTINATION_REQUIRED','CTF_DELIVERY_PRIVATE_PARENT_REQUIRED',
 'CTF_DELIVERY_PROVISION_FAILED','CTF_DELIVERY_PROVISION_PENDING','CTF_DELIVERY_ROLE_COLLISION',
 'CTF_DELIVERY_ROLE_MISMATCH','CTF_DELIVERY_TLS_INVALID','CTF_DELIVERY_TLS_REQUIRED',
]);
for(const code of [...DELIVERY_FAILURE_CODES,'08001','08006','08P01','28000','28P01','3D000','42601','42710','53300','57P03','ECONNREFUSED','ECONNRESET','EPIPE','EPERM','ENOSPC'])FAILURE_CODES.add(code);
function failureCode(error){return FAILURE_CODES.has(error?.code)?error.code:DELIVERY_FAILURE_CODES.has(error?.message)?error.message:null;}
for(const code of ['SECURESHOP_MANAGED_CONFIGURATION_INVALID','SECURESHOP_MANAGED_CONFIGURATION_UNTRUSTED','SECURESHOP_FIXTURE_ROOT_UNTRUSTED','MCP_MANAGED_CONFIGURATION_INVALID','MCP_MANAGED_CONFIGURATION_UNTRUSTED','ANALYTICS_MANAGED_CONFIGURATION_INVALID','COUPON_MANAGED_CONFIGURATION_INVALID'])FAILURE_CODES.add(code);
function sourceFrames(error){
 const stack=typeof error?.stack==='string'?error.stack.slice(0,65536):'',frames=[];
 for(const line of stack.split('\n').slice(1)){const index=line.indexOf(MAIN+path.sep);if(index<0)continue;
  const match=line.slice(index+MAIN.length+1).match(/^([A-Za-z0-9_.\/-]+\.(?:js|cjs|mjs)):(\d{1,8}):(\d{1,8})\)?$/);
  if(match&&!match[1].split('/').includes('..'))frames.push({file:match[1],line:Number(match[2]),column:Number(match[3])});if(frames.length===8)break;
 }return frames;
}
function boundedPreservationComparison(error){
 const candidate=comparisonFailures.get(error)||error?.preservationComparison;
 if(!candidate||typeof candidate!=='object'||!Object.hasOwn(candidate,'table')||!Object.hasOwn(candidate,'missing')||!Object.hasOwn(candidate,'added'))return null;
 const {store,table,missing,added}=candidate;
 if(store!==undefined&&(typeof store!=='string'||!/^[a-z_]{1,63}$/.test(store)))return null;
 if(typeof table!=='string'||!/^[a-z_]{1,63}\.[a-z_]{1,63}$/.test(table))return null;
 if(!Number.isSafeInteger(missing)||missing<0||!Number.isSafeInteger(added)||added<0)return null;
 return Object.freeze({...(store===undefined?{}:{store}),table,missing,added});
}
function boundedRestoreComparison(error){
 const candidate=comparisonFailures.get(error);
 if(!candidate||typeof candidate!=='object'||!['toc','schema','rows-ledger','sequences'].includes(candidate.kind)
   ||!/^[a-f0-9]{64}$/.test(candidate.actualSha256||'')||!/^[a-f0-9]{64}$/.test(candidate.expectedSha256||''))return null;
 const result={kind:candidate.kind,actualSha256:candidate.actualSha256,expectedSha256:candidate.expectedSha256};
 if(candidate.artifacts!==undefined){
  if(candidate.kind!=='schema'||!Array.isArray(candidate.artifacts)||candidate.artifacts.length!==2)return null;
  const expected=['restore-schema-before.sql','restore-schema-after.sql'];
  if(!candidate.artifacts.every((row,index)=>row&&typeof row==='object'&&row.name===expected[index]
    &&Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=16*1024*1024&&/^[a-f0-9]{64}$/.test(row.sha256||'')))return null;
  result.artifacts=candidate.artifacts.map(({name,bytes,sha256})=>({name,bytes,sha256}));
 }else if(candidate.artifactFailure!==undefined){
  if(candidate.kind!=='schema'||candidate.artifactFailure!=='SCHEMA_EVIDENCE_UNAVAILABLE')return null;
  result.artifactFailure=candidate.artifactFailure;
 }
 return Object.freeze(result);
}
const MAX_PRESERVATION_DIAGNOSTICS=32;
const RETAINED_REHEARSAL_COHORTS=new Set(['restored-populated-upgrade','retained-ownership-migrations']);
function boundedCatalogFieldDiagnostic(error){
 const candidate=error?.catalogFieldDiagnostic;
 if(!candidate||typeof candidate!=='object'||!['exercise','objective'].includes(candidate.entityKind)
   ||typeof candidate.workshopKey!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(candidate.workshopKey)
   ||typeof candidate.objectiveId!=='string'
   ||(candidate.entityKind==='objective'&&!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(candidate.objectiveId))
   ||typeof candidate.fieldName!=='string'||!/^[a-z_]{1,63}$/.test(candidate.fieldName)
   ||!([null,'managed','custom','legacy_unknown'].includes(candidate.beforeState))
   ||!([null,'managed','custom','legacy_unknown'].includes(candidate.afterState)))return null;
 if((candidate.entityKind==='exercise')!== (candidate.objectiveId===''))return null;
 return Object.freeze({entityKind:candidate.entityKind,workshopKey:candidate.workshopKey,objectiveId:candidate.objectiveId,fieldName:candidate.fieldName,beforeState:candidate.beforeState,afterState:candidate.afterState});
}
function boundedProcessDiagnostic(error){
 const candidate=error?.privateDiagnostic;
 if(!candidate||typeof candidate!=='object'||typeof candidate.command!=='string'||!/^[A-Za-z0-9_.-]{1,128}$/.test(candidate.command)
   ||!(candidate.exitCode===null||Number.isSafeInteger(candidate.exitCode))
   ||!(candidate.signal===null||['SIGKILL','SIGTERM','SIGINT','SIGHUP'].includes(candidate.signal))
   ||!Number.isSafeInteger(candidate.stdoutBytes)||candidate.stdoutBytes<0||candidate.stdoutBytes>64*1024*1024
   ||typeof candidate.stdoutLimitExceeded!=='boolean'||!Number.isSafeInteger(candidate.stderrBytes)||candidate.stderrBytes<0||candidate.stderrBytes>64*1024*1024)return null;
 return Object.freeze({command:candidate.command,exitCode:candidate.exitCode,signal:candidate.signal,stdoutBytes:candidate.stdoutBytes,stdoutLimitExceeded:candidate.stdoutLimitExceeded,stderrBytes:candidate.stderrBytes});
}
function boundedPreservationDiagnostic(error){
 const candidate=error?.preservationDiagnostic;
 if(!candidate||typeof candidate!=='object'||!['comparison','catalog-transition','revision-transition','baseline-drop'].includes(candidate.phase)
   ||!/^[a-f0-9]{64}$/.test(candidate.querySha256||''))return null;
 const result={phase:candidate.phase,querySha256:candidate.querySha256};
 if(candidate.store!==undefined){if(typeof candidate.store!=='string'||!/^[a-z_]{1,63}$/.test(candidate.store))return null;result.store=candidate.store;}
 return Object.freeze(result);
}
function boundedPreservationComparisons(error){
 const candidate=error?.preservationComparisons;
 if(!candidate||typeof candidate!=='object'||!Array.isArray(candidate.entries)
   ||!Number.isSafeInteger(candidate.omitted)||candidate.omitted<0
   ||candidate.entries.length>MAX_PRESERVATION_DIAGNOSTICS)return null;
 const entries=[];
 for(const entry of candidate.entries){
  const bounded=boundedPreservationComparison({preservationComparison:entry});
  if(!bounded)return null;
  entries.push(bounded);
 }
 return Object.freeze({entries:Object.freeze(entries),omitted:candidate.omitted});
}
function failureProjection(error){
 const comparisons=boundedPreservationComparisons(error);
 const comparison=comparisons?null:(boundedPreservationComparison(error)||boundedRestoreComparison(error));
 const preservationDiagnostic=boundedPreservationDiagnostic(error),processDiagnostic=boundedProcessDiagnostic(error),catalogField=boundedCatalogFieldDiagnostic(error);
 return {status:'failed',stage:currentStage,installedWrites:false,...(comparisons?{comparisons}:comparison?{comparison}:{}),...(preservationDiagnostic?{preservationDiagnostic}:{}),...(catalogField?{catalogField}:{}),...(processDiagnostic?{processDiagnostic}:{}),error:{name:['AssertionError','AggregateError','TypeError','Error'].includes(error?.name)?error.name:'Error',code:failureCode(error)},frames:sourceFrames(error),causes:Array.isArray(error?.causes)?error.causes.filter(code=>FAILURE_CODES.has(code)).slice(0,8):[]};
}

function retainChildDiagnostic(error,evidence){
 const diagnostic=error?.privateDiagnostic;
 if(!diagnostic||!Buffer.isBuffer(diagnostic.stderr))return null;
 assert(path.isAbsolute(evidence)&&fs.realpathSync(evidence)===evidence);
 const st=fs.lstatSync(evidence);assert(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&511)===448);
 const journal=privateJson(path.join(evidence,'ownership.json')).value;
 assert.equal(journal.nativePid,process.pid);assert.equal(journal.owner,process.env.SETUP_PHASE_OWNER);
 assert(RETAINED_REHEARSAL_COHORTS.has(journal.cohort),'Unexpected rehearsal cohort');assert.equal(journal.sourceRoot,MAIN);
 const retained=diagnostic.stderr.subarray(0,16*1024),name='failed-child-stderr.bin';
 const fd=fs.openSync(path.join(evidence,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,384);
 try{fs.writeFileSync(fd,retained);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 const directory=fs.openSync(evidence,fs.constants.O_RDONLY);try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
 return {name,bytes:retained.length,sha256:sha(retained),truncated:diagnostic.stderrTruncated===true||diagnostic.stderr.length>retained.length};
}
function retainFailure(error,evidence){
 const result=failureProjection(error);
 try{const artifact=retainChildDiagnostic(error,evidence);if(artifact)result.diagnostic=artifact;}
 catch{result.diagnosticFailure='CHILD_DIAGNOSTIC_UNAVAILABLE';}
 return result;
}

const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const db=require('../../scripts/qualify-application-backups');
const backup=require('../../scripts/backup-installed-application');
const {provisioningPlan,provisionApplication}=require('../../db/postgres/provision-application');
const {prepareCtfDelivery}=require('../../scripts/install/ctf-delivery-setup');
const {OBJECTIVES}=require('../../server/config/secureshopCurriculum');
function fileHash(file,limit){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const st=fs.fstatSync(fd);assert(st.isFile()&&st.uid===process.getuid()&&st.nlink===1&&st.size<=limit);const hash=crypto.createHash('sha256'),buffer=Buffer.alloc(1024*1024);let total=0,n;while((n=fs.readSync(fd,buffer,0,buffer.length,null))){total+=n;assert(total<=limit);hash.update(buffer.subarray(0,n));}const after=fs.fstatSync(fd),linked=fs.lstatSync(file);for(const key of ['dev','ino','size','mtimeMs','ctimeMs'])assert.equal(after[key],st[key]);assert.equal(total,st.size);assert(!linked.isSymbolicLink()&&linked.dev===st.dev&&linked.ino===st.ino);return hash.digest('hex');}finally{fs.closeSync(fd);}}
function privateJson(file){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);assert(s.isFile()&&s.uid===process.getuid()&&(s.mode&511)===384&&s.size<=16*1024*1024);const b=Buffer.alloc(s.size+1);let n=0,r;while(n<b.length&&(r=fs.readSync(fd,b,n,b.length-n,null)))n+=r;const t=fs.fstatSync(fd),linked=fs.lstatSync(file);assert.equal(n,s.size);for(const key of ['dev','ino','size','mtimeMs','ctimeMs'])assert.equal(t[key],s[key]);assert.equal(linked.ino,s.ino);assert.equal(linked.dev,s.dev);assert(!linked.isSymbolicLink());return{bytes:b.subarray(0,n),value:JSON.parse(b.subarray(0,n))};}finally{fs.closeSync(fd);}}
function admitQuietBackupReceipt(file,expected,backupManifest,backupSha256){
 assert(path.isAbsolute(file)&&fs.realpathSync(file)===file&&path.dirname(file)===path.dirname(backupManifest));const stat=fs.lstatSync(file);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&511)===384&&stat.nlink===1&&stat.size<=1024*1024);
 const {bytes,value}=privateJson(file);assert.equal(sha(bytes),expected);assert.deepEqual(Object.keys(value).sort(),['backup','configuration','inspections','leaseInterval','listeners','observedScope','originalManifestClaimPreserved','scope','status','version','workspace']);
 assert.equal(value.version,1);assert.equal(value.scope,'a21-supported-writer-quiescent-backup');assert.equal(value.status,'passed');assert.equal(value.workspace,MAIN);assert.equal(value.originalManifestClaimPreserved,true);
 assert.deepEqual(value.observedScope,{writerAuthority:'supported-application',exclusion:'canonical-exclusive-application-maintenance-lease',stores:16,unsupportedTransientClients:'pre-and-post-observation-only',listenerPolicy:'refused-or-documented-ipv6-unsupported'});
 assert.deepEqual(Object.keys(value.configuration).sort(),['adminConfigurationSha256','deliveryManifestSha256','localPostgresManifestSha256','provisioningManifestSha256','selectedConfigurationSha256','workspaceEnvSha256']);for(const digest of Object.values(value.configuration))assert(digest===null||/^[a-f0-9]{64}$/.test(digest));for(const key of ['adminConfigurationSha256','provisioningManifestSha256','selectedConfigurationSha256','workspaceEnvSha256'])assert(/^[a-f0-9]{64}$/.test(value.configuration[key]));
 assert.equal(value.backup.manifestPath,backupManifest);assert.equal(value.backup.manifestSha256,backupSha256);assert.equal(value.backup.status,'backed-up-not-restored');assert.equal(value.backup.stores,16);assert.equal(value.backup.activationReady,false);assert.equal(value.backup.crossStoreConsistent,false);
 const manifestStat=fs.lstatSync(backupManifest);assert(manifestStat.isFile()&&!manifestStat.isSymbolicLink()&&manifestStat.nlink===1);assert.equal(value.backup.manifestBytes,manifestStat.size);
 const expectedListeners=new Set(value.listeners.hosts.flatMap(host=>value.listeners.ports.map(port=>`${host}\0${port}`)));
 for(const phase of ['before','after']){const observation=value.inspections[phase];assert.equal(observation.storeCount,16);assert.equal(observation.recordedBackendsAbsent,true);assert(/^[a-f0-9]{64}$/.test(observation.storeInventorySha256));assert(Number.isFinite(Date.parse(observation.observedAt)));const listener=value.listeners[phase];assert(Number.isFinite(Date.parse(listener.observedAt)));assert.equal(listener.checked.length,expectedListeners.size);const seen=new Set();for(const row of listener.checked){const key=`${row.host}\0${row.port}`;assert(expectedListeners.has(key)&&!seen.has(key));seen.add(key);if(row.status==='absent')assert.equal(row.reason,'ECONNREFUSED');else{assert.equal(row.host,'::1');assert.equal(row.status,'unsupported');assert(['EAFNOSUPPORT','EADDRNOTAVAIL','ENETUNREACH'].includes(row.reason));}}assert.equal(seen.size,expectedListeners.size);}
 assert.equal(value.inspections.after.storeInventorySha256,value.inspections.before.storeInventorySha256);
 assert.deepEqual(value.listeners.ports,[3000,8081,8082]);assert.deepEqual(value.listeners.hosts,['127.0.0.1','::1']);assert.equal(value.leaseInterval.heldThroughPostInspection,true);assert.equal(value.leaseInterval.closed,true);assert.equal(value.leaseInterval.lost,false);
 const times=[value.leaseInterval.acquiredAt,value.listeners.before.observedAt,value.inspections.before.observedAt,value.leaseInterval.backupStartedAt,value.leaseInterval.backupFinishedAt,value.inspections.after.observedAt,value.listeners.after.observedAt,value.leaseInterval.releasedAt].map(Date.parse);assert(times.every(Number.isFinite));for(let i=1;i<times.length;i++)assert(times[i]>=times[i-1]);return value;
}
function admitBackup(file,expected){const {bytes,value}=privateJson(file);assert.equal(sha(bytes),expected);assert.equal(value.status,'backed-up-not-restored');assert.deepEqual(Object.keys(value.stores).sort(),provisioningPlan().map(x=>x.schema).sort());for(const row of Object.values(value.stores)){assert(/^[a-z_]+\.dump$/.test(row.dump));const p=path.join(path.dirname(file),row.dump),s=fs.lstatSync(p);assert(s.isFile()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&s.size===row.bytes&&s.size<=256*1024*1024);assert.equal(fileHash(p,256*1024*1024),row.sha256);assert(Array.isArray(row.sequences));assert(row.source?.tables&&Array.isArray(row.source.ledger));}return value;}
function ownedEndpoint(admin,port,sourceConfig){const u=new URL(admin);assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');assert.equal(u.port,String(port));assert.equal(u.pathname,'/postgres');assert(!u.search&&!u.hash);for(const row of provisioningPlan())for(const key of [row.runtimeVariable,row.migrationVariable]){const old=new URL(sourceConfig[key]);assert(!(['127.0.0.1','localhost','::1','[::1]'].includes(old.hostname)&&(old.port||'5432')===u.port),'Installed endpoint cannot be restored into');}return u;}
function ownedAdminEnvironment(admin,port,sourceConfiguration){
 const url=ownedEndpoint(admin,port,sourceConfiguration);assert.equal(url.username,'postgres');
 if(url.password)return db.connectionEnvironment(admin);
 const environment={PATH:'/usr/bin:/bin:/usr/sbin:/sbin',PGHOST:'127.0.0.1',PGPORT:String(port),PGUSER:'postgres',PGDATABASE:'postgres',PGTZ:'UTC'};
 for(const key of ['HOME','TMPDIR'])if(process.env[key])environment[key]=process.env[key];
 return environment;
}
function remapEnvironment(source,configuration,{installation,home,mappings}){
 assert(!Object.hasOwn(source,'NODE_OPTIONS')&&!Object.hasOwn(source,'DVAIA_ISOLATED_TEST_WORKSPACE'),'Unsupported execution override');
 const generatedKeys=new Set(['CTF_DELIVERY_DATABASE_URL']);
 const result={...source,...configuration};for(const key of generatedKeys)if(!Object.hasOwn(configuration,key))delete result[key];
 const urlKeys=new Set([...provisioningPlan().flatMap(x=>[x.runtimeVariable,x.migrationVariable]),...generatedKeys]);
 // Every other path/endpoint/managed feature requires explicit reviewed mapping.
 // Missing resolution is a stop, never a feature-disable default.
 for(const [key,value] of Object.entries(source)){
  if(urlKeys.has(key))continue;
  const sensitive=/(?:PATH|ROOT|DIR|HOME|URL|HOST|PORT|SOCKET|DOCKER|COLIMA)/.test(key)||/^SS_.*ENABLED$/.test(key)||key==='MCP_SIDECARS_AUTOSTART'||key==='IPI_EMAIL_PROVIDER';
  if(sensitive){assert(Object.hasOwn(mappings,key),`Unresolved installation setting: ${key}`);const replacement=mappings[key];assert(typeof replacement==='string');if(value==='true')assert.equal(replacement,'true','Enabled feature cannot be disabled');if(path.isAbsolute(replacement))assert(replacement===installation||replacement.startsWith(installation+path.sep)||replacement===home||replacement.startsWith(home+path.sep),'Remapped path outside owned roots');result[key]=replacement;}
 }
 Object.assign(result,{HOME:home,TMPDIR:path.join(installation,'tmp'),LOGS_DIR:path.join(installation,'logs'),LEGACY_SENSITIVE_FILES_ROOT:path.join(installation,'sensitive'),DVAIA_APP_DATA_ROOT:path.join(installation,'app-data'),PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'});
 assert(!('DVAIA_ISOLATED_TEST_WORKSPACE'in result));return result;
}
async function prepareDisposableEnvironment({sourceConfiguration,provision,directory,admin,installation,home,mappings},delivery=prepareCtfDelivery){
 const environment=sourceConfiguration.PG_TLS?{PG_TLS:sourceConfiguration.PG_TLS}:{};
 const prepared=await delivery({directory,adminUrl:admin,environment,existing:{}});
 const generated=prepared?.configuration?.CTF_DELIVERY_DATABASE_URL;
 assert.equal(typeof generated,'string','Disposable CTF delivery configuration missing');
 if(Object.hasOwn(sourceConfiguration,'CTF_DELIVERY_DATABASE_URL'))assert.notEqual(generated,sourceConfiguration.CTF_DELIVERY_DATABASE_URL,'Installed CTF delivery credential cannot enter disposable target');
 return remapEnvironment(sourceConfiguration,{...provision.configuration,...prepared.configuration},{installation,home,mappings});
}
function compareRestore(actual,expected,kind){
 assert(['toc','schema','rows-ledger','sequences'].includes(kind));
 try{assert.deepEqual(actual,expected);}catch(error){comparisonFailures.set(error,{kind,actualSha256:sha(Buffer.from(JSON.stringify(actual))),expectedSha256:sha(Buffer.from(JSON.stringify(expected)))});throw error;}
}
function sameRestore(actual,expected,sequences){assert.deepEqual(actual,expected.source,'Restored full rows/ledger differ');assert.deepEqual(sequences,expected.sequences,'Restored sequence state differs');}
async function defaultUpgrade({installation,home,admin,environment}, controlled={}){
 const input=path.join(installation,`upgrade-${crypto.randomUUID()}.json`);
 const admittedPath=path.dirname(process.execPath)+':'+path.dirname(db.TOOLS.docker.path)+':/usr/bin:/bin';
 environment={...environment,PATH:admittedPath};
 fs.writeFileSync(input,JSON.stringify({installation,home,admin,environment}),{mode:384,flag:'wx'});
 const controls=controlled.controls||require('../../tests/fixtures/fullBackendBootControls');
 const children=controls.createOwnedChildren(controlled.spawn||require('node:child_process').spawn);
 let primary;
 try{const child=children.launch(process.execPath,[path.join(__dirname,'populated16-upgrade-child.cjs'),input],{cwd:installation,env:{PATH:admittedPath,HOME:home,TMPDIR:path.join(installation,'tmp'),SETUP_PHASE_EVIDENCE_ROOT:process.env.SETUP_PHASE_EVIDENCE_ROOT,SETUP_PHASE_OWNER:process.env.SETUP_PHASE_OWNER,REHEARSAL_NATIVE_PID:String(process.pid),PG_ADMIN_DATABASE_URL:admin,NODE_OPTIONS:'--require '+path.join(__dirname,'populated16-network-guard.cjs')},stdio:['ignore','ignore','ignore']});
 const code=await controls.waitForChild(child,{timeoutMs:600000});assert.equal(code,0,'Owned upgrade child failed');
 }catch(e){primary=e;}finally{try{await children.cleanup();}catch(e){primary=primary?new AggregateError([primary,e],'Upgrade and cleanup failed'):e;}}
 if(primary)throw primary;
}


// PostgreSQL reparses BETWEEN's pair of immutable octet_length predicates as
// a flat AND during restore. Admit exactly the two observed forms of this one
// checked-in constraint; do not normalize other expressions or table scopes.
const PASSWORD_CHECK_FORMS=Object.freeze(["    CONSTRAINT bound_persona_credentials_password_hash_check CHECK ((((octet_length(password_hash) >= 50) AND (octet_length(password_hash) <= 128)) AND (password_hash ~ '^\\$2[aby]\\$[0-9][0-9]\\$'::text))),", "    CONSTRAINT bound_persona_credentials_password_hash_check CHECK (((octet_length(password_hash) >= 50) AND (octet_length(password_hash) <= 128) AND (password_hash ~ '^\\$2[aby]\\$[0-9][0-9]\\$'::text))),"]);
// Observed identity0137 BETWEEN reparse; admit only these two exact forms
// within secureshop_auth.principals, retaining every other schema byte.
const PRINCIPALS_EMAIL_CHECK_FORMS=Object.freeze(["    CONSTRAINT principals_email_check CHECK ((((octet_length(email) >= 3) AND (octet_length(email) <= 320)) AND (email = lower(email)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$'::text))),", "    CONSTRAINT principals_email_check CHECK (((octet_length(email) >= 3) AND (octet_length(email) <= 320) AND (email = lower(email)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$'::text))),"]);
// Observed review0019 BETWEEN reparse, restricted to its exact table and constraint.
const EMBEDDING_POLICY_CHECK_FORMS=Object.freeze(["    CONSTRAINT product_embedding_policy_shape CHECK ((((policy_version IS NULL) AND (policy_snapshot_sha256 IS NULL)) OR (((policy_version >= 1) AND (policy_version <= '9007199254740991'::bigint)) AND (octet_length(policy_snapshot_sha256) = 32)))),", "    CONSTRAINT product_embedding_policy_shape CHECK ((((policy_version IS NULL) AND (policy_snapshot_sha256 IS NULL)) OR ((policy_version >= 1) AND (policy_version <= '9007199254740991'::bigint) AND (octet_length(policy_snapshot_sha256) = 32)))),"]);
function schemaText(value){
 let credentialTable=false,principalsTable=false,embeddingTable=false;
 return value.split('\n').filter(line=>!/^\\(?:un)?restrict [A-Za-z0-9]+$/.test(line)&&!/^-- Dumped (?:from database|by pg_dump) version /.test(line)).map(line=>{
  if(line==='CREATE TABLE secureshop_agents.bound_persona_credentials (')credentialTable=true;
  if(line==='CREATE TABLE secureshop_auth.principals (')principalsTable=true;
  if(line==='CREATE TABLE secureshop_review.product_target_embedding_revisions (')embeddingTable=true;
  const result=credentialTable&&PASSWORD_CHECK_FORMS.includes(line)?PASSWORD_CHECK_FORMS[1]
   :principalsTable&&PRINCIPALS_EMAIL_CHECK_FORMS.includes(line)?PRINCIPALS_EMAIL_CHECK_FORMS[1]
   :embeddingTable&&EMBEDDING_POLICY_CHECK_FORMS.includes(line)?EMBEDDING_POLICY_CHECK_FORMS[1]:line;
  if(line===');'){credentialTable=false;principalsTable=false;embeddingTable=false;}
  return result;
 }).join('\n');
}

function retainSchemaEvidence(before,after,evidence){
 assert.equal(fs.realpathSync(evidence),evidence);const st=fs.lstatSync(evidence);assert(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&511)===448);
 const journal=privateJson(path.join(evidence,'ownership.json')).value;
 assert.equal(journal.nativePid,process.pid);assert.equal(journal.owner,process.env.SETUP_PHASE_OWNER);assert(RETAINED_REHEARSAL_COHORTS.has(journal.cohort),'Unexpected rehearsal cohort');assert.equal(journal.sourceRoot,MAIN);
 const values=[['restore-schema-before.sql',before],['restore-schema-after.sql',after]],records=[];
 for(const [,value]of values)assert(Buffer.byteLength(value)<=16*1024*1024,'Schema diagnostic size limit');
 for(const [name,value]of values){const fd=fs.openSync(path.join(evidence,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,384);try{fs.writeFileSync(fd,value);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}records.push({name,bytes:Buffer.byteLength(value),sha256:sha(Buffer.from(value))});}
 const directory=fs.openSync(evidence,fs.constants.O_RDONLY);try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}return records;
}
async function verifySchema(dump,target,run=db.run){
 const before=await run(db.TOOLS.pg_restore.path,['--schema-only','--file=-',dump],{env:{PATH:'/usr/bin:/bin'}});
 const after=await run(db.TOOLS.pg_dump.path,['--schema-only'],{env:target});
 try{compareRestore(schemaText(after.stdout),schemaText(before.stdout),'schema');}catch(error){if(admittedEvidence){try{comparisonFailures.get(error).artifacts=retainSchemaEvidence(before.stdout,after.stdout,admittedEvidence);}catch{comparisonFailures.get(error).artifactFailure='SCHEMA_EVIDENCE_UNAVAILABLE';}}throw error;}
}
function verifySequenceTransition(before,after,expected={}){
 const old=new Map(before.map(r=>[`${r.schema}.${r.name}`,r])),next=new Map(after.map(r=>[`${r.schema}.${r.name}`,r]));
 for(const [key,row]of old){const got=next.get(key);assert(got,`Sequence removed: ${key}`);const {last_value,is_called,...definition}=row;const {last_value:last,is_called:called,...nextDefinition}=got;assert.deepEqual(nextDefinition,definition);const change=expected[key];if(change){assert.deepEqual(Object.keys(change).sort(),['delta','isCalled']);assert(/^(0|[1-9][0-9]*)$/.test(change.delta));assert.equal(BigInt(last)-BigInt(last_value),BigInt(change.delta));assert.equal(called,change.isCalled);}else{assert.equal(last,last_value,`Undeclared sequence advance: ${key}`);assert.equal(called,is_called);}}
 for(const key of Object.keys(expected))assert(old.has(key),'Unknown expected sequence delta');
}
function maintenanceTimestamp(value){
 assert(typeof value==='string'&&Number.isFinite(Date.parse(value)),'Invalid maintenance timestamp');
 return Date.parse(value);
}
function unavailableBinding(binding,{epoch,operationId,begunAt,finishedAt}){
 assert(binding&&typeof binding==='object','Missing unmanaged maintenance binding');
 assert.equal(String(binding.epoch),String(epoch));assert.equal(binding.operation_id,operationId);
 assert.equal(binding.profile,'unavailable');assert.equal(binding.reason_code,'UNMANAGED_BEGIN');
 for(const key of ['workspace_sha256','store_manifest_sha256','publication_id','publication_sha256','source_manifest_sha256','owner_record','owner_record_sha256'])assert.equal(binding[key],null,`Unexpected unmanaged binding ${key}`);
 const created=maintenanceTimestamp(binding.created_at),begun=maintenanceTimestamp(begunAt),finished=maintenanceTimestamp(finishedAt);
 assert(created>=begun&&created<=finished,'Unmanaged binding timestamp is outside its maintenance epoch');
 assert.deepEqual(Object.keys(binding).sort(),['created_at','epoch','operation_id','owner_record','owner_record_sha256','profile','publication_id','publication_sha256','reason_code','source_manifest_sha256','store_manifest_sha256','workspace_sha256']);
}
function verifyMaintenanceTransition(before,after){
 assert(Array.isArray(before.epochBindings)&&Array.isArray(after.epochBindings),'Maintenance binding history required');
 assert.equal(after.control.length,1);const b=after.control[0];assert.equal(b.state,'clean');
 if(before.control.length===0){
  assert.deepEqual(before,{control:[],epochs:[],ledger:[],epochBindings:[]},'Absent maintenance baseline must have no history');
  assert.equal(String(b.epoch),'1');assert.equal(after.epochs.length,1);assert.equal(after.ledger.length,1);
  assert.equal(after.ledger[0].name,'0001_maintenance_fence.sql');
  assert.equal(after.ledger[0].checksum,sha(fs.readFileSync(path.join(MAIN,'db/postgres/maintenance-migrations/0001_maintenance_fence.sql'))));
 }else{
  assert.equal(before.control.length,1);const a=before.control[0];assert.equal(a.state,'clean');assert.equal(BigInt(b.epoch),BigInt(a.epoch)+1n);
  const mutable=new Set(['epoch','operation_id','owner_host_sha256','begun_at','finished_at']);for(const key of Object.keys(a))if(!mutable.has(key))assert.deepEqual(b[key],a[key]);
  assert.deepEqual(after.ledger,before.ledger);assert.equal(after.epochs.length,before.epochs.length+1);assert.deepEqual(after.epochs.slice(0,-1),before.epochs);assert.notEqual(b.operation_id,a.operation_id);
 }
 const last=after.epochs.at(-1);assert.equal(String(last.epoch),String(b.epoch));assert.equal(last.operation_id,b.operation_id);assert.equal(last.begun_at,b.begun_at);assert.equal(last.finished_at,b.finished_at);assert.equal(last.owner_host_sha256,b.owner_host_sha256);assert(maintenanceTimestamp(last.finished_at)>=maintenanceTimestamp(last.begun_at));
 assert.deepEqual(after.epochBindings.slice(0,before.epochBindings.length),before.epochBindings,'Prior maintenance bindings changed');
 const bindingRequired=before.ledger.length>=2;
 assert.equal(after.epochBindings.length,before.epochBindings.length+(bindingRequired?1:0),'Unexpected maintenance binding append');
 if(bindingRequired)unavailableBinding(after.epochBindings.at(-1),{epoch:b.epoch,operationId:b.operation_id,begunAt:b.begun_at,finishedAt:b.finished_at});
}
const MAINTENANCE_LIFECYCLE_TABLES=Object.freeze(['dvaia_maintenance.control','dvaia_maintenance.epochs','dvaia_maintenance.epoch_bindings']);
function maintenanceLifecycleTables(tables){
 assert(tables&&Object.getPrototypeOf(tables)===Object.prototype);
 for(const table of MAINTENANCE_LIFECYCLE_TABLES.slice(0,2))assert(Object.hasOwn(tables,table),`Missing lifecycle baseline: ${table}`);
 return Object.freeze(MAINTENANCE_LIFECYCLE_TABLES.filter(table=>Object.hasOwn(tables,table)));
}
const RETAINED_ASSESSMENT_DEFAULT_TABLE='secureshop_auth.assessment_objectives';
const RETAINED_ASSESSMENT_DEFAULT_ID='ss_listing_template_execution';
function retainedAssessmentDefaultContract(){
 const matches=OBJECTIVES.filter(objective=>objective?.id===RETAINED_ASSESSMENT_DEFAULT_ID);
 assert.equal(matches.length,1,'Retained assessment default source is ambiguous');
 const objective=matches[0];
 assert.equal(objective.defaultEnabled,false,'Retained assessment default must remain disabled');
 assert.equal(objective.qualification,'native-model','Retained assessment default qualification changed');
 assert(typeof objective.text==='string'&&objective.text.length>0,'Retained assessment default label missing');
 const sourceDocument={version:1,id:objective.id,label:objective.text,defaultEnabled:objective.defaultEnabled,qualification:objective.qualification};
 const source=JSON.stringify(sourceDocument);
 return Object.freeze({objectiveId:objective.id,label:objective.text,enabled:objective.defaultEnabled,
  qualification:objective.qualification,sourceDocument,sourceSha256:sha(source),catalogActive:true,
  configurationSource:'checked_in_default'});
}
function retainedOwnershipPreservationTables(row,tables){
 const lifecycle=maintenanceLifecycleTables(tables);
 assert.equal(row.schema,'identity','Only retained identity tables have lifecycle exclusions');
 assert(Object.hasOwn(tables,RETAINED_ASSESSMENT_DEFAULT_TABLE),'Retained assessment baseline missing');
 return Object.freeze(Object.fromEntries(Object.entries(tables).filter(([table])=>!lifecycle.includes(table)&&table!==RETAINED_ASSESSMENT_DEFAULT_TABLE)));
}
function preservationTablesForLifecycle(row,tables,lifecycleExclusions=[]){
 assert(row&&typeof row==='object'&&typeof row.schema==='string'&&tables&&Object.getPrototypeOf(tables)===Object.prototype);
 assert(Array.isArray(lifecycleExclusions));
 const unique=[...new Set(lifecycleExclusions)];assert.deepEqual(unique,lifecycleExclusions,'Duplicate lifecycle preservation exclusion');
 if(unique.length===0)return tables;
 assert.equal(row.schema,'identity','Only the identity maintenance lifecycle can be excluded');
 const exact=maintenanceLifecycleTables(tables);assert.deepEqual(unique,exact,'Only the exact maintenance lifecycle can be excluded');
 return Object.freeze(Object.fromEntries(Object.entries(tables).filter(([table])=>!exact.includes(table))));
}
function sqlLiteral(value){return `'${String(value).replaceAll("'","''")}'`;}
async function retainedAssessmentDefaultBaseline(env,run=db.run){
 const result=await run(db.TOOLS.psql.path,['-X','-q','-v','ON_ERROR_STOP=1','-At','-c',`CREATE TABLE dvaia_qualification.retained_assessment_objectives(row_value jsonb NOT NULL,multiplicity bigint NOT NULL); INSERT INTO dvaia_qualification.retained_assessment_objectives SELECT to_jsonb(t),count(*) FROM secureshop_auth.assessment_objectives t GROUP BY to_jsonb(t); SELECT json_build_object('rows',(SELECT COALESCE(sum(multiplicity),0) FROM dvaia_qualification.retained_assessment_objectives),'targetRows',(SELECT COALESCE(sum(multiplicity),0) FROM dvaia_qualification.retained_assessment_objectives WHERE row_value->>'objective_id'=${sqlLiteral(RETAINED_ASSESSMENT_DEFAULT_ID)}))::text`],{env});
 const state=JSON.parse(result.stdout);assert(Number.isSafeInteger(Number(state.rows))&&Number(state.rows)>=0,'Retained assessment baseline count invalid');assert.equal(Number(state.targetRows),0,'Retained assessment default already existed');
 return Object.freeze({rows:Number(state.rows)});
}
async function retainedAssessmentDatabaseClock(env,run=db.run){
 const result=await run(db.TOOLS.psql.path,['-X','-q','-v','ON_ERROR_STOP=1','-At','-c',"SELECT json_build_object('at',clock_timestamp())::text"],{env});
 const value=JSON.parse(result.stdout);assert(typeof value.at==='string'&&Number.isFinite(Date.parse(value.at)),'Retained assessment database clock invalid');
 return value.at;
}
async function verifyRetainedAssessmentDefaultAddition(env,{baseline,startedAt,finishedAt},run=db.run){
 assert(baseline&&Number.isSafeInteger(baseline.rows)&&baseline.rows>=0,'Retained assessment baseline unavailable');
 assert(typeof startedAt==='string'&&typeof finishedAt==='string'&&Number.isFinite(Date.parse(startedAt))&&Number.isFinite(Date.parse(finishedAt))&&Date.parse(finishedAt)>=Date.parse(startedAt),'Retained assessment initializer interval invalid');
 const expected=retainedAssessmentDefaultContract(),source=JSON.stringify(expected.sourceDocument);
 const query=`WITH baseline AS (SELECT row_value,multiplicity FROM dvaia_qualification.retained_assessment_objectives), current_rows AS (SELECT to_jsonb(t) row_value,count(*)::bigint multiplicity FROM secureshop_auth.assessment_objectives t GROUP BY to_jsonb(t)), additions AS (SELECT c.row_value,c.multiplicity FROM current_rows c LEFT JOIN baseline b USING(row_value) WHERE b.row_value IS NULL), target AS (SELECT t.* FROM secureshop_auth.assessment_objectives t WHERE t.objective_id=${sqlLiteral(expected.objectiveId)}) SELECT json_build_object('missing',COALESCE((SELECT sum(GREATEST(b.multiplicity-COALESCE(c.multiplicity,0),0)) FROM baseline b LEFT JOIN current_rows c USING(row_value)),0),'added',COALESCE((SELECT sum(multiplicity) FROM additions),0),'baselineRows',(SELECT COALESCE(sum(multiplicity),0) FROM baseline),'targetRows',(SELECT count(*) FROM target),'targetMatches',(SELECT count(*) FROM target WHERE label=${sqlLiteral(expected.label)} AND is_enabled=${expected.enabled?'true':'false'} AND catalog_active=${expected.catalogActive?'true':'false'} AND qualification=${sqlLiteral(expected.qualification)} AND source_sha256=${sqlLiteral(expected.sourceSha256)} AND source_document=${sqlLiteral(source)}::jsonb AND configuration_source=${sqlLiteral(expected.configurationSource)} AND updated_at>=${sqlLiteral(startedAt)}::timestamptz AND updated_at<=${sqlLiteral(finishedAt)}::timestamptz))::text`;
 const result=await run(db.TOOLS.psql.path,['-X','-q','-v','ON_ERROR_STOP=1','-At','-c',query],{env});
 const state=JSON.parse(result.stdout);
 for(const key of ['missing','added','baselineRows','targetRows','targetMatches'])assert(Number.isSafeInteger(Number(state[key]))&&Number(state[key])>=0,'Retained assessment addition evidence invalid');
 assert.equal(Number(state.baselineRows),baseline.rows,'Retained assessment baseline changed');
 assert.equal(Number(state.missing),0,'Preexisting assessment objective changed');
 assert.equal(Number(state.added),1,'Unexpected assessment objective addition');
 assert.equal(Number(state.targetRows),1,'Retained assessment default target cardinality invalid');
 assert.equal(Number(state.targetMatches),1,'Retained assessment default content invalid');
 return Object.freeze({objectiveId:expected.objectiveId,sourceSha256:expected.sourceSha256});
}
async function maintenanceState(env,run=db.run){
 const args=['-X','-q','-v','ON_ERROR_STOP=1','-At','-c'];
 const presence=await run(db.TOOLS.psql.path,[...args,"SELECT json_build_array(to_regclass('dvaia_maintenance.control') IS NOT NULL,to_regclass('dvaia_maintenance.epochs') IS NOT NULL,to_regclass('dvaia_maintenance.ledger') IS NOT NULL,to_regclass('dvaia_maintenance.epoch_bindings') IS NOT NULL)::text"],{env});
 const relations=JSON.parse(presence.stdout);assert(Array.isArray(relations)&&relations.length===4);
 if(relations.every(value=>value===false))return{control:[],epochs:[],ledger:[],epochBindings:[]};
 assert.deepEqual(relations.slice(0,3),[true,true,true],'Partial maintenance schema cannot establish a baseline');
 const bindingProjection=relations[3]?"(SELECT COALESCE(json_agg(t ORDER BY epoch),'[]'::json) FROM dvaia_maintenance.epoch_bindings t)":"'[]'::json";
 const result=await run(db.TOOLS.psql.path,[...args,`SELECT json_build_object('control',(SELECT json_agg(t) FROM dvaia_maintenance.control t),'epochs',(SELECT COALESCE(json_agg(t ORDER BY epoch),'[]'::json) FROM dvaia_maintenance.epochs t),'ledger',(SELECT json_agg(t ORDER BY name) FROM dvaia_maintenance.ledger t),'epochBindings',${bindingProjection})::text`],{env});
 const state=JSON.parse(result.stdout);assert(Array.isArray(state.control)&&state.control.length===1,'Existing maintenance control missing');assert(Array.isArray(state.epochs)&&Array.isArray(state.ledger)&&state.ledger.length>0&&Array.isArray(state.epochBindings),'Existing maintenance history unavailable');
 if(state.ledger.length>=2)assert.equal(relations[3],true,'Maintenance binding table required by ledger');
 return state;
}
function withoutMaintenance(snapshot){return {...snapshot,tables:Object.fromEntries(Object.entries(snapshot.tables).filter(([k])=>!k.startsWith('dvaia_maintenance.')))};}
function encodeRestoredManagedEnvironment(name,values,{installation,home}){
 if(name!=='secureshop-qualified.env'&&name!=='postgres-container.env')return require('../../scripts/setup-application').encodeEnv(values);
 for(const [key,value]of Object.entries(values))assert(/^[A-Z][A-Z0-9_]*$/.test(key)&&typeof value==='string'&&!/[\r\n\0]/.test(value),'Invalid raw managed configuration');
 if(name==='postgres-container.env')assert.deepEqual(Object.keys(values),['POSTGRES_PASSWORD']);
 const encoded=Object.entries(values).map(([key,value])=>`${key}=${value}`).join('\n')+'\n';
 if(name==='secureshop-qualified.env'){
  const parsed=require('../../server/services/secureshopQualifiedManagedConfiguration').parse(Buffer.from(encoded),{root:installation,home});
  assert.deepEqual({...parsed},{...values},'Managed configuration changed during encoding');
 }
 return encoded;
}
function restoreFiles(saved,backupDirectory,installation,home,directory,mappings){
 const files=require('../../scripts/qualify-application-filesystem-backup');const archive=path.join(backupDirectory,'filesystem.archive');assert.equal(fileHash(archive,512*1024*1024),saved.filesystem.sha256);
 const extraction=path.join(installation,'backup-restored');fs.mkdirSync(extraction,{mode:448});files.restoreArchive(archive,extraction,saved.filesystem.roots.flatMap(r=>r.entries));
 const generated=new Set(['provisioning.json','local-postgres.json','local-docker.json']);const clusterBound=new Set(['ctf-authority.json','ctf-delivery.json','ctf-delivery.json.pending']),immutable=[],regenerated=[];
 for(const root of saved.filesystem.roots){let target;const name=path.basename(root.source);
  if(root.label.startsWith('private_')){
   if(generated.has(name))continue; // Original retained intact in backup-restored.
   if(clusterBound.has(name)){const archivePath=path.join(extraction,root.label);regenerated.push({name,archivedSha256:sha(fs.readFileSync(archivePath)),archivePath,target:path.join(directory,name)});continue;}
   target=path.join(directory,name);
  }else if(root.label==='application_logs')target=path.join(installation,'logs');
  else if(root.label==='legacy_sensitive_files')target=path.join(installation,'sensitive');
  else if(root.label==='environment'||root.label.startsWith('legacy_sqlite_'))continue;
  else if(root.label==='app_data')target=path.join(installation,'app-data');
  else{assert(Object.hasOwn(mappings,root.source),`Unmapped archived root: ${root.label}`);target=mappings[root.source];}
  assert(target.startsWith(installation+path.sep)||target.startsWith(home+path.sep));assert(!fs.existsSync(target),'Duplicate archive target');
  fs.cpSync(path.join(extraction,root.label),target,{recursive:true,errorOnExist:true,force:false,preserveTimestamps:true});
  if(name.endsWith('.env')){
   const parsed=require('dotenv').parse(fs.readFileSync(target));const remapped={};for(const [key,value]of Object.entries(parsed)){if(/(?:PATH|ROOT|DIR|URL|HOST|PORT|SOCKET)/.test(key)){assert(Object.hasOwn(mappings,key),`Unresolved managed setting: ${key}`);remapped[key]=mappings[key];}else remapped[key]=value;}
   for(const [key,value]of Object.entries(parsed))if(['true','false'].includes(value))assert.equal(remapped[key],value);
   fs.writeFileSync(target,encodeRestoredManagedEnvironment(name,remapped,{installation,home}),{mode:384});
  }
  const capture=p=>{const stat=fs.lstatSync(p);assert(!stat.isSymbolicLink());if(stat.isDirectory()){for(const name of fs.readdirSync(p))capture(path.join(p,name));}else{assert(stat.isFile());immutable.push({path:p,sha256:sha(fs.readFileSync(p))});}};capture(target);
 }
 return{immutable,regenerated};
}
function verifyRegeneratedPrivateState(entries){for(const entry of entries){const stat=fs.lstatSync(entry.target);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&511)===384&&stat.nlink===1);assert.notEqual(sha(fs.readFileSync(entry.target)),entry.archivedSha256,`${entry.name} retained a foreign cluster binding`);}}
function verifyRetainedOwnershipPrivateState(entries){
 const known=new Set(['ctf-authority.json','ctf-delivery.json','ctf-delivery.json.pending']);
 for(const entry of entries){assert(known.has(entry.name),'Unexpected cluster-bound private state');assert.equal(sha(fs.readFileSync(entry.archivePath)),entry.archivedSha256,'Archived private state changed');}
 const authority=entries.filter(entry=>entry.name==='ctf-authority.json');assert.equal(authority.length,1,'Archived CTF authority state required');
 for(const entry of authority)assert.equal(fs.existsSync(entry.target),false,'Retained ownership migration created CTF authority state');
 const delivery=entries.filter(entry=>entry.name==='ctf-delivery.json');assert.equal(delivery.length,1,'Disposable CTF delivery state required');
 for(const entry of delivery)verifyRegeneratedPrivateState([entry]);
 const pending=entries.filter(entry=>entry.name==='ctf-delivery.json.pending');assert.equal(pending.length,1,'Disposable pending CTF delivery state required');
 for(const entry of pending)verifyRegeneratedPrivateState([entry]);
 return Object.freeze({archivedAuthorityBytesPreserved:true,disposableDeliveryRegenerated:true,noActiveAuthorityState:true});
}
async function restoreStore(row,input,backupRoot,target,deps){
 assert(provisioningPlan().some(known=>known.schema===row.schema&&known.database===row.database));
 const stage=name=>{currentStage='restore-'+row.schema+'-'+name;};
 stage('toc');const toc=await deps.run(db.TOOLS.pg_restore.path,['--list',path.join(backupRoot,input.dump)],{env:{PATH:'/usr/bin:/bin'}});compareRestore(sha(Buffer.from(toc.stdout)),input.tocSha256,'toc');
 stage('pg-restore');await deps.run(db.TOOLS.pg_restore.path,['--exit-on-error','--dbname',row.database,path.join(backupRoot,input.dump)],{env:target,capture:false});
 stage('schema');await deps.schema(path.join(backupRoot,input.dump),target,deps.run);
 stage('rows-ledger');compareRestore(await deps.snapshot(target),input.source,'rows-ledger');
 stage('sequences');compareRestore(await deps.sequences(target),input.sequences,'sequences');
}
async function restoreStoresWithDelivery({sourceConfiguration,provision,directory,admin,port,installation,home,mappings,saved,backupRoot},deps){
 // CTF archives grant privileges to the delivery role. Create the owned role
 // before restoring any store, retaining this same fresh credential for setup.
 currentStage='ctf-delivery-provision';
 const env=await prepareDisposableEnvironment({sourceConfiguration,provision,directory,admin,installation,home,mappings},deps.delivery);
 const restored=[];
 for(const row of provision.plan){
  const target=ownedAdminEnvironment(admin,port,sourceConfiguration);target.PGDATABASE=row.database;
  await restoreStore(row,saved.stores[row.schema],backupRoot,target,deps);
  const migration=db.connectionEnvironment(provision.configuration[row.migrationVariable]);restored.push({row,target:migration});
 }
 return {env,restored};
}

async function sequenceRegression(configuration, Client=require('pg').Client){
 const client=new Client({connectionString:configuration.SECURESHOP_MIGRATION_DATABASE_URL,connectionTimeoutMillis:5000,query_timeout:10000});
 let primary,receipt;
 try{await client.connect();receipt=await require('../../tests/fixtures/secureshopSeedSequenceRegression').verifySeedSequence(client);}
 catch(error){primary=error;}finally{try{await client.end();}catch(error){primary=primary?new AggregateError([primary,error],'Sequence probe cleanup failed'):error;}}
 if(primary)throw primary;return receipt;
}
async function verifyCouponBackfill(source,target,run){
 const migrationApplied=source.ledger.some(row=>row.name==='0025_bound_coupon_commerce.sql');
 for(const [table,columns,predicate,message]of [
  ['product_target_orders',['subtotal_amount','discount_amount','coupon_code','coupon_percent'],'subtotal_amount IS DISTINCT FROM total_amount OR discount_amount IS DISTINCT FROM 0::numeric OR coupon_code IS NOT NULL OR coupon_percent IS NOT NULL','Original order subtotal backfill differs'],
  ['product_target_order_items',['discount_amount'],'discount_amount IS DISTINCT FROM 0::numeric','Original item discount changed'],
 ]){
  const name='secureshop_review.'+table;if(!source.tables[name])continue;
  // These columns were captured from the restored original schema before setup.
  // Modern coupon values remain protected by the exact retained-row comparison.
  const original=await run(db.TOOLS.psql.path,['-X','-q','-v','ON_ERROR_STOP=1','-At','-c',`SELECT column_names::text FROM dvaia_qualification.columns WHERE table_name='${name}'`],{env:target});
  const originalColumns=JSON.parse(original.stdout);assert(Array.isArray(originalColumns));
  assert(columns.every(column=>originalColumns.includes(column)===migrationApplied),'Original coupon schema and ledger disagree');
  if(migrationApplied)continue;
  const proof=await run(db.TOOLS.psql.path,['-X','-q','-v','ON_ERROR_STOP=1','-At','-c',`SELECT count(*)::text FROM ${name} WHERE ${predicate}`],{env:target});
  assert.equal(proof.stdout.trim(),'0',message);
 }
}
async function verifyPriceHistoryBackfill(source,target,run,sequences){
 const table='secureshop_review.product_target_price_history';
 const applied=source.ledger.some(row=>row.name==='0040_owned_product_price_history.sql');
 assert.equal(Object.hasOwn(source.tables,table),applied,'Original price history schema and ledger disagree');
 if(applied)return; // Existing rows are protected by the ordinary exact preservation checks.
 const proof=JSON.parse((await run(db.TOOLS.psql.path,['-X','-q','-v','ON_ERROR_STOP=1','-At','-c',`
 WITH expected AS (
  SELECT p.target_id,p.product_id,COALESCE(o.price,p.price) AS price
  FROM secureshop_review.product_target_products p
  JOIN secureshop_review.product_targets t ON t.target_id=p.target_id AND t.lifecycle='active'
  LEFT JOIN secureshop_review.product_target_listing_overlays o
   ON o.target_id=p.target_id AND o.product_id=p.product_id
 ), actual AS (SELECT * FROM secureshop_review.product_target_price_history)
 SELECT json_build_object(
  'expected',(SELECT count(*)::text FROM expected),
  'actual',(SELECT count(*)::text FROM actual),
  'invalid',(SELECT count(*)::text FROM expected e FULL JOIN actual a
   ON a.target_id=e.target_id AND a.product_id=e.product_id
   WHERE e.target_id IS NULL OR a.target_id IS NULL OR a.price IS DISTINCT FROM e.price
    OR a.source IS DISTINCT FROM 'migration_baseline' OR a.observed_at IS NULL),
  'distinctIds',(SELECT count(DISTINCT observation_id)::text FROM actual),
  'minId',(SELECT COALESCE(min(observation_id),0)::text FROM actual),
  'maxId',(SELECT COALESCE(max(observation_id),0)::text FROM actual))::text`],{env:target})).stdout);
 assert.deepEqual(Object.keys(proof).sort(),['actual','distinctIds','expected','invalid','maxId','minId']);
 for(const value of Object.values(proof))assert(/^(0|[1-9][0-9]*)$/.test(value),'Price history count invalid');
 assert.equal(proof.actual,proof.expected,'Price history baseline cardinality differs');
 assert.equal(proof.invalid,'0','Price history baseline target/product/price/source differs');
 assert.equal(proof.distinctIds,proof.expected,'Price history observation IDs differ');
 assert.equal(proof.minId,proof.expected==='0'?'0':'1');assert.equal(proof.maxId,proof.expected);
 const matching=sequences.filter(row=>row.schema==='secureshop_review'&&row.name==='product_target_price_history_observation_id_seq');
 assert.equal(matching.length,1,'New price history identity sequence missing');
 assert.deepEqual(matching[0],{schema:'secureshop_review',name:'product_target_price_history_observation_id_seq',
  type:'bigint',start:'1',increment:'1',minimum:'1',maximum:'9223372036854775807',cache:'1',cycle:false,
  last_value:proof.expected==='0'?'1':proof.expected,is_called:proof.expected!=='0'},'Price history identity sequence differs');
}
function a21RowSet(rows){
 const digests=rows.map(row=>sha(Buffer.from(row.payload))).sort();
 return Object.freeze({rows:digests.length,sha256:sha(Buffer.from(JSON.stringify(digests))),digests:Object.freeze(digests)});
}
function assertA21RowSet(actual,expected,label,{allowAppend=false}={}){
 if(!allowAppend){assert.deepEqual(actual,expected,label);return;}
 assert(actual.rows>=expected.rows,`${label}: original rows removed`);
 const available=new Map();for(const digest of actual.digests)available.set(digest,(available.get(digest)||0)+1);
 for(const digest of expected.digests){const count=available.get(digest)||0;assert(count>0,`${label}: original row digest missing`);available.set(digest,count-1);}
}
function a21AuthorityKind(row){
 if(row.realm!==row.sessionRealm)return null;
 if(row.realm==='platform'&&Number(row.ownerId)===Number(row.platformUserId)
   &&row.ownerShopPrincipalId===null&&row.ownerShopTenantId===null
   &&Number(row.sessionId)===Number(row.platformSessionId)
   &&row.shopSessionId===null&&row.shopExecutionSessionId===null)return 'platform';
 if(row.realm==='shop'&&row.platformUserId===null&&row.platformSessionId===null){
  if(typeof row.ownerShopPrincipalId==='string'&&row.ownerShopTenantId===null
    &&Number(row.sessionId)===Number(row.shopSessionId)&&row.shopExecutionSessionId===null)return 'shop-principal';
  if(row.ownerShopPrincipalId===null&&typeof row.ownerShopTenantId==='string'
    &&row.shopSessionId===null&&Number(row.sessionId)===Number(row.shopExecutionSessionId))return 'shop-tenant';
 }
 return null;
}
function chooseA21RestoredSubset(identityRows,reviewRows){
 const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
 assert(reviewRows.length>0,'A21 preservation unproven: restored backup has no product targets');
 const identities=new Map();for(const row of identityRows){assert(!identities.has(row.targetId),'A21 target authority is ambiguous');identities.set(row.targetId,row);}
 const reviews=new Map(reviewRows.map(row=>[row.targetId,row]));
 for(const row of identityRows)assert(reviews.has(row.targetId),'A21 identity reservation has no restored review target');
 const targets=[];
 for(const review of reviewRows){
  const identity=identities.get(review.targetId);assert(identity,'A21 restored review target has no identity reservation');
  const authorityKind=a21AuthorityKind(identity);assert(authorityKind,'A21 restored target authority realm is invalid');
  assert.equal(identity.launchId,review.launchId,'A21 target launch differs');
  assert.equal(identity.scenarioId,review.scenarioId,'A21 target scenario differs');
  assert.equal(Number(identity.generation),Number(review.generation),'A21 target generation differs');
  assert.equal(Number(identity.ownerId),Number(review.ownerId),'A21 target owner differs');
  assert.equal(Number(identity.sessionId),Number(review.sessionId),'A21 target session differs');
  if(identity.sceneId){assert.equal(identity.sceneLaunchId,review.launchId);assert.equal(identity.sceneScenarioId,review.scenarioId);
   assert.equal(Number(identity.sceneGeneration),Number(review.generation));assert.equal(Number(identity.sceneOwnerId),Number(review.ownerId));
   assert.equal(Number(identity.sceneSessionId),Number(review.sessionId));}
  assert(/^[a-f0-9]{64}$/.test(review.sourceSha256||''),'A21 target source digest unavailable');
  if(Number(review.productCount)>0)assert.equal(review.productHashesValid,true,'A21 product source digest unavailable');
  if(review.lifecycle==='active')assert(Number(review.productCount)>0,'A21 active target products unavailable');
  targets.push(Object.freeze({...identity,...review,authorityKind}));
 }
 const receiptTargets=targets.filter(row=>row.sceneId&&row.authorityKind.startsWith('shop-')&&row.lifecycle==='active'
   &&Number(row.orderCount)>0&&Number(row.itemCount)>0&&Number(row.checkoutCount)>0
   &&uuid.test(row.receiptOperationId||'')&&Number.isSafeInteger(Number(row.receiptActorId))&&Number(row.receiptActorId)>0);
 assert(receiptTargets.length>0,'A21 preservation unproven: restored backup has no shop scene with coherent checkout evidence');
 const platformScenes=targets.filter(row=>row.sceneId&&row.authorityKind==='platform').length;
 const shopScenes=targets.filter(row=>row.sceneId&&row.authorityKind.startsWith('shop-')).length;
 assert(shopScenes>0,'A21 preservation unproven: restored backup has no shop scene');
 return Object.freeze({targets:Object.freeze(targets),receiptTargetIds:Object.freeze(receiptTargets.map(row=>row.targetId)),
  attestation:Object.freeze({platformScenes,shopScenes,targets:targets.length})});
}
async function withA21Pools(configuration,work,Pool=require('pg').Pool){
 const options=url=>({connectionString:url,max:2,connectionTimeoutMillis:5000,statement_timeout:10000,lock_timeout:3000,
  idle_in_transaction_session_timeout:10000,application_name:'dvaia-a21-preservation'});
 const identity=new Pool(options(configuration.IDENTITY_DATABASE_URL));
 const review=new Pool(options(configuration.SECURESHOP_REVIEW_DATABASE_URL));let primary;
 try{return await work({identity,review});}catch(error){primary=error;throw error;}
 finally{const closed=await Promise.allSettled([identity.end(),review.end()]),failures=closed.filter(row=>row.status==='rejected').map(row=>row.reason);if(failures.length&&!primary)throw new AggregateError(failures,'A21 probe cleanup failed');}
}
async function a21IdentityCandidates(identity){
 return (await identity.query(`SELECT r.target_id AS "targetId",r.launch_id AS "launchId",
   l.scenario_id AS "scenarioId",r.generation::text AS generation,
   r.original_platform_owner_id AS "ownerId",l.original_platform_session_id AS "sessionId",
   o.realm,o.platform_user_id AS "platformUserId",o.shop_principal_id::text AS "ownerShopPrincipalId",
   o.shop_tenant_id::text AS "ownerShopTenantId",a.realm AS "sessionRealm",
   a.platform_session_id AS "platformSessionId",a.shop_session_id AS "shopSessionId",
   a.shop_execution_session_id AS "shopExecutionSessionId",
   s.scene_id AS "sceneId",s.is_default AS "sceneIsDefault",s.status AS "sceneStatus",
   s.birth_launch_id AS "sceneLaunchId",s.birth_scenario_id AS "sceneScenarioId",
   s.birth_generation::text AS "sceneGeneration",s.original_platform_owner_id AS "sceneOwnerId",
   s.birth_platform_session_id AS "sceneSessionId"
  FROM identity.secureshop_target_reservations r
  JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
  JOIN identity.secureshop_authority_owners o ON o.id=r.original_platform_owner_id
  JOIN identity.secureshop_authority_sessions a ON a.id=l.original_platform_session_id AND a.user_id=o.id
  LEFT JOIN identity.secureshop_scenes s ON s.product_target_id=r.target_id
  WHERE r.target_kind='products' ORDER BY r.created_at,r.target_id`)).rows;
}
async function a21ReviewCandidates(review){
 return (await review.query(`SELECT t.target_id AS "targetId",t.launch_id AS "launchId",
   t.scenario_id AS "scenarioId",t.generation::text AS generation,t.lifecycle,
   t.original_platform_owner_id AS "ownerId",t.original_platform_session_id AS "sessionId",
   encode(t.source_sha256,'hex') AS "sourceSha256",
   (SELECT count(*)::integer FROM secureshop_review.product_target_products p WHERE p.target_id=t.target_id) AS "productCount",
   (SELECT COALESCE(bool_and(octet_length(p.source_product_sha256)=32),false)
    FROM secureshop_review.product_target_products p WHERE p.target_id=t.target_id) AS "productHashesValid",
   (SELECT count(*)::integer FROM secureshop_review.product_target_orders o WHERE o.target_id=t.target_id) AS "orderCount",
   (SELECT count(*)::integer FROM secureshop_review.product_target_order_items i WHERE i.target_id=t.target_id) AS "itemCount",
   (SELECT count(*)::integer FROM secureshop_review.bound_commerce_operations c
    JOIN secureshop_review.product_target_orders o ON o.target_id=c.target_id
     AND o.shop_user_id=c.shop_user_id AND o.order_id=(c.result_json::jsonb->>'orderId')::bigint
    WHERE c.target_id=t.target_id AND c.kind='checkout' AND c.state='completed'
     AND EXISTS(SELECT 1 FROM secureshop_review.product_target_order_items i
      WHERE i.target_id=o.target_id AND i.order_id=o.order_id)) AS "checkoutCount",
   (SELECT c.operation_id::text FROM secureshop_review.bound_commerce_operations c
    JOIN secureshop_review.product_target_orders o ON o.target_id=c.target_id
     AND o.shop_user_id=c.shop_user_id AND o.order_id=(c.result_json::jsonb->>'orderId')::bigint
    WHERE c.target_id=t.target_id AND c.kind='checkout' AND c.state='completed'
     AND EXISTS(SELECT 1 FROM secureshop_review.product_target_order_items i
      WHERE i.target_id=o.target_id AND i.order_id=o.order_id)
    ORDER BY c.created_at,c.operation_id LIMIT 1) AS "receiptOperationId",
   (SELECT c.shop_user_id FROM secureshop_review.bound_commerce_operations c
    JOIN secureshop_review.product_target_orders o ON o.target_id=c.target_id
     AND o.shop_user_id=c.shop_user_id AND o.order_id=(c.result_json::jsonb->>'orderId')::bigint
    WHERE c.target_id=t.target_id AND c.kind='checkout' AND c.state='completed'
     AND EXISTS(SELECT 1 FROM secureshop_review.product_target_order_items i
      WHERE i.target_id=o.target_id AND i.order_id=o.order_id)
    ORDER BY c.created_at,c.operation_id LIMIT 1) AS "receiptActorId"
  FROM secureshop_review.product_targets t ORDER BY t.created_at,t.target_id`)).rows;
}
async function a21IdentitySnapshot(identity,row,{requireOriginalAbsence=false}={}){
 const result=await identity.query(`SELECT to_jsonb(v)::text AS payload FROM (
   SELECT 'reservation' AS kind,to_jsonb(r) AS value FROM identity.secureshop_target_reservations r WHERE r.target_id=$1
   UNION ALL SELECT 'launch',to_jsonb(l) FROM identity.secureshop_launches l WHERE l.launch_id=$2
   UNION ALL SELECT 'owner',to_jsonb(o) FROM identity.secureshop_authority_owners o WHERE o.id=$3
   UNION ALL SELECT 'session',to_jsonb(a) FROM identity.secureshop_authority_sessions a WHERE a.id=$4
   UNION ALL SELECT 'scene',to_jsonb(s) FROM identity.secureshop_scenes s WHERE s.scene_id=$5::uuid) v`,
 [row.targetId,row.launchId,row.ownerId,row.sessionId,row.sceneId]);
 assert.equal(result.rowCount,row.sceneId?5:4,'A21 target authority changed');
 if(requireOriginalAbsence&&!row.sceneId){const scenes=await identity.query('SELECT 1 FROM identity.secureshop_scenes WHERE product_target_id=$1',[row.targetId]);assert.equal(scenes.rowCount,0,'A21 upgrade created a scene');}
 return a21RowSet(result.rows);
}
async function a21ReviewSnapshot(review,targetId,expectedTables){
 const discovered=(await review.query(`SELECT table_name AS name FROM information_schema.columns
  WHERE table_schema='secureshop_review' AND column_name='target_id' ORDER BY table_name`)).rows.map(row=>row.name);
 const tables=expectedTables||discovered;
 assert(Array.isArray(tables)&&tables.length>0&&tables.every(table=>discovered.includes(table)),
  'A21 restored target evidence table unavailable');
 assert(tables.includes('product_targets')&&tables.includes('product_target_products')
  &&tables.includes('product_target_orders')&&tables.includes('product_target_order_items')
  &&tables.includes('bound_commerce_operations'),'A21 target evidence schema unavailable');
 const snapshots={};
 for(const table of tables){assert(/^[a-z][a-z0-9_]*$/.test(table));const rows=(await review.query(
   `SELECT to_jsonb(t)::text AS payload FROM secureshop_review.${table} t WHERE target_id=$1`,[targetId])).rows;
  snapshots[table]=a21RowSet(rows);}
 assert.equal(snapshots.product_targets.rows,1,'A21 target identity unavailable');
 return Object.freeze(snapshots);
}
async function captureA21Preservation(configuration){
 return withA21Pools(configuration,async({identity,review})=>{
  const descriptor=chooseA21RestoredSubset(await a21IdentityCandidates(identity),await a21ReviewCandidates(review)),targets={};
  for(const row of descriptor.targets)targets[row.targetId]=Object.freeze({identity:await a21IdentitySnapshot(identity,row,{requireOriginalAbsence:true}),review:await a21ReviewSnapshot(review,row.targetId)});
  return Object.freeze({descriptor,targets:Object.freeze(targets)});
 });
}
async function assertA21Preservation(configuration,expected,{allowSceneAdditions=false,allowSceneExecutionGrantAppend=allowSceneAdditions}={}){
 return withA21Pools(configuration,async({identity,review})=>{
  const current=chooseA21RestoredSubset(await a21IdentityCandidates(identity),await a21ReviewCandidates(review));
  assert.deepEqual(current.targets.map(row=>row.targetId),expected.descriptor.targets.map(row=>row.targetId),'A21 target inventory changed');
  assert.equal(current.attestation.platformScenes,expected.descriptor.attestation.platformScenes,'A21 platform scene inventory changed');
  if(allowSceneAdditions)assert(current.attestation.shopScenes>=expected.descriptor.attestation.shopScenes,'A21 shop scene removed');
  else assert.deepEqual(current.attestation,expected.descriptor.attestation,'A21 restored scene inventory changed');
  for(const descriptor of expected.descriptor.targets){const saved=expected.targets[descriptor.targetId];
   assertA21RowSet(await a21IdentitySnapshot(identity,descriptor,{requireOriginalAbsence:!allowSceneAdditions}),saved.identity,`A21 target authority changed: ${descriptor.targetId}`);
   const actual=await a21ReviewSnapshot(review,descriptor.targetId,Object.keys(saved.review));
   for(const [table,snapshot]of Object.entries(saved.review))assertA21RowSet(actual[table],snapshot,`A21 target evidence changed: ${table}`,
    {allowAppend:allowSceneExecutionGrantAppend&&table==='scene_execution_grants'});
  }
 });
}
async function runA21CollisionProbe(configuration,preservation){
 return withA21Pools(configuration,async({identity,review})=>{
  const suffix=crypto.randomUUID().replaceAll('-','').slice(0,10),username=`a21_${suffix}`;
  const password=`A21-${suffix}-Owned!9a`,email=`${username}@platform.invalid`;
  const identityRepository=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
  const platform=await identityRepository.registerUser({username,email,
   passwordHash:await require('../../server/services/authValidation').secureHashPassword(password)});
  const shopAuth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:
   require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity})});
  const registration=await shopAuth.register({username,email:`${username}@shop.invalid`,password,role:'customer'});
  const execution=await shopAuth.establishTenantContext(registration.context);
  assert.equal(platform.username,username);assert.equal(execution.username,username);
  assert.notEqual(Number(platform.id),execution.principalOwnerId);assert.notEqual(Number(platform.id),execution.ownerId);
  assert.notEqual(execution.principalOwnerId,execution.ownerId);
  const owners=(await identity.query(`SELECT id,realm,platform_user_id,shop_principal_id::text AS shop_principal_id,
   shop_tenant_id::text AS shop_tenant_id FROM identity.secureshop_authority_owners WHERE id=ANY($1::integer[]) ORDER BY id`,
  [[Number(platform.id),execution.principalOwnerId,execution.ownerId]])).rows;
  assert.equal(owners.length,3);const platformOwner=owners.find(row=>row.id===Number(platform.id));
  const principalOwner=owners.find(row=>row.id===execution.principalOwnerId),tenantOwner=owners.find(row=>row.id===execution.ownerId);
  assert(platformOwner&&platformOwner.realm==='platform'&&platformOwner.platform_user_id===Number(platform.id)
   &&platformOwner.shop_principal_id===null&&platformOwner.shop_tenant_id===null);
  assert(principalOwner&&principalOwner.realm==='shop'&&principalOwner.platform_user_id===null
   &&principalOwner.shop_principal_id===execution.principalId&&principalOwner.shop_tenant_id===null);
  assert(tenantOwner&&tenantOwner.realm==='shop'&&tenantOwner.platform_user_id===null
   &&tenantOwner.shop_principal_id===null&&tenantOwner.shop_tenant_id===execution.tenantId);
  const shopIds=[execution.principalOwnerId,execution.ownerId,execution.shopUserId];
  assert.equal(Number((await identity.query('SELECT count(*)::integer AS n FROM identity.users WHERE id=ANY($1::integer[])',[shopIds])).rows[0].n),0);
  assert.equal(Number((await identity.query('SELECT count(*)::integer AS n FROM identity.user_sessions WHERE id=ANY($1::integer[])',[[registration.context.sessionId,execution.sessionId]])).rows[0].n),0);
  assert.equal(Number((await identity.query('SELECT count(*)::integer AS n FROM identity.admin_permissions WHERE admin_id=ANY($1::integer[])',[[Number(platform.id),...shopIds]])).rows[0].n),0);
  const launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
  const issued=await launches.issueOrRenew({platformOwnerId:execution.ownerId,platformSessionId:execution.sessionId,
   expiresAt:new Date(Date.now()+15*60*1000).toISOString(),shopPrincipal:execution});
  const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({repository:
   require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool:identity,launches}),reviewPool:review,launches});
  const visible=await scenes.list(issued.binding),visibleIds=new Set(visible.map(row=>row.id));
  const platformScenes=preservation.descriptor.targets.filter(row=>row.sceneId&&row.authorityKind==='platform');
  for(const row of platformScenes){assert(!visibleIds.has(row.sceneId));await assert.rejects(()=>scenes.select(issued.binding,row.sceneId),error=>error?.code==='SHOP_SCENE_STALE');}
  const primary=preservation.descriptor.targets.find(row=>preservation.descriptor.receiptTargetIds.includes(row.targetId)&&visibleIds.has(row.sceneId));
  assert(primary,'A21 preservation unproven: restored checkout scene is not available to the current shop tenant');
  assert.notEqual(Number(primary.receiptActorId),execution.shopUserId,'A21 restored receipt actor collided with new buyer');
  const originalDefault=visible.find(row=>row.isDefault);assert(originalDefault,'A21 restored shop has no default scene');
  let selected=false;
  try{
   await scenes.select(issued.binding,primary.sceneId);selected=true;
   const binding=await scenes.readExisting(issued.binding);assert(binding?.scene&&binding.targetId===primary.targetId);
   const history=require('../../server/database/postgres/secureshopCheckoutHistoryRepository').createCheckoutHistoryRepository({pool:review,checkCurrent:scope=>launches.assertCurrent(scope)});
   await assert.rejects(()=>history.read(binding,execution.shopUserId,primary.receiptOperationId),error=>error?.code==='CHECKOUT_RECEIPT_NOT_FOUND');
  }finally{if(selected&&originalDefault.id!==primary.sceneId)await scenes.select(issued.binding,originalDefault.id);}
  return Object.freeze({principalsDistinct:true,platformPermissions:0,platformScenesHidden:platformScenes.length,
   restoredReceiptActorIsolated:true});
 });
}
async function runRetainedOwnershipInitializer({environment,initialize=require('../../db/postgres/initialize-application').initializeApplication}={}){
 assert(environment&&Object.getPrototypeOf(environment)===Object.prototype,'Retained ownership environment required');
 assert.equal(typeof initialize,'function','Retained ownership initializer required');
 Object.assign(process.env,environment);
 await initialize();
}
async function defaultRetainedOwnershipInitialization({installation,home,admin,environment},controlled={}){
 assert(path.isAbsolute(installation)&&path.isAbsolute(home)&&typeof admin==='string'&&environment&&Object.getPrototypeOf(environment)===Object.prototype);
 const admittedAdmin=new URL(admin);assert.equal(admittedAdmin.protocol,'postgresql:');assert.equal(admittedAdmin.hostname,'127.0.0.1');assert(/^\d+$/.test(admittedAdmin.port));assert.equal(admittedAdmin.pathname,'/postgres');assert(!admittedAdmin.search&&!admittedAdmin.hash);
 const input=path.join(installation,`retained-initialize-${crypto.randomUUID()}.json`),admittedPath=path.dirname(process.execPath)+':/usr/bin:/bin';
 const childEnvironment={...environment,PATH:admittedPath};fs.writeFileSync(input,JSON.stringify({installation,home,environment:childEnvironment}),{mode:0o600,flag:'wx'});
 const controls=controlled.controls||require('../../tests/fixtures/fullBackendBootControls');const children=controls.createOwnedChildren(controlled.spawn||require('node:child_process').spawn);let primary;
 try{const child=children.launch(process.execPath,[path.join(__dirname,'populated16-retained-ownership-initialize-child.cjs'),input],{cwd:installation,env:{PATH:admittedPath,HOME:home,TMPDIR:path.join(installation,'tmp'),PG_ADMIN_DATABASE_URL:admin,NODE_OPTIONS:'--require '+path.join(__dirname,'populated16-network-guard.cjs')},stdio:['ignore','ignore','ignore']});
  const code=await controls.waitForChild(child,{timeoutMs:600000});assert.equal(code,0,'Owned retained initializer child failed');
 }catch(error){primary=error;}finally{try{await children.cleanup();}catch(error){primary=primary?new AggregateError([primary,error],'Retained initializer and cleanup failed'):error;}}
 if(primary)throw primary;
}
function retainedPlatformTargets(a21){
 const targets=a21?.descriptor?.targets;
 assert(Array.isArray(targets)&&targets.length>0,'A21 retained target inventory unavailable');
 const platform=targets.filter(row=>row?.authorityKind==='platform');
 assert(platform.length>0&&platform.length<=16,'A21 retained platform target required');
 return Object.freeze(platform);
}
function retainedOwnershipReceipt({restored,platformTargets,collision}){
 assert.equal(restored.length,16,'All restored stores required');
 assert(Array.isArray(platformTargets)&&platformTargets.length>=1&&platformTargets.length<=16,'Retained platform target required');
 assert(collision?.principalsDistinct===true&&collision?.platformPermissions===0&&collision?.restoredReceiptActorIsolated===true,
  'A21 collision isolation unproven');
 return Object.freeze({status:'passed',scope:'retained-ownership-migrations-v1',restoredStores:16,canonicalLeaseRuns:2,
  retainedPlatformTargets:platformTargets.length,allStoresPreserved:true,collisionChecksPassed:true,noAutomaticLinking:true,
  noPrivilegedSurrogate:true,fullSetupProven:false,installedWrites:false});
}
async function rehearseLifecycle({backupManifest,backupSha256,quietBackupReceipt,quietBackupReceiptSha256,installation,home,admin,port,sourceConfiguration,mappings,sequenceDeltas={first:{},second:{}}},api={}, {retainedOwnership=false}={}){
 const deps={provision:provisionApplication,delivery:prepareCtfDelivery,run:db.run,snapshot:db.databaseSnapshot,sequences:backup.sequenceState,baseline:db.installPreservationBaseline,preserve:db.verifyPreservedRows,upgrade:defaultUpgrade,initialize:defaultRetainedOwnershipInitialization,schema:verifySchema,maintenance:maintenanceState,sequenceRegression,a21Capture:captureA21Preservation,a21Assert:assertA21Preservation,a21Collision:runA21CollisionProbe,...api};
 assert.deepEqual(Object.keys(sequenceDeltas).sort(),['first','second']);
 for(const phase of ['first','second']){assert(Object.keys(sequenceDeltas[phase]).length>0,'Prospective sequence policy missing');for(const store of Object.keys(sequenceDeltas[phase]))assert(provisioningPlan().some(row=>row.schema===store),'Unknown sequence policy store');}
 currentStage='backup-admission';
 admitQuietBackupReceipt(quietBackupReceipt,quietBackupReceiptSha256,backupManifest,backupSha256);
 const saved=admitBackup(backupManifest,backupSha256);ownedEndpoint(admin,port,sourceConfiguration);
 // Resolve write targets before any provisioning or restore mutation.
 remapEnvironment(sourceConfiguration,{}, {installation,home,mappings});
 for(const root of [installation,home]){assert(path.isAbsolute(root)&&!root.startsWith(MAIN+path.sep));assert.equal(fs.realpathSync(root),root);const s=fs.lstatSync(root);assert(s.isDirectory()&&s.uid===process.getuid()&&(s.mode&511)===448);assert.equal(fs.readdirSync(root).length,0);}
 const id=sha(Buffer.from(installation)).slice(0,12),directory=path.join(home,'.dvaia',id);fs.mkdirSync(directory,{recursive:true,mode:448});
 currentStage='filesystem-restore';
 const restoredFiles=restoreFiles(saved,path.dirname(backupManifest),installation,home,directory,mappings),{immutable,regenerated}=restoredFiles;
 assert.deepEqual(sourceConfiguration,require('dotenv').parse(fs.readFileSync(path.join(installation,'backup-restored','environment'))),'Configuration is not backed-up environment');
 currentStage='provision';
 const provision=await deps.provision({adminUrl:admin,manifestPath:path.join(directory,'provisioning.json')});assert.deepEqual(provision.plan,provisioningPlan());
 for(const name of ['tmp','logs','sensitive','app-data'])fs.mkdirSync(path.join(installation,name),{mode:448,recursive:true});
 const {env,restored}=await restoreStoresWithDelivery({sourceConfiguration,provision,directory,admin,port,installation,home,mappings,saved,backupRoot:path.dirname(backupManifest)},deps);
 currentStage='sequence-regression';
 const sequenceProbe=await deps.sequenceRegression(provision.configuration);assert.deepEqual(sequenceProbe,{cases:6,status:'passed'});
 if(fs.existsSync(path.join(directory,'app-data')))env.DVAIA_APP_DATA_ROOT=path.join(directory,'app-data');
 fs.writeFileSync(path.join(installation,'.env'),require('../../scripts/setup-application').encodeEnv(env),{flag:'wx',mode:384});
 currentStage='preservation-baseline';
 let retainedAssessmentBaseline=null;
 for(const {row,target}of restored){const tables=saved.stores[row.schema].source.tables;await deps.baseline(target,retainedOwnership&&row.schema==='identity'?retainedOwnershipPreservationTables(row,tables):preservationTablesForLifecycle(row,tables,[]));if(retainedOwnership&&row.schema==='identity')retainedAssessmentBaseline=await retainedAssessmentDefaultBaseline(target,deps.run);}
 assert(!retainedOwnership||retainedAssessmentBaseline,'Retained assessment baseline unavailable');
 currentStage='a21-preservation-baseline';
 const a21=await deps.a21Capture(env);
 const platformTargets=retainedOwnership?retainedPlatformTargets(a21):null;
 const identity=restored.find(x=>x.row.schema==='identity').target,originalMaintenance=await deps.maintenance(identity);
 currentStage=retainedOwnership?'retained-ownership-first-initialization':'first-upgrade';
 const firstInitializationStartedAt=retainedOwnership?await retainedAssessmentDatabaseClock(identity,deps.run):null;
 await (retainedOwnership?deps.initialize:deps.upgrade)({installation,home,admin,environment:{...env,...(process.env.DOCKER_HOST?{DOCKER_HOST:process.env.DOCKER_HOST}:{})}});
 const firstInitializationFinishedAt=retainedOwnership?await retainedAssessmentDatabaseClock(identity,deps.run):null;
 if(retainedOwnership)await verifyRetainedAssessmentDefaultAddition(identity,{baseline:retainedAssessmentBaseline,startedAt:firstInitializationStartedAt,finishedAt:firstInitializationFinishedAt},deps.run);
 const review=restored.find(x=>x.row.schema==='secureshop_review');
 await verifyCouponBackfill(saved.stores.secureshop_review.source,review.target,deps.run);
 currentStage='first-preservation';
 const first={},firstSequences={},preservationEntries=[];let preservationOmitted=0;
 for(const {row,target}of restored){
  try{await deps.preserve(target,retainedOwnership?{aggregate:true,maxComparisons:Math.max(0,MAX_PRESERVATION_DIAGNOSTICS-preservationEntries.length)}:{});}
  catch(error){
   if(retainedOwnership&&error?.preservationDiagnostic&&!error.preservationDiagnostic.store){
    Object.defineProperty(error,'preservationDiagnostic',{value:Object.freeze({...error.preservationDiagnostic,store:row.schema}),enumerable:false,configurable:true});
   }
   if(!retainedOwnership)throw error;
   const aggregate=error?.preservationComparisons;
   if(!aggregate||!Array.isArray(aggregate.entries)||!Number.isSafeInteger(aggregate.omitted)||aggregate.omitted<0)throw error;
   for(const comparison of aggregate.entries){const bounded=boundedPreservationComparison({preservationComparison:comparison});if(!bounded)throw error;if(preservationEntries.length<MAX_PRESERVATION_DIAGNOSTICS)preservationEntries.push(Object.freeze({...bounded,store:row.schema}));else preservationOmitted+=1;}
   preservationOmitted+=aggregate.omitted;
   continue;
  }
  first[row.schema]=await deps.snapshot(target);firstSequences[row.schema]=await deps.sequences(target);verifySequenceTransition(saved.stores[row.schema].sequences,firstSequences[row.schema],sequenceDeltas.first[row.schema]);
 }
 if(preservationEntries.length||preservationOmitted){const error=new Error('Preexisting rows changed');Object.defineProperty(error,'preservationComparisons',{value:Object.freeze({entries:Object.freeze(preservationEntries),omitted:preservationOmitted})});throw error;}
 currentStage='price-history-backfill';await verifyPriceHistoryBackfill(saved.stores.secureshop_review.source,review.target,deps.run,firstSequences.secureshop_review);
 const firstMaintenance=await deps.maintenance(identity);verifyMaintenanceTransition(originalMaintenance,firstMaintenance);
 for(const entry of immutable)assert.equal(sha(fs.readFileSync(entry.path)),entry.sha256,'Restored private file changed');
 (retainedOwnership?verifyRetainedOwnershipPrivateState:verifyRegeneratedPrivateState)(regenerated);
 currentStage='a21-first-preservation';await deps.a21Assert(env,a21);
 currentStage=retainedOwnership?'retained-ownership-second-initialization':'second-upgrade';
 await (retainedOwnership?deps.initialize:deps.upgrade)({installation,home,admin,environment:{...env,...(process.env.DOCKER_HOST?{DOCKER_HOST:process.env.DOCKER_HOST}:{})}});
 currentStage='second-preservation';
 const second={};for(const {row,target}of restored){second[row.schema]=await deps.snapshot(target);assert.deepEqual(withoutMaintenance(second[row.schema]),withoutMaintenance(first[row.schema]),'Repeated upgrade changed application rows');verifySequenceTransition(firstSequences[row.schema],await deps.sequences(target),sequenceDeltas.second[row.schema]);}
 verifyMaintenanceTransition(firstMaintenance,await deps.maintenance(identity));
 for(const entry of immutable)assert.equal(sha(fs.readFileSync(entry.path)),entry.sha256,'Restored private file changed');
 (retainedOwnership?verifyRetainedOwnershipPrivateState:verifyRegeneratedPrivateState)(regenerated);
 currentStage='a21-second-preservation';await deps.a21Assert(env,a21);
 currentStage='a21-collision-boundary';const a21Collision=await deps.a21Collision(env,a21);
 currentStage='a21-post-collision-preservation';await deps.a21Assert(env,a21,retainedOwnership?{allowSceneExecutionGrantAppend:true}:{allowSceneAdditions:true});
 if(retainedOwnership)return retainedOwnershipReceipt({restored,platformTargets,collision:a21Collision});
 return{status:'passed',restoredStores:restored.length,sequenceProbe,a21:{restoredTargets:a21.descriptor.attestation.targets,
  platformScenes:a21.descriptor.attestation.platformScenes,shopScenes:a21.descriptor.attestation.shopScenes,...a21Collision},sourceRoot:MAIN,installedWrites:false};
}
async function rehearse(options,api={}){return rehearseLifecycle(options,api);}
async function rehearseRetainedOwnershipMigrations(options,api={}){return rehearseLifecycle(options,api,{retainedOwnership:true});}
module.exports={privateJson,admitQuietBackupReceipt,admitBackup,ownedEndpoint,ownedAdminEnvironment,remapEnvironment,prepareDisposableEnvironment,compareRestore,sameRestore,restoreStore,restoreStoresWithDelivery,retainChildDiagnostic,retainFailure,retainSchemaEvidence,schemaText,verifySchema,verifySequenceTransition,verifyMaintenanceTransition,maintenanceLifecycleTables,retainedOwnershipPreservationTables,retainedAssessmentDefaultContract,retainedAssessmentDefaultBaseline,retainedAssessmentDatabaseClock,verifyRetainedAssessmentDefaultAddition,preservationTablesForLifecycle,maintenanceState,restoreFiles,encodeRestoredManagedEnvironment,verifyRegeneratedPrivateState,verifyRetainedOwnershipPrivateState,sequenceRegression,verifyCouponBackfill,verifyPriceHistoryBackfill,a21RowSet,assertA21RowSet,chooseA21RestoredSubset,a21ReviewSnapshot,captureA21Preservation,assertA21Preservation,runA21CollisionProbe,defaultUpgrade,runRetainedOwnershipInitializer,defaultRetainedOwnershipInitialization,retainedPlatformTargets,retainedOwnershipReceipt,failureProjection,rehearse,rehearseRetainedOwnershipMigrations};

async function main(){
 const gate=Buffer.alloc(1);assert.equal(fs.readSync(0,gate,0,1,null),1);assert.equal(gate[0],49);
 const evidence=process.env.SETUP_PHASE_EVIDENCE_ROOT,journal=privateJson(path.join(evidence,'ownership.json')).value;
 assert.equal(journal.nativePid,process.pid);assert.equal(journal.owner,process.env.SETUP_PHASE_OWNER);assert(RETAINED_REHEARSAL_COHORTS.has(journal.cohort),'Unexpected rehearsal cohort');assert.equal(journal.sourceRoot,MAIN);admittedEvidence=evidence;
 const request=privateJson(process.env.REHEARSAL_REQUEST);assert.equal(sha(request.bytes),process.env.REHEARSAL_REQUEST_SHA256);
 const base=process.env.SETUP_PHASE_INSTALLATION_ROOT,identity=fs.lstatSync(base),owned=journal.privateInstallation;
 assert.equal(owned.path,base);assert.equal(owned.device,identity.dev);assert.equal(owned.inode,identity.ino);assert.equal(owned.uid,process.getuid());
 const installation=path.join(base,'installation'),home=path.join(base,'home');fs.mkdirSync(installation,{mode:448});if(!fs.existsSync(home))fs.mkdirSync(home,{mode:448});
 const options={...request.value,installation,home,admin:process.env.PG_ADMIN_DATABASE_URL,port:Number(new URL(process.env.PG_ADMIN_DATABASE_URL).port)};
 assert.equal(options.port,journal.databasePort);
 const directory=path.join(home,'.dvaia',sha(Buffer.from(installation)).slice(0,12));
 options.mappings=Object.fromEntries(Object.entries(options.mappings).map(([key,value])=>[key,value.replace(/^@private(?=\/|$)/,directory).replace(/^@installation(?=\/|$)/,installation).replace(/^@home(?=\/|$)/,home)]));
 const result=await rehearse(options);fs.writeFileSync(path.join(evidence,'result.json'),JSON.stringify(result),{flag:'wx',mode:384});
}
if(require.main===module)main().catch(error=>{if(admittedEvidence){try{fs.writeFileSync(path.join(admittedEvidence,'result.json'),JSON.stringify(retainFailure(error,admittedEvidence)),{flag:'wx',mode:384});}catch{}}process.stderr.write('POPULATED_REHEARSAL_FAILED\n');process.exitCode=1;});
