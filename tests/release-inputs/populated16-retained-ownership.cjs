'use strict';
// Main-only retained-data migration qualifier. It restores the admitted backup into
// disposable PostgreSQL stores, then runs only the canonical initializer twice.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {privateJson,retainFailure,rehearseRetainedOwnershipMigrations}=require('./populated16-rehearsal.cjs');
const MAIN=path.resolve(__dirname,'../..');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const RESULT_KEYS=Object.freeze(['status','scope','restoredStores','canonicalLeaseRuns','retainedPlatformTargets','allStoresPreserved','collisionChecksPassed','noAutomaticLinking','noPrivilegedSurrogate','fullSetupProven','installedWrites']);
function assertResult(value){
 assert(value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===RESULT_KEYS.slice().sort().join(','));
 assert.equal(value.status,'passed');assert.equal(value.scope,'retained-ownership-migrations-v1');assert.equal(value.restoredStores,16);assert.equal(value.canonicalLeaseRuns,2);
 assert(Number.isInteger(value.retainedPlatformTargets)&&value.retainedPlatformTargets>=1&&value.retainedPlatformTargets<=16);
 for(const key of ['allStoresPreserved','collisionChecksPassed','noAutomaticLinking','noPrivilegedSurrogate'])assert.equal(value[key],true);
 for(const key of ['fullSetupProven','installedWrites'])assert.equal(value[key],false);
 return Object.freeze({...value});
}
function publish(evidence,name,value){
 const directory=fs.realpathSync(evidence),target=path.join(directory,name);assert.equal(path.dirname(target),directory);
 const stat=fs.lstatSync(directory);assert(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&511)===0o700);
 const bytes=Buffer.from(JSON.stringify(value)+'\n');const fd=fs.openSync(target,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}const after=fs.lstatSync(target);assert(after.isFile()&&!after.isSymbolicLink()&&after.uid===process.getuid()&&(after.mode&511)===0o600&&after.nlink===1);
 const directoryFd=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(directoryFd);}finally{fs.closeSync(directoryFd);}return target;
}
function admittedOptions(){
 const gate=Buffer.alloc(1);assert.equal(fs.readSync(0,gate,0,1,null),1);assert.equal(gate[0],49);
 const evidence=fs.realpathSync(process.env.SETUP_PHASE_EVIDENCE_ROOT),journal=privateJson(path.join(evidence,'ownership.json')).value;
 assert.equal(journal.nativePid,process.pid);assert.equal(journal.owner,process.env.SETUP_PHASE_OWNER);assert.equal(journal.cohort,'retained-ownership-migrations');assert.equal(journal.sourceRoot,MAIN);
 const request=privateJson(process.env.REHEARSAL_REQUEST);assert.equal(sha(request.bytes),process.env.REHEARSAL_REQUEST_SHA256);
 const base=process.env.SETUP_PHASE_INSTALLATION_ROOT,identity=fs.lstatSync(base),owned=journal.privateInstallation;
 assert.equal(owned.path,base);assert.equal(owned.device,identity.dev);assert.equal(owned.inode,identity.ino);assert.equal(owned.uid,process.getuid());
 const installation=path.join(base,'installation'),home=path.join(base,'home');fs.mkdirSync(installation,{mode:0o700});if(!fs.existsSync(home))fs.mkdirSync(home,{mode:0o700});
 const options={...request.value,installation,home,admin:process.env.PG_ADMIN_DATABASE_URL,port:Number(new URL(process.env.PG_ADMIN_DATABASE_URL).port)};
 assert.equal(options.port,journal.databasePort);const directory=path.join(home,'.owasp-ai-goat',sha(Buffer.from(installation)).slice(0,12));
 options.mappings=Object.fromEntries(Object.entries(options.mappings).map(([key,value])=>[key,value.replace(/^@private(?=\/|$)/,directory).replace(/^@installation(?=\/|$)/,installation).replace(/^@home(?=\/|$)/,home)]));
 return Object.freeze({evidence,options});
}
async function main(){const {evidence,options}=admittedOptions();let result;try{result=assertResult(await rehearseRetainedOwnershipMigrations(options));publish(evidence,'result.json',result);}catch(error){publish(evidence,'result.json',retainFailure(error,evidence));throw error;}}
if(require.main===module)main().catch(()=>{process.stderr.write('POPULATED_RETAINED_OWNERSHIP_FAILED\n');process.exitCode=1;});
module.exports={RESULT_KEYS,assertResult,publish,admittedOptions,main};
