'use strict';
// Native disposable-PostgreSQL fixture. It uses the real recovery authorities;
// IPC only tells the owning parent when a deliberate interruption is safe.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),{randomUUID}=require('node:crypto');
const allowed=new Set(['hold-lock','claim-only','launch-original','launch-hold-lock','launch-claim-only']);
async function send(value){await new Promise((resolve,reject)=>process.send(value,error=>error?reject(error):resolve()));}
let currentStage='admission';
function diagnostic(error){const code=/^(APPLICATION_MAINTENANCE_|APPLICATION_LEASE_|CTF_JOURNAL_|LOCAL_PROCESS_|MAINTENANCE_INSPECTION_)[A-Z_]+$/.test(error?.code||'')?error.code:'RECOVERY_FIXTURE_FAILED',name=['Error','TypeError','AggregateError'].includes(error?.name)?error.name:'Error',root=path.resolve(__dirname,'../..'),frames=String(error?.stack||'').split('\n').slice(1).flatMap(line=>{const match=line.match(/(?:\(|at )(\/[^():]+):(\d+):(\d+)\)?$/);if(!match)return[];const file=path.resolve(match[1]);if(!file.startsWith(root+path.sep))return[];return[{file:path.relative(root,file),line:Number(match[2]),column:Number(match[3])}];}).slice(0,8);return{type:'fixture-error',stage:currentStage,code,name,frames};}
function persistOrphanFailure(value){const file=path.join(process.env.SETUP_PHASE_EVIDENCE_ROOT,`recovery-orphan-failure-${process.pid}.json`),fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify({version:1,mode:process.argv[2],diagnostic:value},null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function persistOrphanReady(mode){const owner=process.env.SETUP_PHASE_OWNER;if(mode!=='claim-only'||!/^[a-f0-9]{32}$/.test(owner||''))throw Error('Owned recovery readiness invalid');const directory=process.env.SETUP_PHASE_EVIDENCE_ROOT,file=path.join(directory,`recovery-orphan-ready-${process.pid}.json`),temporary=file+'.pending-'+randomUUID(),fd=fs.openSync(temporary,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify({version:1,mode,owner,pid:process.pid,state:'claimed'})+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}try{fs.linkSync(temporary,file);fs.unlinkSync(temporary);}catch(error){try{fs.unlinkSync(temporary);}catch(unlinkError){if(unlinkError.code!=='ENOENT')throw unlinkError;}throw error;}const dir=fs.openSync(directory,'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}
function readBirth(pid){try{return cp.execFileSync('/bin/ps',['-p',String(pid),'-o','lstart='],{encoding:'utf8',timeout:2000}).trim()||null;}catch(error){if(error.status===1&&!String(error.stdout||'').trim())return null;throw error;}}
function groupPresent(pgid){return cp.execFileSync('/bin/ps',['-axo','pgid=,uid='],{encoding:'utf8',timeout:2000}).trim().split('\n').some(line=>{const[group,uid]=line.trim().split(/\s+/).map(Number);return group===pgid&&uid===process.getuid();});}
async function rollbackUnjournaled(child,birth){const observed=readBirth(child.pid);if(observed!==null&&birth!==null&&observed!==birth)throw Error('Owned orphan birth changed before rollback');if(observed!==null){try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}}for(let i=0;i<100;i++){if(!groupPresent(child.pid))return;await new Promise(resolve=>setTimeout(resolve,20));}throw Error('Unjournaled owned orphan remains');}
function appendOwnedGroup(evidence,owner,parentPid,child,birth){
 const file=path.join(evidence,'nested-processes.json');if(!birth)throw Error('Owned orphan birth unavailable');
 const row=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):{owner,parentPid,groups:[]};if(row.owner!==owner||row.parentPid!==parentPid||!Array.isArray(row.groups)||row.groups.length>=256)throw Error('Owned orphan journal mismatch');row.groups.push({pid:child.pid,id:randomUUID(),birth});
 const temporary=file+'.pending',fd=fs.openSync(temporary,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(row));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temporary,file);const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}return{pid:child.pid,birth};
}
async function launchOrphan(mode,root,sourceRoot){
 const target=mode.slice('launch-'.length),script=target==='original'?path.join(sourceRoot,'tests/fixtures/applicationMaintenanceProspectiveProcess.cjs'):__filename,args=target==='original'?['original',root]:[target,root];
 const child=cp.spawn('/bin/sh',['-c','kill -STOP $$; exec "$@"','owned-recovery',process.execPath,script,...args],{cwd:sourceRoot,detached:true,env:{...process.env,RECOVERY_ORPHANED_ATTEMPT:'1'},stdio:['ignore','ignore','ignore','ipc']});let birth=null,appended=false;
 try{birth=readBirth(child.pid);if(!birth)throw Error('Owned orphan birth unavailable');for(let i=0;i<100;i++){const state=cp.execFileSync('/bin/ps',['-p',String(child.pid),'-o','stat='],{encoding:'utf8',timeout:2000}).trim();if(state.startsWith('T'))break;if(i===99)throw Error('Owned orphan did not stop');await new Promise(resolve=>setTimeout(resolve,10));}
  if(process.env.RECOVERY_ORPHAN_TEST_FAIL==='append')throw Error('Controlled orphan append failure');const row=appendOwnedGroup(process.env.SETUP_PHASE_EVIDENCE_ROOT,process.env.SETUP_PHASE_OWNER,Number(process.env.SETUP_PHASE_NATIVE_PARENT),child,birth);appended=true;child.disconnect();child.unref();await send({type:'orphan-stopped',target,pid:row.pid,birth:row.birth});
 }catch(error){if(!appended)await rollbackUnjournaled(child,birth);throw error;}
}
async function main(){
 if(process.env.PG_TEST_DISPOSABLE!=='yes'||process.env.SETUP_PHASE_SCENARIO!=='prospective-recovery'||!process.send||process.argv.length!==4||!allowed.has(process.argv[2]))throw Error('Owned recovery fixture required');
 const sourceRoot=fs.realpathSync(path.resolve(__dirname,'../..')),root=require('./applicationMaintenanceProspectiveProcess.cjs').admitInstallation(process.argv[3],process.env.SETUP_PHASE_EVIDENCE_ROOT,process.env.SETUP_PHASE_OWNER,sourceRoot);
 if(sourceRoot!==process.cwd()||process.env.HOME!==root)throw Error('Owned recovery installation required');
 if(process.argv[2].startsWith('launch-'))return launchOrphan(process.argv[2],root,sourceRoot);
 const installation=require('../../scripts/lib/application-maintenance-installation').resolveMaintenanceInstallation(root);
 Object.assign(process.env,require('dotenv').parse(fs.readFileSync(installation.envPath)));
 currentStage='profile';
 const lease=await require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'maintenance',env:process.env});
 const identity=require('../../server/services/applicationMaintenanceLease').inprocessLeaseIdentity(lease),proofs=require('../../server/database/postgres/applicationMaintenanceRecoveryProof');
 const session=await require('../../server/services/applicationMaintenanceDirtyProfile').prepareDirtyRecovery({lease,root:sourceRoot,configurationRoot:root,homeDirectory:root,adminUrl:process.env.PG_ADMIN_DATABASE_URL});
 currentStage='claim';
 const state=proofs.sessionState(session,identity),token=await lease.claimRecovery(state.expected,proofs.issueVerifiedRecoveryProof(session,identity,'claim'));
 const attempt=require('../../server/database/postgres/applicationMaintenanceRecoveryControl').recoveryTokenState(token,identity);
 if(process.argv[2]==='claim-only'){if(process.env.RECOVERY_ORPHANED_ATTEMPT==='1')persistOrphanReady('claim-only');else await send({type:'claimed',attemptId:attempt.attemptId});await new Promise(()=>{});}
 currentStage='journal';
 await require('../../scripts/install/ctf-authority-journal').withCtfAuthorityJournal({directory:state.directory,binding:state.ctfJournalBinding,maintenanceLease:lease,recoverySession:session,recoveryToken:token},async()=>{if(process.env.RECOVERY_ORPHANED_ATTEMPT!=='1')await send({type:'lock-held',attemptId:attempt.attemptId});await new Promise(()=>{});});
}
if(require.main===module){const timer=setTimeout(()=>process.exit(1),720000);main().then(()=>{clearTimeout(timer);process.exit(0);},async error=>{clearTimeout(timer);const value=diagnostic(error);if(process.env.RECOVERY_ORPHANED_ATTEMPT==='1')try{persistOrphanFailure(value);}catch{}try{await send(value);}catch{}process.exit(1);});}
module.exports={rollbackUnjournaled};
