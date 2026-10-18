'use strict';
const fs=require('node:fs'),path=require('node:path');
function observeSpawn(cp,record){const original=cp.spawn,errors=[];cp.spawn=function(...args){const child=original.apply(this,args);try{record(child,args);}catch{errors.push('OWNERSHIP_OBSERVATION_FAILED');}return child;};const restore=()=>{cp.spawn=original;};restore.assertRecorded=()=>{if(errors.length)throw Error('Ownership observation unavailable');};return restore;}
function admitInstallation(rootInput,evidenceInput,owner,sourceRoot=path.resolve(__dirname,'../..')){
 const root=fs.realpathSync(rootInput),evidence=fs.realpathSync(evidenceInput);
 if(root!==rootInput||root===sourceRoot||root.startsWith(sourceRoot+path.sep)||!evidence.startsWith(path.join(sourceRoot,'backups/private-recovery')+path.sep))throw Error('OWNED_INSTALLATION_INVALID');
 const file=path.join(evidence,'ownership.json'),js=fs.lstatSync(file);
 if(!js.isFile()||js.isSymbolicLink()||js.uid!==process.getuid()||js.nlink!==1||js.size>65536||(js.mode&0o077)!==0)throw Error('OWNED_JOURNAL_INVALID');
 const journal=JSON.parse(fs.readFileSync(file,'utf8')),row=journal.privateInstallation,st=fs.lstatSync(root);
 if(!/^[a-f0-9]{32}$/.test(owner||'')||journal.owner!==owner||journal.evidenceRoot!==evidence||!row||row.path!==root||row.device!==st.dev||row.inode!==st.ino||row.uid!==st.uid||st.uid!==process.getuid()||!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o777)!==0o700)throw Error('OWNED_INSTALLATION_IDENTITY_MISMATCH');
 return root;
}
function failureDiagnostic(error,stage){
 const allowed=new Set(['OWNED_INSTALLATION_INVALID','OWNED_JOURNAL_INVALID','OWNED_INSTALLATION_IDENTITY_MISMATCH','APPLICATION_MAINTENANCE_DIRTY','APPLICATION_MAINTENANCE_UNAVAILABLE']);
 const code=allowed.has(error?.code)?error.code:allowed.has(error?.message)?error.message:'PROSPECTIVE_FIXTURE_FAILED';
 const diagnosticCode=error?.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&error?.diagnosticCode!==undefined?require('../../scripts/application-journal-bound-maintenance').sanitizedFailureCode({code:error.diagnosticCode}):undefined;
 return {type:'fixture-error',...(diagnosticCode?{diagnosticCode}:{}),stage:['admission','bootstrap','original'].includes(stage)?stage:'admission',code};
}
let currentStage='admission';
async function main(){
 if(process.env.PG_TEST_DISPOSABLE!=='yes'||!process.send||process.argv.length!==4||!['bootstrap','original'].includes(process.argv[2]))throw Error('Owned prospective fixture required');
 const sourceRoot=path.resolve(__dirname,'../..'),root=admitInstallation(process.argv[3],process.env.SETUP_PHASE_EVIDENCE_ROOT,process.env.SETUP_PHASE_OWNER,sourceRoot);
 const d=require('../../scripts/lib/application-maintenance-installation').resolveMaintenanceInstallation(root);Object.assign(process.env,require('dotenv').parse(fs.readFileSync(d.envPath)));
 const send=m=>new Promise((resolve,reject)=>process.send(m,e=>e?reject(e):resolve()));
 currentStage=process.argv[2];
 if(process.argv[2]==='original'){
  const cp=require('node:child_process'),restore=observeSpawn(cp,(child,args)=>{
   if(args[1]?.[1]!=='--owned-prospective-original')throw Error('Unexpected observed spawn');
   // Recording is transparent: exact native arguments/result; no authority substitution.
   const birth=cp.execFileSync('/bin/ps',['-p',String(child.pid),'-o','lstart='],{encoding:'utf8',timeout:2000}).trim();if(!birth)throw Error('Owned birth unavailable');
   const file=path.join(process.env.SETUP_PHASE_EVIDENCE_ROOT,'nested-processes.json'),owner=process.env.SETUP_PHASE_OWNER,parentPid=Number(process.env.SETUP_PHASE_NATIVE_PARENT);if(!/^[a-f0-9]{32}$/.test(owner||'')||!Number.isSafeInteger(parentPid))throw Error('Owned journal binding');
   const row=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):{owner,parentPid,groups:[]};if(row.owner!==owner||row.parentPid!==parentPid||row.groups.length>=2)throw Error('Owned journal mismatch');row.groups.push({pid:child.pid,id:require('node:crypto').randomUUID(),birth});const temporary=file+'.pending',fd=fs.openSync(temporary,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(row));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temporary,file);const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
  });try{await require('../../scripts/application-journal-bound-maintenance').runProspectiveJournalBoundMaintenance({installationRoot:root});}finally{restore();}restore.assertRecorded();
 }else{
  await require('../../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment:process.env},async scope=>{
   await require('../../db/postgres/initialize-application').initializeApplication({maintenanceScope:scope});const pool=require('../../server/database/postgres').createPool(process.env,'IDENTITY_MIGRATION_DATABASE_URL');try{await require('../../db/postgres/bootstrap-admin').bootstrapAdmin({pool,...require('../../scripts/lib/setup-administrator-journal').ensureAdministratorJournal({directory:d.directory}),initialTrainingProfile:true});}finally{await pool.end();}
  });
  // Leave the clean bootstrap ledger at its actual supported version. The owned
  // production admission must install its required schema after the parent grant.
 }
 await send({type:'result',completed:true});
}
if(require.main===module){const timer=setTimeout(()=>process.exit(1),590000);main().then(()=>{clearTimeout(timer);process.exit(0);},error=>{clearTimeout(timer);const diagnostic=failureDiagnostic(error,currentStage);if(process.send)process.send(diagnostic,()=>process.exit(1));else process.exit(1);setTimeout(()=>process.exit(1),1000).unref();});}
module.exports={observeSpawn,admitInstallation,failureDiagnostic};
