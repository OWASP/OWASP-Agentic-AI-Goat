'use strict';
const fs=require('node:fs'),path=require('node:path');
const CASES=Object.freeze(['success','begin-commit-loss','finish-commit-loss','interrupted-original']);
function installCommitBoundary(Client,scenario,notify){
 if(!CASES.includes(scenario))throw Error('Unknown original writer case');
 const original=Client.prototype.query;let injected=false;const stages=new WeakMap();
 Client.prototype.query=function(...args){
  const sql=typeof args[0]==='string'?args[0]:args[0]?.text;
  if(this.connectionParameters?.application_name!=='owasp-ai-goat-maintenance-lease'||typeof sql!=='string')return original.apply(this,args);
  if(sql==='BEGIN')stages.delete(this);
  if(sql.startsWith('INSERT INTO dvaia_maintenance.epoch_replay_profiles'))stages.set(this,'begin');
  if(sql.startsWith('INSERT INTO dvaia_maintenance.epoch_finish_receipts'))stages.set(this,'finish');
  const stage=stages.get(this),result=original.apply(this,args);
  if(sql!=='COMMIT'||injected||!stage)return result;
  return Promise.resolve(result).then(async value=>{
   if(scenario===stage+'-commit-loss'||scenario==='interrupted-original'&&stage==='begin'){
    injected=true;await notify({type:'committed',stage});
    if(scenario==='interrupted-original')return new Promise(()=>{});
    throw Object.assign(Error('Owned delegated commit response loss'),{code:'OWNED_COMMIT_RESPONSE_LOST'});
   }
   return value;
  });
 };
 return()=>{Client.prototype.query=original;};
}
function createStageDiagnostics(){
 const codes=new Set(['APPLICATION_INITIALIZATION_REQUIRES_EXIT','APPLICATION_MAINTENANCE_PREPARATION_INVALID','APPLICATION_MAINTENANCE_BUSY','APPLICATION_MAINTENANCE_DIRTY','OWNED_COMMIT_RESPONSE_LOST','ETIMEDOUT','ECONNRESET','ENOENT','EACCES','23505','42501','P0001']);
 const events=[];let stage='workflow-entry',lastCompleted=null;
 const code=e=>codes.has(e?.code)?e.code:'UNCLASSIFIED';
 function wrap(target,key,label){const original=target[key];target[key]=async function(...args){stage=label;if(events.length<24)events.push({stage:label,state:'entered'});try{const value=await original.apply(this,args);lastCompleted=label;if(events.length<24)events.push({stage:label,state:'returned'});return value;}catch(e){if(events.length<24)events.push({stage:label,state:'failed',code:code(e)});throw e;}};}
 return {wrap,snapshot:e=>({stage,lastCompleted,code:code(e),events:events.map(x=>({...x}))})};
}
async function main(){
 if(process.env.PG_TEST_DISPOSABLE!=='yes'||!process.send)throw Error('Owned IPC fixture only');
 const root=fs.realpathSync(process.cwd()),home=process.env.HOME;
 const env=require('dotenv').parse(fs.readFileSync(path.join(root,'.env')));Object.assign(process.env,env);
 const send=m=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Owned IPC deadline')),1000);process.send(m,e=>{clearTimeout(timer);e?reject(e):resolve();});});
 const watchdog=setTimeout(()=>process.exit(72),590000);let lease;const diagnostics=createStageDiagnostics();
 try{
  if(process.env.ORIGINAL_WRITER_MODE==='dirty-entry'){
   const tools=require('../../server/services/applicationMaintenanceLease'),acquire=tools.acquireApplicationMaintenanceLease;
   tools.acquireApplicationMaintenanceLease=async options=>{const actual=await acquire(options);return{...actual,async assertClean(){try{return await actual.assertClean();}catch(e){await send({type:'entry',code:e.code,serverConstructed:Boolean(require.cache[require.resolve('../../server/applicationServer')])});throw e;}}};};
   require('../../server/index');await new Promise(()=>{});
  }
  if(process.env.ORIGINAL_WRITER_MODE==='bootstrap'){
   await require('../../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment:process.env},async scope=>{
    await require('../../db/postgres/initialize-application').initializeApplication({maintenanceScope:scope});
    const pg=require('../../server/database/postgres'),pool=pg.createPool(process.env,'IDENTITY_MIGRATION_DATABASE_URL');
    try{const directory=path.join(home,'.owasp-ai-goat',require('node:crypto').createHash('sha256').update(root).digest('hex').slice(0,12));const admin=require('../../scripts/lib/setup-administrator-journal').ensureAdministratorJournal({directory});await require('../../db/postgres/bootstrap-admin').bootstrapAdmin({pool,...admin,initialTrainingProfile:true});}finally{await pool.end();}
   });await send({type:'result',completed:true});return;
  }
  const scenario=process.env.ORIGINAL_WRITER_CASE;if(!CASES.includes(scenario))throw Error('Closed case required');
  installCommitBoundary(require('pg').Client,scenario,send);
  lease=await require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'maintenance',env:process.env});
  const observed=await require('../../server/services/applicationMaintenanceLease').observeExclusiveMaintenanceLease(lease);await send({type:'lease',pid:observed.pid,backendStart:observed.backendStart});
  const prepared=await require('../../server/services/applicationMaintenanceInprocessAdmission').prepareInprocessAdmission({lease,root,homeDirectory:home,adminUrl:process.env.PG_ADMIN_DATABASE_URL});
  for(const [module,key,label] of [
   ['../../db/postgres/initialize-application','initializeApplication','initialize'],
   ['../../scripts/install/ctf-authority-setup','prepareCtfAuthority','ctf-prepare'],
   ['../../server/database/postgres','drainAndInspectPreparedMaintenance','drain-inspect']
  ])diagnostics.wrap(require(module),key,label);
  const result=await require('../../server/services/applicationMaintenanceInprocessWorkflow').runInprocessMaintenance({lease,prepared});
  await lease.close();lease=null;await send({type:'result',completed:result.completed,epoch:result.epoch});
 }catch(error){await send({type:'result',completed:false,diagnostic:diagnostics.snapshot(error)});process.exitCode=1;}
 // Failure may have unknown physical work: never release its held lease explicitly.
 // The owned CLI terminates below; parent must join and verify backend absence.
 finally{clearTimeout(watchdog);}
}
if(require.main===module)main().then(()=>process.exit(process.exitCode||0),()=>process.exit(1));
module.exports={CASES,installCommitBoundary,createStageDiagnostics};
