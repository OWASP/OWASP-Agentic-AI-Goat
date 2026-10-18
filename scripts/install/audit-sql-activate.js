'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {workspaceId}=require('../../server/services/mcp/ownedManagedConfiguration');
const REQUIRED=Object.freeze({identity:['0090_secureshop_audit_query_operations.sql','0092_secureshop_audit_sql_objective.sql','0094_secureshop_audit_sql_defaults.sql'],agents:['0022_secureshop_audit_sql_purpose.sql']});
async function assertApplicationPrerequisites({root,environment,createPool=options=>new(require('pg').Pool)(options)}){
 if(!require('../../server/config/secureshopCurriculum').isQualifiedObjective('ss_audit_sql_extraction'))throw Error('AUDIT_SQL_OBJECTIVE_UNQUALIFIED');
 const keys=['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL','SECURESHOP_AGENTS_MIGRATION_DATABASE_URL'];if(keys.some(key=>!environment[key]))throw Error('AUDIT_SQL_DATABASE_CONFIGURATION_REQUIRED');const pools=keys.map(key=>createPool({connectionString:environment[key],max:1,connectionTimeoutMillis:5000}));
 try{
  for(const [group,pool,folder] of [['identity',pools[1],'db/postgres/identity-migrations'],['agents',pools[2],'db/postgres/workshop-migrations/secureshop_agents']])for(const name of REQUIRED[group]){const expected=crypto.createHash('sha256').update(await fs.readFile(path.join(root,folder,name))).digest('hex');const row=(await pool.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[name])).rows[0];if(row?.checksum!==expected)throw Error('AUDIT_SQL_MIGRATION_MISMATCH');}
  const unavailable=async()=>{throw Error('Readiness cannot admit operations');};
  await require('../../server/database/postgres/secureshopAuditTargetAdmissionRepository').createAuditTargetAdmissionRepository({pool:pools[0]}).checkReadiness();
  await require('../../server/database/postgres/secureshopAuditQueryRepository').createAuditQueryRepository({pool:pools[0],checkExecutionBinding:unavailable}).checkReadiness();
  await require('../../server/database/postgres/secureshopAuditManualRepository').createAuditManualRepository({pool:pools[0],personaAuth:{authenticateBoundToken:unavailable}}).checkReadiness();
  return{ready:true};
 }finally{const result=await Promise.allSettled(pools.map(pool=>pool.end()));const errors=result.filter(row=>row.status==='rejected').map(row=>row.reason);if(errors.length)throw new AggregateError(errors,'Audit readiness pools failed to close');}
}
async function activateForSetup({root=path.resolve(__dirname,'../..'),homeDirectory=os.homedir(),environment=process.env,checkPrerequisites=assertApplicationPrerequisites,start=require('../../sidecars/audit-sql-target/main').start,createClient=require('../../server/services/secureshopOwnedAuditHttpClient').createOwnedAuditHttpClient}={}){
 const id=workspaceId(root),file=path.join(homeDirectory,'.dvaia',id,'audit-sql-target.json'),native=process.platform==='win32'?require('../lib/audit-sql-private-state'):null;
 let stat,before;if(native)before=native.read(file);else{stat=await fs.lstat(file);if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077)||stat.uid!==process.getuid())throw Error('AUDIT_SQL_PRIVATE_CONFIGURATION_REQUIRED');before=await fs.readFile(file,'utf8');}const config=JSON.parse(before);
 if(config.workspace!==id||config.container!==`dvaia-audit-sql-${id}`||config.volume!==`dvaia-audit-sql-${id}-data`||config.database!==`dvaia_audit_control_${id}`||config.provisioned!==true||typeof config.enabled!=='boolean')throw Error('AUDIT_SQL_OWNERSHIP_CONFLICT');
 // Old or explicitly disabled configurations are operator-owned preferences.
 if(config.activationPending!==true)return{activationEnabled:config.enabled&&config.agentEnabled===true,preserved:true};
 await checkPrerequisites({root,environment});const daemon=await start(file,{cleanupOnly:true});
 try{const client=createClient({url:`http://127.0.0.1:${config.port}`,token:config.token});const status=await client.readiness();if(status?.ready!==true||status.capability!=='owned-audit-postgres.v1')throw Error('AUDIT_SQL_SERVICE_UNAVAILABLE');}finally{await daemon.close();}
 if(native){if(!native.read(file).equals(before))throw Error('AUDIT_SQL_CONFIGURATION_CHANGED');native.write(file,Buffer.from(JSON.stringify({...config,enabled:true,agentEnabled:true,activationPending:false})+'\n'),before);return{activationEnabled:true,preserved:false};}
 const current=await fs.lstat(file);if(current.isSymbolicLink()||current.ino!==stat.ino||current.dev!==stat.dev||current.uid!==stat.uid||(current.mode&0o077)||(await fs.readFile(file,'utf8'))!==before)throw Error('AUDIT_SQL_CONFIGURATION_CHANGED');
 const temporary=file+'.'+crypto.randomBytes(8).toString('hex');try{await fs.writeFile(temporary,JSON.stringify({...config,enabled:true,agentEnabled:true,activationPending:false})+'\n',{flag:'wx',mode:0o600});await fs.rename(temporary,file);}finally{await fs.rm(temporary,{force:true});}
 return{activationEnabled:true,preserved:false};
}
module.exports={REQUIRED,assertApplicationPrerequisites,activateForSetup};
