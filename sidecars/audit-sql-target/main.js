'use strict';
const fs=require('node:fs'),{Pool}=require('pg');
const {createService}=require('./service'),{createJournal}=require('./journal'),{assertReadiness}=require('./readiness'),{createPrivateAuditServer}=require('./http');
const {createOwnedAuditBackend}=require('../../server/services/secureshopOwnedAuditSearchBackend');
async function start(file,{cleanupOnly=false}={}){
 let bytes;if(process.platform==='win32')bytes=require('../../scripts/lib/audit-sql-private-state').read(file);else{const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077)||stat.uid!==process.getuid())throw Error('Private owned configuration required');bytes=fs.readFileSync(file,'utf8');}
 const config=JSON.parse(bytes);
 if((config.enabled!==true&&!cleanupOnly)||!Number.isInteger(config.databasePort)||config.databasePort<1024||config.databasePort>65535||!Number.isInteger(config.port)||config.port<1024||config.port>65535||!/^owasp_ai_goat_audit_control_[a-f0-9]+$/.test(config.database)||!/^[-_A-Za-z0-9]{43,128}$/.test(config.token)||!/^[a-f0-9]{64}$/.test(config.password))throw Error('Audit service configuration unavailable');
 const clusterConfig={host:'127.0.0.1',port:config.databasePort,database:config.database,user:'audit_service_admin',password:config.password,connectionTimeoutMillis:3000};
 const pool=new Pool({...clusterConfig,max:6});const service=createService({controlPool:pool,clusterConfig});
 const check=()=>assertReadiness({pool,controlDatabase:config.database,administrator:'audit_service_admin'});
 try{await check();const app=createPrivateAuditServer({token:config.token,backend:createOwnedAuditBackend({journal:createJournal({pool}),service,checkReadiness:check}),admissions:!cleanupOnly});await app.listen(config.port);
 return{close:()=>require('../../server/services/applicationLifecycle').settleApplicationCleanup([()=>app.close(),()=>pool.end()])};
 }catch(error){try{await require('../../server/services/applicationLifecycle').settleApplicationCleanup([()=>service.close(),()=>pool.end()]);}catch(cleanup){throw new AggregateError([error,cleanup],'Owned audit startup cleanup failed');}throw error;}
}
if(require.main===module){start(process.argv[2]).then(app=>{let closing=false;const close=()=>{if(closing)return;closing=true;app.close().then(()=>process.exit(0),()=>process.exit(1));};process.once('SIGTERM',close);process.once('SIGINT',close);}).catch(()=>{console.error('Owned audit SQL service startup failed');process.exitCode=1;});}
module.exports={start};
