'use strict';
// Read-only observations, never recovery authority or a lease replacement.
const fs=require('node:fs'),{createHash}=require('node:crypto');
const {Client}=require('pg');
const {performance}=require('node:perf_hooks');
const {poolConfig,reserveDedicatedConnection,reserveFinalInspectionConnection}=require('./index');
const {observeExclusiveMaintenanceLease}=require('../../services/applicationMaintenanceLease');
const {provisioningPlan,verifyOwned,clusterIdentity,requirePostgres18}=require('../../../db/postgres/provision-application');
const fail=code=>Object.assign(Error(code),{code});
function privateManifest(file,{filesystemPlatform=process.platform,privateState}={}){
 if(filesystemPlatform==='win32'){
  try{const bytes=(privateState||require('../../../scripts/lib/windows-private-state')).readPrivateFile(file);if(!Buffer.isBuffer(bytes)||bytes.length>1048576)throw Error();return JSON.parse(bytes.toString('utf8'));}catch{throw fail('MAINTENANCE_INSPECTION_MANIFEST_INVALID');}
 }
 if(typeof file!=='string'||fs.realpathSync(file)!==file)throw fail('MAINTENANCE_INSPECTION_MANIFEST_INVALID');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.nlink!==1||s.size>1024*1024)throw fail('MAINTENANCE_INSPECTION_MANIFEST_INVALID');const buffer=Buffer.alloc(1048577);let length=0;while(length<buffer.length){const count=fs.readSync(fd,buffer,length,buffer.length-length,length);if(!count)break;length+=count;}const after=fs.fstatSync(fd),named=fs.lstatSync(file);if(length!==s.size||length>1048576||!named.isFile()||named.isSymbolicLink()||['dev','ino','size','mode','uid','nlink','mtimeMs','ctimeMs'].some(k=>s[k]!==after[k]||s[k]!==named[k]))throw fail('MAINTENANCE_INSPECTION_MANIFEST_INVALID');return JSON.parse(buffer.subarray(0,length).toString('utf8'));}finally{fs.closeSync(fd);}
}
function createApplicationMaintenanceStoreInspection({environment=process.env,manifestPath,deliveryManifestPath,lease,terminalPermit,filesystemPlatform=process.platform,privateState}={}){
 const readManifest=file=>privateManifest(file,{filesystemPlatform,privateState});
 const env=Object.freeze({...environment}),plan=provisioningPlan();let active=false,poisoned=false;
 return Object.freeze({async inspect(){
  if(poisoned)throw fail('MAINTENANCE_INSPECTION_DRAIN_UNKNOWN');
  if(active)throw fail('MAINTENANCE_INSPECTION_BUSY');active=true;
  const clients=[];let primary,result;const deadline=performance.now()+60000;
  const remaining=()=>{const ms=Math.min(3000,deadline-performance.now());if(ms<=0)throw fail('MAINTENANCE_INSPECTION_TIMEOUT');return ms;};
  async function bound(work,ms){let timer;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('MAINTENANCE_INSPECTION_TIMEOUT')),ms);})]);}finally{clearTimeout(timer);}}
  async function observeLease(){const observed=await bound(()=>observeExclusiveMaintenanceLease(lease),remaining());remaining();return observed;}
  async function close(row){if(row.closed)return;await bound(()=>row.client.end(),3000);row.closed=true;row.release();}
  async function connect(key){
   await observeLease();
   const config=poolConfig({...env,PG_POOL_MAX_LEASE:'1'},key,{purpose:'lease'}),release=terminalPermit?reserveFinalInspectionConnection(terminalPermit,lease,env,key):reserveDedicatedConnection(env);
   let client;try{client=new Client({...config,connectionTimeoutMillis:remaining(),query_timeout:3000,statement_timeout:3000,application_name:'owasp-ai-goat-maintenance-inspection'});}catch(e){release();throw e;}
   const row={client,release,closed:false};clients.push(row);client.on('error',()=>{row.failed=true;});await bound(()=>client.connect(),remaining());
   const tls=await query(row,'SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()');if(config.ssl&&tls.rows?.[0]?.ssl!==true)throw fail('MAINTENANCE_INSPECTION_TLS_MISMATCH');
   return row;
  }
  async function query(row,sql,args){if(row.failed||row.closed)throw fail('MAINTENANCE_INSPECTION_CONNECTION_LOST');lease.signal.throwIfAborted();const value=await bound(()=>row.client.query(sql,args),remaining());lease.signal.throwIfAborted();return value;}
  const session=async row=>{const r=await query(row,"SELECT pg_backend_pid() AS pid,a.backend_start::text,a.datid::text,current_database() AS datname,session_user AS usename FROM pg_stat_activity a WHERE a.pid=pg_backend_pid()");const x=r.rows?.[0];if(r.rows?.length!==1||!Number.isSafeInteger(x?.pid)||x.pid<1||typeof x.backend_start!=='string'||!x.backend_start||typeof x.datid!=='string'||!/^[1-9][0-9]*$/.test(x.datid)||typeof x.datname!=='string'||typeof x.usename!=='string')throw fail('MAINTENANCE_INSPECTION_SESSION_UNKNOWN');return x;};
  try{
   const initial=await observeLease(),manifest=readManifest(manifestPath),admin=await connect('PG_ADMIN_DATABASE_URL');
   const adminApi={query:(sql,args)=>query(admin,sql,args)};await requirePostgres18(adminApi);
   const rights=await query(admin,'SELECT rolsuper FROM pg_roles WHERE rolname=current_user');if(rights.rows?.length!==1||rights.rows[0].rolsuper!==true)throw fail('MAINTENANCE_INSPECTION_VISIBILITY_REQUIRED');
   const cluster=await clusterIdentity(adminApi);await verifyOwned(adminApi,manifest,plan,cluster,env.PG_ADMIN_DATABASE_URL);
   for(const item of plan)for(const key of [item.runtimeVariable,item.migrationVariable])if(env[key]!==manifest.configuration[key])throw fail('MAINTENANCE_INSPECTION_CONFIGURATION_MISMATCH');
   const deliveryRoles=(await query(admin,"SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='dvaia_ctf_delivery'")).rows;
   let delivery=false;
   if(deliveryRoles.length||env.CTF_DELIVERY_DATABASE_URL||deliveryManifestPath){
    const prior=readManifest(deliveryManifestPath),ctf=plan.find(x=>x.schema==='ctf'),fingerprint=createHash('sha256').update(JSON.stringify({cluster:manifest.cluster,ctf})).digest('hex');
    if(prior.version!==1||prior.status!=='complete'||prior.baseFingerprint!==fingerprint||prior.cluster!==cluster||prior.database!==ctf.database||prior.role!=='dvaia_ctf_delivery'||Object.keys(prior.configuration||{}).join()!=='CTF_DELIVERY_DATABASE_URL'||prior.configuration.CTF_DELIVERY_DATABASE_URL!==env.CTF_DELIVERY_DATABASE_URL)throw fail('MAINTENANCE_INSPECTION_DELIVERY_MISMATCH');
    const u=new URL(env.CTF_DELIVERY_DATABASE_URL),a=new URL(env.PG_ADMIN_DATABASE_URL);if(u.host!==a.host||u.pathname!=='/'+ctf.database||decodeURIComponent(u.username)!=='dvaia_ctf_delivery'||!u.password||u.search||u.hash)throw fail('MAINTENANCE_INSPECTION_DELIVERY_MISMATCH');
    if(deliveryRoles.length!==1||!deliveryRoles[0].rolcanlogin||['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls'].some(k=>deliveryRoles[0][k])||(await query(admin,"SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member OR r.oid=m.roleid WHERE r.rolname='dvaia_ctf_delivery' LIMIT 1")).rows.length)throw fail('MAINTENANCE_INSPECTION_DELIVERY_MISMATCH');delivery=true;
   }
   const adminSession=await session(admin),stores=[];
   for(const item of plan){
    let observed;
    for(const kind of ['migration','runtime',...(item.schema==='ctf'&&delivery?['delivery']:[])]){
     const c=await connect(kind==='delivery'?'CTF_DELIVERY_DATABASE_URL':item[kind+'Variable']),s=await session(c);
     if(s.datname!==item.database||s.usename!==(kind==='delivery'?'dvaia_ctf_delivery':item[kind+'Role']))throw fail('MAINTENANCE_INSPECTION_STORE_MISMATCH');
     const metadata=await query(admin,'SELECT oid::text AS oid FROM pg_database WHERE datname=$1',[item.database]);if(metadata.rows?.length!==1||metadata.rows[0].oid!==s.datid||observed&&observed.datid!==s.datid)throw fail('MAINTENANCE_INSPECTION_STORE_MISMATCH');
     const visible=await query(admin,'SELECT pid,backend_start::text,datid::text,datname,usename FROM pg_stat_activity WHERE pid=$1',[s.pid]);
     if(visible.rows?.length!==1||!['pid','backend_start','datid','datname','usename'].every(k=>visible.rows[0][k]===s[k]))throw fail('MAINTENANCE_INSPECTION_CLUSTER_MISMATCH');
     observed=s;await close(c);
    }
    const url=new URL(env[item.migrationVariable]);stores.push(Object.freeze({storeKey:item.schema,clusterIdentifier:cluster,databaseOid:Number(observed.datid),databaseName:item.database,runtimeRole:item.runtimeRole,migrationRole:item.migrationRole,deliveryRole:item.schema==='ctf'&&delivery?'dvaia_ctf_delivery':null,endpointPolicySha256:createHash('sha256').update(JSON.stringify({host:url.hostname,port:url.port||'5432',tls:env.PG_TLS||'disable'})).digest('hex')}));
   }
   const identity=stores.find(x=>x.storeKey==='identity');if(initial.endpointPolicySha256!==identity.endpointPolicySha256||initial.databaseName!==identity.databaseName||initial.databaseOid!==String(identity.databaseOid)||initial.role!==identity.migrationRole)throw fail('MAINTENANCE_INSPECTION_LEASE_MISMATCH');
   const current=await observeLease();if(JSON.stringify(current)!==JSON.stringify(initial))throw fail('MAINTENANCE_INSPECTION_LEASE_MISMATCH');
   const rows=(await query(admin,'SELECT pid,backend_start::text,datid::text,datname,usename,backend_type FROM pg_stat_activity WHERE datid=ANY($1::oid[])',[stores.map(x=>x.databaseOid)])).rows;
   if(rows.filter(row=>row.pid===initial.pid&&row.backend_start===initial.backendStart&&row.datid===initial.databaseOid&&row.usename===initial.role).length!==1)throw fail('MAINTENANCE_INSPECTION_LEASE_MISMATCH');
   for(const row of rows){
    if(!Number.isSafeInteger(row.pid)||typeof row.backend_start!=='string'||!row.backend_start||typeof row.backend_type!=='string')throw fail('MAINTENANCE_INSPECTION_ACTIVITY_UNKNOWN');
    const exempt=[adminSession,{pid:initial.pid,backend_start:initial.backendStart,datid:initial.databaseOid,datname:initial.databaseName,usename:initial.role}].some(x=>['pid','backend_start','datid','datname','usename'].every(k=>row[k]===x[k]));
    if(!exempt&&row.backend_type!=='autovacuum worker')throw fail('MAINTENANCE_INSPECTION_OTHER_BACKEND');
   }
   await close(admin);await observeLease();
   result=Object.freeze({stores:Object.freeze(stores),recordedBackendsAbsent:true,recoveryAuthorized:false,observedAt:new Date().toISOString(),scope:'supported single-cluster instantaneous observation; no process or publication proof'});
  }catch(error){primary=fail(error?.code?.startsWith('MAINTENANCE_INSPECTION_')?error.code:'MAINTENANCE_INSPECTION_UNAVAILABLE');}
  const errors=[];for(const row of clients)if(!row.closed)try{await close(row);}catch{errors.push(fail('MAINTENANCE_INSPECTION_DRAIN_UNKNOWN'));}
  active=false;if(errors.length)poisoned=true;if(errors.length)throw new AggregateError([...(primary?[primary]:[]),...errors],'MAINTENANCE_INSPECTION_DRAIN_UNKNOWN');if(primary)throw primary;remaining();return result;
 }});
}
module.exports={createApplicationMaintenanceStoreInspection};
