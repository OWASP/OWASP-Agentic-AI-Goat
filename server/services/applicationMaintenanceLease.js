'use strict';
const {poolConfig,reserveDedicatedConnection}=require('../database/postgres');
// Store-wide identity session key; audit found no two-int use of slot90.
// Distinct from migration1, seed2, provisioning41 and CTF delivery44.
const exclusiveOwners=new WeakMap(),inprocessIdentities=new WeakMap();
function inprocessLeaseIdentity(lease){const identity=inprocessIdentities.get(lease);if(!identity)throw failure('APPLICATION_MAINTENANCE_LOCK_REQUIRED');lease.assertHeld();return identity.identity;}
function authenticLeaseOwnsReservation(lease,handle){const entry=inprocessIdentities.get(lease);if(!entry)return false;lease.assertHeld();return entry.reservation===handle;}
async function observeExclusiveMaintenanceLease(lease){const observe=exclusiveOwners.get(lease);if(!observe)throw failure('APPLICATION_MAINTENANCE_LOCK_REQUIRED');return observe();}
const defaultClientFactory=config=>new(require('pg').Client)(config);
const KEY=Object.freeze([1886610804,90]);
const failure=code=>Object.assign(new Error(code),{code});
async function acquireApplicationMaintenanceLease({mode,env=process.env,signal,timeoutMs=5000,closeMs=2000,probeMs=1000,clientFactory=defaultClientFactory}={}){
 if(!['application','maintenance'].includes(mode)||![timeoutMs,closeMs,probeMs].every(x=>Number.isInteger(x)&&x>=10&&x<=30000))throw TypeError('Invalid maintenance lease options');
 signal?.throwIfAborted();
 const config=poolConfig({...env,PG_POOL_MAX_LEASE:'1'},mode==='application'?'IDENTITY_DATABASE_URL':'IDENTITY_MIGRATION_DATABASE_URL',{purpose:'lease'});
 const releaseBudget=reserveDedicatedConnection(env);
 let client;try{client=clientFactory({...config,connectionTimeoutMillis:timeoutMs,query_timeout:timeoutMs,statement_timeout:timeoutMs,application_name:'dvaia-maintenance-lease'});}catch(error){releaseBudget();throw failure('APPLICATION_LEASE_CLIENT_FAILED');}
 const abort=new AbortController();let state='acquiring',closing,probe;
 const lose=()=>{if(state!=='closed'&&state!=='closing'){state='lost';abort.abort(failure('APPLICATION_LEASE_LOST'));void close().catch(()=>{});}};
 const bound=(work,ms,code,withAbort=true)=>new Promise((resolve,reject)=>{
  const stop=()=>finish(reject,abort.signal.reason||failure('APPLICATION_LEASE_LOST'));
  const timer=setTimeout(()=>finish(reject,failure(code)),ms);
  function finish(fn,value){clearTimeout(timer);abort.signal.removeEventListener('abort',stop);fn(value);}
  if(withAbort){abort.signal.addEventListener('abort',stop,{once:true});if(abort.signal.aborted){stop();return;}}
  Promise.resolve().then(work).then(v=>finish(resolve,v),e=>finish(reject,e));
 });
 function close(){
  if(closing)return closing;
  const lost=state==='lost';state='closing';clearTimeout(probe);signal?.removeEventListener('abort',lose);
  if(!abort.signal.aborted)abort.abort(failure('APPLICATION_LEASE_CLOSED'));
  // End this dedicated session, never return it to a pool or reconnect. Session
  // termination releases locks. A timeout is an explicit uncertain cleanup.
  closing=bound(()=>client.end(),closeMs,'APPLICATION_LEASE_CLOSE_TIMEOUT',false).then(()=>{state='closed';releaseBudget();return Object.freeze({closed:true,lost});},()=>{state='close_failed';throw failure('APPLICATION_LEASE_CLOSE_FAILED');});
  return closing;
 }

 function assertHeld(){if(state!=='held'||abort.signal.aborted)throw failure('APPLICATION_LEASE_NOT_HELD');}
 async function poll(){try{assertHeld();await bound(()=>client.query('SELECT 1'),timeoutMs,'APPLICATION_LEASE_PROBE_TIMEOUT');assertHeld();probe=setTimeout(poll,probeMs);}catch{lose();}}
 try{
  try{client.on('error',lose);client.on('end',lose);signal?.addEventListener('abort',lose,{once:true});if(signal?.aborted)lose();}catch{throw failure('APPLICATION_LEASE_SETUP_FAILED');}
  await bound(()=>client.connect(),timeoutMs,'APPLICATION_LEASE_CONNECT_TIMEOUT');
  const fn=mode==='application'?'pg_try_advisory_lock_shared':'pg_try_advisory_lock';
  const result=await bound(()=>client.query(`SELECT ${fn}($1,$2) AS acquired`,KEY),timeoutMs,'APPLICATION_LEASE_QUERY_TIMEOUT');
  if(result.rows?.[0]?.acquired!==true)throw failure('APPLICATION_MAINTENANCE_BUSY');
  if(abort.signal.aborted)throw failure('APPLICATION_LEASE_LOST');
  state='held';probe=setTimeout(poll,probeMs);
  const identity=Object.freeze({});
  const control=require('../database/postgres/applicationMaintenanceControl').createApplicationMaintenanceControl({mode,identity,assertHeld,query:(sql,args)=>bound(()=>client.query(sql,args),timeoutMs,'APPLICATION_MAINTENANCE_QUERY_TIMEOUT')});
  const lease=Object.freeze({signal:abort.signal,assertHeld,close,status:()=>Object.freeze({state,mode}),assertClean:control.assertClean,assertExecutionReady:control.assertExecutionReady,upgradeExecutionSchema:control.upgradeExecutionSchema,assertProspectiveOriginalComplete:control.assertProspectiveOriginalComplete,beginMaintenance:control.begin,finishMaintenance:control.finish,maintenancePlan:control.plan,readDirtyProfile:control.readDirtyProfile,readRecoveryOutcome:control.readRecoveryOutcome,beginRecoveryEligible:control.beginRecoveryEligible,claimRecovery:control.claimRecovery,advanceRecovery:control.advanceRecovery,finishRecovery:control.finishRecovery,beginPrepared:control.beginPrepared,finishPrepared:control.finishPrepared});
  if(mode==='maintenance'&&clientFactory===defaultClientFactory)inprocessIdentities.set(lease,{identity,reservation:releaseBudget});
  if(mode==='maintenance')exclusiveOwners.set(lease,async()=>{
   assertHeld();const result=await bound(()=>client.query("SELECT a.pid,a.backend_start::text,a.datid::text,a.datname,a.usename,EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory' AND l.mode='ExclusiveLock' AND l.granted AND l.classid=$1 AND l.objid=$2 AND l.objsubid=2 AND l.database=a.datid) AS exclusive FROM pg_stat_activity a WHERE a.pid=pg_backend_pid()",KEY),timeoutMs,'APPLICATION_LEASE_QUERY_TIMEOUT');assertHeld();
   const row=result.rows?.[0];if(result.rows?.length!==1||row?.exclusive!==true||!Number.isSafeInteger(row.pid)||row.pid<1||typeof row.backend_start!=='string'||!row.backend_start||typeof row.datid!=='string'||!/^[1-9][0-9]*$/.test(row.datid)||typeof row.datname!=='string'||typeof row.usename!=='string')throw failure('APPLICATION_MAINTENANCE_LOCK_REQUIRED');
   const endpoint=new URL(config.connectionString);
   return Object.freeze({endpointPolicySha256:require('node:crypto').createHash('sha256').update(JSON.stringify({host:endpoint.hostname,port:endpoint.port||'5432',tls:config.ssl?'require':'disable'})).digest('hex'),pid:row.pid,backendStart:row.backend_start,databaseOid:row.datid,databaseName:row.datname,role:row.usename});
  });
  return lease;
 }catch(error){const allowed=['APPLICATION_MAINTENANCE_BUSY','APPLICATION_LEASE_SETUP_FAILED','APPLICATION_LEASE_CONNECT_TIMEOUT','APPLICATION_LEASE_QUERY_TIMEOUT','APPLICATION_LEASE_LOST'];const primary=failure(allowed.includes(error?.code)?error.code:'APPLICATION_LEASE_ACQUIRE_FAILED');try{await close();}catch{throw Object.assign(new AggregateError([primary,failure('APPLICATION_LEASE_CLOSE_FAILED')],'APPLICATION_LEASE_ACQUIRE_AND_CLOSE_FAILED'),{code:'APPLICATION_LEASE_ACQUIRE_AND_CLOSE_FAILED'});}throw primary;}
}
module.exports={authenticLeaseOwnsReservation,inprocessLeaseIdentity,observeExclusiveMaintenanceLease,acquireApplicationMaintenanceLease,APPLICATION_MAINTENANCE_KEY:KEY};
