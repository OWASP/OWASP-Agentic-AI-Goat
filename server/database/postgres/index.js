'use strict';

const TARGET_MAJOR = 18;
const pools = new Set();
let closing = false;
const reservations = new Map();
const dedicatedHandles=new Map(),finalInspectionPermits=new WeakMap(),terminalAdmissions=new WeakSet();
const { poolBudget } = require('./poolBudget');

function poolConfig(env = process.env, key = 'DATABASE_URL', {purpose} = {}) {
  if (!env[key]) throw new Error(`${key} is required; PostgreSQL has no implicit local or SQLite fallback`);
  let url;
  try { url = new URL(env[key]); } catch { throw new Error(`${key} must be a PostgreSQL URL`); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname || url.pathname.length < 2) {
    throw new Error(`${key} must identify a PostgreSQL host and database`);
  }
  // Prevent connection-string options from overriding bounded pool settings or TLS policy.
  if (url.search || url.hash) throw new Error(`${key} query options and fragments are not supported`);
  const ssl = env.PG_TLS === 'require' ? { rejectUnauthorized: true } : false;
  if (env.PG_TLS && !['require', 'disable'].includes(env.PG_TLS)) throw new Error('PG_TLS must be require or disable');
  if (!ssl && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
    throw new Error('Remote PostgreSQL requires PG_TLS=require');
  }
  return {
    connectionString: url.href, ssl, max: poolBudget(env,key,purpose).max,
    connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000,
    statement_timeout: 30000, lock_timeout: 5000,
    idle_in_transaction_session_timeout: 30000,
    application_name: 'dvaia',
  };
}

// Dedicated sessions participate in the same process budget, but are not pool
// shutdown resources: their owner must release them after application drain.
function reserveDedicatedConnection(env=process.env) {
  if(closing)throw new Error('PostgreSQL pools are shutting down');
  const allocation=poolBudget({...env,PG_POOL_MAX_LEASE:'1'},'IDENTITY_DATABASE_URL','lease');
  const reserved=[...reservations.values()].reduce((sum,item)=>sum+item.max,0);
  if(reserved+1>allocation.budget)throw new Error('PostgreSQL process pool budget exhausted');
  const token={};reservations.set(token,{purpose:'lease',max:1});let released=false;
  const release=()=>{if(!released){released=true;reservations.delete(token);dedicatedHandles.delete(token);}};dedicatedHandles.set(token,release);return release;
}

function createPool(env = process.env, key = 'DATABASE_URL', {purpose} = {}) {
  if (closing) throw new Error('PostgreSQL pools are shutting down');
  const config = poolConfig(env, key, {purpose});
  const allocation = poolBudget(env,key,purpose);
  const reserved = [...reservations.values()].reduce((sum,item)=>sum+item.max,0);
  if(reserved+config.max>allocation.budget)throw new Error('PostgreSQL process pool budget exhausted; reduce pool maxima or allocate a larger explicit process budget');
  const { Pool } = require('pg');
  const pool = new Pool(config);
  pools.add(pool);
  reservations.set(pool,allocation);
  const end = pool.end.bind(pool);
  let endPromise;
  pool.end = () => {
    if (!endPromise) endPromise = Promise.resolve().then(end).finally(() => {pools.delete(pool);reservations.delete(pool);});
    return endPromise;
  };
  // Idle-client errors otherwise become uncaught process errors. Do not log URLs or SQL.
  pool.on('error', error => console.error('PostgreSQL idle connection failed:', error.code || 'connection_error'));
  return pool;
}

async function closePostgresPools() {
  closing = true;
  const results = await Promise.allSettled([...pools].map(pool => pool.end()));
  const errors = results.filter(result => result.status === 'rejected').map(result => result.reason);
  if (errors.length) throw new AggregateError(errors, 'Failed to close PostgreSQL pools');
}

async function withTransaction(pool, work) {
  const client = await pool.connect();
  let discard;
  try {
    await client.query('BEGIN');
    const value = await work(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch (rollbackError) { discard = rollbackError; }
    throw error;
  } finally {
    client.release(discard);
  }
}

async function verifyServer(client) {
  const { rows } = await client.query(`SELECT current_setting('server_version_num')::integer AS version,
    rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
    FROM pg_roles WHERE rolname = current_user`);
  const role = rows[0];
  if (!role || Math.floor(role.version / 10000) !== TARGET_MAJOR) throw new Error(`PostgreSQL ${TARGET_MAJOR} is required`);
  if (['rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolreplication', 'rolbypassrls'].some(key => role[key])) {
    throw new Error('Application/migration role must not hold cluster-wide administrative privileges');
  }
}

function getPoolBudgetSnapshot(){const allocations=[...reservations.values()].map(({purpose,max})=>({purpose,max}));return{reserved:allocations.reduce((sum,p)=>sum+p.max,0),allocations};}

module.exports = { reserveDedicatedConnection, getPoolBudgetSnapshot, TARGET_MAJOR, poolConfig, createPool, closePostgresPools, withTransaction, verifyServer };

// Irreversible original-writer terminal lane. No general admission is reopened.
const terminalFailure=()=>Object.assign(Error('Terminal maintenance inspection unavailable'),{code:'APPLICATION_MAINTENANCE_TERMINAL_UNAVAILABLE'});
function reserveFinalInspectionConnection(permit,lease,env,key){
 const p=finalInspectionPermits.get(permit);
 if(!p||p.lease!==lease||Date.now()>p.expires||!p.keys.has(key)||p.active.has(key)||p.active.size>=2||p.active.size===0&&key!=='PG_ADMIN_DATABASE_URL'||p.active.size===1&&!p.active.has('PG_ADMIN_DATABASE_URL')||Object.keys(p.env).some(k=>env[k]!==p.env[k])||Object.keys(env).some(k=>env[k]!==p.env[k]))throw terminalFailure();
 lease.assertHeld();lease.signal.throwIfAborted();
 const allocation=poolBudget({...p.env,PG_POOL_MAX_LEASE:'1'},'IDENTITY_DATABASE_URL','lease');
 if([...reservations.values()].reduce((n,x)=>n+x.max,0)+1>allocation.budget)throw terminalFailure();
 const token={};reservations.set(token,{purpose:'lease',max:1});p.active.add(key);let released=false;
 return()=>{if(!released){released=true;reservations.delete(token);p.active.delete(key);}};
}
async function drainAndInspectPreparedMaintenance({lease,admission,recoverySession,recoveryToken}){
 const leaseTools=require('../../services/applicationMaintenanceLease'),identity=leaseTools.inprocessLeaseIdentity(lease);
 const authority=admission||recoverySession;
 const a=admission?require('../../services/applicationMaintenanceInprocessAdmission').admittedState(admission,identity):require('./applicationMaintenanceRecoveryProof').sessionState(recoverySession,identity);
 if(recoverySession)require('./applicationMaintenanceRecoveryControl').recoveryTokenState(recoveryToken,identity);
 if(a.lease!==lease||terminalAdmissions.has(authority)||closing)throw terminalFailure();
 terminalAdmissions.add(authority);closing=true;
 let timer,permit;
 try{
  await Promise.race([Promise.allSettled([...pools].map(p=>p.end())).then(results=>{if(results.some(r=>r.status==='rejected'))throw terminalFailure();}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(terminalFailure()),30000);})]);clearTimeout(timer);
  lease.assertHeld();lease.signal.throwIfAborted();
  if(reservations.size!==1||dedicatedHandles.size!==1||![...dedicatedHandles.values()].every(h=>leaseTools.authenticLeaseOwnsReservation(lease,h)))throw terminalFailure();
  const keys=new Set(['PG_ADMIN_DATABASE_URL',...require('../../../db/postgres/initialize-application').requiredStoreManifest.flatMap(s=>[s.runtimeVariable,s.migrationVariable]),...(a.env.CTF_DELIVERY_DATABASE_URL?['CTF_DELIVERY_DATABASE_URL']:[])]);
  permit=Object.freeze({});const record={lease,env:a.env,keys,active:new Set(),expires:Date.now()+90000};finalInspectionPermits.set(permit,record);
  const result=await require('./applicationMaintenanceStoreInspection').createApplicationMaintenanceStoreInspection({environment:a.env,manifestPath:require('node:path').join(a.directory,'provisioning.json'),deliveryManifestPath:require('node:path').join(a.directory,'ctf-delivery.json'),lease,terminalPermit:permit}).inspect();
  lease.assertHeld();lease.signal.throwIfAborted();if(record.active.size||Date.now()>record.expires||reservations.size!==1)throw terminalFailure();return result;
 }catch{throw terminalFailure();}finally{clearTimeout(timer);if(permit)finalInspectionPermits.delete(permit);}
}
module.exports.reserveFinalInspectionConnection=reserveFinalInspectionConnection;
module.exports.drainAndInspectPreparedMaintenance=drainAndInspectPreparedMaintenance;
