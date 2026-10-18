'use strict';
// Same-process capability only: never represented by environment flags or IPC data.
const scopes = new WeakMap();
const fail = code => Object.assign(new Error(code), { code });
function target(environment) {
  const value = environment?.IDENTITY_MIGRATION_DATABASE_URL;
  if (typeof value !== 'string' || !value || !value.isWellFormed()) throw fail('APPLICATION_MAINTENANCE_TARGET_INVALID');
  let runtime, migration;
  try { runtime = new URL(environment.IDENTITY_DATABASE_URL); migration = new URL(value); } catch { throw fail('APPLICATION_MAINTENANCE_TARGET_INVALID'); }
  if (![runtime,migration].every(url => ['postgres:','postgresql:'].includes(url.protocol) && url.hostname && url.pathname.length > 1 && !url.search && !url.hash) || runtime.hostname !== migration.hostname || (runtime.port || '5432') !== (migration.port || '5432') || runtime.pathname !== migration.pathname) throw fail('APPLICATION_MAINTENANCE_TARGET_INVALID');
  return JSON.stringify([value, environment.IDENTITY_DATABASE_URL, environment.PG_TLS]);
}
function assertApplicationMaintenanceScope(scope, environment) {
  const state = scope && scopes.get(scope);
  if (!state || !state.active || state.failed || state.target !== target(environment)) throw fail('APPLICATION_MAINTENANCE_SCOPE_INVALID');
  state.signal?.throwIfAborted();
  state.lease.assertHeld();
  state.verifyAdmission?.();
  return scope;
}
function invalidateApplicationMaintenanceScope(scope) {
  const state = scopes.get(scope);
  if (state) state.failed = true;
}
async function withApplicationMaintenanceScope({ environment = process.env, signal,
  acquire = options => require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease(options),
  afterDrain = async () => {},
  drain = () => require('../../server/database/postgres').closePostgresPools(),
} = {}, work) {
  if (typeof work !== 'function') throw fail('APPLICATION_MAINTENANCE_WORK_INVALID');
  const boundTarget = target(environment);
  const acquisition = new AbortController();
  const cancelAcquisition = () => acquisition.abort();
  signal?.addEventListener('abort', cancelAcquisition, { once: true });
  if (signal?.aborted) acquisition.abort();
  let lease;
  try { lease = await acquire({ mode: 'maintenance', env: environment, signal: acquisition.signal }); }
  finally { signal?.removeEventListener('abort', cancelAcquisition); }
  const lifetimeSignal = signal ? AbortSignal.any([signal, lease.signal || new AbortController().signal]) : lease.signal;
  const state = { lease, signal: lifetimeSignal, target: boundTarget, active: true, failed: false };
  const scope = Object.freeze({ signal: lifetimeSignal, assertHeld() { return assertApplicationMaintenanceScope(scope, environment); } });
  scopes.set(scope, state);
  let result,epoch; const failures = [];
  try { scope.assertHeld(); epoch = await lease.beginMaintenance(); scope.assertHeld(); result = await work(scope); scope.assertHeld(); }
  catch (error) { failures.push(error); state.failed = true; }
  let timer;
  try { await Promise.race([Promise.resolve().then(drain), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('APPLICATION_MAINTENANCE_DRAIN_TIMEOUT')), 30000); })]); } catch (error) { failures.push(error); state.failed = true; } finally { clearTimeout(timer); }
  if (!state.failed) {
    try { scope.assertHeld(); await afterDrain(result, scope); scope.assertHeld(); await lease.finishMaintenance(epoch); scope.assertHeld(); }
    catch (error) { failures.push(error); state.failed = true; }
  }
  state.active = false;
  if (!state.failed) {
    try { lease.assertHeld(); await lease.close(); return result; }
    catch (error) { failures.push(error); }
  }
  const causes = (failures.length ? failures : [fail('APPLICATION_MAINTENANCE_PHASE_FAILED')]).map(primary => {
    const cause = fail(/^[A-Z0-9_]{1,80}$/.test(primary?.code || '') ? primary.code : 'APPLICATION_MAINTENANCE_PHASE_FAILED');
    if (/^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(primary?.migration || '')) cause.migration = primary.migration;
    return cause;
  });
  const error = new AggregateError(causes, 'Maintenance phase requires owned process termination');
  error.code = 'APPLICATION_INITIALIZATION_REQUIRES_EXIT';
  const migration = causes.find(cause => cause.migration)?.migration;
  if (migration) error.migration = migration;
  throw error;
}
module.exports = { withApplicationMaintenanceScope, assertApplicationMaintenanceScope, invalidateApplicationMaintenanceScope };

// Narrow internal bridge: only an authentic already-admitted original capability.
async function withPreparedMaintenanceScope({lease,admission,environment,signal},work){
 const identity=require('../../server/services/applicationMaintenanceLease').inprocessLeaseIdentity(lease);
 const a=require('../../server/services/applicationMaintenanceInprocessAdmission').admittedState(admission,identity);
 if(a.lease!==lease||a.env!==environment||typeof work!=='function')throw fail('APPLICATION_MAINTENANCE_SCOPE_INVALID');
 const state={lease,signal:signal?AbortSignal.any([lease.signal,signal]):lease.signal,target:target(environment),active:true,failed:false,admission,verifyAdmission:()=>require('../../server/services/applicationMaintenanceInprocessAdmission').admittedState(admission,identity)};
 const scope=Object.freeze({signal:state.signal,assertHeld(){return assertApplicationMaintenanceScope(scope,environment);}});scopes.set(scope,state);
 try{return await work(scope);}finally{state.active=false;}
}
function preparedMaintenanceJournalOptions(scope){const state=scopes.get(scope);if(!state?.active||state.failed||(!state.admission&&!state.recoverySession))throw fail('APPLICATION_MAINTENANCE_SCOPE_INVALID');state.lease.assertHeld();return state.admission?{maintenanceAdmission:state.admission,maintenanceLease:state.lease}:{recoverySession:state.recoverySession,recoveryToken:state.recoveryToken,maintenanceLease:state.lease};}
module.exports.withPreparedMaintenanceScope=withPreparedMaintenanceScope;
module.exports.preparedMaintenanceJournalOptions=preparedMaintenanceJournalOptions;

module.exports.hasPreparedMaintenanceScope=scope=>Boolean(scopes.get(scope)?.admission||scopes.get(scope)?.recoverySession);

async function withRecoveryMaintenanceScope({lease,session,recoveryToken,environment,signal},work){
 const identity=require('../../server/services/applicationMaintenanceLease').inprocessLeaseIdentity(lease);
 const recovery=require('../../server/database/postgres/applicationMaintenanceRecoveryProof').sessionState(session,identity);
 const attempt=require('../../server/database/postgres/applicationMaintenanceRecoveryControl').recoveryTokenState(recoveryToken,identity);
 if(recovery.lease!==lease||recovery.env!==environment||attempt.epoch!==recovery.expected.epoch||typeof work!=='function')throw fail('APPLICATION_MAINTENANCE_SCOPE_INVALID');
 const state={lease,signal:signal?AbortSignal.any([lease.signal,signal]):lease.signal,target:target(environment),active:true,failed:false,recoverySession:session,recoveryToken,verifyAdmission:()=>{require('../../server/database/postgres/applicationMaintenanceRecoveryProof').sessionState(session,identity);require('../../server/database/postgres/applicationMaintenanceRecoveryControl').recoveryTokenState(recoveryToken,identity);}};
 const scope=Object.freeze({signal:state.signal,assertHeld(){return assertApplicationMaintenanceScope(scope,environment);}});scopes.set(scope,state);
 try{return await work(scope);}finally{state.active=false;}
}
module.exports.withRecoveryMaintenanceScope=withRecoveryMaintenanceScope;
module.exports.recoveryMaintenanceJournalOptions=scope=>{const state=scopes.get(scope);if(!state?.active||state.failed||!state.recoverySession||!state.recoveryToken)throw fail('APPLICATION_MAINTENANCE_SCOPE_INVALID');state.verifyAdmission();return{recoverySession:state.recoverySession,recoveryToken:state.recoveryToken,maintenanceLease:state.lease};};

// Used only after the canonical16 prospective segment has completed. Remaining
// setup steps retain the exclusive lease and their own idempotent journals but
// cannot create a second ordinary, unrecoverable maintenance epoch.
async function withCleanApplicationMaintenanceScope({environment=process.env,sourceRoot,signal,acquire=options=>require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease(options),afterDrain=async()=>{},drain=()=>require('../../server/database/postgres').closePostgresPools()}={},work){
 if(typeof work!=='function')throw fail('APPLICATION_MAINTENANCE_WORK_INVALID');const lease=await acquire({mode:'maintenance',env:environment,signal}),state={lease,signal:signal?AbortSignal.any([signal,lease.signal]):lease.signal,target:target(environment),active:true,failed:false,prospectiveComplete:true};const scope=Object.freeze({signal:state.signal,assertHeld(){return assertApplicationMaintenanceScope(scope,environment);}});scopes.set(scope,state);const failures=[];let result;
 try{const completed=await lease.assertProspectiveOriginalComplete();if(typeof sourceRoot!=='string'||require('../../server/services/applicationMaintenanceInprocessAdmission').sourceBinding(sourceRoot)!==completed.sourceManifestSha256)throw fail('APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE');scope.assertHeld();result=await work(scope);scope.assertHeld();}catch(error){state.failed=true;failures.push(error);}try{await drain();if(!state.failed){scope.assertHeld();await afterDrain(result,scope);scope.assertHeld();}}catch(error){state.failed=true;failures.push(error);}state.active=false;try{await lease.close();}catch(error){failures.push(error);}if(failures.length){const error=new AggregateError(failures.map(value=>fail(/^[A-Z0-9_]{1,80}$/.test(value?.code||'')?value.code:'APPLICATION_MAINTENANCE_PHASE_FAILED')),'Post-prospective setup phase requires retry');error.code='APPLICATION_INITIALIZATION_REQUIRES_EXIT';throw error;}return result;
}
module.exports.withCleanApplicationMaintenanceScope=withCleanApplicationMaintenanceScope;
module.exports.hasCompletedProspectiveMaintenanceScope=scope=>{const state=scopes.get(scope);return Boolean(state?.active&&!state.failed&&state.prospectiveComplete);};
