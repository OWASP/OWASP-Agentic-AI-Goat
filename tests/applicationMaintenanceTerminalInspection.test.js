'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),{createRequire}=require('node:module');
function fixture({endFailure=false,endHangs=false,extraLease=false,lost=false,inspection}={}){
 const file=path.resolve('server/database/postgres/index.js'),req=createRequire(file),module={exports:{}},identity={},admission={},env={IDENTITY_DATABASE_URL:'postgres://runtime:owned@127.0.0.1/owasp_ai_goat_identity',IDENTITY_MIGRATION_DATABASE_URL:'postgres://migration:owned@127.0.0.1/owasp_ai_goat_identity',PG_ADMIN_DATABASE_URL:'postgres://admin:owned@127.0.0.1/postgres',PG_POOL_BUDGET:'32'},controller=new AbortController();let leaseReservation,inspected=0,closed=0,now=0;
 const lease=Object.freeze({signal:controller.signal,assertHeld(){if(controller.signal.aborted)throw Error('lost');}});
 class Pool{on(){}end(){closed++;if(lost)controller.abort();if(endFailure)throw Error('private');return endHangs?new Promise(()=>{}):Promise.resolve();}}
 const fakeDate={now:()=>now};
 const overrides={'pg':{Pool},'../../services/applicationMaintenanceLease':{inprocessLeaseIdentity:l=>{if(l!==lease)throw Error('fake');return identity;},authenticLeaseOwnsReservation:(l,h)=>l===lease&&h===leaseReservation},'../../services/applicationMaintenanceInprocessAdmission':{admittedState:(t,i)=>{if(t!==admission||i!==identity)throw Error('invalid');return{lease,env,directory:'/private-owned'};}},'./applicationMaintenanceStoreInspection':{createApplicationMaintenanceStoreInspection:options=>({inspect:async()=>{inspected++;assert.equal(options.environment,env);return inspection?inspection(module.exports,options,{advance:()=>{now=100000;}}):{stores:[]};}})}};
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,require:n=>Object.hasOwn(overrides,n)?overrides[n]:req(n),process,URL,Date:fakeDate,setTimeout:(f,ms)=>setTimeout(f,Math.min(ms,10)),clearTimeout});
 const api=module.exports;leaseReservation=api.reserveDedicatedConnection(env);if(extraLease)api.reserveDedicatedConnection(env);api.createPool(env,'IDENTITY_DATABASE_URL');return{api,env,lease,admission,stats:()=>({inspected,closed}),release:()=>leaseReservation()};
}
test('terminal drain never reopens ordinary pools or dedicated clients; same admission is single-use',async()=>{const f=fixture();try{await f.api.drainAndInspectPreparedMaintenance(f);assert.equal(f.stats().inspected,1);assert.throws(()=>f.api.createPool(f.env));assert.throws(()=>f.api.reserveDedicatedConnection(f.env));await assert.rejects(f.api.drainAndInspectPreparedMaintenance(f));}finally{f.release();}});
test('failed/hung drain, other dedicated owner and lost lease deny inspection and retry',async()=>{for(const options of [{endFailure:true},{endHangs:true},{extraLease:true},{lost:true}]){const f=fixture(options);try{await assert.rejects(f.api.drainAndInspectPreparedMaintenance(f));assert.equal(f.stats().inspected,0);await assert.rejects(f.api.drainAndInspectPreparedMaintenance(f));assert.throws(()=>f.api.reserveDedicatedConnection(f.env));}finally{f.release();}}});
test('private inspector permit binds exact lease/env/key, max2 slots, expiry and honest unknown reservations',async()=>{
 let captured;const f=fixture({inspection:async(api,o,clock)=>{
  captured=o.terminalPermit;assert.throws(()=>api.reserveFinalInspectionConnection({},o.lease,o.environment,'PG_ADMIN_DATABASE_URL'));
  const admin=api.reserveFinalInspectionConnection(captured,o.lease,o.environment,'PG_ADMIN_DATABASE_URL');
  assert.throws(()=>api.reserveFinalInspectionConnection(captured,o.lease,{...o.environment,PG_TLS:'require'},'IDENTITY_DATABASE_URL'));
  const store=api.reserveFinalInspectionConnection(captured,o.lease,o.environment,'IDENTITY_DATABASE_URL');
  assert.throws(()=>api.reserveFinalInspectionConnection(captured,o.lease,o.environment,'IDENTITY_MIGRATION_DATABASE_URL'));
  store();clock.advance();assert.throws(()=>api.reserveFinalInspectionConnection(captured,o.lease,o.environment,'IDENTITY_DATABASE_URL'));
  // Simulated noncooperative admin end: deliberately do not release its physical reservation.
  return{stores:[]};
 }});try{await assert.rejects(f.api.drainAndInspectPreparedMaintenance(f));assert.equal(f.api.getPoolBudgetSnapshot().reserved,2);assert.throws(()=>f.api.reserveFinalInspectionConnection(captured,f.lease,f.env,'IDENTITY_DATABASE_URL'));}finally{f.release();}
});
test('concurrent terminal admission cannot acquire a second inspector permit',async()=>{let release;const f=fixture({inspection:()=>new Promise(r=>{release=r;})});const pending=f.api.drainAndInspectPreparedMaintenance(f);await new Promise(setImmediate);await assert.rejects(f.api.drainAndInspectPreparedMaintenance(f));release({stores:[]});await pending;f.release();});
