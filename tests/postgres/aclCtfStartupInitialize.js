'use strict';
// Prospective fixed owned initializer, not an application entry or authority bypass.
const assert=require('node:assert/strict');
function admitDelivery(env){
 require('../../tests/postgres/adminStudentDeletionRenderedSupport').admitStores(env);
 const ctf=new URL(env.CTF_DATABASE_URL),delivery=new URL(env.CTF_DELIVERY_DATABASE_URL);
 assert.equal(delivery.protocol,'postgresql:');assert.equal(delivery.hostname,'127.0.0.1');
 assert.equal(delivery.host,ctf.host);assert.equal(delivery.pathname,ctf.pathname);
 assert.equal(decodeURIComponent(delivery.username),'dvaia_ctf_delivery');
 assert.equal(delivery.search,'');assert.equal(delivery.hash,'');
 assert.equal(delivery.password,ctf.password);return delivery.href;
}
async function initialize(){
 const env=process.env;admitDelivery(env);
 const pg=require('../../server/database/postgres');
 const {withApplicationMaintenanceScope}=require('../../scripts/lib/application-maintenance-scope');
 await withApplicationMaintenanceScope({environment:env},async scope=>{
  await require('../../db/postgres/initialize-application').initializeApplication({maintenanceScope:scope});
  scope.assertHeld();
  const identity=pg.createPool(env,'IDENTITY_MIGRATION_DATABASE_URL',{purpose:'migration'});
  const ctf=pg.createPool(env,'CTF_MIGRATION_DATABASE_URL',{purpose:'migration'});
  const repository=require('../../server/database/postgres/ctfAuthorityBootstrapRepository').createCtfAuthorityBootstrapRepository({identityPool:identity,ctfPool:ctf});
  const operationId=require('node:crypto').randomUUID();
  const prepared=await require('../../server/services/ctfAuthorityBootstrap').createCtfAuthorityBootstrap({repository}).prepare({operationId,signal:scope.signal});
  assert.equal(prepared.prepared,true);assert.equal(prepared.runtimeReady,false);scope.assertHeld();
  const operator=require('../../server/database/postgres/ctfDeliveryActivationOperator').createCtfDeliveryActivationOperator({identityMigrationPool:identity,ctfMigrationPool:ctf});
  const activationId=require('node:crypto').randomUUID();
  const activated=await operator.activate({activationId,bootstrapOperationId:operationId,pageBudget:64},{signal:scope.signal});
  assert.ok(activated.activation);assert.equal(activated.trafficStarted,false);scope.assertHeld();
  await require('../../server/database/postgres/ctfDeliveryActivation').createCtfDeliveryActivation({identityPool:identity,ctfPool:ctf}).verify(activated.activation,{signal:scope.signal});
  scope.assertHeld();
 }); // Genuine scope drains all budgeted pools before finishing the clean epoch.
}
module.exports={admitDelivery,initialize};
if(require.main===module)initialize().catch(error=>{
 const summary=require('../../db/postgres/initialize-application').initializationFailureSummary(error);
 process.stderr.write('Student-deletion initialization failed: '+JSON.stringify(summary)+'\n');
 if(error?.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT')process.exit(1);
 else process.exitCode=1;
});
