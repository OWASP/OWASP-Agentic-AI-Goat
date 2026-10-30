'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {setupOwnedPricing}=require('../scripts/install/pricing-setup');
const prerequisites={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
test('disabled setup is dependency free and prerequisite failure precedes mutation',async()=>{
 assert.deepEqual(await setupOwnedPricing({provision:()=>assert.fail()}),{requested:false,activationEnabled:false});
 await assert.rejects(setupOwnedPricing({requested:true,provision:()=>assert.fail()}),{code:'PRICING_SETUP_PREREQUISITES_REQUIRED'});
});
test('explicit setup forwards closed port and effective persistent prerequisites without exposing credentials',async()=>{
 let calls=0;const maintenanceScope=Object.freeze({opaque:true});const options={requested:true,root:'/owned',homeDirectory:'/private',platform:'linux',maintenanceScope,applicationEnvironment:prerequisites,environment:{OWASP_AI_GOAT_OWNED_PRICING_PORT:'28193'},provision:async input=>{calls++;assert.equal(input.maintenanceScope,maintenanceScope);assert.equal(input.port,28193);assert.equal(input.home,'/private');assert.equal(input.environment.SS_ENABLE,'true');return{enabled:true,workspaceId:'abc',token:'not returned'};}};
 assert.deepEqual(await setupOwnedPricing(options),{requested:true,activationEnabled:true,workspaceId:'abc'});
 for(const port of ['0','008093','65536','8093x'])await assert.rejects(setupOwnedPricing({...options,environment:{OWASP_AI_GOAT_OWNED_PRICING_PORT:port}}),{code:'PRICING_INSTALL_PORT_INVALID'});
 assert.equal(calls,1);
});
test('explicit repository-only setup forwards the storage admission without changing ordinary defaults',async()=>{
 const admission=async()=>true;let called=0;
 const provision=async input=>{called++;assert.equal(input.repositoryOnlyStorage,true);assert.equal(input.admitRepositoryStorage,admission);return{enabled:true,workspaceId:'abc'};};
 const options={requested:true,root:'/owned',homeDirectory:'/private',platform:'darwin',applicationEnvironment:prerequisites,repositoryOnlyStorage:true,admitRepositoryStorage:admission,provision};
 assert.equal((await setupOwnedPricing(options)).activationEnabled,true);
 assert.equal(called,1);
 await setupOwnedPricing({...options,repositoryOnlyStorage:false,admitRepositoryStorage:undefined,provision:async input=>{assert.equal(input.repositoryOnlyStorage,false);assert.equal(input.admitRepositoryStorage,undefined);return{enabled:true,workspaceId:'abc'};}});
});
