'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {activationPolicy,prepareSystemDiagnosticClient} = require('../server/services/secureshopSystemDiagnosticActivation');
const {HTTP_VERSION,CAPABILITY} = require('../server/services/secureshopSystemDiagnosticClient');
const env={SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED:'true',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',
 PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',
 SS_SYSTEM_DIAGNOSTIC_BASE_URL:'http://127.0.0.1:8091',SS_SYSTEM_DIAGNOSTIC_TOKEN:'a'.repeat(43)};
test('disabled diagnostics make no network probe and ignore unused private configuration',async()=>{
 let probes=0;
 for(const value of [{},{SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED:'false',SS_SYSTEM_DIAGNOSTIC_BASE_URL:'invalid'}]){
  assert.equal(await prepareSystemDiagnosticClient({env:value,fetchImpl:async()=>{probes++;throw Error();}}),undefined);
 }
 assert.equal(probes,0);
});
test('diagnostic activation requires owned bound PostgreSQL configuration and hides its token',()=>{
 for(const change of [{SS_ENABLE:'false'},{SS_BOUND_REVIEWS_ENABLED:'false'},{WORKSHOP_DATABASE_ENGINE:'sqlite'},
  {SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED:'yes'},{SS_SYSTEM_DIAGNOSTIC_TOKEN:'short'},
  {SS_SYSTEM_DIAGNOSTIC_BASE_URL:'http://user:secret@localhost/'}]){
  assert.throws(()=>activationPolicy({...env,...change}),{code:'INVALID_CONFIGURATION'});
 }
 assert.deepEqual(activationPolicy(env),{requested:true,baseUrl:env.SS_SYSTEM_DIAGNOSTIC_BASE_URL});
 assert.ok(!JSON.stringify(activationPolicy(env)).includes(env.SS_SYSTEM_DIAGNOSTIC_TOKEN));
});
test('diagnostic readiness requires the exact capability and authenticated private endpoint',async()=>{
 const health={version:HTTP_VERSION,ready:true,isolation:'bwrap-system-diagnostic-v1',diagnosticCapability:CAPABILITY};
 let calls=0;
 const client=await prepareSystemDiagnosticClient({env,fetchImpl:async(url,options)=>{
  calls++;assert.equal(String(url),env.SS_SYSTEM_DIAGNOSTIC_BASE_URL+'/secureshop/system/diagnostic-health');
  assert.equal(options.headers.authorization,'Bearer '+env.SS_SYSTEM_DIAGNOSTIC_TOKEN);
  return Response.json(health);
 }});
 assert.equal(calls,1);assert.equal(typeof client.execute,'function');
 for(const value of [{...health,ready:false},{...health,diagnosticCapability:'wrong'},{...health,extra:true}]){
  await assert.rejects(prepareSystemDiagnosticClient({env,fetchImpl:async()=>Response.json(value)}),{code:'SYSTEM_DIAGNOSTIC_UNAVAILABLE'});
 }
});
