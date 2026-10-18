'use strict';
// Main-only auth adapter: genuine setup maintenance scope prepares disposable stores; no recovery qualification.
const test=require('node:test'),assert=require('node:assert/strict');
const enabled=process.env.PG_MAIN_BACKEND_AUTH==='1';
if(!enabled)test('main-only backend auth explicitly selected',{skip:true},()=>{});
else{
 const admission=require('../fixtures/mainBackendAuthAdmission');
 admission.awaitStartupGate(); // Parent publishes complete ownership before releasing stdin.
 test.before(async()=>{
  const owned=admission.admit(process.env),admin=new URL(process.env.PG_ADMIN_DATABASE_URL);
  assert.equal(admin.protocol,'postgresql:');assert.equal(admin.hostname,'127.0.0.1');assert.equal(admin.port,String(owned.port));assert.equal(admin.pathname,'/postgres');assert.equal(admin.username,'postgres');assert.equal(admin.password,'');assert.equal(admin.search,'');assert.equal(admin.hash,'');
  const {requiredStoreManifest}=require('../../db/postgres/initialize-application');assert.equal(requiredStoreManifest.length,16);
  const {Client}=require('pg');const client=new Client({connectionString:admin.href,connectionTimeoutMillis:3000,query_timeout:5000});
  try{
   await client.connect();assert.deepEqual((await client.query("SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')")).rows,[],'launcher must supply empty owned cluster');
   const fs=require('node:fs'),path=require('node:path');
   const {networkGuardSource}=require('../fixtures/fullBackendBootControls');
   const guard=path.join(owned.evidence,'ctf-setup-network-guard.cjs');fs.writeFileSync(guard,networkGuardSource({host:'127.0.0.1',port:owned.port}),{mode:0o600,flag:'wx'});
   await require('../fixtures/mainBackendCtfSetup').runOwnedSetup({source:owned.source,root:owned.root,environment:{...process.env,NODE_OPTIONS:'--require='+guard}});
   admission.admit(process.env);
   const output=path.join(owned.appData,'setup-result.json');
   const prepared=await require('../fixtures/mainBackendCtfSetup').readResult(output);assert.equal(prepared.publicResult.ctfJournalComplete,true);assert.equal(prepared.publicResult.canonicalStores,16);
   Object.assign(process.env,require('../fixtures/mainBackendCtfSetup').validateConfiguration(prepared.configuration,requiredStoreManifest,owned.port));
   Object.assign(process.env,admission.ownershipEnvironment(process.env));
  }finally{await client.end();}
 },{timeout:180000});
 // Registration occurs now; before hook admits/provisions before either body executes.
 process.env.PG_FULL_BACKEND_AUTH='1';process.env.PG_AUTHENTICATED_RUN_READS='1';
 require('./fullApplicationBackendAuth.integration.test');
 if(process.env.PG_MAIN_CAPACITY_200!=='1')require('./agentRunAuthenticatedOwnership.integration.test');
}
