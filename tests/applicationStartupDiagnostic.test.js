'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {projectStartupDiagnostic,reportStartupDiagnostic}=require('../server/services/applicationStartupDiagnostic');
test('closed categories retain actionable codes without arbitrary error content',()=>{
 for(const [code,category] of [['CTF_DELIVERY_ACTIVATION_UNAVAILABLE','ctf_prerequisite'],['MIGRATION_HISTORY_MISMATCH','postgres_migration'],['APPLICATION_LEASE_CONNECT_TIMEOUT','postgres_readiness'],['ERR_POSTGRES_REQUIRED','postgres_configuration']]){
  assert.deepEqual(projectStartupDiagnostic({code,message:'secret',stack:'secret',url:'secret'}),{code:'APPLICATION_START_FAILED',category,reason:code});
 }
 assert.deepEqual(projectStartupDiagnostic({code:'postgres://secret'}),{code:'APPLICATION_START_FAILED',category:'unknown',reason:'UNCLASSIFIED_STARTUP_ERROR'});
});
test('bounded cause and aggregate traversal never invokes accessors or coercion',()=>{
 let reads=0;const hostile={get code(){reads++;throw Error('secret');},get cause(){reads++;throw Error('secret');},get errors(){reads++;throw Error('secret');}};
 assert.equal(projectStartupDiagnostic(hostile).category,'unknown');assert.equal(reads,0);
 const cycle={};cycle.cause=cycle;assert.equal(projectStartupDiagnostic(cycle).category,'unknown');
 const proxy=new Proxy({}, {getOwnPropertyDescriptor(){throw Error('secret');}});assert.equal(projectStartupDiagnostic(proxy).category,'unknown');
 const nested=new AggregateError([hostile,{cause:{code:'CTF_DELIVERY_ACTIVATION_UNAVAILABLE'}}]);
 assert.equal(projectStartupDiagnostic(nested).category,'ctf_prerequisite');
 let deep={code:'CTF_DELIVERY_ACTIVATION_UNAVAILABLE'};for(let i=0;i<20;i++)deep={cause:deep};assert.equal(projectStartupDiagnostic(deep).category,'unknown');
 assert.equal(projectStartupDiagnostic({code:{toString(){throw Error('secret');}}}).category,'unknown');
});
test('logging failure cannot replace startup error',()=>{assert.doesNotThrow(()=>reportStartupDiagnostic({code:'MIGRATION_HISTORY_MISMATCH'},()=>{throw Error('logger');}));});
test('actual index catch logs before shutdown and retains rejection and generic HTTP response',async()=>{
 for(const loggingThrows of [false,true]){
  const events=[], original=Object.assign(Error('secret'),{code:'CTF_DELIVERY_ACTIVATION_UNAVAILABLE'});let middleware;
  const app={locals:{},use(fn){middleware=fn;}};
  const fakeRequire=id=>{
   if(id.includes('application-node-runtime'))return{assertSupportedApplicationNodeVersion(){}};
   if(id==='dotenv')return{config(){}};
   if(id.includes('applicationDatabaseEngine'))return{assertApplicationDatabaseEngine(){}};
   if(id.includes('platformSigningConfiguration'))return{assertPlatformSigningConfiguration(){}};
   if(id==='express')return()=>app;
   if(id.includes('applicationLifecycle'))return{createApplicationLifecycle:()=>({shutdown:async code=>events.push(['shutdown',code])})};
   if(id.includes('applicationMaintenanceLease'))return{acquireApplicationMaintenanceLease:async()=>{throw original;}};
   if(id.includes('applicationStartupDiagnostic'))return{reportStartupDiagnostic};
   throw Error('Unexpected import');
  };
  vm.runInNewContext(fs.readFileSync(require.resolve('../server/index'),'utf8'),{require:fakeRequire,module:{exports:{}},AbortController,process:{versions:{node:'26.10.0'},env:{},once(){},on(){}},console:{error(...args){events.push(['log',...args]);if(loggingThrows)throw Error('logger');}}});
  await assert.rejects(app.locals.applicationReady,error=>error===original);
  assert.equal(events[0][0],'log');assert.equal(events[0][2].reason,'CTF_DELIVERY_ACTIVATION_UNAVAILABLE');
  assert.equal(events[1][0],'log');assert.match(events[1][1],/^application_start_detail \{.*\}$/);
  assert.equal(events[1][1].includes('secret'),false);
  assert.deepEqual(events[2],['shutdown',1]);
  let body;middleware({}, {status(code){assert.equal(code,503);return this;},json(value){body=value;}},()=>assert.fail('not ready'));assert.equal(JSON.stringify(body),' {"error":"Application unavailable"}'.trim());
 }
});
