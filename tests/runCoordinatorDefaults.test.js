'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
test('coordinator selects lazy PostgreSQL default, honors overrides and leaves SQLite local',async()=>{
 const previous=process.env.PLATFORM_DATABASE_ENGINE;
 const path=require.resolve('../server/agent-runtime/postgresRunLedger');
 const cached=require.cache[path];let factories=0,begins=0,resets=0;const families=[];
 const ledger={begin:async()=>{begins++;return{durableGeneration:'8'};},assertCurrent:async()=>{},finish:async()=>{},invalidate:async()=>{resets++;}};
 require.cache[path]={id:path,filename:path,loaded:true,exports:{configuredRunLedger:options=>{factories++;families.push(options.family);return ledger;}}};
 try{
  process.env.PLATFORM_DATABASE_ENGINE='postgres';
  const coordinator=createRunCoordinator({family:'DPI'});assert.equal(factories,0,'Route construction must not initialize pools');
  await coordinator.run(1,{},async execution=>assert.equal(execution.durableGeneration,'8'));
  await coordinator.run(2,{},async()=>{});await coordinator.reset(1);
  assert.equal(factories,1);assert.equal(begins,2);assert.equal(resets,1);
  const resetFirst=createRunCoordinator({family:'XSS'});await resetFirst.reset(1);assert.equal(factories,2);
  assert.deepEqual(families,['DPI','XSS']);
  await createRunCoordinator({family:'MCP',ledger:null}).run(1,{},async execution=>assert.equal(execution.durableGeneration,undefined));
  const injected={...ledger,begin:async()=>({durableGeneration:'custom'})};
  await createRunCoordinator({family:'EA',ledger:injected}).run(1,{},async execution=>assert.equal(execution.durableGeneration,'custom'));
  assert.equal(factories,2);
  process.env.PLATFORM_DATABASE_ENGINE='sqlite';
  await createRunCoordinator({family:'CodeBot'}).run(1,{},async execution=>assert.equal(execution.durableGeneration,undefined));assert.equal(factories,2);
 }finally{if(previous===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=previous;if(cached)require.cache[path]=cached;else delete require.cache[path];}
});
