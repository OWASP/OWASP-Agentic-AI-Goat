'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {preparePasswordResetRepository:prepare}=require('../server/services/secureshopPasswordResetComposition');
test('missing configuration or missing key leaves only optional reset unavailable without writes/probes',async()=>{let probes=0;const deps={stat(){probes++;throw Object.assign(Error('absent'),{code:'ENOENT'});},load(){throw Error('must not load');},createRepository(){throw Error('must not create');}};assert.equal(await prepare({},deps),undefined);assert.equal(probes,0);assert.equal(await prepare({filePath:'/private/absent'},deps),undefined);assert.equal(probes,1);});
test('same exact pool/audit and private envelope are checked before instance publication',async()=>{const pool={},auditStore={},keys={activeKeyId:'key',keys:new Map()},envelope={},calls=[],repository={async checkReadiness(){calls.push('ready');}};const actual=await prepare({filePath:'/private/key',pool,auditStore},{stat(){calls.push('stat');},load(input){assert.deepEqual(input,{filePath:'/private/key'});calls.push('load');return keys;},createEnvelope(input){assert.equal(input,keys);return envelope;},createRepository(input){assert.deepEqual(input,{pool,auditStore,envelope});return repository;}});assert.equal(actual,repository);assert.deepEqual(calls,['stat','load','ready']);});
test('configured malformed/inaccessible key and failed SQL readiness never fall back',async()=>{for(const phase of ['stat','load','ready']){let created=0;await assert.rejects(prepare({filePath:'/private/key'},{stat(){if(phase==='stat')throw Error('denied');},load(){if(phase==='load')throw Error('invalid');return{};},createEnvelope(){return{};},createRepository(){created++;return{async checkReadiness(){throw Error('schema unavailable');}};}}));assert.equal(created,phase==='ready'?1:0);}});

test('registered reset uses identity pool and private envelope only after readiness',async()=>{
 const {prepareRegisteredAdminResetService}=require('../server/services/secureshopPasswordResetComposition');
 const pool={},keys={},envelope={},calls=[],repository={async checkReadiness(){calls.push('ready');}},service={};
 const deps={stat(){},load(){return keys;},createEnvelope(input){assert.equal(input,keys);return envelope;},
  createRepository(input){assert.equal(input.pool,pool);assert.equal(input.envelope,envelope);assert.equal(input.auditStore,undefined);return repository;},
  createService(input){assert.equal(input.repository,repository);assert.deepEqual(calls,['ready']);return service;}};
 assert.equal(await prepareRegisteredAdminResetService({filePath:'/private/key',pool},deps),service);
 assert.equal(await prepareRegisteredAdminResetService({pool},deps),undefined);
 repository.checkReadiness=async()=>{throw Error('schema not ready');};
 await assert.rejects(prepareRegisteredAdminResetService({filePath:'/private/key',pool},deps),/schema not ready/);
});
