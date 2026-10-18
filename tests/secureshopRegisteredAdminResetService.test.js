'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {createRegisteredAdminResetService}=require('../server/services/secureshopRegisteredAdminReset');

const TOKEN='A'.repeat(43);
const OP='a5e90000-91bc-4aba-8e14-018000000001';
const HASH='$2b$12$'+ 'a'.repeat(53);
const base={token:TOKEN,targetId:1000000002,operationId:OP,expectedCredentialVersion:'1',expectedAuthorityVersion:'2',expectedMembershipVersion:'3'};

test('normal operation UUID reaches repository with exact protected token hash and CAS',async()=>{
 let captured,hashCalls=0;
 const repository={preview:async x=>x,reset:async x=>{captured=x;return{replayed:false};},read:async x=>x,reveal:async x=>x,acknowledge:async x=>x};
 const service=createRegisteredAdminResetService({repository,randomSecret:()=> 'S'.repeat(43),hashPassword:async secret=>{hashCalls++;assert.equal(secret,'S'.repeat(43));return HASH;}});
 assert.deepEqual(await service.reset(base),{replayed:false});
 assert.equal(hashCalls,1);
 assert.deepEqual(captured,{tokenHash:createHash('sha256').update(TOKEN).digest('hex'),targetId:base.targetId,
  operationId:OP,expectedCredentialVersion:'1',expectedAuthorityVersion:'2',expectedMembershipVersion:'3',secret:'S'.repeat(43),passwordHash:HASH});
});

test('invalid operation and revision never generate credential material or enter repository',async()=>{
 let calls=0;
 const repository=Object.fromEntries(['preview','reset','read','reveal','acknowledge'].map(name=>[name,async()=>{calls++;}]));
 const service=createRegisteredAdminResetService({repository,randomSecret:()=>{calls++;return 'S'.repeat(43);},hashPassword:async()=>{calls++;return HASH;}});
 for(const bad of [{operationId:'a5e90000-91bc-4aba-8e14018000000001'},{expectedCredentialVersion:'0'},{targetId:-1}]){
  await assert.rejects(service.reset({...base,...bad}),{code:'INVALID_ARGUMENT'});
 }
 assert.equal(calls,0);
});
