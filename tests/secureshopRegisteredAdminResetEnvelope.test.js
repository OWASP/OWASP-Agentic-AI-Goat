'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomBytes}=require('node:crypto');
const {createRegisteredAdminResetEnvelope}=require('../server/services/secureshopRegisteredAdminResetEnvelope');
const time=Date.parse('2026-10-09T10:00:00.000Z');
const ids={operationId:'a5e90000-91bc-4aba-8e14-018000000001',tenantId:'5ec0e500-0000-4000-8000-000000000001',actorPrincipalId:'a5e90000-91bc-4aba-8e14-018000000002',targetPrincipalId:'a5e90000-91bc-4aba-8e14-018000000003'};
function receipt(){return{version:1,...ids,actorAuthSessionId:7,actorExecutionSessionId:8,actorMembershipVersion:'2',actorAuthorityVersion:'3',targetId:1000000002,
 expectedCredentialVersion:'4',expectedAuthorityVersion:'5',expectedMembershipVersion:'6',credentialVersion:'5',authorityVersion:'6',receiptSha256:'a'.repeat(64),expiresAt:new Date(time+600000).toISOString()};}
function codec(now=()=>time){return createRegisteredAdminResetEnvelope({activeKeyId:'k1',keys:new Map([['k1',randomBytes(32)]]),now});}

test('private envelope seals exact registered reset receipt with a random nonce',()=>{
 const c=codec(),r=receipt(),secret='S'.repeat(43),a=c.seal({receipt:r,secret}),b=c.seal({receipt:r,secret});
 assert.notEqual(a.nonce,b.nonce);
 assert.equal(c.open({receipt:r,envelope:a}),secret);
 assert.equal(c.open({receipt:Object.fromEntries(Object.entries(r).reverse()),envelope:a}),secret);
 assert.equal(JSON.stringify(a).includes(secret),false);
});

test('every current actor, target, CAS and expiry coordinate is authenticated',()=>{
 const c=codec(),r=receipt(),e=c.seal({receipt:r,secret:'S'.repeat(43)});
 for(const key of Object.keys(r)){
  const changed={...r,[key]:typeof r[key]==='number'?r[key]+1: key.endsWith('Id')&&typeof r[key]==='string'?ids.targetPrincipalId: key==='expiresAt'?new Date(time+500000).toISOString():key==='receiptSha256'?'b'.repeat(64):key==='version'?2:'7'};
  if(changed[key]===r[key])changed[key]=ids.actorPrincipalId;
  assert.throws(()=>c.open({receipt:changed,envelope:e}),{code:'REGISTERED_RESET_RECOVERY_UNAVAILABLE'},key);
 }
 assert.throws(()=>c.open({receipt:{...r,extra:'x'},envelope:e}),{code:'REGISTERED_RESET_RECOVERY_UNAVAILABLE'});
});

test('tampering, key loss and expiry cannot reveal the temporary credential',()=>{
 const c=codec(),r=receipt(),e=c.seal({receipt:r,secret:'S'.repeat(43)});
 assert.throws(()=>c.open({receipt:r,envelope:{...e,tag:'A'+e.tag.slice(1)}}),{code:'REGISTERED_RESET_RECOVERY_UNAVAILABLE'});
 assert.throws(()=>codec(()=>time+600000).seal({receipt:r,secret:'S'.repeat(43)}),{code:'REGISTERED_RESET_RECOVERY_UNAVAILABLE'});
 assert.throws(()=>createRegisteredAdminResetEnvelope({activeKeyId:'other',keys:new Map([['other',randomBytes(32)]]),now:()=>time}).open({receipt:r,envelope:e}),{code:'REGISTERED_RESET_RECOVERY_UNAVAILABLE'});
});
