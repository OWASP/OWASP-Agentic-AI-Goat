'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {FLAG,activationPolicy}=require('../server/services/sensitiveInfoResetActivationPolicy');

test('release policy is PostgreSQL-default-on with one explicit maintenance opt-out',()=>{
 const pg={PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
 assert.deepEqual(activationPolicy(pg),{requested:true,postgres:true,explicitlyDisabled:false});
 assert.equal(activationPolicy({...pg,[FLAG]:'true'}).requested,true);
 assert.deepEqual(activationPolicy({...pg,[FLAG]:'false'}),
  {requested:false,postgres:true,explicitlyDisabled:true});
 assert.equal(activationPolicy({}).requested,false);
 assert.throws(()=>activationPolicy({...pg,[FLAG]:'TRUE'}),{code:'INVALID_CONFIGURATION'});
 assert.throws(()=>activationPolicy({PLATFORM_DATABASE_ENGINE:'postgres'}),{code:'INVALID_CONFIGURATION'});
});
