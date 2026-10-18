'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopPersonaInboxAvailability,PERSONA_INBOX_OBJECTIVE_IDS}
  =require('../server/services/secureshopPersonaInboxAvailability');

function pool(state){return{async query(_sql,args){assert.equal(args[0],'secureshop_agent_security');
  return{rows:PERSONA_INBOX_OBJECTIVE_IDS.map(objective_id=>({objective_id,catalog_active:true,
    exercise_active:true,is_visible:state.visible,is_enabled:state.enabled.has(objective_id)}))};}};}

test('hidden startup remains structurally registered but operations fail closed',async()=>{
  const availability=createSecureShopPersonaInboxAvailability(pool({visible:false,enabled:new Set()}));
  const state=await availability.read();assert.equal(state.registered,true);assert.equal(state.visible,false);
  await assert.rejects(availability.assertObjectives(['ss_cross_persona_effect']),
    {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
});

test('selective objective enablement requires the exact operation objectives',async()=>{
  const enabled=new Set(['ss_cross_persona_effect','ss_acl_advisory_effect']);
  const availability=createSecureShopPersonaInboxAvailability(pool({visible:true,enabled}));
  await availability.assertObjectives(['ss_cross_persona_effect','ss_acl_advisory_effect']);
  await assert.rejects(availability.assertObjectives(['ss_acl_enforced_block']),
    {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
});

test('hide after startup is observed on every operation check',async()=>{
  const state={visible:true,enabled:new Set(PERSONA_INBOX_OBJECTIVE_IDS)};
  const availability=createSecureShopPersonaInboxAvailability(pool(state));
  await availability.assertObjectives(['ss_cross_persona_effect']);
  state.visible=false;
  await assert.rejects(availability.assertObjectives(['ss_cross_persona_effect']),
    {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
});

test('standalone tenant availability reads qualified shop objectives from the exact current scope',async()=>{
  const scope={launchId:'10000000-0000-4000-8000-000000000001',
    scenarioId:'20000000-0000-4000-8000-000000000001',generation:2,platformOwnerId:19,platformSessionId:23};
  const tenantId='30000000-0000-4000-8000-000000000001',calls=[];
  const availability=createSecureShopPersonaInboxAvailability({async query(sql,args){calls.push({sql,args});
    if(sql.includes('identity.secureshop_authority_owners'))return {rows:[{realm:'shop',shop_tenant_id:tenantId}]};
    if(sql.includes('secureshop_auth.assessment_objectives'))return {rows:[
      {objective_id:'ss_cross_persona_effect'},{objective_id:'ss_acl_advisory_effect'}]};
    throw Error('Legacy catalog must not authorize standalone objectives');}});
  const state=await availability.read(scope);
  assert.equal(state.visible,true);
  assert.deepEqual([...state.enabled],['ss_cross_persona_effect','ss_acl_advisory_effect']);
  await availability.assertObjectives(['ss_cross_persona_effect'],scope);
  await assert.rejects(availability.assertObjectives(['ss_acl_enforced_block'],scope),
    {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  assert.equal(calls[0].args[0],scope.platformOwnerId);
  assert.equal(calls[1].args[0],tenantId);
});
