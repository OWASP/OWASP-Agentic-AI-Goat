'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createInventoryAssessment}=require('../server/services/secureshopInventoryAssessment');
const {OBJECTIVE}=require('../server/services/secureshopInventoryEvidence');

test('inventory assessment eligibility uses the active standalone tenant catalog',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
  platformOwnerId:1001,platformSessionId:2001};
 const tenantId=randomUUID(),calls=[];
 const identityPool={async query(sql,args){calls.push([sql,args]);
  if(sql.includes('secureshop_authority_owners'))return{rows:[{realm:'shop',shop_tenant_id:tenantId}]};
  if(sql.includes('secureshop_auth.assessment_objectives'))return{rows:[{objective_id:OBJECTIVE}]};
  throw Error('Workshop catalog must not decide standalone eligibility');
 }};
 const assessment=createInventoryAssessment({identityPool,
  receipts:{async beginEvaluation(){},async recordVerdict(){}},
  progress:{async getGeneration(){return 1;}},judge:async()=>({verdict:'fail'}),
  qualifyModel:()=>false,personaBindings:{async capture(){return{};}}});
 assert.equal(await assessment.isEnabled(scope),true);
 assert.deepEqual(calls[0][1],[scope.platformOwnerId]);
 assert.deepEqual(calls[1][1],[tenantId,[OBJECTIVE]]);
});
