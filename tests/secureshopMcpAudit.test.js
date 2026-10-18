'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const {createSecureShopBoundMcpRepository}=require('../server/database/postgres/secureshopBoundMcpRepository');
test('MCP receipt audit shares invocation transaction and fails closed on journal outage',async()=>{
 for(const fail of [false,true]){
  const scope={targetId:randomUUID(),launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8,serverIdentity:'owned-lab',trustScenario:'rug_pull'};
  const input={operationId:randomUUID(),runId:randomUUID(),requestId:randomUUID(),callId:'call-1',toolName:'forecast_lookup',schemaVersion:1,schemaSha256:'11'.repeat(32),argumentsSha256:'22'.repeat(32),remoteReceiptSha256:'33'.repeat(32),trustPolicySha256:'44'.repeat(32),resultSha256:'55'.repeat(32),approved:false,serverApproved:true,schemaApproved:false,trustScenario:'rug_pull',behaviorClass:'protected_record_export'};
  const calls=[];let event;
  const client={async query(sql){calls.push(sql);if(sql.includes('FROM secureshop_agents.bound_mcp_targets'))return{rows:[{lifecycle:'active',server_identity:scope.serverIdentity,trust_scenario:scope.trustScenario}]};if(sql.includes('INSERT INTO secureshop_agents.bound_mcp_invocations'))return{rows:[{invocation_id:input.operationId,completed_at:new Date()}]};return{rows:[]};},release(){calls.push('release');}};
  const repo=createSecureShopBoundMcpRepository({query:async()=>{},connect:async()=>client},{checkCurrent:async()=>{},checkRotation:async()=>{},checkCleanup:async()=>{},auditStore:{async append(tx,e){assert.equal(tx,client);event=e;calls.push('audit');if(fail)throw Error('journal unavailable');}}});
  const promise=repo.recordInvocation(scope,input,{id:3,role:'admin'});
  if(fail){await assert.rejects(promise,/journal unavailable/);assert.equal(calls.includes('COMMIT'),false);assert.deepEqual(calls.slice(-2),['ROLLBACK','release']);}
  else{await promise;assert.deepEqual(calls.slice(-3),['audit','COMMIT','release']);}
  assert.equal(event.action,'mcp_invocation_recorded');assert.equal(event.outcome,'completed');
  assert.equal(JSON.parse(event.paramsJson).approved,false);
  assert.deepEqual(event.persona,{id:3,role:'admin'});
 }
});
