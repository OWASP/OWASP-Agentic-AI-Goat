'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createSecureShopBoundMcpRepository } = require('../server/database/postgres/secureshopBoundMcpRepository');

function scope() {
  return { targetId:randomUUID(),launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
    platformOwnerId:7,platformSessionId:8,serverIdentity:'owned-lab',trustScenario:'rug_pull' };
}
function binding(value,overrides={}) {
  return { launchId:value.launchId,scenarioId:value.scenarioId,generation:value.generation,
    platformOwnerId:value.platformOwnerId,platformSessionId:value.platformSessionId,
    personaId:3,role:'admin',sessionId:randomUUID(),authorityVersion:'1',...overrides };
}
function repository(pool,overrides={}) {
  return createSecureShopBoundMcpRepository(pool,{checkCurrent:async()=>{},checkRotation:async()=>{},checkCleanup:async()=>{},...overrides});
}

test('revoked persona fence rejects before repository SQL or pool acquisition',async()=>{
  const value=scope(),calls=[];
  const fence={binding:binding(value),async withPersonaEffect(){calls.push('fence');throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};
  const repo=repository({async query(){calls.push('pool-query');},async connect(){calls.push('connect');throw Error('unexpected');}});
  await assert.rejects(repo.provision(value,fence),{code:'SHOP_AUTH_INVALID'});
  assert.deepEqual(calls,['fence']);
});

test('scope and actor mismatches reject before entering the fence or executing SQL',async()=>{
  const value=scope();
  for(const changed of [
    {launchId:randomUUID()},{scenarioId:randomUUID()},{generation:2},{platformOwnerId:9},{platformSessionId:10},
  ]){
    let entered=0,sql=0;
    const fence={binding:binding(value,changed),async withPersonaEffect(){entered++;}};
    const repo=repository({async query(){sql++;},async connect(){sql++;}});
    await assert.rejects(repo.provision(value,fence),{code:'SHOP_AUTH_INVALID'});
    assert.equal(entered,0);assert.equal(sql,0);
  }
  for(const changed of [{personaId:4},{role:'merchant'}]){
    let entered=0,sql=0;
    const fence={binding:binding(value,changed),async withPersonaEffect(){entered++;}};
    const repo=repository({async query(){sql++;},async connect(){sql++;}});
    await assert.rejects(repo.provision({...value,shopUserId:3,role:'admin'},fence),{code:'SHOP_AUTH_INVALID'});
    assert.equal(entered,0);assert.equal(sql,0);
  }
  let entered=0,sql=0;
  const fence={binding:binding(value),async withPersonaEffect(){entered++;}};
  const repo=repository({async query(){sql++;},async connect(){sql++;}});
  await assert.rejects(repo.recordInvocation(value,{}, {id:4,role:'admin'},fence),{code:'SHOP_AUTH_INVALID'});
  assert.equal(entered,0);assert.equal(sql,0);
  await assert.rejects(repo.currentSchema({...value,shopUserId:4},fence),{code:'SHOP_AUTH_INVALID'});
  assert.equal(entered,0);assert.equal(sql,0);
});

test('fenced invocation effect and audit use one supplied client and audit failure rolls back',async()=>{
  const value=scope(),operationId=randomUUID();
  const input={operationId,runId:randomUUID(),requestId:randomUUID(),callId:'call-1',toolName:'forecast_lookup',schemaVersion:1,
    schemaSha256:'11'.repeat(32),argumentsSha256:'22'.repeat(32),remoteReceiptSha256:'33'.repeat(32),
    trustPolicySha256:'44'.repeat(32),resultSha256:'55'.repeat(32),approved:false,serverApproved:true,
    schemaApproved:false,trustScenario:'rug_pull',behaviorClass:'protected_record_export'};
  const calls=[];
  const client={async query(sql){calls.push(sql);
    if(sql.includes('FROM secureshop_agents.bound_mcp_targets'))return{rows:[{lifecycle:'active',server_identity:value.serverIdentity,trust_scenario:value.trustScenario}]};
    if(sql.includes('WHERE operation_id=$1'))return{rows:[]};
    if(sql.includes('INSERT INTO secureshop_agents.bound_mcp_invocations'))return{rows:[{invocation_id:operationId,completed_at:new Date()}]};
    return{rows:[]};}};
  const authority=binding(value);
  const fence={binding:authority,async withPersonaEffect(work){calls.push('BEGIN');try{const result=await work(client,authority);calls.push('COMMIT');return result;}
    catch(error){calls.push('ROLLBACK');throw error;}}};
  let auditClient;
  const repo=repository({async query(){throw Error('pool query not expected');},async connect(){throw Error('pool connect not expected');}},
    {checkCurrent:async(_value,tx)=>assert.equal(tx,client),auditStore:{async append(tx){auditClient=tx;calls.push('audit');throw Error('controlled audit rollback');}}});
  await assert.rejects(repo.recordInvocation(value,input,{id:3,role:'admin'},fence),/controlled audit rollback/);
  assert.equal(auditClient,client);
  assert.equal(calls.includes('COMMIT'),false);
  assert.deepEqual(calls.slice(-2),['audit','ROLLBACK']);
  assert.equal(calls.filter(item=>item==='BEGIN').length,1);
});

test('provision, schema read, and discovery all execute through the supplied fenced client',async()=>{
  const value=scope(),authority=binding(value),calls=[];let version=0;
  const client={async query(sql){calls.push(sql);
    if(sql.includes('FROM secureshop_agents.bound_mcp_targets'))return{rows:[{lifecycle:'active',server_identity:value.serverIdentity,
      trust_scenario:value.trustScenario,current_schema_version:version}]};
    if(sql.includes('UPDATE secureshop_agents.bound_mcp_targets'))version=1;
    return{rows:[]};}};
  const fence={binding:authority,async withPersonaEffect(work){calls.push('fence');return work(client,authority);}};
  const repo=repository({async query(){throw Error('pool query not expected');},async connect(){throw Error('pool connect not expected');}},
    {checkCurrent:async(_value,tx)=>assert.equal(tx,client)});
  assert.equal(await repo.provision(value,fence),value);
  assert.equal(await repo.currentSchema(value,fence),null);
  const schema=await repo.recordDiscovery(value,{expectedVersion:0,schemaSha256:'11'.repeat(32),
    discoveryReceiptSha256:'22'.repeat(32),tools:[]},{id:3,role:'admin'},fence);
  assert.equal(schema.version,1);
  assert.equal(calls.filter(item=>item==='fence').length,3);
  assert.equal(calls.some(sql=>sql==='BEGIN'||sql==='COMMIT'||sql==='ROLLBACK'),false);
});
