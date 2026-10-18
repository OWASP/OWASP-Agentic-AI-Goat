'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createPricingHistoryRepository } = require('../server/database/postgres/secureshopPricingHistoryRepository');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');

function fixture({ missing=false, deniedGrant=false, staleAt=0, points, immutableProductRole=false }={}) {
  const current={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,platformOwnerId:5,platformSessionId:22};
  const birth={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:5,platformSessionId:11,targetId:randomUUID()};
  const persona={id:1000000002,role:'merchant'};
  const queries=[], checks=[], counters={leases:0,connections:0,releases:0};
  const target=createSceneBinding(birth,{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:current,
    withLease:async work=>{counters.leases++;return work();}});
  const client={async query(sql,args){
    queries.push({sql,args});
    if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:!deniedGrant}]};
    if(sql.includes('SELECT COALESCE(o.name')){
      // PostgreSQL requires UPDATE privilege on every relation named by a row
      // lock. The supported runtime deliberately cannot UPDATE base products.
      const locked=sql.match(/\bFOR\s+(?:NO KEY UPDATE|KEY SHARE|UPDATE|SHARE)\s+OF\s+([a-z,\s]+)$/i);
      if(immutableProductRole&&locked?.[1].split(',').map(value=>value.trim()).includes('p'))
        throw Object.assign(new Error('permission denied for immutable product relation'),{code:'42501'});
      return{rows:missing?[]:[{name:'Edited item',price:'25.00'}]};
    }
    if(sql.includes('SELECT price,observed_at'))return{rows:points||[
      {price:'25.00',observed_at:'2026-10-10 12:01:00.151+00',source:'price_change'},
      {price:'20.00',observed_at:'2026-10-10 12:00:00+00',source:'migration_baseline'}]};
    return{rows:[]};
  },release(){counters.releases++;}};
  const repository=createPricingHistoryRepository({pool:{async connect(){counters.connections++;return client;}},
    async checkCurrent(scope){checks.push(scope);assert.deepEqual(scope,current);if(checks.length===staleAt)throw Error('retired');}});
  return{repository,target,birth,current,persona,queries,checks,counters};
}
test('real observation timestamps and prices reach the chart in order under current grant and birth storage',async()=>{
  const f=fixture(),result=await f.repository.read(f.target,{productId:7,persona:f.persona});
  assert.deepEqual(result,{product_id:7,name:'Edited item',current_price:25,grounded:true,
    historyAvailable:true,historySource:'owned_product_price_observations',periodDays:30,historyTruncated:false,
    history:[{date:'2026-10-10T12:00:00.000Z',price:20,source:'migration_baseline'},
      {date:'2026-10-10T12:01:00.151Z',price:25,source:'price_change'}]});
  const product=f.queries.find(q=>q.sql.includes('SELECT COALESCE(o.name'));
  assert.deepEqual(product.args,[f.birth.targetId,f.birth.launchId,f.birth.scenarioId,1,5,11,7,'merchant',f.persona.id,true]);
  assert.match(product.sql,/p\.retailer_id=\$9/);assert.match(product.sql,/t\.lifecycle='active'/);
  assert.equal(f.queries.filter(q=>q.sql.includes('assert_scene_execution_grant')).length,2);
  assert.deepEqual(f.counters,{leases:1,connections:1,releases:1});assert.equal(f.checks.length,3);
});
test('history runtime needs no immutable product UPDATE privilege and still locks target retirement',async()=>{
  const f=fixture({immutableProductRole:true});
  const result=await f.repository.read(f.target,{productId:7,persona:f.persona});
  assert.equal(result.current_price,25);assert.equal(result.history.length,2);
  const transaction=f.queries[0].sql;
  assert.equal(transaction,'BEGIN ISOLATION LEVEL REPEATABLE READ');
  const sql=f.queries.find(query=>query.sql.includes('SELECT COALESCE(o.name')).sql;
  assert.match(sql,/FOR SHARE OF t\s*$/);
  assert.equal(f.queries.filter(query=>query.sql.includes('assert_scene_execution_grant')).length,2);
  assert.equal(f.checks.length,3);assert.equal(f.queries.at(-1).sql,'COMMIT');
});
test('missing or foreign merchant product, stale grant, and retired launch deny before history data',async()=>{
  for(const options of [{missing:true},{deniedGrant:true},{staleAt:1}]){
    const f=fixture(options);await assert.rejects(f.repository.read(f.target,{productId:7,persona:f.persona}));
    assert.equal(f.queries.filter(q=>q.sql.includes('SELECT price,observed_at')).length,0);
    if(!options.staleAt){assert.equal(f.queries.at(-1).sql,'ROLLBACK');assert.equal(f.counters.releases,1);}
  }
});
test('forged scene capability cannot read, while explicit customer read uses its current scene authority',async()=>{
  const f=fixture();await assert.rejects(f.repository.read({...f.target},{productId:7,persona:f.persona}),{code:'SHOP_SCENE_STALE'});
  assert.equal(f.counters.connections,0);
  const result=await f.repository.read(f.target,{productId:7,persona:{id:3,role:'customer'}});
  assert.equal(result.grounded,true);
  assert.equal(f.queries.find(q=>q.sql.includes('SELECT COALESCE(o.name')).args[7],'customer');
});
test('empty recorded window stays empty and dense actual events are bounded without generated samples',async()=>{
  const empty=fixture({points:[]});assert.deepEqual((await empty.repository.read(empty.target,{productId:7,persona:empty.persona})).history,[]);
  const points=Array.from({length:513},(_,i)=>({price:String(513-i),observed_at:new Date(Date.UTC(2026,9,10,0,0,513-i)).toISOString(),source:'price_change'}));
  const f=fixture({points}),result=await f.repository.read(f.target,{productId:7,persona:f.persona});
  assert.equal(result.history.length,512);assert.equal(result.historyTruncated,true);
  assert.equal(result.history[0].price,2);assert.equal(result.history.at(-1).price,513);
});
test('corrupt observation and revocation during read roll back without publishing history',async()=>{
  for(const options of [{staleAt:2},{points:[{price:'bad',observed_at:'2026-10-10T00:00:00Z',source:'price_change'}]},
    {points:[{price:'25',observed_at:'bad',source:'price_change'}]},
    {points:[{price:'25',observed_at:'2026-10-10T00:00:00Z',source:'fabricated'}]}]){
    const f=fixture(options);await assert.rejects(f.repository.read(f.target,{productId:7,persona:f.persona}));
    assert.equal(f.queries.at(-1).sql,'ROLLBACK');assert.equal(f.counters.releases,1);
    assert.equal(f.queries.some(q=>q.sql==='COMMIT'),false);
  }
});
