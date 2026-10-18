'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createSecureShopModeRepository}=require('../server/database/postgres/secureshopModeRepository');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:51,platformSessionId:61};
const key='secureshop_agent_security';
test('shop mode is a read-only exact execution principal snapshot and never workshop state',async()=>{
  let revision='1',principal=randomUUID();const queries=[];
  const repo=createSecureShopModeRepository({connect(){throw Error('No transaction inside effect');},
    async query(sql,args){queries.push(sql);assert.deepEqual(args,[51,61]);
      return {rows:[{realm:'shop',shop_tenant_id:'tenant',principal_id:principal,tenant_active:true,
        mode:'fixed',generation:0,revision}]};}});
  const first=await repo.getEvaluationScope(51,key,scope);
  assert.equal(first.mode,'fixed');
  revision='2';const next=await repo.getEvaluationScopeAtEffect(51,key,scope);
  assert.notEqual(first.modeStamp,next.modeStamp);
  principal=randomUUID();const sibling=await repo.getEvaluationScopeAtEffect(51,key,scope);
  assert.notEqual(next.modeStamp,sibling.modeStamp);
  assert.ok(queries.every(sql=>!/(workshop_platform|FOR UPDATE|INSERT|BEGIN|advisory)/i.test(sql)));
  await assert.rejects(repo.getEvaluationScope(52,key,scope));
});
test('missing shop state cannot fall back to workshop authority',async()=>{
  let count=0;const repo=createSecureShopModeRepository({connect(){throw Error('Legacy fallback forbidden');},
    async query(){count++;return {rows:[{realm:'shop',shop_tenant_id:'tenant',tenant_active:true}]};}});
  await assert.rejects(repo.getEvaluationScope(51,key,scope),{code:'ANALYTICS_MODE_STALE'});
  assert.equal(count,1);
});
test('shop owner ID collision remains bound to tenant mode instead of platform workshop mode',async()=>{
  const ownerId=2,collisionScope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
    platformOwnerId:ownerId,platformSessionId:9},tenant=randomUUID(),principal=randomUUID(),queries=[];
  const repo=createSecureShopModeRepository({connect(){throw Error('Platform workshop fallback forbidden');},
    async query(sql,args){queries.push(sql);assert.deepEqual(args,[ownerId,collisionScope.platformSessionId]);
      return{rows:[{realm:'shop',shop_tenant_id:tenant,tenant_active:true,
        principal_id:principal,mode:'vuln',generation:4,revision:'7'}]};}});
  const value=await repo.getEvaluationScope(ownerId,key,collisionScope);
  assert.equal(value.mode,'vuln');assert.equal(value.generation,4);
  assert.match(value.modeStamp,/^[a-f0-9]{64}$/);assert.equal(queries.length,1);
  assert.match(queries[0],/secureshop_auth\.tenant_modes/);
  assert.doesNotMatch(queries[0],/workshop_platform\.user_modes/);
});
test('platform realm keeps the legacy effect-time mode reader',async()=>{
  const queries=[];const repo=createSecureShopModeRepository({connect(){throw Error('No owner lock at effect');},
    async query(sql){queries.push(sql);return {rows:[sql.includes('secureshop_authority_owners')
      ?{realm:'platform',shop_tenant_id:null}:{generation:0,mode:'fixed',stamp:'legacy',revision:'8'}]};}});
  assert.equal((await repo.getEvaluationScopeAtEffect(51,key,scope)).mode,'fixed');
  assert.equal(queries.length,2);assert.match(queries[1],/workshop_platform.user_state/);
});
