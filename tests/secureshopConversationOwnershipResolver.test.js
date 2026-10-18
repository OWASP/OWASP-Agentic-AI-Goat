'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopConversationOwnershipResolver}=require('../server/services/secureshopConversationOwnershipResolver');

const IDS={active:'11111111-1111-4111-8111-111111111111',abandoned:'22222222-2222-4222-8222-222222222222',
 pending:'33333333-3333-4333-8333-333333333333',legacy:'44444444-4444-4444-8444-444444444444',
 mismatch:'55555555-5555-4555-8555-555555555555',launch:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 scenario:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'};
function row(id,state='active',extra={}){return {id,authority_mode:'launch_bound',binding_state:state,
 platform_launch_id:IDS.launch,platform_scenario_id:IDS.scenario,platform_launch_generation:2,
 original_platform_owner_id:7,original_platform_session_id:70,...extra};}
function fixture(){
 const rows=[row(IDS.active),row(IDS.abandoned,'abandoned',{platform_launch_generation:1}),row(IDS.pending,'pending'),
  row(IDS.legacy,'active',{authority_mode:'legacy',platform_launch_id:null}),row(IDS.mismatch,'active',{original_platform_owner_id:8})];
 const agentsPool={query:async(sql,params)=>({rows:sql.includes('original_platform_owner_id=$1')
  ? rows.filter(item=>item.original_platform_owner_id===params[0])
  : rows.filter(item=>params[0].includes(item.id))})};
 const identityPool={query:async()=>({rows:[{launch_id:IDS.launch,scenario_id:IDS.scenario,generation:2,status:'active',
  original_platform_owner_id:7,original_platform_session_id:70}]})};
 return createSecureShopConversationOwnershipResolver({agentsPool,identityPool});
}

test('resolver accepts exact active and historical abandoned bindings only',async()=>{
 const resolver=fixture();
 assert.equal((await resolver.resolve(IDS.active)).ownerId,'7');
 assert.deepEqual((await resolver.resolve(IDS.abandoned)),{conversationId:IDS.abandoned,ownerId:'7',launchId:IDS.launch,
  scenarioId:IDS.scenario,generation:1,state:'abandoned'});
 for(const id of [IDS.pending,IDS.legacy,IDS.mismatch])assert.equal(await resolver.resolve(id),null);
 assert.deepEqual(await resolver.listOwnedConversationIds(7),[IDS.active,IDS.abandoned]);
});

test('resolver rejects forged input and cross-store coordinate mismatches',async()=>{
 const resolver=fixture();
 await assert.rejects(resolver.resolve('not-a-conversation'),TypeError);
 await assert.rejects(resolver.listOwnedConversationIds('shop-customer'),TypeError);
 const wrong=createSecureShopConversationOwnershipResolver({agentsPool:{query:async()=>({rows:[row(IDS.active)]})},
  identityPool:{query:async()=>({rows:[{launch_id:IDS.launch,scenario_id:IDS.scenario,generation:2,
   original_platform_owner_id:7,original_platform_session_id:71}]})}});
  assert.equal(await wrong.resolve(IDS.active),null);
  const legacy=createSecureShopConversationOwnershipResolver({agentsPool:{query:async()=>({rows:[row(IDS.legacy,'active',{
   authority_mode:'legacy',platform_launch_id:null,platform_scenario_id:null,platform_launch_generation:null,
   original_platform_owner_id:null,original_platform_session_id:null})]})},identityPool:{query:async()=>{throw new Error('invalid rows must not reach identity');}}});
  assert.equal(await legacy.resolve(IDS.legacy),null);
});
