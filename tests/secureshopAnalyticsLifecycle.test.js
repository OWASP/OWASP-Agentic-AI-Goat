'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createAnalyticsLifecycle}=require('../server/services/secureshopAnalyticsLifecycle');
test('private Analytics retirement is bound to canonical original generation and deletion owner',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:4,platformOwnerId:1,platformSessionId:2},resetId=randomUUID();let calls=0;
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async id=>({resetId:id,status:'fenced',binding:scope})},service:{retire:async actual=>{assert.deepEqual(actual,scope);calls++;return{retired:true};}}});
 assert.deepEqual(await lifecycle.retireGeneration(resetId),{resetId,retired:true});await assert.rejects(lifecycle.destroyForDeletion({resetIds:[resetId],subjectId:3,check:async()=>{}}));assert.equal(calls,1);
 assert.deepEqual(await lifecycle.destroyForDeletion({resetIds:[resetId],subjectId:1,check:async()=>{}}),{completed:true});assert.equal(calls,2);
});
test('missing or changed reset authority cannot acknowledge cleanup',async()=>{
 let count=0;const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},resetId=randomUUID();
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>({resetId,status:'fenced',binding:{...scope,generation:++count}})},service:{retire:async()=>({retired:true})}});await assert.rejects(lifecycle.retireGeneration(resetId),/changed/);
});
test('missing private configuration cannot acknowledge known admission cleanup debt',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},resetId=randomUUID();let known=true;
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>({resetId,status:'fenced',binding:scope})},agentsPool:{query:async sql=>({rows:sql.includes('to_regclass')?[{relation:'secureshop_agents.analytics_request_admissions'}]:known?[{present:1}]:[]})}});
 await assert.rejects(lifecycle.retireGeneration(resetId),{code:'ANALYTICS_CLEANUP_UNAVAILABLE'});known=false;assert.deepEqual(await lifecycle.retireGeneration(resetId),{resetId,retired:true});
});
test('coupon-only durable debt also requires private cleanup configuration',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:5,platformSessionId:6},resetId=randomUUID();let debt=true;
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>({resetId,status:'fenced',binding:scope})},agentsPool:{query:async()=>({rows:[]})},reviewPool:{query:async(sql,args)=>{if(sql.includes('to_regclass'))return{rows:[{relation:'secureshop_review.bound_commerce_operations'}]};assert.deepEqual(args,[scope.launchId,scope.scenarioId,2,5,6]);assert.match(sql,/o.kind='coupon'/);return{rows:debt?[{present:1}]:[]};}}});
 await assert.rejects(lifecycle.retireGeneration(resetId),{code:'ANALYTICS_CLEANUP_UNAVAILABLE'});debt=false;assert.deepEqual(await lifecycle.retireGeneration(resetId),{resetId,retired:true});
});

test('coupon probe started or uncertain turns prevent false cleanup when private configuration is missing',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,platformOwnerId:7,platformSessionId:8},resetId=randomUUID();let debt=true;
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>({resetId,status:'fenced',binding:scope})},agentsPool:{query:async(sql,args)=>{
  if(sql.includes('to_regclass'))return{rows:[{relation:sql.includes('turn_requests')?'secureshop_agents.turn_requests':null}]};
  assert.match(sql,/conversation_purpose IN \('secureshop_coupon_probe','secureshop_product_search_union','secureshop_order_status_error'\)/);
  assert.match(sql,/JOIN secureshop_agents.agent_sessions/);
  assert.doesNotMatch(sql,/t.status\s*=/);
  assert.deepEqual(args,[scope.launchId,scope.scenarioId,3,7,8]);
  return{rows:debt?[{present:1}]:[]};
 }}});
 await assert.rejects(lifecycle.retireGeneration(resetId),{code:'ANALYTICS_CLEANUP_UNAVAILABLE'});
 debt=false;assert.deepEqual(await lifecycle.retireGeneration(resetId),{resetId,retired:true});
});

test('product search started or uncertain turn debt cannot be acknowledged without its private target cleanup',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:4,platformOwnerId:2,platformSessionId:3},resetId=randomUUID();let debt=true;
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>({resetId,status:'fenced',binding:scope})},agentsPool:{query:async(sql,args)=>{
  if(sql.includes('to_regclass'))return{rows:[{relation:sql.includes('turn_requests')?'secureshop_agents.turn_requests':null}]};
  assert.match(sql,/s.conversation_purpose IN \('secureshop_coupon_probe','secureshop_product_search_union','secureshop_order_status_error'\)/);
  assert.doesNotMatch(sql,/t.status\s*=/);assert.deepEqual(args,[scope.launchId,scope.scenarioId,4,2,3]);
  return{rows:debt?[{present:1}]:[]};
 }}});
 await assert.rejects(lifecycle.retireGeneration(resetId),{code:'ANALYTICS_CLEANUP_UNAVAILABLE'});
 debt=false;assert.deepEqual(await lifecycle.retireGeneration(resetId),{resetId,retired:true});
});

test('order status started or uncertain turn debt cannot be acknowledged without its private target cleanup',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:4,platformOwnerId:2,platformSessionId:3},resetId=randomUUID();let debt=true;
 const lifecycle=createAnalyticsLifecycle({cleanupAuthority:{getOperation:async()=>({resetId,status:'fenced',binding:scope})},agentsPool:{query:async(sql,args)=>{
  if(sql.includes('to_regclass'))return{rows:[{relation:sql.includes('turn_requests')?'secureshop_agents.turn_requests':null}]};
  assert.match(sql,/s.conversation_purpose IN \('secureshop_coupon_probe','secureshop_product_search_union','secureshop_order_status_error'\)/);
  assert.doesNotMatch(sql,/t.status\s*=/);assert.deepEqual(args,[scope.launchId,scope.scenarioId,4,2,3]);
  return{rows:debt?[{present:1}]:[]};
 }}});
 await assert.rejects(lifecycle.retireGeneration(resetId),{code:'ANALYTICS_CLEANUP_UNAVAILABLE'});
 debt=false;assert.deepEqual(await lifecycle.retireGeneration(resetId),{resetId,retired:true});
});
