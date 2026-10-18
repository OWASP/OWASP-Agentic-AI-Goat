'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('Analytics bridge preserves exact request identity and exposes only closed recovery operations',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const requestId='11111111-1111-4111-8111-111111111111';
 const query=compileOperation('merchant.analytics.query',{body:{question:'count products',requestId}});
 assert.deepEqual(query.body,{question:'count products',requestId});
 assert.equal(compileOperation('merchant.analytics.describe',{}).path,'/api/secureshop/merchant/analytics');
 assert.equal(compileOperation('merchant.analytics.request',{params:{requestId}}).method,'GET');
 assert.equal(matchOperationRequest({pathname:'/api/secureshop/merchant/analytics/requests/'+requestId,method:'GET'}).name,'merchant.analytics.request');
 assert.throws(()=>compileOperation('merchant.analytics.query',{body:{question:'x',requestId,scope:{owner:1}}}));
 assert.throws(()=>compileOperation('merchant.analytics.history',{query:{ownerId:1}}));
});
test('merchant owned top-products bridge remains separate from teaching analytics',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const read=compileOperation('merchant.overview.topProducts',{query:{limit:8,days:30}});
 assert.equal(read.method,'GET');assert.equal(read.path,'/api/secureshop/merchant/overview/top-products?limit=8&days=30');
 assert.equal(matchOperationRequest({pathname:'/api/secureshop/merchant/overview/top-products',method:'GET',query:{limit:8,days:30}}).name,'merchant.overview.topProducts');
 assert.equal(matchOperationRequest({pathname:'/api/secureshop/merchant/analytics/top-products',method:'GET'}).name,'merchant.analytics.topProducts');
 for(const query of [{targetId:'foreign'},{retailer_id:12},{ownerId:1}])assert.throws(()=>compileOperation('merchant.overview.topProducts',{query}));
 assert.throws(()=>matchOperationRequest({pathname:'/api/secureshop/merchant/overview/top-products',method:'POST'}));
});
