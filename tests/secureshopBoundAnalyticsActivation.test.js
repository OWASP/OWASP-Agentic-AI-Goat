'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopBoundAnalytics}=require('../server/services/secureshopBoundAnalytics');
const {normalizeConversationPurpose}=require('../server/services/secureshopConversationPurpose');
test('qualified Analytics purpose still requires explicit trusted target composition',()=>{
 assert.equal(normalizeConversationPurpose('secureshop_analytics'),'secureshop_analytics');
 assert.throws(()=>createSecureShopBoundAnalytics({}),/Owned analytics dependencies required/);
 assert.throws(()=>createSecureShopBoundAnalytics({launches:{assertCurrent(){}},coordinator:{run(){}},provider:{chat(){},finalResponse(){}},personaAuthority:{capture(){}},ownedQuery:{execute(){}}}),/Owned analytics dependencies required/);
});
