'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopStandaloneCartImport:create}=require('../server/services/secureshopStandaloneCartImport');
test('cookie principal is rebound to real launch and actor authority without returning credentials',async()=>{
 const principal={role:'customer',shopUserId:101},scope={},input={requestId:'request',items:[{productId:1,quantity:1}]};
 const outcome={requestId:'request',imported:true};
 const run=create({bootstrap:async value=>{assert.equal(value,principal);return {bearer:'private',persona:{token:'private-actor'}};},
 launches:{resolveCapability:async token=>{assert.equal(token,'private');return scope;}},
 personaAuth:{authenticateBoundToken:async value=>{assert.deepEqual(value,{scope,token:'private-actor'});return {user:{id:101,role:'customer'},sessionId:'session',authorityVersion:'2'};}},
 commerce:{importGuestCart:async value=>{assert.deepEqual(value,{scope,persona:{id:101,role:'customer'},personaSession:{sessionId:'session',authorityVersion:'2'},...input});return outcome;}}});
 assert.equal(await run(principal,input),outcome);
 await assert.rejects(run({role:'merchant',shopUserId:101},input),{code:'SHOP_AUTH_INVALID'});
});
test('substituted actor cannot import into another customer cart',async()=>{
 let effects=0;
 const run=create({bootstrap:async()=>({bearer:'private',persona:{token:'private-actor'}}),
 launches:{resolveCapability:async()=>({})},personaAuth:{authenticateBoundToken:async()=>({user:{id:202,role:'customer'}})},
 commerce:{importGuestCart:async()=>{effects++;}}});
 await assert.rejects(run({role:'customer',shopUserId:101},{}),{code:'SHOP_AUTH_INVALID'});
 assert.equal(effects,0);
});
