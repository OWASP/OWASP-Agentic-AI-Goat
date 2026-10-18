'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {createListingOptimizeSetup,validateListingOptimizeSetup,projectListingOptimizeSetup}=require('../server/services/secureshopRoleListingOptimizeSetup');
const mode=featureId=>({version:1,featureId,policyVersion:featureId==='listings'?'owned-listing-import-v1':'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:featureId}});
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function fixture(){const context={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:12,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},target:{targetId:randomUUID(),scene:{sceneId:randomUUID(),sceneGeneration:7,grantId:randomUUID()}}};
 const product={id:7,name:'Owned image',imageUrl:'https://owned.invalid/p.jpg; /usr/bin/uname -n; #',retailer_id:12,status:'active'};
 const selected={version:1,kind:'merchant_product',choiceId:randomUUID(),sourceId:7,snapshotSha256:digest({id:7}),card:{}};
 return{context,product,selected,source:{sessionId:randomUUID(),requestId:randomUUID()},origin:{step:1,callId:'tool_1'},modeCapability:mode('merchant_assistant'),listingsModeCapability:mode('listings')};}
test('freezes exact owned image bytes and projects review data without authority IDs',()=>{const f=fixture(),value=createListingOptimizeSetup(f),publicValue=projectListingOptimizeSetup(value);
 assert.notEqual(f.context.scope.scenarioId,f.context.target.scene.sceneId);assert.notEqual(f.context.scope.generation,f.context.target.scene.sceneGeneration);assert.equal(value.scene.sceneId,f.context.target.scene.sceneId);assert.equal(value.scene.grantId,f.context.target.scene.grantId);assert.equal(value.product.imageUrl,f.product.imageUrl);assert.equal(publicValue.product.imageUrl,f.product.imageUrl);assert.equal(Object.hasOwn(publicValue.product,'productId'),false);assert.equal(validateListingOptimizeSetup(JSON.parse(JSON.stringify(value))).operationId,value.operationId);});
test('rejects sibling merchant, changed image, synthetic fields, and oversize duplicated command',()=>{const f=fixture();
 assert.throws(()=>createListingOptimizeSetup({...f,product:{...f.product,retailer_id:13}}),{code:'ROLE_LISTINGS_CHOICE_STALE'});
 const value=createListingOptimizeSetup(f);assert.throws(()=>validateListingOptimizeSetup({...value,product:{...value.product,imageUrl:value.product.imageUrl+'changed'}}));
 assert.throws(()=>createListingOptimizeSetup({...f,product:{...f.product,imageUrl:'https://owned.invalid/'+('x'.repeat(4070))}}));
 assert.throws(()=>validateListingOptimizeSetup({...value,clientUrl:'https://attacker.invalid'}));});
