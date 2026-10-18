'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {sameOptimizeAuthority}=require('../server/services/secureshopListingOptimizeEvidence');
test('retained scene binding remains distinct from launch scope coordinates',()=>{
 const targetId=randomUUID(),sceneId=randomUUID(),grantId=randomUUID(),sessionId=randomUUID();
 const admission={binding:{targetId,scope:{scenarioId:randomUUID(),generation:1},persona:{id:12},personaSession:{sessionId,authorityVersion:'4'}},request:{sceneId,sceneGeneration:7,grantId}};
 const setup={scene:{targetId,sceneId,sceneGeneration:7,grantId},persona:{id:12,sessionId,authorityVersion:'4'}};
 assert.notEqual(admission.binding.scope.scenarioId,sceneId);assert.notEqual(admission.binding.scope.generation,7);assert.equal(sameOptimizeAuthority(setup,admission),true);
 assert.equal(sameOptimizeAuthority({...setup,scene:{...setup.scene,grantId:randomUUID()}},admission),false);
 assert.equal(sameOptimizeAuthority({...setup,scene:{...setup.scene,sceneGeneration:1}},admission),false);
});
