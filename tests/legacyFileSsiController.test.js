'use strict';const test=require('node:test'),assert=require('node:assert/strict');
test('controller maps all five genuine manual/agent paths and never supplies owner or completion',async()=>{
 const {createLegacyFileSsiController}=await import('../client/src/utils/legacyFileSsiController.mjs');const calls=[];
 const controller=createLegacyFileSsiController({http:{get:async()=>({data:{challenges:[]}}),post:async(...args)=>{calls.push(args);return{data:{}};}}});
 for(const objectiveId of ['path_traversal','ssi_injection','combined_traversal_ssi','ai_assisted_path_traversal','ai_assisted_ssi'])await controller.attempt({objectiveId,input:'owned input'});
 assert.deepEqual(calls.map(c=>c[0]),['file/read','template/render','document/process','canonical-agent/chat','canonical-agent/chat'].map(p=>'/api/sensitive-info/'+p));
 assert.ok(calls.every(c=>!('userId'in c[1])&&!('completed'in c[1])));assert.equal(await controller.snapshot(),null);
});
test('uncertain reset response retains exact operation for retry',async()=>{
 const {createLegacyFileSsiController}=await import('../client/src/utils/legacyFileSsiController.mjs');const ids=[];let failed=true;
 const controller=createLegacyFileSsiController({operationId:()=> 'exact-operation',http:{get:async()=>{},post:async(_u,_b,opts)=>{ids.push(opts.headers['x-reset-operation-id']);if(failed){failed=false;throw Error('lost response');}return{data:{success:true}};}}});
 await assert.rejects(controller.reset());await controller.reset();assert.deepEqual(ids,['exact-operation','exact-operation']);
});
test('mode changes use only the canonical mode DTO',async()=>{
 const {createLegacyFileSsiController}=await import('../client/src/utils/legacyFileSsiController.mjs');const calls=[];
 const controller=createLegacyFileSsiController({http:{get:async()=>({data:{}}),post:async(...args)=>{calls.push(args);return{data:{success:true,effectiveMode:'fixed'}};}}});
 await controller.setMode({mode:'fixed'});
 assert.deepEqual(calls[0].slice(0,2),['/api/sensitive-info/canonical-agent/mode',{mode:'fixed'}]);
 await assert.rejects(controller.setMode({mode:'other'}),TypeError);
});
