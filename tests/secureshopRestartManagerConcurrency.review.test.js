'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{randomUUID}=require('node:crypto');
const {createRestartManager}=require('../sidecars/sandbox-runner/owned-system/restart-manager');
test('concurrent inspections of the same target create one owned child',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-manager-concurrency-'));let created=0;
 const manager=createRestartManager({stateRoot:dir,executeOwnedCommand:async()=>{},targetFactory:({targetId,onState})=>{
  created++;let state={targetId,instanceId:randomUUID(),generation:1,resident:false};
  return {state:()=>({...state}),start:async()=>{state.resident=true;onState(state);return {...state};},hibernate:async()=>{state.resident=false;onState(state);},close:async()=>{state.resident=false;}};
 }});
 t.after(async()=>{await manager.close();fs.rmSync(dir,{recursive:true,force:true});});
 const targetId=randomUUID();const results=await Promise.all([manager.inspect(targetId),manager.inspect(targetId)]);
 assert.equal(created,1,'one persisted target must not create orphaned duplicate children');
 assert.equal(results[0].instanceId,results[1].instanceId);
});
