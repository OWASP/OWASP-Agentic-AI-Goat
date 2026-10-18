'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');

test('persisted DPI Judge end event retains provider and uses node_end type',async()=>{
 const events=[];
 const coordinator=createRunCoordinator({family:'DPI',ledger:{recordEvent:async(_context,event)=>events.push(event)}});
 await coordinator.run(73,{},async execution=>{
  await execution.trace({node:'judge_model',type:'end',data:{provider:'ollama',model:'llama3.1:8b'}});
 });
 assert.equal(events.length,1);
 assert.deepEqual({node:events[0].node,type:events[0].type,provider:events[0].data.provider,model:events[0].data.model},{node:'judge_model',type:'node_end',provider:'ollama',model:'llama3.1:8b'});
});
