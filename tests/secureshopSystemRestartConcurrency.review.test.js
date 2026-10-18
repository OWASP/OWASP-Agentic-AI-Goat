'use strict';
const controlledRestartModeAuthority={capture:async()=>({snapshot:{mode:'vuln'},assertCurrent:async()=>{}}),assertToken:t=>t};
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createBoundSystemRestartService}=require('../server/services/secureshopBoundSystemRestartService');
test('independent learner targets are not rejected by a global restart-service lock',async()=>{
 let release,entered;const gate=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});let healthCalls=0;
 const service=createBoundSystemRestartService({modeAuthority:controlledRestartModeAuthority,
  resolveTarget:async input=>({targetId:input.scope.targetId}),
  client:{health:async()=>{if(++healthCalls===1){entered();await gate;}},inspect:async()=>({instanceId:randomUUID(),generation:1}),execute:async()=>{throw Error('replayed operation must not dispatch');}},
  repository:{ensureTarget:async()=>{},begin:async input=>({state:'completed',operationId:input.operationId}),assertCurrent:async()=>{},complete:async()=>{},fail:async()=>{},operation:async()=>{}},
 });
 const input=()=>({scope:{targetId:randomUUID()},operationId:randomUUID(),name:'nginx'});
 const first=service.execute(input());await started;
 try{const second=await service.execute(input());assert.equal(second.state,'completed');}
 finally{release();await first;}
});
