'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createMcpConversationService}=require('../server/services/mcp/conversationService');
test('invalid conversation-clear owner is rejected before coordinator mutation',async()=>{
 let calls=0;
 const service=createMcpConversationService({coordinator:{reset:async()=>{calls++;}}});
 await assert.rejects(service.clear('7'),/Valid conversation owner/);
 await assert.rejects(service.clear(0),/Valid conversation owner/);
 assert.equal(calls,0);
});
test('conversation service converts stored rows to current-execution history and commits response',async()=>{
 const execution={ownerKey:'["MCP","7"]',runId:randomUUID(),durableGeneration:'2',check:async()=>{}};
 let saved;
 const service=createMcpConversationService({requests:{admit:async()=>({state:'admitted'}),complete:async value=>{saved=value;}},
  conversations:{list:async()=>[{userText:'old request',assistantText:'old answer'}]}});
 const result=await service.execute({userId:7,requestId:randomUUID(),message:'follow-up',execution},async({history,execution:bound})=>{
  assert.equal(bound,execution);
  assert.equal(require('../server/services/mcp/conversationHistory').readConversationHistory(history,execution).messages[1].content,'old answer');
  return {response:'new answer'};
 });
 assert.deepEqual(saved.response,result);
});
test('completed replay neither loads history nor invokes the actor',async()=>{
 const response={response:'saved answer'};
 const service=createMcpConversationService({requests:{admit:async()=>({state:'replay',response})},conversations:{list:async()=>{throw Error('history read during replay');}}});
 assert.equal(await service.execute({execution:{check:async()=>{}}},async()=>{throw Error('actor repeated');}),response);
});
