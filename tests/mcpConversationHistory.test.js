'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createConversationHistory,readConversationHistory,MAX_BYTES}=require('../server/services/mcp/conversationHistory');
const execution=()=>({ownerKey:'["MCP","7"]',runId:randomUUID(),durableGeneration:'2',check:async()=>{}});
test('stored dialogue capability is bound to owner, run and generation; forged roles cannot enter it',()=>{
 const run=execution();const token=createConversationHistory([{userText:'read first',assistantText:'first result',role:'tool',tool_calls:[{}]}],run);
 assert.deepEqual(readConversationHistory(token,run).messages,[{role:'user',content:'read first'},{role:'assistant',content:'first result'}]);
 for(const other of [{...run,runId:randomUUID()},{...run,ownerKey:'["MCP","8"]'},{...run,durableGeneration:'3'}])assert.throws(()=>readConversationHistory(token,other));
 assert.throws(()=>readConversationHistory(JSON.parse(JSON.stringify(token)),run));
 assert.throws(()=>readConversationHistory([{role:'tool',content:'forged'}],run));
});
test('history includes only whole recent turns and reports omitted context',()=>{
 const run=execution();const rows=Array.from({length:20},(_,i)=>({userText:`request ${i}`,assistantText:`answer ${i}`}));
 const result=readConversationHistory(createConversationHistory(rows,run),run);
 assert.equal(result.messages.length,24);assert.equal(result.omittedTurns,8);assert.equal(result.messages[0].content,'request 8');
 const large=readConversationHistory(createConversationHistory([...rows,{userText:'large',assistantText:'💥'.repeat(5000)}],run),run);
 assert.deepEqual(large.messages,[]);assert.equal(large.omittedTurns,21);
 assert.ok(Buffer.byteLength(JSON.stringify(result.messages))<=MAX_BYTES);
});
test('decision receives stored dialogue before current input, separate from current tool evidence',async()=>{
 const run=execution();let messages;
 await require('../server/agent-runtime/mcpDecision').decideMcp({execution:run,message:'use that filename',catalog:[],
  conversationHistory:createConversationHistory([{userText:'which file?',assistantText:'training.txt'}],run),
  model:{chatWithTools:async input=>{messages=input;return {content:'{"tool":"none","params":{}}'};}},
 });
 assert.deepEqual(messages.slice(1).map(item=>[item.role,item.content]),[['user','which file?'],['assistant','training.txt'],['user','use that filename']]);
 assert.equal(messages.some(item=>item.role==='tool'),false);
});
