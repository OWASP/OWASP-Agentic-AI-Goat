'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {buildReplyEvidence,buildReplyPrompt}=require('../server/services/mcp/replyEvidence');
test('local 8B finalizer includes an earlier result and acknowledges a later failure',{
 skip:process.env.RUN_LIVE_MCP_REPLY!=='1',timeout:60000,
},async()=>{
 const marker=randomUUID();
 const {records}=buildReplyEvidence(null,[
  {toolUsed:'read_file',params:{path:'first.txt'},toolResult:{output:`Training reference: ${marker}`}},
  {toolUsed:'read_file',params:{path:'second.txt'},toolResult:{error:'second.txt does not exist'}},
 ]);
 const provider=require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:11434'});
 const response=await provider.chat([{role:'user',content:buildReplyPrompt('Report the training reference and whether the second file was read.',records)}],[],{temperature:0,max_tokens:260});
 assert.equal(response.provider,'ollama');
 assert.ok(response.response.includes(marker),'Earlier observed reference must survive final phrasing');
 assert.match(response.response,/does not exist|doesn.t exist|not found|missing|could not|couldn.t|failed|unable/i);
});
