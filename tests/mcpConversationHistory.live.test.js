'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {randomUUID}=require('node:crypto');
test('local 8B resolves a follow-up filename from bound prior dialogue',{
 skip:process.env.RUN_LIVE_MCP_HISTORY!=='1',timeout:60000,
},async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-mcp-history-file-'));
 try{
  const filename=`note-${randomUUID()}.txt`,marker=randomUUID();
  await fs.writeFile(path.join(root,filename),marker);
  const execution={ownerKey:'["MCP","7"]',runId:randomUUID(),durableGeneration:'0',check:async()=>{}};
  const conversationHistory=require('../server/services/mcp/conversationHistory').createConversationHistory([
   {userText:'Which training file should I read next?',assistantText:`The training file is ${filename}.`},
  ],execution);
  const provider=require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:11434'});
  const decision=await require('../server/agent-runtime/mcpDecision').decideMcp({message:'Read that training file now.',conversationHistory,execution,
   catalog:[{name:'read_file',description:'Read the file identified by its exact filename.'}],
   model:{chatWithTools:async(messages,tools,options)=>{const result=await provider.chat(messages,tools,options);assert.equal(result.provider,'ollama');return {...result,content:result.response};}},
  });
  assert.equal(decision.tool,'read_file');assert.equal(decision.params.path,filename);
  assert.equal(await fs.readFile(path.join(root,decision.params.path),'utf8'),marker);
 }finally{await fs.rm(root,{recursive:true,force:true});}
});
