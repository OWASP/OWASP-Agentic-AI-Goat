'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {randomUUID}=require('node:crypto');
const {runMcpWorkshopGraph}=require('../server/agent-runtime/mcpWorkshopGraph');
const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
test('real 8B uses an observed filename for its next graph action',{
 skip:process.env.RUN_LIVE_MCP_LOOP!=='1',timeout:120000,
},async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-mcp-loop-'));
 try{
  const name=`receipt-${randomUUID()}.txt`,marker=randomUUID();
  await fs.writeFile(path.join(root,'index.txt'),`The requested receipt is in ${name}. Read that file next.`);
  await fs.writeFile(path.join(root,name),`Requested receipt: ${marker}. Task complete.`);
  const transport=createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:11434'});
  const model={provider:'ollama',chatWithTools:async(messages,tools,options)=>{
   const result=await transport.chat(messages,tools,options);
   assert.equal(result.provider,'ollama');
   return {...result,content:result.response};
  }};
  const reads=[];
  const result=await runMcpWorkshopGraph({message:'Read index.txt, then read the receipt file it identifies. Stop when you have the receipt.',
   sandbox:{toolListTools:()=>[{name:'read_file',description:'Read a training file by its exact filename.'}]}},{
   model,execution:{check:async()=>{},trace:async()=>{}},resolveInjectionIntent:async()=>null,
   executeTool:async(tool,params)=>{
    assert.equal(tool,'read_file');assert.ok(['index.txt',name].includes(params.path),
      `Unexpected training filename after ${reads.length} reads: ${JSON.stringify(params.path)}; expected ${JSON.stringify(name)}`);
    reads.push(params.path);return {tool,args:params,output:await fs.readFile(path.join(root,params.path),'utf8')};
   },detectObjectives:()=>[],phraseReply:async(_message,value)=>value.output,
  });
  assert.deepEqual(reads,['index.txt',name]);
  t.diagnostic(JSON.stringify({toolSteps:reads.length,stopReason:result.stopReason,decisionCalls:result.decisionCalls}));
  // Small local models may ask to repeat the last read after finding the
  // receipt. The runtime must stop without executing that duplicate.
  assert.ok(['model_finished','repeated_call'].includes(result.stopReason));
  assert.ok(result.response.includes(marker));
 }finally{await fs.rm(root,{recursive:true,force:true});}
});
