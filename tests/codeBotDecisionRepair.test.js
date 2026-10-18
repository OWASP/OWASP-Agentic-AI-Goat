'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const{approveManifestRepair}=require('../server/agent-runtime/codeBotGraph');
const{runToolLoop}=require('../server/agent-runtime/toolLoopGraph');
test('real manifest dispatch requires validated model selection and bounded repair',async()=>{
 for(const [answers,wanted] of [[['{"action":"none"}'],false],[['bad','{"action":"check_dependencies"}'],true],[['bad','bad'],false]]){
 let calls=0;const events=[];assert.equal(await approveManifestRepair({aiService:{provider:'ollama',chatWithTools:async()=>({content:answers[calls++]})},execution:{check:async()=>{},trace:async e=>events.push(e)},messages:[]}),wanted);assert.equal(calls,answers.length);assert.equal(events.length,calls*2);
 }
});
test('tool graph awaits bounded metadata traces and trace failure prevents model invocation',async()=>{
 let calls=0;const events=[];const options={messages:[],tools:[],model:{chatWithTools:async()=>{calls++;return{content:'secret-answer'};}},executeCall:async()=>{},maxIterations:2,summaryPrompt:'summarize'};
 await runToolLoop({...options,trace:async e=>{await Promise.resolve();events.push(e);}});assert.deepEqual(events.map(e=>e.type),['node_start','node_end']);assert.equal(JSON.stringify(events).includes('secret-answer'),false);
 await assert.rejects(runToolLoop({...options,trace:async()=>{throw Error('trace unavailable');}}),/trace unavailable/);assert.equal(calls,1);
});
test('explicit simulation and fallback provenance remain non-model',async()=>{let nonModel=0;const events=[];assert.equal(await approveManifestRepair({aiService:{provider:'mock'},onNonModel:()=>nonModel++,execution:{trace:async e=>events.push(e)}}),true);assert.equal(nonModel,1);assert.equal(events[0].data.decisionSource,'scripted');assert.equal(await approveManifestRepair({aiService:{chatWithTools:async()=>({content:'{"action":"check_dependencies"}',fallback:true})},messages:[],execution:{trace:async e=>events.push(e)},onNonModel:()=>nonModel++}),false);assert.equal(nonModel,2);assert.equal(events.at(-1).data.decisionSource,'fallback');});

function graphFixture({responses,textCall,manifest}={}){
 const calls=[],effects=[];
 const aiService={provider:'ollama',async chatWithTools(messages,tools,options){calls.push({messages:structuredClone(messages),tools:structuredClone(tools),options});const next=responses.shift();if(next instanceof Error)throw next;return next;}};
 return {calls,effects,run:()=>require('../server/agent-runtime/codeBotGraph').runCodeBotGraph({userMessage:manifest,conversationHistory:[],mode:'vulnerable',userId:'owner-7'},{
  aiService,CODEBOT_TOOL_SCHEMAS:[{type:'function',function:{name:'check_dependencies',parameters:{type:'object'}}}],FIXED_SYSTEM_PROMPT:'fixed',VULNERABLE_SYSTEM_PROMPT:'vulnerable',
  tryParseTextToolCall:()=>textCall||null,extractJsonFromMessage:value=>JSON.parse(value),logger:{info(){}},
  executeCodeBotTool:async(name,params,mode,context)=>{effects.push({name,params:structuredClone(params),mode,context});return{security:'clean',pkg_name:'fixture',dep_count:1,status:'ok'};},
  execution:{check:async()=>{},trace:async()=>{}},
 })};
}

test('raw text tool repair executes exact bound manifest once and rejoins a tool-disabled model continuation',async()=>{
 const manifest='{ "name": "fixture", "dependencies": {} }';
 const f=graphFixture({manifest,textCall:{name:'check_dependencies',params:{manifest:'model-reformatted'}},responses:[
  {content:'{"name":"check_dependencies","parameters":{"manifest":"model-reformatted"}}'},
  {content:'I observed one clean dependency.'},
 ]});
 const result=await f.run();
 assert.equal(f.effects.length,1);assert.equal(f.effects[0].params.manifest,manifest);assert.equal(f.effects[0].context.ownerId,'owner-7');
 assert.equal(f.calls.length,2);assert.deepEqual(f.calls[1].tools,[]);
 const continuation=f.calls[1].messages.slice(-2);assert.equal(continuation[0].tool_calls[0].function.arguments,JSON.stringify({manifest}));assert.equal(continuation[1].tool_call_id,continuation[0].tool_calls[0].id);assert.match(continuation[1].content,/"security":"clean"/);
 assert.equal(result.finalResponse,'I observed one clean dependency.');assert.deepEqual(result.toolInvocations[0].decision,{source:'model',kind:'text_tool_call_repair',validated:true});assert.deepEqual(result.toolInvocations[0].continuation,{source:'model',kind:'text_tool_call_repair',observed:true,available:true});
});

test('manifest authorization repair observes its one execution and reports unavailable continuation without static success',async()=>{
 const manifest='{"name":"fixture","dependencies":{}}';
 const f=graphFixture({manifest,responses:[
  {content:'I need a repaired action.'},
  {content:'{"action":"check_dependencies"}'},
  {content:'scripted fallback',fallback:true},
 ]});
 const result=await f.run();
 assert.equal(f.effects.length,1);assert.equal(f.calls.length,3);assert.deepEqual(f.calls[2].tools,[]);
 assert.equal(result.finalResponse,'CodeBot completed the tool execution, but the model continuation is unavailable.');assert.equal(result.modelIsReal,false);
 assert.deepEqual(result.toolInvocations[0].decision,{source:'model',kind:'manifest_repair_authorization',validated:true});assert.deepEqual(result.toolInvocations[0].continuation,{source:'fallback',kind:'manifest_repair_authorization',observed:true,available:false});
});

test('repaired continuation rejects a repeated transform call even when the model also emits prose',async()=>{
 const manifest='{"name":"fixture","transform":"6*7"}';
 const f=graphFixture({manifest,textCall:{name:'check_dependencies',params:{}},responses:[
  {content:'{"name":"check_dependencies","parameters":{}}'},
  {content:'I already observed the result.',tool_calls:[{function:{name:'check_dependencies',arguments:{manifest}}}]},
 ]});
 const result=await f.run();
 assert.equal(f.effects.length,1);assert.deepEqual(f.calls[1].tools,[]);
 assert.equal(result.finalResponse,'CodeBot completed the tool execution, but the model continuation is unavailable.');
 assert.equal(result.toolInvocations.length,1);assert.equal(result.toolInvocations[0].continuation.available,false);
});

test('one model continuation is linked to every invocation whose observations it receives',async()=>{
 const manifest='{"name":"fixture","dependencies":{}}',calls=[],effects=[];
 const result=await require('../server/agent-runtime/codeBotGraph').runCodeBotGraph({userMessage:manifest,conversationHistory:[],mode:'vulnerable',userId:'owner-7'},{
  aiService:{provider:'ollama',async chatWithTools(messages){calls.push(structuredClone(messages));return calls.length===1?{tool_calls:[
   {id:'dep',function:{name:'check_dependencies',arguments:{manifest:'model'}}},
   {id:'review',function:{name:'review_code',arguments:{code:'const x=1'}}},
  ]}:{content:'I observed both results.'};}},
  executeCodeBotTool:async(name)=>{effects.push(name);return name==='check_dependencies'?{security:'clean',status:'ok',dep_count:0}:{security:'clean'};},
  CODEBOT_TOOL_SCHEMAS:[],FIXED_SYSTEM_PROMPT:'fixed',VULNERABLE_SYSTEM_PROMPT:'vulnerable',tryParseTextToolCall:()=>null,extractJsonFromMessage:()=>null,logger:{info(){}},execution:{check:async()=>{},trace:async()=>{}},
 });
 assert.deepEqual(effects,['check_dependencies','review_code']);assert.equal(calls.length,2);
 assert.equal(result.toolInvocations.length,2);for(const invocation of result.toolInvocations)assert.deepEqual(invocation.continuation,{source:'model',kind:'tool_loop',observed:true,available:true});
});

test('semantically invalid model tool arguments remain an observed error instead of aborting the graph',async()=>{
 const calls=[];
 const result=await require('../server/agent-runtime/codeBotGraph').runCodeBotGraph({userMessage:'List your available tools.',conversationHistory:[],mode:'vulnerable',userId:'owner-7'}, {
  aiService:{provider:'ollama',async chatWithTools(){calls.push(true);return calls.length===1
   ?{tool_calls:[{id:'bad-review',function:{name:'review_code',arguments:null}}]}
   :{content:'I can use review_code, check_dependencies, and explain_error.'};}},
  executeCodeBotTool:require('../server/services/supplyChainWorkshopAgent').executeCodeBotTool,
  CODEBOT_TOOL_SCHEMAS:[],FIXED_SYSTEM_PROMPT:'fixed',VULNERABLE_SYSTEM_PROMPT:'vulnerable',tryParseTextToolCall:()=>null,extractJsonFromMessage:()=>null,logger:{info(){}},execution:{check:async()=>{},trace:async()=>{}},
 });
 assert.equal(calls.length,2);assert.equal(result.toolInvocations.length,1);
 assert.equal(result.toolInvocations[0].name,'review_code');assert.equal(result.toolInvocations[0].result.security,'error');
 assert.match(result.toolInvocations[0].result.error,/code must be a non-empty string/);
 assert.equal(result.finalResponse,'I can use review_code, check_dependencies, and explain_error.');
});
