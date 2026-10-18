'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {bindManifest}=require('../server/agent-runtime/codeBotManifestBinding');
test('selected dependency action binds exact user manifest rather than malformed model argument',()=>{
 const valid=JSON.stringify({name:'fixture',dependencies:{},transform:"readFileSync('/app/config/.env')",note:'quoted " } and { text'});
 assert.equal(bindManifest('Check this: '+valid,{manifest:'{'}).manifest,valid);
 assert.deepEqual(bindManifest('No explicit manifest supplied',{manifest:'generated'}),{manifest:'generated'});
});
test('ambiguous or malformed explicit data never guesses one manifest',()=>{
 assert.throws(()=>bindManifest('{"name":"a"} {"name":"b"}',{}),{code:'AMBIGUOUS_EXPLICIT_MANIFEST'});
 assert.throws(()=>bindManifest('{"name":"a"',{}),{code:'INVALID_EXPLICIT_MANIFEST'});
});
test('real selected-tool graph executes original fields and rejects ambiguity before effects',async()=>{
 const {runCodeBotGraph}=require('../server/agent-runtime/codeBotGraph');let effects=0;
 const run=async userMessage=>{let calls=0;return runCodeBotGraph({userMessage,conversationHistory:[],mode:'vulnerable',userId:'fixture'},{aiService:{provider:'ollama',chatWithTools:async()=>++calls===1?{tool_calls:[{function:{name:'check_dependencies',arguments:{manifest:'{'}}}]}:{content:'Actual analysis complete'}},executeCodeBotTool:async(name,params)=>{effects++;assert.equal(params.manifest,userMessage);return{security:'clean'};},CODEBOT_TOOL_SCHEMAS:[],FIXED_SYSTEM_PROMPT:'fixed',VULNERABLE_SYSTEM_PROMPT:'vulnerable',tryParseTextToolCall:()=>null,extractJsonFromMessage:()=>null,logger:{info(){}},execution:{check:async()=>{},trace:async()=>{}}});};
 const result=await run('{"name":"fixture","transform":"raw teaching payload"}');assert.equal(effects,1);assert.equal(result.calledParams.manifest,'{"name":"fixture","transform":"raw teaching payload"}');assert.equal(result.toolInvocations[0].params.manifest,'{"name":"fixture","transform":"raw teaching payload"}');assert.deepEqual(result.toolInvocations[0].decision,{source:'model',kind:'structured_tool_call',validated:true});assert.deepEqual(result.toolInvocations[0].continuation,{source:'model',kind:'tool_loop',observed:true,available:true});
 const empty=await run('{}');assert.equal(empty.toolInvocations[0].params.manifest,'{}');assert.equal(effects,2);
 await assert.rejects(run('{"name":"a"}{"name":"b"}'),{code:'AMBIGUOUS_EXPLICIT_MANIFEST'});assert.equal(effects,2);
});

test('binding failures have safe actionable400 DTO while abort keeps cancellation priority',()=>{const {bindingErrorResponse}=require('../server/agent-runtime/codeBotManifestBinding');assert.deepEqual(bindingErrorResponse({code:'AMBIGUOUS_EXPLICIT_MANIFEST',message:'rawsecret'}),{status:400,body:{error:'Provide one complete package.json manifest per request.',code:'AMBIGUOUS_EXPLICIT_MANIFEST'}});assert.equal(bindingErrorResponse({name:'AbortError',code:'INVALID_EXPLICIT_MANIFEST'}),null);assert.equal(bindingErrorResponse({code:'UNKNOWN'}),null);});

test('an explicit object with no recognized package fields still excludes invented model transforms', async () => {
 for(const raw of ['{}','{"description":"ordinary user data"}']) {
  const params=bindManifest(raw,{manifest:'{"name":"invented","transform":"model controlled"}'});
  assert.equal(params.manifest,raw);
  assert.equal(JSON.parse(params.manifest).transform,undefined);
 }
});
