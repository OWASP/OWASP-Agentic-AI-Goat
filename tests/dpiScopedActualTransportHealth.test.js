'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const {once}=require('node:events');
const {forwardOllamaVersion,createDpiScopedActualTransport,classifyDpiChatRequest,completeDpiWireResponse}=require('./fixtures/dpiScopedActualTransport');
const {getPromptInjectionProviderStatus}=require('../server/services/promptInjectionStatusService');
const {createMultiProviderAIService}=require('../server/services/multiProviderAIService');

async function listen(handler){const server=http.createServer(handler);server.listen(0,'127.0.0.1');await once(server,'listening');return server;}
async function close(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}

test('bounded live version metadata makes the DPI provider badge accurate without inference',async()=>{
 let versionReads=0,chatReads=0;
 const upstream=await listen((req,res)=>{
  if(req.method==='GET'&&req.url==='/api/version'){versionReads++;res.writeHead(200,{'content-type':'application/json'});res.end('{"version":"0.0-controlled"}');return;}
  if(req.url==='/api/chat')chatReads++;
  res.writeHead(404);res.end();
 });
 const upstreamPort=upstream.address().port;
 const proxy=await listen((req,res)=>{
  if(req.url==='/api/version')return forwardOllamaVersion(req,res,{port:upstreamPort});
  if(req.method==='GET'&&req.url==='/api/tags'){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({models:[{name:'llama3.1:8b'}]}));return;}
  res.writeHead(503);res.end();
 });
 try{
  const service=createMultiProviderAIService({env:{AI_PROVIDER:'ollama',OLLAMA_BASE_URL:`http://127.0.0.1:${proxy.address().port}`,OLLAMA_MODEL:'llama3.1:8b'},logger:{log(){}}});
  const ready=await getPromptInjectionProviderStatus(service);
  assert.equal(ready.available,true);assert.equal(ready.healthy,true);assert.equal(ready.model,'llama3.1:8b');assert.equal(versionReads,1);assert.equal(chatReads,0);
  await close(upstream);
  const unavailable=await getPromptInjectionProviderStatus(service);
  assert.equal(unavailable.available,false);assert.equal(unavailable.healthy,false);assert.equal(chatReads,0);
 }finally{await close(proxy);if(upstream.listening)await close(upstream);}
});

test('zero-call health budget rejects chat before any upstream model request',async()=>{
 const originalFetch=global.fetch;
 global.fetch=async url=>{assert.equal(url,'http://127.0.0.1:11434/api/tags');return{ok:true,json:async()=>({models:[{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}]})};};
 let transport;
 try{
  transport=await createDpiScopedActualTransport({maxHttpCalls:0});
  const response=await originalFetch(transport.actorUrl+'/api/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({model:'llama3.1:8b'})});
  assert.equal(response.status,503);assert.equal(transport.calls.length,0);
 }finally{global.fetch=originalFetch;await transport?.close();}
});

test('closed 70B transport classifies both current Judge stages and requires a real terminal frame',()=>{
 const {createDpiExistentialComparison}=require('../server/agent-runtime/dpiExistentialComparison');
 const c=createDpiExistentialComparison({primary:true,objective:'multi_language',protocolVersion:'dpi-answer-comparison-v13'},[{id:'request',source:'student_input',content:'¿Cuál es la capital de Francia?'},{id:'response',source:'assistant_response',content:'La capital de Francia es París.'}]);
 const model='llama3.3:70b';
 for(const stage of c.stages){if(stage.id==='verify')c.stages[0].validate(JSON.stringify({decision:'supported',sourceRange:{first:'s_0',last:'s_0'},responseRange:{first:'r_0',last:'r_0'}}));const prepared=stage.messages();assert.equal(classifyDpiChatRequest(JSON.stringify({model,...prepared}),model),'judge');if(stage.id==='verify')assert.equal(classifyDpiChatRequest(JSON.stringify({model,...stage.messages('INVALID_EXISTENTIAL_OUTPUT')}),model),'judge');}
 const frame=(content,done)=>JSON.stringify({model,message:{role:'assistant',content},done,...(done?{done_reason:'stop'}:{})})+'\n';
 assert.equal(completeDpiWireResponse(frame('Par',false)+frame('ís',true),model).content,'París');
 assert.throws(()=>completeDpiWireResponse(frame('Par',false),model),/Incomplete/);
 assert.throws(()=>completeDpiWireResponse(frame('Par',true),'llama3.1:8b'),/Mismatched/);
});
