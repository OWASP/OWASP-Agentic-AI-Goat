'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {validateRequest,requestRole}=require('./fixtures/mcpMountedHttpWirePolicy');
const {transportProfile,budget}=require('./postgres/finflowBackupBrowserActualTransport');
const actor=()=>({model:'llama3.1:8b',stream:true,options:{temperature:0,num_predict:1024},messages:[{role:'user',content:'Synthetic controlled request'}],format:require('../server/agent-runtime/mcpDecision').schema});
const check=(v,url='/api/chat')=>validateRequest('POST',url,Buffer.from(JSON.stringify(v)));
test('mounted MCP admits actual production decision/phrase/Judge option families',()=>{
 const a=actor();assert.equal(check(a),'chat');assert.equal(requestRole('/api/chat',a),'actor');
 const j={...a,options:{temperature:0,num_predict:900,num_ctx:32768},format:{type:'object'}};assert.equal(check(j),'chat');assert.equal(requestRole('/api/chat',j),'judge');
 for(const n of [260,500])assert.equal(check({model:a.model,stream:true,options:{temperature:0.4,num_predict:n},prompt:'Controlled observation'},'/api/generate'),'generate');
});
test('closed option/schema/metadata deviations are denied',()=>{
 for(const change of [v=>v.options.num_predict=2048,v=>v.options.num_ctx=32768,v=>v.format.oneOf[0].properties.tool.const='invented',v=>v.format.oneOf.push(v.format.oneOf[0]),v=>v.options.allowFallback=false]){const v=structuredClone(actor());change(v);assert.throws(()=>check(v));}
 assert.throws(()=>validateRequest('GET','/api/version',Buffer.alloc(0)));assert.throws(()=>validateRequest('POST','/api/pull',Buffer.from('{}')));
});
test('MCP cap is three turns, 30 chats, three phrases and one metadata without changing old profiles',()=>{
 const p=transportProfile('mcp-mounted-http');assert.deepEqual(p.ids,['sensitive-positive','sibling-benign','fixed-denial']);assert.equal(p.external,34);const b=budget(p);b.reserve('tags');assert.throws(()=>b.reserve('tags'));for(let i=0;i<30;i++)b.reserve('chat');assert.throws(()=>b.reserve('chat'));for(let i=0;i<3;i++)b.reserve('generate');assert.equal(b.counts.external,34);assert.throws(()=>b.reserve('version'));
 assert.equal(transportProfile().external,29);assert.equal(transportProfile('traversal').external,127);assert.equal(transportProfile('plain').ids.length,6);
});
test('installed LangChain cold actor and phrase use only admitted endpoints, without metadata',async()=>{
 const original=global.fetch,seen=[];
 global.fetch=async(url,init)=>{const pathname=new URL(url).pathname;seen.push(pathname);validateRequest(init.method,pathname,Buffer.from(init.body));const message=pathname==='/api/chat'?{message:{role:'assistant',content:'{"tool":"none","params":{}}'}}:{response:'Controlled observation'};return new Response(JSON.stringify({model:'llama3.1:8b',...message,done:false})+'\n'+JSON.stringify({model:'llama3.1:8b',...(pathname==='/api/chat'?{message:{role:'assistant',content:''}}:{response:''}),done:true,done_reason:'stop'})+'\n',{headers:{'content-type':'application/x-ndjson'}});};
 try{const p=require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:1'});await p.chat([{role:'user',content:'Controlled no-resource request'}],[],{temperature:0,format:actor().format,timeout:1000});await p.generate('Controlled observation',{temperature:0.4,max_tokens:260,timeout:1000});assert.deepEqual(seen,['/api/chat','/api/generate']);}finally{global.fetch=original;}
});

test('closed supply cohort allows only two bounded turns and 23 external calls, preserving HTTP ceiling',()=>{const p=transportProfile('mcp-mounted-supply-chain');assert.deepEqual(p.ids,['supply-positive','supply-benign']);assert.equal(p.perCaseChat,10);assert.equal(p.perCaseGenerate,1);const b=budget(p);b.reserve('tags');for(let i=0;i<20;i++)b.reserve('chat');for(let i=0;i<2;i++)b.reserve('generate');assert.equal(b.counts.external,23);for(const kind of ['chat','generate','tags','version'])assert.throws(()=>b.reserve(kind));assert.equal(transportProfile('mcp-mounted-http').external,34);});
test('selected70B is exact recon-only and supported context options stay closed',()=>{
 const transport=require('./postgres/finflowBackupBrowserActualTransport');const selected=transport.selectedMcpModel('mcp-mounted-recon',true);assert.equal(selected.model,'llama3.3:70b');assert.equal(selected.digest,'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa');
 for(const cohort of [undefined,'mcp-mounted-http','mcp-mounted-supply-chain','mcp-mounted-poisoning-positive','plain'])assert.throws(()=>transport.selectedMcpModel(cohort,true));assert.throws(()=>transport.selectedMcpModel('mcp-mounted-recon','true'));assert.equal(transport.selectedMcpModel('mcp-mounted-http').model,'llama3.1:8b');
 const a=actor();a.model=selected.model;a.options.num_ctx=8192;const opts={recon:true,recon70b:true};assert.equal(validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(a)),opts),'chat');assert.throws(()=>check(a));assert.throws(()=>validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(a)),{recon70b:true}));a.options.num_ctx=131072;assert.throws(()=>validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(a)),opts));
 const crypto=require('node:crypto'),response=JSON.stringify({models:[{name:selected.model,digest:selected.digest}]});const row={kind:'tags',status:200,responseComplete:true,responseCaptureTruncated:false,response,responseBytes:Buffer.byteLength(response),responseSha256:crypto.createHash('sha256').update(response).digest('hex')};transport.validateResponse(row,{recon70b:true});assert.throws(()=>transport.validateResponse(row));const bad=structuredClone(row);bad.response=JSON.stringify({models:[{name:selected.model,digest:'0'.repeat(64)}]});bad.responseBytes=Buffer.byteLength(bad.response);bad.responseSha256=crypto.createHash('sha256').update(bad.response).digest('hex');assert.throws(()=>transport.validateResponse(bad,{recon70b:true}));assert.equal(transport.caseDeadlineFor(transport.transportProfile('mcp-mounted-recon'),600000,()=>0),120000);
});

test('recon70B timing is explicit, bounded, and never changes legacy profiles',()=>{
 const transport=require('./postgres/finflowBackupBrowserActualTransport'),t=transport.MCP_RECON_TIMING,p=transport.transportProfile('mcp-mounted-recon',true);
 assert.equal(p.overallMs,720000);assert.equal(p.external,11);assert.equal(p.chat,8);assert.equal(p.generate,2);assert.equal(t.wireMs,95000);
 assert.equal(transport.caseDeadlineFor(p,720000,()=>0,'recon-benign'),300000);assert.equal(transport.caseDeadlineFor(p,720000,()=>0,'recon-positive'),300000);assert.equal(transport.caseDeadlineFor(p,720000,()=>0,'recon-named-refusal'),100000);assert.equal(transport.caseDeadlineFor(p,12000,()=>0,'recon-positive'),12000);assert.throws(()=>transport.caseDeadlineFor(p,720000,()=>0,'unknown'));
 assert(t.caseMs>t.runMs&&t.wireMs>t.judgeMs&&t.refusalCaseMs>t.wireMs&&t.totalMs>2*t.runMs+t.judgeMs&&t.childSeconds*1000>t.totalMs&&t.parentSeconds>t.childSeconds);
 assert.equal(transport.transportProfile('mcp-mounted-recon').overallMs,600000);assert.equal(transport.caseDeadlineFor(transport.transportProfile('mcp-mounted-recon'),600000,()=>0),120000);assert.throws(()=>transport.transportProfile('mcp-mounted-http',true));
});

test('120s recon transport has exact enclosing budgets with unchanged call caps',()=>{
 const transport=require('./postgres/finflowBackupBrowserActualTransport'),t=transport.reconTiming(true),p=transport.transportProfile('mcp-mounted-recon',true,true);
 assert.equal(t.judgeMs,120000);assert.equal(t.wireMs,125000);assert.equal(t.refusalCaseMs,130000);assert.equal(p.overallMs,750000);assert.equal(t.childSeconds,870);assert.equal(t.parentSeconds,990);assert.equal(t.cleanupSeconds,120);
 assert.equal(transport.caseDeadlineFor(p,750000,()=>0,'recon-positive'),300000);assert.equal(transport.caseDeadlineFor(p,750000,()=>0,'recon-named-refusal'),130000);assert.equal(transport.caseDeadlineFor(p,1000,()=>0,'recon-named-refusal'),1000);
 assert.equal(p.chat,8);assert.equal(p.generate,2);assert.equal(p.external,11);assert(t.judgeMs<t.wireMs&&t.wireMs<t.refusalCaseMs);assert.equal(t.totalMs-2*t.runMs-t.judgeMs,50000);assert.equal(t.childSeconds-t.totalMs/1000,120);assert.equal(t.parentSeconds-t.childSeconds,120);
 assert.equal(transport.transportProfile('mcp-mounted-recon',true).overallMs,720000);assert.throws(()=>transport.transportProfile('mcp-mounted-http',true,true));assert.throws(()=>transport.transportProfile('mcp-mounted-recon',false,true));assert.throws(()=>transport.reconTiming('1'));
});
