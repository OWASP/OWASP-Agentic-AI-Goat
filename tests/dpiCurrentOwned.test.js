'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const C=require('./fixtures/dpiCurrentOwnedContractV2');
test('request-only cohort preserves all eight retained candidate requests and mounted negatives',()=>{
 const retained=require('./fixtures/dpiJudgeCases');const rows=C.cases();assert.equal(rows.length,17);
 for(const objective of C.IDS){const selected=rows.filter(x=>x.objective===objective),candidate=selected[0],negative=selected.at(-1);if(objective!=='interact')assert.equal(candidate.message,retained.find(x=>x.name===objective+':observed').request);else assert.deepEqual(selected.slice(0,2).map(x=>x.message),['Explain what Amazon S3 stores and one practical use case in two sentences.','Explain how AWS IAM roles help applications access S3 securely in two sentences.']);assert.deepEqual(Object.keys(candidate),['id','objective','kind','message']);assert.equal(negative.message,objective==='interact'?'Write a poem about a red balloon. Do not discuss cloud computing.':'What is the capital of France?');}
});
test('closed budgets admit full production maximum once and reject excess/cross-case admission',()=>{
 const b=C.createBudget();b.reserve('tags');assert.throws(()=>b.reserve('actor'));
 for(const c of C.cases()){b.begin(c.id);const l=C.limits(c.objective);for(let i=0;i<l.actor*3;i++)b.reserve('tags');for(let i=0;i<l.actor;i++)b.reserve('actor');for(let i=0;i<l.judge;i++)b.reserve('judge');assert.throws(()=>b.reserve('actor'));assert.throws(()=>b.reserve('judge'));b.end();assert.throws(()=>b.reserve('judge'));}
 assert.deepEqual(b.counts,{external:119,actor:19,judge:42,tags:58});assert.throws(()=>b.begin(C.cases()[0].id));
});
test('explicit retained four selector admits exactly nine fixed requests within smaller physical cap',()=>{
 const previous=process.env.DPI_CURRENT_SELECTOR;process.env.DPI_CURRENT_SELECTOR=C.RETAINED_FOUR;
 try{
  const rows=C.cases();assert.deepEqual(rows.map(x=>x.id),['multi_language:candidate','multi_language:negative','virtualization:candidate','virtualization:negative','side_stepping:candidate','side_stepping:negative','obfuscation:candidate','obfuscation:negative','obfuscation:fixed']);
  assert.equal(rows.at(-1).mode,'fixed');assert.equal(rows.at(-1).message,rows.at(-3).message);assert.equal(Buffer.from(rows.at(-2).message,'base64').toString(),'Explain what Amazon S3 stores.');
  assert.deepEqual(C.TOTAL,C.RETAINED_TOTAL);const budget=C.createBudget();budget.reserve('tags');
  for(const row of rows){budget.begin(row.id);const cap=C.limits(row.objective);for(let i=0;i<(cap.actor+(row.mode==='fixed'?2:0))*3;i++)budget.reserve('tags');for(let i=0;i<cap.actor;i++)budget.reserve('actor');for(let i=0;i<(row.mode==='fixed'?0:cap.judge);i++)budget.reserve('judge');if(row.mode==='fixed'){assert.throws(()=>budget.reserve('judge'));for(let i=0;i<2;i++)budget.reserve('review');}budget.end();}
  assert.deepEqual(budget.counts,{external:81,actor:12,judge:24,review:2,tags:43});assert.throws(()=>budget.begin(rows[0].id));
 }finally{if(previous===undefined)delete process.env.DPI_CURRENT_SELECTOR;else process.env.DPI_CURRENT_SELECTOR=previous;}
 assert.equal(C.cases().length,17);assert.deepEqual(C.TOTAL.turns,17);
});
test('fixed-only selector admits one publication review with a separate physical cap',()=>{
 const previous=process.env.DPI_CURRENT_SELECTOR;process.env.DPI_CURRENT_SELECTOR=C.RETAINED_FIXED;
 try{
  assert.deepEqual(C.cases().map(row=>row.id),['obfuscation:fixed']);assert.deepEqual(C.TOTAL,C.FIXED_TOTAL);
  const row=C.cases()[0],defense=require('../server/agent-runtime/dpiPublicationDefense'),decoded=require('../server/services/dpiDecodedRequest').decodeDpiRequest(row.message).decodedRequest;
  const request={model:C.MODEL,stream:true,messages:defense.messages(row.message,decoded,'The capital of France is Paris.'),format:defense.FORMAT,options:{temperature:0,num_predict:128,num_ctx:8192}};
  assert.equal(C.validateRequest('actor','POST','/api/chat',Buffer.from(JSON.stringify(request)),row),'review');
  for(const bad of [{...request,options:{...request.options,num_predict:1024}},{...request,messages:defense.messages('foreign',decoded,'The capital of France is Paris.')},{...request,format:{type:'object'}}])assert.throws(()=>C.validateRequest('actor','POST','/api/chat',Buffer.from(JSON.stringify(bad)),row));
  const budget=C.createBudget();budget.reserve('tags');budget.begin(row.id);for(let i=0;i<12;i++)budget.reserve('tags');budget.reserve('actor');budget.reserve('actor');budget.reserve('review');budget.reserve('review');assert.deepEqual(budget.counts,{external:17,actor:2,judge:0,review:2,tags:13});assert.throws(()=>budget.reserve('review'));assert.throws(()=>budget.reserve('judge'));budget.end();
 }finally{if(previous===undefined)delete process.env.DPI_CURRENT_SELECTOR;else process.env.DPI_CURRENT_SELECTOR=previous;}
});
test('closed five-case retry retains exact request bytes and physical caps',()=>{
 const previous=process.env.DPI_CURRENT_SELECTOR;process.env.DPI_CURRENT_SELECTOR=C.RETAINED_RETRY;
 try{
  const rows=C.cases();assert.deepEqual(rows.map(row=>row.id),['virtualization:candidate','side_stepping:candidate','side_stepping:negative','obfuscation:candidate','obfuscation:fixed']);
  assert.deepEqual(C.TOTAL,C.RETRY_TOTAL);assert.equal(C.sha(JSON.stringify(rows)),'94d2fd5eed24f83c2210dcd04457261db64aa74030ac7c65b6e360fb4f24a936');
  const budget=C.createBudget();budget.reserve('tags');for(const row of rows){budget.begin(row.id);const cap=C.limits(row.objective);for(let i=0;i<(cap.actor+(row.mode==='fixed'?2:0))*3;i++)budget.reserve('tags');for(let i=0;i<cap.actor;i++)budget.reserve('actor');for(let i=0;i<(row.mode==='fixed'?0:cap.judge);i++)budget.reserve('judge');if(row.mode==='fixed'){assert.throws(()=>budget.reserve('judge'));for(let i=0;i<2;i++)budget.reserve('review');}budget.end();}
  assert.deepEqual(budget.counts,{external:49,actor:7,judge:12,review:2,tags:28});assert.throws(()=>budget.begin(rows[0].id));
 }finally{if(previous===undefined)delete process.env.DPI_CURRENT_SELECTOR;else process.env.DPI_CURRENT_SELECTOR=previous;}
});
test('mode UX selector admits two fixed practice turns and one vulnerable system-prompt turn',()=>{
 const previous=process.env.DPI_CURRENT_SELECTOR;process.env.DPI_CURRENT_SELECTOR=C.UX_MODE;
 try{
  const rows=C.cases();assert.deepEqual(rows.map(row=>row.id),['interact:fixed1','interact:fixed2','system_prompt:candidate']);
  assert.deepEqual(rows.map(row=>row.mode||'vuln'),['fixed','fixed','vuln']);
  assert.equal(C.sha(JSON.stringify(rows)),'a44412622aa2296f510517f5f8e7fce8de9a1712ed34332a0aaa14b20c1d9b36');
  assert.deepEqual(C.TOTAL,C.UX_TOTAL);const budget=C.createBudget();budget.reserve('tags');
  for(const row of rows){budget.begin(row.id);const cap=C.limits(row.objective);
   for(let i=0;i<(cap.actor+(row.mode==='fixed'?2:0))*3;i++)budget.reserve('tags');
   for(let i=0;i<cap.actor;i++)budget.reserve('actor');for(let i=0;i<cap.judge;i++)budget.reserve('judge');
   assert.throws(()=>budget.reserve('review'));budget.end();}
  assert.deepEqual(budget.counts,{external:31,actor:3,judge:6,review:0,tags:22});
 }finally{if(previous===undefined)delete process.env.DPI_CURRENT_SELECTOR;else process.env.DPI_CURRENT_SELECTOR=previous;}
});
test('actual SDK actor and Judge bodies satisfy exact transport contract without a socket',async()=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');const original=global.fetch;let role,calls=0;
 global.fetch=async(url,options)=>{calls++;assert.equal(new URL(url).pathname,'/api/chat');C.validateRequest(role,options.method,new URL(url).pathname,Buffer.from(options.body));return new Response(JSON.stringify({model:C.MODEL,message:{role:'assistant',content:'{}'},done:true,done_reason:'stop'})+'\n');};
 try{const provider=createLangChainProvider({provider:'ollama',model:C.MODEL,baseURL:'http://127.0.0.1:1'});role='actor';await provider.chat([{role:'user',content:'controlled'}],[],{temperature:0.6,max_tokens:1024,timeout:1000});role='judge';await provider.chat([{role:'user',content:'controlled'}],[],{temperature:0,num_ctx:32768,max_tokens:900,format:{type:'object'},timeout:1000});assert.equal(calls,2);}finally{global.fetch=original;}
});
test('response validation distinguishes physically complete output limit from truncation',()=>{
 for(const reason of ['stop','length']){const response=JSON.stringify({model:C.MODEL,message:{content:'{}'},done:true,done_reason:reason})+'\n';const row={status:200,responseComplete:true,responseCaptureTruncated:false,response,responseSha256:C.sha(response)};assert.equal(C.responseText(row).doneReason,reason);assert.throws(()=>C.responseText({...row,responseComplete:false}));assert.throws(()=>C.responseText({...row,responseSha256:'0'.repeat(64)}));}
});
test('entry imports remain inert and reject installed, foreign or option-bearing database URLs',()=>{
 const {urls}=require('./postgres/dpiCurrentOwnedMain');require('./postgres/dpiCurrentOwnedActualTransport');require('./fixtures/dpiCurrentOwnedQualification');
 const nonce='a'.repeat(12),env={IDENTITY_DATABASE_URL:`postgresql://dvaia_identity_runtime@127.0.0.1:54321/dvaia_test_dpi_current_${nonce}_identity`,IDENTITY_MIGRATION_DATABASE_URL:`postgresql://dvaia_identity_migration@127.0.0.1:54321/dvaia_test_dpi_current_${nonce}_identity`};urls(env,54321,nonce);
 for(const bad of [env.IDENTITY_DATABASE_URL+'?sslmode=disable',env.IDENTITY_DATABASE_URL.replace('127.0.0.1','localhost'),env.IDENTITY_DATABASE_URL.replace(nonce,'b'.repeat(12)),env.IDENTITY_MIGRATION_DATABASE_URL])assert.throws(()=>urls({...env,IDENTITY_DATABASE_URL:bad},54321,nonce));assert.throws(()=>urls({...env,CTF_DATABASE_URL:env.IDENTITY_DATABASE_URL},54321,nonce));
});
test('actual SDK decoder tool transcript matches independent exact wire projection',async()=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');const {wireMessages}=require('./fixtures/dpiCurrentOwnedWireBinding');
 const messages=[{role:'system',content:'owned synthetic task'},{role:'user',content:'controlled input'},{role:'assistant',content:'{"action":"decode_payload"}',tool_calls:[{id:'controlled-call',type:'function',function:{name:'decode_payload',arguments:'{}'}}]},{role:'tool',tool_call_id:'controlled-call',name:'decode_payload',content:'owned observation'}];
 const original=global.fetch;let calls=0;global.fetch=async(url,options)=>{calls++;const body=JSON.parse(options.body);assert.deepEqual(body.messages,wireMessages(messages));C.validateRequest('actor','POST','/api/chat',Buffer.from(options.body));return new Response(JSON.stringify({model:C.MODEL,message:{role:'assistant',content:'answer'},done:true,done_reason:'stop'})+'\n');};
 try{await createLangChainProvider({provider:'ollama',model:C.MODEL,baseURL:'http://127.0.0.1:1'}).chat(messages,[],{temperature:0.2,max_tokens:1024,timeout:1000});assert.equal(calls,1);}finally{global.fetch=original;}
});
test('post-checkpoint deadline admission denies expired dispatch',()=>{const {assertDeadline}=require('./postgres/dpiCurrentOwnedActualTransport');assertDeadline(10,9);assert.throws(()=>assertDeadline(10,10));assert.throws(()=>assertDeadline(10,11));});
test('Judge binding rejects foreign packet, request/schema and response while retaining length separately',()=>{
 const {bindTranscript}=require('./fixtures/dpiCurrentOwnedWireBinding');const packet={rubric:{version:'controlled'},facts:{observed:true},evidence:[]};
 const request={messages:[{role:'user',content:'controlled'}],format:{type:'object'},options:{temperature:0,num_ctx:32768,num_predict:900}},response=JSON.stringify({model:C.MODEL,message:{content:'{}'},done:true,done_reason:'stop'})+'\n';
 const row={kind:'judge',terminal:'returned',status:200,responseComplete:true,responseCaptureTruncated:false,response,responseSha256:C.sha(response),request:JSON.stringify(request)};row.requestSha256=C.sha(row.request);
 const transcript={complete:true,header:{packet:JSON.stringify(packet)},calls:[{request:{method:'chat',input:request.messages,schema:request.format,options:{temperature:0,num_ctx:32768,max_tokens:900}},response:'{}',responseSha256:C.sha('{}'),metadata:{provider:'ollama',model:C.MODEL}}]};
 assert.equal(bindTranscript(transcript,[row],{packet}).judgeCalls,1);
 for(const mutate of [t=>t.header.packet='{}',t=>t.calls[0].request.input[0].content='foreign',t=>t.calls[0].request.schema.type='string',t=>t.calls[0].response='forged',t=>t.calls[0].metadata.fallback=true]){const t=structuredClone(transcript);mutate(t);assert.throws(()=>bindTranscript(t,[row],{packet}));}
 const length=structuredClone(row);length.response=length.response.replace('stop','length');length.responseSha256=C.sha(length.response);assert.equal(bindTranscript(transcript,[length],{packet}).judgeCalls,1);assert.equal(C.responseText(length).doneReason,'length');
});
test('physical retirement waits for request, socket, server and handler settlement',async()=>{
 const {retire}=require('./postgres/dpiCurrentOwnedActualTransport'),{EventEmitter}=require('node:events');const upstreams=new Set(),sockets=new Set(),handlers=new Set();let release;
 for(const set of [upstreams,sockets]){const resource=new EventEmitter();set.add(resource);resource.destroy=()=>queueMicrotask(()=>{set.delete(resource);resource.emit('close');});}
 const pending=new Promise(resolve=>release=resolve);handlers.add(pending);pending.then(()=>handlers.delete(pending));let serverClosed=false,settled=false;
 const done=retire({upstreams,sockets,handlers,servers:[{close(callback){serverClosed=true;queueMicrotask(callback);}}]},1000).then(()=>settled=true);
 await new Promise(resolve=>setImmediate(resolve));assert(serverClosed);assert.equal(settled,false);release();await done;assert.equal(settled,true);
});
test('physical retirement timeout retains unresolved ownership rather than reporting a drain',async()=>{
 const {retire}=require('./postgres/dpiCurrentOwnedActualTransport'),{EventEmitter}=require('node:events');const resource=new EventEmitter();resource.destroy=()=>{};const upstreams=new Set([resource]);
 await assert.rejects(retire({upstreams,sockets:new Set(),handlers:new Set(),servers:[]},10),/physical cleanup timeout/);assert.equal(upstreams.size,1);
});
test('every current proof-required objective rejects missing, null or duplicate owned evidence before wire acceptance',()=>{
 const {bindActor}=require('./fixtures/dpiCurrentOwnedWireBinding');
 for(const objective of ['virtualization','jailbreak','role_playing','side_stepping','obfuscation']){const id=objective==='obfuscation'?'owned_decoder':'owned_actor';for(const evidence of [[],[{id,content:null}],[{id,content:{}},{id,content:{}}]])assert.throws(()=>bindActor({objective},[],{evidence},[]),/owned evidence/);}
});
test('loaded main source must be pinned to current bytes',()=>{
 const {assertLoaded}=require('./postgres/dpiCurrentOwnedMain'),fs=require('node:fs'),path=require('node:path');const file=require.resolve('./fixtures/dpiCurrentOwnedContractV2'),relative=path.relative(path.resolve(__dirname,'..'),file),cache={[file]:{}};
 assertLoaded({sourcePins:{[relative]:C.sha(fs.readFileSync(file))}},cache);assert.throws(()=>assertLoaded({sourcePins:{}},cache));assert.throws(()=>assertLoaded({sourcePins:{[relative]:'0'.repeat(64)}},cache));
});
function transportHarness({hang=false,oldBytes=0}={}){
 const vm=require('node:vm'),fs=require('node:fs'),{EventEmitter}=require('node:events'),{createRequire}=require('node:module');const file=require.resolve('./postgres/dpiCurrentOwnedActualTransport'),local=createRequire(file);const servers=[],requests=[],saved=[];
 const http={request(options,callback){const up=new EventEmitter();up.destroy=()=>{if(up.closed)return;up.closed=true;queueMicrotask(()=>up.emit('close'));};up.end=body=>{requests.push({options,body});if(hang&&options.path==='/api/chat')return;queueMicrotask(()=>{const response=new EventEmitter();response.statusCode=200;response.headers={'content-type':'application/json'};callback(response);const text=options.path==='/api/tags'?JSON.stringify({models:[{name:C.MODEL,digest:C.DIGEST}]}):JSON.stringify({model:C.MODEL,message:{content:'{}'},done:true,done_reason:'stop'})+'\n';response.emit('data',Buffer.from(text));response.emit('end');up.destroy();});};return up;},createServer(handler){const s=new EventEmitter();s.handler=handler;s.listen=(_p,_h,callback)=>{servers.push(s);queueMicrotask(callback);};s.address=()=>({port:40000+servers.indexOf(s)});s.close=callback=>queueMicrotask(callback);return s;}};
 const fakeFs={realpathSync:x=>x,lstatSync:()=>({isDirectory:()=>true,uid:process.getuid(),mode:0o40700}),existsSync:()=>oldBytes>0,statSync:()=>({size:oldBytes})};
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,Buffer,process,structuredClone,setTimeout:(f,ms)=>setTimeout(f,Math.min(ms,30)),clearTimeout,require:name=>name==='node:http'?http:name==='node:fs'?fakeFs:name==='../fixtures/boundedJsonArtifact'?{saveBounded:(_file,value)=>saved.push(structuredClone(value))}:local(name)},{filename:file});
 async function request(method,url,body,role=0,abort=false){const req=new EventEmitter();req.method=method;req.url=url;req.destroy=()=>req.emit('close');req[Symbol.asyncIterator]=async function*(){if(body)yield Buffer.from(JSON.stringify(body));};const res=new EventEmitter();res.headersSent=false;res.writableFinished=false;res.writeHead=status=>{res.status=status;res.headersSent=true;};res.write=()=>{};let finish;const done=new Promise(r=>finish=r);res.end=()=>{res.writableFinished=true;res.emit('close');finish();};res.destroy=()=>{res.emit('close');finish();};servers[role].handler(req,res);if(abort)setImmediate(()=>res.destroy());await done;await new Promise(r=>setImmediate(r));return res;}
 return {api:module.exports,requests,saved,request};
}
const actorBody=()=>({model:C.MODEL,stream:true,messages:[{role:'user',content:'controlled'}],options:{temperature:0.6,num_predict:1024,num_ctx:8192}});
test('review dispatch is fixed-only; a denied attempt remains in wire failure evidence',async()=>{
 const previous=process.env.DPI_CURRENT_SELECTOR;process.env.DPI_CURRENT_SELECTOR=C.RETAINED_RETRY;
 try{
  const h=transportHarness(),t=await h.api.createTransport({evidence:'/owned-evidence'});await new Promise(r=>setImmediate(r));t.beginCase('virtualization:candidate');
  const defense=require('../server/agent-runtime/dpiPublicationDefense'),body={model:C.MODEL,stream:true,messages:defense.messages('foreign',null,'{}'),format:defense.FORMAT,options:{temperature:0,num_predict:128,num_ctx:8192}};
  assert.equal((await h.request('POST','/api/chat',body)).status,503);assert.equal(h.requests.length,1);assert.deepEqual(t.snapshot().failures,[{index:null,code:'REQUEST_DENIED_OR_INCOMPLETE'}]);await t.close();assert.throws(()=>t.assertComplete());
 }finally{if(previous===undefined)delete process.env.DPI_CURRENT_SELECTOR;else process.env.DPI_CURRENT_SELECTOR=previous;}
});
test('fixed publication review binds to completed actor bytes and records foreign draft denial',async()=>{
 const previous=process.env.DPI_CURRENT_SELECTOR;process.env.DPI_CURRENT_SELECTOR=C.RETAINED_FIXED;
 try{
  const h=transportHarness(),t=await h.api.createTransport({evidence:'/owned-evidence'});await new Promise(r=>setImmediate(r));const row=C.cases()[0];t.beginCase(row.id);
  assert.equal((await h.request('POST','/api/chat',actorBody())).status,200);
  const defense=require('../server/agent-runtime/dpiPublicationDefense'),decoded=require('../server/services/dpiDecodedRequest').decodeDpiRequest(row.message).decodedRequest;
  const review=draft=>({model:C.MODEL,stream:true,messages:defense.messages(row.message,decoded,draft),format:defense.FORMAT,options:{temperature:0,num_predict:128,num_ctx:8192}});
  assert.equal((await h.request('POST','/api/chat',review('{}'))).status,200);assert.equal(t.snapshot().calls.at(-1).kind,'review');
  assert.equal((await h.request('POST','/api/chat',review('foreign'))).status,503);assert.equal(h.requests.length,3);assert.deepEqual(t.snapshot().failures,[{index:null,code:'REQUEST_DENIED_OR_INCOMPLETE'}]);await t.close();assert.throws(()=>t.assertComplete());
 }finally{if(previous===undefined)delete process.env.DPI_CURRENT_SELECTOR;else process.env.DPI_CURRENT_SELECTOR=previous;}
});
test('injected HTTP retains raw return then rejects unrelated endpoint and poisons later dispatch',async()=>{
 const h=transportHarness(),t=await h.api.createTransport({evidence:'/owned-evidence'});await new Promise(r=>setImmediate(r));t.beginCase(C.cases()[0].id);
 assert.equal((await h.request('POST','/api/chat',actorBody())).status,200);assert.equal(h.requests.length,2);assert.equal(t.snapshot().calls[1].terminal,'returned');
 assert.equal((await h.request('GET','/api/version')).status,503);assert.equal((await h.request('POST','/api/chat',actorBody())).status,503);assert.equal(h.requests.length,2);await t.close();assert.equal(t.snapshot().physicalPending,0);assert.equal(t.snapshot().closed,true);assert.throws(()=>t.beginCase(C.cases()[1].id));
});
test('injected upstream timeout drains locally and poisons without retry',async()=>{
 const h=transportHarness({hang:true}),t=await h.api.createTransport({evidence:'/owned-evidence'});await new Promise(r=>setImmediate(r));t.beginCase(C.cases()[0].id);await h.request('POST','/api/chat',actorBody());await t.close();const s=t.snapshot();assert.equal(h.requests.length,2);assert.equal(s.calls[1].terminal,'incomplete');assert.equal(s.closed,true);assert.equal(s.physicalPending,0);assert(s.failures.length);assert.throws(()=>t.assertComplete());
});
test('aggregate previous plus temporary artifact cap rejects before upstream dispatch',async()=>{const h=transportHarness({oldBytes:128*1024*1024});await assert.rejects(h.api.createTransport({evidence:'/owned-evidence'}));assert.equal(h.requests.length,0);});
test('injected consumer abort retires its upstream and prevents reuse',async()=>{const h=transportHarness({hang:true}),t=await h.api.createTransport({evidence:'/owned-evidence'});await new Promise(r=>setImmediate(r));t.beginCase(C.cases()[0].id);await h.request('POST','/api/chat',actorBody(),0,true);await t.close();assert.equal(h.requests.length,2);assert.equal(t.snapshot().calls[1].terminal,'incomplete');assert.equal(t.snapshot().physicalPending,0);assert.equal(t.snapshot().closed,true);assert.throws(()=>t.assertComplete());});
test('actual proof flag requires bound actor and Judge calls, independently of technical or semantic outcome',()=>{const {hasActualModelProof}=require('./postgres/dpiCurrentOwnedMain');const turn={status:200,actualActorCalls:1,actualJudgeCalls:2,actorBinding:{actorCalls:1},judgeBinding:{judgeCalls:2,transcriptSha256:'a'.repeat(64)},qualified:false};assert(hasActualModelProof({turns:[turn]}));for(const patch of [{status:503},{actualJudgeCalls:0},{actorBinding:null},{judgeBinding:{judgeCalls:1,transcriptSha256:'a'.repeat(64)}}])assert.equal(hasActualModelProof({technicalPassed:true,turns:[{...turn,...patch}]}),false);assert.equal(hasActualModelProof({turns:[]}),false);});
test('terminal receipt omits oversized raw wire without modifying standalone evidence and enforces parent cap',()=>{
 const {compactWire,assertReceiptBound}=require('./postgres/dpiCurrentOwnedMain');const raw={version:'dpi-current-owned-wire-v1',model:C.MODEL,digest:C.DIGEST,counts:{external:1,actor:1,judge:0,tags:0},physicalPending:0,handlersPending:0,closed:true,failures:[],calls:[{request:'controlled',response:'x'.repeat(2*1024*1024)}]};const before=C.sha(JSON.stringify(raw)),receipt={status:'passed',wireSummary:compactWire(raw)};assertReceiptBound(receipt);assert(!JSON.stringify(receipt).includes('response'));assert(!Object.hasOwn(receipt.wireSummary,'calls'));assert.equal(C.sha(JSON.stringify(raw)),before);assert.throws(()=>assertReceiptBound({wire:raw}),/parent byte limit/);assert.equal(compactWire(null),null);
});

test('current policy binding joins all eight captured actor transcripts and denies policy/message grafts',async()=>{
 const {randomUUID}=require('node:crypto'),{bindActor,wireMessages}=require('./fixtures/dpiCurrentOwnedWireBinding');
 const policy=require('../server/agent-runtime/dpiPolicyContract'),actor=require('../server/agent-runtime/dpiActorProof'),decoder=require('../server/agent-runtime/dpiDecoderEvidence'),graph=require('../server/agent-runtime/dpiObfuscationGraph'),binding=require('../server/agent-runtime/dpiPolicyBinding');
 const rowsFor=capture=>capture.actor.map(call=>{const request=JSON.stringify({messages:wireMessages(call.messages)}),response=JSON.stringify({model:C.MODEL,message:{content:call.result.response},done:true,done_reason:'stop'})+'\n';return {kind:'actor',terminal:'returned',request,requestSha256:C.sha(request),response,responseSha256:C.sha(response),status:200,responseComplete:true,responseCaptureTruncated:false};});
 for(const {objective,mode} of [...policy.TEXT_OBJECTIVES,'obfuscation'].map(objective=>({objective,mode:'vuln'})).concat({objective:'interact',mode:'fixed'})){
  const capture={objective,...(mode==='fixed'?{mode}:{}),ownerId:'7',generation:'2',runId:randomUUID(),message:objective==='obfuscation'?'Decode '+Buffer.from('What is two plus two?').toString('base64'):'Explain AWS S3.',actor:[],body:{}},effects=[];
  const execution={runId:capture.runId,ownerKey:JSON.stringify(['DPI','7']),durableGeneration:'2',async check(){},async effectWithReceipt(key,fn){const effectKey=this.runId+':'+key;effects.push({effect_key:effectKey,owner_key:this.ownerKey,run_id:this.runId,generation:2,status:'completed'});return {value:await fn(),receipt:{version:1,ownerKey:this.ownerKey,generation:'2',runId:this.runId,effectKey,status:'completed'}};}},attempt={runId:capture.runId,mode,objectiveId:objective};let proof;
  if(objective==='obfuscation'){
   const result=await graph.runDpiObfuscationGraph({request:capture.message,execution,attempt,aiService:{async chatWithMessages(messages){const result={response:capture.actor.length?'Four.':'{"action":"decode_payload"}',provider:'ollama',model:C.MODEL};capture.actor.push({messages:structuredClone(messages),result});return result;}}});capture.body.response=result.response;proof=graph.captureDecoderProof(result.proof,{request:capture.message,response:result.response,execution,attempt});
  }else{
   const messages=[{role:'system',content:policy.textSystemPrompt(objective,mode)},{role:'user',content:capture.message}],result={response:'AWS object storage.',provider:'ollama',model:C.MODEL};capture.actor.push({messages,result});capture.body.response=result.response;const raw=actor.createActorProof({request:capture.message,response:result.response,result,execution,attempt,objective,messages});proof=actor.captureActorProof(raw,{request:capture.message,response:result.response,execution,attempt});
  }
  const id=objective==='obfuscation'?'owned_decoder':'owned_actor',legacy=objective==='obfuscation'?decoder.projectLegacyDecoderEvidence(proof):actor.projectLegacyActorEvidence(proof);
  const packet={rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:objective,mode,dpiPolicyBinding:binding.VERSION},facts:{},evidence:[{id:'request',source:'student_input',content:capture.message},{id:'response',source:'assistant_response',content:capture.body.response},{id:'owned_policy',source:'server_observation',content:binding.createPolicyBinding(proof)},{id,source:'server_observation',content:legacy}]};
  const rows=rowsFor(capture);assert.equal(bindActor(capture,rows,packet,effects,{requirePolicyBinding:true}).actorCalls,capture.actor.length);
  const noPolicy=structuredClone(packet);delete noPolicy.rubric.dpiPolicyBinding;noPolicy.evidence=noPolicy.evidence.filter(x=>x.id!=='owned_policy');assert.doesNotThrow(()=>bindActor(capture,rows,noPolicy,effects));assert.throws(()=>bindActor(capture,rows,noPolicy,effects,{requirePolicyBinding:true}));
  for(const [key,value] of [['ownerKey','foreign-owner'],['runId',randomUUID()],['generation','99']]){const graft=structuredClone(packet);const reconstructed=require('../server/agent-runtime/dpiPolicyBinding').admitPolicyBinding(graft).proof;reconstructed[key]=value;graft.evidence.find(x=>x.id==='owned_policy').content=require('../server/agent-runtime/dpiPolicyBinding').createPolicyBinding(reconstructed);graft.evidence.find(x=>x.id===id).content[key]=value;assert.throws(()=>bindActor(capture,rows,graft,effects,{requirePolicyBinding:true}));}
  const wrongDigest=structuredClone(packet);wrongDigest.evidence.find(x=>x.id==='owned_policy').content.extension[objective==='obfuscation'?'decisionMessagesSha256':'messagesSha256']='0'.repeat(64);assert.throws(()=>bindActor(capture,rows,wrongDigest,effects,{requirePolicyBinding:true}));
  const changed=structuredClone(capture);changed.actor[0].messages[0].content+=' changed';assert.throws(()=>bindActor(changed,rowsFor(changed),packet,effects,{requirePolicyBinding:true}));
  const bad=structuredClone(packet);bad.evidence.find(x=>x.id==='owned_policy').content.policy.systemPolicySha256='0'.repeat(64);assert.throws(()=>bindActor(capture,rows,bad,effects,{requirePolicyBinding:true}));
  if(mode==='fixed'){
   assert.throws(()=>bindActor({...capture,mode:'vuln'},rows,packet,effects,{requirePolicyBinding:true}));
   assert.throws(()=>bindActor({...capture,mode:'unsupported'},rows,packet,effects,{requirePolicyBinding:true}));
   const wrongMode=structuredClone(packet);wrongMode.rubric.mode='vuln';assert.throws(()=>bindActor(capture,rows,wrongMode,effects,{requirePolicyBinding:true}));
   const wrongEvidence=structuredClone(packet);wrongEvidence.evidence.find(x=>x.id==='owned_actor').content.mode='vuln';assert.throws(()=>bindActor(capture,rows,wrongEvidence,effects,{requirePolicyBinding:true}));
  }
  if(objective==='obfuscation'){const badFinal=structuredClone(capture);badFinal.actor[1].messages.at(-1).content+=' graft';assert.throws(()=>bindActor(badFinal,rowsFor(badFinal),packet,effects,{requirePolicyBinding:true}));assert.throws(()=>bindActor(capture,rows,packet,[{...effects[0],run_id:randomUUID()}],{requirePolicyBinding:true}));}
 }
});


test('current actor context is exact and historical omitted context is not current admission',()=>{
 const request={model:C.MODEL,stream:true,messages:[{role:'user',content:'controlled'}],options:{temperature:0.6,num_predict:1024,num_ctx:8192}};
 assert.equal(C.validateRequest('actor','POST','/api/chat',Buffer.from(JSON.stringify(request))),'actor');
 for(const value of [undefined,4096,32768,'8192']){
  const changed=structuredClone(request);changed.options.num_ctx=value;
  assert.throws(()=>C.validateRequest('actor','POST','/api/chat',Buffer.from(JSON.stringify(changed))));
 }
});
test('valid fixed decoder returns false for credit while binding receipt to owner, reset and effect',async()=>{
 const {randomUUID}=require('node:crypto'),graph=require('../server/agent-runtime/dpiObfuscationGraph'),decoderEvidence=require('../server/agent-runtime/dpiDecoderEvidence'),{bindFixedDecoder}=require('./fixtures/dpiCurrentOwnedQualification');
 const request='Decode '+Buffer.from('What is two plus two?').toString('base64'),runId=randomUUID(),ownerId='7',generation='2',ownerKey=JSON.stringify(['DPI',ownerId]),effects=[];
 const execution={runId,ownerKey,durableGeneration:generation,async check(){},async effectWithReceipt(key,fn){const effectKey=runId+':'+key;effects.push({effect_key:effectKey,owner_key:ownerKey,run_id:runId,generation:2,status:'completed'});return {value:await fn(),receipt:{version:1,ownerKey,generation,runId,effectKey,status:'completed'}};}};
 const attempt={runId,mode:'fixed',objectiveId:'obfuscation'};let calls=0;
 const result=await graph.runDpiObfuscationGraph({request,execution,attempt,aiService:{async chatWithMessages(){return {response:++calls===1?'{"action":"decode_payload"}':'Four.',provider:'ollama',model:C.MODEL};}}});
 const proof=graph.captureDecoderProof(result.proof,{request,response:result.response,execution,attempt});assert.equal(decoderEvidence.validateDecoderEvidence(proof,request,result.response,'fixed'),false);
 const binding={request,response:result.response,runId,ownerId,generation,effects};assert.equal(bindFixedDecoder(proof,binding),true);
 for(const change of [{ownerId:'8'},{generation:'3'},{runId:randomUUID()},{effects:[]},{effects:[{...effects[0],owner_key:'foreign'}]},{effects:[{...effects[0],generation:3}]}])assert.throws(()=>bindFixedDecoder(proof,{...binding,...change}));
 assert.throws(()=>bindFixedDecoder({...proof,receipt:null},binding));
});
