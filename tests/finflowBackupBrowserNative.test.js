'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{Readable}=require('node:stream'),{createHash}=require('node:crypto');
const entry=require('./postgres/finflowBackupBrowser.integration.test');
const t=require('./postgres/finflowBackupBrowserActualTransport');
const hash=x=>createHash('sha256').update(x).digest('hex');
test('entry import is inert and rejects missing opt-in before authority/resources',()=>{assert.throws(()=>entry.admit({}));});
test('one-byte parent release gate rejects extra or missing bytes',async()=>{await entry.startGate(Readable.from(['1']));await assert.rejects(entry.startGate(Readable.from(['12'])));await assert.rejects(entry.startGate(Readable.from([])));});
test('29 external cap keeps distinct inference and metadata quotas',()=>{
 const b=t.budget();for(let i=0;i<20;i++)b.reserve('generate');for(let i=0;i<4;i++)b.reserve('chat');for(let i=0;i<3;i++)b.reserve('tags');for(let i=0;i<2;i++)b.reserve('version');
 assert.equal(b.counts.external,29);assert.equal(b.counts.metadata,5);for(const k of ['generate','chat','tags','version'])assert.throws(()=>b.reserve(k));
 const c=t.budget();for(let i=0;i<3;i++)c.reserve('tags');assert.throws(()=>c.reserve('tags'));assert.equal(c.counts.external,3);
 for(let i=0;i<29;i++)c.incoming();assert.throws(()=>c.incoming());
});
test('request admission pins actor/Judge options, model and endpoint; no tools/fallback',()=>{
 const generate={model:t.MODEL,stream:true,prompt:'selected action',format:'json',options:{temperature:0,num_predict:400,num_ctx:8192}};
 assert.equal(t.validateRequest('POST','/api/generate',Buffer.from(JSON.stringify(generate))),'generate');
 const chat={model:t.MODEL,stream:true,messages:[{role:'system',content:'criterion'},{role:'user',content:'evidence'}],format:{type:'object'},options:{temperature:0,num_predict:900,num_ctx:32768}};
 assert.equal(t.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(chat))),'chat');
 for(const mutate of [x=>{x.model='other';},x=>{x.options.num_ctx=4096;},x=>{x.options.temperature=1;},x=>{x.tools=[{}];},x=>{x.extra=true;}]){const x=structuredClone(chat);mutate(x);assert.throws(()=>t.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(x))));}
 assert.throws(()=>t.validateRequest('GET','/api/pull',Buffer.alloc(0)));
});
test('version metadata is not model proof; tags need exact digest; responses require stop/full bytes',()=>{
 const base={status:200,responseComplete:true,responseCaptureTruncated:false};
 const row=(kind,value)=>{const response=JSON.stringify(value);return {...base,kind,response,responseSha256:hash(response),responseBytes:Buffer.byteLength(response)};};
 t.validateResponse(row('version',{version:'0.11.2'}));assert.throws(()=>t.validateResponse(row('version',{version:{}})));
 t.validateResponse(row('tags',{models:[{name:t.MODEL,digest:t.DIGEST}]}));assert.throws(()=>t.validateResponse(row('tags',{models:[{name:t.MODEL,digest:'wrong'}]})));
 const good=row('generate',{model:t.MODEL,response:'observed',done:true,done_reason:'stop'});t.validateResponse(good);
 for(const changed of [{...good,responseComplete:false},{...good,responseSha256:'0'.repeat(64)},row('generate',{model:t.MODEL,response:'partial',done:true,done_reason:'length'}),row('chat',{model:t.MODEL,message:{content:'text',tool_calls:[{}]},done:true,done_reason:'stop'})])assert.throws(()=>t.validateResponse(changed));
 assert.throws(()=>t.validateTimedResponse(good,10,()=>10));
});

test('all owned cleanup branches run even when one never settles or throws',async()=>{
 const {settleOwnership}=require('./fixtures/secureshopAnalyticsBrowserOwner');const visited=[];
 const outcomes=await settleOwnership([['pools',()=>{visited.push('pools');return new Promise(()=>{});}],['auth',()=>{visited.push('auth');throw Error('private detail');}],['transport',()=>{visited.push('transport');}]],10);
 assert.deepEqual(visited,['pools','auth','transport']);assert.deepEqual(outcomes.map(x=>x.status),['rejected','rejected','fulfilled']);assert(!JSON.stringify(outcomes).includes('private detail'));
});

test('browser readiness captured before spawn continuation; old late listener loses early data',async()=>{
 const {EventEmitter}=require('node:events'),{once}=require('node:events');const {observeBrowserEndpoint}=require('./fixtures/secureshopAnalyticsBrowserOwner');
 const make=()=>{const child=new EventEmitter();child.stderr=new EventEmitter();child.stderr.on('data',()=>{});return child;};
 const line=Buffer.from('DevTools listening on ws://127.0.0.1:45678/devtools/browser/owned\n');
 const old=make(),spawned=once(old,'spawn');queueMicrotask(()=>{old.emit('spawn');old.stderr.emit('data',line);});await spawned;
 await assert.rejects(observeBrowserEndpoint(old,()=>{},5),/startup deadline/);
 const current=make(),captured=[];const ready=observeBrowserEndpoint(current,b=>captured.push(b),50),started=once(current,'spawn');queueMicrotask(()=>{current.emit('spawn');current.stderr.emit('data',line);});await started;
 assert.equal(await ready,'ws://127.0.0.1:45678/devtools/browser/owned');assert.equal(Buffer.concat(captured).toString(),line.toString());assert.equal(current.listenerCount('exit'),0);
});
test('native diagnostic omits arbitrary messages, URLs, secrets and foreign stack paths',()=>{
 const d=entry.failureDiagnostic(Object.assign(Error('password=secret https://user:pass@example.test/private'),{stack:'Error: secret\n    at f (/outside/private/file.js:8:2)\n    at f ('+require('node:path').resolve('tests/fixtures/secureshopAnalyticsBrowserOwner.js')+':20:3)'}),'browser-launch');
 assert.equal(d.message,'Unclassified failure (message omitted)');assert.equal(d.frames.length,1);assert(!JSON.stringify(d).includes('secret'));assert(!JSON.stringify(d).includes('/outside'));assert.equal(entry.failureDiagnostic(Error('Owned Chrome startup deadline'),'browser-launch').message,'Owned Chrome startup deadline');
});
