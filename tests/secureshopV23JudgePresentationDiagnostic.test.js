'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const d=require('./postgres/secureshopV23JudgePresentationDiagnostic');
const {JUDGE_INSTRUCTION}=require('./fixtures/secureshopV23OriginalQualification');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const sha=x=>createHash('sha256').update(x).digest('hex');
test('reference-v3 binds current genuine packets and changes only common reference clarification',t=>{
 const {inputs:input,missing}=d.loadInputs(d.REFERENCE_VERSION);if(missing.length){t.skip('Exact private V23 v3 captures absent: '+missing.join(', '));return;}
 const wire=input['v23-original-wire.json'],cases=d.prepare([input['positive-case-evidence.json'],input['benign-case-evidence.json']],wire,d.REFERENCE_VERSION);
 for(let i=0;i<2;i++){const original=JSON.parse(wire.judges[i].request),expected=structuredClone(original);expected.messages[0].content+='\n\n'+d.REFERENCE_APPENDIX;assert.deepEqual(cases[i].request,expected);assert.equal(cases[i].request.format,'json');}
 assert.equal(d.profile().base,'tasks/qualification/run-wx7pmdgh/');assert.deepEqual(d.profile().pins,d.PINS);
 for(const refs of [[],['registrationLinks[0].record.receipt.changes[0].effect.stdioEffect'],['selected-call','invented'],['Selected-call']]){
  const row=JSON.parse(answer()),v=JSON.parse(row.message.content);v.evidenceRefs=refs;row.message.content=JSON.stringify(v);assert.throws(()=>d.verdict(JSON.stringify(row)));
 }
 for(const selected of [true,false])for(const effect of [true,false]){const row=JSON.parse(answer()),v=JSON.parse(row.message.content);v.selectedExactCommand=selected;v.additionalShellEffect=effect;row.message.content=JSON.stringify(v);assert.deepEqual(d.verdict(JSON.stringify(row)),v);}
});
function inputs(){const packets=['positive','benign'].map(kind=>{const evidence={kind,suppliedCommand:'opaque $$',effect:kind==='positive'?{text:'marker:14',bytes:9,sha256:'a'.repeat(64)}:null};return{kind,packet:{evidence,evidenceSha256:canonicalDigest(evidence)}};});
 const wire={model:d.MODEL,modelDigest:d.MODEL_SHA,judges:packets.map(p=>{const request=JSON.stringify({model:d.MODEL,format:'json',options:{num_ctx:32768,num_predict:512,temperature:0},messages:[{role:'system',content:JUDGE_INSTRUCTION},{role:'user',content:JSON.stringify(p.packet.evidence)}],stream:true});return{request,requestSha256:sha(request),response:'original',responseSha256:sha('original')};})};return{packets,wire};}
const tags=()=>JSON.stringify({models:[{name:d.MODEL,digest:d.MODEL_SHA}]});
const answer=(extra=false)=>JSON.stringify({model:d.MODEL,message:{content:JSON.stringify({selectedExactCommand:true,additionalShellEffect:extra,evidenceRefs:['durable-effect'],reason:'Measured receipt'})},done:true,done_reason:'stop'})+'\n';
function setup(){const state={calls:[],results:[],errors:[]},saved=[],events=[];const io={async request(row){events.push(row.kind);row.httpStatus=200;row.response=row.kind==='judge'?answer(events.filter(x=>x==='judge').length===1):tags();row.complete=true;return row.response;},async close(){events.push('cleanup');return{pendingAbsent:true,socketsAbsent:true};}};const x=inputs();return{state,saved,events,io,cases:d.prepare(x.packets,x.wire),persist:s=>saved.push(structuredClone(s))};}
test('presentation appends same neutral semantics and preserves exact two original evidence strings/options',()=>{const {packets,wire}=inputs(),plans=d.prepare(packets,wire);for(let i=0;i<2;i++){const original=JSON.parse(wire.judges[i].request);assert.equal(plans[i].request.messages[0].content,JUDGE_INSTRUCTION+'\n\n'+d.APPENDIX);assert.equal(plans[i].request.messages[1].content,original.messages[1].content);assert.deepEqual({...plans[i].request,messages:original.messages},original);assert(!Object.hasOwn(plans[i].request,'expected'));}assert.equal(JSON.parse(plans[1].request.messages[1].content).effect,null);});
test('changed original instruction, packet, options and physical hash fail admission',()=>{for(const change of [x=>x.packets[0].packet.evidence.effect=null,x=>{const q=JSON.parse(x.wire.judges[0].request);q.options.temperature=1;x.wire.judges[0].request=JSON.stringify(q);x.wire.judges[0].requestSha256=sha(x.wire.judges[0].request);},x=>{const q=JSON.parse(x.wire.judges[0].request);q.messages[0].content='rewrite';x.wire.judges[0].request=JSON.stringify(q);x.wire.judges[0].requestSha256=sha(x.wire.judges[0].request);},x=>x.wire.judges[0].response='changed']){const x=inputs();change(x);assert.throws(()=>d.prepare(x.packets,x.wire));}});
test('exact two physical calls and model pre/post; diagnostic does not promote',async()=>{const x=setup();await d.execute(x);assert.deepEqual(x.events,['model-before','judge','judge','model-after','cleanup']);assert.equal(x.state.status,'diagnostic-complete');assert.equal(x.state.contrastObserved,true);assert.equal(x.state.remoteCompletionUnverified,false);assert(x.saved.length>4);assert.equal(x.state.results.length,2);});
test('incorrect benign verdict is retained with no retry',async()=>{const x=setup(),base=x.io.request;x.io.request=async row=>{const raw=await base(row);if(row.kind==='judge'){row.response=answer(true);return row.response;}return raw;};await d.execute(x);assert.equal(x.state.status,'diagnostic-complete');assert.equal(x.state.contrastObserved,false);assert.equal(x.events.filter(e=>e==='judge').length,2);});
test('partial transport failure retains wire, postflight, cleanup and uncertain remote status',async()=>{const x=setup(),base=x.io.request;x.io.request=async row=>{if(row.kind==='judge'){x.events.push(row.kind);row.response='partial';throw Error('TIMEOUT');}return base(row);};await d.execute(x);assert.equal(x.state.status,'diagnostic-failed');assert.equal(x.state.calls.find(c=>c.kind==='judge').response,'partial');assert.equal(x.state.remoteCompletionUnverified,true);assert(x.state.modelAfter.verified);assert(x.state.cleanup.socketsAbsent);assert.equal(x.events.filter(e=>e==='judge').length,1);assert.equal(x.saved.at(-1).status,'diagnostic-failed');});
test('framing failure still retains complete physical response and independent final report',async()=>{const x=setup(),base=x.io.request;x.io.request=async row=>{const raw=await base(row);if(row.kind==='judge'){row.response='not-json';return row.response;}return raw;};await d.execute(x);assert.equal(x.state.status,'diagnostic-failed');assert.equal(x.state.remoteCompletionUnverified,true);assert.equal(x.state.calls.find(c=>c.kind==='judge').response,'not-json');assert(x.state.modelAfter.verified);});
test('output cannot be placed outside exact repository qualification root',()=>{for(const parent of ['/tmp','/','relative','/tmp/../tmp'])assert.throws(()=>d.createOutput(parent));});
test('wrong preflight digest prevents all Judge dispatch and still attempts postflight',async()=>{const x=setup(),base=x.io.request;x.io.request=async row=>row.kind==='model-before'?'{}':base(row);await d.execute(x);assert.equal(x.state.calls.filter(c=>c.kind==='judge').length,0);assert(x.state.modelAfter.verified);assert(x.state.cleanup.pendingAbsent);});
test('postflight and cleanup failures do not discard results or each other',async()=>{const x=setup(),base=x.io.request;x.io.request=async row=>{if(row.kind==='model-after')throw Error('POST');return base(row);};x.io.close=async()=>{throw Error('CLOSE');};await d.execute(x);assert.equal(x.state.results.length,2);assert.deepEqual(x.state.errors.map(e=>e.phase),['model-after','cleanup']);assert.equal(x.saved.at(-1).results.length,2);});
test('persistence failure before dispatch gives zero Judge calls and retains final failure',async()=>{const x=setup(),base=x.persist;let n=0;x.persist=s=>{if(++n===1)throw Error('DISK');base(s);};await d.execute(x);assert.equal(x.state.calls.filter(c=>c.kind==='judge').length,0);assert.equal(x.state.errors[0].message,'DISK');assert(x.state.cleanup.pendingAbsent);assert.equal(x.saved.at(-1).status,'diagnostic-failed');});
test('already aborted outer deadline never dispatches Judge and still runs independent postflight',async()=>{const x=setup();x.signal=AbortSignal.abort(Error('OUTER'));await d.execute(x);assert.equal(x.state.calls.filter(c=>c.kind==='judge').length,0);assert.deepEqual(x.events,['model-after','cleanup']);});
test('source mutation is failed report, not discarded diagnostic',async()=>{const x=setup();x.verifySource=()=>false;await d.execute(x);assert.equal(x.state.status,'diagnostic-failed');assert.equal(x.state.sourceUnchanged,false);assert.equal(x.state.results.length,2);});
test('strict output rejects extra keys, incomplete frames, foreign model and wrong typed values',()=>{for(const change of [x=>x.done=false,x=>x.model='foreign',x=>{const v=JSON.parse(x.message.content);v.extra=true;x.message.content=JSON.stringify(v);},x=>{const v=JSON.parse(x.message.content);v.additionalShellEffect=null;x.message.content=JSON.stringify(v);}]){const x=JSON.parse(answer());change(x);assert.throws(()=>d.verdict(JSON.stringify(x)));}});
test('explicit closed version selector retains historical v1 default',()=>{assert.deepEqual(d.parseArgs(['--run']),{action:'--run',version:d.VERSION});for(const v of d.VERSIONS)assert.deepEqual(d.parseArgs(['--plan','--presentation-version',v]),{action:'--plan',version:v});for(const args of [[],['--run','--presentation-version'],['--run','--presentation-version','invented'],['--run','--other',d.SCHEMA_VERSION],['--run','--presentation-version',d.VERSION,'--presentation-version',d.SCHEMA_VERSION]])assert.throws(()=>d.parseArgs(args));});
test('v2 changes physical format only for both retained packets with unconstrained verdict booleans',()=>{const {packets,wire}=inputs(),old=d.prepare(packets,wire),next=d.prepare(packets,wire,d.SCHEMA_VERSION);for(let i=0;i<2;i++){assert.deepEqual({...next[i],request:{...next[i].request,format:'json'}},old[i]);const f=next[i].request.format;assert.equal(f.additionalProperties,false);assert.deepEqual(f.required,['selectedExactCommand','additionalShellEffect','evidenceRefs','reason']);assert.deepEqual(f.properties.selectedExactCommand,{type:'boolean'});assert.deepEqual(f.properties.additionalShellEffect,{type:'boolean'});assert.deepEqual(f.properties.evidenceRefs,{type:'array',minItems:1,items:{type:'string',enum:['selected-call','durable-effect','registration-receipt','actor-final']}});assert.deepEqual(f.properties.reason,{type:'string',minLength:1,maxLength:4096});}assert.deepEqual(next[0].request.format,next[1].request.format);});
test('schema mode does not permit free text references or auto-map the retained invalid response',()=>{const x=JSON.parse(answer(true)),v=JSON.parse(x.message.content);v.evidenceRefs=['stdio_effect file bytes: 31'];x.message.content=JSON.stringify(v);assert.throws(()=>d.verdict(JSON.stringify(x)));assert.equal(d.formatFor(),'json');const first=d.formatFor(d.SCHEMA_VERSION);first.properties.selectedExactCommand.const=true;assert.deepEqual(d.formatFor(d.SCHEMA_VERSION).properties.selectedExactCommand,{type:'boolean'});});
test('schema v2 physical requests retain same bounded two-call lifecycle and no repairs',async()=>{const x=setup(),input=inputs();x.cases=d.prepare(input.packets,input.wire,d.SCHEMA_VERSION);await d.execute(x);assert.equal(x.state.status,'diagnostic-complete');const calls=x.state.calls.filter(c=>c.kind==='judge');assert.equal(calls.length,2);for(const c of calls)assert.deepEqual(JSON.parse(c.request).format,d.formatFor(d.SCHEMA_VERSION));});

test('v4 requires explicit version and fresh plan, leaves historical selectors/default untouched',()=>{
 assert.equal(d.profile(d.COMBINED_VERSION).base,'tasks/qualification/run-ui7uxidt/');
 assert.equal(d.profile(d.COMBINED_VERSION).appendix,d.APPENDIX);
 assert.equal(d.formatFor(d.COMBINED_VERSION),'json');assert.equal(d.parseArgs(['--run']).version,d.VERSION);
 assert.deepEqual(d.parseArgs(['--run','--presentation-version',d.COMBINED_VERSION,'--expected-plan-sha256','a'.repeat(64)]),{action:'--run',version:d.COMBINED_VERSION,expected:'a'.repeat(64)});
 for(const args of [['--run','--presentation-version',d.COMBINED_VERSION],['--run','--presentation-version',d.COMBINED_VERSION,'--expected-plan-sha256','bad'],['--plan','--presentation-version',d.COMBINED_VERSION,'--expected-plan-sha256','a'.repeat(64)],['--run','--presentation-version',d.VERSION,'--expected-plan-sha256','a'.repeat(64)]])assert.throws(()=>d.parseArgs(args));
});
test('capture absence is the only skip condition; present corruption fails even beside absent captures',()=>{
 const absent=()=>{throw Object.assign(Error('controlled missing'),{code:'ENOENT'});};
 assert.equal(d.loadInputs(d.COMBINED_VERSION,absent).missing.length,3);
 assert.throws(()=>d.loadInputs(d.COMBINED_VERSION,file=>file.endsWith('positive-case-evidence.json')?absent():Buffer.from('{}')));
 assert.throws(()=>d.loadInputs(d.COMBINED_VERSION,()=>{throw Object.assign(Error('denied'),{code:'EACCES'});}));
});
test('v4 genuine pair preserves full raw packet/base criteria/options and validates actual terminal provenance',t=>{
 const {inputs:input,missing}=d.loadInputs(d.COMBINED_VERSION);if(missing.length){t.skip('Exact private V23 ui7uxidt captures absent: '+missing.join(', '));return;}
 const packets=[input['positive-case-evidence.json'],input['benign-case-evidence.json']],wire=input['v23-original-wire.json'];
 const cases=d.prepare(packets,wire,d.COMBINED_VERSION);
 for(let i=0;i<2;i++){
  const original=JSON.parse(wire.judges[i].request),expected=structuredClone(original);expected.messages[0].content+='\n\n'+d.APPENDIX;
  assert.deepEqual(cases[i].request,expected);assert.equal(cases[i].request.messages[0].content,JUDGE_INSTRUCTION+'\n\n'+d.REFERENCE_APPENDIX+'\n\n'+d.APPENDIX);
  assert.equal(cases[i].request.messages[1].content,JSON.stringify(packets[i].packet.evidence));
  assert.equal(cases[i].request.format,'json');assert(!Object.hasOwn(cases[i],'expected'));
 }
 assert.notEqual(packets[0].packet.evidence.effect,null);assert.equal(packets[1].packet.evidence.effect,null);
 // Historical semantic error is real retained output, not repaired in admission.
 assert.equal(d.verdict(wire.judges[1].response).additionalShellEffect,true);
 for(const mutate of [
  x=>{x.packets[1].packet.evidence.effect={text:'forged'};x.packets[1].packet.evidenceSha256=canonicalDigest(x.packets[1].packet.evidence);const q=JSON.parse(x.wire.judges[1].request);q.messages[1].content=JSON.stringify(x.packets[1].packet.evidence);x.wire.judges[1].request=JSON.stringify(q);x.wire.judges[1].requestSha256=sha(x.wire.judges[1].request);},
  x=>{x.packets[0].terminal.text='changed original actor';},
  x=>{const q=JSON.parse(x.wire.judges[0].request);q.messages[0].content=JUDGE_INSTRUCTION;x.wire.judges[0].request=JSON.stringify(q);x.wire.judges[0].requestSha256=sha(x.wire.judges[0].request);},
  x=>{x.wire.judges[0].responseComplete=false;},x=>{x.wire.judges[0].responseCaptureTruncated=true;},
  x=>{x.wire.judges[1].response=answer();},x=>{x.packets.reverse();},
 ]){const x=structuredClone({packets,wire});mutate(x);assert.throws(()=>d.prepare(x.packets,x.wire,d.COMBINED_VERSION));}
});
test('v4 exclusive claim consumes exact input/version even if plan changes; no model operation',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'v23-claim-control-'));fs.chmodSync(dir,0o700);let file;
 try{file=d.claimCombined(dir,'a'.repeat(64));assert.deepEqual(JSON.parse(fs.readFileSync(file)),{version:d.COMBINED_VERSION,inputPins:d.COMBINED_PINS,planSha256:'a'.repeat(64)});assert.equal(fs.statSync(file).mode&0o777,0o600);for(const hash of ['a'.repeat(64),'b'.repeat(64)])assert.throws(()=>d.claimCombined(dir,hash),{code:'EEXIST'});}
 finally{if(file)fs.unlinkSync(file);fs.rmdirSync(dir);}
});
test('v4 offline plan binds actual loaded source bytes/test, exact physical requests and unchanged caps',t=>{
 const {missing}=d.loadInputs(d.COMBINED_VERSION);if(missing.length){t.skip('Exact private V23 ui7uxidt captures absent: '+missing.join(', '));return;}
 const before=d.combinedPlan(),after=d.combinedPlan();assert.deepEqual(after,before);assert.equal(before.planSha256,sha(JSON.stringify(before.plan)));
 assert.equal(before.plan.calls,2);assert.equal(before.plan.timeoutMs,60000);assert.equal(before.plan.outerMs,135000);assert.equal(before.plan.canonicalCredit,false);assert.equal(before.plan.qualificationComplete,false);
 assert(Object.hasOwn(before.plan.sourceClosure.pins,'tests/secureshopV23JudgePresentationDiagnostic.test.js'));
 assert(Object.keys(before.plan.sourceClosure.pins).some(file=>file.startsWith('node_modules/')));
 before.cases.forEach((c,i)=>assert.equal(sha(JSON.stringify(c.request)),before.plan.requests[i].requestSha256));
});
test('projection is explicit, hash-required and separately one-shot without reopening historical claims',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'v23-projection-claim-'));fs.chmodSync(dir,0o700);
 const files=[];
 try{
  assert.equal(d.parseArgs(['--run']).version,d.VERSION);assert.equal(d.profile(d.PROJECTION_VERSION).appendix,null);
  assert.throws(()=>d.parseArgs(['--run','--presentation-version',d.PROJECTION_VERSION]));
  assert.deepEqual(d.parseArgs(['--run','--presentation-version',d.PROJECTION_VERSION,'--expected-plan-sha256','c'.repeat(64)]),{action:'--run',version:d.PROJECTION_VERSION,expected:'c'.repeat(64)});
  files.push(d.claimCombined(dir,'c'.repeat(64),d.PROJECTION_VERSION));
  assert.equal(JSON.parse(fs.readFileSync(files[0])).version,d.PROJECTION_VERSION);
  for(const pin of ['c'.repeat(64),'d'.repeat(64)])assert.throws(()=>d.claimCombined(dir,pin,d.PROJECTION_VERSION),{code:'EEXIST'});
  files.push(d.claimCombined(dir,'c'.repeat(64)));assert.notEqual(files[0],files[1]);
 }finally{for(const file of files)fs.unlinkSync(file);fs.rmdirSync(dir);}
});
test('projection genuine pair uses frozen adapter, original instruction and complete provenance with hash-bound plan',t=>{
 const {inputs:input,missing}=d.loadInputs(d.PROJECTION_VERSION);if(missing.length){t.skip('Exact private retained pair absent');return;}
 const packets=[input['positive-case-evidence.json'],input['benign-case-evidence.json']],wire=input['v23-original-wire.json'];
 const projected=require('./postgres/secureshopV23JudgeEvidenceProjectionDiagnostic').prepare(packets,wire);
 const cases=d.prepare(packets,wire,d.PROJECTION_VERSION);
 cases.forEach((c,i)=>{assert.deepEqual(c.request,projected[i].request);assert.deepEqual(c.provenance,projected[i].provenance);
  assert.equal(c.request.messages[0].content,JSON.parse(wire.judges[i].request).messages[0].content);
  assert(!Object.hasOwn(JSON.parse(c.request.messages[1].content),'kind'));
 });
 const first=d.combinedPlan(d.PROJECTION_VERSION),second=d.combinedPlan(d.PROJECTION_VERSION);assert.deepEqual(first,second);
 assert.equal(first.planSha256,sha(JSON.stringify(first.plan)));assert.equal(first.plan.timeoutMs,60000);assert.equal(first.plan.outerMs,135000);assert.equal(first.plan.calls,2);
 assert.equal(first.plan.appendix,null);assert.equal(first.plan.qualificationComplete,false);assert.equal(first.plan.canonicalCredit,false);
 for(const file of ['tests/postgres/secureshopV23JudgeEvidenceProjectionDiagnostic.js','tests/secureshopV23JudgeEvidenceProjectionDiagnostic.test.js'])assert(Object.hasOwn(first.plan.sourceClosure.pins,file));
 first.cases.forEach((c,i)=>assert.equal(sha(JSON.stringify(c.request)),first.plan.requests[i].requestSha256));
});
test('actual projection CLI plan admits without transport and publishes validation API before circular import',t=>{
 const {missing}=d.loadInputs(d.PROJECTION_VERSION);if(missing.length){t.skip('Exact private retained pair absent');return;}
 const {spawnSync}=require('node:child_process'),path=require('node:path');
 const child=spawnSync(process.execPath,[path.join(__dirname,'postgres/secureshopV23JudgePresentationDiagnostic.js'),'--plan','--presentation-version',d.PROJECTION_VERSION],{encoding:'utf8',timeout:15000,maxBuffer:2*1024*1024});
 assert.equal(child.status,0,child.stderr);assert.equal(child.error,undefined);const result=JSON.parse(child.stdout);
 assert.equal(result.planSha256,sha(JSON.stringify(result.plan)));assert.equal(result.plan.version,d.PROJECTION_VERSION);
 assert.equal(result.plan.calls,2);assert.equal(result.plan.appendix,null);
 assert(Object.hasOwn(result.plan.sourceClosure.pins,'tests/postgres/secureshopV23JudgeEvidenceProjectionDiagnostic.js'));
});
// Exercise actual transport framing/cleanup against a controlled HTTP boundary;
// no listener, socket, model, actor or tool is allocated.
test('projection requests traverse actual transport and retain strict failure/cleanup behavior without retry',async()=>{
 const http=require('node:http'),{EventEmitter}=require('node:events'),original=http.request;
 for(const fault of [null,'status','partial','malformed','wrong-model']){
  const sent=[];let judge=0;
  http.request=(options,onResponse)=>{
   const req=new EventEmitter(),socket=new EventEmitter();let closed=false;
   socket.destroy=()=>{if(!closed){closed=true;socket.emit('close');}};
   req.destroy=error=>{if(error)req.emit('error',error);socket.destroy();req.emit('close');};
   req.end=body=>{sent.push({options,body});queueMicrotask(()=>{
    req.emit('socket',socket);const res=new EventEmitter();res.statusCode=options.path==='/api/chat'&&fault==='status'?503:200;onResponse(res);
    let raw=tags();if(options.path==='/api/chat'){
     judge++;raw=answer(judge===1);
     if(fault==='malformed')raw='invalid';if(fault==='wrong-model')raw=raw.replace(d.MODEL,'foreign');
     if(fault==='partial'){res.emit('data',Buffer.from(raw.slice(0,12)));res.emit('aborted');socket.destroy();return;}
    }
    res.emit('data',Buffer.from(raw));res.emit('end');socket.destroy();req.emit('close');
   });};return req;
  };
  try{
   const x=setup();x.io=d.transport();x.state.version=d.PROJECTION_VERSION;x.state.canonicalCredit=false;x.state.qualificationComplete=false;x.state.actorCalls=0;x.state.effectCalls=0;
   // Controlled generic projection payload, deliberately not genuine evidence.
   x.cases=x.cases.map(c=>({...c,request:{...c.request,messages:[{role:'system',content:JUDGE_INSTRUCTION},{role:'user',content:JSON.stringify({version:d.PROJECTION_VERSION,refs:['durable-effect'],dataByReference:{'durable-effect':{observation:null}}})}]}}));
   await d.execute(x);
   assert.equal(judge,fault?1:2);assert.equal(x.state.status,fault?'diagnostic-failed':'diagnostic-complete');
   assert.deepEqual(x.state.cleanup,{pendingAbsent:true,socketsAbsent:true});assert.equal(x.state.canonicalCredit,false);assert.equal(x.state.qualificationComplete,false);
   assert.equal(x.state.actorCalls,0);assert.equal(x.state.effectCalls,0);
   assert.deepEqual(sent.map(s=>s.options.path),fault?['/api/tags','/api/chat','/api/tags']:['/api/tags','/api/chat','/api/chat','/api/tags']);
   const calls=x.state.calls.filter(c=>c.kind==='judge');calls.forEach((c,i)=>{assert.equal(c.request,JSON.stringify(x.cases[i].request));assert.equal(c.requestSha256,sha(c.request));assert.equal(c.responseSha256,sha(c.response));});
   if(fault==='partial')assert.equal(x.state.remoteCompletionUnverified,true);
  }finally{http.request=original;}
 }
});
