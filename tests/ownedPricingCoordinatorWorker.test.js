'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const worker=require('./postgres/ownedPricingCoordinatorWorker');
const root=path.resolve(__dirname,'..');
async function run(fault,profile='v33'){
 const runId=crypto.randomBytes(16).toString('hex'),directory=path.join(root,'tasks/qualification','pricing-private-'+runId);fs.mkdirSync(directory,{mode:0o700});
 const extra=profile==='v33'?{}:{consumerProfile:profile},version=profile==='v33'?1:2;
 const plan={inputs:{sources:{},packageDigest:'a'.repeat(64),...extra}},binding={version,runId,ownerPlanSha256:'b'.repeat(64),nodePlanSha256:crypto.createHash('sha256').update(JSON.stringify(plan)).digest('hex'),...extra};
 const admission={version,verb:'admit',runId,ownerId:'10000000-0000-4000-8000-000000000001',ownerPlanSha256:binding.ownerPlanSha256,sources:{},packageSha256:plan.inputs.packageDigest,...extra};
 const messages=[admission,{...binding,verb:'build'},{...binding,verb:'publish',token:'t'.repeat(43)},{...binding,verb:'consumer-retired'},{...binding,verb:'retire',retired:fault!=='unjoined',remainingMs:500000}];
 if(fault==='binding')messages[1].nodePlanSha256='c'.repeat(64);
 if(fault==='eof')messages.pop();
 if(fault==='cross-profile')messages[1].consumerProfile='v33';
 if(fault==='mixed-plan')delete plan.inputs.consumerProfile;
 const sent=[],calls=[];let clock=100;
 try{
  const result=await worker.execute({read:async()=>{if(!messages.length)throw Error('eof');return messages.shift();},send:async v=>{sent.push(v);if(v.verb==='retirement-ready'&&fault==='delayed')clock+=500001;}},
   {profile,now:()=>clock,makePlan:async(_root,_run,selected)=>{assert.equal(selected,profile);return plan;},makeTransport:()=>({phase:async(name,args)=>{calls.push(name);assert.equal(args.publication.token,'t'.repeat(43));return JSON.stringify({version:1,runId,published:true,runtimeStarted:false});},beginRetirement:(n,t)=>calls.push(['retire',n,t]),close:()=>calls.push('close')}),
    build:async(_plan,{consume,beforeRetirement,record})=>{if(fault==='journal')try{await record('diagnostic','x'.repeat(2*1024**2));}catch{}await consume({imageId:'sha256:'+'d'.repeat(64)});await beforeRetirement();calls.push('delete-owned-builder');return {cleanupVerified:true};}});
  return {result,calls,sent};
 }catch(error){return {error,calls,sent};}
 finally{for(const name of fs.readdirSync(directory))fs.unlinkSync(path.join(directory,name));fs.rmdirSync(directory);}
}
test('worker finite protocol holds daemon until consumer retirement and joins both plan hashes',async()=>{
 assert.equal(worker.LIVE_ENABLED,true);const r=await run();assert.ifError(r.error);
 assert.deepEqual(r.sent.map(x=>x.verb),['ready','image','published','retirement-ready','terminal']);
 assert.deepEqual(r.calls,['publishHandoff',['retire',500000,100],'delete-owned-builder','close']);
 assert(!JSON.stringify(r.sent).includes('t'.repeat(43)));
});
test('V34 worker binds every message to its profile and forced closed entry refuses',async()=>{
 const good=await run(undefined,'v34-browser');assert.ifError(good.error);
 assert(good.sent.every(row=>row.version===2&&row.consumerProfile==='v34-browser'));
 for(const fault of ['cross-profile','mixed-plan','eof','unjoined','delayed']){
  const r=await run(fault,'v34-browser');assert(r.error);assert(!r.calls.includes('delete-owned-builder'));
 }
 await assert.rejects(worker.main(false,'v34-browser'),/NOT_ADMITTED/);
 const {PassThrough}=require('node:stream'),{EventEmitter}=require('node:events');
 for(const [name,total] of [['v33',2616000],['v34-browser',3016000]]){
  let now=100;const input=new PassThrough(),output=new EventEmitter();output.write=(_b,cb)=>cb();
  const io=worker.ownerChannel(input,output,name,()=>now);
  now+=total-1;await io.send({bounded:true});now++;
  await assert.rejects(io.send({late:true}),/DEADLINE/);io.close();input.destroy();
 }
});
test('V25 enabled entry retains exact owner protocol and forced closed admission',async()=>{
 assert.equal(worker.V25_LIVE_ENABLED,true);
 const good=await run(undefined,'v25-manual');assert.ifError(good.error);
 assert(good.sent.every(row=>row.version===2&&row.consumerProfile==='v25-manual'));
 assert.deepEqual(good.calls,['publishHandoff',['retire',500000,100],'delete-owned-builder','close']);
 for(const fault of ['cross-profile','mixed-plan','eof','unjoined','delayed']){
  const r=await run(fault,'v25-manual');assert(r.error);assert(!r.calls.includes('delete-owned-builder'));
 }
 await assert.rejects(worker.main(false,'v25-manual'),/NOT_ADMITTED/);
 assert.equal(worker.entryProfile(['--v25-manual-session']),'v25-manual');
 const r=require('node:child_process').spawnSync(process.execPath,[path.join(root,'tests/postgres/ownedPricingCoordinatorWorker.js'),'--v25-manual-session'],{input:'{}\n',encoding:'utf8',timeout:5000});
 assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'');
 for(const argv of [['--v25-manual-session','--v25-manual-session'],['--v25-manual-session','--v34-retained-session'],['--profile=v25-manual']])assert.throws(()=>worker.entryProfile(argv),/ARGUMENTS/);
 // Exercise the actual dedicated gate with only its literal forced closed;
 // no stream access, channel creation or owner-source read is allowed.
 const file=path.join(root,'tests/postgres/ownedPricingCoordinatorWorker.js');
 const source=fs.readFileSync(file,'utf8');assert.equal(source.split('const V25_LIVE_ENABLED=true;').length,2);
 const module={exports:{}},localRequire=require('node:module').createRequire(file);
 const guardedProcess={get stdin(){throw Error('unexpected input');},get stdout(){throw Error('unexpected output');}};
 require('node:vm').runInNewContext(source.replace('const V25_LIVE_ENABLED=true;','const V25_LIVE_ENABLED=false;'),
   {module,exports:module.exports,require:localRequire,process:guardedProcess,__dirname:path.dirname(file),__filename:file});
 await assert.rejects(module.exports.main(true,'v25-manual'),{code:'PRICING_WORKER_NOT_ADMITTED'});
});
test('missing, unjoined or mismatched owner messages never authorize builder deletion',async()=>{
 for(const fault of ['eof','unjoined','binding','delayed']){const r=await run(fault);assert(r.error);assert(!r.calls.includes('delete-owned-builder'));}
});
test('actual worker cannot publish clean terminal after swallowed journal failure',async()=>{
 const r=await run('journal');assert(r.error);const terminal=r.sent.find(x=>x.verb==='terminal');
 assert.equal(terminal.result.cleanupVerified,false);assert.equal(terminal.result.failure,'PRICING_JOURNAL_LIMIT');assert.deepEqual(terminal.result.cleanupErrors,['PRICING_JOURNAL_INCOMPLETE']);
});
test('actual pipe channel bounds stalled writes and rejects error/close and queued overflow',async()=>{
 const {PassThrough}=require('node:stream'),{EventEmitter}=require('node:events');
 for(const event of ['timeout','error','close']){
  const input=new PassThrough(),output=new EventEmitter();output.write=()=>false;
  const io=worker.channel(input,output,Date.now()+20,Date.now);
  const pending=io.send({a:1});
  if(event!=='timeout')output.emit(event,new Error('controlled'));
  await assert.rejects(pending);io.close();input.destroy();
 }
 const input=new PassThrough(),output=new EventEmitter();output.write=(_r,cb)=>cb();
 const io=worker.channel(input,output,Date.now()+1000,Date.now);
 input.write('{}\n');input.write(Buffer.alloc(262145));
 await assert.rejects(io.read());io.close();input.destroy();
});
test('forced closed and malformed actual worker entry cannot reach transport',async()=>{
 await assert.rejects(worker.main(false),{code:'PRICING_WORKER_NOT_ADMITTED'});
 const {spawnSync}=require('node:child_process');
 const result=spawnSync(process.execPath,[path.join(root,'tests/postgres/ownedPricingCoordinatorWorker.js')],{input:'{}\n',encoding:'utf8',timeout:5000});
 assert.equal(result.status,1);assert.equal(result.stdout,'');
 assert.equal(worker.V34_LIVE_ENABLED,true);
 assert.equal(worker.entryProfile([]),'v33');
 assert.equal(worker.entryProfile(['--v34-retained-session']),'v34-browser');
 for(const argv of [['--v34-retained-session','--v34-retained-session'],['--duration','3016'],['--profile=v34-browser']])assert.throws(()=>worker.entryProfile(argv),/ARGUMENTS/);
 const v34=spawnSync(process.execPath,[path.join(root,'tests/postgres/ownedPricingCoordinatorWorker.js'),'--v34-retained-session'],{input:'{}\n',encoding:'utf8',timeout:5000});
 assert.equal(v34.status,1);assert.equal(v34.stdout,'');assert.equal(v34.stderr,'');
});
function memoryJournal(fault){
 const files=new Map();let next=0,once=true;
 const io={openSync(name){const fd=++next;files.set(fd,{name,bytes:[]});return fd;},writeSync(fd,b,offset,size){if(fault==='write'&&once){once=false;throw Error('write');}files.get(fd).bytes.push(Buffer.from(b.subarray(offset,offset+size)));return size;},fsyncSync(){if(fault==='fsync'&&once){once=false;throw Error('fsync');}},closeSync(){if(fault==='close'&&once){once=false;throw Error('close');}}};
 return {record:worker.journal('/controlled',{io}),files};
}
test('finite full phase census fits 94 work and 37 independently reserved retirement records',async()=>{
 const {record,files}=memoryJournal();
 // 18 ordinary work phases (including checkpoint), one inner-only publication,
 // and image observation: 18*5 +3 +1. Seven cleanup phases plus export/final.
 for(let phase=0;phase<18;phase++)for(const kind of ['outer-intent','inner-intent','diagnostic','inner-result','outer-result'])await record(kind,{phase});
 for(const kind of ['intent','diagnostic','result','image-observation'])await record(kind,{});
 await assert.rejects(record('extra-work',{}),/JOURNAL_LIMIT/);
 record.beginRetirement();
 for(let phase=0;phase<7;phase++)for(const kind of ['outer-intent','inner-intent','diagnostic','inner-result','outer-result'])await record(kind,{phase});
 await record('retained-export-published',{});await record('result',{});
 assert.equal(files.size,131);assert.equal(record.status().used.retirement.count,37);
 await assert.rejects(record('extra-retirement',{}),/JOURNAL_LIMIT/);
});
test('normal encoded-byte overflow and write/fsync/close faults cannot poison reserved retirement',async()=>{
 for(const fault of ['write','fsync','close']){
  const {record}=memoryJournal(fault);await assert.rejects(record('phase-diagnostic','raw\n\n'));
  assert.equal(record.status().used.work.count,0);assert.equal(record.status().reserved.work.count,1);
  record.beginRetirement();for(let i=0;i<37;i++)await record('cleanup-evidence',{i});
  assert.equal(record.status().used.retirement.count,37);assert(record.status().failure);
 }
 const {record}=memoryJournal();await assert.rejects(record('phase-diagnostic','\0'.repeat(400000)),/JOURNAL_LIMIT/);
 assert.equal(record.status().reserved.work.count,0);record.beginRetirement();await record('cleanup',{});
 const bytes=memoryJournal();for(let i=0;i<12;i++)await bytes.record('result','x'.repeat(2*1024**2-100));
 await assert.rejects(bytes.record('diagnostic','x'.repeat(2000)),/JOURNAL_LIMIT/);
 bytes.record.beginRetirement();await bytes.record('cleanup',{});assert(bytes.record.status().failure);
 for(const value of ['"'.repeat(1100000),'\\'.repeat(1100000),'\n'.repeat(1100000),'é'.repeat(1048576),'x'.repeat(2*1024**2)]){
  const j=memoryJournal();await assert.rejects(j.record('diagnostic',value),/JOURNAL_LIMIT/);j.record.beginRetirement();await j.record('result',{cleanupVerified:false});assert(j.record.status().failure);
 }
});
