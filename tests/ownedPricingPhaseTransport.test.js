'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {EventEmitter}=require('node:events'),{PassThrough}=require('node:stream');
const api=require('./postgres/ownedPricingPhaseTransport');
const root=path.resolve(__dirname,'..');
function harness(){
 let now=0,args;const timers=[];const child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();
 const execute=api.createExecutor({randomToken:()=> 'a'.repeat(64),launch:(_exe,a)=>{args=a;return child;},now:()=>now,
  setTimer:(fn,ms)=>{const t={fn,at:now+ms};timers.push(t);return t;},clearTimer:t=>{t.off=true;}});
 const plan={commands:{build:'true'},binding:{base:'sha256:abc'},spec:{root,lima:'/not-executed',guest:'/owned',runId:'a'.repeat(32),limaHome:path.join(root,'tasks/runtime/lima')}};
 return {child,execute,plan,args:()=>args,advance:async n=>{now=n;for(const t of timers)if(!t.off&&t.at<=now){t.off=true;t.fn();}await Promise.resolve();}};
}
test('74 fragmented diagnostic lines including blanks aggregate once without ACK or byte loss',async()=>{
 const h=harness(),saved=[],p=h.execute(h.plan,'build',{deadline:30000,diagnosticSink:b=>saved.push(b)});
 const raw=Array.from({length:74},(_,i)=>i%5===0?'\n':`diagnostic ${i} é\n`).join('');
 for(const byte of Buffer.from(raw))h.child.stderr.write(Buffer.from([byte]));
 h.child.stderr.write('DVAIA_PRICING_DONE:'+'a'.repeat(64)+':0\n');h.child.emit('close',0,null);
 await p;assert.equal(saved.length,1);assert.equal(saved[0].toString(),raw);
 const tail=harness(),parts=[],q=tail.execute(tail.plan,'build',{deadline:30000,diagnosticSink:b=>parts.push(b)});
 tail.child.stderr.write('DVAIA_PRICING_DONE:'+'a'.repeat(64)+':0\nunterminated');tail.child.emit('close',0,null);
 await q;assert.equal(Buffer.concat(parts).toString(),'unterminated');
});
test('remaining deadline is propagated into remote timeout and success joins output',async()=>{
 const h=harness(),p=h.execute(h.plan,'build',{deadline:300000});
 assert.equal(h.args()[h.args().indexOf('owned-pricing-envelope')+1],'284');
 h.child.stdout.write('ok');h.child.stderr.write('DVAIA_PRICING_DONE:'+'a'.repeat(64)+':0\n');h.child.emit('close',0,null);assert.equal(await p,'ok');
 const none=harness();await assert.rejects(none.execute(none.plan,'build',{deadline:16000}),/BUDGET/);assert.equal(none.args(),undefined);
});
test('lost local reply waits known remote timeout and unresolved child becomes debt',async()=>{
 const h=harness(),p=h.execute(h.plan,'build',{deadline:30000});let settled=false;p.catch(()=>{settled=true;});
 h.child.emit('close',1,null);await h.advance(23000);assert.equal(settled,false);
 await h.advance(24000);await assert.rejects(p,e=>e.code==='PRICING_REMOTE_ACK_MISSING'&&e.retirementUnproven===true);
 const u=harness(),pending=u.execute(u.plan,'build',{deadline:30000});
 await u.advance(30000);await assert.rejects(pending,e=>e.retirementUnproven===true);
});
test('exact remote completion acknowledges nonzero exit without renewing uncertainty',async()=>{
 const h=harness(),p=h.execute(h.plan,'build',{deadline:30000});
 await h.advance(20000);h.child.stderr.write('DVAIA_PRICING_DONE:'+'a'.repeat(64)+':1\n');h.child.emit('close',1,null);
 await assert.rejects(p,e=>e.code==='PRICING_REMOTE_PHASE_FAILED'&&!e.retirementUnproven);
 for(const kind of ['wrong','duplicate','timeout']){
  const x=harness(),q=x.execute(x.plan,'build',{deadline:30000});q.catch(()=>{});await x.advance(20000);
  const code=kind==='timeout'?124:1,token=(kind==='wrong'?'b':'a').repeat(64);
  x.child.stderr.write('DVAIA_PRICING_DONE:'+token+':'+code+'\n');
  if(kind==='duplicate')x.child.stderr.write('DVAIA_PRICING_DONE:'+token+':'+code+'\n');
  x.child.emit('close',code,null);await x.advance(30000);await assert.rejects(q,e=>e.retirementUnproven===true);
 }
});
test('uncertainty stays sticky when early nonzero-time close misses the original wakeup',async()=>{
 for(const kind of ['missing','wrong','duplicate','timeout']){
  const h=harness(),p=h.execute(h.plan,'build',{deadline:30000});p.catch(()=>{});
  await h.advance(1000);const code=kind==='timeout'?124:1;
  if(kind!=='missing')h.child.stderr.write('DVAIA_PRICING_DONE:'+(kind==='wrong'?'b':'a').repeat(64)+':'+code+'\n');
  if(kind==='duplicate')h.child.stderr.write('DVAIA_PRICING_DONE:'+'a'.repeat(64)+':'+code+'\n');
  h.child.emit('close',code,null);
  await h.advance(24000);await h.advance(30000);
  await assert.rejects(p,e=>e.retirementUnproven===true);
 }
});
test('wrong completion marker cannot be laundered by a valid marker in either order',async()=>{
 for(const tokens of [['b','a'],['a','b']]){
  const h=harness(),p=h.execute(h.plan,'build',{deadline:30000});p.catch(()=>{});
  await h.advance(1000);
  for(const token of tokens)h.child.stderr.write('DVAIA_PRICING_DONE:'+token.repeat(64)+':0\n');
  h.child.emit('close',0,null);await h.advance(24000);await h.advance(30000);
  await assert.rejects(p,e=>e.code==='PRICING_REMOTE_ACK'&&e.retirementUnproven===true);
 }
});
test('actual shell envelope preserves phase status and emits exact completion after child exit',async()=>{
 const {spawnSync}=require('node:child_process');
 for(const code of [0,1,37]){
  const h=harness(),p=h.execute(h.plan,'build',{deadline:30000});
  const args=h.args(),index=args.indexOf('owned-pricing-envelope'),wrapper=args[index-1];
  // Controlled local timeout stand-in only; actual shell positional quoting and
  // completion emitter execute, without limactl, VM, network or resource creation.
  const result=spawnSync('/bin/sh',['-c','timeout(){ shift; shift; shift; "$@"; };\n'+wrapper,'owned-pricing-envelope','14','exit '+code,'/owned',h.plan.spec.runId,'','a'.repeat(64)],{encoding:'utf8',timeout:2000});
  assert.equal(result.status,code);assert.equal(result.stderr,'\nDVAIA_PRICING_DONE:'+'a'.repeat(64)+':'+code+'\n');
  h.child.stderr.write(result.stderr);h.child.emit('close',code,null);
  if(code)await assert.rejects(p,e=>e.code==='PRICING_REMOTE_PHASE_FAILED'&&!e.retirementUnproven);else assert.equal(await p,'');
 }
});
test('pending sink cannot yield clean retirement and late completion cannot change rejection',async()=>{
 const h=harness();let release;const p=h.execute(h.plan,'build',{deadline:30000,sink:()=>new Promise(r=>{release=r;})});
 h.child.stdout.write('x');await Promise.resolve();h.child.emit('close',0,null);
 await h.advance(30000);await assert.rejects(p,e=>e.retirementUnproven===true);release();await Promise.resolve();
});
test('late local failure cannot turn the original spawn time into remote retirement proof',async()=>{
 const h=harness(),p=h.execute(h.plan,'build',{deadline:30000});
 await h.advance(20000);h.child.emit('close',1,null);await h.advance(30000);
 await assert.rejects(p,e=>e.retirementUnproven===true);
});
test('export is exclusive and only durable after bounded write fsync close and inode readback',async()=>{
 const id=require('node:crypto').randomBytes(16).toString('hex'),file=path.join(root,'tasks/tmp','pricing-retained-'+id+'.tar');
 const e=api.createExport(root,id);
 try{await e.sink(Buffer.from('archive'));assert.throws(()=>api.createExport(root,id),/EEXIST/);
  const receipt=e.finish();assert.equal(receipt.bytes,7);assert.equal(receipt.durable,true);assert.equal(fs.readFileSync(file,'utf8'),'archive');
  await assert.rejects(e.sink(Buffer.from('late')),/CLOSED/);
 }finally{e.close();fs.unlinkSync(file);}
});
test('fsync and close failures never publish export proof',async()=>{
 for(const method of ['fsyncSync','closeSync']){
  const id=require('node:crypto').randomBytes(16).toString('hex'),file=path.join(root,'tasks/tmp','pricing-retained-'+id+'.tar');let injected=false;
  const io=new Proxy(fs,{get(target,key){if(key===method)return(...args)=>{if(!injected){injected=true;if(key==='closeSync')fs.closeSync(...args);throw Error('injected '+key);}return target[key](...args);};return target[key];}});
  const e=api.createExport(root,id,{io});try{await e.sink(Buffer.from('x'));assert.throws(()=>e.finish(),/injected/);}finally{e.close();fs.unlinkSync(file);}
 }
});
