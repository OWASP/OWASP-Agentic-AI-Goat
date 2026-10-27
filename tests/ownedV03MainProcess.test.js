'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03MainProcess'),'utf8');
const make=new Function('handles','fail',source.slice(source.indexOf('function handleFor('),source.indexOf('async function createMainProcess('))+';return handleFor;')(new WeakMap(),code=>Object.assign(Error(code),{code}));
function fixture(){
 const main={identity:{pid:100,ppid:50,pgid:100,uid:1,birth:[1,2]},argv:['python','MAIN']};
 const browser={identity:{pid:200,ppid:100,pgid:200,uid:1,birth:[2,3]},argv:['node','--require','barrier']};
 const calls=[],control={pending:new Set(),debts:[],observe:async request=>{calls.push(request);
  return request.op==='inspect'?{observed:request.pid===100?main:browser}:{groupAbsent:true};}};
 return {main,browser,calls,control,handle:make({pid:100},{},control,main)};
}
test('browser attach independently observes exact MAIN and browser birth',async()=>{
 const f=fixture();await f.handle.attachBrowser(f.browser.identity);
 assert.deepEqual(f.calls.map(x=>x.pid),[100,200]);
 await f.handle.requireBrowserAbsent();assert.equal(f.calls.at(-1).op,'retire');
});
test('foreign birth does not become browser retirement authority',async()=>{
 const f=fixture();await assert.rejects(f.handle.attachBrowser({...f.browser.identity,birth:[99,99]}),{code:'V03_MAIN_BROWSER_CHANGED'});
 await f.handle.retire();assert.deepEqual(f.calls.filter(x=>x.op==='retire').map(x=>x.pid),[100]);
});
test('retirement joins browser before MAIN and is once-only',async()=>{
 const f=fixture();await f.handle.attachBrowser(f.browser.identity);
 const first=f.handle.retire();assert.equal(first,f.handle.retire());assert.equal((await first).groupAbsent,true);
 assert.deepEqual(f.calls.filter(x=>x.op==='retire').map(x=>x.pid),[200,100]);
});
test('outstanding helper or retained control debt prevents successful retirement',async()=>{
 for(const kind of ['pending','debts']){
  const f=fixture();if(kind==='pending')f.control.pending.add({pid:300});else f.control.debts.push('unjoined');
  await assert.rejects(f.handle.retire(),{code:'V03_MAIN_RETIREMENT_UNPROVEN'});
 }
});
test('production factory remains closed and receipts cannot forge process identity',async()=>{
 const api=require('./postgres/ownedV03MainProcess');
 await assert.rejects(api.createMainProcess(),{code:'V03_MAIN_PROCESS_NOT_ADMITTED'});
 assert.throws(()=>api.assertMainProcess({groupAbsent:true}),{code:'V03_MAIN_PROCESS_REQUIRED'});
});
function inspectFixture(mode){
 const {EventEmitter}=require('node:events');let child,timed;
 const journal=[];
 const launch=()=>{
  if(mode==='launch')throw Error('spawn failed');
  child=new EventEmitter();child.pid=4321;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.stdin=new EventEmitter();
  child.stdin.end=()=>{};return child;
 };
 const fragment=source.slice(source.indexOf('function inspector('),source.indexOf('function handleFor('));
 const factory=new Function('spawn','path','fail','setTimeout','clearTimeout',fragment+';return inspector;')(
  launch,require('node:path'),code=>Object.assign(Error(code),{code}),callback=>{timed=callback;return 1;},()=>{});
 const control=factory('/synthetic','/fixed-python','a'.repeat(64),journal);
 return {control,journal,child:()=>child,timeout:()=>timed()};
}
test('fixed inspector retains launch failure without an absence claim',async()=>{
 const f=inspectFixture('launch');await assert.rejects(f.control.observe({}),e=>e.cleanupDebt===true);
 assert.equal(f.journal[0].closed,false);assert.equal(f.control.debts.length,1);
});
test('helper timeout never signals unknown identity and late close cannot clear debt',async()=>{
 const f=inspectFixture(),pending=f.control.observe({});f.timeout();
 await assert.rejects(pending,{code:'V03_PROCESS_CONTROL_UNJOINED'});
 assert.equal(f.control.pending.size,1);
 f.child().emit('close',1,null);await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.control.pending.size,0);assert.equal(f.control.debts.length,1);
});
test('helper terminal with foreign controller identity is not proof',async()=>{
 const f=inspectFixture(),pending=f.control.observe({});
 f.child().stdout.emit('data',Buffer.from(JSON.stringify({version:1,controller:{pid:999},result:{groupAbsent:true}})));
 f.child().emit('close',0,null);
 await assert.rejects(pending,{code:'V03_PROCESS_CONTROL_IDENTITY'});assert.equal(f.control.debts.length,1);
});
const terminalFactory=new Function(source.slice(source.indexOf('function childTerminal('),source.indexOf('function handleFor('))+';return childTerminal;')();
test('actual terminal observer captures early child failure separately from process absence',async()=>{
 const {EventEmitter}=require('node:events'),child=new EventEmitter();child.pid=10;
 const terminal=terminalFactory(child,()=>100);child.emit('error',Object.assign(Error('spawn'),{code:'EACCES'}));child.emit('close',1,null);
 assert.deepEqual(await terminal.done,{pid:10,closed:true,code:1,signal:null,spawnFailure:'EACCES',observedAtMs:100});
 assert.equal(terminal.snapshot().code,1);
});
test('live child terminal stays pending and cannot be inferred from a successful identity probe',()=>{
 const {EventEmitter}=require('node:events'),child=new EventEmitter();child.pid=10;
 const terminal=terminalFactory(child);assert.equal(terminal.snapshot().closed,false);assert.equal(terminal.snapshot().code,null);
});
function timeoutFixture(mode){
 let now=1800000,closed=false;const calls=[],timers=[];
 const owner={nowMs:()=>now,wrapperWindow:()=>({deadlineMs:1800000,graceDeadlineMs:2100000}),binding:()=>({expiresAtMs:11096000})};
 let resolve;const done=new Promise(r=>{resolve=r;});
 const terminal={done,snapshot:()=>({closed,code:closed?0:null})};
 const control={pending:new Set(),debts:[],observe:async request=>{
  calls.push([request.op,now]);
  if(mode==='unknown')throw Object.assign(Error('changed'),{code:'V03_PROCESS_CHANGED'});
  now+=1000;
  if(request.op==='kill'||mode==='term-exit'){closed=true;resolve({closed:true,code:0});}
  return {groupAbsent:false};
 }};
 const handle=make({pid:100},{},control,{identity:{pid:100},argv:['MAIN']},terminal,owner,
  (callback,delay)=>{timers.push(delay);queueMicrotask(()=>{now+=delay;callback();});return 1;},()=>{});
 return {handle,calls,timers,setNow:n=>{now=n;}};
}
test('timeout preserves absolute 300 second grace and fixed forced-join boundary',async()=>{
 const f=timeoutFixture(),result=await f.handle.shutdownTimedOutWork();
 assert.deepEqual(f.calls,[['term',1800000],['kill',2100000]]);
 assert.deepEqual(f.timers,[299000]);assert.equal(result.timedOut,true);assert.equal(result.qualificationComplete,false);
});
test('TERM exit stays failed and does not invoke KILL',async()=>{
 const f=timeoutFixture('term-exit');assert.equal((await f.handle.shutdownTimedOutWork()).timedOut,true);
 assert.deepEqual(f.calls.map(x=>x[0]),['term']);
});
test('late callback cannot renew KILL allowance and unknown identity cannot progress',async()=>{
 const late=timeoutFixture();late.setNow(2121000);
 await assert.rejects(late.handle.shutdownTimedOutWork(),{code:'V03_MAIN_SIGNAL_RESERVE'});assert.deepEqual(late.calls,[]);
 const unknown=timeoutFixture('unknown');await assert.rejects(unknown.handle.shutdownTimedOutWork(),e=>e.cleanupDebt&&e.code==='V03_PROCESS_CHANGED');
 assert.equal(unknown.calls.length,1);
});
