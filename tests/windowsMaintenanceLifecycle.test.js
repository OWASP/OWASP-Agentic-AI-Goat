'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {superviseWindows}=require('../scripts/application-journal-bound-maintenance');
const {awaitWindowsMaintenanceActivation,completeWindowsMaintenance}=require('../scripts/lib/windows-maintenance-activation');
const tick=()=>new Promise(r=>setImmediate(r));
function fixture(overrides={}){
 const child=new EventEmitter();Object.assign(child,{pid:12345,connected:true,disconnect(){this.connected=false;events.push('disconnect');},send(message,callback){messages.push(message);callback?.();if(message.type==='journal-bound-completion-approved')setImmediate(()=>{child.emit('exit',0,null);child.emit('close',0);});}});
 const events=[],messages=[];let admitResolve,admitReject,failureReject,drainResolve;
 const admission=new Promise((r,j)=>{admitResolve=r;admitReject=j;}),failure=new Promise((_,j)=>{failureReject=j;});
 const job={failure,admitGuardian(c){assert.equal(c,child);events.push('admit');return admission;},async assertGuardianOnly(){events.push('only');},expectGuardianExit(){events.push('expected');},async waitForDrain(){events.push('drain');if(overrides.holdDrain)await new Promise(r=>{drainResolve=r;});},async stop(){events.push('stop');},async close(){events.push('close');},...overrides.job};
 const installation={installationRoot:'/installation',bindingSha256:'binding',assertCurrent(){events.push('installation');}};
 const run=()=>superviseWindows({prospective:true,installation,environment:{},createJob:async()=>job,spawn(node,args,options){assert.equal(args[1],'--owned-prospective-original');assert.equal(options.detached,false);return child;},timeoutMs:1000,joinMs:50});
 const ready=()=>child.emit('message',{type:'prospective-original-ready',nonce:'11111111-1111-4111-8111-111111111111',childPid:child.pid,parentPid:process.pid,installationBinding:'binding'});
 const complete=(extra={})=>child.emit('message',{type:'journal-bound-complete',completed:true,nonce:'a'.repeat(64),...extra});
 return{child,events,messages,run,ready,complete,admitResolve,admitReject,failureReject,releaseDrain:()=>drainResolve()};
}
test('native admission precedes grant; completion requires guardian-only, expected exit, drain and close',async()=>{
 const f=fixture({holdDrain:true});let finished=false;const work=f.run().then(()=>{finished=true;});await tick();f.ready();await tick();assert.equal(f.messages.length,0);f.admitResolve();await tick();assert.equal(f.messages[0].type,'prospective-original-grant');f.complete();await tick();await tick();assert.equal(finished,false);assert.deepEqual(f.events.slice(-3),['only','expected','drain']);f.releaseDrain();await work;assert.equal(finished,true);assert.equal(f.events.at(-1),'close');
});
test('native foreign descendants prevent completion approval and require owned stop',async()=>{
 const f=fixture({job:{async assertGuardianOnly(){throw Error('foreign identity');}}});const work=f.run();await tick();f.admitResolve();f.ready();await tick();f.complete();await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert(!f.messages.some(m=>m.type==='journal-bound-completion-approved'));assert(f.events.includes('stop'));assert.equal(f.events.at(-1),'close');
});
test('cancel during admission revokes IPC and joins late assignment before stopping',async()=>{
 const f=fixture();const work=f.run();await tick();f.child.emit('message',{type:'journal-bound-failed',code:'APPLICATION_MAINTENANCE_PREPARATION_INVALID'});await tick();assert(!f.events.includes('stop'));f.admitResolve();await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT',diagnosticCode:'APPLICATION_MAINTENANCE_PREPARATION_INVALID'});assert(f.events.indexOf('disconnect')<f.events.indexOf('stop'));
});
test('failed assignment and helper lifetime cannot succeed from a fabricated completion',async()=>{
 for(const lifetime of [false,true]){const f=fixture();const work=f.run();await tick();if(lifetime){f.admitResolve();await tick();f.failureReject(Error('helper unavailable'));}else f.admitReject(Error('assignment denied'));f.complete();await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert(!f.messages.some(m=>m.type==='journal-bound-completion-approved'));assert.equal(f.events.at(-1),'close');}
});
test('unexpected exit, malformed completion, and cleanup failure all reject',async()=>{
 for(const mode of ['exit','malformed','cleanup']){const f=fixture(mode==='cleanup'?{job:{async close(){throw Error('unverified release');}}}:{});const work=f.run();await tick();f.admitResolve();f.ready();await tick();if(mode==='exit'){f.child.emit('exit',0,null);f.child.emit('close',0);}else f.complete(mode==='malformed'?{secret:'forbidden'}:{});await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});}
});
function runtime(){const r=new EventEmitter();Object.assign(r,{pid:42,connected:true,messages:[],send(m,callback){r.messages.push(m);callback?.();}});return r;}
test('cooperative child starts only after exact challenge/nonce activation acknowledgment',async()=>{
 const r=runtime();let active=false;const work=awaitWindowsMaintenanceActivation({runtime:r,timeoutMs:100}).then(()=>{active=true;});r.emit('message',{type:'dvaia-owned-guardian-hello'});const challenge=r.messages[0].challenge;assert.equal(active,false);r.emit('message',{type:'dvaia-owned-guardian-probe',challenge,nonce:'b'.repeat(64)});assert.equal(active,false);r.emit('message',{type:'dvaia-owned-guardian-activate',challenge,nonce:'b'.repeat(64)});await work;assert.equal(active,true);
});
test('child denies early work, malformed activation, disconnect and send failure',async()=>{
 for(const mode of ['early','malformed','disconnect','send']){const r=runtime();if(mode==='send')r.send=(m,callback)=>callback(Error());const work=awaitWindowsMaintenanceActivation({runtime:r,timeoutMs:30});if(mode==='early')r.emit('message',{type:'prospective-original-grant'});else if(mode==='disconnect')r.emit('disconnect');else if(mode==='malformed')r.emit('message',{type:'dvaia-owned-guardian-hello',extra:true});else r.emit('message',{type:'dvaia-owned-guardian-hello'});await assert.rejects(work,{code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'});}
});
test('child completion awaits exact nonce approval; mismatched approval denies',async()=>{
 for(const match of [true,false]){const r=runtime();let complete=false;const work=completeWindowsMaintenance({runtime:r,timeoutMs:100}).then(()=>{complete=true;});assert.equal(complete,false);r.emit('message',{type:'journal-bound-completion-approved',nonce:match?r.messages[0].nonce:'c'.repeat(64)});if(match){await work;assert.equal(complete,true);}else await assert.rejects(work,{code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'});}
});
test('admission timeout is bounded, revokes IPC, and never grants work',async()=>{
 const f=fixture();const started=Date.now(),work=f.run();await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert(Date.now()-started<500);assert(f.events.includes('disconnect'));assert.equal(f.messages.length,0);assert.equal(f.events.at(-1),'close');
});
test('failure during guardian-only observation cannot approve completion afterward',async()=>{
 let release;const f=fixture({job:{async assertGuardianOnly(){await new Promise(r=>{release=r;});}}});const work=f.run();await tick();f.admitResolve();f.ready();await tick();f.complete();await tick();f.child.emit('message',{type:'journal-bound-failed',code:'APPLICATION_MAINTENANCE_PREPARATION_INVALID'});release();await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert(!f.messages.some(m=>m.type==='journal-bound-completion-approved'));
});
