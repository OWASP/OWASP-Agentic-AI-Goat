'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {EventEmitter}=require('node:events');
const {createSystemDiagnosticHttpListener,runSystemDiagnosticListener}=require('../sidecars/sandbox-runner/owned-system/diagnostic-http-listener');
const token='x'.repeat(43);const base={enabled:true,token,host:'127.0.0.1',port:0};
test('explicit enable/configuration and actual readiness are required before bind',async()=>{
 assert.throws(()=>createSystemDiagnosticHttpListener({...base,enabled:false}));assert.throws(()=>createSystemDiagnosticHttpListener({...base,host:'example.com'}));
 const listener=createSystemDiagnosticHttpListener({...base,executor:{assertReady:async()=>{throw Error('private detail');},executeBound:async()=>{}}});await assert.rejects(listener.start(),{code:'SYSTEM_DIAGNOSTIC_LISTENER_NOT_READY'});assert.equal(listener.address(),null);await listener.close();
});
test('real controlled loopback readiness, wrong bearer and close are bounded',async()=>{
 let probes=0;const listener=createSystemDiagnosticHttpListener({...base,executor:{assertReady:async()=>{probes++;},executeBound:async()=>{throw Error('unexpected');}}});
 try{const address=await listener.start();const origin='http://127.0.0.1:'+address.port;const response=await fetch(origin+'/secureshop/system/diagnostic-health',{headers:{authorization:'Bearer '+token}});assert.equal(response.status,200);assert.equal((await response.json()).ready,true);assert.equal(probes,2);assert.equal((await fetch(origin+'/secureshop/system/diagnostic-health')).status,401);}finally{await listener.close();}assert.equal(listener.address(),null);await listener.close();await assert.rejects(listener.start());
});
test('close aborts and joins startup readiness without late bind',async()=>{
 let entered,joined=false;const enteredPromise=new Promise(r=>entered=r);const listener=createSystemDiagnosticHttpListener({...base,executor:{assertReady:async({signal})=>{entered();await new Promise(r=>signal.addEventListener('abort',r,{once:true}));joined=true;signal.throwIfAborted();},executeBound:async()=>{}}});
 const startup=listener.start().catch(error=>error);await enteredPromise;await listener.close();assert.equal(joined,true);assert.equal(listener.address(),null);assert.ok(await startup instanceof Error);
});
test('CLI signals invoke one joined close and logs contain no configured secret',async()=>{
 const signals=new EventEmitter();let closes=0;const output=[];
 const work=runSystemDiagnosticListener({env:{SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED:'true',SECURESHOP_SYSTEM_DIAGNOSTIC_PORT:'8091',SECURESHOP_SYSTEM_DIAGNOSTIC_HOST:'127.0.0.1',SECURESHOP_SYSTEM_DIAGNOSTIC_TOKEN:token},signals,createListener:()=>({start:async()=>{setImmediate(()=>{signals.emit('SIGTERM');signals.emit('SIGINT');});},close:async()=>{closes++;}}),write:text=>output.push(text)});
 assert.equal(await work,0);assert.equal(closes,1);assert.ok(!output.join('').includes(token));assert.equal(signals.listenerCount('SIGTERM'),0);
});
test('startup timeout cannot report clean close while original readiness remains active',async()=>{
 let release,aborted=false;const listener=createSystemDiagnosticHttpListener({...base,readinessTimeoutMs:10,closeTimeoutMs:20,executor:{assertReady:async({signal})=>{signal.addEventListener('abort',()=>{aborted=true;},{once:true});await new Promise(resolve=>release=resolve);},executeBound:async()=>{}}});
 try{await assert.rejects(listener.start(),{code:'SYSTEM_DIAGNOSTIC_LISTENER_NOT_READY'});assert.equal(aborted,true);await assert.rejects(listener.close(),{code:'SYSTEM_DIAGNOSTIC_LISTENER_DRAIN_FAILED'});assert.equal(listener.address(),null);}finally{release?.();}
});
test('close waits for original readiness settling after startup timeout',async()=>{
 let release;const listener=createSystemDiagnosticHttpListener({...base,readinessTimeoutMs:10,closeTimeoutMs:200,executor:{assertReady:async()=>{await new Promise(resolve=>release=resolve);},executeBound:async()=>{}}});
 await assert.rejects(listener.start());let closed=false;const closing=listener.close().then(()=>{closed=true;});await new Promise(resolve=>setTimeout(resolve,20));assert.equal(closed,false);release();await closing;assert.equal(closed,true);assert.equal(listener.address(),null);
});
