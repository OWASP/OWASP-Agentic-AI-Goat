'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createAdmittedPlatformSessionFence:create}=require('../server/agent-runtime/admittedPlatformSession');
const req=()=>({headers:{authorization:'Bearer private-test'},user:{id:7},identitySession:{id:11}}),valid=()=>({user:{id:7},session:{id:11,user_id:7}});
test('exact private token/owner/session cannot be replaced and missing authority rejects',async()=>{
 let live=valid(),seen=[];const request=req(),f=create(request,{validateSession:async token=>{seen.push(token);return live;}});request.headers.authorization='Bearer replacement';await f.check();assert.deepEqual(seen,['private-test']);assert.equal(JSON.stringify(f).includes('private-test'),false);
 for(const value of [null,{user:{id:8},session:{id:11,user_id:8}},{user:{id:7},session:{id:12,user_id:7}},{user:{id:7},session:{id:11,user_id:8}}]){live=value;await assert.rejects(f.check(),{code:'SESSION_REVOKED'});}
 for(const value of [{...req(),identitySession:null},{...req(),user:null},{...req(),rawHeaders:['Authorization','Bearer a','Authorization','Bearer b']},{...req(),headers:{authorization:'Bearer a,b'}}])assert.throws(()=>create(value,{validateSession:async()=>valid()}));assert.throws(()=>create(req(),{}));
});
test('wrapped effects preserve receiver,args,callback,result,signal and errors; fences do not roll back committed work',async()=>{
 let live=valid(),count=0;const abort=new AbortController(),originalError=Error('original');const execution={signal:abort.signal,context:{value:1},check:async()=>{},effect:async function(...args){assert.equal(this,execution);assert.equal(args[0],'key');assert.equal(args[2],42);return args[1]();}};
 const f=create(req(),{validateSession:async()=>live}),wrapped=f.wrap(execution);assert.equal(wrapped.signal,abort.signal);assert.equal(wrapped.context,execution.context);assert.equal(await wrapped.effect('key',async()=>{count++;return 3;},42),3);
 live=null;await assert.rejects(wrapped.effect('key',async()=>{count++;},42));assert.equal(count,1);
 live=valid();await assert.rejects(wrapped.effect('key',async()=>{count++;live=null;return 4;},42),{code:'SESSION_REVOKED'});assert.equal(count,2,'completed callback is not rolled back');
 live=valid();await assert.rejects(wrapped.effect('key',async()=>{throw originalError;},42),error=>error===originalError);execution.check=async()=>{throw originalError;};await assert.rejects(wrapped.check(),error=>error===originalError);
});

test('revocation during ledger admission blocks callback and callback receiver/arguments remain intact',async()=>{
 let live=valid(),called=0;const callbackThis={bound:true};const execution={check:async()=>{},effect:async function(key,callback){live=null;return callback.call(callbackThis,42);},checkpoint:async function(node){assert.equal(this,execution);assert.equal(node,'node');return 'checkpoint';}};
 const wrapped=create(req(),{validateSession:async()=>live}).wrap(execution);await assert.rejects(wrapped.effect('key',function(){called++;}),{code:'SESSION_REVOKED'});assert.equal(called,0);
 live=valid();execution.effect=async function(key,callback){return callback.call(callbackThis,42);};const fresh=create(req(),{validateSession:async()=>live}).wrap(execution);assert.equal(await fresh.effect('key',function(value){assert.equal(this,callbackThis);return value;}),42);assert.equal(await fresh.checkpoint('node'),'checkpoint');
});
