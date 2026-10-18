'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const x=require('./postgres/ctfStage9ActualTransport');
const body=patch=>Buffer.from(JSON.stringify({model:x.MODEL,stream:true,prompt:'owned synthetic control',options:{temperature:0.7,num_predict:1000},...patch}));
test('generate/chat only exact model and finite canonical generation limits',()=>{
 assert.equal(x.validateRequest('POST','/api/generate',body()),'generate');assert.equal(x.validateRequest('POST','/api/chat',body({prompt:undefined,messages:[{role:'user',content:'x'}]})),'chat');
 for(const change of [{model:'other'},{options:{temperature:0,num_predict:1001}},{options:{temperature:0,num_predict:-1}},{options:{temperature:1,num_predict:100}},{options:{temperature:0,num_predict:100,num_ctx:32769}},{options:{temperature:0,num_predict:100,unknown:true}}])assert.throws(()=>x.validateRequest('POST','/api/generate',body(change)));
 for(const route of ['/api/pull','/api/show','/v1/chat/completions'])assert.throws(()=>x.validateRequest('POST',route,body()));
});
test('twenty upstream attempts including metadata and separate incoming cap',()=>{const b=x.budget();b.reserve('metadata');for(let n=0;n<19;n++)b.reserve('generate');assert.throws(()=>b.reserve('chat'));for(let n=0;n<20;n++)b.incoming();assert.throws(()=>b.incoming());assert.equal(b.counts.external,20);});
test('digest, stop/model and post-parse absolute deadline mandatory',()=>{
 const row={status:200,responseComplete:true,responseCaptureTruncated:false,kind:'generate',response:JSON.stringify({model:x.MODEL,done:true,done_reason:'stop',response:'x'})};x.validateResponse(row);
 for(const done_reason of ['length',null])assert.throws(()=>x.validateResponse({...row,response:JSON.stringify({model:x.MODEL,done:true,done_reason})}));
 assert.throws(()=>x.validateResponse({...row,kind:'metadata',response:JSON.stringify({models:[{name:x.MODEL,digest:'bad'}]})}));let count=0;assert.throws(()=>x.validateTimedResponse(row,10,()=>++count===1?9:11));
});
test('wire size preflight includes escaped UTF8 content exactly and upstream capability defaults closed',()=>{const v={a:'\n"🦉',calls:[{x:'x'}]};assert.equal(x.serializedBytes(v),Buffer.byteLength(JSON.stringify(v)));assert.equal(x.allowsUpstream(),false);});
test('physical drain waits for owned close events and rejects unconfirmed shutdown',async()=>{
 const {EventEmitter}=require('node:events');const owned=new EventEmitter();let destroyed=false;owned.destroy=()=>{destroyed=true;};let done=false;const pending=x.closeOwned([owned],[],50).then(()=>{done=true;});await Promise.resolve();assert(destroyed);assert.equal(done,false);owned.emit('close');await pending;assert(done);
 const hung=new EventEmitter();hung.destroy=()=>{};await assert.rejects(x.closeOwned([hung],[],5),/Physical close deadline/);
});
test('checkpoint time cannot permit expired upstream dispatch',()=>{let now=9,dispatches=0;const deadline=10;now+=2;assert.throws(()=>{x.assertDispatchDeadline(deadline,()=>now);dispatches++;});assert.equal(dispatches,0);});
