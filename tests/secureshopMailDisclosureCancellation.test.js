'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {trackRequestCancellation}=require('./fixtures/secureshopMailDisclosureBrowser');
const invalid=()=>Error('Protocol error (Fetch.continueRequest): Invalid InterceptionId.');
function fixture(send){const cdp=new EventEmitter();cdp.send=send;const tracker=trackRequestCancellation(cdp);return{cdp,tracker};}
test('held response continuation succeeds without inventing cancellation',async()=>{const f=fixture(async(method,args)=>{assert.equal(method,'Fetch.continueRequest');assert.equal(args.requestId,'held');});try{assert.deepEqual(await f.tracker.release({requestId:'held',networkId:'n'}),{released:true,cancelled:false});}finally{f.tracker.close();}assert.equal(f.cdp.listenerCount('Network.loadingFailed'),0);});
test('invalid interception accepts only exact correlated canceled event before or after error',async()=>{for(const before of [true,false]){const f=fixture(async()=>{throw invalid();});try{if(before)f.cdp.emit('Network.loadingFailed',{requestId:'n',canceled:true});const work=f.tracker.release({requestId:'held',networkId:'n'});if(!before)setImmediate(()=>f.cdp.emit('Network.loadingFailed',{requestId:'n',canceled:true}));assert.deepEqual(await work,{released:false,cancelled:true,networkId:'n'});}finally{f.tracker.close();}}});
test('wrong identity, non-cancellation, missing identity and unrelated errors never become passes',async()=>{for(const mode of ['wrong','not-cancelled','missing','other']){const f=fixture(async()=>{throw mode==='other'?Error('CDP disconnected'):invalid();});try{f.cdp.emit('Network.loadingFailed',{requestId:mode==='wrong'?'other':'n',canceled:mode!=='not-cancelled'});await assert.rejects(f.tracker.release({requestId:'held',...(mode==='missing'?{}:{networkId:'n'})},{timeoutMs:10}));}finally{f.tracker.close();}}});

test('Network enable rejection still removes tracker and detaches owned CDP session',async()=>{
 const {qualifyDisclosureInFrame}=require('./fixtures/secureshopMailDisclosureBrowser');const cdp=new EventEmitter(),failure=Error('Network enable rejected');let detached=false,clicked=false;
 cdp.send=async method=>{if(method==='Network.enable')throw failure;assert.equal(method,'Fetch.disable');};cdp.detach=async()=>{detached=true;};
 const page=new EventEmitter();page.createCDPSession=async()=>cdp;
 await assert.rejects(qualifyDisclosureInFrame({page,frame:{},origin:'http://owned.invalid',root:'/unused',click:async()=>{clicked=true;},observations:{personas:async()=>({student_merchant:{id:1},student_customer:{id:2}})}}),error=>error===failure);
 assert.equal(detached,true);assert.equal(cdp.listenerCount('Network.loadingFailed'),0);assert.equal(clicked,false);
});
