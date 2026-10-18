'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {createResponseCapture}=require('./postgres/secureshopMailActualTransport');
test('timeout retains bounded partial stream and data timing without marking successful completion',()=>{
 const call={startedAt:'start'},ticks=['headers','first','second','terminal'];let records=0;
 const capture=createResponseCapture(call,{now:()=>ticks.shift(),record:()=>records++});capture.headers(200);capture.data(Buffer.from('{"message":'));capture.data(Buffer.from('{"content":"partial'));capture.finish(false,'deadline');
 assert.equal(call.response,'{"message":{"content":"partial');assert.equal(call.headersAt,'headers');assert.equal(call.firstDataAt,'first');assert.equal(call.lastDataAt,'second');assert.equal(call.finishedAt,'terminal');assert.equal(call.responseChunkCount,2);assert.equal(call.responseComplete,false);assert.equal(call.terminalReason,'deadline');assert.equal(call.responseSha256,createHash('sha256').update(call.response).digest('hex'));assert.equal(records,2);
});
test('capture enforces byte bound and counts observed bytes separately without retaining excess',()=>{
 const call={},capture=createResponseCapture(call,{maxBytes:8});assert.equal(capture.data(Buffer.from('12345')),true);assert.equal(capture.data(Buffer.from('678901')),false);capture.finish(false,'bound');assert.equal(call.response,'12345678');assert.equal(call.responseBytes,8);assert.equal(call.responseObservedBytes,11);assert.equal(call.responseCaptureTruncated,true);assert.equal(call.responseComplete,false);
});
test('no-data timeout distinguishable from completed stream and close cannot overwrite terminal outcome',()=>{
 const empty={},e=createResponseCapture(empty);e.headers(200);e.finish(false,'deadline');assert.equal(empty.responseBytes,0);assert.equal(empty.responseChunkCount,0);assert.equal(empty.firstDataAt,undefined);assert.equal(empty.responseComplete,false);
 const full={},f=createResponseCapture(full);f.data(Buffer.from('done'));f.finish(true,'end');const snapshot=JSON.stringify(full);f.finish(false,'close');assert.equal(JSON.stringify(full),snapshot);assert.equal(full.responseComplete,true);
});
