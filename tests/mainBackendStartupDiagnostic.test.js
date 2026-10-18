'use strict';
const test=require('node:test'),assert=require('node:assert/strict');const {diagnostic,wrap}=require('./fixtures/mainBackendStartupDiagnostic.cjs');
test('diagnostics retain bounded code and source locations, never messages or credential frames',()=>{
 const error=Object.assign(Error('postgres://user:secret@host/private'),{code:'CTF_DELIVERY_ACTIVATION_UNAVAILABLE'});error.stack='Error: SECRET\n at invoke (/main/server/service.js:12:3)\n at postgres://user:secret@host/file.js:1:2\n at SECRET';
 const row=diagnostic(error,'/main');assert.equal(row.code,error.code);assert.deepEqual(row.frames,[{file:'server/service.js',line:12,column:3}]);assert(!JSON.stringify(row).includes('secret'));assert(!JSON.stringify(row).includes('SECRET'));error.code='PRIVATE_TOKEN';assert.equal(diagnostic(error).code,'UNCLASSIFIED_STARTUP_ERROR');
});
test('wrapper preserves receiver arguments result and original rejection before caller shutdown',async()=>{
 const receiver={},args=[{},{}],value={},error=Error('private'),events=[];
 assert.equal(await wrap(function(...actual){assert.equal(this,receiver);assert.deepEqual(actual,args);return value;},()=>assert.fail()).apply(receiver,args),value);
 await assert.rejects(wrap(()=>Promise.reject(error),()=>events.push('diagnostic'))().catch(e=>{events.push('caller');throw e;}),e=>e===error);assert.deepEqual(events,['diagnostic','caller']);
 assert.throws(()=>wrap(()=>{throw error;},()=>{throw Error('loggingfailed');})(),e=>e===error);
});
