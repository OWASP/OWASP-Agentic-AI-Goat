'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const file=path.resolve(__dirname,'postgres/secureshopV23Original.integration.test.js');
const source=fs.readFileSync(file,'utf8');
const actual=new Module(file,module);actual.filename=file;actual.paths=Module._nodeModulePaths(path.dirname(file));actual._compile(source,file);
const {assessThenLifecycle}=actual.exports;
function controls({semantic,settlement,lifecycle,expired}={}){
 const events=[],secondary=[];let checked=0;
 return {events,secondary,options:{
  check(){events.push('check');if(expired&&++checked>1)throw expired;},
  assess:async()=>{events.push('assess');if(semantic)throw semantic;},
  settle:async()=>{events.push('settle');if(settlement)throw settlement;},
  lifecycle:async()=>{events.push('reset','sibling','journal','no-credit');if(lifecycle)throw lifecycle;},
  recordSecondary:e=>secondary.push(e)}};
}
test('actual proposed module preserves semantic error after ordered lifecycle and transport settlement',async()=>{
 const error=Object.assign(Error('controlled semantic mismatch'),{code:'ERR_ASSERTION'}),x=controls({semantic:error});
 await assert.rejects(assessThenLifecycle(x.options),e=>e===error);
 assert.deepEqual(x.events,['check','assess','settle','check','reset','sibling','journal','no-credit','check']);
 assert.deepEqual(x.secondary,[]);
});
test('lifecycle error retained without replacing original semantic failure',async()=>{
 const first=Error('semantic'),second=Error('lifecycle'),x=controls({semantic:first,lifecycle:second});
 await assert.rejects(assessThenLifecycle(x.options),e=>e===first);assert.deepEqual(x.secondary,[second]);
});
test('unproved transport settlement or expired owner blocks reset and preserves both errors',async()=>{
 for(const key of ['settlement','expired']){const first=Error('semantic'),second=Error(key),x=controls({semantic:first,[key]:second});
  await assert.rejects(assessThenLifecycle(x.options),e=>e===first);assert(!x.events.includes('reset'));assert.deepEqual(x.secondary,[second]);}
});
test('success still requires lifecycle; lifecycle-only error stays primary',async()=>{
 const x=controls();await assessThenLifecycle(x.options);assert(x.events.includes('no-credit'));
 const failure=Error('lifecycle'),y=controls({lifecycle:failure});await assert.rejects(assessThenLifecycle(y.options),e=>e===failure);
});
test('actual integration preserves prerequisites, assertions, finally cleanup and failure calculation',()=>{
 assert(source.indexOf('const validatedPackets=gate.complete()')<source.indexOf('await assessThenLifecycle({check:owned.check'));
 assert(source.includes('assert.equal(reset.status,\'committed\')'));
 assert(source.includes('assert.deepEqual(await creditSnapshot(),creditsBefore)'));
 assert(source.includes('result.passed=!primary&&!errors.length&&GATES.every'));
 assert(source.includes('finally{\n  await retireCohortResources'));
 assert(source.includes("result.cohort=await fixture.assessCohort"));
});
