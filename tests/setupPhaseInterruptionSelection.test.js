'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {selectInterruptionCases}=require('./fixtures/setupPhaseInterruptionSelection');
for(const mode of ['runner-failure','signal','disconnect','abrupt'])test('fresh interruption selects only '+mode,()=>{
 const selected=selectInterruptionCases('fresh-interruption',mode);
 assert.deepEqual(selected,[mode]);assert.equal(Object.isFrozen(selected),true);
});
test('interruption rejects missing, multiple and unknown cases',()=>{
 for(const mode of [undefined,'','all','signal,abrupt',['signal','abrupt']])assert.throws(()=>selectInterruptionCases('fresh-interruption',mode));
});
test('success and unrelated scenarios never run interruption; historical shared installation rejected',()=>{
 for(const scenario of ['fresh-success','additive-success','ctf-fresh']){
  assert.deepEqual(selectInterruptionCases(scenario),[]);
  assert.throws(()=>selectInterruptionCases(scenario,'signal'));
 }
 assert.throws(()=>selectInterruptionCases('fresh'));
});
