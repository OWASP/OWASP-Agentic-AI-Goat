'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSequence}=require('./fixtures/csrfManagedBrowserSequence');
test('two sequential leases require confirmed cleanup; concurrent and excess third launches fail closed',()=>{const s=createSequence(2),a=s.reserve();assert.equal(a.index,1);assert.throws(()=>s.reserve(),/still active/);a.release();const b=s.reserve();assert.equal(b.index,2);assert.throws(()=>s.reserve(),/still active/);b.release();assert.throws(()=>s.reserve(),/budget exhausted/);assert.throws(()=>b.release(),/already released/);});
test('original one-browser budget and invalid limits remain closed',()=>{const s=createSequence(),a=s.reserve();a.release();assert.throws(()=>s.reserve(),/budget exhausted/);for(const limit of [0,3,Infinity,'2'])assert.throws(()=>createSequence(limit));});
