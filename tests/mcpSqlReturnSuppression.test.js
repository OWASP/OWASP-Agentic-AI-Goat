'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createSqlReturnSuppression}=require('./helpers/mcpSqlReturnSuppression');
test('only exact armed successful statement loses its return once',async()=>{
 const s=createSqlReturnSuppression('COMMIT'),calls=[];const q=s.wrapQuery(async(...args)=>{calls.push(args);return {rows:[{ok:true}]};});
 await q('COMMIT');s.arm();await q('SELECT 1',[2]);await q('COMMIT ');
 await assert.rejects(q('COMMIT'),{code:'TEST_SQL_RETURN_SUPPRESSED'});assert.deepEqual(await q('COMMIT'),{rows:[{ok:true}]});
 assert.equal(calls.length,5);assert.deepEqual(s.snapshot(),{armed:false,consumed:true,delegated:1,suppressed:1});assert.throws(()=>s.arm());
});
test('failed real execution is never recorded as successful suppression',async()=>{
 const s=createSqlReturnSuppression('COMMIT');s.arm();const failure=Error('real failure');
 await assert.rejects(s.wrapQuery(async()=>{throw failure;})('COMMIT'),e=>e===failure);
 assert.deepEqual(s.snapshot(),{armed:false,consumed:true,delegated:0,suppressed:0});
});
test('concurrent statements cannot consume the one-shot twice',async()=>{
 const s=createSqlReturnSuppression('COMMIT');s.arm();let release;const barrier=new Promise(r=>release=r);
 const q=s.wrapQuery(async()=>{await barrier;return 1;});const a=q('COMMIT'),b=q('COMMIT');const settled=Promise.allSettled([a,b]);release();
 assert.deepEqual((await settled).map(x=>x.status),['rejected','fulfilled']);assert.equal(s.snapshot().suppressed,1);
});
test('invalid delegates and statements fail before execution',()=>{
 for(const x of [null,'',{},' '])assert.throws(()=>createSqlReturnSuppression(x));
 assert.throws(()=>createSqlReturnSuppression('COMMIT').wrapQuery(null));
});
