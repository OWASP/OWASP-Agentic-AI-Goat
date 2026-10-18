'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {createPostgresRunLedger}=require('../server/agent-runtime/postgresRunLedger');
function fixture(){
 const raw=new EventEmitter(),queries=[];let generation='9',released=false;
 raw.query=async sql=>{queries.push(sql);return{rows:sql.includes('pg_try_advisory_lock')?[{acquired:true}]:[{generation}]};};
 raw.release=()=>{released=true;};
 const pool={connect:async()=>raw};
 return{ledger:createPostgresRunLedger(pool),queries,raw,bump:()=>{generation='10';},released:()=>released};
}
test('maintenance holds existing owner lease without changing parent or creating runs',async()=>{
 const f=fixture();let retained;
 const result=await f.ledger.withOwnerLease({ownerKey:'["XSS","4"]'},async lease=>{
  retained=lease;assert.ok(Object.isFrozen(lease));assert.equal(lease.durableGeneration,'9');
  await lease.check();return 7;
 });
 assert.equal(result,7);assert.equal(f.released(),true);
 assert.ok(f.queries.every(sql=>sql.startsWith('SELECT')));
 assert.ok(f.queries.at(-1).includes('pg_advisory_unlock'));
 await assert.rejects(retained.check(),{name:'AbortError'});
});
test('parent supersession fails and releases maintenance lease',async()=>{
 const f=fixture();
 await assert.rejects(f.ledger.withOwnerLease({ownerKey:'owner'},async()=>{f.bump();}),{name:'AbortError'});
 assert.equal(f.released(),true);
});
test('lost lease and callback failures release without success',async()=>{
 for(const mode of ['lost','callback']){
  const f=fixture();
  await assert.rejects(f.ledger.withOwnerLease({ownerKey:'owner'},async()=>{
   if(mode==='lost')f.raw.emit('error',new Error('disconnected'));
   else throw new Error('callback failed');
  }));
  assert.equal(f.released(),true);
 }
});
