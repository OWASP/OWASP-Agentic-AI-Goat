'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { withStudentLifecycleLock } = require('../server/database/postgres/studentLifecycleLock');
function fixture() {
  const client = new EventEmitter();
  const calls = [];
  let releaseError;
  client.query = async (sql, values) => {
    calls.push({sql, values});
    if (sql.includes('pg_locks')) return {rows:[{held:true}]};
    return {rows:[{unlocked:true}]};
  };
  client.release = error => { releaseError = error; };
  return {client, calls, pool:{connect:async()=>client}, released:()=>releaseError};
}
test('optional guard checks exact owned lock and expires when callback ends', async () => {
  const f = fixture(); let retained;
  await withStudentLifecycleLock(f.pool, 42, async (client, guard) => {
    assert.equal(client, f.client); assert.ok(Object.isFrozen(guard));
    assert.equal(guard.ownerId,42); retained=guard;
    await guard.check();
  });
  assert.deepEqual(f.calls[1].values,[1886610806,42]);
  assert.match(f.calls[1].sql,/objsubid = 2/);
  await assert.rejects(retained.check(),{code:'STUDENT_LIFECYCLE_LOCK_LOST'});
  assert.equal(f.calls.length,3);
});
test('connection error during check rejects and destroys connection', async () => {
  const f=fixture(); const query=f.client.query;
  f.client.query=async (sql,values)=>{
    if(sql.includes('pg_locks')) f.client.emit('error',new Error('disconnected'));
    return query(sql,values);
  };
  await assert.rejects(withStudentLifecycleLock(f.pool,42,async (_,guard)=>guard.check()),
    {code:'STUDENT_LIFECYCLE_LOCK_LOST'});
  assert.ok(f.released() instanceof Error);
});
test('missing advisory lock fails before caller continues',async()=>{
  const f=fixture(); const query=f.client.query; let effect=false;
  f.client.query=async(sql,values)=>sql.includes('pg_locks')?{rows:[{held:false}]}:query(sql,values);
  await assert.rejects(withStudentLifecycleLock(f.pool,42,async(_,guard)=>{
    await guard.check(); effect=true;
  }),{code:'STUDENT_LIFECYCLE_LOCK_LOST'});
  assert.equal(effect,false); assert.ok(f.released() instanceof Error);
});
test('existing callbacks retain their query sequence',async()=>{
  const f=fixture();
  assert.equal(await withStudentLifecycleLock(f.pool,42,async()=>17),17);
  assert.equal(f.calls.length,2); assert.equal(f.released(),undefined);
});

test('connection error during unlock stays handled and destroys connection',async()=>{
  const f=fixture(); const query=f.client.query;
  f.client.query=async(sql,values)=>{
    if(sql.includes('pg_advisory_unlock')) f.client.emit('error',new Error('unlock disconnected'));
    return query(sql,values);
  };
  await assert.rejects(withStudentLifecycleLock(f.pool,42,async()=>17),
    {code:'STUDENT_LIFECYCLE_LOCK_LOST'});
  assert.ok(f.released() instanceof Error);
  assert.equal(f.client.listenerCount('error'),0);
});
