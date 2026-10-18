'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createTeachingSessionProduction}=require('../server/services/teachingSessionProduction');
function fixture({fail=false}={}) {
 const calls=[],adapter={},pool={end:async()=>calls.push('pool.close')};
 const runtime={initialize:async()=>calls.push('initialize'),close:async()=>calls.push('runtime.close'),middleware:()=>calls.push('request')};
 const env={PLATFORM_DATABASE_ENGINE:'postgres'};
 const load=name=>({
  './postgresIdentityAdapter':{getPostgresIdentityAdapter:()=>adapter},
  '../database/postgres':{createPool:(actual,key,options)=>{assert.equal(actual,env);assert.equal(key,'IDENTITY_DATABASE_URL');assert.deepEqual(options,{purpose:'teaching'});calls.push('pool');return pool;}},
  './teachingSessionRuntime':{createTeachingSessionRuntime:options=>{assert.deepEqual(options,{adapter,effectPool:pool});if(fail)throw new Error('construction failure');return runtime;}},
 })[name];
 return {calls,runtime,production:createTeachingSessionProduction({env,load})};
}
test('production allocates one bounded effect pool and closes runtime before pool',async()=>{
 const f=fixture();assert.deepEqual(f.calls,[]);
 assert.equal(await f.production.initialize(),f.runtime);await f.production.initialize();
 assert.equal(f.calls.filter(x=>x==='pool').length,1);
 await Promise.all([f.production.close(),f.production.close()]);
 assert.deepEqual(f.calls.slice(-2),['runtime.close','pool.close']);
 await assert.rejects(f.production.initialize(),/closed/);
});
test('construction failure cannot allocate more pools and remains cleanable',async()=>{
 const f=fixture({fail:true});await assert.rejects(f.production.initialize(),/construction failure/);
 await assert.rejects(f.production.initialize(),/closed/);await f.production.close();
 assert.deepEqual(f.calls,['pool','pool.close']);
});
test('before initialization and after shutdown requests fail closed',async()=>{
 const f=fixture(),res={status(n){assert.equal(n,503);return this;},json(v){assert.deepEqual(v,{error:'Teaching session store unavailable'});}};
 f.production.middleware({},res,()=>assert.fail());await f.production.initialize();await f.production.close();
 f.production.middleware({},res,()=>assert.fail());
 assert.throws(()=>createTeachingSessionProduction({env:{PLATFORM_DATABASE_ENGINE:'sqlite'}}),/PostgreSQL/);
});
