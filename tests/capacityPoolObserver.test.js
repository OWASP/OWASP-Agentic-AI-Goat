'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{EventEmitter}=require('node:events');
test('observer sees subinterval actual managed reservation peaks, dedicated slots, denied allocations and exact end identity',async()=>{
 const samples=[];class Pool extends EventEmitter{constructor(options){super();this.options=options;this.totalCount=0;this.waitingCount=0;}async end(){this.ended=true;}}
 const pg={Pool};const context={URL,module:{exports:{}},require:name=>name==='./poolBudget'?require('../server/database/postgres/poolBudget'):pg,process:{env:{},},console};vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../server/database/postgres/index.js'),'utf8'),context);const managed=context.module.exports;
 const observer={require:name=>name==='node:fs'?{statSync:()=>({isDirectory:()=>true}),writeFileSync:(_p,v)=>samples.push(JSON.parse(v))}:name==='node:path'?path:name==='pg'?pg:managed,process:{env:{DVAIA_CAPACITY_METRICS:'/owned'},pid:1,argv:['node','/owned/server/index.js'],memoryUsage:()=>({rss:123}),on(){}},setInterval:()=>({unref(){}})};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'fixtures/capacityPoolObserver.cjs'),'utf8'),observer);
 const env={IDENTITY_DATABASE_URL:'postgres://fixture@127.0.0.1/test',PG_POOL_BUDGET:'3',PG_POOL_MAX_CONTROL:'2'};
 const release=managed.reserveDedicatedConnection(env),pool=managed.createPool(env,'IDENTITY_DATABASE_URL');assert.equal(samples.at(-1).managedReservedPeak,3);assert.equal(samples.at(-1).dedicatedPeak,1);assert.throws(()=>managed.reserveDedicatedConnection(env),/budget exhausted/);assert.equal(samples.at(-1).allocationFailures,1);
 const first=pool.end();assert.equal(first,pool.end());await first;await Promise.resolve();release();release();assert.equal(samples.at(-1).managedReservedFinal,0);assert.equal(samples.at(-1).dedicatedActive,0);assert.equal(samples.at(-1).managedReservedPeak,3);assert(!JSON.stringify(samples).includes('postgres://'));assert(!JSON.stringify(samples).includes('fixture'));
});
