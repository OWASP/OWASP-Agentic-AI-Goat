'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {createAdmission,withTargetPool}=require('../sidecars/analytics-sql-target/admission');
const {createClusterVerifier}=require('../sidecars/analytics-sql-target/cluster');
const {createFixture}=require('../sidecars/analytics-sql-target/fixture');
const {collectQuery}=require('../sidecars/analytics-sql-target/bounded-query');
test('global admission rejects before third work starts and releases on failure',async()=>{
 const admission=createAdmission(2);let release;const gate=new Promise(r=>release=r);
 const a=admission.run(()=>gate),b=admission.run(()=>gate);let touched=false;
 await assert.rejects(admission.run(()=>{touched=true;}),{code:'ANALYTICS_CAPACITY'});assert.equal(touched,false);assert.equal(admission.active,2);
 release();await Promise.all([a,b]);assert.equal(admission.active,0);
 await assert.rejects(admission.run(()=>{throw Error('failed');}));assert.equal(admission.active,0);
});
test('target pool remains max-one and closes deterministically after work failure',async()=>{
 let ended=0,config;await assert.rejects(withTargetPool(c=>{config=c;return {end:async()=>ended++};},{max:200},async()=>{throw Error('failed');}));
 assert.equal(config.max,1);assert.equal(ended,1);
});
test('concrete cluster inspection rejects wrong identity, shared databases and public CONNECT',async()=>{
 const identity={systemIdentifier:'123456789012',controlDatabase:'dvaia_analytics_control_123456abcdef',clusterName:'dvaia-owned-analytics-123456abcdef'};
 const base={database:identity.controlDatabase,cluster:identity.clusterName,system_identifier:identity.systemIdentifier};
 async function verify(row=base,dbs=[{datname:'postgres',datallowconn:true,public_connect:false}]){let calls=0;return createClusterVerifier({query:async()=>({rows:++calls===1?[row]:dbs})},identity).verify();}
 assert.equal(await verify(),true);
 await assert.rejects(verify({...base,system_identifier:'987654321000'}),{code:'ANALYTICS_CLUSTER_MISMATCH'});
 await assert.rejects(verify(base,[{datname:'application_identity',datallowconn:true,public_connect:false}]),{code:'ANALYTICS_CLUSTER_GRANTS'});
 await assert.rejects(verify(base,[{datname:'postgres',datallowconn:true,public_connect:true}]),{code:'ANALYTICS_CLUSTER_GRANTS'});
});
test('fresh source manifests differ without copying live commerce',()=>{
 const a=createFixture(),b=createFixture();assert.notEqual(a.sourceManifestSha256,b.sourceManifestSha256);
});
test('fresh analytics targets use an independent opaque synthetic admin password',()=>{
 const a=createFixture(),b=createFixture(),passwordA=a.rows.shop_users[0][3],passwordB=b.rows.shop_users[0][3];
 assert.match(passwordA,/^[a-f0-9]{64}$/);assert.match(passwordB,/^[a-f0-9]{64}$/);
 assert.notEqual(passwordA,passwordB);assert.doesNotMatch(passwordA,/SYNTHETIC_KEY|admin|password/i);
 assert.notEqual(passwordA,a.rows.shop_users[0][5]);
});
test('evented raw SQL retains exact text and rejects row overflow before buffering it',async()=>{
 class Query extends EventEmitter{constructor(config){super();this.config=config;}}
 const client=new EventEmitter();let observed;
 client.query=q=>{observed=q.config;queueMicrotask(()=>{q.emit('row',{value:1});q.emit('end',{fields:[{name:'value'}],rowCount:1});});};
 const sql='SELECT 1 AS value -- raw';const result=await collectQuery(client,sql,{QueryType:Query});assert.equal(result.sql,sql);assert.equal(observed.text,sql);assert.equal(observed.queryMode,'extended');
 client.query=q=>queueMicrotask(()=>{q.emit('row',{value:1});q.emit('row',{value:2});});
 await assert.rejects(collectQuery(client,sql,{maxRows:1,QueryType:Query}),{code:'ANALYTICS_QUERY_BUDGET'});
});
test('failed termination still destroys target client and closes pool',async()=>{
 const {createExecutor}=require('../sidecars/analytics-sql-target/executor');const {randomUUID}=require('node:crypto');
 let released=0,ended=0;const client=new EventEmitter();
 client.release=destroy=>{assert.equal(destroy,true);released++;};
 client.query=query=>{if(typeof query!=='string')throw Error('raw query failed');if(query.includes('pg_backend_pid'))return {rows:[{pid:42,backend_start:'2026-09-20T00:00:00Z'}]};return {rows:[]};};
 const execute=createExecutor({controlPool:{query:async()=>{throw Error('termination unavailable');}},createPool:()=>({connect:async()=>client,end:async()=>{ended++;}}),verifyTarget:async()=>{},connection:{host:'controlled.invalid'}});
 await assert.rejects(execute({targetId:randomUUID()},'a'.repeat(64),'SELECT 1'),{code:'ANALYTICS_QUERY_DRAIN_UNCERTAIN'});
 assert.equal(released,1);assert.equal(ended,1);client.emit('error',Error('late connection error'));
});
test('lost control lease aborts in-flight work, forbids writes and discards connection',async()=>{
 const {createOwnedAnalyticsJournal}=require('../sidecars/analytics-sql-target/journal');const {randomUUID}=require('node:crypto');const client=new EventEmitter();let released,queries=0;
 client.query=async()=>{queries++;return {rows:[{held:true,released:true}]};};client.release=broken=>released=broken;
 const journal=createOwnedAnalyticsJournal({connect:async()=>client});
 await assert.rejects(journal.withLock({launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},async()=>{
  const signal=journal.signal();client.emit('error',Error('connection lost'));assert.equal(signal.aborted,true);
  await assert.rejects(journal.eraseCredential(randomUUID()),{code:'ANALYTICS_LEASE_LOST'});
 }),{code:'ANALYTICS_LEASE_LOST'});assert.equal(released,true);assert.equal(queries,1);
});
test('canonical hashing preserves PostgreSQL date and nested JSON serialization semantics',()=>{
 const {hash}=require('../sidecars/analytics-sql-target/contract');const value={rows:[{when:new Date('2026-09-20T00:00:00Z'),nested:{z:[3,2,1],a:true}}],columns:['when','nested']};
 assert.equal(hash(value),hash(JSON.parse(JSON.stringify(value))));assert.notEqual(hash(value),hash({...value,rows:[{when:value.rows[0].when,nested:{z:[1,2,3],a:true}}]}));
});

test('target pool captures idle errors through drain without publishing a result',async()=>{
 const pool=new EventEmitter();let ended=false;pool.end=async()=>{pool.emit('error',Object.assign(Error('terminated'),{code:'57P01'}));ended=true;};
 await assert.rejects(withTargetPool(()=>pool,{},async()=>({rows:[1]})),error=>error.code==='ANALYTICS_POOL_DRAIN_UNCERTAIN'&&error.cause.code==='57P01');assert.equal(ended,true);
});

test('event collector observes callback-only PostgreSQL errors with configured query timeout',async()=>{
 class Query extends EventEmitter{}const client=new EventEmitter();client.query=q=>queueMicrotask(()=>q.callback(Object.assign(Error('denied'),{code:'42501'})));
 await assert.rejects(collectQuery(client,'SELECT api_key FROM shop_users',{QueryType:Query}),{code:'42501'});
});
test('42501 becomes a terminal denial only after exact backend absence; failed drain stays uncertain',async()=>{
 const {createExecutor}=require('../sidecars/analytics-sql-target/executor'),{randomUUID}=require('node:crypto');
 for(const failDrain of [false,true]){let releases=0,absence=0;const client=new EventEmitter();client.release=destroy=>{assert.equal(destroy,true);releases++;};client.query=query=>{if(typeof query!=='string'){queueMicrotask(()=>query.callback(Object.assign(Error('denied'),{code:'42501'})));return;}if(query.includes('has_any_column'))return {rows:[{protected_read:false,metrics_read:true,schema_write:false,memberships:false,powerful:false}]};if(query.includes('pg_backend_pid'))return {rows:[{pid:42,backend_start:'2026-09-20T00:00:00Z'}]};if(query.includes('pg_attribute'))return {rows:[{table_id:123,column_id:6}]};return {rows:[]};};
 const id=randomUUID(),execute=createExecutor({controlPool:{query:async q=>{if(failDrain)throw Error('drain failed');if(q.text.startsWith('SELECT 1'))absence++;return {rows:[]};}},createPool:()=>({connect:async()=>client,end:async()=>{}}),verifyTarget:async()=>{},connection:{}});
 const work=execute({targetId:id},'a'.repeat(64),'SELECT api_key FROM shop_users',{loginRole:'analytics_'+id.replaceAll('-','')+'_metrics',captureProtected:true});
 if(failDrain)await assert.rejects(work,{code:'ANALYTICS_QUERY_DRAIN_UNCERTAIN'});else{const result=await work;assert.equal(result.denial.code,'42501');assert.equal(result.denial.backendAbsent,true);assert.equal(absence,1);assert.deepEqual(result.result.rows,[]);}assert.equal(releases,1);
 }
});

test('trusted query parameters are separately bound and copied; malformed arrays never reach pg',async()=>{
 class Query extends EventEmitter{constructor(config){super();this.config=config;}}
 const client=new EventEmitter();let observed,calls=0;client.query=q=>{calls++;observed=q.config;queueMicrotask(()=>q.emit('end',{fields:[{name:'code'}],rowCount:0}));};
 const values=['[{"id":1}]',"' OR 1=1--"];const work=collectQuery(client,'SELECT $2 AS code',{values,QueryType:Query});values[1]='changed';await work;assert.equal(observed.values[1],"' OR 1=1--");assert.equal(observed.queryMode,'extended');
 for(const bad of [[{}],[null],[1],new Array(1),['a','b','c']])assert.throws(()=>collectQuery(client,'SELECT 1',{values:bad,QueryType:Query}),{code:'ANALYTICS_QUERY_PARAMETERS'});
 const getter=[];Object.defineProperty(getter,0,{get(){assert.fail('getter evaluated');},enumerable:true});assert.throws(()=>collectQuery(client,'SELECT 1',{values:getter,QueryType:Query}));assert.equal(calls,1);
});
