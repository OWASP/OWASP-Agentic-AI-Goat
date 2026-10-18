'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createOwnedAnalyticsService}=require('../sidecars/analytics-sql-target/service');
const {hash}=require('../sidecars/analytics-sql-target/contract');
const Probe=require('../server/services/secureshopCouponProbeContract');
function fixture({seedFailure=false,beforeLock}={}){
 const identity={systemIdentifier:'123456789012',controlDatabase:'dvaia_analytics_control_123456abcdef',clusterName:'dvaia-owned-analytics-123456abcdef'};
 const tables=new Map(),queries=new Map(),credentials=new Map(),dbs=new Map(),sql=[],journalSql=[],pools=[];let discarded=0,couponProbeFailure=null;
 let referencePassword='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',referenceCharacter=null;
 let productRows=[],productFailure=null,productReference='SYNTHETIC_KEY_'+'a'.repeat(48);const productQueries=[];
 let orderRows=[],orderFailure=null;const orderQueries=[];
 const metadata=async(text,values=[])=>{
  journalSql.push(text);
  if(text.includes('pg_try_advisory_lock')){await beforeLock?.();return {rows:[{held:true}]};}if(text.includes('pg_advisory_unlock'))return {rows:[{released:true}]};
  if(text.startsWith('SELECT target_id'))return {rows:tables.has(values[0])?[tables.get(values[0])]:[]};
  if(text.startsWith('SELECT password'))return {rows:credentials.has(values[0])?[{password:credentials.get(values[0])}]:[]};
  if(text.startsWith('SELECT request_sha256'))return {rows:queries.has(values.join(':'))?[queries.get(values.join(':'))]:[]};
  if(text.startsWith('INSERT INTO owned_analytics_queries')){queries.set(`${values[0]}:${values[1]}`,{request_sha256:values[2],state:'pending',receipt:null,result_sha256:null});return {rows:[]};}
  if(text.startsWith("UPDATE owned_analytics_queries SET state='completed'")){const row=queries.get(`${values[0]}:${values[1]}`);if(!row||row.state!=='pending')return {rowCount:0};Object.assign(row,{state:'completed',receipt:values[2],result_sha256:values[3]});return {rowCount:1};}
  if(text.startsWith('INSERT INTO owned_analytics_targets')){tables.set(values[0],{target_id:values[1],scope:values[2],source_manifest_sha256:values[3],state:'pending'});return {rows:[]};}
  if(text.startsWith('INSERT INTO owned_analytics_credentials')){credentials.set(values[0],values[1]);return {rows:[]};}
  if(text.startsWith('UPDATE owned_analytics_targets')){const row=tables.get(values[0]);assert.equal(row.state,values[2]);row.state=values[1];return {rowCount:1};}
  return {rows:[]};
 };
 const controlPool={connect:async()=>Object.assign(new (require('node:events').EventEmitter)(),{query:metadata,release(){}}),async query(query){
  const text=typeof query==='string'?query:query?.text;
  if(typeof text!=='string')throw TypeError('expected controlled SQL text');
  sql.push(text);
  if(text.includes('pg_terminate_backend'))return {rows:[{pg_terminate_backend:true}]};
  if(text.includes('FROM pg_stat_activity WHERE pid='))return {rows:[]};
  if(text.includes('pg_control_system'))return {rows:[{database:identity.controlDatabase,cluster:identity.clusterName,system_identifier:identity.systemIdentifier}]};
  if(text.includes('FROM pg_database'))return {rows:[{datname:'postgres',datallowconn:true,public_connect:false},...dbs.values()]};
  const name=text.match(/analytics_[a-f0-9]{32}/)?.[0];
  if(text.startsWith('CREATE DATABASE')){assert.ok(text.endsWith('ALLOW_CONNECTIONS false'));dbs.set(name,{datname:name,datallowconn:false,public_connect:true});}
  if(text.startsWith('REVOKE ALL ON DATABASE'))dbs.get(name).public_connect=false;
  if(text.startsWith('ALTER DATABASE')){assert.equal(dbs.get(name).public_connect,false);dbs.get(name).datallowconn=true;}
  return {rows:[]};
 }};
 const createPool=config=>{let ended=false;const pool={async connect(){return Object.assign(new (require('node:events').EventEmitter)(),{async query(text){
  if(typeof text!=='string'){
   queueMicrotask(()=>{
    if(text.text.startsWith('WITH orders AS')){
     orderQueries.push({text:text.text,values:[...text.values]});
     if(orderFailure)return text.emit('error',orderFailure);
     for(const row of orderRows)text.emit('row',row);
     return text.emit('end',{fields:Object.keys(orderRows[0]||{}).map(name=>({name})),rowCount:orderRows.length});
    }
    if(text.text.startsWith('WITH products AS')||text.text.startsWith('SELECT id,api_key FROM shop_users')){
     productQueries.push({text:text.text,values:[...text.values]});
     if(productFailure)return text.emit('error',productFailure);
     const rows=text.text.startsWith('WITH products AS')?productRows:[{id:1,api_key:productReference}];
     for(const row of rows)text.emit('row',row);
     return text.emit('end',{fields:Object.keys(rows[0]||{}).map(name=>({name})),rowCount:rows.length});
    }
    if(text.text.includes('WITH coupons AS')){
     if(couponProbeFailure)return text.emit('error',couponProbeFailure);
     const row={id:1,code:'WELCOME10',discount_percent:10,active:1};text.emit('row',row);return text.emit('end',{fields:Object.keys(row).map(name=>({name})),rowCount:1});
    }
    if(text.text.includes('substring(password FROM')){
     const position=Number(text.values?.[0]);
     const row={id:1,password:referencePassword,character:referenceCharacter??referencePassword[position-1]};text.emit('row',row);return text.emit('end',{fields:Object.keys(row).map(name=>({name})),rowCount:1});
    }
    text.emit('end',{fields:[],rowCount:0});
   });return text;
  }
  if(text.includes('pg_control_system'))return {rows:[{database:config.database,cluster:identity.clusterName,system_identifier:identity.systemIdentifier}]};
  if(text.includes('current_database() AS database,current_user AS username'))return {rows:[{database:config.database,username:config.user,cluster:identity.clusterName}]};
  if(text.includes('pg_backend_pid'))return {rows:[{pid:42,backend_start:'2026-10-01T00:00:00Z'}]};
  if(text.includes('WITH coupons AS')){if(couponProbeFailure)throw couponProbeFailure;return {rows:[{id:1,code:'WELCOME10',discount_percent:10,active:1}]};}
  if(text.includes('substring(password FROM')){const position=Number(arguments[1]?.[0]);return {rows:[{id:1,password:referencePassword,character:referenceCharacter??referencePassword[position-1]}]};}
  if(seedFailure&&text.startsWith('INSERT'))throw Error('seed failed');return {rows:[]};},release(destroy){assert.equal(destroy,true);discarded++;}});},async end(){ended=true;},closed:()=>ended};pools.push(pool);return pool;};
 const service=createOwnedAnalyticsService({identity,connection:{host:'controlled.invalid'},controlPool,createPool});
 const scope=()=>({launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2});
 return {service,scope,tables,queries,journalSql,pools,productQueries,orderQueries,setOrderRows:value=>{orderRows=value;},setOrderFailure:value=>{orderFailure=value;},setProductRows:value=>{productRows=value;},
  setProductFailure:value=>{productFailure=value;},setProductReference:value=>{productReference=value;},
  discarded:()=>discarded,setCouponProbeFailure:value=>{couponProbeFailure=value;},setReferenceRow:({password,character=null})=>{referencePassword=password;referenceCharacter=character;}};
}
test('two controlled provisionings never expose PUBLIC-connectable targets and close every pool',async()=>{
 const f=fixture(),[a,b]=await Promise.all([f.service.provision(f.scope()),f.service.provision(f.scope())]);
 assert.notEqual(a.targetId,b.targetId);assert.notEqual(a.sourceManifestSha256,b.sourceManifestSha256);
 assert.equal(f.discarded(),2);assert.ok(f.pools.every(p=>p.closed()));assert.ok([...f.tables.values()].every(r=>r.state==='ready'));
});
test('failed seed destroys admin client and leaves durable pending instead of ready',async()=>{
 const f=fixture({seedFailure:true});await assert.rejects(f.service.provision(f.scope()),/seed failed/);
 assert.equal(f.discarded(),1);assert.ok(f.pools.every(p=>p.closed()));assert.equal([...f.tables.values()][0].state,'pending');
});
test('coupon receipt reader uses only the existing ready target and completed immutable row',async()=>{
 const f=fixture(),scope=f.scope(),targetId=randomUUID(),operationId=randomUUID(),requestSha256='b'.repeat(64),sourceManifestSha256='c'.repeat(64);
 f.tables.set(hash(scope),{target_id:targetId,scope,source_manifest_sha256:sourceManifestSha256,state:'ready'});
 const result={coupon:null},receipt={version:1,kind:'coupon',operationId,requestSha256,targetId,scope,sourceManifestSha256,resultSha256:hash(result),result};
 const input={scope,targetId,operationId,requestSha256};
 assert.equal(await f.service.readCouponReceipt(input),null);
 f.queries.set(`${targetId}:${operationId}`,{request_sha256:requestSha256,state:'pending',receipt:null,result_sha256:null});
 assert.equal(await f.service.readCouponReceipt(input),null);
 f.queries.set(`${targetId}:${operationId}`,{request_sha256:requestSha256,state:'redacted',receipt:null,result_sha256:hash({coupon:null})});
 assert.equal(await f.service.readCouponReceipt(input),null);
 f.queries.set(`${targetId}:${operationId}`,{request_sha256:requestSha256,state:'completed',receipt,result_sha256:receipt.resultSha256});
 assert.deepEqual(await f.service.readCouponReceipt(input),receipt);
 assert.equal(f.discarded(),0);
 assert.equal(f.journalSql.some(text=>/\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/i.test(text)),false);
 assert.equal(f.journalSql.some(text=>text.startsWith('SELECT request_sha256')),true);
});
test('coupon receipt reader rejects foreign target, request conflict and damaged completed receipts',async()=>{
 const f=fixture(),scope=f.scope(),targetId=randomUUID(),operationId=randomUUID(),requestSha256='b'.repeat(64),sourceManifestSha256='c'.repeat(64);
 f.tables.set(hash(scope),{target_id:targetId,scope,source_manifest_sha256:sourceManifestSha256,state:'ready'});
 const input={scope,targetId,operationId,requestSha256},result={coupon:null};
 const receipt={version:1,kind:'coupon',operationId,requestSha256,targetId,scope,sourceManifestSha256,resultSha256:hash(result),result};
 const row={request_sha256:requestSha256,state:'completed',receipt,result_sha256:receipt.resultSha256};
 f.queries.set(`${targetId}:${operationId}`,row);
 await assert.rejects(f.service.readCouponReceipt({...input,targetId:randomUUID()}),{code:'ANALYTICS_TARGET_INVALID'});
 await assert.rejects(f.service.readCouponReceipt({...input,unused:true}),{code:'ANALYTICS_TARGET_INVALID'});
 await assert.rejects(f.service.readCouponReceipt({...input,requestSha256:'d'.repeat(64)}),{code:'ANALYTICS_QUERY_CONFLICT'});
 for(const bad of [{...receipt,kind:'query'},{...receipt,scope:{...scope,platformOwnerId:99}},{...receipt,result:{coupon:null,extra:true}},{...receipt,resultSha256:'d'.repeat(64)}]){
  f.queries.set(`${targetId}:${operationId}`,{...row,receipt:bad});
  await assert.rejects(f.service.readCouponReceipt(input),{code:'ANALYTICS_QUERY_CONFLICT'});
 }
 f.queries.set(`${targetId}:${operationId}`,{...row,result_sha256:'d'.repeat(64)});
 await assert.rejects(f.service.readCouponReceipt(input),{code:'ANALYTICS_QUERY_CONFLICT'});
 f.queries.set(`${targetId}:${operationId}`,{...row,state:'unknown'});
 await assert.rejects(f.service.readCouponReceipt(input),{code:'ANALYTICS_QUERY_CONFLICT'});
 f.tables.get(hash(scope)).state='retired';
 await assert.rejects(f.service.readCouponReceipt(input),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
 assert.equal(f.journalSql.some(text=>/\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/i.test(text)),false);
});
test('coupon receipt read snapshots validated IDs and hash before asynchronous lease admission',async()=>{
 let entered,release;const enteredLock=new Promise(resolve=>{entered=resolve;}),held=new Promise(resolve=>{release=resolve;});
 const f=fixture({beforeLock:async()=>{entered();await held;}}),scope=f.scope(),targetId=randomUUID(),operationId=randomUUID(),requestSha256='b'.repeat(64),sourceManifestSha256='c'.repeat(64);
 f.tables.set(hash(scope),{target_id:targetId,scope,source_manifest_sha256:sourceManifestSha256,state:'ready'});
 const result={coupon:null},receipt={version:1,kind:'coupon',operationId,requestSha256,targetId,scope,sourceManifestSha256,resultSha256:hash(result),result};
 f.queries.set(`${targetId}:${operationId}`,{request_sha256:requestSha256,state:'completed',receipt,result_sha256:receipt.resultSha256});
 const input={scope,targetId,operationId,requestSha256},pending=f.service.readCouponReceipt(input);
 await enteredLock;
 input.targetId=randomUUID();input.operationId=randomUUID();input.requestSha256='d'.repeat(64);
 release();
 assert.deepEqual(await pending,receipt);
});

test('coupon probe persists distinct SQL/value/request/result digests and exposes its character only through the private reference reader',async()=>{
 const f=fixture(),scope=f.scope(),target=await f.service.provision(scope);
 const lookup={scope,operationId:randomUUID(),persona:{id:3,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',code:"' OR 1=1--",coupons:[{id:1,code:'WELCOME10',discount_percent:10,active:1}]};
 const request={version:1,lookup,execution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),generation:'0',sessionId:randomUUID(),requestId:randomUUID(),step:1,callId:'coupon-probe:1'}};
 const receipt=await f.service.lookupCouponProbe(request);
 assert.equal(receipt.kind,'coupon-probe');assert.equal(receipt.result.coupon.code,'WELCOME10');assert.equal(Object.hasOwn(receipt,'character'),false);
 assert.deepEqual(await f.service.readCouponProbeReceipt({scope,targetId:target.targetId,operationId:lookup.operationId,requestSha256:receipt.requestSha256}),receipt);
 const reference=await f.service.readCouponProbeReference({scope,targetId:target.targetId,operationId:lookup.operationId,requestSha256:receipt.requestSha256,position:1});
 assert.deepEqual(reference,{version:1,targetId:target.targetId,operationId:lookup.operationId,requestSha256:receipt.requestSha256,position:1,rowId:1,character:'0',characterSha256:hash('0')});
 await assert.rejects(f.service.readCouponProbeReference({scope,targetId:target.targetId,operationId:lookup.operationId,requestSha256:receipt.requestSha256,position:65}),{code:'ANALYTICS_PROBE_REFERENCE_UNAVAILABLE'});
 f.setReferenceRow({password:'legacy-shared-value',character:'l'});
 await assert.rejects(f.service.readCouponProbeReference({scope,targetId:target.targetId,operationId:lookup.operationId,requestSha256:receipt.requestSha256,position:1}),{code:'ANALYTICS_PROBE_REFERENCE_UNAVAILABLE'});
 f.setReferenceRow({password:'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',character:'f'});
 await assert.rejects(f.service.readCouponProbeReference({scope,targetId:target.targetId,operationId:lookup.operationId,requestSha256:receipt.requestSha256,position:1}),{code:'ANALYTICS_PROBE_REFERENCE_UNAVAILABLE'});
 f.setReferenceRow({password:'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'});
 assert.deepEqual(await f.service.lookupCouponProbe(structuredClone(request)),receipt);
 f.queries.set(`${target.targetId}:${lookup.operationId}`,{request_sha256:receipt.requestSha256,state:'completed',receipt:{...receipt,targetId:randomUUID()},result_sha256:receipt.resultSha256});
 await assert.rejects(f.service.lookupCouponProbe(structuredClone(request)),{code:'ANALYTICS_QUERY_CONFLICT'});
 await assert.rejects(f.service.lookupCouponProbe({...request,lookup:{...lookup,code:"' OR 1=0--"}}),{code:'ANALYTICS_QUERY_CONFLICT'});
});

test('coupon probe execution errors reject rather than becoming a false receipt',async()=>{
 const f=fixture(),scope=f.scope(),target=await f.service.provision(scope);
 const request={version:1,lookup:{scope,operationId:randomUUID(),persona:{id:3,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',code:'WELCOME10',coupons:[{id:1,code:'WELCOME10',discount_percent:10,active:1}]},execution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),generation:'0',sessionId:randomUUID(),requestId:randomUUID(),step:1,callId:'coupon-probe:1'}};
 f.setCouponProbeFailure(Object.assign(Error('target failed'),{code:'ANALYTICS_QUERY_DEADLINE'}));
 await assert.rejects(f.service.lookupCouponProbe(request),{code:'ANALYTICS_QUERY_DEADLINE'});
 assert.equal(await f.service.readCouponProbeReceipt({scope,targetId:target.targetId,operationId:request.lookup.operationId,requestSha256:hash(Probe.request(request))}),null);
});

test('named product search preserves controlled UNION rows, immutable replay and SELECT-only receipt reads',async()=>{
 const C=require('../server/services/secureshopProductSearchSqlContract'),{source,row}=require('./secureshopProductSearchSqlContract.test');
 const f=fixture(),input=source(),scope=input.search.scope,target=await f.service.provision(scope);
 input.search.query="' UNION SELECT 1,api_key,NULL,0,NULL,NULL,0,0,NULL,NULL,NULL FROM shop_users--";
 const original=[row({name:'SYNTHETIC_KEY_'+'a'.repeat(48)})];f.setProductRows(original);
 const saved=await f.service.searchProducts(input),selectors={scope,targetId:target.targetId,operationId:input.search.operationId,requestSha256:saved.requestSha256};
 assert.deepEqual(saved.result,{rows:original,row_count:1});assert.equal(saved.kind,'product-search-sql');
 assert.deepEqual(f.productQueries,[C.statement(input)]);
 assert.deepEqual(await f.service.searchProducts(structuredClone(input)),saved);assert.equal(f.productQueries.length,1);
 const before=f.journalSql.length;
 assert.deepEqual(await f.service.readProductSearchReceipt(selectors),saved);
 assert.equal(f.journalSql.slice(before).some(sql=>/\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/.test(sql)),false);
 assert.equal(f.productQueries.length,1);
 const reference=await f.service.readProductSearchReference(selectors);
 assert.deepEqual(reference,{version:1,targetId:target.targetId,operationId:input.search.operationId,requestSha256:saved.requestSha256,
  sourceManifestSha256:target.sourceManifestSha256,rowId:1,field:'api_key',value:original[0].name,valueSha256:hash(original[0].name)});
 assert.equal(Object.hasOwn(saved,'value'),false);assert.equal(f.productQueries.length,2);
 await assert.rejects(f.service.searchProducts({...input,search:{...input.search,query:'different'}}),{code:'ANALYTICS_QUERY_CONFLICT'});
 await assert.rejects(f.service.readProductSearchReference({...selectors,targetId:randomUUID()}),{code:'ANALYTICS_TARGET_INVALID'});
 f.setProductReference('not-the-owned-reference');await assert.rejects(f.service.readProductSearchReference(selectors),{code:'ANALYTICS_PRODUCT_REFERENCE_UNAVAILABLE'});
 const siblingScope=f.scope(),sibling=await f.service.provision(siblingScope);
 f.tables.get(hash(scope)).state='retired';const count=f.productQueries.length;
 for(const name of ['readProductSearchReceipt','readProductSearchReference'])await assert.rejects(f.service[name](selectors),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
 await assert.rejects(f.service.searchProducts(input),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
 assert.equal(f.productQueries.length,count);assert.deepEqual(await f.service.resolve(siblingScope),sibling);
 assert.ok(f.pools.every(pool=>pool.closed()));
});

test('product fixed search passes original literal as parameter; errors and oversized results never become receipts',async()=>{
 const C=require('../server/services/secureshopProductSearchSqlContract'),{source,row}=require('./secureshopProductSearchSqlContract.test');
 const f=fixture(),input=source();input.search.mode='fixed';input.search.query="' UNION SELECT secret--";
 const target=await f.service.provision(input.search.scope),saved=await f.service.searchProducts(input);
 assert.deepEqual(saved.result,{rows:[],row_count:0});assert.deepEqual(f.productQueries[0],C.statement(input));
 for(const oversized of [false,true]){
  const next={...input,search:{...input.search,operationId:randomUUID()}};
  if(oversized){f.setProductFailure(null);f.setProductRows(Array.from({length:51},()=>row()));}
  else f.setProductFailure(Object.assign(Error('controlled SQL failure'),{code:'42601'}));
  await assert.rejects(f.service.searchProducts(next));
  const selectors={scope:input.search.scope,targetId:target.targetId,operationId:next.search.operationId,requestSha256:hash(C.request(next))};
  assert.equal(await f.service.readProductSearchReceipt(selectors),null);
  await assert.rejects(f.service.readProductSearchReference(selectors),{code:'ANALYTICS_QUERY_CONFLICT'});
  const before=f.productQueries.length;await assert.rejects(f.service.searchProducts(next),{code:'ANALYTICS_QUERY_UNCERTAIN'});
  assert.equal(f.productQueries.length,before);
 }
});

test('product receipt reader rejects copied, damaged and conflicting saved authority without SQL execution',async()=>{
 const {source}=require('./secureshopProductSearchSqlContract.test');const f=fixture(),input=source();
 const target=await f.service.provision(input.search.scope),saved=await f.service.searchProducts(input);
 const selectors={scope:input.search.scope,targetId:target.targetId,operationId:input.search.operationId,requestSha256:saved.requestSha256};
 const key=target.targetId+':'+input.search.operationId,original=structuredClone(f.queries.get(key)),before=f.productQueries.length;
 for(const bad of [{...saved,scope:{...saved.scope,platformOwnerId:9}},{...saved,sourceManifestSha256:'b'.repeat(64)},
  {...saved,resultSha256:'b'.repeat(64)},{...saved,kind:'coupon-probe'}]){
  f.queries.set(key,{...original,receipt:bad});await assert.rejects(f.service.readProductSearchReceipt(selectors));
  await assert.rejects(f.service.readProductSearchReference(selectors));
 }
 f.queries.set(key,original);await assert.rejects(f.service.readProductSearchReceipt({...selectors,requestSha256:'b'.repeat(64)}));
 assert.equal(f.productQueries.length,before);
});


test('order-status query-local PostgreSQL errors become immutable receipts only after drain; saved replay never dispatches',async()=>{
 const C=require('../server/services/secureshopOrderStatusSqlContract'),{source}=require('./secureshopOrderStatusSqlContract.test');
 const f=fixture(),input=source(),scope=input.lookup.scope,target=await f.service.provision(scope);
 input.lookup.order_id='1 AND CAST((SELECT api_key FROM shop_users WHERE id=1) AS INTEGER)=0';
 const message='invalid input syntax for type integer: "SYNTHETIC_KEY_'+'a'.repeat(48)+'"';
 const error=new(require('pg').DatabaseError)(message,0,'error');error.code='22P02';f.setOrderFailure(error);
 const saved=await f.service.lookupOrderStatus(input);
 const selectors={scope,targetId:target.targetId,operationId:input.lookup.operationId,requestSha256:saved.requestSha256};
 assert.deepEqual(saved.result,{kind:'postgres-error',sqlstate:'22P02',message});assert.equal(saved.kind,'order-status-sql');
 assert.deepEqual(f.orderQueries,[C.statement(input)]);assert.ok(f.pools.every(pool=>pool.closed()));
 assert.deepEqual(C.receipt(saved,input),saved);
 assert.deepEqual(await f.service.lookupOrderStatus(structuredClone(input)),saved);assert.equal(f.orderQueries.length,1);
 const before=f.journalSql.length;
 assert.deepEqual(await f.service.readOrderStatusReceipt(selectors),saved);
 assert.equal(f.journalSql.slice(before).some(sql=>/\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/.test(sql)),false);
 assert.equal(f.orderQueries.length,1);
 const reference=await f.service.readOrderStatusReference(selectors);
 assert.deepEqual(reference,{version:1,targetId:target.targetId,operationId:input.lookup.operationId,requestSha256:saved.requestSha256,
  sourceManifestSha256:target.sourceManifestSha256,rowId:1,field:'api_key',value:'SYNTHETIC_KEY_'+'a'.repeat(48),valueSha256:hash('SYNTHETIC_KEY_'+'a'.repeat(48))});
 assert.equal(Object.hasOwn(saved,'value'),false);
 await assert.rejects(f.service.lookupOrderStatus({...input,lookup:{...input.lookup,order_id:'2'}}),{code:'ANALYTICS_QUERY_CONFLICT'});
 await assert.rejects(f.service.readOrderStatusReference({...selectors,targetId:randomUUID()}),{code:'ANALYTICS_TARGET_INVALID'});
 f.setProductReference('not-owned');await assert.rejects(f.service.readOrderStatusReference(selectors),{code:'ANALYTICS_ORDER_REFERENCE_UNAVAILABLE'});
 const siblingScope=f.scope(),sibling=await f.service.provision(siblingScope);f.tables.get(hash(scope)).state='retired';
 const count=f.orderQueries.length;
 for(const method of ['readOrderStatusReceipt','readOrderStatusReference'])await assert.rejects(f.service[method](selectors),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
 await assert.rejects(f.service.lookupOrderStatus(input),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
 assert.equal(f.orderQueries.length,count);assert.deepEqual(await f.service.resolve(siblingScope),sibling);
});
test('fixed order-status uses bound string literal and generic public error; normal numeric lookup retains original row',async()=>{
 const C=require('../server/services/secureshopOrderStatusSqlContract'),{source,row}=require('./secureshopOrderStatusSqlContract.test');
 const f=fixture(),input=source();input.lookup.mode='fixed';input.lookup.order_id='1 AND CAST(secret AS INTEGER)=0';
 await f.service.provision(input.lookup.scope);
 const error=new(require('pg').DatabaseError)('invalid input syntax: original raw literal',0,'error');error.code='22P02';f.setOrderFailure(error);
 const saved=await f.service.lookupOrderStatus(input);
 assert.deepEqual(f.orderQueries[0],C.statement(input));assert.deepEqual(f.orderQueries[0].values,[input.lookup.order_id]);
 assert.equal(C.publicResult(input,saved.result).error,'Order lookup unavailable.');
 const ordinary={...input,lookup:{...input.lookup,operationId:randomUUID(),order_id:1}};f.setOrderFailure(null);f.setOrderRows([row()]);
 const observed=await f.service.lookupOrderStatus(ordinary);assert.deepEqual(C.publicResult(ordinary,observed.result).order,row());
 assert.deepEqual(f.orderQueries[1].values,['1']);
});
test('order-status spoofed or other SQL errors and oversized rows leave uncertainty, never a false receipt or redispatch',async()=>{
 const C=require('../server/services/secureshopOrderStatusSqlContract'),{source,row}=require('./secureshopOrderStatusSqlContract.test');
 const f=fixture(),input=source(),target=await f.service.provision(input.lookup.scope);
 const other=new(require('pg').DatabaseError)('syntax error',0,'error');other.code='42601';
 for(const failure of [Object.assign(Error('spoof'),{code:'22P02'}),other,null]){
  const next={...input,lookup:{...input.lookup,operationId:randomUUID()}};
  f.setOrderFailure(failure);f.setOrderRows(failure?[]:[row(),row()]);
  await assert.rejects(f.service.lookupOrderStatus(next));
  const selectors={scope:input.lookup.scope,targetId:target.targetId,operationId:next.lookup.operationId,requestSha256:hash(C.request(next))};
  assert.equal(await f.service.readOrderStatusReceipt(selectors),null);
  await assert.rejects(f.service.readOrderStatusReference(selectors),{code:'ANALYTICS_QUERY_CONFLICT'});
  const count=f.orderQueries.length;await assert.rejects(f.service.lookupOrderStatus(next),{code:'ANALYTICS_QUERY_UNCERTAIN'});assert.equal(f.orderQueries.length,count);
 }
});
test('order-status saved reader rejects changed target, result, execution and digest authority',async()=>{
 const {source}=require('./secureshopOrderStatusSqlContract.test');const f=fixture(),input=source();
 const target=await f.service.provision(input.lookup.scope),saved=await f.service.lookupOrderStatus(input);
 const selectors={scope:input.lookup.scope,targetId:target.targetId,operationId:input.lookup.operationId,requestSha256:saved.requestSha256};
 const key=target.targetId+':'+input.lookup.operationId,original=structuredClone(f.queries.get(key)),count=f.orderQueries.length;
 for(const mutate of [r=>{r.receipt.targetId=randomUUID();},r=>{r.receipt.scope.platformOwnerId++;},r=>{r.receipt.result.row_count=1;},r=>{r.receipt.execution.generation='01';},r=>{r.result_sha256='f'.repeat(64);},r=>{r.receipt.sourceManifestSha256='f'.repeat(64);},r=>{r.receipt.kind='query';}]){
  const value=structuredClone(original);mutate(value);f.queries.set(key,value);
  await assert.rejects(f.service.readOrderStatusReceipt(selectors));await assert.rejects(f.service.readOrderStatusReference(selectors));
 }
 f.queries.set(key,original);await assert.rejects(f.service.readOrderStatusReceipt({...selectors,requestSha256:'e'.repeat(64)}),{code:'ANALYTICS_QUERY_CONFLICT'});
 assert.equal(f.orderQueries.length,count);assert.equal(f.productQueries.length,0);
});
