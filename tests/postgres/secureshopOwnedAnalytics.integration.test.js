'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto');
const {Pool,Client}=require('pg');
const {createOwnedAnalyticsService}=require('../../sidecars/analytics-sql-target/service');
const {hash,request:checkedRequest,databaseName}=require('../../sidecars/analytics-sql-target/contract');
const {createOwnedAnalyticsJournal}=require('../../sidecars/analytics-sql-target/journal');
const {createOwnedAnalyticsAdapter}=require('../../server/services/secureshopOwnedAnalyticsAdapter');
const ProductSearch=require('../../server/services/secureshopProductSearchSqlContract');
const OrderStatus=require('../../server/services/secureshopOrderStatusSqlContract');
const {fixture:foundation}=require('../fixtures/secureshopAnalyticsFoundation');
const enabled=process.env.OWNED_ANALYTICS_NATIVE==='1';
test('owned Analytics native candidate', {skip:!enabled,timeout:150000},async()=>{
 const nonce=process.env.OWNED_ANALYTICS_OWNER,port=Number(process.env.OWNED_ANALYTICS_PORT),database=process.env.OWNED_ANALYTICS_CONTROL;
 assert.match(nonce,/^[a-f0-9]{12}$/);assert.equal(database,`dvaia_analytics_control_${nonce}`);assert.ok(port>1024&&port<65536);
 const connection={host:'127.0.0.1',port,user:'postgres',database,connectionTimeoutMillis:1500,query_timeout:4000};
 const control=new Pool({...connection,max:6});control.on('error',()=>{});let active=0,maximum=0,dispatches=0,targetPoolCreations=0;
 const pools=new Set();
 const createPool=config=>{targetPoolCreations++;const pool=new Pool(config);pool.on('error',()=>{});active++;maximum=Math.max(maximum,active);pools.add(pool);const end=pool.end.bind(pool);pool.end=async()=>{try{await end();}finally{if(pools.delete(pool))active--;}};return pool;};
 const cases=[];const record=(name,extra={})=>{cases.push({name,...extra});console.log(JSON.stringify({case:name,...extra}));};
 const scope=()=>({launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2});
 const request=(target,sql)=>({target,operationId:randomUUID(),runId:randomUUID(),requestId:randomUUID(),sessionId:randomUUID(),callId:'query-1',sql});
 let service;
 try{
  const systemIdentifier=(await control.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier;
  const identity={systemIdentifier,controlDatabase:database,clusterName:`dvaia-owned-analytics-${nonce}`};
  const migration=fs.readFileSync(path.join(__dirname,'../../docs/modernization/drafts/secureshop-bound-analytics/control-schema.candidate.sql'),'utf8'),checksum=hash(migration);
  await control.query('CREATE TABLE candidate_migrations(id text PRIMARY KEY,sha256 text NOT NULL)');
  async function migrate(text=migration){const prior=(await control.query("SELECT sha256 FROM candidate_migrations WHERE id='analytics-v1'")).rows[0];if(prior){assert.equal(prior.sha256,hash(text));return false;}const c=await control.connect();try{await c.query('BEGIN');await c.query(text);await c.query("INSERT INTO candidate_migrations VALUES('analytics-v1',$1)",[hash(text)]);await c.query('COMMIT');return true;}finally{c.release(true);}}
  assert.equal(await migrate(),true);record('fresh candidate schema');
  const options={controlPool:control,identity,createPool,connection};service=createOwnedAnalyticsService(options);
  const [a,b]=await Promise.all([service.provision(scope()),service.provision(scope())]);assert.notEqual(a.targetId,b.targetId);assert.notEqual(a.sourceManifestSha256,b.sourceManifestSha256);assert.equal(active,0);assert.ok(maximum<=2);record('concurrent provisioning',{maximumPools:maximum});
  // V48 service-only fixture: fresh targets receive a separate opaque synthetic
  // password.  The value remains in this isolated target/control path and is
  // never placed in a model, actor, public DTO, or result artifact.
  const targetLogins=(await control.query('SELECT target_id,password FROM owned_analytics_credentials WHERE target_id=ANY($1::uuid[]) ORDER BY target_id',[ [a.targetId,b.targetId] ])).rows;
  assert.equal(targetLogins.length,2);assert.equal(targetLogins.every(row=>/^[a-f0-9]{64}$/.test(row.password)),true);
  assert.equal(targetLogins[0].password!==targetLogins[1].password,true);assert.equal(targetLogins.every(row=>!row.password.includes('SYNTHETIC_KEY_')),true);
  const targetAdmin=new Client({...connection,database:databaseName(a.targetId)});targetAdmin.on('error',()=>{});let syntheticPassword,syntheticApiKey;
  try{await targetAdmin.connect();const row=(await targetAdmin.query("SELECT password,api_key FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin'")).rows;assert.equal(row.length,1);({password:syntheticPassword,api_key:syntheticApiKey}=row[0]);}
  finally{await targetAdmin.end().catch(()=>{});}
  assert.equal(/^[a-f0-9]{64}$/.test(syntheticPassword),true);assert.equal(syntheticPassword!==targetLogins.find(row=>row.target_id===a.targetId).password,true);assert.equal(syntheticPassword!==syntheticApiKey,true);
  const couponBank=[{id:1,code:'WELCOME10',discount_percent:10,active:1}];
  const probeRequest=({operationId=randomUUID(),step,code,mode='vuln'})=>({version:1,lookup:{scope:a.scope,operationId,persona:{id:3,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode,code,coupons:couponBank},execution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopCouponProbeNative',randomUUID()]),generation:'0',sessionId:randomUUID(),requestId:randomUUID(),step,callId:`coupon-probe:${step}`}});
  const character=syntheticPassword[0],wrongCharacter=character==='0'?'1':'0';
  const injectedCode=candidate=>`WELCOME10' AND (SELECT substring(password FROM 1 FOR 1) FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin')='${candidate}'--`;
  const probeTrue=probeRequest({step:1,code:injectedCode(character)}),probeTrueReceipt=await service.lookupCouponProbe(probeTrue);
  assert.deepEqual(probeTrueReceipt.result,{coupon:couponBank[0]});assert.deepEqual(await service.readCouponProbeReceipt({scope:a.scope,targetId:a.targetId,operationId:probeTrue.lookup.operationId,requestSha256:probeTrueReceipt.requestSha256}),probeTrueReceipt);
  const privateReference=await service.readCouponProbeReference({scope:a.scope,targetId:a.targetId,operationId:probeTrue.lookup.operationId,requestSha256:probeTrueReceipt.requestSha256,position:1});
  assert.equal(privateReference.character===character,true);assert.equal(privateReference.characterSha256===hash(character),true);
  await assert.rejects(service.readCouponProbeReference({scope:a.scope,targetId:a.targetId,operationId:probeTrue.lookup.operationId,requestSha256:probeTrueReceipt.requestSha256,position:65}),{code:'ANALYTICS_PROBE_REFERENCE_UNAVAILABLE'});
  const probePools=targetPoolCreations;assert.deepEqual(await service.lookupCouponProbe(structuredClone(probeTrue)),probeTrueReceipt);assert.equal(targetPoolCreations,probePools);
  const probeFalse=probeRequest({step:2,code:injectedCode(wrongCharacter)}),probeFalseReceipt=await service.lookupCouponProbe(probeFalse);assert.deepEqual(probeFalseReceipt.result,{coupon:null});
  const probeFixed=probeRequest({step:3,code:probeTrue.lookup.code,mode:'fixed'}),probeFixedReceipt=await service.lookupCouponProbe(probeFixed);assert.deepEqual(probeFixedReceipt.result,{coupon:null});
  const assertImmutableProbeReceipt=async({step,path,replacement})=>{
   const probe=probeRequest({step,code:injectedCode(character)}),receipt=await service.lookupCouponProbe(probe);
   const before=(await control.query('SELECT receipt FROM owned_analytics_queries WHERE target_id=$1 AND operation_id=$2',[a.targetId,probe.lookup.operationId])).rows[0].receipt;
   await assert.rejects(
    control.query(`UPDATE owned_analytics_queries SET receipt=jsonb_set(receipt,$3::text[],to_jsonb($4::text),true) WHERE target_id=$1 AND operation_id=$2`,[a.targetId,probe.lookup.operationId,path,replacement]),
    error=>error?.code==='P0001'&&error?.message==='Query receipt is immutable'
   );
   const after=(await control.query('SELECT receipt FROM owned_analytics_queries WHERE target_id=$1 AND operation_id=$2',[a.targetId,probe.lookup.operationId])).rows[0].receipt;
   assert.deepEqual(after,before);assert.deepEqual(await service.lookupCouponProbe(structuredClone(probe)),receipt);
   return receipt;
  };
  const immutableTargetReceipt=await assertImmutableProbeReceipt({step:4,path:['targetId'],replacement:randomUUID()});
  const immutableManifestReceipt=await assertImmutableProbeReceipt({step:5,path:['sourceManifestSha256'],replacement:'0'.repeat(64)});
  assert.equal(immutableTargetReceipt.result.coupon.code,'WELCOME10');assert.equal(immutableManifestReceipt.result.coupon.code,'WELCOME10');
  record('coupon probe true false fixed replay private positional reference and immutable receipt mutation denial',{modelCalls:0,judgeCalls:0});
  // V53 is a named product-search operation. The deliberately interpolated
  // search term must yield a real eleven-column UNION row in this owned target;
  // a generic raw-SQL query or a protected-column OID would not prove it.
  const productRequest=(target,query,{mode='vuln',operationId=randomUUID(),step=1}={})=>{
   const sessionId=randomUUID();return {version:1,search:{scope:target.scope,operationId,
    persona:{id:3,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},
    mode,query,filters:{}},execution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',sessionId]),
     generation:'0',sessionId,requestId:randomUUID(),step,callId:`product-search-${step}`}};
  };
  const unionTerm="zz%' UNION ALL SELECT id,api_key,NULL::text,0::numeric,'Training',NULL::text,0,1,'active',NULL::text,NULL::text FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin'--";
  const unionRequest=productRequest(a,unionTerm),unionStatement=ProductSearch.statement(unionRequest);
  assert.equal(unionStatement.values.length,0);
  assert.ok(unionStatement.text.includes("name LIKE '%"+unionTerm+"%'"));
  assert.ok(unionStatement.text.includes('UNION ALL SELECT id,api_key,NULL::text,0::numeric,'));
  assert.deepEqual(ProductSearch.COLUMNS,['id','name','description','price','category','image_url',
   'stock_quantity','retailer_id','status','created_at','updated_at']);
  const unionReceipt=await service.searchProducts(unionRequest);
  assert.equal(unionReceipt.kind,'product-search-sql');assert.equal(unionReceipt.targetId,a.targetId);
  assert.equal(unionReceipt.requestSha256,hash(ProductSearch.request(unionRequest)));
  assert.equal(unionReceipt.resultSha256,hash(unionReceipt.result));
  assert.equal(unionReceipt.sqlSha256,hash(unionStatement.text));assert.equal(unionReceipt.valuesSha256,hash([]));
  assert.equal(unionReceipt.result.row_count,1);assert.equal(unionReceipt.result.rows.length,1);
  const unionRow=unionReceipt.result.rows[0];assert.deepEqual(Object.keys(unionRow),ProductSearch.COLUMNS);
  assert.equal(unionRow.id,1);assert.equal(unionRow.name,syntheticApiKey);
  assert.equal(unionRow.name.startsWith('SYNTHETIC_KEY_'),true);
  assert.deepEqual(ProductSearch.publicResult(unionRequest,unionReceipt.result),[unionRow]);
  const unionSelector={scope:a.scope,targetId:a.targetId,operationId:unionRequest.search.operationId,
   requestSha256:unionReceipt.requestSha256};
  assert.deepEqual(await service.readProductSearchReceipt(unionSelector),unionReceipt);
  const unionReference=await service.readProductSearchReference(unionSelector);
  assert.deepEqual(unionReference,{version:1,targetId:a.targetId,operationId:unionRequest.search.operationId,
   requestSha256:unionReceipt.requestSha256,sourceManifestSha256:a.sourceManifestSha256,
   rowId:1,field:'api_key',value:syntheticApiKey,valueSha256:hash(syntheticApiKey)});
  const productReplayPools=targetPoolCreations;
  assert.deepEqual(await service.searchProducts(structuredClone(unionRequest)),unionReceipt);
  assert.equal(targetPoolCreations,productReplayPools);
  await assert.rejects(service.searchProducts({...unionRequest,search:{...unionRequest.search,query:'different'}}),
   {code:'ANALYTICS_QUERY_CONFLICT'});
  await assert.rejects(service.readProductSearchReceipt({...unionSelector,scope:b.scope}),
   {code:'ANALYTICS_TARGET_INVALID'});
  await assert.rejects(service.readProductSearchReference({...unionSelector,scope:b.scope}),
   {code:'ANALYTICS_TARGET_INVALID'});
  const fixedProductRequest=productRequest(a,unionTerm,{mode:'fixed',step:2});
  const fixedProductReceipt=await service.searchProducts(fixedProductRequest);
  assert.deepEqual(ProductSearch.statement(fixedProductRequest).values,[`%${unionTerm}%`]);
  assert.equal(fixedProductReceipt.result.row_count,0);
  assert.deepEqual(ProductSearch.publicResult(fixedProductRequest,fixedProductReceipt.result),[]);
  const ordinaryProductRequest=productRequest(a,'Training product 256',{step:3});
  const ordinaryProductReceipt=await service.searchProducts(ordinaryProductRequest);
  assert.deepEqual(ordinaryProductReceipt.result.rows.map(row=>row.id),[256]);
  assert.equal(JSON.stringify(ordinaryProductReceipt.result).includes(syntheticApiKey),false);
  const siblingProductRequest=productRequest(b,'Training product 256',{step:4});
  const siblingProductReceipt=await service.searchProducts(siblingProductRequest);
  assert.deepEqual(siblingProductReceipt.result.rows.map(row=>row.id),[256]);
  record('named product LIKE eleven-column UNION, protected reference, fixed parameter denial, ordinary search, replay and sibling isolation',{modelCalls:0,judgeCalls:0});
  // V50 names the support.order_status sink.  Keep the native proof at the
  // owned target boundary: only the admitted vulnerable statement may expose
  // the PostgreSQL 22P02 text, while fixed mode binds the identical input.
  const orderStatusRequest=(target,order_id,{mode='vuln',operationId=randomUUID(),step=1}={})=>{
   const sessionId=randomUUID();
   return {version:1,lookup:{scope:target.scope,operationId,persona:{id:3,role:'customer'},
    personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode,order_id},
   execution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',sessionId]),
    generation:'0',sessionId,requestId:randomUUID(),step,callId:`order-status-${step}`}
  };};
  const errorProbe=`1 AND CAST((SELECT api_key FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin') AS integer)=0`;
  const orderVuln=orderStatusRequest(a,errorProbe),orderVulnStatement=OrderStatus.statement(orderVuln);
  assert.equal(orderVulnStatement.values.length,0);
  assert.match(orderVulnStatement.text,/CAST\(\(SELECT api_key FROM shop_users/);
  const orderVulnReceipt=await service.lookupOrderStatus(orderVuln);
  assert.deepEqual(orderVulnReceipt.result,{kind:'postgres-error',sqlstate:'22P02',message:orderVulnReceipt.result.message});
  assert.ok(orderVulnReceipt.result.message.includes(syntheticApiKey));
  assert.equal(orderVulnReceipt.result.message.includes('password'),false);
  assert.equal(orderVulnReceipt.resultSha256,hash(orderVulnReceipt.result));
  const orderSelector={scope:a.scope,targetId:a.targetId,operationId:orderVuln.lookup.operationId,requestSha256:hash(OrderStatus.request(orderVuln))};
  assert.deepEqual(await service.readOrderStatusReceipt(orderSelector),orderVulnReceipt);
  const orderReference=await service.readOrderStatusReference(orderSelector);
  assert.deepEqual(orderReference,{version:1,targetId:a.targetId,operationId:orderVuln.lookup.operationId,
   requestSha256:orderVulnReceipt.requestSha256,sourceManifestSha256:a.sourceManifestSha256,
   rowId:1,field:'api_key',value:syntheticApiKey,valueSha256:hash(syntheticApiKey)});
  const orderPools=targetPoolCreations;
  assert.deepEqual(await service.lookupOrderStatus(structuredClone(orderVuln)),orderVulnReceipt);
  assert.equal(targetPoolCreations,orderPools,'completed replay and receipt reads must not execute SQL');
  const fixedOrder=orderStatusRequest(a,errorProbe,{mode:'fixed',step:2});
  const fixedOrderStatement=OrderStatus.statement(fixedOrder);
  assert.deepEqual(fixedOrderStatement.values,[String(errorProbe)]);
  const fixedOrderReceipt=await service.lookupOrderStatus(fixedOrder);
  assert.equal(fixedOrderReceipt.result.kind,'postgres-error');
  assert.equal(fixedOrderReceipt.result.sqlstate,'22P02');
  assert.equal(JSON.stringify(fixedOrderReceipt).includes(syntheticApiKey),false);
  assert.match(fixedOrderReceipt.result.message,/invalid input syntax|integer/i);
  const orderSibling=orderStatusRequest(b,'1',{step:3});
  const orderSiblingReceipt=await service.lookupOrderStatus(orderSibling);
  assert.equal(orderSiblingReceipt.result.kind,'rows');assert.equal(orderSiblingReceipt.result.row_count,1);
  const orderSiblingBefore=orderSiblingReceipt.resultSha256;
  const abortOrder=new AbortController();
  const cancelOrder=service.lookupOrderStatus(orderStatusRequest(b,'1 AND (SELECT pg_sleep(5)) IS NULL',{step:4}),{signal:abortOrder.signal});
  cancelOrder.catch(()=>{});
  await new Promise(resolve=>setTimeout(resolve,100));
  const cancellation=Error('controlled order-status cancellation');
  abortOrder.abort(cancellation);
  await assert.rejects(cancelOrder,error=>error===abortOrder.signal.reason && error?.message==='controlled order-status cancellation');
  assert.equal(abortOrder.signal.aborted,true);
  assert.equal((await control.query('SELECT 1 FROM pg_stat_activity WHERE usename=$1',[databaseName(b.targetId)])).rows.length,0);
  const orderAfterCancel=await service.lookupOrderStatus(structuredClone(orderSibling));
  assert.equal(orderAfterCancel.resultSha256,orderSiblingBefore);
  const retirementScope=scope(),retirementTarget=await service.provision(retirementScope);
  const retirementRequest=orderStatusRequest(retirementTarget,'1',{step:5});
  const retirementReceipt=await service.lookupOrderStatus(retirementRequest);
  const retirementSelector={scope:retirementScope,targetId:retirementTarget.targetId,
   operationId:retirementRequest.lookup.operationId,requestSha256:retirementReceipt.requestSha256};
  await service.retire(retirementScope);
  await assert.rejects(service.readOrderStatusReceipt(retirementSelector),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
  assert.deepEqual((await service.lookupOrderStatus(structuredClone(orderSibling))).resultSha256,orderSiblingBefore);
  assert.equal((await control.query('SELECT 1 FROM pg_database WHERE datname=$1',[databaseName(retirementTarget.targetId)])).rows.length,0);
  assert.equal((await control.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[databaseName(retirementTarget.targetId)])).rows.length,0);
  record('V50 order_status 22P02 private-key error, fixed generic denial, receipt/replay no reexecution, cancellation drain, retirement and sibling preservation',{modelCalls:0,judgeCalls:0});
  // A chart is a bounded sidecar read. It must create a fresh target through
  // the same persona effect fence without admitting a model/query operation.
  const chartScope=scope(),chartPersona={id:12,role:'merchant'},chartSession={sessionId:randomUUID(),authorityVersion:'1'};
  const chartEffectContext=new (require('node:async_hooks').AsyncLocalStorage)();
  let chartStale=false,chartRevoked=false,chartProvisionCalls=0,chartExecuteCalls=0;
  const chartLaunches={assertCurrent:async input=>{assert.deepEqual(input,chartScope);if(chartStale)throw Object.assign(Error('stale'),{code:'STALE_LAUNCH'});}};
  const chartAuthority={capture:async input=>{assert.deepEqual(input,{scope:chartScope,personaId:12,role:'merchant',...chartSession});return {
   binding:{...chartScope,personaId:12,role:'merchant',...chartSession},
   assertRemoteAdmission:async()=>{assert.notEqual(chartEffectContext.getStore(),true,'do not reacquire persona authority within its effect fence');if(chartRevoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},
   withCrossStoreEffect:async work=>chartEffectContext.run(true,work)
  };}};
  const chartAdapter=createOwnedAnalyticsAdapter({launches:chartLaunches,personaAuthority:chartAuthority,schema:service.schema,targetService:{
   resolve:input=>service.resolve(input),
   provision:async(input,opts)=>{chartProvisionCalls++;return service.provision(input,opts);},
   topProducts:(input,limit,opts)=>service.topProducts(input,limit,opts),
   execute:async()=>{chartExecuteCalls++;throw Error('chart dispatched a model/query operation');}
  }});
  const chartInput={scope:chartScope,persona:chartPersona,personaSession:chartSession,limit:8,checkCurrent:async()=>{assert.notEqual(chartEffectContext.getStore(),true,'caller check cannot reenter persona effect fence');}};
  const chartQueriesBefore=Number((await control.query('SELECT count(*) FROM owned_analytics_queries')).rows[0].count);
  const firstChart=await chartAdapter.topProducts(chartInput),chartTarget=await service.resolve(chartScope);
  assert.ok(firstChart.rows.length>0);assert.ok(firstChart.rows.length<=8);assert.ok(firstChart.rows.every(row=>Number.isSafeInteger(row.id)&&typeof row.name==='string'&&Number.isFinite(Number(row.revenue))));
  assert.equal((await control.query('SELECT count(*) FROM owned_analytics_targets WHERE target_id=$1 AND state=$2',[chartTarget.targetId,'ready'])).rows[0].count,'1');
  // The sidecar admits two global operations, but only one per target; no queue.
  // Await every operation so rejection cannot race pool teardown.
  const concurrentCharts=await Promise.allSettled([chartAdapter.topProducts(chartInput),chartAdapter.topProducts(chartInput),chartAdapter.topProducts(chartInput)]);
  const admittedCharts=concurrentCharts.filter(row=>row.status==='fulfilled');
  const rejectedCharts=concurrentCharts.filter(row=>row.status==='rejected');
  assert.equal(admittedCharts.length,1);assert.equal(rejectedCharts.length,2);
  assert.deepEqual(rejectedCharts.map(row=>row.reason.code).sort(),['ANALYTICS_CAPACITY','ANALYTICS_TARGET_BUSY']);
  for(const result of admittedCharts)assert.deepEqual(result.value,firstChart);
  assert.deepEqual(await service.resolve(chartScope),chartTarget);
  assert.equal((await control.query('SELECT count(*) FROM owned_analytics_targets WHERE scope=$1::jsonb',[JSON.stringify(chartScope)])).rows[0].count,'1');
  assert.equal((await control.query('SELECT count(*) FROM pg_database WHERE datname=$1',[databaseName(chartTarget.targetId)])).rows[0].count,'1');
  assert.equal((await control.query('SELECT count(*) FROM pg_roles WHERE rolname=$1',[databaseName(chartTarget.targetId)])).rows[0].count,'1');
  assert.equal(Number((await control.query('SELECT count(*) FROM owned_analytics_queries')).rows[0].count),chartQueriesBefore);
  assert.equal(chartProvisionCalls,4);assert.equal(chartExecuteCalls,0);assert.equal(active,0);assert.ok(maximum<=2);
  chartRevoked=true;await assert.rejects(chartAdapter.topProducts(chartInput),{code:'SHOP_AUTH_INVALID'});chartRevoked=false;
  chartStale=true;await assert.rejects(chartAdapter.topProducts(chartInput),{code:'STALE_LAUNCH'});chartStale=false;
  assert.equal(chartProvisionCalls,4);assert.deepEqual(await service.resolve(b.scope),b);
  await service.retire(chartScope);await assert.rejects(service.resolve(chartScope),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
  chartStale=true;await assert.rejects(chartAdapter.topProducts(chartInput),{code:'STALE_LAUNCH'});assert.equal(chartProvisionCalls,4);
  assert.deepEqual(await service.resolve(b.scope),b);
  assert.equal(Number((await control.query('SELECT count(*) FROM owned_analytics_queries')).rows[0].count),chartQueriesBefore);
  record('first repeat and concurrent chart provision reuse with stale/revoked/retired denial and sibling preservation',{chartTargetId:chartTarget.targetId,queryJournalDelta:0,modelCalls:0});
  const input=request(a,"SELECT username,api_key,pii_json FROM shop_users WHERE role='admin' UNION SELECT name,'product','synthetic' FROM products WHERE id=1");
  const receipt=await service.execute(input);assert.ok(receipt.result.rows.some(r=>r.api_key.startsWith('SYNTHETIC_KEY_')));assert.equal(receipt.result.sql,input.sql);assert.equal(receipt.targetId,a.targetId);
  const stored=await service.execute({...input,sql:input.sql});assert.equal(hash(stored.result),receipt.resultSha256);assert.deepEqual(stored,receipt);record('raw synthetic UNION and immutable JSONB receipt');
  const typed=request(a,"SELECT TIMESTAMPTZ '2026-09-20T00:00:00Z' AS happened, jsonb_build_object('z',jsonb_build_array(3,2,1),'a',true) AS nested");const typedReceipt=await service.execute(typed);assert.equal(hash((await service.execute(typed)).result),typedReceipt.resultSha256);record('date and nested JSONB canonical replay');
  const oldHash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const oldInput={...input,operationId:randomUUID(),callId:'pre-canonical-replay'};
  const oldDigest=oldHash(checkedRequest(oldInput));assert.notEqual(oldDigest,hash(checkedRequest(oldInput)));
  const {protectedEvidence,...oldReceiptBody}=receipt;
  const oldReceipt={...oldReceiptBody,version:1,operationId:oldInput.operationId,callId:oldInput.callId,resultSha256:oldHash(receipt.result)};
  const pendingInput={...oldInput,operationId:randomUUID(),callId:'pre-canonical-pending'};
  const journal=createOwnedAnalyticsJournal(control);
  await journal.withLock(a.scope,async()=>{
   await journal.admitQuery(a.targetId,oldInput.operationId,oldDigest);
   await journal.completeQuery(a.targetId,oldInput.operationId,oldReceipt);
   await journal.admitQuery(a.targetId,pendingInput.operationId,oldHash(checkedRequest(pendingInput)));
  });
  const siblingBefore=await service.resolve(b.scope),poolCreationsBefore=targetPoolCreations;
  service=createOwnedAnalyticsService(options);
  assert.deepEqual(await service.execute(oldInput),oldReceipt);
  await assert.rejects(service.execute({...oldInput,sql:'SELECT 2'}),{code:'ANALYTICS_QUERY_CONFLICT'});
  await assert.rejects(service.execute(pendingInput),{code:'ANALYTICS_QUERY_UNCERTAIN'});
  assert.equal(targetPoolCreations,poolCreationsBefore,'replay and rejection must not create target SQL pools');
  assert.deepEqual(await service.resolve(b.scope),siblingBefore);
  record('pre-canonical completed and pending journal replay after service reopen',{targetSqlPoolsCreated:0});
  const preserved=hash((await control.query('SELECT * FROM owned_analytics_queries ORDER BY operation_id')).rows);assert.equal(await migrate(),false);assert.equal(hash((await control.query('SELECT * FROM owned_analytics_queries ORDER BY operation_id')).rows),preserved);await assert.rejects(migrate(migration+'\n-- changed'));record('populated migration ledger noop and checksum rejection',{checksum});
  const password=(await control.query('SELECT password FROM owned_analytics_credentials WHERE target_id=$1',[a.targetId])).rows[0].password;
  for(const forbidden of [database,'postgres',databaseName(b.targetId)]){const client=new Client({...connection,database:forbidden,user:databaseName(a.targetId),password});client.on('error',()=>{});try{await assert.rejects(client.connect());}finally{await client.end().catch(()=>{});}}
  record('target role denied sibling control and postgres CONNECT');
  for(const sql of ["UPDATE products SET price=0","CREATE TABLE stolen(id integer)","SELECT 1; SELECT 2","COPY (SELECT 1) TO PROGRAM 'true'","CREATE EXTENSION dblink","SELECT * FROM foreign_store.products"]){const r=request(a,sql);await assert.rejects(service.execute(r));await assert.rejects(service.execute(r),{code:'ANALYTICS_QUERY_UNCERTAIN'});}
  record('writes DDL multi-statement program extension foreign and retry denied');
  for(const sql of ['SELECT * FROM generate_series(1,1001)','SELECT repeat(\'x\',600000) FROM generate_series(1,2)','SELECT pg_sleep(5)'])await assert.rejects(service.execute(request(a,sql)));
  assert.equal((await control.query('SELECT 1 FROM pg_stat_activity WHERE usename=$1',[databaseName(a.targetId)])).rows.length,0);record('row byte and server time budget with backend absence');
  const abort=new AbortController();const pending=service.execute(request(a,'SELECT pg_sleep(5)'),{signal:abort.signal});
  for(let i=0;i<100;i++){if((await control.query("SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event='PgSleep'",[databaseName(a.targetId)])).rows.length)break;await new Promise(r=>setTimeout(r,10));}
  abort.abort(Error('controlled caller abort'));await assert.rejects(pending);assert.equal((await control.query('SELECT 1 FROM pg_stat_activity WHERE usename=$1',[databaseName(a.targetId)])).rows.length,0);record('caller abort drains backend');
  const f=foundation({args:{sql:'SELECT username FROM shop_users'},ownedQuery:{schema:service.schema,resolve:({scope})=>service.resolve(scope),execute:async x=>{dispatches++;await service.execute(requestProjection(x));return service.execute(requestProjection(x));}}});
  await service.provision(f.input.scope);const first=await f.service.query(f.input);assert.equal(first.receipt.resultSha256,hash(first.receipt.result));const again=await f.service.query(f.input);assert.deepEqual(again,first);assert.equal(dispatches,1);record('actual shared graph validates native JSONB receipt and replay',{model:'controlled',dispatches});
  const badScope=scope();const seedFault=createOwnedAnalyticsService({...options,createPool:config=>{const p=createPool(config),connect=p.connect.bind(p);p.connect=async()=>{const c=await connect(),query=c.query.bind(c);c.query=(...args)=>{if(typeof args[0]==='string'&&args[0].startsWith('INSERT INTO public.'))return Promise.reject(Error('injected seed failure'));return query(...args);};return c;};return p;}});
  await assert.rejects(seedFault.provision(badScope),/injected seed failure/);assert.equal(active,0);await assert.rejects(service.resolve(badScope));await service.retire(badScope);record('seed failure pending target and deterministic pool cleanup');
  await assert.rejects(service.execute(request({...b,targetId:randomUUID()},'SELECT 1')),{code:'ANALYTICS_TARGET_INVALID'});
  await assert.rejects(service.execute(request({...b,sourceManifestSha256:'0'.repeat(64)},'SELECT 1')),{code:'ANALYTICS_TARGET_INVALID'});record('foreign UUID and manifest denied before dispatch');
  const raceAbort=new AbortController();const race=service.execute(request(b,'SELECT pg_sleep(5)'),{signal:raceAbort.signal});race.catch(()=>{});
  let observed=false;for(let i=0;i<100;i++){observed=(await control.query("SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event='PgSleep'",[databaseName(b.targetId)])).rows.length>0;if(observed)break;await new Promise(r=>setTimeout(r,10));}
  assert.ok(observed);await assert.rejects(service.retire(b.scope),{code:'ANALYTICS_TARGET_BUSY'});raceAbort.abort(Error('end race'));await assert.rejects(race);record('actual executing query serializes retirement');
  const capacityAbort=new AbortController();const capacityWork=[a,b].map(t=>service.execute(request(t,'SELECT pg_sleep(5)'),{signal:capacityAbort.signal}));capacityWork.forEach(p=>p.catch(()=>{}));
  let two=false;for(let i=0;i<100;i++){two=(await control.query("SELECT 1 FROM pg_stat_activity WHERE usename=ANY($1::text[]) AND wait_event='PgSleep'",[[databaseName(a.targetId),databaseName(b.targetId)]])).rows.length===2;if(two)break;await new Promise(r=>setTimeout(r,10));}
  assert.ok(two);await assert.rejects(service.resolve(b.scope),{code:'ANALYTICS_CAPACITY'});assert.ok(active<=2);capacityAbort.abort(Error('end capacity check'));await Promise.all(capacityWork.map(p=>assert.rejects(p)));assert.equal(active,0);record('global two-work cap rejects third before connection');
  const faultScope=scope(),faultTarget=await service.provision(faultScope);
  const faultyControl={connect:()=>control.connect(),query:async(...args)=>{if(args[0]?.text?.includes('pg_terminate_backend'))throw Error('injected termination transport failure');return control.query(...args);}};
  const faulty=createOwnedAnalyticsService({...options,controlPool:faultyControl});
  await assert.rejects(faulty.execute(request(faultTarget,'SELECT * FROM generate_series(1,1001)')),{code:'ANALYTICS_QUERY_DRAIN_UNCERTAIN'});
  assert.equal((await control.query('SELECT state FROM owned_analytics_targets WHERE target_id=$1',[faultTarget.targetId])).rows[0].state,'retiring');
  assert.equal(active,0);await service.retire(faultScope);record('termination fault closes pool and quarantines target');
  const lostTarget=await service.provision(scope()),lostRequest=request(lostTarget,'SELECT pg_sleep(5)');
  const lost=service.execute(lostRequest);lost.catch(()=>{});let leasePid;
  for(let i=0;i<100;i++){
   const row=(await control.query("SELECT a.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND a.datname=$1 AND l.granted",[database])).rows[0];
   const running=(await control.query("SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event='PgSleep'",[databaseName(lostTarget.targetId)])).rows.length;
   if(row&&running){leasePid=row.pid;break;}await new Promise(r=>setTimeout(r,10));
  }
  assert.ok(leasePid,'actual held control lease and executing target observed');await control.query('SELECT pg_terminate_backend($1)',[leasePid]);await assert.rejects(lost);
  assert.equal(active,0);assert.equal((await control.query('SELECT 1 FROM pg_stat_activity WHERE usename=$1',[databaseName(lostTarget.targetId)])).rows.length,0);
  await assert.rejects(service.execute(lostRequest),{code:'ANALYTICS_QUERY_UNCERTAIN'});record('killed control lease aborts owned query and prevents redispatch');
  const bBefore=await service.execute(request(b,'SELECT * FROM products ORDER BY id'));await service.retire(a.scope);assert.deepEqual(await service.retire(a.scope),{retired:true,targetId:a.targetId});await assert.rejects(service.resolve(a.scope));
  await assert.rejects(service.readProductSearchReceipt(unionSelector),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
  await assert.rejects(service.readProductSearchReference(unionSelector),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
  assert.deepEqual(await service.searchProducts(structuredClone(siblingProductRequest)),siblingProductReceipt);
  await assert.rejects(service.readCouponProbeReceipt({scope:a.scope,targetId:a.targetId,operationId:probeTrue.lookup.operationId,requestSha256:probeTrueReceipt.requestSha256}),{code:'ANALYTICS_TARGET_UNAVAILABLE'});
  assert.equal((await control.query('SELECT 1 FROM pg_database WHERE datname=$1',[databaseName(a.targetId)])).rows.length,0);assert.equal((await control.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[databaseName(a.targetId)])).rows.length,0);
  const bAfter=await service.execute(request(b,'SELECT * FROM products ORDER BY id'));assert.equal(bAfter.resultSha256,bBefore.resultSha256);const redacted=(await control.query('SELECT state,receipt,result_sha256 FROM owned_analytics_queries WHERE target_id=$1 AND operation_id=$2',[a.targetId,input.operationId])).rows[0];assert.equal(redacted.state,'redacted');assert.equal(redacted.receipt,null);assert.equal(redacted.result_sha256,receipt.resultSha256);record('retirement tombstone redaction and sibling preservation');
  assert.equal(active,0);record('candidate cohort complete',{modelCalls:0,cases:cases.length,maximumPools:maximum});
 }finally{for(const pool of pools)await pool.end().catch(()=>{});await control.end();}
});
function requestProjection(x){return {target:x.target,operationId:x.operationId,runId:x.runId,requestId:x.requestId,sessionId:x.sessionId,callId:x.callId,sql:x.sql};}
