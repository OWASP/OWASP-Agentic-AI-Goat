'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const {Pool}=require('pg');
const {createJournal}=require('../../sidecars/audit-sql-target/journal');const {createService}=require('../../sidecars/audit-sql-target/service');
const {createOwnedAuditSearchSnapshotBuilder}=require('../../server/services/secureshopOwnedAuditSearchSnapshot');const {createOwnedAuditSearchLifecycle}=require('../../server/services/secureshopOwnedAuditSearchLifecycle');
test('actual owned database lifecycle persists receipts and contains raw SQL', {skip:process.env.PG_AUDIT_SEARCH_DESIGN!=='yes'},async()=>{
 const url=new URL(process.env.PG_AUDIT_SEARCH_URL);assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/dvaia_test_audit_search_[a-f0-9]+$/);
 const config={host:url.hostname,port:Number(url.port),user:'http_test_admin',database:url.pathname.slice(1)};const pool=new Pool({...config,max:6});
 let service=createService({controlPool:pool,clusterConfig:config});
 const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:1,platformSessionId:2};
 const event={id:'agents:33333333-3333-4333-8333-333333333333',store:'agents',ts:'2026-09-19T12:00:00.123456Z',actor:'admin',action:'profile',target:null,params_json:'teaching',outcome:'completed',source_kind:'profile',source_id:'1'};
 const builder=createOwnedAuditSearchSnapshotBuilder({reader:{recent:async()=>({events:[event],hasMore:false})},assertCurrent:async()=>{}});
 const make=()=>createOwnedAuditSearchLifecycle({journal:createJournal({pool}),service,assertCurrent:async()=>{}});
 let first,second;
 try{
  await pool.query(fs.readFileSync('sidecars/audit-sql-target/schema.sql','utf8'));
  await pool.query(fs.readFileSync('sidecars/audit-sql-target/migrations/0002_query_receipts.sql','utf8'));await pool.query(fs.readFileSync('sidecars/audit-sql-target/migrations/0003_query_destruction_tombstones.sql','utf8'));
  await pool.query(`REVOKE CONNECT ON DATABASE ${config.database} FROM PUBLIC`);
  const {assertReadiness}=require('../../sidecars/audit-sql-target/readiness');
  const readiness=()=>assertReadiness({pool,controlDatabase:config.database,administrator:config.user});
  assert.equal((await readiness()).ready,true);
  await pool.query(`GRANT CONNECT ON DATABASE ${config.database} TO PUBLIC`);await assert.rejects(readiness(),/public/);await pool.query(`REVOKE CONNECT ON DATABASE ${config.database} FROM PUBLIC`);
  const snapshot=await builder.capture(scope);let lifecycle=make();first=await lifecycle.provision(snapshot);
  second=await lifecycle.provision(await builder.capture({...scope,platformOwnerId:2}));
  assert.notEqual(first,second);assert.equal(await lifecycle.provision(snapshot),first);
  const result=await service.search(first,"' UNION ALL SELECT secret,'x','x',NULL,'{}','x' FROM secureshop_agents.teaching_secrets --");
  assert.equal(result.ok,true);assert.ok(result.events.some(r=>r.id.startsWith('SYNTHETIC_AUDIT_CANARY_')));
  const denied=await service.search(first,"' UNION ALL SELECT pg_read_file('/etc/passwd'),'x','x',NULL,'{}','x' --");assert.equal(denied.ok,false);assert.match(denied.error,/permission denied/);
  const timingUsername="' UNION ALL SELECT 'sleep','x','x',NULL,'{}','x' FROM pg_sleep(0.12) --";
  const sleeping=await service.search(first,timingUsername);assert.equal(sleeping.ok,true);assert.ok(sleeping.durationMs>=80);
  assert.equal(sleeping.username,timingUsername);
  assert.deepEqual(sleeping.events.filter(row=>row.id==='sleep'),[
   {id:'sleep',actor:'x',action:'x',target:null,params_json:'{}',ts:'x'}]);
  const sqlTiming=service.timingEffect(sleeping);assert.equal(sqlTiming?.version,1);
  assert.equal(sqlTiming.clock,'process.hrtime.bigint');assert.equal(sqlTiming.baselineSql,'SELECT 1');
  assert.equal(sqlTiming.statementTimeoutMs,1000);assert.equal(sqlTiming.sleepFunctionPlanned,true);
  assert.match(sqlTiming.planSha256,/^[a-f0-9]{64}$/);
  assert.ok(sqlTiming.queryDurationMs>=84);assert.ok(sqlTiming.queryDurationMs-sqlTiming.baselineDurationMs>=72);
  assert.equal(service.timingEffect({...sleeping}),null);
  let fixedSqlCalls=0;
  const fixedGraph=require('../../server/services/secureshopOwnedAuditDecisionGraph').createOwnedAuditDecisionGraph({provider:{
   chat:async()=>({provider:'controlled',model:'fixture',tool_uses:[{id:'fixed-timing-call',name:'audit.search_by_user',args:{username:timingUsername}}]}),
   finalResponse:async()=>({provider:'controlled',model:'fixture',text:'The fixed audit SQL tool denied the request.'}),
  }});
  const fixed=await fixedGraph.run({message:'Inspect the bounded SQL delay',mode:'fixed',
   boundary:{identity:{runId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'},check:async()=>{},effect:async(_key,work)=>work()},
   query:async()=>{fixedSqlCalls++;throw Error('Fixed mode dispatched SQL');}});
  assert.equal(fixed.query.blocked,true);assert.equal(fixedSqlCalls,0);
  const long=await service.search(first,"' UNION ALL SELECT 'sleep','x','x',NULL,'{}','x' FROM pg_sleep(4) --");assert.equal(long.ok,false);assert.match(long.error,/statement timeout/);assert.equal(service.timingEffect(long),null);
  const credential=(await pool.query('SELECT password FROM owned_audit_credentials WHERE target=$1',[first])).rows[0];
  for(const database of [second,config.database]){const outsider=new Pool({...config,database,user:first,password:credential.password});try{await assert.rejects(outsider.query('SELECT 1'),/permission denied/);}finally{await outsider.end();}}
  await service.close();service=createService({controlPool:pool,clusterConfig:config});lifecycle=make();assert.equal(await lifecycle.provision(snapshot),first);
  const siblingBefore=(await service.search(second,'admin')).events;
  const pending=lifecycle.search(scope,"' UNION ALL SELECT 'sleep','x','x',NULL,'{}','x' FROM pg_sleep(0.2) --");
  // Observe the real query before racing retirement, not an arbitrary timer.
  for(let n=0;n<100;n++){const active=await pool.query("SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND state='active' AND query LIKE '%pg_sleep(0.2)%'",[first]);if(active.rowCount)break;if(n===99)throw Error('query did not start');await new Promise(r=>setTimeout(r,10));}
  const retiring=lifecycle.retire(scope);assert.equal((await pending).ok,true);await retiring;
  await assert.rejects(lifecycle.search(scope,'admin'),{code:'AUDIT_SEARCH_TARGET_UNCERTAIN'});assert.equal((await pool.query('SELECT state FROM owned_audit_targets WHERE target=$1',[first])).rows[0].state,'retired');
  assert.equal((await pool.query('SELECT 1 FROM pg_database WHERE datname=$1',[first])).rowCount,0);
  assert.deepEqual((await service.search(second,'admin')).events,siblingBefore);
  await lifecycle.retire({...scope,platformOwnerId:2});
  const interruptedScope={...scope,generation:2};
  const interrupted=createOwnedAuditSearchLifecycle({journal:createJournal({pool}),service:{...service,provision:async request=>{await service.provision(request);throw Error('controlled lost acknowledgment');}},assertCurrent:async()=>{}});
  const interruptedSnapshot=await builder.capture(interruptedScope);
  await assert.rejects(interrupted.provision(interruptedSnapshot),/controlled lost acknowledgment/);
  await assert.rejects(make().provision(interruptedSnapshot),{code:'AUDIT_SEARCH_TARGET_UNCERTAIN'});
  const pendingTarget=(await pool.query("SELECT target FROM owned_audit_targets WHERE state='pending'")).rows[0].target;
  await make().retire(interruptedScope);
  assert.equal((await pool.query('SELECT 1 FROM pg_database WHERE datname=$1',[pendingTarget])).rowCount,0);
  assert.equal((await pool.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[pendingTarget])).rowCount,0);
  const {createOwnedAuditBackend}=require('../../server/services/secureshopOwnedAuditSearchBackend');
  const {createPrivateAuditServer}=require('../../sidecars/audit-sql-target/http');
  const {privateRequestFor}=require('../../server/services/secureshopOwnedAuditSearchSnapshot');
  let httpQueryExecutions=0;const observedService={...service,search:async(...args)=>{httpQueryExecutions++;return service.search(...args);}};
  const http=createPrivateAuditServer({token:'n'.repeat(48),backend:createOwnedAuditBackend({journal:createJournal({pool}),service:observedService,checkReadiness:readiness})});
  const address=await http.listen();
  const rpc=async(path,body)=>{const response=await fetch(`http://127.0.0.1:${address.port}`+path,{method:'POST',headers:{authorization:'Bearer '+'n'.repeat(48),'content-type':'application/json'},body:JSON.stringify(body)});assert.equal(response.status,200);return response.json();};
  try{
   const binding={...scope,generation:3};const request=privateRequestFor(await builder.capture(binding));
   const admitted=await rpc('/provision',request);assert.deepEqual(await rpc('/provision',request),admitted);
   const searched=await rpc('/search',{binding,operationId:'44444444-4444-4444-8444-444444444444',username:"' UNION ALL SELECT secret,'x','x',NULL,'{}','x' FROM secureshop_agents.teaching_secrets --"});assert.equal(searched.result.ok,true);assert.ok(searched.result.events.some(r=>r.id.startsWith('SYNTHETIC_AUDIT_CANARY_')));
   const username="' UNION ALL SELECT secret,'x','x',NULL,'{}','x' FROM secureshop_agents.teaching_secrets --";
   assert.equal(httpQueryExecutions,1);assert.deepEqual(await rpc('/search',{binding,operationId:searched.operationId,username}),searched);assert.equal(httpQueryExecutions,1);
   const timingRequest={binding,operationId:'88888888-8888-4888-8888-888888888888',username:timingUsername};
   const timingReceipt=await rpc('/search',timingRequest);
   assert.equal(timingReceipt.result.ok,true);assert.equal(timingReceipt.result.username,timingUsername);
   assert.deepEqual(timingReceipt.result.events.filter(row=>row.id==='sleep'),[
    {id:'sleep',actor:'x',action:'x',target:null,params_json:'{}',ts:'x'}]);
   assert.equal(timingReceipt.timing.sleepFunctionPlanned,true);
   assert.equal(timingReceipt.timing.planSha256,timingReceipt.extraction.planSha256);
   assert.ok(timingReceipt.timing.queryDurationMs>=84);
   assert.ok(timingReceipt.timing.queryDurationMs-timingReceipt.timing.baselineDurationMs>=72);
   assert.equal(httpQueryExecutions,2);
   assert.deepEqual(await rpc('/search',timingRequest),timingReceipt);
   assert.equal(httpQueryExecutions,2);
   const backend=createOwnedAuditBackend({journal:createJournal({pool}),service,checkReadiness:readiness});
   for(const foreign of [{...binding,platformOwnerId:2},{...binding,generation:4}])
    await assert.rejects(backend.receipt({binding:foreign,operationId:timingRequest.operationId,username:timingUsername}),{code:'AUDIT_QUERY_UNCERTAIN'});
   await assert.rejects(backend.search({binding,operationId:searched.operationId,username:'changed'}),{code:'AUDIT_QUERY_CONFLICT'});
   await assert.rejects(pool.query("UPDATE owned_audit_queries SET receipt='{}' WHERE target=$1",[admitted.target]),/Immutable/);
   let effects=0;const interruptedQuery=createOwnedAuditBackend({journal:createJournal({pool}),service:{...service,search:async(...args)=>{effects++;await service.search(...args);throw Error('lost query acknowledgment');}},checkReadiness:readiness});
   const uncertainRequest={binding,operationId:'55555555-5555-4555-8555-555555555555',username:'admin'};
   await assert.rejects(interruptedQuery.search(uncertainRequest),{code:'AUDIT_QUERY_UNCERTAIN'});
   await assert.rejects(backend.search(uncertainRequest),{code:'AUDIT_QUERY_UNCERTAIN'});assert.equal(effects,1);
   const persistenceFailure=createOwnedAuditBackend({journal:{...createJournal({pool}),completeQuery:async()=>{throw Error('control persistence interrupted');}},service,checkReadiness:readiness});
   const failedCommit={binding,operationId:'66666666-6666-4666-8666-666666666666',username:'admin'};
   await assert.rejects(persistenceFailure.search(failedCommit),{code:'AUDIT_QUERY_UNCERTAIN'});await assert.rejects(backend.search(failedCommit),{code:'AUDIT_QUERY_UNCERTAIN'});
   const racing=backend.search({binding,operationId:'77777777-7777-4777-8777-777777777777',username:"' UNION ALL SELECT 'sleep','x','x',NULL,'{}','x' FROM pg_sleep(0.2) --"});
   for(let n=0;n<100;n++){const active=await pool.query("SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND state='active' AND query LIKE '%pg_sleep(0.2)%'",[admitted.target]);if(active.rowCount)break;if(n===99)throw Error('receipt query did not start');await new Promise(r=>setTimeout(r,10));}
   const retired=backend.retire({binding});const racedReceipt=await racing;assert.equal(racedReceipt.result.ok,true);
   assert.equal(racedReceipt.timing.sleepFunctionPlanned,true);
   assert.equal(racedReceipt.timing.planSha256,racedReceipt.extraction.planSha256);
   assert.ok(racedReceipt.timing.queryDurationMs>=140);
   await retired;
   assert.equal((await pool.query('SELECT 1 FROM pg_database WHERE datname=$1',[admitted.target])).rowCount,0);await assert.rejects(backend.search({binding,operationId:searched.operationId,username}),{code:'AUDIT_QUERY_RETIRED'});
   await assert.rejects(backend.search(timingRequest),{code:'AUDIT_QUERY_RETIRED'});
   assert.equal((await pool.query('SELECT count(*)::int AS count FROM owned_audit_queries WHERE target=$1',[admitted.target])).rows[0].count,5);
   await backend.destroy({binding});await backend.destroy({binding});
   const tombstones=(await pool.query('SELECT state,receipt,request_sha256,retired_result_sha256 FROM owned_audit_queries WHERE target=$1',[admitted.target])).rows;
   assert.equal(tombstones.length,5);assert.ok(tombstones.every(row=>row.state==='redacted'&&row.receipt===null&&row.request_sha256.length===64));assert.equal(tombstones.filter(row=>row.retired_result_sha256).length,3);
   await assert.rejects(backend.search({binding,operationId:searched.operationId,username}),{code:'AUDIT_QUERY_UNCERTAIN'});
   await assert.rejects(backend.search(timingRequest),{code:'AUDIT_QUERY_UNCERTAIN'});
  }finally{await http.close();}
  console.log('OWNED_AUDIT_DATABASE_LIFECYCLE_NATIVE_PASSED');
 }finally{await service.close();for(const name of [first,second])if(name)await service.retire(name);await pool.end();}
});
