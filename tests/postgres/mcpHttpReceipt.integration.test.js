'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),path=require('node:path');
const {Pool}=require('pg');const {receiptFor}=require('../fixtures/mcpOwnedHttpReceipt');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.PG_HTTP_RUNTIME_URL&&process.env.PG_HTTP_MIGRATION_URL;
test('candidate central HTTP intent/receipt replay, uncertainty, reset and sibling isolation', {skip:!enabled},async t=>{
 for(const key of ['PG_HTTP_RUNTIME_URL','PG_HTTP_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_http_[a-f0-9]+$/);
 const runtime=new Pool({connectionString:process.env.PG_HTTP_RUNTIME_URL}),migration=new Pool({connectionString:process.env.PG_HTTP_MIGRATION_URL});
 t.after(async()=>{await runtime.end();await migration.end();});
 const canonical=require('../../db/postgres/migrate'),view=require('../helpers/xssBoundedMigrationView').createXssBoundedMigrationView({identity:82});
 const directory=view.directories.identity,manifest=await canonical.readMigrations(directory);
 const prefix=manifest.filter(row=>Number(row.name.slice(0,4))<=82);
 assert.deepEqual(await view.initializeIdentityRepository(runtime,migration),prefix.map(row=>row.name));
 const ledger=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(ledger.map(({name,checksum})=>({name,checksum})),prefix.map(({name,checksum})=>({name,checksum})));
 assert.equal(ledger.some(row=>row.name==='0083_mcp_http_operations.sql'),false);
 const population=async()=>({
  users:(await migration.query('SELECT id,username,email,password FROM identity.users ORDER BY id')).rows,
  owners:(await migration.query('SELECT owner_key,generation FROM graph_runtime.owners ORDER BY owner_key')).rows,
  runs:(await migration.query('SELECT run_id,owner_key,generation,status FROM graph_runtime.runs ORDER BY run_id')).rows,
 });
 const repository=require('../../server/database/postgres/mcpHttpReceiptRepository').createMcpHttpReceiptRepository(runtime);
 const scopes=[];
 for(let i=0;i<2;i++){
  const user=await require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime).createUser({username:'http-'+i,email:'http-'+i+'@example.invalid',passwordHash:await require('bcryptjs').hash('controlled-fixture',4)});
  const ownerKey=JSON.stringify(['MCP',String(user.id)]),runId=crypto.randomUUID();
  await migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);
  await migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[runId,ownerKey]);
  const execution={ownerKey,runId,durableGeneration:'0',check:async()=>{}};
  const identity={runId,operationId:crypto.randomUUID(),invocationId:crypto.randomUUID(),mcpSessionId:'mcp_'+user.id,mode:'vuln',url:'http://169.254.169.254/latest/?raw=%2f',binding:{ownerId:String(user.id),platformSessionId:String(i+1),generation:'0',targetId:crypto.randomUUID()}};
  scopes.push({identity,execution,userId:user.id});
 }
 const populatedBefore=await population();assert.equal(populatedBefore.users.length,2);assert.equal(populatedBefore.owners.length,2);assert.equal(populatedBefore.runs.length,2);
 view.setCeiling('identity',83);
 assert.deepEqual(await view.migrate(migration,directory),['0083_mcp_http_operations.sql']);
 const after83=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(after83.slice(0,ledger.length),ledger);
 assert.deepEqual(after83.map(({name,checksum})=>({name,checksum})),manifest.filter(row=>Number(row.name.slice(0,4))<=83).map(({name,checksum})=>({name,checksum})));
 assert.deepEqual(await population(),populatedBefore);
 assert.deepEqual(await view.migrate(migration,directory),[]);
 assert.deepEqual(await repository.checkReadiness(),{ready:true});
 await migration.query('REVOKE UPDATE(receipt_json) ON workshop_conversations.mcp_http_operations FROM dvaia_identity_runtime');await assert.rejects(repository.checkReadiness(),{code:'HTTP_RECEIPT_UNAVAILABLE'});await migration.query('GRANT UPDATE(receipt_json) ON workshop_conversations.mcp_http_operations TO dvaia_identity_runtime');
 const a=scopes[0],b=scopes[1];
 await assert.rejects(repository.begin({...a,identity:b.identity}),{code:'HTTP_RECEIPT_SCOPE_INVALID'});
 assert.deepEqual(await repository.begin(a),{state:'admitted'});await assert.rejects(repository.begin(a),{code:'HTTP_OPERATION_UNCERTAIN'});
 await assert.rejects(repository.begin({...a,identity:{...a.identity,url:a.identity.url+'x'}}),{code:'HTTP_RECEIPT_CONFLICT'});
 const receipt=receiptFor(a.identity);assert.equal((await repository.complete({...a,receipt})).replayed,false);
 assert.equal((await repository.complete({...a,receipt})).replayed,true);assert.deepEqual((await repository.begin(a)).receipt,receipt);
 await assert.rejects(repository.complete({...a,receipt:{...receipt,result:{...receipt.result,category:'different'}}}),{code:'HTTP_RECEIPT_CONFLICT'});
 await repository.begin(b);await repository.complete({...b,receipt:receiptFor(b.identity)});
 const siblingBefore=(await runtime.query('SELECT row_to_json(x) AS row FROM workshop_conversations.mcp_http_operations x WHERE user_id=$1',[b.userId])).rows;
 const pending={...a,identity:{...a.identity,operationId:crypto.randomUUID(),invocationId:crypto.randomUUID()}};await repository.begin(pending);
 // SQL failure after dispatch: a failed publish cannot erase admission or retry network.
 await migration.query("CREATE FUNCTION workshop_conversations.http_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'controlled publish failure'; END$$; CREATE TRIGGER http_test_failure BEFORE UPDATE ON workshop_conversations.mcp_http_operations FOR EACH ROW EXECUTE FUNCTION workshop_conversations.http_test_failure()");
 await assert.rejects(repository.complete({...pending,receipt:receiptFor(pending.identity)}),/controlled publish failure/);
 await migration.query('DROP TRIGGER http_test_failure ON workshop_conversations.mcp_http_operations; DROP FUNCTION workshop_conversations.http_test_failure()');
 await assert.rejects(repository.begin(pending),{code:'HTTP_OPERATION_UNCERTAIN'});
 // Simulated reset commits while a dispatched request is outside the SQL transaction.
 const reset=await migration.connect();await reset.query('BEGIN');
 await reset.query('UPDATE graph_runtime.owners SET generation=1 WHERE owner_key=$1',[a.execution.ownerKey]);
 const late=repository.complete({...pending,receipt:receiptFor(pending.identity)});
 const rejected=assert.rejects(late,{code:'STALE_GENERATION'});
 await reset.query('COMMIT');reset.release();await rejected;
 assert.deepEqual((await runtime.query('SELECT row_to_json(x) AS row FROM workshop_conversations.mcp_http_operations x WHERE user_id=$1',[b.userId])).rows,siblingBefore);
 await assert.rejects(runtime.query('UPDATE workshop_conversations.mcp_http_operations SET receipt_json=receipt_json WHERE operation_id=$1',[a.identity.operationId]),/immutable/);
 await assert.rejects(runtime.query('DELETE FROM workshop_conversations.mcp_http_operations WHERE operation_id=$1',[a.identity.operationId]),/permission denied/);
 await migration.query('DELETE FROM identity.users WHERE id=$1',[a.userId]);
 assert.equal((await runtime.query('SELECT count(*)::int AS n FROM workshop_conversations.mcp_http_operations WHERE user_id=$1',[a.userId])).rows[0].n,0);
 assert.deepEqual((await runtime.query('SELECT row_to_json(x) AS row FROM workshop_conversations.mcp_http_operations x WHERE user_id=$1',[b.userId])).rows,siblingBefore);
 if(process.env.MCP_HTTP_TEST_BASE_URL&&process.env.MCP_HTTP_TEST_TOKEN){
  const http=require('../../server/services/mcp/ownedHttpServiceClient').createOwnedHttpServiceClient({baseUrl:process.env.MCP_HTTP_TEST_BASE_URL,token:process.env.MCP_HTTP_TEST_TOKEN});
  assert.equal((await http.readiness()).ready,true);
  const scope={targetId:crypto.randomUUID(),platformOwnerId:b.userId,platformSessionId:2,generation:0};
  const owned=await http.admit(scope);let calls=0,lastInput;
  const client=require('../../server/services/mcp/ownedHttpClient').createOwnedHttpClient({scope,capability:owned.capability,readMode:async()=>'vuln',receiptRepository:repository,request:async(route,body)=>{if(route==='/owned-http/execute'){calls++;lastInput=body.request;}return http.request(route,body);}});
  const protocol=require('../../server/services/mcp/protocolContext');const sessionId='mcp_'+b.userId;const execution={...b.execution,effect:async()=>{}};
  try{
   await protocol.withProtocolInvocation({sessionId,execution,surface:'controlled-native-http'},async()=>{
    const receipt=await client.fetch(sessionId,'http://169.254.169.254/latest/?raw=%2f');assert.equal(receipt.result.hits.length,1);
    assert.deepEqual(await client.fetch(sessionId,'http://169.254.169.254/latest/?raw=%2f'),receipt);assert.equal(calls,1);
    const central=(await runtime.query('SELECT receipt_json FROM workshop_conversations.mcp_http_operations WHERE operation_id=$1',[receipt.identity.operationId])).rows[0];assert.deepEqual(central.receipt_json,receipt);
   });
   await migration.query("CREATE FUNCTION workshop_conversations.http_real_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'controlled real post-network SQL failure'; END$$; CREATE TRIGGER http_real_failure BEFORE UPDATE ON workshop_conversations.mcp_http_operations FOR EACH ROW EXECUTE FUNCTION workshop_conversations.http_real_failure()");
   try{await protocol.withProtocolInvocation({sessionId,execution,surface:'controlled-native-http-failure'},async()=>{
    await assert.rejects(client.fetch(sessionId,'http://169.254.169.254/latest/?failure=1'),{code:'HTTP_OPERATION_UNCERTAIN'});assert.equal(calls,2);
    const pending=(await runtime.query('SELECT request_digest,receipt_json FROM workshop_conversations.mcp_http_operations WHERE operation_id=$1',[lastInput.operationId])).rows[0];assert.equal(pending.receipt_json,null);
    const sidecar=await http.request('/owned-http/receipt',{capability:owned.capability,operationId:lastInput.operationId,requestDigest:pending.request_digest});assert.equal(sidecar.state,'completed');assert.equal(sidecar.receipt.result.hits.length,1);
    await assert.rejects(client.fetch(sessionId,'http://169.254.169.254/latest/?failure=1'),{code:'HTTP_OPERATION_UNCERTAIN'});assert.equal(calls,2);
   });}finally{await migration.query('DROP TRIGGER http_real_failure ON workshop_conversations.mcp_http_operations; DROP FUNCTION workshop_conversations.http_real_failure()');}
   console.log('ACTUAL_HTTP_CENTRAL_RECEIPT_AND_POST_NETWORK_SQL_FAILURE_VERIFIED');
  }finally{await http.retire({...scope,operationId:crypto.randomUUID()});}
 }
 // Keep historical receipt/reset/deletion checks at0083; then independently
 // prove the complete canonical suffix preserves surviving rows and receipts.
 const beforeTail=await population(),receiptRows=(await migration.query('SELECT * FROM workshop_conversations.mcp_http_operations ORDER BY operation_id')).rows;
 assert.ok(receiptRows.length>0);
 assert.deepEqual(await canonical.migrate(migration,directory),manifest.filter(row=>Number(row.name.slice(0,4))>83).map(row=>row.name));
 const fullLedger=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(fullLedger.slice(0,after83.length),after83);
 assert.deepEqual(fullLedger.map(({name,checksum})=>({name,checksum})),manifest.map(({name,checksum})=>({name,checksum})));
 assert.deepEqual(await population(),beforeTail);
 assert.deepEqual((await migration.query('SELECT * FROM workshop_conversations.mcp_http_operations ORDER BY operation_id')).rows,receiptRows);
 assert.deepEqual(await canonical.migrate(migration,directory),[]);
});
