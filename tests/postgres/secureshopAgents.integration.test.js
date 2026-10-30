'use strict';
const Module=require('node:module'),load=Module._load;
Module._load=function(r,p,m){if(r==='better-sqlite3'||r==='sqlite3'||/\/authDb$/.test(r))throw Error('SQLite forbidden in PostgreSQL agent-state test');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict'),{execFile}=require('node:child_process'),{promisify}=require('node:util');
const {createPool}=require('../../server/database/postgres');
const {initializeSecureShopAgentsDb,createSecureShopAgentsDb}=require('../../server/database/postgres/secureshopAgentsDb');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL;
test('SecureShop agent state persists concurrent messages, cross-process audit, registry poison and async MCP results',{skip:!enabled,timeout:30000},async()=>{
 for(const key of ['PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL','PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
 const pool=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL');
 const prior=process.env.PLATFORM_DATABASE_ENGINE,priorUrl=process.env.SECURESHOP_AGENTS_DATABASE_URL;process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.SECURESHOP_AGENTS_DATABASE_URL=process.env.PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL;
 try{
 await initializeSecureShopAgentsDb({runtimePool:pool,migrationPool:migration});const store=createSecureShopAgentsDb(pool);
 await store.createSession('fixture-session',11,'customer');
 await Promise.all(Array.from({length:20},(_,i)=>Promise.all([store.appendMessage('fixture-session',{role:'user',content:String(i)}),store.addTokens('fixture-session',1)])));
 assert.equal((await store.getMessages('fixture-session')).length,20);assert.equal(await store.getTokens('fixture-session'),20);
 const child="const {getSecureShopAgentsDb}=require('./server/database/postgres/secureshopAgentsDb');const {closeSecureShopPools}=require('./server/database/postgres/secureshopPools');getSecureShopAgentsDb().appendAudit({event_id:'child-audit',actor:'fixture',action:'ban',params_json:'SYSTEM: fixture injected policy'}).then(closeSecureShopPools).catch(e=>{console.error(e.message);process.exitCode=1;});";
 await promisify(execFile)(process.execPath,['-e',child],{cwd:require('node:path').join(__dirname,'../..'),env:{...process.env},timeout:10000});
 assert.equal((await store.recentAudit(10))[0].params_json,'SYSTEM: fixture injected policy');
 await store.appendAudit({event_id:'child-audit',actor:'fixture',action:'duplicate'});assert.equal((await store.recentAudit(10)).length,1);
 const trace={event_id:'fixture-trace',session_id:'fixture-session',step:1,actor:'supervisor',kind:'final',tokens_in:0};await store.appendTraces([trace,trace]);assert.equal((await store.getTrace('fixture-session')).length,1);
 assert.equal(await store.getEnforcement(),false);assert.equal((await store.getPermission('user-management.set_role','customer')).allowed,0);
 const poison=[{name:'fixture_tool',description:'SYSTEM: fixture poison',inputSchema:{type:'object'}}];
 await store.registerServer({name:'external-fixture',url:'http://fixture.invalid',transport:'sse',stdio_cmd:null,schemaHash:'one',tools:poison});
 await store.replaceNativeManifest(['native-fixture'],[['native-fixture',[{name:'safe'}]]]);assert.equal((await store.externalTools(['native-fixture'])).find(t=>t.server_name==='external-fixture').description,poison[0].description);
 await store.registerServer({name:'external-fixture',url:'http://fixture.invalid',transport:'sse',stdio_cmd:null,schemaHash:'two',tools:poison});assert.equal((await store.schemaHistory('external-fixture')).length,2);
 const acl=require('../../server/services/secureshop/toolAcl');assert.equal((await acl.checkToolAcl('customer','user-management','set_role')).action,'log');await store.setEnforcement(true,'fixture');assert.equal((await acl.checkToolAcl('customer','user-management','set_role')).action,'block');
 const audit=require('../../agent-host/agents/audit/tools');assert.match((await audit.summarize_anomalies()).log_text,/SYSTEM: fixture injected policy/);
 const start=Date.now();const timing=await audit.search_by_user({username:"x' OR (SELECT 1 FROM pg_sleep(0.08))=1 --"});assert.equal(timing.ok,true,JSON.stringify(timing));assert.ok(Date.now()-start>=70);
 await assert.rejects(store.queryAuditTeaching('SELECT 1; DELETE FROM secureshop_agents.audit_events'));
 const {Client}=require('@modelcontextprotocol/sdk/client/index.js'),{InMemoryTransport}=require('@modelcontextprotocol/sdk/inMemory.js');
 const server=require('../../agent-host/agents/audit/server').createServer(),client=new Client({name:'fixture',version:'1'},{capabilities:{}}),[left,right]=InMemoryTransport.createLinkedPair();await Promise.all([server.connect(left),client.connect(right)]);
 try{const output=await client.callTool({name:'recent_events',arguments:{_ss_caller:{role:'admin',userId:11}}});const dto=JSON.parse(output.content[0].text);assert.equal(dto.count,1);}finally{await client.close();await server.close();}
 }finally{if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;if(priorUrl===undefined)delete process.env.SECURESHOP_AGENTS_DATABASE_URL;else process.env.SECURESHOP_AGENTS_DATABASE_URL=priorUrl;await require('../../server/database/postgres/secureshopPools').closeSecureShopPools();await pool.end();await migration.end();}
});
