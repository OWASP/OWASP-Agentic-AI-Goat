'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {Pool}=require('pg');
const PREFIX='PG_STUDENT_DELETION_STORES_';
const stores=['ARIA','NOVA','MCP','CSRF','SUPPLY','CTF'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&stores.every(key=>process.env[`${PREFIX}${key}_MIGRATION_URL`]&&process.env[`${PREFIX}${key}_RUNTIME_URL`]);
function url(key,kind){const value=new URL(process.env[`${PREFIX}${key}_${kind}_URL`]);assert.ok(['127.0.0.1','localhost'].includes(value.hostname));assert.match(value.pathname,/^\/dvaia_test_[a-z0-9_]+$/);return value.href;}

test('native workshop destruction removes exact owner state, preserves shared content and siblings, and replays',{skip:!enabled,timeout:60000},async()=>{
 const pools=Object.fromEntries(stores.map(key=>[key,{migration:new Pool({connectionString:url(key,'MIGRATION')}),runtime:new Pool({connectionString:url(key,'RUNTIME')})}]));
 const owner='10101',sibling='20202';
 try{
  const aria=require('../../server/database/postgres/sqlWorkshopDb').createSqlWorkshopDb(pools.ARIA.runtime);await aria.initializeSqlWorkshopDb(pools.ARIA.migration);
  const nova=require('../../server/database/postgres/nosqlWorkshopDb').createNosqlWorkshopDb(pools.NOVA.runtime);await nova.initializeNosqlWorkshopDb(pools.NOVA.migration);
  const mcp=require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(pools.MCP.runtime);await mcp.initialize(pools.MCP.migration);
  const csrf=require('../../server/database/postgres/csrfWorkshopDb').createCsrfWorkshopDb(pools.CSRF.runtime);await csrf.initialize(pools.CSRF.migration);
  const supply=require('../../server/database/postgres/supplyChainWorkshopDb').createSupplyChainWorkshopDb(pools.SUPPLY.runtime);await supply.initialize(pools.SUPPLY.migration);
  const ctf=require('../../server/database/postgres/ctfDb').createCtfDb(pools.CTF.runtime);await ctf.initialize(pools.CTF.migration);

  for(const id of [owner,sibling]){
   const order=`DELETE-${id}`;
   await pools.ARIA.runtime.query("INSERT INTO aria.orders(order_number,user_id,product_name) VALUES($1,$2,'fixture')",[order,id]);
   await pools.ARIA.runtime.query("INSERT INTO aria.receipts(order_number,receipt_number) VALUES($1,$2)",[order,`RECEIPT-${id}`]);
   await pools.ARIA.runtime.query("INSERT INTO aria.cart(user_id,product_name) VALUES($1,'fixture')",[id]);
   await pools.ARIA.runtime.query("INSERT INTO aria.chat_history(user_id,message_type,message) VALUES($1,'user','private')",[id]);
   await pools.NOVA.runtime.query("INSERT INTO nova.reading_lists(user_id,paper_id) SELECT $1,paper_id FROM nova.papers ORDER BY id LIMIT 1",[id]);
   await pools.NOVA.runtime.query("INSERT INTO nova.chat_history(user_id,message_type,message) VALUES($1,'user','private')",[id]);
   await pools.MCP.runtime.query("INSERT INTO mcp.progress(user_key,objective_id) VALUES($1,'mcp_tool_discovery')",[id]);
   await pools.MCP.runtime.query("INSERT INTO mcp.tool_log(user_key,tool_name) VALUES($1,'fixture')",[id]);
   await pools.CSRF.runtime.query("INSERT INTO csrf.progress(user_key,objective_id) VALUES($1,'csrf_g1')",[id]);
   await pools.CSRF.runtime.query("INSERT INTO csrf.tool_log(user_key,tool_name) VALUES($1,'fixture')",[id]);
   await pools.CSRF.runtime.query("INSERT INTO csrf.victim_state(session_key,state_json) VALUES($1,'{}')",[`csrf_${id}`]);
   await pools.CSRF.runtime.query("INSERT INTO csrf.wallets(user_key) VALUES($1)",[id]);
   await pools.SUPPLY.runtime.query("INSERT INTO supply_chain.progress(user_id,objective_id) SELECT $1,objective_id FROM supply_chain.objectives ORDER BY ordinal LIMIT 1",[id]);
  }
  const targetParticipant=await ctf.registerParticipant(Number(owner),'delete-owner','delete-owner@test.invalid');
  const siblingParticipant=await ctf.registerParticipant(Number(sibling),'keep-owner','keep-owner@test.invalid');
  const stage=(await pools.CTF.runtime.query('SELECT id FROM ctf.ctf_stages ORDER BY stage_order LIMIT 1')).rows[0];
  const progress=await ctf.startStage(targetParticipant,stage.id);
  await pools.CTF.runtime.query("INSERT INTO ctf.ctf_judgments(run_id,participant_id,stage_id,progress_id,stage_digest,verdict,metadata) VALUES('delete-run',$1,$2,$3,$4,'fail','{}')",[targetParticipant,stage.id,progress,'a'.repeat(64)]);
  await pools.CTF.runtime.query("INSERT INTO ctf.ctf_bans(user_id,reason) VALUES($1,'fixture')",[Number(owner)]);
  await ctf.startStage(siblingParticipant,stage.id);

  for(const [name,service,expected] of [['ARIA',aria,4],['NOVA',nova,2],['MCP',mcp,2],['CSRF',csrf,4],['SUPPLY',supply,1]]){
   assert.equal((await service.destroyOwner(owner)).removed,expected,name);
   assert.equal((await service.destroyOwner(owner)).removed,0,`${name} replay`);
  }
  assert.equal((await ctf.destroyOwner(Number(owner))).removed,3);
  assert.equal((await ctf.destroyOwner(Number(owner))).removed,0);
  assert.equal((await pools.ARIA.runtime.query('SELECT count(*)::int n FROM aria.orders WHERE user_id=$1',[sibling])).rows[0].n,1);
  assert.equal((await pools.NOVA.runtime.query('SELECT count(*)::int n FROM nova.reading_lists WHERE user_id=$1',[sibling])).rows[0].n,1);
  assert.equal((await pools.MCP.runtime.query('SELECT count(*)::int n FROM mcp.progress WHERE user_key=$1',[sibling])).rows[0].n,1);
  assert.equal((await pools.CSRF.runtime.query('SELECT count(*)::int n FROM csrf.victim_state WHERE session_key=$1',[`csrf_${sibling}`])).rows[0].n,1);
  assert.equal((await pools.SUPPLY.runtime.query('SELECT count(*)::int n FROM supply_chain.progress WHERE user_id=$1',[sibling])).rows[0].n,1);
  assert.equal((await pools.CTF.runtime.query('SELECT count(*)::int n FROM ctf.ctf_participants WHERE user_id=$1',[Number(sibling)])).rows[0].n,1);
  assert.ok((await pools.ARIA.runtime.query('SELECT count(*)::int n FROM aria.products')).rows[0].n>0);
  assert.ok((await pools.NOVA.runtime.query('SELECT count(*)::int n FROM nova.papers')).rows[0].n>0);
  assert.ok((await pools.CTF.runtime.query('SELECT count(*)::int n FROM ctf.ctf_stages')).rows[0].n>0);
 }finally{await Promise.allSettled(Object.values(pools).flatMap(value=>[value.runtime.end(),value.migration.end()]));}
});
