'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const bcrypt=require('bcryptjs');
const {createPool}=require('../../../server/database/postgres');
const {initializeSecureShopCommerceDb,initializeSecureShopAgentsDb}=require('../../../server/database/postgres/secureshopInitialization');

const PAIRS=Object.freeze({
  commerce:{runtimeKey:'SECURESHOP_DATABASE_URL',migrationKey:'SECURESHOP_MIGRATION_DATABASE_URL',runtimeRole:'dvaia_secureshop_runtime',migrationRole:'dvaia_secureshop_migration'},
  agents:{runtimeKey:'SECURESHOP_AGENTS_DATABASE_URL',migrationKey:'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL',runtimeRole:'dvaia_secureshop_agents_runtime',migrationRole:'dvaia_secureshop_agents_migration'},
});
let commerce,commerceMigration,agents,agentsMigration,admitted;
let closingPools;

function admitUrl(key,role){
  const value=process.env[key];
  if(!value)throw new Error(`${key} is required for the native SecureShop schema test`);
  let url;try{url=new URL(value);}catch{throw new Error(`${key} must be a valid PostgreSQL URL`);}
  if(!['postgres:','postgresql:'].includes(url.protocol)||url.search||url.hash)throw new Error(`${key} must be a PostgreSQL URL without options or fragments`);
  if(!['127.0.0.1','localhost','[::1]'].includes(url.hostname))throw new Error(`${key} must use a loopback host`);
  if(decodeURIComponent(url.username)!==role)throw new Error(`${key} must use role ${role}`);
  const database=decodeURIComponent(url.pathname.slice(1));
  if(!/^dvaia_test_[a-z0-9_]+$/.test(database))throw new Error(`${key} must name a dvaia_test_* database`);
  return{database,hostname:url.hostname,port:url.port||'5432'};
}

function admitPair(pair){
  const runtime=admitUrl(pair.runtimeKey,pair.runtimeRole),migration=admitUrl(pair.migrationKey,pair.migrationRole);
  assert.deepEqual({database:runtime.database,hostname:runtime.hostname,port:runtime.port},{database:migration.database,hostname:migration.hostname,port:migration.port},`${pair.runtimeKey} and ${pair.migrationKey} must address the same disposable store`);
  return runtime;
}

async function endPools(){
  if(closingPools)return closingPools;
  const pools=[commerce,commerceMigration,agents,agentsMigration].filter(Boolean);
  commerce=commerceMigration=agents=agentsMigration=undefined;
  if(!pools.length)return;
  const current=(async()=>{
    const outcomes=await Promise.allSettled(pools.map(pool=>Promise.resolve().then(()=>pool.end())));
    const errors=outcomes.filter(item=>item.status==='rejected').map(item=>item.reason);
    if(errors.length)throw new AggregateError(errors,'Failed to close SecureShop schema-test pools');
  })();
  closingPools=current;
  try{await current;}finally{if(closingPools===current)closingPools=undefined;}
}

test.before(async()=>{
  if(process.env.PG_TEST_DISPOSABLE!=='yes')throw new Error('SecureShop schema test requires PG_TEST_DISPOSABLE=yes');
  admitted={commerce:admitPair(PAIRS.commerce),agents:admitPair(PAIRS.agents)};
  if(admitted.commerce.database===admitted.agents.database&&admitted.commerce.hostname===admitted.agents.hostname&&admitted.commerce.port===admitted.agents.port)throw new Error('SecureShop commerce and agents tests require distinct databases');
  commerce=createPool(process.env,PAIRS.commerce.runtimeKey);
  commerceMigration=createPool(process.env,PAIRS.commerce.migrationKey);
  agents=createPool(process.env,PAIRS.agents.runtimeKey);
  agentsMigration=createPool(process.env,PAIRS.agents.migrationKey);
  try{
    await initializeSecureShopCommerceDb({runtimePool:commerce,migrationPool:commerceMigration});
    await initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration});
  }catch(error){await endPools().catch(closeError=>{error.closeError=closeError;});throw error;}
});
test.after(endPools);

async function tableExists(pool,schema,table){
  return (await pool.query('SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=$1 AND table_name=$2) AS present',[schema,table])).rows[0].present;
}
async function columnExists(pool,schema,table,column){
  return (await pool.query('SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 AND column_name=$3) AS present',[schema,table,column])).rows[0].present;
}

test('secureshop PostgreSQL store has v2 tables',async()=>{
  for(const table of ['product_images','product_manuals','reviews','coupons','support_tickets','email_threads','emails','policies'])assert.ok(await tableExists(commerce,'secureshop',table),`missing table ${table}`);
});

test('secureshop PostgreSQL store has additive columns on existing tables',async()=>{
  for(const [table,column] of [['shop_users','avatar_path'],['shop_users','session_token'],['shop_users','api_key'],['shop_users','pii_json'],['products','template_source'],['products','description_html'],['chat_messages','agent_trace_id']])assert.ok(await columnExists(commerce,'secureshop',table,column),`missing column ${table}.${column}`);
});

test('secureshop agents PostgreSQL store uses the admitted isolated database',async()=>{
  const row=(await agents.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  assert.deepEqual(row,{role:PAIRS.agents.runtimeRole,database:admitted.agents.database});
});

test('secureshop agents PostgreSQL store has all runtime tables',async()=>{
  for(const table of ['agent_sessions','agent_trace','mcp_registry','mcp_tool_cache','audit_events','vector_documents','vector_corpora','background_jobs','agent_provider_state'])assert.ok(await tableExists(agents,'secureshop_agents',table),`missing table ${table}`);
});

test('secureshop PostgreSQL production seed has multi-role student personas',async()=>{
  const rows=(await commerce.query("SELECT username,role FROM secureshop.shop_users WHERE username=ANY($1::text[]) ORDER BY username",[['student_c','student_m','student_a']])).rows;
  assert.deepEqual(rows,[{username:'student_a',role:'admin'},{username:'student_c',role:'customer'},{username:'student_m',role:'merchant'}]);
});

test('canonical shop practice accounts log in and reseeding preserves an edited account',async()=>{
  const names=['student_customer','student_merchant','student_admin'];
  const rows=(await commerce.query('SELECT username,role,password FROM secureshop.shop_users WHERE username=ANY($1::text[]) ORDER BY username',[names])).rows;
  assert.deepEqual(rows.map(({username,role})=>({username,role})),[
    {username:'student_admin',role:'admin'},
    {username:'student_customer',role:'customer'},
    {username:'student_merchant',role:'merchant'},
  ]);
  for(const row of rows)assert.equal(await bcrypt.compare('student123',row.password),true,row.username);
  const client=await commerceMigration.connect();
  try{
    await client.query('BEGIN');
    const changed=await bcrypt.hash('student-edited-password',10);
    await client.query('UPDATE secureshop.shop_users SET password=$1,full_name=$2 WHERE username=$3',[changed,'Edited Practice Name','student_customer']);
    await require('../../../server/database/postgres/secureshopSeed').seedSecureShop(client);
    const preserved=(await client.query('SELECT password,full_name FROM secureshop.shop_users WHERE username=$1',['student_customer'])).rows[0];
    assert.deepEqual(preserved,{password:changed,full_name:'Edited Practice Name'});
  }finally{try{await client.query('ROLLBACK');}finally{client.release();}}
});

test('secureshop PostgreSQL production seed has SQLi teaching coupon',async()=>{
  const row=(await commerce.query("SELECT code FROM secureshop.coupons WHERE code LIKE $1",["%OR '1'='1%"])).rows[0];
  assert.ok(row,'expected SQLi teaching coupon seeded');
});

test('secureshop PostgreSQL production seed has at least 3 policies',async()=>{
  const count=Number((await commerce.query('SELECT COUNT(*) AS count FROM secureshop.policies')).rows[0].count);
  assert.ok(count>=3);
});

test('secureshop agents PostgreSQL seed has 1 legitimate MCP server pre-registered',async()=>{
  const row=(await agents.query('SELECT name FROM secureshop_agents.mcp_registry WHERE name=$1',['filesystem-mcp'])).rows[0];
  assert.ok(row,'expected filesystem-mcp seed');
});
