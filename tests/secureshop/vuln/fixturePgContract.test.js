'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {seedShop,seedAgents}=require('./_fixture');
const KEYS=['PG_TEST_DISPOSABLE','SECURESHOP_DATABASE_URL','SECURESHOP_MIGRATION_DATABASE_URL','SECURESHOP_AGENTS_DATABASE_URL','SECURESHOP_AGENTS_MIGRATION_DATABASE_URL'];

function controlledEnv(t,values){
  const prior=Object.fromEntries(KEYS.map(key=>[key,process.env[key]]));
  for(const key of KEYS)delete process.env[key];
  Object.assign(process.env,values);
  t.after(()=>{for(const key of KEYS)prior[key]===undefined?delete process.env[key]:process.env[key]=prior[key];});
}

test('shared PG fixture refuses missing disposable authority before connecting',async t=>{
  controlledEnv(t,{
    SECURESHOP_DATABASE_URL:'postgresql://dvaia_secureshop_runtime@127.0.0.1:1/dvaia_test_fixture',
    SECURESHOP_MIGRATION_DATABASE_URL:'postgresql://dvaia_secureshop_migration@127.0.0.1:1/dvaia_test_fixture',
  });
  await assert.rejects(seedShop(),/PG_TEST_DISPOSABLE=yes/);
});

test('shared PG fixture refuses non-loopback and wrong-role URL pairs before connecting',async t=>{
  controlledEnv(t,{
    PG_TEST_DISPOSABLE:'yes',
    SECURESHOP_DATABASE_URL:'postgresql://dvaia_secureshop_runtime@example.com/dvaia_test_fixture',
    SECURESHOP_MIGRATION_DATABASE_URL:'postgresql://dvaia_secureshop_migration@example.com/dvaia_test_fixture',
  });
  await assert.rejects(seedShop(),/loopback host/);
  process.env.SECURESHOP_AGENTS_DATABASE_URL='postgresql://wrong_role@127.0.0.1:1/dvaia_test_fixture';
  process.env.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL='postgresql://dvaia_secureshop_agents_migration@127.0.0.1:1/dvaia_test_fixture';
  await assert.rejects(seedAgents(),/must use role dvaia_secureshop_agents_runtime/);
});

test('shared PG fixture refuses mismatched disposable databases before connecting',async t=>{
  controlledEnv(t,{
    PG_TEST_DISPOSABLE:'yes',
    SECURESHOP_DATABASE_URL:'postgresql://dvaia_secureshop_runtime@127.0.0.1:1/dvaia_test_fixture_a',
    SECURESHOP_MIGRATION_DATABASE_URL:'postgresql://dvaia_secureshop_migration@127.0.0.1:1/dvaia_test_fixture_b',
  });
  await assert.rejects(seedShop(),/same disposable database/);
});

test('shared PG fixture refuses endpoint mismatches and connection-string overrides before connecting',async t=>{
  controlledEnv(t,{
    PG_TEST_DISPOSABLE:'yes',
    SECURESHOP_DATABASE_URL:'postgresql://dvaia_secureshop_runtime@127.0.0.1:5432/dvaia_test_fixture',
    SECURESHOP_MIGRATION_DATABASE_URL:'postgresql://dvaia_secureshop_migration@localhost:5432/dvaia_test_fixture',
  });
  await assert.rejects(seedShop(),/same loopback endpoint/);
  process.env.SECURESHOP_DATABASE_URL='postgresql://dvaia_secureshop_runtime@127.0.0.1:5432/dvaia_test_fixture?host=example.com';
  process.env.SECURESHOP_MIGRATION_DATABASE_URL='postgresql://dvaia_secureshop_migration@127.0.0.1:5432/dvaia_test_fixture';
  await assert.rejects(seedShop(),/must not contain query parameters/);
});

test('shared PG fixture refuses commerce and agents store aliasing before connecting',async t=>{
  controlledEnv(t,{
    PG_TEST_DISPOSABLE:'yes',
    SECURESHOP_DATABASE_URL:'postgresql://dvaia_secureshop_runtime@127.0.0.1:5432/dvaia_test_shared',
    SECURESHOP_MIGRATION_DATABASE_URL:'postgresql://dvaia_secureshop_migration@127.0.0.1:5432/dvaia_test_shared',
    SECURESHOP_AGENTS_DATABASE_URL:'postgresql://dvaia_secureshop_agents_runtime@127.0.0.1:5432/dvaia_test_shared',
  });
  await assert.rejects(seedShop(),/require distinct databases/);
});

test('agents reset preserves immutable import history',()=>{
  const source=fs.readFileSync(require.resolve('./_fixture'),'utf8');
  const reset=source.match(/async function resetAgents\(client\) \{([\s\S]*?)\n\}/)?.[1];
  assert.ok(reset,'expected resetAgents implementation');
  assert.doesNotMatch(reset,/import_batches|import_provenance/);
  assert.match(reset,/secureshopAgentsDb'\)\.seed\(client\)/);
});

test('fixture leases preserve cached production pools until the test file ends',()=>{
  const source=fs.readFileSync(require.resolve('./_fixture'),'utf8');
  const leaseClose=source.match(/async close\(\)\{([\s\S]*?)\n\s*\},\n\s*\};/)?.[1];
  assert.ok(leaseClose,'expected fixture close implementation');
  assert.doesNotMatch(leaseClose,/closeSecureShopPools/);
  assert.match(source,/after\(async\(\)=>\{\s*await require\('[^']*secureshopPools'\)\.closeSecureShopPools\(\);\s*\}\);/);
});
