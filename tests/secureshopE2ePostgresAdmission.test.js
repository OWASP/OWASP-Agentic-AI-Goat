'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {admitSecureShopE2ePostgres}=require('../scripts/lib/secureshop-e2e-postgres-admission');

const valid=()=>({
  PG_TEST_DISPOSABLE:'yes',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',
  SS_DISABLE_OLLAMA:'true',SS_ENABLE_REAL_LLM_TESTS:'false',AI_PROVIDER:'mock',
  SECURESHOP_DATABASE_URL:'postgresql://dvaia_secureshop_runtime@127.0.0.1:55432/owasp_ai_goat_test_browser_commerce',
  SECURESHOP_MIGRATION_DATABASE_URL:'postgresql://dvaia_secureshop_migration@127.0.0.1:55432/owasp_ai_goat_test_browser_commerce',
  SECURESHOP_AGENTS_DATABASE_URL:'postgresql://dvaia_secureshop_agents_runtime@127.0.0.1:55432/owasp_ai_goat_test_browser_agents',
  SECURESHOP_AGENTS_MIGRATION_DATABASE_URL:'postgresql://dvaia_secureshop_agents_migration@127.0.0.1:55432/owasp_ai_goat_test_browser_agents',
});

test('SecureShop E2E PostgreSQL admission returns only the closed disposable worker environment',()=>{
  const environment={...valid(),UNRELATED_PRIVATE_VALUE:'not-forwarded'};
  const admitted=admitSecureShopE2ePostgres(environment);
  assert.deepEqual(admitted,valid());
  assert.equal(Object.isFrozen(admitted),true);
  assert.equal('UNRELATED_PRIVATE_VALUE' in admitted,false);
});

test('SecureShop E2E PostgreSQL admission rejects flags that could enable application or model behavior',()=>{
  for(const [key,value] of [
    ['PG_TEST_DISPOSABLE','no'],['PLATFORM_DATABASE_ENGINE','sqlite'],['WORKSHOP_DATABASE_ENGINE','sqlite'],
    ['SS_DISABLE_OLLAMA','false'],['SS_ENABLE_REAL_LLM_TESTS','true'],['AI_PROVIDER','ollama'],
  ]){
    const environment=valid();environment[key]=value;
    assert.throws(()=>admitSecureShopE2ePostgres(environment),error=>error.code===`SECURESHOP_E2E_${key}_DENIED`);
  }
});

test('SecureShop E2E PostgreSQL admission rejects noncanonical URLs and never includes their value in errors',()=>{
  const cases=[
    ['SECURESHOP_DATABASE_URL','postgresql://dvaia_secureshop_runtime@localhost:55432/owasp_ai_goat_test_browser_commerce','SECURESHOP_E2E_DATABASE_HOST_DENIED'],
    ['SECURESHOP_DATABASE_URL','postgresql://wrong_role@127.0.0.1:55432/owasp_ai_goat_test_browser_commerce','SECURESHOP_E2E_DATABASE_ROLE_DENIED'],
    ['SECURESHOP_DATABASE_URL','postgresql://dvaia_secureshop_runtime@127.0.0.1/owasp_ai_goat_test_browser_commerce','SECURESHOP_E2E_DATABASE_PORT_INVALID'],
    ['SECURESHOP_DATABASE_URL','postgresql://dvaia_secureshop_runtime@127.0.0.1:55432/application','SECURESHOP_E2E_DATABASE_NAME_DENIED'],
    ['SECURESHOP_DATABASE_URL','postgresql://dvaia_secureshop_runtime@127.0.0.1:55432/owasp_ai_goat_test_browser_commerce?sslmode=disable','SECURESHOP_E2E_DATABASE_OPTIONS_DENIED'],
  ];
  for(const [key,value,code] of cases){
    const environment=valid();environment[key]=value;
    assert.throws(()=>admitSecureShopE2ePostgres(environment),error=>error.code===code&&!error.message.includes(value));
  }
});

test('SecureShop E2E PostgreSQL admission binds each role pair and keeps commerce separate from agents',()=>{
  let environment=valid();environment.SECURESHOP_MIGRATION_DATABASE_URL=environment.SECURESHOP_MIGRATION_DATABASE_URL.replace('browser_commerce','other');
  assert.throws(()=>admitSecureShopE2ePostgres(environment),{code:'SECURESHOP_E2E_DATABASE_PAIR_MISMATCH'});
  environment=valid();environment.SECURESHOP_MIGRATION_DATABASE_URL=environment.SECURESHOP_DATABASE_URL;
  assert.throws(()=>admitSecureShopE2ePostgres(environment),{code:'SECURESHOP_E2E_DATABASE_ROLE_DENIED'});
  environment=valid();
  environment.SECURESHOP_AGENTS_DATABASE_URL=environment.SECURESHOP_AGENTS_DATABASE_URL.replace('browser_agents','browser_commerce');
  environment.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL=environment.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL.replace('browser_agents','browser_commerce');
  assert.throws(()=>admitSecureShopE2ePostgres(environment),{code:'SECURESHOP_E2E_DATABASE_STORES_NOT_DISTINCT'});
});
