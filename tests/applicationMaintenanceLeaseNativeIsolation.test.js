'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {ownedUrls}=require('./postgres/applicationMaintenanceLease.integration.test');
test('native lease admits only explicit owned loopback pairs',()=>{
 const env={PG_TEST_DISPOSABLE:'yes',APPLICATION_MAINTENANCE_LEASE_ISOLATED:'1',PG_APPLICATION_LEASE_1_RUNTIME_URL:'postgres://runtime@127.0.0.1:1234/owasp_ai_goat_test_lease_1_aaaaaaaaaaaa',PG_APPLICATION_LEASE_1_MIGRATION_URL:'postgres://migration@127.0.0.1:1234/owasp_ai_goat_test_lease_1_aaaaaaaaaaaa'};
 assert.ok(ownedUrls(env,1));
 for(const patch of [{PG_TEST_DISPOSABLE:'no'},{APPLICATION_MAINTENANCE_LEASE_ISOLATED:'0'},{PG_APPLICATION_LEASE_1_RUNTIME_URL:undefined},{PG_APPLICATION_LEASE_1_RUNTIME_URL:'postgres://runtime@localhost:1234/application'},{PG_APPLICATION_LEASE_1_MIGRATION_URL:env.PG_APPLICATION_LEASE_1_RUNTIME_URL},{PG_APPLICATION_LEASE_1_MIGRATION_URL:env.PG_APPLICATION_LEASE_1_MIGRATION_URL.replace(':1234',':9999')}])assert.throws(()=>ownedUrls({...env,...patch},1));
});
