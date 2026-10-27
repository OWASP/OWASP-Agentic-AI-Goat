'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const inventory=require('./postgres/ownedV03SourceInventory');
test('fixed V03 inventory captures deferred roots and their actual imported children',()=>{
 const files=inventory.capture();
 for(const file of ['ownedV03ParentEntry.js','ownedV03PostgresOwner.js','ownedV03ListingsBridgeHost.js',
  'ownedSystemDiagnosticProducer.js','ownedSystemConfigPhaseDriver.js','ownedMcpOriginalBuildAdapter.js'])
  assert.ok(files.includes('tests/postgres/'+file),file);
 for(const file of ['tests/postgres/v03_browser_start_barrier.js','tests/postgres/v03_private_process.py','tests/postgres/owned_system_private_http_channel.py',
  'scripts/install/secureshop-owned-mcp-registry-setup.js','scripts/local-docker-authority.js'])assert.ok(files.includes(file),file);
 assert.equal(new Set(files).size,files.length);assert.deepEqual(files,[...files].sort());
 assert.ok(Object.isFrozen(files));
});
test('fixed inventory accepts no caller-selected roots or file maps',()=>{
 assert.throws(()=>inventory.capture({roots:[]}),/V03_SOURCE_INVENTORY_OPTIONS/);
});
