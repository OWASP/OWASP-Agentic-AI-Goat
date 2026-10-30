'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.MCP_SHADOW_PRODUCTION_NATIVE==='1';
test('owned shadow activation binds exact current migrations and live packaged runtime before production composition',{skip:!enabled},async t=>{
 const {Pool}=require('pg');const pools=[];const pool=key=>{const url=new URL(process.env[key]);assert.match(url.pathname,/^\/owasp_ai_goat_test_workshop_rag_[a-f0-9]+(?:_mcp)?$/);const p=new Pool({connectionString:url.href});pools.push(p);return p;};
 const identityPool=pool('WORKSHOP_RAG_RUNTIME_URL'),identityMigrationPool=pool('WORKSHOP_RAG_MIGRATION_URL'),resourcePool=pool('SHADOW_MCP_RUNTIME_URL'),resourceMigrationPool=pool('SHADOW_MCP_MIGRATION_URL');t.after(()=>Promise.all(pools.map(p=>p.end())));
 await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identityPool,identityMigrationPool);
 await require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(resourcePool).initialize(resourceMigrationPool);
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'shadow-native-activation-'));t.after(()=>fs.rm(home,{recursive:true,force:true}));const file=path.join(home,'shadow.json');
 const config=require('../../server/services/mcp/ownedShadowManagedConfiguration');
 const value={version:1,enabled:false,url:process.env.MCP_SHADOW_TEST_BASE_URL,token:process.env.MCP_SHADOW_TEST_TOKEN,profile:process.env.MCP_SHADOW_TEST_PROFILE,container:process.env.MCP_SHADOW_TEST_PROFILE,image:process.env.MCP_SHADOW_TEST_IMAGE,runtimeDigest:null};config.validate(value);await fs.writeFile(file,JSON.stringify(value),{mode:0o600});
 // The already-qualified CLI dependency is controlled here; this gate proves
 // actual shadow service + exact two native stores, not full CLI installer.
 const cli={readiness:async()=>({ready:true,runnerReady:true,isolation:'bwrap-seccomp-v1'}),admit:async()=>({runner:{}}),retire:async()=>{}};
 const args={file,identityPool,identityMigrationPool,resourcePool,resourceMigrationPool,cli};const {activateOwnedShadow}=require('../../scripts/install/mcp-owned-shadow-activate');
 assert.equal((await activateOwnedShadow(args)).activationEnabled,true);const saved=config.load({file});assert.match(saved.runtimeDigest,/^[a-f0-9]{64}$/);const bytes=await fs.readFile(file);await activateOwnedShadow(args);assert.deepEqual(await fs.readFile(file),bytes);
 const {composeOwnedShadowProduction}=require('../../server/services/mcp/ownedShadowProduction');const composed=await composeOwnedShadowProduction({identityPool,resourcePool,targets:cli,configuration:saved,env:{LAB_MODE:'vuln'}});const ready=await composed.readiness();assert.equal(ready.shadowTransportReady,true);assert.equal(ready.shadowObjectiveQualified,false);
 const drift=await composeOwnedShadowProduction({identityPool,resourcePool,targets:cli,configuration:{...saved,runtimeDigest:'f'.repeat(64)},env:{LAB_MODE:'vuln'}});await assert.rejects(drift.readiness(),{code:'SHADOW_CHILD_CLEANUP_REQUIRED'});
 await resourceMigrationPool.query('REVOKE UPDATE(cleanup_receipt) ON mcp.shadow_target_leases FROM dvaia_mcp_runtime');await assert.rejects(activateOwnedShadow(args),{code:'SHADOW_LEASE_UNAVAILABLE'});assert.deepEqual(await fs.readFile(file),bytes);
 await resourceMigrationPool.query('GRANT UPDATE(cleanup_receipt) ON mcp.shadow_target_leases TO dvaia_mcp_runtime');await activateOwnedShadow(args);
 console.log(JSON.stringify({nativeActivation:true,currentMigrationChecksums:true,realPackagedReadiness:true,digestMismatchDenied:true,ACLDriftDenied:true,idempotentActivation:true,objectiveRelease:false,runtimeDigest:saved.runtimeDigest}));
});
