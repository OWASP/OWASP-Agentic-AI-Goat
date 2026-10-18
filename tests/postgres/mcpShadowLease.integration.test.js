'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),path=require('node:path');const {Pool}=require('pg');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.PG_SHADOW_RUNTIME_URL&&process.env.PG_SHADOW_MIGRATION_URL;
function cleanup(scope,operationId){const body={version:1,targetId:scope.targetId,ownerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId,generation:scope.generation,operationId,status:'completed',completedAt:new Date(0).toISOString(),cleanupPending:false};return {...body,receiptSha256:crypto.createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.keys(body).sort().map(key=>[key,body[key]])))).digest('hex')};}
test('SHADOW child lease fences parent retirement, survives disabled restart and preserves siblings', {skip:!enabled},async t=>{
 for(const key of ['PG_SHADOW_RUNTIME_URL','PG_SHADOW_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_shadow_[a-f0-9]+$/);
 const runtime=new Pool({connectionString:process.env.PG_SHADOW_RUNTIME_URL}),migration=new Pool({connectionString:process.env.PG_SHADOW_MIGRATION_URL});t.after(async()=>{await runtime.end();await migration.end();});
 await require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(runtime).initialize(migration);
 const ledger=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 const resources=require('../../server/database/postgres/mcpResourceRepository').createMcpResourceRepository(runtime);
 const a={targetId:crypto.randomUUID(),platformOwnerId:7,platformSessionId:11,generation:0},b={targetId:crypto.randomUUID(),platformOwnerId:8,platformSessionId:12,generation:0};await resources.reserveRunnerTarget(a);await resources.reserveRunnerTarget(b);
 const copy=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'dvaia-shadow-lease-migrations-'));t.after(()=>fs.rm(copy,{recursive:true,force:true}));
 for(const name of await fs.readdir(path.resolve(__dirname,'../../db/postgres/workshop-migrations/mcp')))if(name.endsWith('.sql'))await fs.copyFile(path.resolve(__dirname,'../../db/postgres/workshop-migrations/mcp',name),path.join(copy,name));
 await fs.copyFile(path.resolve(__dirname,'../../docs/modernization/drafts/mcp-shadow/0006_mcp_shadow_child_leases.candidate.sql'),path.join(copy,'0006_mcp_shadow_child_leases.sql'));
 const migrate=require('../../db/postgres/migrate').migrate;assert.deepEqual(await migrate(migration,copy),ledger.some(row=>row.name==='0006_mcp_shadow_child_leases.sql')?[]:['0006_mcp_shadow_child_leases.sql']);assert.deepEqual((await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows.slice(0,ledger.length),ledger);assert.deepEqual(await migrate(migration,copy),[]);
 const lease=require('../../server/database/postgres/mcpShadowLeaseRepository').createMcpShadowLeaseRepository(runtime);
 assert.deepEqual(await lease.checkReadiness(),{ready:true});
 await migration.query('REVOKE UPDATE(cleanup_receipt) ON mcp.shadow_target_leases FROM dvaia_mcp_runtime');await assert.rejects(lease.checkReadiness(),{code:'SHADOW_LEASE_UNAVAILABLE'});await migration.query('GRANT UPDATE(cleanup_receipt) ON mcp.shadow_target_leases TO dvaia_mcp_runtime');
 await lease.reserve(a);await lease.reserve(a);await lease.activate(a);await lease.reserve(b);await lease.activate(b);
 const sibling=(await runtime.query('SELECT row_to_json(x) AS row FROM mcp.shadow_target_leases x WHERE target_id=$1',[b.targetId])).rows;
 const parentOp=crypto.randomUUID();await resources.beginRunnerRetirement({...a,operationId:parentOp});
 await assert.rejects(resources.completeRunnerRetirement({...a,operationId:parentOp,receipt:cleanup(a,parentOp)}),/Shadow child cleanup remains required/);
 await assert.rejects(runtime.query("UPDATE mcp.runner_targets SET state='retired',retired_at=now() WHERE target_id=$1",[a.targetId]),/Shadow child cleanup remains required/);
 await assert.rejects(lease.activate(a),{code:'SHADOW_LEASE_RETIRED'});
 const {createOwnedShadowCompositeTargets}=require('../../server/services/mcp/ownedShadowCompositeTargets');const cli={admit:async()=>{},retire:async()=>{},readRetirement:async()=>cleanup(a,parentOp)};
 const disabled=createOwnedShadowCompositeTargets({base:cli,leases:lease,enabled:false});await assert.rejects(disabled.retire({scope:a,operationId:parentOp}),{code:'SHADOW_CHILD_CLEANUP_REQUIRED'});
 let childScope;const shadow={retire:async value=>{childScope=value;},readRetirement:async()=>cleanup(a,childScope.operationId)};
 const resumed=createOwnedShadowCompositeTargets({base:cli,leases:lease,shadow,enabled:false});await resumed.retire({scope:a,operationId:parentOp});await resources.completeRunnerRetirement({...a,operationId:parentOp,receipt:cleanup(a,parentOp)});
 await disabled.retire({scope:a,operationId:parentOp});await lease.assertRetired(a);await assert.rejects(lease.reserve(a),{code:'SHADOW_LEASE_RETIRED'});
 assert.deepEqual((await runtime.query('SELECT row_to_json(x) AS row FROM mcp.shadow_target_leases x WHERE target_id=$1',[b.targetId])).rows,sibling);
 await assert.rejects(runtime.query("UPDATE mcp.shadow_target_leases SET state='active' WHERE target_id=$1",[a.targetId]),/transition rejected/);
 await assert.rejects(runtime.query('DELETE FROM mcp.shadow_target_leases WHERE target_id=$1',[a.targetId]),/permission denied/);
 if(process.env.PG_SHADOW_FRESH_MIGRATION_URL){const url=new URL(process.env.PG_SHADOW_FRESH_MIGRATION_URL);assert.equal(url.pathname,new URL(process.env.PG_SHADOW_MIGRATION_URL).pathname+'_fresh');const fresh=new Pool({connectionString:url.href});try{const applied=await migrate(fresh,copy);assert.deepEqual(applied,(await fs.readdir(copy)).filter(name=>name.endsWith('.sql')).sort());assert.deepEqual(await migrate(fresh,copy),[]);}finally{await fresh.end();}}
 assert.deepEqual(await migrate(migration,copy),[]);
});
