'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID}=require('node:crypto');const {Pool}=require('pg');const {migrate}=require('../../db/postgres/migrate');
test('durable bulk reset cohort survives enrollment, retry, authority change and uncertain effects',{skip:process.env.BULK_RESET_NATIVE!=='1',timeout:120000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE),fs.realpathSync(process.cwd()));
 const url=role=>{const u=new URL(process.env['WORKSHOP_RAG_'+role.toUpperCase()+'_URL']);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_workshop_rag_[a-f0-9]+$/);assert.equal(u.username,'dvaia_identity_'+role);return u.href;};
 const migration=new Pool({connectionString:url('migration')}),runtime=new Pool({connectionString:url('runtime'),max:1}),leasePool=new Pool({connectionString:url('runtime'),max:2});let dir;
 try{
 dir=fs.mkdtempSync(path.join(os.tmpdir(),'bulk-cohort-'));for(const name of fs.readdirSync('db/postgres/identity-migrations'))if(name.endsWith('.sql'))fs.copyFileSync('db/postgres/identity-migrations/'+name,path.join(dir,name));
 await migrate(migration,dir);
 const identity=require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime);
 const make=async role=>{const u=await identity.createUser({username:randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash('owned-password',4)});if(role==='admin'){await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[u.id]);await identity.grantPermission({userId:u.id,permission:'manage_progress',grantedBy:u.id});}return u.id;};
 const admin=await make('admin'),other=await make('admin'),one=await make(),two=await make();
 const session=async id=>(await migration.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour') RETURNING id",[id,require('node:crypto').createHash('sha256').update(randomUUID()).digest('hex')])).rows[0].id;
 let authority={actorId:admin,sessionId:String(await session(admin))};
 const before=JSON.stringify((await migration.query('SELECT id,username FROM identity.users ORDER BY id')).rows);
 fs.copyFileSync('docs/modernization/drafts/admin-bulk-reset/0084_admin_bulk_reset_cohort.candidate.sql',path.join(dir,'0084_admin_bulk_reset_cohort.sql'));
 await migrate(migration,dir);assert.deepEqual(await migrate(migration,dir),[]);assert.equal(JSON.stringify((await migration.query('SELECT id,username FROM identity.users ORDER BY id')).rows),before);
 const repo=require('../../server/database/postgres/adminBulkResetRepository').createAdminBulkResetRepository(runtime,{leasePool});
 await assert.rejects(runtime.query('SELECT * FROM identity.bulk_reset_children'),{code:'42501'});
 await assert.rejects(runtime.query('SELECT identity.bulk_reset_snapshot($1)',[randomUUID()]),{code:'42501'});
 const op=randomUUID();const input={operationId:op,requestKind:'workshop',workshopKeys:['csrf_workshop'],...authority};
 let calls=[],fail=true;const childReceipts=new Set();
 const service=require('../../server/services/postgresWorkshopResetService').createPostgresWorkshopResetService({progress:{},bulkJournal:repo,resolveBulkActor:async()=>authority,adapters:{csrf_workshop:{bulkResetReplaySafe:()=>true,resetOwner:async(owner,{operationId})=>{calls.push(Number(owner));if(childReceipts.has(operationId))return;if(Number(owner)===two&&fail){fail=false;throw new Error('controlled remote failure');}childReceipts.add(operationId);}}}});
 await assert.rejects(service.resetWorkshop({workshopKey:'csrf_workshop',operationId:op}),/controlled/);
 const three=await make();assert.equal((await repo.listPending(authority)).length,1);
 // Completed child's newly created state is represented by a sentinel; it must never be called again.
 calls=[];authority={actorId:admin,sessionId:String(await session(admin))};await service.resetWorkshop({workshopKey:'csrf_workshop',operationId:op});assert.deepEqual(calls,[two]);assert.ok(!calls.includes(three));assert.equal((await repo.listPending(authority)).length,0);
 const state=await repo.begin({...input,...authority});assert.deepEqual(state.children.map(c=>c.ownerId),[one,two]);assert.ok(state.children.every(c=>c.state==='completed'));
 await assert.rejects(repo.begin({...input,...authority,workshopKeys:['xss_workshop']}),{code:'BULK_RESET_CONFLICT'});
 await assert.rejects(repo.begin({...input,actorId:other,sessionId:String(await session(other))}),{code:'BULK_RESET_CONFLICT'});
 await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[authority.sessionId]);await assert.rejects(repo.listPending(authority),{code:'BULK_RESET_AUTHORITY_REJECTED'});authority={actorId:admin,sessionId:String(await session(admin))};
 await identity.revokePermission(admin,'manage_progress');await assert.rejects(repo.listPending(authority),{code:'BULK_RESET_AUTHORITY_REJECTED'});await identity.grantPermission({userId:admin,permission:'manage_progress',grantedBy:admin});
 await migration.query("UPDATE identity.user_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[authority.sessionId]);await assert.rejects(repo.listPending(authority),{code:'BULK_RESET_AUTHORITY_REJECTED'});authority={actorId:admin,sessionId:String(await session(admin))};
 await migration.query("UPDATE identity.users SET role='student',admin_level=0 WHERE id=$1",[admin]);await assert.rejects(repo.listPending(authority),{code:'BULK_RESET_AUTHORITY_REJECTED'});await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin]);
 const debt=randomUUID();await repo.begin({operationId:debt,requestKind:'workshop',workshopKeys:['xss_workshop'],...authority});
 await assert.rejects(repo.claim({operationId:debt,ordinal:1,...authority}),{code:'BULK_RESET_RECONCILIATION_REQUIRED'});
 await repo.withOperation(debt,async lease=>{await lease.claim({operationId:debt,ordinal:1,...authority});await assert.rejects(repo.withOperation(debt,async()=>{}),{code:'BULK_RESET_BUSY'});});
 await repo.withOperation(debt,async lease=>{await assert.rejects(lease.claim({operationId:debt,ordinal:1,...authority}),{code:'BULK_RESET_RECONCILIATION_REQUIRED'});});
 assert.ok((await repo.listPending(authority)).some(p=>p.operationId===debt));
 // Parent scope stays fixed even if all-workshop catalog expands on retry.
 const all=randomUUID();await repo.begin({operationId:all,requestKind:'all',workshopKeys:['csrf_workshop'],...authority});const retained=await repo.begin({operationId:all,requestKind:'all',workshopKeys:['csrf_workshop','xss_workshop'],...authority});assert.deepEqual(retained.workshopKeys,['csrf_workshop']);
 // Two concurrent operation leases leave the single runtime connection available for effects.
 await Promise.all([randomUUID(),randomUUID()].map(id=>repo.withOperation(id,async()=>assert.equal((await runtime.query('SELECT 1 AS ok')).rows[0].ok,1))));
 // Completed cohort does not depend on current adapter readiness.
 const completeService=require('../../server/services/postgresWorkshopResetService').createPostgresWorkshopResetService({bulkJournal:repo,resolveBulkActor:async()=>authority,adapters:{csrf_workshop:{preflight(){throw new Error('must not preflight completed');}}}});
 await completeService.resetWorkshop({workshopKey:'csrf_workshop',operationId:op});
 // A target removed after cohort capture receives an explicit terminal deletion receipt.
 const deleted=await make(),deletionOp=randomUUID();const deletion=await repo.begin({operationId:deletionOp,requestKind:'workshop',workshopKeys:['csrf_workshop'],...authority});
 const removed=deletion.children.find(c=>c.ownerId===deleted);await migration.query('DELETE FROM identity.users WHERE id=$1',[deleted]);
 await repo.withOperation(deletionOp,async lease=>assert.equal((await lease.claim({operationId:deletionOp,ordinal:removed.ordinal,...authority})).state,'deleted'));
 // Scope filtering must precede the bounded list: cross-device recovery past 100 unrelated cohorts.
 const populatedBefore=JSON.stringify((await migration.query('SELECT * FROM identity.bulk_reset_operations ORDER BY operation_id')).rows);
 fs.copyFileSync('docs/modernization/drafts/admin-bulk-reset/0088_admin_bulk_reset_scope_discovery.candidate.sql',path.join(dir,'0088_admin_bulk_reset_scope_discovery.sql'));
 await migrate(migration,dir);assert.deepEqual(await migrate(migration,dir),[]);
 assert.equal(JSON.stringify((await migration.query('SELECT * FROM identity.bulk_reset_operations ORDER BY operation_id')).rows),populatedBefore);
 for(let i=0;i<101;i++)await repo.begin({operationId:randomUUID(),requestKind:'workshop',workshopKeys:['xss_workshop'],...authority});
 const wanted=randomUUID();await repo.begin({operationId:wanted,requestKind:'workshop',workshopKeys:['mcp_workshop'],...authority});
 assert.ok(!(await repo.listPending(authority)).some(p=>p.operationId===wanted));
 await require('../../server/services/adminBulkResetComposition').assertAdminBulkResetReadiness(runtime);
 await migration.query('REVOKE EXECUTE ON FUNCTION identity.list_bulk_resets_for_scope(integer,bigint,text,text) FROM dvaia_identity_runtime');
 await assert.rejects(require('../../server/services/adminBulkResetComposition').assertAdminBulkResetReadiness(runtime),{code:'RESET_STORAGE_NOT_READY'});
 await migration.query('GRANT EXECUTE ON FUNCTION identity.list_bulk_resets_for_scope(integer,bigint,text,text) TO dvaia_identity_runtime');
 await require('../../server/services/adminBulkResetComposition').assertAdminBulkResetReadiness(runtime);
 const original=await repo.listPending(authority,{requestKind:'workshop',workshopKey:'mcp_workshop'});
 assert.equal(original.length,1);assert.equal(original[0].operationId,wanted);
 authority={actorId:admin,sessionId:String(await session(admin))};await make();
 assert.deepEqual(await repo.listPending(authority,{requestKind:'workshop',workshopKey:'mcp_workshop'}),original);
 assert.equal((await repo.listPending(authority,{requestKind:'all'}))[0].operationId,all);
 assert.deepEqual(await repo.listPending({actorId:other,sessionId:String(await session(other))},{requestKind:'workshop',workshopKey:'mcp_workshop'}),[]);
 for(const args of [[null,null],['all','mcp_workshop'],['workshop',null],['database_reset',null],['workshop','bad/key']])await assert.rejects(runtime.query('SELECT identity.list_bulk_resets_for_scope($1,$2,$3,$4)',[admin,authority.sessionId,...args]),{code:'22023'});
 await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[authority.sessionId]);
 await assert.rejects(repo.listPending(authority,{requestKind:'workshop',workshopKey:'mcp_workshop'}),{code:'BULK_RESET_AUTHORITY_REJECTED'});
 fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH,JSON.stringify({status:'passed',scope:'Native candidate0084 repository and production bulk service with controlled child effects; no actual cross-store recovery claim',cohortPreserved:true,completedChildrenSkipped:true,freshSessionResume:true,revokedSessionAndPermissionDenied:true,conflictingActorAndRequestDenied:true,uncertainNonReplayDebtPreserved:true,advisoryLeaseFenced:true,populatedUsersPreserved:true,secondMigrationNoop:true,scopeBeyond100Recovered:true,scopeFreshSessionExactCohort:true,scopeInputsAndAuthorityValidated:true},null,2));
 }finally{await leasePool.end();await runtime.end();await migration.end();if(dir)fs.rmSync(dir,{recursive:true,force:true});}
});
