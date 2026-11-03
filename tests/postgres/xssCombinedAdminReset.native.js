'use strict';
const assert=require('node:assert/strict'),path=require('node:path'),{randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const {migrate,readMigrations,executionSql}=require('../../db/postgres/migrate');
async function main(){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const port=Number(process.env.XSS_COMBINED_TEST_PORT);assert(port>1024&&port<65536);
 const nonce=process.env.XSS_COMBINED_TEST_NONCE;assert.match(nonce,/^[a-f0-9]{12}$/);
 const dir=path.resolve(__dirname,'../../db/postgres/identity-migrations'),migrations=await readMigrations(dir);
 for(const scenario of ['fresh','populated']){
  const database=`owasp_ai_goat_test_xss_combined_${scenario}_${nonce}`;
  const migration=new Pool({host:'127.0.0.1',port,database,user:'dvaia_identity_migration'}),runtime=new Pool({host:'127.0.0.1',port,database,user:'dvaia_identity_runtime'}),leases=new Pool({host:'127.0.0.1',port,database,user:'dvaia_identity_runtime'});
  try{
   if(scenario==='fresh')await migrate(migration,dir);
   else{
    await migration.query('BEGIN');
    await migration.query('CREATE SCHEMA dvaia_migrations; CREATE TABLE dvaia_migrations.ledger(name text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())');
    for(const entry of migrations.filter(m=>m.name<'0156')){await migration.query(executionSql(entry));await migration.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',[entry.name,entry.checksum]);}
    await migration.query('COMMIT');
   }
   const identity=require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime);
   async function owner(admin=false){const u=await identity.createUser({username:randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash('controlled-not-login',4)});if(admin){await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[u.id]);await identity.grantPermission({userId:u.id,permission:'manage_progress',grantedBy:u.id});}return u.id;}
   const admin=await owner(true),student=await owner(),sibling=await owner();
   const session=(await migration.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour') RETURNING id",[admin,'a'.repeat(64)])).rows[0].id;
   const authority={actorId:admin,sessionId:String(session)},repo=require('../../server/database/postgres/adminBulkResetRepository').createAdminBulkResetRepository(runtime,{leasePool:leases});
   const prior=await repo.begin({operationId:randomUUID(),requestKind:'workshop',workshopKeys:['csrf_workshop'],...authority});
   const before=(await migration.query('SELECT * FROM identity.bulk_reset_children ORDER BY operation_id,ordinal')).rows;
   if(scenario==='populated'){
    await require('../../server/services/adminBulkResetComposition').assertAdminBulkResetReadiness(runtime);
    await assert.rejects(require('../../server/services/adminBulkResetComposition').assertAdminBulkResetReadiness(runtime,{requireCombinedScope:true}),{code:'RESET_STORAGE_NOT_READY'});
    assert.deepEqual(await migrate(migration,dir),['0156_admin_bulk_xss_combined_scope.sql']);
   }
   assert.deepEqual(await migrate(migration,dir),[]);assert.deepEqual((await migration.query('SELECT * FROM identity.bulk_reset_children ORDER BY operation_id,ordinal')).rows,before);
   await require('../../server/services/adminBulkResetComposition').assertAdminBulkResetReadiness(runtime,{requireCombinedScope:true});
   await assert.rejects(repo.begin({operationId:randomUUID(),requestKind:'workshop',workshopKeys:['xss_workshop','csrf_workshop'],...authority}),{code:'BULK_RESET_CONFLICT'});
   const op=randomUUID(),input={operationId:op,requestKind:'workshop',workshopKeys:['xss_workshop','xss_email_builder'],...authority};
   const cohort=await repo.begin(input);assert.deepEqual(cohort.workshopKeys,['xss_email_builder','xss_workshop']);assert.equal(cohort.children.length,4);
   await owner();assert.deepEqual(await repo.begin(input),cohort);
   const pending=await repo.listPending(authority,{requestKind:'workshop',workshopKey:'xss_combined'});assert.equal(pending[0].operationId,op);
   await assert.rejects(repo.begin({...input,workshopKeys:['xss_workshop']}),{code:'BULK_RESET_CONFLICT'});
   const calls=[],receipts=new Set();let interrupted=true;
   const service=require('../../server/services/postgresWorkshopResetService').createPostgresWorkshopResetService({bulkJournal:repo,resolveBulkActor:async()=>authority,adapters:Object.fromEntries(cohort.workshopKeys.map(key=>[key,{bulkResetReplaySafe:async()=>true,resetAdministrativeOwner:async(owner,{operationId})=>{calls.push(operationId);if(!receipts.has(operationId))receipts.add(operationId);if(interrupted&&key==='xss_email_builder'){interrupted=false;throw Error('controlled post-effect interruption');}}}]))});
   await assert.rejects(service.resetWorkshop({workshopKey:'xss_combined',operationId:op}),/controlled/);
   await service.resetWorkshop({workshopKey:'xss_combined',operationId:op});assert.equal(receipts.size,4);assert.equal(calls.length,5);
   await service.resetWorkshop({workshopKey:'xss_combined',operationId:op});assert.equal(calls.length,5);
   assert.deepEqual(await repo.listPending(authority,{requestKind:'workshop',workshopKey:'xss_combined'}),[]);
   assert.deepEqual(await repo.begin({operationId:prior.operationId,requestKind:'workshop',workshopKeys:['csrf_workshop'],...authority}),prior);
   assert.deepEqual((await migration.query('SELECT id FROM identity.users WHERE id=ANY($1) ORDER BY id',[[student,sibling]])).rows.map(r=>r.id),[student,sibling]);
   console.log(JSON.stringify({scenario,passed:true,checks:['exact pair admission','immutable cohort','interrupted builder replay with controlled effects','completed replay no-op','scoped pending lookup','unrelated journal and users preserved','migration no-op','runtime grants and readiness']}));
  }finally{await Promise.all([migration.end(),runtime.end(),leases.end()]);}
 }
}
main().catch(e=>{console.error(e.code||e.message);process.exitCode=1;});
