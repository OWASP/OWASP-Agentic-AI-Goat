'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),http=require('node:http'),express=require('express'),{randomUUID}=require('node:crypto');
const {Pool}=require('pg'),jwt=require('jsonwebtoken');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
const {createLegacyChallengeDb}=require('../../server/database/postgres/legacyChallengeDb');
const {createSensitiveLookupDb}=require('../../server/database/postgres/sensitiveLookupDb');
const {createLegacyChallengeOwnerCleanup}=require('../../server/services/legacyChallengeOwnerCleanup');
const PREFIX='PG_STUDENT_DELETION_LEGACY_';
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&['IDENTITY_MIGRATION_URL','IDENTITY_RUNTIME_URL','LEGACY_MIGRATION_URL','LEGACY_RUNTIME_URL','LOOKUP_MIGRATION_URL','LOOKUP_RUNTIME_URL'].every(key=>process.env[PREFIX+key]);
function owned(key){const value=new URL(process.env[PREFIX+key]);assert.ok(['127.0.0.1','localhost'].includes(value.hostname));assert.match(value.pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);return value.href;}
async function staged(pool,directory,draft,migrationName){
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-student-deletion-store-migrations-'));
 try{
  const source=path.resolve(__dirname,'../..',directory),rows=await readMigrations(source);
  for(const row of rows)await fs.copyFile(path.join(source,row.name),path.join(temporary,row.name));
  const sql=await fs.readFile(path.resolve(__dirname,'../../docs/modernization/drafts',draft),'utf8');
  const existing=rows.find(row=>row.name===migrationName);
  if(existing)assert.equal(existing.sql,sql,'promoted migration differs from qualified draft');
  else await fs.writeFile(path.join(temporary,migrationName),sql,{flag:'wx'});
  assert.deepEqual(await migrate(pool,temporary),existing?[]:[migrationName]);
  assert.deepEqual(await migrate(pool,temporary),[]);
  assert.deepEqual((await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
    (await readMigrations(temporary)).map(({name,checksum})=>({name,checksum})));
 }finally{await fs.rm(temporary,{recursive:true,force:true});}
}

test('legacy and sensitive lookup deletion removes exact owner rows and owned bytes while preserving siblings',{skip:!enabled,timeout:60000},async()=>{
 // Mounted routes use canonical singletons: reject an unbound launcher before
 // importing a route can fall back to a repository SQLite fixture.
 assert.equal(process.env.PLATFORM_DATABASE_ENGINE,'postgres','Disposable mounted routes require PostgreSQL');
 for(const [appKey,store] of [['IDENTITY','IDENTITY'],['LEGACY_CHALLENGE','LEGACY'],['SENSITIVE_LOOKUP','LOOKUP']]){
  assert.ok(process.env[appKey+'_DATABASE_URL']===owned(store+'_RUNTIME_URL'),'Canonical runtime must bind to its disposable test store');
  assert.ok(process.env[appKey+'_MIGRATION_DATABASE_URL']===owned(store+'_MIGRATION_URL'),'Canonical migration must bind to its disposable test store');
 }
 const lm=new Pool({connectionString:owned('LEGACY_MIGRATION_URL')}),legacyPool=new Pool({connectionString:owned('LEGACY_RUNTIME_URL')});
 const sm=new Pool({connectionString:owned('LOOKUP_MIGRATION_URL')}),lookupPool=new Pool({connectionString:owned('LOOKUP_RUNTIME_URL')});
 const im=new Pool({connectionString:owned('IDENTITY_MIGRATION_URL')}),identityPool=new Pool({connectionString:owned('IDENTITY_RUNTIME_URL')});
 const uploadRoot=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-owned-legacy-uploads-'));
 try{
  const legacy=createLegacyChallengeDb(legacyPool),lookup=createSensitiveLookupDb(lookupPool);
  const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
  await initializeIdentityRepository(identityPool,im);
  await legacy.initializeLegacyChallengeDb(lm);await lookup.initialize(sm);
  await staged(im,'db/postgres/identity-migrations','legacy-upload-lifecycle.sql','0040_legacy_upload_lifecycle.sql');
  await staged(lm,'db/postgres/workshop-migrations/legacy_challenge','legacy-challenge-student-deletion.sql','0003_student_deletion.sql');
  await staged(sm,'db/postgres/workshop-migrations/sensitive_lookup','sensitive-lookup-student-deletion.sql','0002_student_deletion.sql');
  const identities=createIdentityRepository(identityPool),password='$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';
  const admin=await identities.createUser({username:'legacy-delete-admin',email:'legacy-delete-admin@test.invalid',passwordHash:password});
  const instructor=await identities.createUser({username:'legacy-delete-instructor',email:'legacy-delete-instructor@test.invalid',passwordHash:password});
  const subject=await identities.createUser({username:'legacy-delete-subject',email:'legacy-delete-subject@test.invalid',passwordHash:password});
  const keep=await identities.createUser({username:'legacy-delete-sibling',email:'legacy-delete-sibling@test.invalid',passwordHash:password});
  const interrupted=await identities.createUser({username:'legacy-delete-interrupted',email:'legacy-delete-interrupted@test.invalid',passwordHash:password});
  await im.query("UPDATE identity.users SET role='super_admin',admin_level=2 WHERE id=$1",[admin.id]);
  await im.query("UPDATE identity.users SET role='admin',admin_level=1 WHERE id=$1",[instructor.id]);
  const platformAdapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identities,progress:null,jwtSecret:process.env.JWT_SECRET});
  const adminIssued=await platformAdapter.createSession(await identities.findCredentialById(admin.id),{get:()=>null,ip:'127.0.0.1'}),adminSession={id:adminIssued.internalSessionId,token:adminIssued.token};
  const instructorIssued=await platformAdapter.createSession(await identities.findCredentialById(instructor.id),{get:()=>null,ip:'127.0.0.1'}),instructorSession={id:instructorIssued.internalSessionId,token:instructorIssued.token};
  const subjectSession=await identities.createSession({userId:subject.id,token:'legacy-subject-token',expiresAt:new Date(Date.now()+3600000),expectedPasswordHash:password});
  const siblingSession=await identities.createSession({userId:keep.id,token:'legacy-sibling-token',expiresAt:new Date(Date.now()+3600000),expectedPasswordHash:password});
  const interruptedSession=await identities.createSession({userId:interrupted.id,token:'legacy-interrupted-token',expiresAt:new Date(Date.now()+3600000),expectedPasswordHash:password});
  const owner=subject.id,sibling=keep.id,product=(await lm.query('SELECT id FROM legacy_challenge.products ORDER BY id LIMIT 1')).rows[0].id;
  for(const id of [owner,sibling]){
   const order=(await legacyPool.query("INSERT INTO legacy_challenge.orders(user_id,total_amount,platform_owner_id) VALUES($1,10,$1) RETURNING id",[id])).rows[0].id;
   await legacyPool.query('INSERT INTO legacy_challenge.order_items(order_id,product_id,quantity,price) VALUES($1,$2,1,10)',[order,product]);
   await legacyPool.query('INSERT INTO legacy_challenge.cart(user_id,product_id,platform_owner_id) VALUES($1,$2,$1)',[id,product]);
   await legacyPool.query("INSERT INTO legacy_challenge.reviews(product_id,user_id,rating,comment,platform_owner_id) VALUES($2,$1,5,'private',$1)",[id,product]);
   await legacyPool.query("INSERT INTO legacy_challenge.comments(user_id,content,platform_owner_id) VALUES($1,'private',$1)",[id]);
   await lm.query("INSERT INTO legacy_challenge.ai_conversations(user_id,prompt,platform_owner_id) VALUES($1,'historical private source',$1)",[id]);
   await lookupPool.query("INSERT INTO sensitive_lookup.exploitation_log(user_id,user_input) VALUES($1,'private')",[String(id)]);
  }
  await legacyPool.query("INSERT INTO legacy_challenge.comments(user_id,content) VALUES($1,'local identity collision')",[owner]);
  const historical=path.join(uploadRoot,'historical.bin'),sharedFile=path.join(uploadRoot,'shared.bin');await fs.writeFile(historical,'historical');await fs.writeFile(sharedFile,'shared');
  await legacyPool.query("INSERT INTO legacy_challenge.files(filename,original_name,file_path,uploaded_by) VALUES('historical.bin','historical.bin',$1,$2),('shared-a.bin','shared.bin',$3,$2),('shared-b.bin','shared.bin',$3,$4)",[historical,owner,sharedFile,sibling]);
  const {createLegacyUploadLifecycle}=require('../../server/services/legacyUploadLifecycle');
  const lifecycle=createLegacyUploadLifecycle({identityPool,uploadRoot});
  const cleanup=createLegacyChallengeOwnerCleanup({store:legacy,uploadRoot,lifecycle});
  await legacy.withPlatformMutationAuthority({identityPool,ownerId:admin.id,sessionId:adminSession.id},
    ()=>legacy.addComment([admin.id,'super-admin platform mutation',admin.id]));
  await legacy.withPlatformMutationAuthority({identityPool,ownerId:instructor.id,sessionId:instructorSession.id},
    ()=>legacy.addComment([instructor.id,'admin platform mutation',instructor.id]));
  const adminUpload=await lifecycle.runUpload({ownerId:instructor.id,sessionId:instructorSession.id},async lease=>{
   await lease.bindFilename('admin.bin');const target=path.join(lease.directory,'admin.bin');await fs.writeFile(target,'admin');
   await legacy.addManagedFile(['admin.bin','admin.bin',target,5,'application/octet-stream',instructor.id,instructor.id,lease.intentId]);return target;
  });
  assert.equal(await fs.readFile(adminUpload,'utf8'),'admin');
  let routeServer;const app=express();app.use(express.json());app.use((req,_res,next)=>{req.session={userId:2,platformOwnerId:999,platformSessionId:999};next();});app.use('/api/ecommerce',require('../../server/routes/ecommerce'));
  routeServer=await new Promise(resolve=>{const server=app.listen(0,'127.0.0.1',()=>resolve(server));});
  try{
   const base=`http://127.0.0.1:${routeServer.address().port}/api/ecommerce/product/${product}/review`,beforeRoute=(await legacyPool.query('SELECT count(*)::integer n FROM legacy_challenge.reviews WHERE platform_owner_id=$1',[admin.id])).rows[0].n;
   assert.notEqual(await platformAdapter.validateSession(adminSession.token),null,'canonical bearer remains valid without Express session continuity');
   const response=await fetch(base,{method:'POST',headers:{authorization:`Bearer ${adminSession.token}`,'content-type':'application/json'},body:JSON.stringify({rating:5,comment:'restart-equivalent bearer write'})});assert.equal(response.status,200);
   assert.equal((await legacyPool.query("SELECT count(*)::integer n FROM legacy_challenge.reviews WHERE platform_owner_id=$1 AND comment='restart-equivalent bearer write'",[admin.id])).rows[0].n,beforeRoute+1);
   const rejected=await fetch(base,{method:'POST',headers:{authorization:'Bearer malformed','content-type':'application/json'},body:JSON.stringify({rating:5,comment:'must not write'})});assert.equal(rejected.status,401);
   const expired=jwt.sign({userId:admin.id},process.env.JWT_SECRET,{algorithm:'HS256',expiresIn:-1});
   assert.equal((await fetch(base,{method:'POST',headers:{authorization:`Bearer ${expired}`,'content-type':'application/json'},body:JSON.stringify({rating:5,comment:'expired must not write'})})).status,401);
   assert.equal((await legacyPool.query("SELECT count(*)::integer n FROM legacy_challenge.reviews WHERE comment='must not write'")).rows[0].n,0);
   assert.equal((await legacyPool.query("SELECT count(*)::integer n FROM legacy_challenge.reviews WHERE comment='expired must not write'")).rows[0].n,0);
  }finally{await new Promise((resolve,reject)=>routeServer.close(error=>error?reject(error):resolve()));}
  await assert.rejects(identityPool.query('SELECT identity.assert_legacy_platform_mutation($1,$2)',[admin.id,subjectSession.id]),/authority unavailable/i);
  await assert.rejects(identityPool.query('SELECT identity.admit_legacy_upload($1,$2,$3)',[randomUUID(),admin.id,subjectSession.id]),/authority unavailable/i);
  await im.query("UPDATE identity.users SET account_locked_until=clock_timestamp()+interval '1 hour' WHERE id=$1",[admin.id]);
  await assert.rejects(identityPool.query('SELECT identity.assert_legacy_platform_mutation($1,$2)',[admin.id,adminSession.id]),/authority unavailable/i);
  await assert.rejects(identityPool.query('SELECT identity.admit_legacy_upload($1,$2,$3)',[randomUUID(),admin.id,adminSession.id]),/authority unavailable/i);
  await im.query('UPDATE identity.users SET account_locked_until=NULL WHERE id=$1',[admin.id]);
  await identityPool.query("UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),revoke_reason='test' WHERE id=$1",[instructorSession.id]);
  await assert.rejects(identityPool.query('SELECT identity.assert_legacy_platform_mutation($1,$2)',[instructor.id,instructorSession.id]),/authority unavailable/i);
  await assert.rejects(identityPool.query('SELECT identity.admit_legacy_upload($1,$2,$3)',[randomUUID(),instructor.id,instructorSession.id]),/authority unavailable/i);
  // A real PostgreSQL connection loss releases the advisory lock while an
  // application callback may still be alive. The pre-admission immutable
  // directory must be removable by cleanup, and the delayed callback must not
  // be able to recreate it or publish bytes afterward.
  const lossPool=new Pool({connectionString:owned('IDENTITY_RUNTIME_URL'),application_name:'owasp_ai_goat_owned_interrupted_upload'});let backendPid,discarded=false;
  const lossLifecycle=createLegacyUploadLifecycle({identityPool:{async connect(){const raw=await lossPool.connect();backendPid=(await raw.query('SELECT pg_backend_pid() pid')).rows[0].pid;return{query:(...args)=>raw.query(...args),on:(...args)=>raw.on(...args),off:(...args)=>raw.off(...args),release(error){discarded=Boolean(error);raw.release(error);}};}},uploadRoot});
  const lossCleanup=createLegacyChallengeOwnerCleanup({store:legacy,uploadRoot,lifecycle:lossLifecycle});let lossLease,continueLostWrite;const lostGate=new Promise(resolve=>{continueLostWrite=resolve;});
  const lostUpload=lossLifecycle.runUpload({ownerId:interrupted.id,sessionId:interruptedSession.id},async lease=>{lossLease=lease;await lostGate;await fs.writeFile(path.join(lease.directory,'late.bin'),'late');});
  while(!lossLease)await new Promise(resolve=>setImmediate(resolve));assert.ok(backendPid);
  assert.equal((await im.query('SELECT pg_terminate_backend($1) terminated',[backendPid])).rows[0].terminated,true);
  await lossCleanup.destroyOwner(interrupted.id);continueLostWrite();await assert.rejects(lostUpload,/ENOENT|terminat|connection/i);assert.equal(discarded,true,'a connection whose unlock failed is discarded from its pool');
  await assert.rejects(fs.stat(lossLease.directory),{code:'ENOENT'});await lossPool.end();
  const fencedPool=new Pool({connectionString:owned('LEGACY_RUNTIME_URL'),application_name:'owasp_ai_goat_owned_interrupted_mutation'});let fencedPid;
  const fencedStore=createLegacyChallengeDb({async connect(){const raw=await fencedPool.connect();fencedPid=(await raw.query('SELECT pg_backend_pid() pid')).rows[0].pid;return raw;}});
  let fenceEntered,releaseFence;const fenceInside=new Promise(resolve=>{fenceEntered=resolve;}),fenceGate=new Promise(resolve=>{releaseFence=resolve;});
  const fencedMutation=fencedStore.withPlatformMutationAuthority({identityPool,ownerId:interrupted.id,sessionId:interruptedSession.id},async()=>{fenceEntered();await fenceGate;return fencedStore.addComment([interrupted.id,'must not survive',interrupted.id]);});
  await fenceInside;assert.equal((await lm.query('SELECT pg_terminate_backend($1) terminated',[fencedPid])).rows[0].terminated,true);releaseFence();await assert.rejects(fencedMutation,/authority expired|terminat|connection/i);
  assert.equal((await legacyPool.query("SELECT count(*)::integer n FROM legacy_challenge.comments WHERE platform_owner_id=$1 AND content='must not survive'",[interrupted.id])).rows[0].n,0);await fencedPool.end();
  let entered,release;const inside=new Promise(resolve=>{entered=resolve;}),held=new Promise(resolve=>{release=resolve;});
  let managedPath;
  const delayed=lifecycle.runUpload({ownerId:owner,sessionId:subjectSession.id},async lease=>{
   await lease.bindFilename('delayed.bin');managedPath=path.join(lease.directory,'delayed.bin');await fs.writeFile(managedPath,'delayed');
   await legacy.addManagedFile(['delayed.bin','delayed.bin',managedPath,7,'application/octet-stream',owner,owner,lease.intentId]);entered();await held;return{written:true};
  });
  await inside;
  const {createStudentDeletionRepository}=require('../../server/database/postgres/studentDeletionRepository');
  const {STUDENT_DELETION_STEPS}=require('../../server/services/studentDeletionComposition');
  const jobs=createStudentDeletionRepository(identityPool,{steps:STUDENT_DELETION_STEPS});
  let mutationEntered,releaseMutation;const mutationInside=new Promise(resolve=>{mutationEntered=resolve;}),mutationHeld=new Promise(resolve=>{releaseMutation=resolve;});
  const delayedMutation=legacy.withPlatformMutationAuthority({identityPool,ownerId:owner,sessionId:subjectSession.id},async()=>{mutationEntered();await mutationHeld;await legacy.addComment([owner,'delayed authenticated comment',owner]);});
  await mutationInside;let admitted=false;const admission=jobs.admit({requesterId:admin.id,subjectId:owner}).then(value=>{admitted=true;return value;});await new Promise(resolve=>setTimeout(resolve,30));assert.equal(admitted,false,'deletion admission waits for an admitted platform mutation');releaseMutation();await delayedMutation;await admission;
  assert.equal(await identities.findActiveSession('legacy-subject-token',owner),null,'admission revokes subject session before cleanup');
  let staleWrite=false;await assert.rejects(legacy.withPlatformMutationAuthority({identityPool,ownerId:owner,sessionId:subjectSession.id},async()=>{staleWrite=true;}),/authority unavailable/i);assert.equal(staleWrite,false,'revoked session cannot begin another platform mutation');
  const sourceBefore=(await lm.query('SELECT to_jsonb(source) row FROM legacy_challenge.ai_conversations source ORDER BY id')).rows;
  await assert.rejects(legacyPool.query('SELECT * FROM legacy_challenge.ai_conversations'),{code:'42501'});
  const before=(await lm.query(`SELECT
   (SELECT count(*)::integer FROM legacy_challenge.order_items i JOIN legacy_challenge.orders o ON o.id=i.order_id WHERE o.platform_owner_id=$1) order_items,
   (SELECT count(*)::integer FROM legacy_challenge.orders WHERE platform_owner_id=$1) orders,
   (SELECT count(*)::integer FROM legacy_challenge.cart WHERE platform_owner_id=$1) cart,
   (SELECT count(*)::integer FROM legacy_challenge.reviews WHERE platform_owner_id=$1) reviews,
   (SELECT count(*)::integer FROM legacy_challenge.comments WHERE platform_owner_id=$1) comments,
   (SELECT count(*)::integer FROM legacy_challenge.ai_conversations WHERE platform_owner_id=$1) conversations,
   (SELECT count(*)::integer FROM legacy_challenge.files WHERE platform_owner_id=$1) files`,[owner])).rows[0];
  assert.deepEqual(before,{order_items:1,orders:1,cart:1,reviews:1,comments:2,conversations:1,files:1});
  let settled=false;const destroying=cleanup.destroyOwner(owner).finally(()=>{settled=true;});await new Promise(resolve=>setTimeout(resolve,30));assert.equal(settled,false,'cleanup waits for an admitted writer');
  release();assert.deepEqual(await delayed,{written:true});
  assert.deepEqual(await destroying,{removed:7,filesRemoved:1});
  const after=(await lm.query(`SELECT
   (SELECT count(*)::integer FROM legacy_challenge.order_items i JOIN legacy_challenge.orders o ON o.id=i.order_id WHERE o.platform_owner_id=$1) order_items,
   (SELECT count(*)::integer FROM legacy_challenge.orders WHERE platform_owner_id=$1) orders,
   (SELECT count(*)::integer FROM legacy_challenge.cart WHERE platform_owner_id=$1) cart,
   (SELECT count(*)::integer FROM legacy_challenge.reviews WHERE platform_owner_id=$1) reviews,
   (SELECT count(*)::integer FROM legacy_challenge.comments WHERE platform_owner_id=$1) comments,
   (SELECT count(*)::integer FROM legacy_challenge.ai_conversations WHERE platform_owner_id=$1) conversations,
   (SELECT count(*)::integer FROM legacy_challenge.files WHERE platform_owner_id=$1) files`,[owner])).rows[0];
  assert.deepEqual(after,{order_items:0,orders:0,cart:0,reviews:0,comments:0,conversations:1,files:0});
  assert.deepEqual((await lm.query('SELECT to_jsonb(source) row FROM legacy_challenge.ai_conversations source ORDER BY id')).rows,sourceBefore,'historical mutable owner labels do not authorize source removal; attested operator cutover is required');
  assert.deepEqual(await lookup.destroyOwner(owner),{removed:1});
  assert.deepEqual(await cleanup.destroyOwner(owner),{removed:0,filesRemoved:0});
  assert.deepEqual(await lookup.destroyOwner(owner),{removed:0});
  assert.equal(await fs.readFile(historical,'utf8'),'historical','ambiguous pre-provenance bytes are preserved');await assert.rejects(fs.stat(managedPath),{code:'ENOENT'});assert.equal(await fs.readFile(sharedFile,'utf8'),'shared');
  assert.equal((await legacyPool.query("SELECT count(*)::integer n FROM legacy_challenge.comments WHERE user_id=$1 AND platform_owner_id IS NULL AND content='local identity collision'",[owner])).rows[0].n,1,'classic local-shop IDs are not reclassified as platform ownership');
  assert.equal((await legacyPool.query('SELECT count(*)::integer n FROM legacy_challenge.orders WHERE user_id=$1',[sibling])).rows[0].n,1);
  assert.equal((await legacyPool.query('SELECT count(*)::integer n FROM legacy_challenge.files WHERE uploaded_by=$1',[sibling])).rows[0].n,1);
  assert.equal((await lookupPool.query('SELECT count(*)::integer n FROM sensitive_lookup.exploitation_log WHERE user_id=$1',[String(sibling)])).rows[0].n,1);
  assert.notEqual(await identities.findActiveSession('legacy-sibling-token',sibling),null);
  await assert.rejects(identityPool.query('SELECT * FROM identity.legacy_upload_intents'),{code:'42501'});
  assert.equal((await im.query("SELECT count(*)::integer n FROM identity.legacy_upload_intents WHERE owner_id=$1 AND state='retired' AND file_path IS NULL",[owner])).rows[0].n,1);
  for(const [pool,signature] of [[legacyPool,'legacy_challenge.destroy_student_owner(integer,uuid[])'],[lookupPool,'sensitive_lookup.destroy_student_owner(text)']]){
   const acl=(await pool.query(`SELECT has_function_privilege(current_user,$1,'EXECUTE') executable,
    NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
      WHERE p.oid=to_regprocedure($1) AND a.grantee=0 AND a.privilege_type='EXECUTE') public_revoked`,[signature])).rows[0];
   assert.deepEqual(acl,{executable:true,public_revoked:true});
  }
 }finally{await require('../../server/database/postgres').closePostgresPools().catch(()=>{});await Promise.allSettled([im.end(),identityPool.end(),lm.end(),legacyPool.end(),sm.end(),lookupPool.end()]);await fs.rm(uploadRoot,{recursive:true,force:true});}
});
