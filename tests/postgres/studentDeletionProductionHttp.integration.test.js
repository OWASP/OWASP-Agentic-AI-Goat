'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http'),express=require('express'),bcrypt=require('bcryptjs'),path=require('node:path'),fs=require('node:fs/promises'),{randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.IDENTITY_DATABASE_URL;
const pool=key=>new Pool({connectionString:process.env[key]});
const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server)));
const close=server=>server&&new Promise(resolve=>server.close(resolve));
function typeErrorSource(error){
 if(!(error instanceof TypeError)||typeof error.stack!=='string')return null;
 const frame=error.stack.split('\n').slice(1).map(line=>line.trim())
   .map(line=>line.match(/^at (?:(.{1,120}?) \()?(.+?):(\d+):(\d+)\)?$/)).find(Boolean);
 if(!frame)return null;
 const functionName=/^[A-Za-z0-9_.$<>\[\] /-]+$/.test(frame[1]||'')?frame[1]||null:null;
 const file=path.basename(frame[2]);
 return /^[A-Za-z0-9_.-]{1,120}$/.test(file)
   ?{functionName,file,line:Number(frame[3]),column:Number(frame[4])}:null;
}

test('mounted production admin deletion retries one durable job and clears every owner store',{skip:!enabled,timeout:120000},async()=>{
 assert.equal(Object.hasOwn(process.env,'LEGACY_PLATFORM_LIFECYCLE_ENABLED'),false,'qualification must exercise the PostgreSQL default-on policy');
 assert.equal(require('../../server/services/platformDataLifecycleActivation').isPlatformDataLifecycleRequested(process.env),true);
 for(const key of Object.keys(process.env).filter(key=>key.endsWith('_DATABASE_URL')))if(key!=='DATABASE_URL')assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const fixtureBase=path.join(process.env.DVAIA_ISOLATED_TEST_WORKSPACE,'bound-feature-targets');
 const mcpFixtureRoot=path.join(fixtureBase,'mcp'),ssrfFixtureRoot=path.join(fixtureBase,'ssrf');
 await fs.mkdir(mcpFixtureRoot,{recursive:true,mode:0o700});await fs.mkdir(ssrfFixtureRoot,{recursive:true,mode:0o700});
 await fs.chmod(fixtureBase,0o700);await fs.chmod(mcpFixtureRoot,0o700);await fs.chmod(ssrfFixtureRoot,0o700);
 Object.assign(process.env,{SS_PERSONA_INBOX_READY:'true',SS_MCP_TRUST_READY:'true',
   SS_CONTROLLED_SSRF_READY:'true',SS_MCP_TRUST_FIXTURE_ROOT:mcpFixtureRoot,
   SS_CONTROLLED_SSRF_FIXTURE_ROOT:ssrfFixtureRoot});
 const sidecar=await listen(http.createServer((req,res)=>{let body='';req.on('data',chunk=>{body+=chunk;});req.on('end',()=>{
  res.setHeader('content-type','application/json');
  if(req.url==='/api/v1/info')return res.end('{"ok":true}');
  if(req.url==='/reset'||req.url==='/codebot/reset')return res.end('{"ok":true}');
  res.statusCode=404;res.end('{"ok":false}');
 });}));
 process.env.SANDBOX_RUNNER_URL=`http://127.0.0.1:${sidecar.address().port}`;
 process.env.MAILPIT_API_URL=`http://127.0.0.1:${sidecar.address().port}`;
 process.env.MCP_BACKEND_TIMEOUT_MS='1000';
 const identity=pool('IDENTITY_DATABASE_URL'),identityMigration=pool('IDENTITY_MIGRATION_DATABASE_URL');
 const pools=Object.fromEntries(['SQL_WORKSHOP','NOSQL_WORKSHOP','MCP_WORKSHOP','CSRF_WORKSHOP','SUPPLY_CHAIN_WORKSHOP','FINFLOW_WORKSHOP','EXCESSIVE_AGENCY','CTF','LEGACY_CHALLENGE','SENSITIVE_LOOKUP','SECURESHOP','SECURESHOP_AGENTS','SECURESHOP_REVIEW'].map(key=>[key,pool(`${key}_DATABASE_URL`)]));
 let api;
 try{
  const {createIdentityRepository}=require('../../server/database/postgres/identityRepository');
  const identities=createIdentityRepository(identity),password=await bcrypt.hash('OwnedDeletion@123',4);
  const admin=await identities.createUser({username:'delete-http-admin',email:'delete-http-admin@test.invalid',passwordHash:password});
  const subject=await identities.createUser({username:'delete-http-subject',email:'delete-http-subject@test.invalid',passwordHash:password});
  const sibling=await identities.createUser({username:'delete-http-sibling',email:'delete-http-sibling@test.invalid',passwordHash:password});
  await identityMigration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1",[admin.id]);
  await identities.grantPermission({userId:admin.id,permission:'user_management',grantedBy:admin.id});
  await identities.grantPermission({userId:admin.id,permission:'manage_progress',grantedBy:admin.id});
  const {createPostgresIdentityAdapter}=require('../../server/services/postgresIdentityAdapter');
  const {createWorkshopProgressRepository}=require('../../server/database/postgres/workshopProgressRepository');
  const adapter=createPostgresIdentityAdapter({repository:identities,progress:createWorkshopProgressRepository(identity),jwtSecret:process.env.JWT_SECRET});
  const adminSession=await adapter.createSession(await identities.findCredentialById(admin.id),{get:()=>null,ip:'127.0.0.1'});
  const subjectSession=await adapter.createSession(await identities.findCredentialById(subject.id),{get:()=>null,ip:'127.0.0.1'});
  const siblingSession=await adapter.createSession(await identities.findCredentialById(sibling.id),{get:()=>null,ip:'127.0.0.1'});
  const {createSecureShopLaunchRepository}=require('../../server/database/postgres/secureshopLaunchRepository');const launches=createSecureShopLaunchRepository(identity);
  let subjectLaunch=await launches.issueOrRenew({platformOwnerId:subject.id,platformSessionId:(await identities.findActiveSession(subjectSession.token,subject.id)).session.id,expiresAt:new Date(Date.now()+3600000)});
  const siblingLaunch=await launches.issueOrRenew({platformOwnerId:sibling.id,platformSessionId:(await identities.findActiveSession(siblingSession.token,sibling.id)).session.id,expiresAt:new Date(Date.now()+3600000)});
  const cleanupComposition=await require('../../server/services/secureshopCleanupComposition').getSecureShopCleanupComposition();
  const personaRepository=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:pools.SECURESHOP,agentsPool:pools.SECURESHOP_AGENTS});await personaRepository.ensureTemplates();const merchantPersona=await personaRepository.readPersona(12);
  const productFixtures=[{id:1,sourceRetailerId:12,retailerId:12,name:'Owned product',description:'owned',descriptionHtml:'<p>owned</p>',price:10,category:'fixture',imageUrl:null,images:[],stockQuantity:2,status:'active',templateSource:'owned deletion fixture',createdAt:null,updatedAt:null},{id:2,sourceRetailerId:9,retailerId:9,name:'Decoy product',description:'decoy',descriptionHtml:'<p>decoy</p>',price:20,category:'fixture',imageUrl:null,images:[],stockQuantity:3,status:'active',templateSource:'owned deletion fixture',createdAt:null,updatedAt:null}];
  // Controlled vectors qualify lifecycle erasure only, never model provenance.
  const embeddingAuthority={checkCurrent:binding=>launches.assertCurrent(binding),checkCleanup:async()=>{throw new Error("Fixture provisioning must not perform cleanup");}};
  const retrieval=require('../../server/database/postgres/secureshopBoundProductRetrievalRepository').createSecureShopBoundProductRetrievalRepository(pools.SECURESHOP_REVIEW,embeddingAuthority);
  const embeddingRevisions=require('../../server/database/postgres/secureshopEmbeddingRevisionRepository').createSecureShopEmbeddingRevisionRepository(pools.SECURESHOP_REVIEW,{...embeddingAuthority,getRuntimeFingerprint:()=> 'a'.repeat(64)});
  async function embeddingSnapshot(targetId){
   const result={};
   for(const [key,table] of [['revisions','product_target_embedding_revisions'],['heads','product_target_embedding_heads'],['cleanup','product_target_embedding_cleanup_receipts']])result[key]=(await pools.SECURESHOP_REVIEW.query(`SELECT to_jsonb(r) AS row FROM secureshop_review.${table} r WHERE target_id=$1 ORDER BY to_jsonb(r)::text`,[targetId])).rows;
   result.vectors=(await pools.SECURESHOP_REVIEW.query('SELECT to_jsonb(v) AS row FROM secureshop_review.product_target_embedding_vectors v JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id) WHERE r.target_id=$1 ORDER BY to_jsonb(v)::text',[targetId])).rows;
   return result;
  }
  async function populateSecureShop(issued,id){
   const scope=issued.binding,authority={platformSessionId:scope.platformSessionId,platformOwnerId:scope.platformOwnerId,launchId:scope.launchId,expectedGeneration:scope.generation};
   const reviewTarget=await launches.reserveReviewsTarget(authority),productTarget=await launches.reserveProductsTarget(authority);
   await cleanupComposition.reviews.provision({...scope,targetId:reviewTarget.targetId},{reviews:[{productId:1,authorId:id,body:`private-${id}`,rating:3}]});
   await cleanupComposition.products.provision({...scope,targetId:productTarget.targetId},{ownMerchantId:12,products:productFixtures});
   const embeddingBinding={targetId:productTarget.targetId,launchId:scope.launchId,scenarioId:scope.scenarioId,generation:scope.generation,platformOwnerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId};
   await retrieval.provision(embeddingBinding,{embeddingModel:'controlled-deletion-fixture',embeddingDimension:2,documents:[{sourceKind:'product',sourceId:1,chunkIndex:0,text:`private product ${id}`,embedding:[1,0]},{sourceKind:'manual',sourceId:91,chunkIndex:0,text:`private manual ${id}`,embedding:[.8,.2]}]});
   const snapshot=await embeddingRevisions.snapshot(embeddingBinding);
   await embeddingRevisions.publish(embeddingBinding,{operationId:randomUUID(),sourceSetDigest:snapshot.sourceSetDigest,expectedHead:snapshot.expectedHead,expectedRuntimeFingerprint:'a'.repeat(64),documents:snapshot.documents.map(d=>({sourceKind:d.sourceKind,sourceId:d.sourceId,chunkIndex:d.chunkIndex,sourceSha256:d.sourceSha256,embedding:Array.from({length:384},(_,i)=>i===0?1:0)}))});
   const conversation=await cleanupComposition.conversationService.create(scope,{id:merchantPersona.id,role:merchantPersona.role});
   await personaRepository.createSession({sessionId:randomUUID(),jti:randomUUID(),scope,persona:merchantPersona,expiresAt:new Date(Date.now()+3600000).toISOString()});
   return {reviewTarget,productTarget,conversation};
  }
  let subjectSecureShop=await populateSecureShop(subjectLaunch,subject.id);const siblingSecureShop=await populateSecureShop(siblingLaunch,sibling.id);
  const boundApplication=await require('../../server/services/secureshopBoundApplication')
    .createSecureShopBoundApplication({engine:'postgres',shopEnabled:true,
      authenticateToken:(_req,_res,next)=>next(),audit:()=> (_req,_res,next)=>next(),
      agentRuntime:{pool:{async callTool(){throw new Error('Reset qualification must not call upstream tools');}},provider:{
        async chat(){throw new Error('Reset qualification must not call a model');},
        async finalResponse(){throw new Error('Reset qualification must not call a model');},
      }}});
  assert.equal(typeof boundApplication.ownerResetService.resetOwner,'function');
  assert.equal(boundApplication.readiness.ready,true);
  const nestedReset=await require('../../server/services/postgresWorkshopResetService')
    .getPostgresWorkshopResetService().resetStudent({userId:subject.id,workshopKey:'secureshop_agent_security'});
  assert.equal(nestedReset.completed,true,'SecureShop reset must complete while the lifecycle admission lock is held');
  const resetBinding=await launches.readActiveMetadata({platformOwnerId:subject.id,
    platformSessionId:(await identities.findActiveSession(subjectSession.token,subject.id)).session.id});
  assert.equal(resetBinding.launchId,subjectLaunch.binding.launchId);
  assert.equal(resetBinding.generation,subjectLaunch.binding.generation+1);
  subjectLaunch={binding:resetBinding};
  subjectSecureShop=await populateSecureShop(subjectLaunch,subject.id);
  await identityMigration.query("UPDATE workshop_platform.exercises SET catalog_active=false,is_visible=false WHERE workshop_key='secureshop_agent_security'");

  for(const id of [subject.id,sibling.id]){
   const order=`DELETE-HTTP-${id}`;
   await pools.SQL_WORKSHOP.query("INSERT INTO aria.orders(order_number,user_id,product_name) VALUES($1,$2,'fixture')",[order,String(id)]);
   await pools.SQL_WORKSHOP.query("INSERT INTO aria.cart(user_id,product_name) VALUES($1,'fixture')",[String(id)]);
   await pools.NOSQL_WORKSHOP.query("INSERT INTO nova.reading_lists(user_id,paper_id) SELECT $1,paper_id FROM nova.papers ORDER BY id LIMIT 1",[String(id)]);
   await pools.MCP_WORKSHOP.query("INSERT INTO mcp.progress(user_key,objective_id) VALUES($1,'mcp_tool_discovery')",[String(id)]);
   await pools.CSRF_WORKSHOP.query("INSERT INTO csrf.progress(user_key,objective_id) VALUES($1,'csrf_g1')",[String(id)]);
   await pools.SUPPLY_CHAIN_WORKSHOP.query("INSERT INTO supply_chain.progress(user_id,objective_id) SELECT $1,objective_id FROM supply_chain.objectives ORDER BY ordinal LIMIT 1",[String(id)]);
   await pools.SENSITIVE_LOOKUP.query("INSERT INTO sensitive_lookup.exploitation_log(user_id,user_input) VALUES($1,'private')",[String(id)]);
   await pools.FINFLOW_WORKSHOP.query("INSERT INTO finflow.progress(user_id,objective_id,completed) SELECT $1,objective_id,true FROM finflow.objectives ORDER BY ordinal LIMIT 1",[String(id)]);
  }
  const ctf=require('../../server/database/postgres/ctfDb').CTFHelpers;
  await ctf.registerParticipant(subject.id,'delete-http-subject','delete-http-subject@test.invalid');await ctf.registerParticipant(sibling.id,'delete-http-sibling','delete-http-sibling@test.invalid');
  await require('../../server/database/postgres/excessiveAgencyLabDb').forAttendee(String(subject.id)).then(db=>db.ensureSeeded());
  await require('../../server/database/postgres/excessiveAgencyLabDb').forAttendee(String(sibling.id)).then(db=>db.ensureSeeded());
  await require('../../server/database/postgres/sessionDisclosureDb').getSessionDisclosureDb().getOrCreate(subject.id);await require('../../server/database/postgres/sessionDisclosureDb').getSessionDisclosureDb().getOrCreate(sibling.id);
  const xss=pool('XSS_WORKSHOP_DATABASE_URL');pools.XSS=xss;
  for(const id of [subject.id,sibling.id])await xss.query("INSERT INTO xss.profiles(user_key,name,bio,website) VALUES($1,$2,'private','https://example.invalid')",[String(id),`owner-${id}`]);
  const product=(await pools.LEGACY_CHALLENGE.query('SELECT id FROM legacy_challenge.products ORDER BY id LIMIT 1')).rows[0].id;
  for(const id of [subject.id,sibling.id])await pools.LEGACY_CHALLENGE.query("INSERT INTO legacy_challenge.cart(user_id,product_id,platform_owner_id) VALUES($1,$2,$1)",[id,product]);
  const uploadRoot=path.resolve(__dirname,'../../server/uploads'),legacy=require('../../server/database/postgres/legacyChallengeDb');
  const lifecycle=require('../../server/services/legacyUploadLifecycle').getLegacyUploadLifecycle();
  let managedUploadPath;
  await lifecycle.runUpload({ownerId:subject.id,sessionId:(await identities.findActiveSession(subjectSession.token,subject.id)).session.id},async lease=>{await lease.bindFilename('delete-http.bin');managedUploadPath=path.join(lease.directory,'delete-http.bin');await fs.writeFile(managedUploadPath,'private',{mode:0o600});await legacy.addManagedFile(['delete-http.bin','delete-http.bin',managedUploadPath,7,'application/octet-stream',subject.id,subject.id,lease.intentId]);});
  // Exercise retry through a genuine durable owner resource. Cleanup must
  // reject an owned upload whose published path is no longer a regular file;
  // restoring that exact path lets the same admitted job resume safely.
  await fs.unlink(managedUploadPath);await fs.mkdir(managedUploadPath,{mode:0o700});

  const auth=require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(identity);
  const stores={pool:identity,progress:createWorkshopProgressRepository(identity),config};
  let deletionFailure;
  const deletionService={async deleteStudent(input){try{return await require('../../server/services/studentDeletionApplication')
    .getStudentDeletionApplication().deleteStudent(input);}catch(error){deletionFailure={name:error?.constructor?.name||null,
      code:typeof error?.code==='string'?error.code:null,statusCode:Number.isInteger(error?.statusCode)?error.statusCode:null,
      source:typeErrorSource(error)};throw error;}}};
  const app=express();app.use(express.json());app.use('/api/admin',require('../../server/routes/postgresAdmin').createPostgresAdminRouter({adapter,stores,auth,repository:require('../../server/database/postgres/adminRepository').createPostgresAdminRepository(identity),resetService:{},deletionService}));
  api=await listen(http.createServer(app));const base=`http://127.0.0.1:${api.address().port}`;
  async function adminRequest(pathname,{method='GET',body}={}){const response=await fetch(`${base}${pathname}`,{method,headers:{authorization:`Bearer ${adminSession.token}`,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});return{status:response.status,body:await response.json()};}
  const memoryRag=require('../../server/services/ragVectorStore');
  const memoryFamilies=[memoryRag,memoryRag.forFamily('CSRF')];
  for(const family of memoryFamilies)for(const id of [subject.id,sibling.id]){
    const key=family._userSessionKey(String(id),'owned-deletion-document');
    family.sessions.set(key,[{text:'Synthetic lifecycle-only document',embedding:new Float32Array([1,0]),chunkIndex:0}]);
    family.sessionMetadata.set(key,{filename:'owned.txt'});
  }
  const subjectEmbeddingBefore=await embeddingSnapshot(subjectSecureShop.productTarget.targetId);
  const siblingEmbeddingBefore=await embeddingSnapshot(siblingSecureShop.productTarget.targetId);
  assert.equal(subjectEmbeddingBefore.vectors.length,2);assert.equal(subjectEmbeddingBefore.heads.length,1);
  assert.equal(siblingEmbeddingBefore.vectors.length,2);assert.equal(siblingEmbeddingBefore.heads.length,1);
  async function remove(){return adminRequest(`/api/admin/students/${subject.id}`,{method:'DELETE'});}
  const first=await remove();assert.equal(first.status,503,JSON.stringify({httpStatus:first.status,
    routeCode:typeof first.body?.code==='string'?first.body.code:null,deletionFailure}));assert.equal(await adapter.validateSession(subjectSession.token),null,'admission revokes the learner session before cleanup');
  const job=(await identityMigration.query('SELECT job_id,state FROM identity.student_deletion_jobs WHERE subject_user_id=$1',[subject.id])).rows[0];assert.equal(job.state,'failed');
  const failed=(await identityMigration.query("SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 AND state='failed'",[job.job_id])).rows;assert.deepEqual(failed,[{step_key:'legacy_challenge',state:'failed'}]);
  await fs.rm(managedUploadPath,{recursive:true});await fs.writeFile(managedUploadPath,'private',{mode:0o600});
  const second=await remove();assert.equal(second.status,200);assert.equal(second.body.jobId,job.job_id);
  assert.deepEqual((await identityMigration.query('SELECT state FROM identity.student_deletion_jobs WHERE job_id=$1',[job.job_id])).rows[0],{state:'completed'});
  for(const family of memoryFamilies){
    assert.equal(family.getSessionInfo(String(subject.id),'owned-deletion-document').exists,false,'canonical deletion clears both RAG families');
    assert.equal(family.getSessionInfo(String(sibling.id),'owned-deletion-document').exists,true,'canonical deletion preserves sibling RAG families');
  }
  const subjectEmbeddingAfter=await embeddingSnapshot(subjectSecureShop.productTarget.targetId);
  assert.deepEqual(subjectEmbeddingAfter.vectors,[],'canonical DELETE erases derived private vectors');
  assert.deepEqual(subjectEmbeddingAfter.heads,[],'canonical DELETE removes the derived retrieval head');
  assert.deepEqual(subjectEmbeddingAfter.revisions,subjectEmbeddingBefore.revisions,'immutable revision provenance survives deletion');
  assert.equal(subjectEmbeddingAfter.cleanup.length,1);assert.equal(subjectEmbeddingAfter.cleanup[0].row.deleted_vector_count,2);
  assert.deepEqual(await embeddingSnapshot(siblingSecureShop.productTarget.targetId),siblingEmbeddingBefore,'sibling vectors, head and metadata remain byte-exact');
  const terminalBefore=(await identityMigration.query('SELECT * FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[job.job_id])).rows;
  const replay=await remove();assert.equal(replay.status,200);assert.equal(replay.body.jobId,job.job_id);
  assert.deepEqual((await identityMigration.query('SELECT * FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[job.job_id])).rows,terminalBefore,'completed HTTP replay must not repeat cleanup or alter its durable receipts');
  assert.deepEqual(await embeddingSnapshot(subjectSecureShop.productTarget.targetId),subjectEmbeddingAfter,'completed deletion replay preserves immutable embedding receipts');
  assert.deepEqual(await embeddingSnapshot(siblingSecureShop.productTarget.targetId),siblingEmbeddingBefore,'replay preserves sibling state');
  const students=await adminRequest('/api/admin/students');assert.equal(students.status,200);assert.ok(!students.body.students.some(row=>row.id===subject.id),'completed tombstone is not an operational learner');
  const users=await adminRequest('/api/admin/users?limit=100');assert.equal(users.status,200);assert.ok(!users.body.users.some(row=>row.id===subject.id),'inactive tombstone remains absent from the active user list');
  const auditDetail=await adminRequest(`/api/admin/users/${subject.id}`);assert.equal(auditDetail.status,200);assert.equal(auditDetail.body.user.username,`deleted-${job.job_id}`,'explicit administrative audit detail retains the tombstone');
  assert.equal((await adminRequest(`/api/admin/students/${subject.id}/progress`)).status,404);
  assert.equal((await adminRequest(`/api/admin/student-workshop-view/${subject.id}`)).status,404);
  assert.equal((await adminRequest(`/api/admin/progress?studentId=${subject.id}`)).body.progress.length,0);
  assert.equal((await adminRequest(`/api/admin/students/${subject.id}`,{method:'PUT',body:{fullName:'revived'}})).status,404);
  assert.equal((await adminRequest(`/api/admin/students/${subject.id}/change-password`,{method:'POST',body:{password:'MustStayDeleted@123'}})).status,404);
  assert.equal((await adminRequest(`/api/admin/users/${subject.id}/lock`,{method:'POST',body:{}})).status,404);
  assert.equal((await identityMigration.query('SELECT is_active,full_name FROM identity.users WHERE id=$1',[subject.id])).rows[0].is_active,0);
  const steps=(await identityMigration.query('SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[job.job_id])).rows;assert.equal(steps.length,17);assert.ok(steps.every(row=>row.state==='completed'));
  assert.equal((await identityMigration.query("SELECT catalog_active,is_visible FROM workshop_platform.exercises WHERE workshop_key='secureshop_agent_security'")).rows[0].catalog_active,false);
  assert.equal((await identityMigration.query('SELECT status FROM identity.secureshop_launches WHERE launch_id=$1',[subjectLaunch.binding.launchId])).rows[0].status,'revoked');assert.equal((await identityMigration.query('SELECT status FROM identity.secureshop_launches WHERE launch_id=$1',[siblingLaunch.binding.launchId])).rows[0].status,'active');
  assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.reviews WHERE target_id=$1',[subjectSecureShop.reviewTarget.targetId])).rows[0].n,0);assert.ok((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.reviews WHERE target_id=$1',[siblingSecureShop.reviewTarget.targetId])).rows[0].n>0);
  assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.product_target_products WHERE target_id=$1',[subjectSecureShop.productTarget.targetId])).rows[0].n,0);assert.ok((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.product_target_products WHERE target_id=$1',[siblingSecureShop.productTarget.targetId])).rows[0].n>0);
  assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.review_cleanup_receipts WHERE target_id=$1',[subjectSecureShop.reviewTarget.targetId])).rows[0].n,1);assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.product_cleanup_receipts WHERE target_id=$1',[subjectSecureShop.productTarget.targetId])).rows[0].n,1);
  assert.equal((await pools.SECURESHOP_AGENTS.query('SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',[subjectSecureShop.conversation.id])).rows[0].binding_state,'abandoned');assert.equal((await pools.SECURESHOP_AGENTS.query('SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',[siblingSecureShop.conversation.id])).rows[0].binding_state,'active');
  assert.equal((await pools.SECURESHOP_AGENTS.query('SELECT count(*)::integer n FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1 AND revoked_at IS NULL',[subjectLaunch.binding.launchId])).rows[0].n,0);assert.ok((await pools.SECURESHOP_AGENTS.query('SELECT count(*)::integer n FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1 AND revoked_at IS NULL',[siblingLaunch.binding.launchId])).rows[0].n>0);
  assert.notEqual(await adapter.validateSession(siblingSession.token),null);assert.equal((await identityMigration.query('SELECT username FROM identity.users WHERE id=$1',[subject.id])).rows[0].username,`deleted-${job.job_id}`);
  const checks=[[pools.SQL_WORKSHOP,'aria.cart','user_id'],[pools.NOSQL_WORKSHOP,'nova.reading_lists','user_id'],[pools.MCP_WORKSHOP,'mcp.progress','user_key'],[pools.CSRF_WORKSHOP,'csrf.progress','user_key'],[pools.SUPPLY_CHAIN_WORKSHOP,'supply_chain.progress','user_id'],[pools.SENSITIVE_LOOKUP,'sensitive_lookup.exploitation_log','user_id'],[pools.FINFLOW_WORKSHOP,'finflow.progress','user_id'],[pools.LEGACY_CHALLENGE,'legacy_challenge.cart','user_id'],[xss,'xss.profiles','user_key']];
  for(const [store,table,column] of checks){assert.equal((await store.query(`SELECT count(*)::integer n FROM ${table} WHERE ${column}=$1`,[String(subject.id)])).rows[0].n,0,table);assert.ok((await store.query(`SELECT count(*)::integer n FROM ${table} WHERE ${column}=$1`,[String(sibling.id)])).rows[0].n>0,`${table} sibling`);}
  assert.equal((await pools.EXCESSIVE_AGENCY.query('SELECT count(*)::integer n FROM excessive_agency.attendees WHERE platform_user_id=$1',[String(subject.id)])).rows[0].n,0);assert.equal((await pools.CTF.query('SELECT count(*)::integer n FROM ctf.ctf_participants WHERE user_id=$1',[subject.id])).rows[0].n,0);
 }finally{await close(api);await close(sidecar);await require('../../server/services/secureshopBoundReviewComposition').closeSecureShopBoundReviewComposition().catch(()=>{});await require('../../server/services/studentDeletionProduction').closeProductionStudentDeletionComposition().catch(()=>{});await require('../../server/database/postgres/sessionDisclosureDb').closeSessionDisclosureDb().catch(()=>{});await require('../../server/database/postgres').closePostgresPools().catch(()=>{});await Promise.allSettled([identity.end(),identityMigration.end(),...Object.values(pools).map(value=>value.end())]);}
});
