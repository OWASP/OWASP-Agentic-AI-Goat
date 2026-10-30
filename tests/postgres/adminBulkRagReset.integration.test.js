'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');const {Pool}=require('pg');
const enabled=process.env.BULK_RAG_NATIVE==='1';
test('bulk parent journal reconciles actual RAG and CSRF child reset journals',{skip:!enabled,timeout:180000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE),fs.realpathSync(process.cwd()));
 process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.WORKSHOP_DATABASE_ENGINE='postgres';
 for(const role of ['RUNTIME','MIGRATION']){const u=new URL(process.env['CSRF_NATIVE_'+role+'_URL']);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_csrf_[a-f0-9]+$/);assert.equal(u.username,'dvaia_csrf_'+role.toLowerCase());process.env[role==='RUNTIME'?'CSRF_WORKSHOP_DATABASE_URL':'CSRF_WORKSHOP_MIGRATION_DATABASE_URL']=u.href;}
 const pools=[];const pool=role=>{const u=new URL(process.env['WORKSHOP_RAG_'+role.toUpperCase()+'_URL']);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_workshop_rag_[a-f0-9]+$/);assert.equal(u.username,'dvaia_identity_'+role);const p=new Pool({connectionString:u.href,max:8,statement_timeout:15000,lock_timeout:5000});pools.push(p);return p;};
 const migration=pool('migration'),runtime=pool('runtime'),leases=pool('runtime'),bulkLeases=pool('runtime');let temporary,httpServer;
 const evidence={scope:'Real bulk parent service and durable RAG/CSRF child journals, identity and CSRF PostgreSQL stores, canonical progress and email retirement; controlled embeddings and interruption after real progress clear; no installed activation',modelCalled:false};
 try{
  temporary=fs.mkdtempSync(path.join(os.tmpdir(),'rag-admin-candidate-'));for(const f of fs.readdirSync('db/postgres/identity-migrations'))if(f.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/identity-migrations',f),path.join(temporary,f));fs.copyFileSync('docs/modernization/drafts/workshop-rag/0082_workshop_rag_sources.candidate.sql',path.join(temporary,'0082_workshop_rag_sources.sql'));
  assert.equal(fs.readFileSync('docs/modernization/drafts/admin-bulk-reset/0084_admin_bulk_reset_cohort.candidate.sql','utf8'),fs.readFileSync('db/postgres/identity-migrations/0084_admin_bulk_reset_cohort.sql','utf8'));
  const {migrate}=require('../../db/postgres/migrate');await migrate(migration,temporary);assert.deepEqual(await migrate(migration,temporary),[]);await require('../../server/database/postgres/csrfWorkshopDb').initializeCsrfWorkshopDb();await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  const identity=require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime),adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:identity,jwtSecret:'owned-lifecycle-signing-key-at-least-32-bytes'});
  const password=await require('bcryptjs').hash(randomUUID(),4);
  async function owner(admin=false){const u=await identity.createUser({username:'owned-'+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:password});if(admin){await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[u.id]);await identity.grantPermission({userId:u.id,permission:'manage_progress',grantedBy:u.id});}const session=await adapter.createSession({...u,password},{});return{id:u.id,sessionId:session.internalSessionId,token:session.token};}
  const admin=await owner(true),learner=await owner(),sibling=await owner();const request=o=>({user:{id:o.id},identitySession:{id:o.sessionId},headers:{authorization:'Bearer '+o.token}});
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(runtime,{leasePool:leases});const {createRunCoordinator}=require('../../server/agent-runtime/runCoordinator');const coordinators=Object.fromEntries(['RAG','CSRF'].map(f=>[f,createRunCoordinator({family:f,ledger})]));
  const embedder={getRuntimeFingerprint:()=>({fingerprint:'a'.repeat(64)}),embed:async()=>({embeddingDimension:384,embedding:Array.from({length:384},(_,i)=>i===0?1:0)})};
  const bootstrapRoutes=Object.fromEntries(['RAG','CSRF'].map(family=>[family,{resetOwner:(o,work)=>coordinators[family].reset(o,work),durableRagComposition(){return this.configured||null;},configureDurableRag(value){this.configured=value;}}]));
  const production=require('../../server/services/workshopRagProduction').createWorkshopRagProduction({env:{PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',IDENTITY_DATABASE_URL:process.env.WORKSHOP_RAG_RUNTIME_URL},load:name=>{
    if(name==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({...adapter,pool:runtime})};
    if(name==='../routes/ragInjection')return bootstrapRoutes.RAG;if(name==='../routes/csrfWorkshop')return bootstrapRoutes.CSRF;
    if(name==='../database/postgres/csrfWorkshopDb')return{engine:'postgres',getVictimState:()=>{throw Error('Unexpected bootstrap source read');},saveVictimState:()=>{throw Error('Unexpected bootstrap source write');}};
    if(name==='./secureshopProductEmbedder')return{createSecureShopProductEmbedder:()=>embedder};
    return require('../../server/services/'+name);
  }});
  const activation=await production.initialize(),composition=activation.composition;assert.equal(await activation.warmEmbedding(),true);
  assert.equal(bootstrapRoutes.RAG.durableRagComposition(),composition);assert.equal(bootstrapRoutes.CSRF.durableRagComposition(),composition);evidence.productionBootstrap=true;

  async function upload(o,family,slot,label){const authority=await composition.resolveRequest(request(o));return coordinators[family].run(String(o.id),{},async execution=>(await authority.bind(execution,{family,slot})).ingestAndSelect({documentId:randomUUID(),operationId:randomUUID(),sourceBuffer:Buffer.from('Exact owned source for '+label+' with enough real words.'),filename:label+'.txt',ingestionKind:slot==='clean'?'canonical_clean':slot==='poison'?'poison_upload':'upload'}));}
  async function snapshot(o){return(await migration.query(`SELECT d.document_id,d.source_sha256,d.chunk_manifest_sha256,d.retired_at,s.source_text AS body, (SELECT count(*) FROM workshop_rag.embedding_vectors v JOIN workshop_rag.embedding_revisions r USING(revision_id) WHERE r.document_id=d.document_id)::integer AS vectors FROM workshop_rag.documents d LEFT JOIN workshop_rag.sources s USING(document_id) WHERE d.owner_id=$1 ORDER BY d.document_id`,[o.id])).rows;}
  for(const o of [learner,sibling])for(const [family,slot]of[['RAG','current'],['CSRF','clean'],['CSRF','poison']])await upload(o,family,slot,family+'-'+slot);
  let continuations=0;const emailArtifacts=require('../../server/database/postgres/emailArtifactRepository').createEmailArtifactRepository(runtime);const actualCsrf=require('../../server/database/postgres/csrfWorkshopDb');
  const ragRoute={durableRagComposition:()=>composition,resetOwner:(o,work)=>coordinators.RAG.reset(o,work),clearOwnerState:()=>{throw Error('RAM fallback');}};
  const csrfRoute={durableRagComposition:()=>composition,resetOwner:(o,work)=>coordinators.CSRF.reset(o,work),clearRagOwnerState:()=>{throw Error('RAM fallback');}};
  const load=name=>{
   if(name==='../routes/ragInjection')return ragRoute;if(name==='../routes/csrfWorkshop')return csrfRoute;
   if(name==='../routes/emailAgent')return{resetOwner:async(_,work)=>work(),destroyOwnerArtifacts:async()=>0};
   if(name==='./emailArtifactStore')return{assertReady:()=>emailArtifacts.assertReady(),retireOwner:async scope=>{continuations++;return emailArtifacts.retireOwner(scope);}};
   if(name==='../database/postgres/csrfWorkshopDb')return actualCsrf;
   if(name==='./csrfVictimSandbox')return require('../../server/services/csrfVictimSandbox');
   throw Error('Uncontrolled dependency '+name);
  };
  const realProgress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime);
  let failOwner=null,failOnce=false;
  const progress={resetWorkshopProgress:async(id,key)=>{await realProgress.resetWorkshopProgress(id,key);if(Number(id)===failOwner&&failOnce){failOnce=false;throw new Error('injected interruption after canonical clear');}}};
  const resets=require('../../server/services/postgresWorkshopResetService');
  const journal=require('../../server/database/postgres/adminBulkResetRepository').createAdminBulkResetRepository(runtime,{leasePool:bulkLeases});
  const bulk=require('../../server/services/adminBulkResetComposition').createAdminBulkResetComposition({pool:runtime,identityAdapter:adapter,createLeasePool:()=>bulkLeases});
  await bulk.assertReady();
  await migration.query('REVOKE EXECUTE ON FUNCTION identity.list_bulk_resets(integer,bigint) FROM dvaia_identity_runtime');await assert.rejects(bulk.assertReady(),{code:'RESET_STORAGE_NOT_READY'});await migration.query('GRANT EXECUTE ON FUNCTION identity.list_bulk_resets(integer,bigint) TO dvaia_identity_runtime');await bulk.assertReady();
  for(const privilege of ['SELECT','INSERT','UPDATE','REFERENCES']){
    await migration.query(`GRANT ${privilege}(owner_id) ON identity.bulk_reset_children TO dvaia_identity_runtime`);
    await assert.rejects(bulk.assertReady(),{code:'RESET_STORAGE_NOT_READY'});
    await migration.query(`REVOKE ${privilege}(owner_id) ON identity.bulk_reset_children FROM dvaia_identity_runtime`);await bulk.assertReady();
  }
  // Replace the correct signature with an overload carrying the exact original body.
  const originalFunction=(await migration.query("SELECT pg_get_functiondef('identity.bulk_reset_snapshot(uuid)'::regprocedure) AS definition")).rows[0].definition;
  await migration.query('ALTER FUNCTION identity.bulk_reset_snapshot(uuid) RENAME TO bulk_reset_snapshot_qualification_saved');
  try{
    await migration.query(originalFunction.replace('bulk_reset_snapshot(op uuid)','bulk_reset_snapshot(op uuid, extra integer)'));
    await migration.query('REVOKE ALL ON FUNCTION identity.bulk_reset_snapshot(uuid,integer) FROM PUBLIC,dvaia_identity_runtime');
    await assert.rejects(bulk.assertReady(),{code:'RESET_STORAGE_NOT_READY'});
  }finally{await migration.query('DROP FUNCTION IF EXISTS identity.bulk_reset_snapshot(uuid,integer)');await migration.query('ALTER FUNCTION identity.bulk_reset_snapshot_qualification_saved(uuid) RENAME TO bulk_reset_snapshot');}
  await bulk.assertReady();
  const service=resets.createPostgresWorkshopResetService({progress,adapters:resets.createPostgresWorkshopResetAdapters(load),bulkJournal:bulk.bulkJournal,resolveBulkActor:bulk.resolveBulkActor,
    withStudentResetAdmission:(id,work)=>resets.withPostgresStudentResetAdmission(leases,id,work)});
  const express=require('express'),app=express();
  const handler=(_req,res)=>res.json({});const operational=Object.fromEntries(['providerStatus','switchProvider','configureProvider','testProvider','testLlm','appLogs','llmLogs','logStats','systemMonitoring'].map(name=>[name,handler]));
  app.use('/api/admin',require('../../server/routes/postgresAdmin').createPostgresAdminRouter({adapter,stores:{pool:runtime,config:{},progress:realProgress},resetService:service,operational}));
  httpServer=await new Promise(resolve=>{const server=app.listen(0,'127.0.0.1',()=>resolve(server));});
  const discovery=`http://127.0.0.1:${httpServer.address().port}/api/admin/workshops/reset-operations`;
  assert.equal((await fetch(discovery)).status,401);
  assert.equal((await fetch(discovery+'?actorId=8',{headers:{authorization:'Bearer '+admin.token}})).status,400);
  evidence.cohorts=[];
  for(const [family,workshopKey,slot] of [['CSRF','csrf_workshop','poison'],['RAG','indirect_prompt_injection','current']]){
    const op=randomUUID();failOwner=sibling.id;failOnce=true;
    await assert.rejects(service.resetWorkshop({workshopKey,operationId:op,actorRequest:request(admin)}),/injected interruption/);
    const parent=(await journal.listPending({actorId:admin.id,sessionId:String(admin.sessionId)})).find(p=>p.operationId===op);
    const discovered=await fetch(discovery,{headers:{authorization:'Bearer '+admin.token}});assert.equal(discovered.status,200);assert.equal(discovered.headers.get('cache-control'),'no-store');assert.ok((await discovered.json()).operations.some(p=>p.operationId===op));
    const completed=parent.children.find(c=>c.ownerId===learner.id),interrupted=parent.children.find(c=>c.ownerId===sibling.id);
    assert.equal(completed.state,'completed');assert.equal(interrupted.state,'uncertain');
    const childBefore=(await migration.query('SELECT state FROM workshop_rag.reset_operations WHERE operation_id=$1',[interrupted.childOperationId])).rows[0];assert.equal(childBefore.state,'erased');
    await assert.rejects(upload(sibling,family,slot,'blocked-'+family),/Reset reconciliation required/);
    const newer=await upload(learner,family,slot,'newer-'+family);
    const late=await owner();await upload(late,family,slot,'late-'+family);const lateBefore=await snapshot(late);
    await service.resetWorkshop({workshopKey,operationId:op,actorRequest:request(admin)});
    assert.equal((await migration.query('SELECT state FROM workshop_rag.reset_operations WHERE operation_id=$1',[interrupted.childOperationId])).rows[0].state,'completed');
    assert.equal((await(await composition.resolveRequest(request(learner))).read({family,slot})).documentId,newer.documentId);
    assert.deepEqual(await snapshot(late),lateBefore);
    const done=await journal.begin({operationId:op,requestKind:'workshop',workshopKeys:[workshopKey],actorId:admin.id,sessionId:String(admin.sessionId)});assert.ok(done.children.every(c=>c.state==='completed'));assert.ok(!done.children.some(c=>c.ownerId===late.id));
    await service.resetWorkshop({workshopKey,operationId:op,actorRequest:request(admin)});assert.deepEqual(await snapshot(late),lateBefore);
    evidence.cohorts.push({family,completedOwnerSkipped:true,lateEnrollmentExcluded:true,interruptedChildStateBefore:'erased',interruptedChildStateAfter:'completed',newerCompletedOwnerSourcePreserved:true,repeatNoop:true});
  }
  Object.assign(evidence,{passed:true,actualIdentityAndCsrfStores:true,actualSourceVectorResetJournal:true,actualCanonicalProgressClear:true,actualEmailArtifactRetirement:true,controlledInterruptionAfterEffect:true,actualModel:false});
  evidence.mountedAuthenticatedDiscovery=true;
 }catch(error){evidence.failure={name:error.name,code:error.code||null,message:error.message};throw error;}finally{if(httpServer)await new Promise(resolve=>httpServer.close(resolve));await require('../../server/database/postgres').closePostgresPools();await Promise.all(pools.map(p=>p.end()));if(temporary)fs.rmSync(temporary,{recursive:true,force:true});fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH,JSON.stringify(evidence,null,2)+'\n',{mode:0o600});}
});
