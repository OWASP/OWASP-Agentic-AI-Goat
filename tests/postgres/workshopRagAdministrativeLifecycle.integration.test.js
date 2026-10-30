'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');const {Pool}=require('pg');
const enabled=process.env.WORKSHOP_RAG_ADMIN_NATIVE==='1';
test('candidate durable RAG canonical admin reset and lease-bound deletion adapters',{skip:!enabled,timeout:180000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE),fs.realpathSync(process.cwd()));
 const pools=[];const pool=role=>{const u=new URL(process.env['WORKSHOP_RAG_'+role.toUpperCase()+'_URL']);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_workshop_rag_[a-f0-9]+$/);assert.equal(u.username,'dvaia_identity_'+role);const p=new Pool({connectionString:u.href,max:8,statement_timeout:15000,lock_timeout:5000});pools.push(p);return p;};
 const migration=pool('migration'),runtime=pool('runtime'),leases=pool('runtime');let temporary;
 const evidence={scope:'Real identity/source/vector/run-ledger/reset-service and canonical deletion admission/lease with exact RAG/CSRF adapters; external email/CSRF continuations controlled; not complete sixteen-store deletion',modelCalled:false};
 try{
  temporary=fs.mkdtempSync(path.join(os.tmpdir(),'rag-admin-candidate-'));for(const f of fs.readdirSync('db/postgres/identity-migrations'))if(f.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/identity-migrations',f),path.join(temporary,f));fs.copyFileSync('docs/modernization/drafts/workshop-rag/0082_workshop_rag_sources.candidate.sql',path.join(temporary,'0082_workshop_rag_sources.sql'));
  const {migrate}=require('../../db/postgres/migrate');await migrate(migration,temporary);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
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
  const siblingBefore=await snapshot(sibling);let failFlush=true,continuations=0;
  const ragRoute={durableRagComposition:()=>composition,resetOwner:(o,work)=>coordinators.RAG.reset(o,work),clearOwnerState:()=>{throw Error('RAM fallback');}};
  const csrfRoute={durableRagComposition:()=>composition,resetOwner:(o,work)=>coordinators.CSRF.reset(o,work),clearRagOwnerState:()=>{throw Error('RAM fallback');}};
  const load=name=>{
   if(name==='../routes/ragInjection')return ragRoute;if(name==='../routes/csrfWorkshop')return csrfRoute;
   if(name==='../routes/emailAgent')return{resetOwner:async(_,work)=>work(),destroyOwnerArtifacts:async()=>0};
   if(name==='./emailArtifactStore')return{assertReady:async()=>{},retireOwner:async()=>{continuations++;}};
   if(name==='../database/postgres/csrfWorkshopDb')return{resetUser:async()=>{},destroyOwner:async()=>({removed:0})};
   if(name==='./csrfVictimSandbox')return{resetSandbox:()=>{},getOrCreateSandbox:()=>({ready:async()=>{},reset:()=>{},flush:async()=>{if(failFlush)throw Error('controlled victim flush failure');}})};
   throw Error('Uncontrolled dependency '+name);
  };
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(runtime);
  const resets=require('../../server/services/postgresWorkshopResetService');const service=resets.createPostgresWorkshopResetService({progress,adapters:resets.createPostgresWorkshopResetAdapters(load),withStudentResetAdmission:(id,work)=>resets.withPostgresStudentResetAdmission(leases,id,work)});
  const op=randomUUID();await assert.rejects(service.resetAdministrativeStudent({userId:learner.id,workshopKey:'csrf_workshop',operationId:op,actorRequest:request(admin)}),/controlled victim flush failure/);
  assert.equal((await migration.query('SELECT state FROM workshop_rag.reset_operations WHERE operation_id=$1',[op])).rows[0].state,'erased');
  await assert.rejects(upload(learner,'CSRF','poison','blocked'),{code:'55000',message:'Reset reconciliation required'});assert.deepEqual(await snapshot(sibling),siblingBefore);
  failFlush=false;await service.resetAdministrativeStudent({userId:learner.id,workshopKey:'csrf_workshop',operationId:op,actorRequest:request(admin)});
  assert.equal((await migration.query('SELECT state FROM workshop_rag.reset_operations WHERE operation_id=$1',[op])).rows[0].state,'completed');
  const newer=await upload(learner,'CSRF','poison','newer');await service.resetAdministrativeStudent({userId:learner.id,workshopKey:'csrf_workshop',operationId:op,actorRequest:request(admin)});
  assert.equal((await(await composition.resolveRequest(request(learner))).read({family:'CSRF',slot:'poison'})).documentId,newer.documentId);
  await service.resetAdministrativeStudent({userId:learner.id,workshopKey:'indirect_prompt_injection',operationId:randomUUID(),actorRequest:request(admin)});assert.equal(continuations,1);
  await upload(learner,'RAG','current','deletion-source');
  const before=await snapshot(learner),revisionRows=(await migration.query('SELECT * FROM workshop_rag.embedding_revisions WHERE owner_id=$1 ORDER BY revision_id',[learner.id])).rows;
  const steps=require('../../server/services/studentDeletionComposition').STUDENT_DELETION_STEPS;
  const deletion=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(runtime,{steps});const job=await deletion.admit({requesterId:admin.id,subjectId:learner.id}),lease=await deletion.claim(job.jobId);
  const scope={subjectId:learner.id,jobId:job.jobId,leaseToken:lease.leaseToken,check:async()=>deletion.renew({jobId:job.jobId,leaseToken:lease.leaseToken,leaseMs:30000})};
  await assert.rejects(service.resetAdministrativeStudent({userId:learner.id,workshopKey:'csrf_workshop',operationId:randomUUID(),actorRequest:request(admin)}),{code:'STUDENT_DELETION_ADMITTED'});
  const adapters=require('../../server/services/studentDeletionAdapters').createStudentDeletionAdapters(load);
  await adapters.csrf_workshop(scope);await adapters.indirect_prompt_injection(scope);await adapters.csrf_workshop(scope);
  const after=await snapshot(learner);assert.equal(after.length,before.length);assert.ok(after.every(row=>row.body===null&&row.vectors===0&&row.retired_at));
  assert.deepEqual(after.map(r=>[r.document_id,r.source_sha256,r.chunk_manifest_sha256]),before.map(r=>[r.document_id,r.source_sha256,r.chunk_manifest_sha256]));
  assert.deepEqual((await migration.query('SELECT * FROM workshop_rag.embedding_revisions WHERE owner_id=$1 ORDER BY revision_id',[learner.id])).rows,revisionRows);assert.deepEqual(await snapshot(sibling),siblingBefore);
  Object.assign(evidence,{passed:true,populatedAdminReset:true,failedContinuationResumed:true,completedReplayPreservesNewerSource:true,canonicalDeletionJobAndLease:true,bothFamiliesErased:true,immutableManifestAndRevisionsPreserved:true,siblingPreserved:true,terminalFullDeletionClaimed:false});
 }finally{await Promise.all(pools.map(p=>p.end()));if(temporary)fs.rmSync(temporary,{recursive:true,force:true});fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH,JSON.stringify(evidence,null,2)+'\n',{mode:0o600});}
});
