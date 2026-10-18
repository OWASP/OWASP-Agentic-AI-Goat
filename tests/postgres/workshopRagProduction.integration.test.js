'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

test('production bootstrap binds real IPI and CSRF route exports before mounted lifecycle', {
  skip: process.env.WORKSHOP_RAG_PRODUCTION_NATIVE !== '1', timeout: 120000,
}, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  const url = role => {
    const u = new URL(process.env['WORKSHOP_RAG_' + role.toUpperCase() + '_URL']);
    assert.equal(u.hostname, '127.0.0.1'); assert.match(u.pathname, /^\/dvaia_test_workshop_rag_[a-f0-9]+$/);
    assert.equal(u.username, 'dvaia_identity_' + role); return u.href;
  };
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.WORKSHOP_DATABASE_ENGINE='postgres';process.env.AI_PROVIDER='mock';process.env.JUDGE_PROVIDER='mock';
  for(const role of ['RUNTIME','MIGRATION']){const u=new URL(process.env['CSRF_NATIVE_'+role+'_URL']);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_csrf_[a-f0-9]+$/);assert.equal(u.username,'dvaia_csrf_'+role.toLowerCase());process.env[role==='RUNTIME'?'CSRF_WORKSHOP_DATABASE_URL':'CSRF_WORKSHOP_MIGRATION_DATABASE_URL']=u.href;}
  process.env.IDENTITY_DATABASE_URL = url('runtime');
  process.env.IDENTITY_MIGRATION_DATABASE_URL = url('migration');
  process.env.JWT_SECRET = 'owned-native-route-qualification-secret-32bytes';
  const migration = new Pool({ connectionString: url('migration'), max: 2 });
  let directory, server;
  const evidence = { status: 'incomplete', scope: 'Mounted CSRF routes with canonical bearer, real isolated identity+CSRF databases and durable sources; controlled embeddings and always-fail fixture Judge; no actual model or credit qualification' };
  const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH;
  assert.ok(path.isAbsolute(evidencePath) && !path.resolve(evidencePath).startsWith(process.cwd() + path.sep));
  const save = () => fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  save();
  try {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rag-route-migrations-'));
    const base = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    for (const name of fs.readdirSync(base)) if (name.endsWith('.sql')) fs.copyFileSync(path.join(base, name), path.join(directory, name));
    assert.ok(fs.existsSync(path.join(directory,'0082_workshop_rag_sources.sql'))); // Use the registered production chain, no candidate overlay.
    await migrate(migration, directory); assert.deepEqual(await migrate(migration, directory), []);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const identity = require('../../server/database/postgres/identityRepository').createIdentityRepository(adapter.pool);
    const password = await require('bcryptjs').hash(randomUUID(), 4);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    await require('../../server/database/postgres/csrfWorkshopDb').initializeCsrfWorkshopDb();
    const completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts:require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(adapter.pool),progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(adapter.pool),judge:async packet=>{const prepared=require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet);return{family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,evidenceDigest:prepared.evidenceDigest,runId:packet.execution.runId,mode:packet.rubric.mode,verdict:'fail',criteria:[],explanation:'Controlled lifecycle-only fixture; no model credit.',provider:'fixture',model:'controlled-fail',usage:null};}});
    const graderModule=require('../../server/services/csrfObjectiveGrader'),original=graderModule.createCsrfObjectiveGrader;graderModule.createCsrfObjectiveGrader=options=>original({...options,completionService:completion,postgres:true});
    const router=require('../../server/routes/csrfWorkshop');graderModule.createCsrfObjectiveGrader=original;
    const production=require('../../server/services/workshopRagProduction').createWorkshopRagProduction({env:process.env,load:name=>name==='./secureshopProductEmbedder'?{createSecureShopProductEmbedder:()=>({getRuntimeFingerprint:()=>({fingerprint:'a'.repeat(64)}),embed:async()=>({embeddingDimension:384,embedding:Array.from({length:384},(_,i)=>i===0?1:0)})})}:require('../../server/services/'+name)});
    const activation=await production.initialize(),composition=activation.composition;
    assert.equal(await activation.warmEmbedding(),true);
    const ipiRouter=require('../../server/routes/ragInjection');
    assert.equal(router.durableRagComposition(),composition);assert.equal(ipiRouter.durableRagComposition(),composition);
    assert.equal(activation.resetAdapters.csrf_workshop.bulkResetReplaySafe(),true);
    assert.equal(activation.resetAdapters.indirect_prompt_injection.bulkResetReplaySafe(),true);
    const express=require('express'),app=express();app.use(express.json());app.use('/csrf',require('../../server/middleware/adminAuth').authenticateToken,router);app.use('/ipi',require('../../server/middleware/adminAuth').authenticateToken,ipiRouter);
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const origin=`http://127.0.0.1:${server.address().port}`;
    async function owner(){const user=await identity.createUser({username:'csrf-rag-'+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:password});const session=await adapter.createSession({...user,password},{});const req={user:{id:user.id},identitySession:{id:session.internalSessionId},headers:{authorization:`Bearer ${session.token}`}};return{user,session,scope:await composition.resolveRequest(req)};}
    const a=await owner(),b=await owner();
    const request=async(o,pathname,body,extra={})=>{const response=await fetch(origin+pathname,{method:body===undefined?'GET':'POST',headers:{...(o?{authorization:`Bearer ${o.session.token}`}:{}) ,...(body===undefined?{}:{'content-type':'application/json'}),...extra},...(body===undefined?{}:{body:JSON.stringify(body)})});return{status:response.status,body:await response.json()};};
    assert.equal((await request(null,'/csrf/rag/state')).status,401);assert.equal((await request(null,'/csrf/rag/state',undefined,{authorization:'Bearer invalid'})).status,401);
    assert.equal((await request(a,'/ipi/current-session')).status,200);
    const state=await request(a,'/csrf/rag/state');assert.equal(state.status,200,JSON.stringify(state.body));assert.equal(state.body.poisoned,false);
    const cleanBefore=await a.scope.read({family:'CSRF',slot:'clean'});assert.ok(cleanBefore.document);
    const ragRuns=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'RAG'});let ipiDocument;
    await ragRuns.run(String(a.user.id),{},async execution=>{const store=await a.scope.bind(execution,{family:'RAG',slot:'current'});ipiDocument=randomUUID();await store.ingestAndSelect({documentId:ipiDocument,operationId:randomUUID(),filename:'ipi-sibling.txt',ingestionKind:'upload',sourceBuffer:Buffer.from('Separate IPI family source must survive CSRF poison reset.')});});
    const poison='\ufeff  Owned poison training document. <img src="/api/workshop/csrf/agent-action?tab=indirect&action=disable_mfa">  ';
    const first=await request(a,'/csrf/rag/poison',{doc:poison});assert.equal(first.status,200,JSON.stringify(first.body));const p1=await a.scope.read({family:'CSRF',slot:'poison'});assert.equal(p1.document.sourceText,poison);
    assert.equal((await request(b,'/csrf/rag/poison',{doc:'Sibling durable poison source with independent owner.'})).status,200);const siblingBefore=await b.scope.read({family:'CSRF',slot:'poison'});
    const operationId=randomUUID();const reset=await request(a,'/csrf/rag/reset',{}, {'x-reset-operation-id':operationId});assert.equal(reset.status,200,JSON.stringify(reset.body));
    assert.equal((await a.scope.read({family:'CSRF',slot:'poison'})).document,null);assert.deepEqual(await a.scope.read({family:'CSRF',slot:'clean'}),cleanBefore);assert.equal((await a.scope.read({family:'RAG',slot:'current'})).documentId,ipiDocument);assert.deepEqual(await b.scope.read({family:'CSRF',slot:'poison'}),siblingBefore);
    assert.equal((await request(a,'/csrf/rag/state')).status,200);assert.equal((await request(a,'/csrf/rag/reset',{}, {'x-reset-operation-id':operationId})).status,200);
    const second=await request(a,'/csrf/rag/poison',{doc:poison+' New explicit upload.'});assert.equal(second.status,200,JSON.stringify(second.body));const p2=await a.scope.read({family:'CSRF',slot:'poison'});assert.notEqual(p2.documentId,p1.documentId);assert.equal(p2.resourceGeneration,'1');
    assert.equal((await request(a,'/csrf/rag/reset',{})).status,200);
    // Explicit owned fixture: retained legacy victim-state text exists but no durable poison source.
    const victim=require('../../server/services/csrfVictimSandbox').getOrCreateSandbox('csrf_'+a.user.id);victim.tab('indirect').ragPoisoned=true;victim.tab('indirect').ragDocText='Retained legacy source; never silently import.';await victim.flush();
    const missing=await request(a,'/csrf/rag/state');assert.equal(missing.status,503,JSON.stringify(missing.body));assert.equal(missing.body.code,'CSRF_RAG_RESOURCE_UNAVAILABLE');assert.equal((await a.scope.read({family:'CSRF',slot:'poison'})).document,null);
    assert.equal((await request(a,'/csrf/rag/reset',{})).status,200);assert.equal((await request(a,'/csrf/rag/state')).status,200);
    await adapter.logout(a.session.token);assert.equal((await request(a,'/csrf/rag/state')).status,401);
    evidence.productionBootstrap=true;evidence.actualRouteGetters=true;evidence.status='passed';evidence.checks=['missing/invalid/revoked bearer denied','exact BOM poison source persists','CSRF poison reset preserves clean and same-owner IPI family','sibling owner unchanged','reset operation replay and subsequent upload generation continuation','retained legacy poison without durable source explicit503 and no import','explicit reset recovers missing source'];save();
  }catch(error){evidence.failure={name:error.name,code:error.code||null,message:error.message};save();throw error;}
  finally{if(server)await new Promise(resolve=>server.close(resolve));await require('../../server/database/postgres').closePostgresPools();await migration.end();if(directory)fs.rmSync(directory,{recursive:true,force:true});}
});
