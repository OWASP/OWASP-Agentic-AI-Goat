'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {createWorkshopProgressRepository}=require('../../server/database/postgres/workshopProgressRepository');
const {createObjectiveEvidenceRepository}=require('../../server/database/postgres/objectiveEvidenceRepository');
test('PG objective evidence is owner/scenario/generation scoped, idempotent, bounded and expirable',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_EVIDENCE_TEST_RUNTIME_URL},async()=>{
 const pool=createPool(process.env,'PG_EVIDENCE_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_EVIDENCE_TEST_MIGRATION_URL');
 try{
  await initializeIdentityRepository(pool,migration);await seedWorkshopPlatform(migration);
  const users=createIdentityRepository(pool),hash=await require('bcryptjs').hash('Fixture@123',4);
  const a=await users.createUser({username:'evidence-a',email:'ea@test.test',passwordHash:hash}),b=await users.createUser({username:'evidence-b',email:'eb@test.test',passwordHash:hash});
  const repo=createObjectiveEvidenceRepository(pool,{maxEntries:3,maxBytes:256,retentionSeconds:60}),progress=createWorkshopProgressRepository(pool);
  const base={userId:a.id,workshopKey:'sql_injection_workshop',scenario:'column_boundary',generation:0};
  const first={...base,runId:randomUUID(),evidenceID:'order8',evidence:{tool:'search_products',columns:8,error:null}};
  await Promise.all([repo.append(first),repo.append(first)]);assert.equal((await repo.list(base)).length,1);
  await assert.rejects(repo.append({...first,evidence:{columns:9}}),{code:'IDEMPOTENCY_CONFLICT'});
  await repo.append({...base,runId:randomUUID(),evidenceID:'order9',evidence:{tool:'search_products',columns:9,error:'ORDER BY position not in select list'}});
  assert.deepEqual((await repo.list(base)).map(e=>e.evidence.columns),[8,9]);assert.equal((await repo.list({...base,userId:b.id})).length,0);assert.equal((await repo.list({...base,scenario:'other'})).length,0);
  const omitted=await repo.append({...base,runId:randomUUID(),evidenceID:'huge',evidence:{output:'x'.repeat(1000)}});assert.equal(omitted.omitted,true);assert.equal(omitted.evidence,null);assert.equal(omitted.omissionReason,'byte_limit');
  const forbidden=await repo.append({...base,runId:randomUUID(),evidenceID:'headers',evidence:{headers:{Authorization:'do-not-store'}}});assert.equal(forbidden.omitted,true);assert.equal(forbidden.omissionReason,'forbidden_transport_field');assert.deepEqual((await repo.list(base)).map(r=>r.evidenceID),['order9','huge','headers']);
  const saved=await migration.query('SELECT evidence_json FROM workshop_platform.objective_evidence');assert.equal(JSON.stringify(saved.rows).includes('do-not-store'),false);
  await progress.resetWorkshopProgress(a.id,base.workshopKey);await assert.rejects(repo.append({...first,evidenceID:'stale'}),{code:'STALE_GENERATION'});await assert.rejects(repo.list(base),{code:'STALE_GENERATION'});
  const fresh={...base,generation:1};assert.deepEqual(await repo.list(fresh),[]);assert.equal((await migration.query('SELECT count(*)::int n FROM workshop_platform.objective_evidence WHERE user_id=$1',[a.id])).rows[0].n,0);
  await repo.append({...fresh,runId:randomUUID(),evidenceID:'new',evidence:{rows:[]}});
  await migration.query("UPDATE workshop_platform.objective_evidence SET expires_at=clock_timestamp()-interval '1 second'");assert.equal(await repo.purgeExpired(),1);assert.deepEqual(await repo.list(fresh),[]);
 }finally{await Promise.all([pool.end(),migration.end()]);}
});
