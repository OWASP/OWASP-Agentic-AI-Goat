'use strict';
// Import-inert support only. No browser, provisioning, provider, or qualification
// is performed by importing this module. The launcher owns initialization.
const assert=require('node:assert/strict');
const {requiredStoreManifest}=require('../../db/postgres/initialize-application');
const {STUDENT_DELETION_STEPS}=require('../../server/services/studentDeletionComposition');
const {poolBudget}=require('../../server/database/postgres/poolBudget');
const STORES=Object.freeze(requiredStoreManifest.map(row=>Object.freeze({...row,
  migrationRole:row.runtimeRole.replace(/_runtime$/,'_migration')})));
const BUDGET=78;
function admitStores(env){
  assert.equal(env.PG_TEST_DISPOSABLE,'yes');
  assert.equal(env.PLATFORM_DATABASE_ENGINE,'postgres');assert.equal(env.WORKSHOP_DATABASE_ENGINE,'postgres');
  assert.equal(Object.hasOwn(env,'LEGACY_PLATFORM_LIFECYCLE_ENABLED'),false);
  assert.equal(String(env.PG_POOL_BUDGET),'78');
  const databases=new Set(),endpoints=new Set();
  const rows=STORES.map(store=>{
    const pair=[store.runtimeVariable,store.migrationVariable].map(key=>{
      const u=new URL(env[key]);assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');
      assert.match(u.port,/^[1-9][0-9]{0,4}$/);assert.ok(Number(u.port)<=65535);
      assert.equal(u.search,'');assert.equal(u.hash,'');
      const tag=u.pathname.match(/^\/owasp_ai_goat_test_student_deletion_([a-f0-9]{12})_/ )?.[1];
      assert.ok(tag);const expected=`owasp_ai_goat_test_student_deletion_${tag}_${store.schema}`;
      assert.ok(Buffer.byteLength(expected,'utf8')<=63);
      assert.equal(u.pathname,'/'+expected);
      return u;
    });
    assert.equal(decodeURIComponent(pair[0].username),store.runtimeRole);
    assert.equal(decodeURIComponent(pair[1].username),store.migrationRole);
    assert.equal(pair[0].pathname,pair[1].pathname);assert.equal(pair[0].host,pair[1].host);
    assert.ok(pair[0].pathname.endsWith('_'+store.schema));
    assert.equal(databases.has(pair[0].pathname),false);databases.add(pair[0].pathname);endpoints.add(pair[0].host);
    return Object.freeze({schema:store.schema,database:pair[0].pathname.slice(1)});
  });
  assert.equal(rows.length,16);assert.equal(endpoints.size,1);
  assert.equal(new Set(rows.map(r=>r.database.match(/deletion_([a-f0-9]{12})_/)[1])).size,1);
  return Object.freeze(rows);
}
// Each entry is one actual pool/reservation, NOT one distinct store. Duplicates
// deliberately count; production createPool remains the allocation-time gate.
function planPools(env,allocations){
  admitStores(env);assert.ok(Array.isArray(allocations)&&allocations.length>0);
  const ids=new Set();const rows=allocations.map(a=>{
    assert.match(a.id,/^[a-z][a-z0-9_-]{0,79}$/);assert.equal(ids.has(a.id),false);ids.add(a.id);
    assert.ok(STORES.some(s=>s.runtimeVariable===a.key||s.migrationVariable===a.key));
    const b=poolBudget(env,a.key,a.purpose);assert.equal(b.budget,BUDGET);
    return {id:a.id,purpose:b.purpose,max:b.max};
  });
  const reserved=rows.reduce((n,r)=>n+r.max,0);assert.ok(reserved<=BUDGET);
  return {reserved,allocations:rows};
}
function assertPoolSnapshot(snapshot){
  assert.ok(Array.isArray(snapshot.allocations));
  for(const row of snapshot.allocations){assert.ok(Number.isSafeInteger(row.max)&&row.max>0);assert.ok(['control','workshop','lease','provision','teaching','protected','migration'].includes(row.purpose));}
  assert.equal(snapshot.reserved,snapshot.allocations.reduce((n,r)=>n+r.max,0));
  assert.ok(snapshot.reserved<=BUDGET);return snapshot;
}
function createFixturePool(env,key,{purpose}={}){
  admitStores(env);assert.ok(STORES.some(s=>s.runtimeVariable===key||s.migrationVariable===key));
  return require('../../server/database/postgres').createPool(env,key,{purpose});
}
function assertPoolsDrained(){
  const snapshot=assertPoolSnapshot(require('../../server/database/postgres').getPoolBudgetSnapshot());
  assert.equal(snapshot.reserved,0);return true;
}
async function openProductionDeletionSupport(env=process.env){
  assert.equal(env,process.env,'Production deletion support requires process.env identity');
  admitStores(process.env);
  // Singleton production factories read process.env. Never admit a different
  // supplied object and accidentally allocate against the application's URLs.
  for(const row of STORES)for(const key of [row.runtimeVariable,row.migrationVariable])assert.equal(env[key],process.env[key]);
  assert.equal(process.env.PG_POOL_BUDGET,'78');
  const pg=require('../../server/database/postgres');
  const before=assertPoolSnapshot(pg.getPoolBudgetSnapshot());
  assert.equal(before.allocations.some(a=>a.purpose==='migration'),false,'Initialization pools must be closed before runtime admission');
  const production=require('../../server/services/studentDeletionProduction');
  try {
    const composition=await production.getProductionStudentDeletionComposition();
    assert.deepEqual(composition.steps,STUDENT_DELETION_STEPS);
    assert.equal(composition.steps.length,17);
    const after=assertPoolSnapshot(pg.getPoolBudgetSnapshot());
    return Object.freeze({application:composition.application,steps:composition.steps,poolSnapshot:after,
      readPoolSnapshot:()=>assertPoolSnapshot(pg.getPoolBudgetSnapshot()),
      close:()=>production.closeProductionStudentDeletionComposition()});
  } catch(error){await production.closeProductionStudentDeletionComposition().catch(()=>{});throw error;}
}
async function readIdentityDeletionState(pool,subjectId){
  assert.ok(Number.isSafeInteger(subjectId)&&subjectId>0);
  const user=(await pool.query('SELECT id,username,email,is_active FROM identity.users WHERE id=$1',[subjectId])).rows;
  const sessions=(await pool.query('SELECT id,is_active FROM identity.user_sessions WHERE user_id=$1 ORDER BY id',[subjectId])).rows;
  const jobs=(await pool.query('SELECT job_id,state FROM identity.student_deletion_jobs WHERE subject_user_id=$1 ORDER BY job_id',[subjectId])).rows;
  const steps=jobs.length===1?(await pool.query('SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[jobs[0].job_id])).rows:[];
  return {user,sessions,jobs,steps};
}
function assertIdentityDeletionComplete(state,{subjectId,jobId,siblingBefore,siblingAfter}){
  assert.deepEqual(state.jobs,[{job_id:jobId,state:'completed'}]);
  assert.deepEqual(state.steps,STUDENT_DELETION_STEPS.map(step_key=>({step_key,state:'completed'})));
  assert.deepEqual(state.user,[{id:subjectId,username:`deleted-${jobId}`,email:`deleted-${jobId}@invalid.local`,is_active:0}]);
  assert.deepEqual(state.sessions,[]);
  assert.ok(siblingBefore&&siblingAfter);assert.deepEqual(siblingAfter,siblingBefore);
  // This validates identity/journal only. Store-specific immutable evidence and
  // physical Cancel/ACK-loss proofs must be supplied by the future fixture.
  return {identityTerminal:true,allStepsCompleted:true,sessionsRemoved:true,siblingSnapshotUnchanged:true,
    fullQ05Qualification:false,canonicalCredit:false};
}
module.exports={STORES,BUDGET,STUDENT_DELETION_STEPS,admitStores,planPools,assertPoolSnapshot,createFixturePool,assertPoolsDrained,
  openProductionDeletionSupport,readIdentityDeletionState,assertIdentityDeletionComplete};
