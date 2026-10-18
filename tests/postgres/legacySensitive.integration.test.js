'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {createFinflowWorkshopDb}=require('../../server/database/postgres/sensitiveInfoWorkshopDb');
const {createLegacySensitiveStore}=require('../../server/database/postgres/legacySensitiveStore');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_FINFLOW_TEST_RUNTIME_URL;
test('legacy file/SSI PG keeps five judged types owner-scoped and retains receipts across reset',{skip:!enabled},async()=>{
 const pool=createPool(process.env,'PG_FINFLOW_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_FINFLOW_TEST_MIGRATION_URL');
 try{
  await createFinflowWorkshopDb(pool).initialize(migration);const store=createLegacySensitiveStore(pool);
  assert.equal((await store.getPublicDocuments()).length,3);
  const input={userId:11,objectiveId:'path_traversal',runId:randomUUID(),generation:0,flagFound:'fixture',exploitUsed:'../',completed:true,judgment:{verdict:'pass',judgeVersion:'fixture'}};
  for(const objectiveId of ['path_traversal','ssi_injection','combined_traversal_ssi','ai_assisted_path_traversal','ai_assisted_ssi'])await store.recordJudgment({...input,objectiveId});
  await store.recordJudgment(input);assert.equal((await store.getChallengeStats(11)).length,5);assert.deepEqual(await store.getChallengeStats(12),[]);
  await store.logFileAccess(11,'../secret/fixture','read','exploited','127.0.0.1','test');await store.logFileAccess(12,'public/file','read','success','127.0.0.1','test');
  assert.equal((await store.getAccessLogs(11)).length,1);assert.equal((await store.getAccessLogs(12)).length,1);
  await store.reset(11);assert.equal(await store.getGeneration(11),1);assert.deepEqual(await store.getChallengeStats(11),[]);assert.deepEqual(await store.getAccessLogs(11),[]);assert.equal((await store.getAccessLogs(12)).length,1);
  await assert.rejects(store.recordJudgment({...input,runId:randomUUID()}),{code:'STALE_GENERATION'});
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM legacy_sensitive.judgments WHERE user_id=11')).rows[0].n,5);
  await assert.rejects(pool.query('DELETE FROM legacy_sensitive.judgments WHERE user_id=11'),{code:'42501'});await assert.rejects(pool.query('UPDATE legacy_sensitive.judgments SET success=0 WHERE user_id=11'),{code:'42501'});
 }finally{await Promise.all([pool.end(),migration.end()]);}
});
