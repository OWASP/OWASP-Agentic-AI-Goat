'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const express=require('express');
const bcrypt=require('bcryptjs');
const {randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const {readMigrations}=require('../../db/postgres/migrate');
const {initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
const {createFinflowWorkshopDb}=require('../../server/database/postgres/sensitiveInfoWorkshopDb');

const ROOT=path.resolve(__dirname,'../..');
const identityHead=path.join(ROOT,'db/postgres/identity-migrations');
const finflowHead=path.join(ROOT,'db/postgres/workshop-migrations/finflow');
const candidates=[
  [path.join(ROOT,'docs/modernization/drafts/sensitive-info-aggregate-reset.sql'),path.join(identityHead,'0044_sensitive_info_aggregate_reset.sql')],
  [path.join(ROOT,'docs/modernization/drafts/sensitive-info-aggregate-reset-finflow.sql'),path.join(finflowHead,'0009_sensitive_info_aggregate_reset.sql')],
];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.IDENTITY_DATABASE_URL
  &&process.env.IDENTITY_MIGRATION_DATABASE_URL&&process.env.FINFLOW_WORKSHOP_DATABASE_URL
  &&process.env.FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL;

async function json(url,options={}){
  const response=await fetch(url,options);let body;
  try{body=await response.json();}catch{body=null;}
  return{status:response.status,body};
}
async function seedOwner(identity,finflow,id){
  await identity.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation)
    VALUES($1,'sensitive_info_disclosure',2)`,[id]);
  await identity.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
    VALUES($1,'sensitive_info_disclosure','llm_identify')`,[id]);
  await identity.query(`INSERT INTO workshop_platform.activity_counters(user_id,workshop_key,activity_key,activity_count)
    VALUES($1,'sensitive_info_disclosure','attempts',2)`,[id]);
  await identity.query(`INSERT INTO workshop_platform.time_tracking
    (user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,'sensitive_info_disclosure',now(),now(),11)`,[id]);
  await finflow.query('INSERT INTO legacy_sensitive.owner_state(user_id,generation) VALUES($1,4)',[id]);
  await finflow.query(`INSERT INTO legacy_sensitive.access_logs(user_id,file_path,access_type,status)
    VALUES($1,'/owned/http-reset','read','success')`,[id]);
  await finflow.query(`INSERT INTO finflow.progress(user_id,objective_id,completed,completed_at)
    VALUES($1,'llm_identify',true,clock_timestamp())`,[String(id)]);
  await finflow.query(`INSERT INTO finflow.tool_log(user_id,tool_name,mode)
    VALUES($1,'owned_http_reset','vulnerable')`,[String(id)]);
}

test('mounted authenticated reset is durable, replayable, isolated, and catalog independent',{
  skip:!enabled,timeout:45000,
},async()=>{
  assert.equal(process.env.SENSITIVE_INFO_AGGREGATE_RESET_ENABLED,'true');
  const isolated=await fs.realpath(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  const source=await fs.realpath(ROOT);const relative=path.relative(isolated,source);
  assert.ok(relative&&!relative.startsWith(`..${path.sep}`)&&relative!=='..'&&!path.isAbsolute(relative));
  for(const [draft,target] of candidates)await fs.copyFile(draft,target);
  const identityRuntime=new Pool({connectionString:process.env.IDENTITY_DATABASE_URL,max:6});
  const identityMigration=new Pool({connectionString:process.env.IDENTITY_MIGRATION_DATABASE_URL,max:3});
  const finflowRuntime=new Pool({connectionString:process.env.FINFLOW_WORKSHOP_DATABASE_URL,max:6});
  const finflowMigration=new Pool({connectionString:process.env.FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL,max:3});
  let server;let authRouter;
  try{
    await initializeIdentityRepository(identityRuntime,identityMigration);await seedWorkshopPlatform(identityMigration);
    await createFinflowWorkshopDb(finflowRuntime).initialize(finflowMigration);
    assert.deepEqual(await initializeIdentityRepository(identityRuntime,identityMigration),[]);
    assert.deepEqual((await identityMigration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
      (await readMigrations(identityHead)).map(({name,checksum})=>({name,checksum})));
    assert.deepEqual((await finflowMigration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
      (await readMigrations(finflowHead)).map(({name,checksum})=>({name,checksum})));
    const phase=(await identityRuntime.query(`SELECT objective_id,is_enabled,catalog_active
      FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure'
      AND objective_id=ANY($1::text[])`,[[
      'path_traversal','ssi_injection','combined_traversal_ssi','ai_assisted_path_traversal','ai_assisted_ssi']])).rows;
    assert.deepEqual(phase,[],'reset-only promotion must not register the five phase-two objectives');
    const password='Owned-Reset9!';const hash=await bcrypt.hash(password,4);
    const owner=7301,sibling=7302;
    for(const [id,name] of [[owner,'http-reset-owner'],[sibling,'http-reset-sibling']]){
      await identityRuntime.query(`INSERT INTO identity.users(id,username,email,password,role,is_active,email_verified)
        VALUES($1,$2,$3,$4,'student',1,1)`,[id,name,`${name}@owned.invalid`,hash]);
      await seedOwner(identityRuntime,finflowRuntime,id);
    }
    await identityMigration.query(`UPDATE workshop_platform.objectives SET label='Instructor retained HTTP label'
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='llm_identify'`);
    await identityMigration.query(`UPDATE workshop_platform.objectives SET is_enabled=false
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='tool_enum'`);
    const staleRun=randomUUID(),ownerKey=JSON.stringify(['LegacySensitiveInfo',String(owner)]);
    await identityRuntime.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);
    await identityRuntime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
      VALUES($1,$2,0,'running')`,[staleRun,ownerKey]);

    const app=express();app.use(express.json());
    authRouter=require('../../server/routes/auth');
    app.use('/api/auth',authRouter);
    app.use('/api/workshop/sensitive-info',require('../../server/routes/sensitiveInfoWorkshop'));
    app.use('/api/sensitive-info',require('../../server/routes/sensitiveInfo'));
    app.use((error,_req,res,_next)=>res.status(error?.code==='23514'?409:500).json({error:'owned reset failure'}));
    server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
    const base=`http://127.0.0.1:${server.address().port}`;
    async function login(username){const response=await json(`${base}/api/auth/login`,{method:'POST',
      headers:{'content-type':'application/json'},body:JSON.stringify({username,password})});
      assert.equal(response.status,200);return response.body.token;}
    const ownerToken=await login('http-reset-owner'),siblingToken=await login('http-reset-sibling');
    const auth=token=>({authorization:`Bearer ${token}`});
    const canonicalTotal=(await identityMigration.query(`SELECT count(*)::int n
      FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure'
      AND is_enabled=true AND catalog_active=true`)).rows[0].n;
    assert.equal(canonicalTotal,17,'existing FinFlow18 minus the instructor-disabled objective');
    const before=await json(`${base}/api/workshop/sensitive-info/progress/999999`,{headers:auth(ownerToken)});
    assert.equal(before.status,200);assert.equal(before.body.total,canonicalTotal);
    assert.equal(before.body.progress.some(row=>row.id==='tool_enum'),false);
    assert.equal(before.body.progress.find(row=>row.id==='llm_identify').label,'Instructor retained HTTP label');

    await finflowMigration.query(`CREATE FUNCTION finflow.reject_owned_http_cleanup() RETURNS trigger
      LANGUAGE plpgsql AS $$BEGIN IF OLD.user_id='${owner}' THEN RAISE EXCEPTION 'owned cleanup unavailable'; END IF; RETURN OLD; END$$`);
    await finflowMigration.query(`CREATE TRIGGER reject_owned_http_cleanup BEFORE DELETE ON finflow.tool_log
      FOR EACH ROW EXECUTE FUNCTION finflow.reject_owned_http_cleanup()`);
    const operationId=randomUUID();
    const first=await json(`${base}/api/workshop/sensitive-info/progress/reset`,{method:'POST',
      headers:{...auth(ownerToken),'x-reset-operation-id':operationId}});
    assert.equal(first.status,500);
    const pending=(await identityMigration.query(`SELECT status,from_generation,to_generation
      FROM identity.sensitive_info_resets WHERE operation_id=$1`,[operationId])).rows[0];
    assert.deepEqual(pending,{status:'failed',from_generation:2,to_generation:3});
    assert.equal((await identityMigration.query('SELECT status FROM graph_runtime.runs WHERE run_id=$1',[staleRun])).rows[0].status,'interrupted');
    await assert.rejects(identityRuntime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
      VALUES($1,$2,0,'running')`,[randomUUID(),ownerKey]),error=>error.code==='23514');
    await finflowMigration.query('DROP TRIGGER reject_owned_http_cleanup ON finflow.tool_log');
    await finflowMigration.query('DROP FUNCTION finflow.reject_owned_http_cleanup()');

    const retry=await json(`${base}/api/sensitive-info/progress/reset`,{method:'POST',
      headers:{...auth(ownerToken),'x-reset-operation-id':operationId}});
    assert.equal(retry.status,200);assert.equal(retry.body.reset.operationId,operationId);
    assert.deepEqual(retry.body.reset,{operationId,fromGeneration:2,toGeneration:3,status:'completed'});
    const replay=await json(`${base}/api/workshop/sensitive-info/progress/reset`,{method:'POST',
      headers:{...auth(ownerToken),'x-reset-operation-id':operationId}});
    assert.equal(replay.status,200);assert.deepEqual(replay.body.reset,retry.body.reset);
    const after=await json(`${base}/api/workshop/sensitive-info/progress/999999`,{headers:auth(ownerToken)});
    assert.equal(after.status,200);assert.equal(after.body.total,canonicalTotal);
    assert.equal(after.body.completedCount,0);
    assert.equal(after.body.progress.some(row=>row.id==='tool_enum'),false);
    assert.equal(after.body.progress.find(row=>row.id==='llm_identify').label,'Instructor retained HTTP label');
    const legacyStats=await json(`${base}/api/sensitive-info/stats`,{headers:auth(ownerToken)});
    assert.equal(legacyStats.status,200);assert.deepEqual(legacyStats.body.stats,[]);
    assert.equal(legacyStats.body.totalChallenges,0);
    const legacyLogs=await json(`${base}/api/sensitive-info/logs/access`,{headers:auth(ownerToken)});
    assert.equal(legacyLogs.status,200);assert.deepEqual(legacyLogs.body.logs,[]);assert.equal(legacyLogs.body.count,0);
    const malformed=await json(`${base}/api/sensitive-info/progress/reset`,{method:'POST',
      headers:{...auth(ownerToken),'x-reset-operation-id':'malformed'}});
    assert.equal(malformed.status,400);
    const wrongOwner=await json(`${base}/api/sensitive-info/progress/reset`,{method:'POST',
      headers:{...auth(siblingToken),'x-reset-operation-id':operationId}});
    assert.equal(wrongOwner.status,409);
    assert.equal((await identityRuntime.query(`SELECT generation FROM workshop_platform.user_state
      WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`,[owner])).rows[0].generation,3);
    assert.equal((await identityRuntime.query(`SELECT generation FROM workshop_platform.user_state
      WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`,[sibling])).rows[0].generation,2);
    assert.equal((await finflowRuntime.query('SELECT count(*)::int n FROM finflow.tool_log WHERE user_id=$1',[String(owner)])).rows[0].n,0);
    assert.equal((await finflowRuntime.query('SELECT count(*)::int n FROM finflow.tool_log WHERE user_id=$1',[String(sibling)])).rows[0].n,1);
    const settings=(await identityMigration.query(`SELECT label,is_enabled FROM workshop_platform.objectives
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id=ANY($1::text[]) ORDER BY objective_id`,
    [['llm_identify','tool_enum']])).rows;
    assert.deepEqual(settings,[{label:'Instructor retained HTTP label',is_enabled:true},
      {label:'Tool Enumeration — list all tools including admin tools',is_enabled:false}]);
  }finally{
    if(server)await new Promise(resolve=>server.close(resolve));authRouter?.close?.();
    await require('../../server/services/sensitiveInfoResetComposition').closeSensitiveInfoResetComposition();
    await require('../../server/database/postgres').closePostgresPools();
    await Promise.allSettled([identityRuntime.end(),identityMigration.end(),finflowRuntime.end(),finflowMigration.end()]);
    await Promise.all(candidates.map(([,target])=>fs.rm(target,{force:true})));
  }
});
