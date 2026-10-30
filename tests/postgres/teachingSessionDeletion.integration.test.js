'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID}=require('node:crypto');const {Pool}=require('pg');
test('canonical authenticated deletion retires live and previously retired teaching cookies without sibling damage',{
 skip:process.env.TEACHING_DELETION_NATIVE!=='1',timeout:180000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const pools=[];const connect=role=>{const u=new URL(process.env[`WORKSHOP_RAG_${role.toUpperCase()}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_workshop_rag_[a-f0-9]+$/);assert.equal(u.username,`dvaia_identity_${role}`);const p=new Pool({connectionString:u.href,max:5,statement_timeout:10000});pools.push(p);return p;};
 const migration=connect('migration'),runtime=connect('runtime'),effectPool=connect('runtime');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'teaching-deletion-migrations-'));
 try{
  for(const file of fs.readdirSync('db/postgres/identity-migrations').filter(x=>x.endsWith('.sql')))fs.copyFileSync(path.join('db/postgres/identity-migrations',file),path.join(dir,file));
  fs.copyFileSync('docs/modernization/drafts/teaching-sessions/0095_teaching_sessions.candidate.sql',path.join(dir,'0095_teaching_sessions.sql'));
  const {migrate}=require('../../db/postgres/migrate');await migrate(migration,dir);assert.deepEqual(await migrate(migration,dir),[]);
  const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime);
  const hash=await require('bcryptjs').hash(randomUUID(),4);
  const make=label=>users.createUser({username:label+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash:hash});
  const admin=await make('admin'),owner=await make('owner'),sibling=await make('sibling');
  await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.id]);
  const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:users,jwtSecret:'synthetic-teaching-deletion-signing-key-32chars'});
  const sessions={};for(const u of [admin,owner,sibling])sessions[u.id]=await adapter.createSession({...await users.getUserById(u.id),password:hash},{});
  const authenticatedAdmin=await adapter.validateSession(sessions[admin.id].token);assert.equal(authenticatedAdmin.user.id,admin.id);
  const Store=require('../../server/services/postgresTeachingSessionStore').PostgresTeachingSessionStore;
  const store=new Store({pool:runtime,effectPool,secret:'owned-teaching-deletion-private-issuance-key'});
  const call=(method,...args)=>new Promise((resolve,reject)=>store[method](...args,(e,v)=>e?reject(e):resolve(v)));
  const data=u=>({userId:u.id,platformOwnerId:u.id,platformSessionId:sessions[u.id].internalSessionId,username:u.username,cookie:{maxAge:14400000}});
  const live=store.genid(),retired=store.genid(),siblingSid=store.genid();
  await call('set',live,data(owner));await call('set',retired,data(owner));await call('destroy',retired);await call('set',siblingSid,data(sibling));
  const siblingBefore=(await runtime.query('SELECT * FROM identity.teaching_sessions WHERE owner_id=$1',[sibling.id])).rows;
  const tombstonesBefore=(await runtime.query('SELECT session_hash,expires_at FROM identity.teaching_sessions WHERE revoked')).rows;
  const {STUDENT_DELETION_STEPS}=require('../../server/services/studentDeletionComposition');
  const repository=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(runtime,{steps:STUDENT_DELETION_STEPS});
  // No nonidentity stores exist in this owned fixture. Their acknowledged steps
  // are controlled adapters, not qualification of sixteen-store deletion.
  const controlled=[];let admissionProof=false;
  const adapters=Object.fromEntries(STUDENT_DELETION_STEPS.map(step=>[step,async scope=>{
   await scope.check();controlled.push(step);
   if(step==='revoke_runs'){
    assert.equal(await call('get',live),null);assert.equal(await call('get',retired),null);
    await assert.rejects(call('set',live,data(owner)));await assert.rejects(call('set',retired,data(owner)));
    assert.equal((await runtime.query('SELECT count(*)::int n FROM identity.teaching_sessions WHERE owner_id=$1',[owner.id])).rows[0].n,0);admissionProof=true;
   }return{completed:true};
  }]));
  const unused={query:async()=>{throw Error('Nonidentity pool not provisioned');}};
  adapters.identity=require('../../server/services/studentDeletionStoreCleanup').createStudentDeletionStoreCleanup({identityPool:runtime,xssPool:unused,finflowPool:unused}).identity;
  const worker=require('../../server/services/studentDeletionWorker').createStudentDeletionWorker({repository,adapters});
  const application=require('../../server/services/studentDeletionApplication').createStudentDeletionApplication({repository,worker});
  await assert.rejects(application.deleteStudent({requesterId:sibling.id,subjectId:owner.id}),{code:'ADMIN_REQUIRED'});
  const outcome=await application.deleteStudent({requesterId:authenticatedAdmin.user.id,subjectId:owner.id});
  assert.equal(outcome.completed,true);assert.equal(admissionProof,true);assert.equal(controlled.length,STUDENT_DELETION_STEPS.length-1);
  const receipt=(await runtime.query('SELECT job_id,state,completed_at FROM identity.student_deletion_jobs WHERE job_id=$1',[outcome.jobId])).rows[0];assert.equal(receipt.state,'completed');
  const replay=await application.deleteStudent({requesterId:admin.id,subjectId:owner.id});assert.equal(replay.replayed,true);assert.equal(controlled.length,STUDENT_DELETION_STEPS.length-1);
  assert.deepEqual((await runtime.query('SELECT job_id,state,completed_at FROM identity.student_deletion_jobs WHERE job_id=$1',[outcome.jobId])).rows[0],receipt);
  assert.equal(await adapter.validateSession(sessions[owner.id].token),null);
  for(const sid of [live,retired]){let executed=false;assert.equal(await call('get',sid),null);await assert.rejects(call('set',sid,data(owner)));await assert.rejects(store.withAuthority(sid,{ownerId:owner.id,sessionId:sessions[owner.id].internalSessionId},async()=>{executed=true;}));assert.equal(executed,false);}
  assert.deepEqual((await runtime.query('SELECT * FROM identity.teaching_sessions WHERE owner_id=$1',[sibling.id])).rows,siblingBefore);
  assert.equal((await call('get',siblingSid)).userId,sibling.id);assert.equal((await adapter.validateSession(sessions[sibling.id].token)).user.id,sibling.id);
  for(const prior of tombstonesBefore)assert.deepEqual((await runtime.query('SELECT session_hash,expires_at FROM identity.teaching_sessions WHERE session_hash=$1',[prior.session_hash])).rows[0],prior);
  const retiredRows=(await runtime.query('SELECT revoked,payload,owner_id,platform_session_id FROM identity.teaching_sessions WHERE owner_id IS NULL')).rows;
  assert.equal(retiredRows.length,2);assert.ok(retiredRows.every(r=>r.revoked&&r.payload===null&&r.platform_session_id===null));
  if(process.env.WORKSHOP_RAG_EVIDENCE_PATH)fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH,JSON.stringify({status:'pass',scope:'Real canonical identity authentication/repository/application/worker/finalizer; controlled nonidentity adapters',liveAndRetiredDenied:true,lateSaveDenied:true,siblingUnchanged:true,completedReceiptReplay:true,identityCandidate:'0095'},null,2));
 }finally{await Promise.all(pools.map(p=>p.end()));fs.rmSync(dir,{recursive:true,force:true});}
});
