'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
test('candidate canonical persona regrade lifecycle with controlled held Judge',{skip:process.env.PERSONA_REVIEW_CANONICAL_NATIVE!=='1',timeout:90000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(commerce|fresh|review|identity|identityfresh)$/);const p=new Pool({connectionString:u.href,max:6,statement_timeout:8000});t.after(()=>p.end());return p;};
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION');const {migrate}=require('../../db/postgres/migrate');await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const dir=fs.mkdtempSync(path.join(process.cwd(),'canonical-candidate-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));for(const name of fs.readdirSync('db/postgres/workshop-migrations/secureshop_agents'))if(name.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/workshop-migrations/secureshop_agents',name),path.join(dir,name));fs.copyFileSync('docs/modernization/drafts/secureshop-user-administration/persona-state.candidate.sql',path.join(dir,'9999_persona_admin.sql'));await migrate(am,dir);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s),auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore;
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:auditFactory({store:'agents',pool:agents})});await personas.ensureTemplates();const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-canonical-review-native-only-secret'});
 const createOwner=async name=>{const passwordHash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:name,email:name+'@example.invalid',passwordHash}),token=randomUUID(),expiresAt=new Date(Date.now()+600000).toISOString(),session=await users.createSession({userId:user.id,token,expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),logged=await auth.login({scope,username:'student_customer',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:logged.token});return{user,token,scope,bearer:issued.bearer,personaToken:logged.token,persona:logged.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};





 await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
 // Explicit owned fixture configuration; supported curriculum defaults stay disabled.
 const objective='ss_loop_observation';
 assert.equal((await im.query("UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='secureshop_agent_security'")).rowCount,1);
 assert.equal((await im.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id=$1",[objective])).rowCount,1);
 const visibility=(await identity.query("SELECT w.is_visible,w.catalog_active AS exercise_active,o.is_enabled,o.catalog_active AS objective_active FROM workshop_platform.exercises w JOIN workshop_platform.objectives o USING(workshop_key) WHERE w.workshop_key='secureshop_agent_security' AND o.objective_id=$1",[objective])).rows[0];
 assert.deepEqual(visibility,{is_visible:true,exercise_active:true,is_enabled:true,objective_active:true});
 const o=await createOwner('judgment-owner');
 const write=async(c,evalId,runId,required)=>{await c.query(`INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,run_id,generation,mode,canonical_mode,mode_stamp,platform_launch_id,platform_scenario_id,platform_launch_generation${required===undefined?'':',persona_authority_required'}) VALUES($1,$2,'secureshop_agent_security',$3,'SecureShop','candidate','candidate-v1',$4,$5,0,'vuln','vuln','default',$6,$7,$8${required===undefined?'':',$9'})`,[o.user.id,evalId,objective,'a'.repeat(64),runId,o.scope.launchId,o.scope.scenarioId,o.scope.generation,...(required===undefined?[]:[required])]);await c.query("INSERT INTO workshop_platform.grade_packets(user_id,evaluation_id,packet,judge_version,mode_stamp) VALUES($1,$2,'{}','controlled-test','default')",[o.user.id,evalId]);};
 const oldId=randomUUID();await write(identity,oldId,randomUUID());
 const identityDir=fs.mkdtempSync(path.join(process.cwd(),'judgment-candidate-'));t.after(()=>fs.rmSync(identityDir,{recursive:true,force:true}));for(const name of fs.readdirSync('db/postgres/identity-migrations'))if(name.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/identity-migrations',name),path.join(identityDir,name));fs.copyFileSync('docs/modernization/drafts/secureshop-persona-judgments/persona-judgments.candidate.sql',path.join(identityDir,'9999_persona_judgments.sql'));assert.deepEqual(await migrate(im,identityDir),['9999_persona_judgments.sql']);assert.deepEqual(await migrate(im,identityDir),[]);const freshIdentity=pool('IDENTITYFRESH','MIGRATION');assert.ok((await migrate(freshIdentity,identityDir)).includes('9999_persona_judgments.sql'));assert.deepEqual(await migrate(freshIdentity,identityDir),[]);assert.equal((await freshIdentity.query('SELECT count(*)::int n FROM workshop_platform.persona_evaluation_bindings')).rows[0].n,0);
 assert.equal((await identity.query('SELECT persona_authority_required FROM workshop_platform.objective_judgments WHERE evaluation_id=$1',[oldId])).rows[0].persona_authority_required,false);
 const candidate=require('../../docs/modernization/drafts/secureshop-persona-judgments/repository.candidate').createPersonaJudgmentCandidate({pool:identity,personaAuthority:authority});
 const lifecycleEvidence={completed:[],races:[]};
 const saveLifecycleEvidence=()=>fs.writeFileSync(path.join(process.cwd(),'persona-judgment-lifecycle-result.json'),JSON.stringify(lifecycleEvidence,null,2)+'\n',{mode:0o600});
 t.after(saveLifecycleEvidence);
 const leases=pool('IDENTITY','RUNTIME');
 const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:leases});
 const {createRunCoordinator}=require('../../server/agent-runtime/runCoordinator');
 const family='SecureShop',coordinator=createRunCoordinator({family,ledger});
 const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identity,{personaBindings:candidate});
 const admins=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:agents,checkCurrent,auditStore:auditFactory({store:'agents',pool:agents})});
 const judgeModule=require('../../server/agent-runtime/objectiveJudge');
 const rubric={family:'SecureShop',scenario:'candidate',objectiveId:objective,version:'candidate-v1',mode:'vuln',requiredFacts:[],criteria:[{id:'proof',description:'Owned controlled evidence',allowedSources:['tool_result']}]};
 const prepared=judgeModule.prepareJudgeInput({rubric,evidence:[{id:'effect',source:'tool_result',content:'Owned controlled lifecycle effect'}],facts:{}});assert.equal(prepared.evidenceError,undefined);
 const seed=async owner=>coordinator.run(String(owner.user.id),{},async execution=>{
   const token=await candidate.capture({scope:owner.scope,personaId:owner.persona.id,sessionId:owner.personaSession.sessionId,role:owner.persona.role,authorityVersion:owner.personaSession.authorityVersion});
   const input={userId:owner.user.id,evaluationId:randomUUID(),workshopKey:'secureshop_agent_security',objectiveId:objective,family:'SecureShop',scenario:'candidate',rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest,runId:execution.runId,mode:'vuln',instanceScope:owner.scope,recovery:{packet:prepared.packet,judgeVersion:judgeModule.JUDGE_VERSION,ownerKey:execution.ownerKey,ownerGeneration:execution.durableGeneration}};
   await receipts.beginEvaluation(input,token);
   await receipts.recordVerdict({userId:owner.user.id,evaluationId:input.evaluationId,result:{family:'SecureShop',scenario:'candidate',objectiveId:objective,rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest,runId:execution.runId,mode:'vuln',verdict:'unavailable',criteria:[],explanation:'Controlled initial unavailable result',errorCode:'JUDGE_TRANSPORT'}});
   return input;
 });
 const deletion=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(identity,{steps:['revoke_runs','identity']});
 const administrator=await users.createUser({username:'lifecycle-platform-admin',email:'lifecycle-admin@example.invalid',passwordHash:await require('bcryptjs').hash('owned-only',4)});
 await im.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[administrator.id]);
 const prepareAdmin=async owner=>{const logged=await auth.login({scope:owner.scope,username:'student_admin',password:'student123'});return auth.authenticateBoundToken({scope:owner.scope,token:logged.token});};
 const transition=async(owner,kind,preparedAdmin)=>{
  if(kind==='role'){const admin=preparedAdmin??await prepareAdmin(owner);return admins.mutate({scope:owner.scope,actorId:admin.user.id,actorSessionId:admin.sessionId,targetId:owner.persona.id,operationId:randomUUID(),expectedVersion:'1',action:'set_role',role:'merchant'});}
  if(kind==='persona')return personas.revokeOwnedSession({scope:owner.scope,shopUserId:owner.persona.id,sessionId:owner.personaSession.sessionId});
  if(kind==='platform')return users.revokeSession(owner.token,owner.user.id,'owned lifecycle qualification');
  if(kind==='reset')return launches.beginReset({...owner.scope,expectedGeneration:owner.scope.generation,idempotencyKey:randomUUID()});
  if(kind==='deletion')return deletion.admit({requesterId:administrator.id,subjectId:owner.user.id});
 };
 const completionFactory=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService;
 const regradeFactory=require('../../server/services/objectiveRegradeService').createObjectiveRegradeService;
 const resultFor=input=>({family:input.family,scenario:input.scenario,objectiveId:objective,rubricVersion:rubric.version,evidenceDigest:prepared.evidenceDigest,runId:input.runId,mode:'vuln',verdict:'unavailable',criteria:[],explanation:'Controlled lifecycle Judge',errorCode:'JUDGE_TRANSPORT',provider:'mock',model:'controlled-lifecycle'});
 const makeRegrade=(store,judge)=>regradeFactory({receipts:store,completion:completionFactory({progress:{getGeneration:async()=>0},receipts:store,judge}),coordinatorFactory:()=>coordinator});
 for(const phase of ['before_judge','held_judge'])for(const kind of ['role','persona','platform','reset','deletion']){
  const owner=await createOwner('lifecycle-'+phase+'-'+kind),input=await seed(owner),entered=Promise.withResolvers(),gate=Promise.withResolvers();let calls=0;
  const retry=makeRegrade(receipts,async()=>{calls++;entered.resolve();await gate.promise;return {...resultFor(input),verdict:'pass',errorCode:null,criteria:[{id:'proof',satisfied:true,evidenceRefs:['effect']}]};});
  const expected=['role','persona'].includes(kind)?'SHOP_AUTH_INVALID':'STALE_LAUNCH';
  if(phase==='before_judge'){await transition(owner,kind);await assert.rejects(retry({userId:owner.user.id,evaluationId:input.evaluationId}),{code:expected});assert.equal(calls,0);}
  else {const pending=retry({userId:owner.user.id,evaluationId:input.evaluationId});pending.catch(()=>{});await Promise.race([entered.promise,pending.then(()=>{throw Error('Held Judge not entered');})]);
   // This real mutation completing before Judge release proves inference holds no agents authority lease.
   await transition(owner,kind);gate.resolve();await assert.rejects(pending,{code:expected});assert.equal(calls,1);
   const child=(await identity.query('SELECT j.* FROM workshop_platform.grade_packets p JOIN workshop_platform.objective_judgments j ON j.user_id=p.user_id AND j.evaluation_id=p.child_evaluation_id WHERE p.user_id=$1 AND p.evaluation_id=$2',[owner.user.id,input.evaluationId])).rows[0];assert.ok(child);assert.equal(child.verdict,null);
  }
  assert.equal((await receipts.listRecoverable({userId:owner.user.id,judgeVersion:judgeModule.JUDGE_VERSION})).some(r=>r.canRetry),false);
  lifecycleEvidence.completed.push({phase,kind,controlledJudgeCalls:calls});saveLifecycleEvidence();
 }
 const sibling=await createOwner('lifecycle-live-sibling'),live=await seed(sibling);let judgeCalls=0,lost=true;
 const lossy={...receipts,async recordVerdict(args){const committed=await receipts.recordVerdict(args);if(lost){lost=false;throw Object.assign(Error('Controlled postcommit acknowledgement loss'),{code:'OWNED_ACK_LOST'});}return committed;}};
 const retry=makeRegrade(lossy,async()=>{judgeCalls++;return resultFor(live);});
 await assert.rejects(retry({userId:sibling.user.id,evaluationId:live.evaluationId}),{code:'OWNED_ACK_LOST'});
 const immutable=(await identity.query('SELECT j.* FROM workshop_platform.grade_packets p JOIN workshop_platform.objective_judgments j ON j.user_id=p.user_id AND j.evaluation_id=p.child_evaluation_id WHERE p.user_id=$1 AND p.evaluation_id=$2',[sibling.user.id,live.evaluationId])).rows[0];assert.equal(immutable.verdict,'unavailable');
 const recovered=await retry({userId:sibling.user.id,evaluationId:live.evaluationId});assert.equal(recovered.replayed,true);assert.equal(recovered.receipt.evaluationId,immutable.evaluation_id);assert.equal(judgeCalls,1);
 assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.objective_judgments WHERE user_id=$1',[sibling.user.id])).rows[0].n,2);
 assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[sibling.user.id])).rows[0].n,0);
 lifecycleEvidence.completed.push({phase:'sibling_lost_ack_replay',controlledJudgeCalls:judgeCalls});saveLifecycleEvidence();
 // Controlled pass deliberately exercises the real contribution/progress transaction.
 // It is authority/concurrency evidence, never actual-model or learner-earned proof.
 for(const kind of ['role','reset','deletion']){
  const owner=await createOwner('commit-race-'+kind),input=await seed(owner),entered=Promise.withResolvers(),release=Promise.withResolvers();
  const preparedAdmin=kind==='role'?await prepareAdmin(owner):null;
  let hold=true;
  const heldPool={query:(...args)=>identity.query(...args),async connect(){const client=await identity.connect();return {release:()=>client.release(),async query(sql,...args){const result=await client.query(sql,...args);if(hold&&sql.includes('accept_secureshop_objective_contribution')){hold=false;entered.resolve();await release.promise;}return result;}};}};
  const bound=require('../../docs/modernization/drafts/secureshop-persona-judgments/repository.candidate').createPersonaJudgmentCandidate({pool:heldPool,personaAuthority:authority});
  const store=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(heldPool,{personaBindings:bound});
  const pass={...resultFor(input),verdict:'pass',errorCode:null,criteria:[{id:'proof',satisfied:true,evidenceRefs:['effect']}]};
  const grading=makeRegrade(store,async()=>pass)({userId:owner.user.id,evaluationId:input.evaluationId});grading.catch(()=>{});
  await Promise.race([entered.promise,grading.then(()=>{throw Error('Contribution hold not reached');})]);
  const changing=transition(owner,kind,preparedAdmin);changing.catch(()=>{});
  let blocked=false;const deadline=Date.now()+2000;
  const race={kind,waitingLocks:[],completed:false};lifecycleEvidence.races.push(race);saveLifecycleEvidence();
  while(Date.now()<deadline){
   // transactionid waits have no database OID; scope via the waiting backend.
   // datname/pid are public activity metadata; do not inspect private SQL text.
   const waiting=(await im.query("SELECT l.locktype,l.mode,l.granted FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname IN (current_database(),$1) AND NOT l.granted AND l.pid<>pg_backend_pid()",[new URL(process.env.PERSONA_FRESH_RUNTIME_URL).pathname.slice(1)])).rows;
   if(waiting.length){race.waitingLocks=waiting;blocked=true;saveLifecycleEvidence();break;}
   await new Promise(r=>setTimeout(r,10));
  }
  release.resolve();await changing;await grading.catch(error=>{const expected=kind==='role'?'SHOP_AUTH_INVALID':'STALE_LAUNCH';assert.ok(error.code===expected||(error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&error.executionBoundary===true&&error.cause?.code===expected));});
  assert.equal(blocked,true,`Actual ${kind} lifecycle SQL waits on the bounded commit authority locks`);
  const child=(await identity.query('SELECT j.* FROM workshop_platform.grade_packets p JOIN workshop_platform.objective_judgments j ON j.user_id=p.user_id AND j.evaluation_id=p.child_evaluation_id WHERE p.user_id=$1 AND p.evaluation_id=$2',[owner.user.id,input.evaluationId])).rows[0];
  assert.equal(child.verdict,'pass');assert.equal(child.disposition,'awarded');
  assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.objective_contributions WHERE user_id=$1 AND evaluation_id=$2',[owner.user.id,child.evaluation_id])).rows[0].n,1);
  await assert.rejects(store.assertRecoveryAuthority({userId:owner.user.id,evaluationId:child.evaluation_id}),{code:kind==='role'?'SHOP_AUTH_INVALID':'STALE_LAUNCH'});
  race.completed=true;saveLifecycleEvidence();
 }
 t.diagnostic('Canonical ledger/regrade/completion with controlled unavailable Judge, actual role/session/reset/deletion admission, no fabricated credit. Controlled pass exercises contribution/progress commit against concurrent role/reset/deletion admission. Full deletion finalizer remains a separate gate.');
});
