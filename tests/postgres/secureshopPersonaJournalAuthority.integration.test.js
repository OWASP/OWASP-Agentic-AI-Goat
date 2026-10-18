'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomUUID}=require('node:crypto'),{Pool}=require('pg');

test('persona authority and turn completion have one PostgreSQL linearization boundary',{skip:process.env.PERSONA_REVIEW_CANONICAL_NATIVE!=='1',timeout:90000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
 const url=new URL(process.env.PERSONA_FRESH_RUNTIME_URL);assert.equal(url.hostname,'127.0.0.1');
 assert.match(url.pathname,/^\/dvaia_test_persona_[a-f0-9]+_fresh$/);
 const pool=(store,role,max=4)=>{const value=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(value.hostname,'127.0.0.1');assert.match(value.pathname,/^\/dvaia_test_persona_[a-f0-9]+_(identity|fresh|commerce)$/);const p=new Pool({connectionString:value.href,max,statement_timeout:8000});t.after(()=>p.end());return p;};
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME',8),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION');
 const waiterUrl=new URL(process.env.PERSONA_FRESH_RUNTIME_URL);waiterUrl.searchParams.set('application_name','persona_journal_revoke_waiter');
 const waiterPool=new Pool({connectionString:waiterUrl.href,max:2,statement_timeout:8000});t.after(()=>waiterPool.end());
 const {migrate}=require('../../db/postgres/migrate');await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const candidateDir=fs.mkdtempSync(path.join(process.cwd(),'journal-persona-candidate-'));t.after(()=>fs.rmSync(candidateDir,{recursive:true,force:true}));
 for(const name of fs.readdirSync('db/postgres/workshop-migrations/secureshop_agents'))if(name.endsWith('.sql'))fs.copyFileSync(path.join('db/postgres/workshop-migrations/secureshop_agents',name),path.join(candidateDir,name));
 fs.copyFileSync('docs/modernization/drafts/secureshop-user-administration/persona-state.candidate.sql',path.join(candidateDir,'9999_persona_admin.sql'));await migrate(am,candidateDir);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=scope=>launches.assertCurrent(scope);
 const auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore;
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});
 const personaOptions={commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:auditFactory({store:'agents',pool:agents})};
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository(personaOptions);await personas.ensureTemplates();
 const revoker=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({...personaOptions,agentsPool:waiterPool,auditStore:auditFactory({store:'agents',pool:waiterPool})});
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-journal-authority-only-secret'});
 const conversationRows=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
 const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({conversations:conversationRows,launches});
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const owner=async name=>{const passwordHash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:name,email:name+'@example.invalid',passwordHash}),token=randomUUID(),expiresAt=new Date(Date.now()+600000).toISOString(),session=await users.createSession({userId:user.id,token,expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),logged=await auth.login({scope,username:'student_customer',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:logged.token});return{user,token,scope,personaToken:logged.token,persona:logged.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};
 const admitted=async(label)=>{const value=await owner(label),session=await conversations.create(value.scope,value.persona,'general'),binding={...value.scope,shopUserId:value.persona.id,role:value.persona.role},requestId=randomUUID(),message='Owned journal publication';const claim=await journal.claim({sessionId:session.id,requestId,binding,message}),fence=authority.capture({scope:value.scope,personaId:value.persona.id,sessionId:value.personaSession.sessionId,role:value.persona.role,authorityVersion:value.personaSession.authorityVersion});return{...value,sessionId:session.id,binding,requestId,message,claim,fence};};
 const row=async value=>(await agents.query('SELECT status,result_json,finished_at FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[value.sessionId,value.requestId])).rows[0];
 const completeInput=(value,result)=>({sessionId:value.sessionId,requestId:value.requestId,binding:value.binding,claimId:value.claim.claimId,result});

 const revokedFirst=await admitted('journal-revoke-first');
 assert.equal(await revoker.revokeOwnedSession({scope:revokedFirst.scope,shopUserId:revokedFirst.persona.id,sessionId:revokedFirst.personaSession.sessionId}),true);
 await assert.rejects(journal.complete(completeInput(revokedFirst,{case:'revoked-first'}),revokedFirst.fence),{code:'SHOP_AUTH_INVALID'});
 assert.deepEqual(await row(revokedFirst),{status:'started',result_json:null,finished_at:null});

 const completedFirst=await admitted('journal-complete-first'),entered=Promise.withResolvers(),release=Promise.withResolvers();let completionSettled=false,revocationSettled=false;
 const holdingFence=Object.freeze({binding:completedFirst.fence.binding,withPersonaEffect(work){return completedFirst.fence.withPersonaEffect(async(client,binding)=>{const original=client.query.bind(client);client.query=async(sql,args)=>{const result=await original(sql,args);if(typeof sql==='string'&&sql.includes("SET status='completed'")){entered.resolve();await release.promise;}return result;};try{return await work(client,binding);}finally{client.query=original;}});}});
 const completion=journal.complete(completeInput(completedFirst,{case:'completed-first'}),holdingFence).finally(()=>{completionSettled=true;});completion.catch(()=>{});
 await Promise.race([entered.promise,completion.then(()=>{throw Error('Completion missed hold');})]);
 const revocation=revoker.revokeOwnedSession({scope:completedFirst.scope,shopUserId:completedFirst.persona.id,sessionId:completedFirst.personaSession.sessionId}).finally(()=>{revocationSettled=true;});revocation.catch(()=>{});
 try{
  let waiting;
  for(let attempt=0;attempt<40;attempt++){
   waiting=(await agents.query(`SELECT a.pid,a.wait_event_type,a.wait_event,
    count(l.pid) FILTER (WHERE l.granted=false)::integer AS ungranted
    FROM pg_stat_activity a LEFT JOIN pg_locks l ON l.pid=a.pid
    LEFT JOIN pg_database d ON l.database=d.oid
    WHERE a.datname=current_database() AND a.application_name='persona_journal_revoke_waiter'
    GROUP BY a.pid,a.wait_event_type,a.wait_event`)).rows.find(value=>value.wait_event_type==='Lock'&&value.ungranted>0);
   if(waiting)break;await new Promise(resolve=>setTimeout(resolve,25));
  }
  assert.ok(waiting,'revocation must be observed waiting on an actual PostgreSQL lock');assert.equal(completionSettled,false);assert.equal(revocationSettled,false);
 }finally{release.resolve();await Promise.allSettled([completion,revocation]);}
 const [completionOutcome,revocationOutcome]=await Promise.allSettled([completion,revocation]);
 assert.equal(completionOutcome.status,'fulfilled');assert.equal(revocationOutcome.status,'fulfilled');assert.equal(revocationOutcome.value,true);
 const completedRow=await row(completedFirst);assert.equal(completedRow.status,'completed');assert.deepEqual(completedRow.result_json,{case:'completed-first'});assert.ok(completedRow.finished_at);
 await assert.rejects(completedFirst.fence.assertRemoteAdmission(),{code:'SHOP_AUTH_INVALID'});await assert.rejects(auth.authenticateBoundToken({scope:completedFirst.scope,token:completedFirst.personaToken}));
 assert.deepEqual((await journal.claim({sessionId:completedFirst.sessionId,requestId:completedFirst.requestId,binding:completedFirst.binding,message:completedFirst.message})).result,{case:'completed-first'});

 const sibling=await admitted('journal-sibling'),siblingBefore=await row(sibling);
 await assert.rejects(journal.complete(completeInput(sibling,{case:'wrong-fence'}),completedFirst.fence),{code:'SHOP_AUTH_INVALID'});assert.deepEqual(await row(sibling),siblingBefore);
 await journal.complete(completeInput(sibling,{case:'sibling'}),sibling.fence);assert.equal((await row(sibling)).status,'completed');
 const legacy=await admitted('journal-default');await journal.complete(completeInput(legacy,{case:'legacy-default'}));assert.deepEqual((await row(legacy)).result_json,{case:'legacy-default'});
 // Readonly review and SSRF target resolution uses the real identity runtime repository.
 const reads=[];
 const readonlyLaunches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository({
  async query(sql,values){reads.push(sql);assert.match(sql.trim(),/^SELECT\b/);return identity.query(sql,values);},
  async connect(){throw Error('Readonly resolver must not acquire a write transaction');},
 });
 const snapshot=async()=>({
  reservations:(await identity.query('SELECT * FROM identity.secureshop_target_reservations ORDER BY target_id')).rows,
  launches:(await identity.query('SELECT * FROM identity.secureshop_launches ORDER BY launch_id')).rows,
 });
 let readCases=0;const ssrfTargets=new Map();
 const verifyRead=async(scope,expected)=>{const before=await snapshot(),count=reads.length;
  if(expected)assert.equal((await readonlyLaunches.readExistingReviewsTarget(scope)).targetId,expected);
  else await assert.rejects(readonlyLaunches.readExistingReviewsTarget(scope),{code:'REVIEW_TARGET_UNAVAILABLE'});
  assert.equal(reads.length,count+1);assert.deepEqual(await snapshot(),before);readCases++;
  const ssrfExpected=expected?ssrfTargets.get(scope.launchId):null;
  if(ssrfExpected){const found=await readonlyLaunches.readExistingSsrfTarget(scope);assert.equal(found.targetId,ssrfExpected);assert.equal(found.kind,'controlled_ssrf');}
  else await assert.rejects(readonlyLaunches.readExistingSsrfTarget(scope),{code:'SSRF_TARGET_UNAVAILABLE'});
  assert.equal(reads.length,count+2);assert.deepEqual(await snapshot(),before);readCases++;
 };
 await verifyRead(sibling.scope,null); // Missing target never provisions one.
 const target=await launches.reserveReviewsTarget({...sibling.scope,expectedGeneration:sibling.scope.generation});
 const siblingTarget=await launches.reserveReviewsTarget({...legacy.scope,expectedGeneration:legacy.scope.generation});
 await verifyRead(sibling.scope,target.targetId); // Review reservation must not satisfy SSRF lookup.
 for(const owner of [sibling,legacy]){const reserved=await launches.reserveSsrfTarget({...owner.scope,expectedGeneration:owner.scope.generation});ssrfTargets.set(owner.scope.launchId,reserved.targetId);}
 await verifyRead(sibling.scope,target.targetId);
 for(const altered of [
  {...sibling.scope,platformOwnerId:legacy.user.id},
  {...sibling.scope,platformSessionId:legacy.scope.platformSessionId},
  {...sibling.scope,scenarioId:randomUUID()},
  {...sibling.scope,generation:sibling.scope.generation+1},
 ])await verifyRead(altered,null);
 let forbiddenEffects=0;const forbidden=()=>{forbiddenEffects++;throw Error('Readonly lookup attempted reserve/provision/effect');};
 const readonlyApplication=require('../../server/services/secureshopBoundReviewApplication').createSecureShopBoundReviewApplication({
  launches:{readExistingReviewsTarget:readonlyLaunches.readExistingReviewsTarget,reserveReviewsTarget:forbidden},
  repository:Object.fromEntries(['provision','listReviews','listPending','submitReview','decide'].map(name=>[name,forbidden])),checkCurrent,
 });
 const appBefore=await snapshot();assert.deepEqual(await readonlyApplication.resolveExistingTarget(sibling.scope),{targetId:target.targetId,...sibling.scope});assert.equal(forbiddenEffects,0);assert.deepEqual(await snapshot(),appBefore);
 const expiry=(await identity.query('SELECT expires_at FROM identity.secureshop_launches WHERE launch_id=$1',[sibling.scope.launchId])).rows[0];
 try{await im.query("UPDATE identity.secureshop_launches SET expires_at=created_at+interval '1 microsecond' WHERE launch_id=$1",[sibling.scope.launchId]);await verifyRead(sibling.scope,null);await verifyRead(legacy.scope,siblingTarget.targetId);}
 finally{await im.query('UPDATE identity.secureshop_launches SET expires_at=$2 WHERE launch_id=$1',[sibling.scope.launchId,expiry.expires_at]);}
 try{await im.query("UPDATE identity.users SET account_locked_until=clock_timestamp()+interval '1 minute' WHERE id=$1",[sibling.user.id]);await verifyRead(sibling.scope,null);await verifyRead(legacy.scope,siblingTarget.targetId);}
 finally{await im.query('UPDATE identity.users SET account_locked_until=NULL WHERE id=$1',[sibling.user.id]);}
 await launches.beginReset({...sibling.scope,expectedGeneration:sibling.scope.generation,idempotencyKey:randomUUID()});
 await verifyRead(sibling.scope,null);await verifyRead(legacy.scope,siblingTarget.targetId);
 const deniedBefore=await snapshot();await assert.rejects(readonlyApplication.resolveExistingTarget(sibling.scope));assert.equal(forbiddenEffects,0);assert.deepEqual(await snapshot(),deniedBefore);
 t.diagnostic(`Readonly review/SSRF target resolvers: ${readCases} real SELECT-only cases; missing/current/foreign/session/scenario/generation/expired/locked/reset and sibling, unchanged reservations/launch snapshots; application reserve/provision/effect calls zero.`);
 // Real artifact SQL publication versus real persona revocation; no model/effect completion claim.
 const spoolRoot=fs.mkdtempSync(path.join(process.cwd(),'audit-publication-native-'));t.after(()=>fs.rmSync(spoolRoot,{recursive:true,force:true}));
 const publicationRepository=require('../../server/database/postgres/secureshopAuditRunRepository').createSecureShopAuditRunRepository({pool:agents,checkCurrent});
 const adminOwner=async name=>{const value=await owner(name),logged=await auth.login({scope:value.scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope:value.scope,token:logged.token});return{...value,persona:logged.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};
 const artifactInput=async value=>{const runId=randomUUID(),spool=await require('../../server/services/secureshopAuditObservationSpool').spoolAuditObservation({root:spoolRoot,scope:value.scope,runId,requestedCount:1,checkCurrent,rows:(async function*(){})()});t.after(()=>spool.dispose());
  const artifacts=await require('../../server/agent-runtime/workers/secureshopAuditWorker').writeArtifacts(spool.directory,{messages:[{text:'Owned synthetic storage bytes'}],traces:[],effects:[]});
  const fence=authority.capture({scope:value.scope,personaId:value.persona.id,sessionId:value.personaSession.sessionId,role:value.persona.role,authorityVersion:value.personaSession.authorityVersion});
  return{fence,input:{scope:value.scope,persona:value.persona,requestId:randomUUID(),execution:{runId,ownerKey:'owned-audit-publication:'+value.user.id,durableGeneration:1},effectKey:'storage-only',spool,result:{runId,provider:'ollama',model:'controlled-storage-fixture',summary:'Storage-only controlled artifact fixture; no model execution',logSha256:spool.manifest.logSha256,sourcesSha256:spool.manifest.sourcesSha256,rowCount:0,objectiveCredit:false,artifacts}}};
 };
 const storedArtifacts=async runId=>{const output={};for(const [key,table,order] of [['runs','bound_audit_runs','run_id'],['artifacts','bound_audit_run_artifacts','artifact'],['chunks','bound_audit_run_chunks','artifact,ordinal'],['publications','bound_audit_run_publications','run_id']])output[key]=(await agents.query(`SELECT * FROM secureshop_agents.${table} WHERE run_id=$1 ORDER BY ${order}`,[runId])).rows;return output;};
 const absentArtifacts=async runId=>{for(const rows of Object.values(await storedArtifacts(runId)))assert.equal(rows.length,0);};
 const revokeAdmin=value=>revoker.revokeOwnedSession({scope:value.scope,shopUserId:value.persona.id,sessionId:value.personaSession.sessionId});
 const deniedAdmin=await adminOwner('audit-revoke-first'),deniedArtifact=await artifactInput(deniedAdmin);
 await revokeAdmin(deniedAdmin);await assert.rejects(publicationRepository.publish(deniedArtifact.input,deniedArtifact.fence),{code:'SHOP_AUTH_INVALID'});await absentArtifacts(deniedArtifact.input.execution.runId);
 const firstAdmin=await adminOwner('audit-publish-first'),firstArtifact=await artifactInput(firstAdmin),enteredPublication=Promise.withResolvers(),releasePublication=Promise.withResolvers();
 let publishSettled=false,revokeSettled=false;
 const publicationFence=Object.freeze({binding:firstArtifact.fence.binding,withPersonaEffect(work){return firstArtifact.fence.withPersonaEffect(async(client,binding)=>{const original=client.query.bind(client);client.query=async(sql,args)=>{const value=await original(sql,args);if(typeof sql==='string'&&sql.startsWith('INSERT INTO secureshop_agents.bound_audit_run_publications')){enteredPublication.resolve();await releasePublication.promise;}return value;};try{return await work(client,binding);}finally{client.query=original;}});}});
 const publishing=publicationRepository.publish(firstArtifact.input,publicationFence).finally(()=>{publishSettled=true;});publishing.catch(()=>{});let revoking,publicationWaitTimer;
 try{
  await Promise.race([enteredPublication.promise,publishing.then(()=>{throw Error('Publication did not reach commit hold');}),new Promise((_,reject)=>{publicationWaitTimer=setTimeout(()=>reject(Error('Publication hold deadline exceeded')),5000);})]);clearTimeout(publicationWaitTimer);
  revoking=revokeAdmin(firstAdmin).finally(()=>{revokeSettled=true;});revoking.catch(()=>{});
  let blocked=false;for(let attempt=0;attempt<40;attempt++){blocked=(await agents.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() AND a.application_name='persona_journal_revoke_waiter' AND a.wait_event_type='Lock' AND NOT l.granted) AS blocked")).rows[0].blocked;if(blocked)break;await new Promise(resolve=>setTimeout(resolve,25));}
  assert.equal(blocked,true,'actual revocation must wait on publication transaction lock');assert.equal(publishSettled,false);assert.equal(revokeSettled,false);
 }finally{clearTimeout(publicationWaitTimer);releasePublication.resolve();await Promise.allSettled([publishing,...(revoking?[revoking]:[])]);}
 const published=await publishing;assert.equal(published.published,true);assert.equal(published.objectiveCredit,false);assert.equal(await revoking,true);await assert.rejects(firstArtifact.fence.assertRemoteAdmission(),{code:'SHOP_AUTH_INVALID'});
 const firstStored=await storedArtifacts(firstArtifact.input.execution.runId);assert.equal(firstStored.runs.length,1);assert.equal(firstStored.artifacts.length,5);assert.equal(firstStored.publications.length,1);
 for(const manifest of firstStored.artifacts){const chunks=firstStored.chunks.filter(c=>c.artifact===manifest.artifact),bytes=Buffer.concat(chunks.map(c=>c.content));assert.equal(bytes.length,Number(manifest.bytes));assert.deepEqual(require('node:crypto').createHash('sha256').update(bytes).digest(),manifest.sha256);}
 const siblingAdmin=await adminOwner('audit-publication-sibling'),siblingArtifact=await artifactInput(siblingAdmin);
 await assert.rejects(publicationRepository.publish(siblingArtifact.input,firstArtifact.fence),{code:'SHOP_AUTH_INVALID'});await absentArtifacts(siblingArtifact.input.execution.runId);
 assert.equal((await publicationRepository.publish(siblingArtifact.input,siblingArtifact.fence)).published,true);const siblingStored=await storedArtifacts(siblingArtifact.input.execution.runId);
 const rollbackArtifact=await artifactInput(siblingAdmin);let chunkInserted=false;
 const rollbackFence={binding:rollbackArtifact.fence.binding,withPersonaEffect(work){return rollbackArtifact.fence.withPersonaEffect(async(client,binding)=>{const original=client.query.bind(client);client.query=async(sql,args)=>{const result=await original(sql,args);if(typeof sql==='string'&&sql.startsWith('INSERT INTO secureshop_agents.bound_audit_run_chunks')){chunkInserted=true;throw Error('owned publication interruption');}return result;};try{return await work(client,binding);}finally{client.query=original;}});}};
 await assert.rejects(publicationRepository.publish(rollbackArtifact.input,rollbackFence),/owned publication interruption/);assert.equal(chunkInserted,true);await absentArtifacts(rollbackArtifact.input.execution.runId);
 await assert.rejects(agents.query("UPDATE secureshop_agents.bound_audit_runs SET summary='changed' WHERE run_id=$1",[firstArtifact.input.execution.runId]),{code:'42501'});
 await assert.rejects(agents.query('DELETE FROM secureshop_agents.bound_audit_run_chunks WHERE run_id=$1',[firstArtifact.input.execution.runId]),{code:'42501'});
 assert.deepEqual(await storedArtifacts(firstArtifact.input.execution.runId),firstStored);assert.deepEqual(await storedArtifacts(siblingArtifact.input.execution.runId),siblingStored);
 for(const value of [deniedArtifact,firstArtifact,siblingArtifact,rollbackArtifact])await value.input.spool.dispose();assert.deepEqual(fs.readdirSync(spoolRoot),[]);
 t.diagnostic('Audit candidate publication: real admin persona/revoke, observed SQL lock ordering, real hashed files, rollback and immutable sibling storage readback. Required ollama DTO label uses controlled-storage-fixture; no actual model, completed ledger effect, production reader or credit claim.');
 t.diagnostic('Real PostgreSQL authority/journal same-client linearization; controlled data only, no MCP provider, model, Judge, credit, activation, or installed-store writes.');
});
