'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID,randomBytes}=require('node:crypto'),{Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
(async()=>{
 assert.equal(process.env.MAIL_NATIVE,'1');const pools=[];
 const pool=(label,role)=>{const u=new URL(process.env[`MAIL_${label}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_mail_[a-f0-9]+_/);const p=new Pool({connectionString:u.href,max:4,statement_timeout:10000});pools.push(p);return p;};
 try{
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('AGENTS','RUNTIME'),am=pool('AGENTS','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION'),lease=pool('IDENTITY','RUNTIME');
 await migrate(im,'db/postgres/identity-migrations');await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 await migrate(am,'db/postgres/workshop-migrations/secureshop_agents');await migrate(rm,'db/postgres/workshop-migrations/secureshop_review');
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const templates=await personas.listPersonas(),auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:randomBytes(32).toString('hex')});
 const cleanupAuthority=require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identity);
 const bundle=require('../../server/services/secureshopPersonaInboxComposition').createSecureShopPersonaInboxRepositoryBundle({agentsPool:agents,launches,cleanupAuthority});
 const fixtures=require('../../server/services/secureshopPersonaInboxComposition').mapPersonaInboxFixtures(templates);
 async function owner(){const key=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:'mail-'+key.slice(0,8),email:key+'@example.invalid',passwordHash});const expiresAt=new Date(Date.now()+600000).toISOString();const session=await users.createSession({userId:user.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);const login=await auth.login({scope,username:'student_merchant',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});const target=await launches.reservePersonaInboxTarget({...scope,expectedGeneration:scope.generation});await bundle.repository.provision({...scope,targetId:target.targetId},{fixtures,mode:'advisory'});return {scope,targetId:target.targetId,persona:{id:login.user.id,role:'merchant'},personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion},mode:'vuln',operationId:randomUUID()};}
 const {createBoundMailRepository,prepareSend}=require('../../server/database/postgres/secureshopBoundMailRepository');
 const mail=createBoundMailRepository({pool:agents,personaAuthority:authority,checkCleanup:input=>cleanupAuthority.checkTarget({...input,targetKind:'persona_inbox',fromGeneration:input.generation})});
 const lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,reviewPool:review,leasePool:lease,launches,cleanupAuthority});
 const merchant=templates.find(t=>t.role==='merchant'),customer=templates.find(t=>t.role==='customer'),message={from:merchant.email,to:customer.email,subject:'Owned lifecycle',body_markdown:'<b>owned source</b>'};
 const direct=async(b,payload)=>{const s=b.scope;return agents.query('SELECT secureshop_agents.bound_lab_mail($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb) AS result',[b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,b.persona.id,b.personaSession.sessionId,b.persona.role,b.personaSession.authorityVersion,b.mode,b.operationId,'send',JSON.stringify(payload)]);};
 const snapshot=async b=>({messages:(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[b.targetId])).rows,operations:(await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[b.targetId])).rows,fixtures:await bundle.repository.list({...b.scope,targetId:b.targetId})});
 const sibling=await owner();await mail.send(sibling,message);const siblingBefore=await snapshot(sibling);
 // Actual credential lifecycle invalidates the original direct-SQL binding.
 const credential=await owner();await mail.send(credential,message);const credentialBefore=await snapshot(credential);
 const passwordActor=await auth.login({scope:credential.scope,username:'student_merchant',password:'student123'}),passwordSession=await auth.authenticateBoundToken({scope:credential.scope,token:passwordActor.token});
 await auth.changePassword({scope:credential.scope,shopPersona:credential.persona,currentSessionId:passwordSession.sessionId,currentPassword:'student123',newPassword:'Owned-mail-new-password-2026'});
 await assert.rejects(direct({...credential,operationId:randomUUID()},prepareSend(message)));assert.deepEqual(await snapshot(credential),credentialBefore);
 const relogin=await auth.login({scope:credential.scope,username:'student_merchant',password:'Owned-mail-new-password-2026'});const authenticated=await auth.authenticateBoundToken({scope:credential.scope,token:relogin.token});
 const renewed={...credential,operationId:randomUUID(),personaSession:{sessionId:authenticated.sessionId,authorityVersion:authenticated.authorityVersion}};await mail.send(renewed,message);
 await assert.rejects(direct({...renewed,operationId:randomUUID(),personaSession:{...renewed.personaSession,authorityVersion:String(Number(renewed.personaSession.authorityVersion)+1)}},prepareSend(message)));
 const administration=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:agents,checkCurrent,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});
 for(const action of ['set_role','ban']){
  const subject=await owner();await mail.send(subject,message);const before=await snapshot(subject);
  const administrator=await auth.login({scope:subject.scope,username:'student_admin',password:'student123'}),adminSession=await auth.authenticateBoundToken({scope:subject.scope,token:administrator.token});
  await administration.mutate({scope:subject.scope,actorId:administrator.user.id,actorSessionId:adminSession.sessionId,targetId:subject.persona.id,operationId:randomUUID(),expectedVersion:subject.personaSession.authorityVersion,action,...(action==='set_role'?{role:'customer'}:{reason:'Owned mail qualification'})});
  await assert.rejects(direct({...subject,operationId:randomUUID()},prepareSend(message)));assert.deepEqual(await snapshot(subject),before);
 }
 // Fail the actual mail deletion trigger: original target receipt and deletion
 // roll back together, then canonical aggregate recovery resumes unchanged ID.
 const fault=await owner();await mail.send(fault,message);const faultBefore=await snapshot(fault);
 await am.query(`CREATE FUNCTION secureshop_agents.mail_test_cleanup_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.target_id='${fault.targetId}'::uuid THEN RAISE EXCEPTION 'owned mail cleanup fault'; END IF; RETURN OLD; END $$; REVOKE ALL ON FUNCTION secureshop_agents.mail_test_cleanup_failure() FROM PUBLIC; CREATE TRIGGER mail_test_cleanup_failure BEFORE DELETE ON secureshop_agents.lab_mail_messages FOR EACH ROW EXECUTE FUNCTION secureshop_agents.mail_test_cleanup_failure()`);
 const faultOperation=randomUUID();let faultReset;
 try{await assert.rejects(lifecycle.launchResetCoordinator.reset({...fault.scope,expectedGeneration:1,idempotencyKey:faultOperation}),/owned mail cleanup fault/);faultReset=(await launches.beginReset({...fault.scope,expectedGeneration:1,idempotencyKey:faultOperation})).resetId;
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.persona_inbox_cleanup_receipts WHERE operation_id=$1',[faultReset])).rows[0].n,0);
 assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[fault.targetId])).rows,faultBefore.messages);
 }finally{await am.query('DROP TRIGGER mail_test_cleanup_failure ON secureshop_agents.lab_mail_messages; DROP FUNCTION secureshop_agents.mail_test_cleanup_failure()');}
 const recovered=await lifecycle.launchResetCoordinator.recover(faultReset);assert.equal(recovered.resolved,true);assert.equal((await am.query('SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[fault.targetId])).rows[0].n,0);
 // Deterministic barrier inside actual SQL publication. Blocking PIDs, not time
 // elapsed, prove the owner lock order. Finally always releases and settles both.
 const racing=await owner(),barrier=await am.connect(),lockKey='813790421';let sending,resetting,sendOutcome,resetOutcome,blocking;
 await am.query(`CREATE FUNCTION secureshop_agents.mail_test_publication_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.target_id='${racing.targetId}'::uuid THEN PERFORM pg_advisory_xact_lock(${lockKey}::bigint); END IF; RETURN NEW; END $$; REVOKE ALL ON FUNCTION secureshop_agents.mail_test_publication_barrier() FROM PUBLIC; CREATE TRIGGER mail_test_publication_barrier BEFORE INSERT ON secureshop_agents.lab_mail_messages FOR EACH ROW EXECUTE FUNCTION secureshop_agents.mail_test_publication_barrier()`);
 async function blockedBy(pid){const deadline=Date.now()+1800;while(Date.now()<deadline){const rows=(await am.query('SELECT pid,datname,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))',[pid])).rows;if(rows.length)return rows;await new Promise(resolve=>setImmediate(resolve));}throw Error('Expected SQL lock edge absent');}
 const settle=p=>p.then(value=>({status:'fulfilled',value}),error=>({status:'rejected',code:error.code,message:error.message}));
 try{
  await barrier.query('SELECT pg_advisory_lock($1::bigint)',[lockKey]);const holder=(await barrier.query('SELECT pg_backend_pid() pid')).rows[0].pid;
  sending=settle(mail.send(racing,message));const publication=(await blockedBy(holder))[0];
  resetting=settle(lifecycle.launchResetCoordinator.reset({...racing.scope,expectedGeneration:1,idempotencyKey:randomUUID()}));const resetWait=await blockedBy(publication.pid);blocking={holder,publication,resetWait};
 }finally{
  try{await barrier.query('SELECT pg_advisory_unlock($1::bigint)',[lockKey]);}finally{barrier.release();}
  [sendOutcome,resetOutcome]=await Promise.all([sending,resetting]);await am.query('DROP TRIGGER mail_test_publication_barrier ON secureshop_agents.lab_mail_messages; DROP FUNCTION secureshop_agents.mail_test_publication_barrier()');
 }
 assert.equal(sendOutcome?.status,'rejected','Post-commit current-authority fence must reject a send racing an admitted reset');
 assert.equal(resetOutcome?.status,'fulfilled',JSON.stringify(resetOutcome));assert.equal((await am.query('SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[racing.targetId])).rows[0].n,0);await assert.rejects(mail.recover(racing));
 const raceEvidence=(await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1',[racing.targetId])).rows;assert.equal(raceEvidence.length,1);
 assert.equal((await lifecycle.personaInbox.repository.readCleanupReceipt({...racing.scope,targetId:racing.targetId},{operationId:resetOutcome.value.resetId})).operationId,resetOutcome.value.resetId);
 // Actual student deletion admission and aggregate SecureShop cleanup stage.
 // The unrelated application-store deletion stages are not claimed here.
 const deleted=await owner();await mail.send(deleted,message);const deleteBefore=await snapshot(deleted),admin=await users.createUser({username:'mail-admin-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash('owned',4),role:'admin',adminLevel:2});
 await im.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.id]); // Owned fixture instructor, not a platform mutation endpoint.
 const deletion=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(identity,{steps:['revoke_runs','secureshop','identity']});
 const admitted=await deletion.admit({requesterId:admin.id,subjectId:deleted.scope.platformOwnerId}),claim=await deletion.claim(admitted.jobId,120000);
 const deletionInput={jobId:admitted.jobId,subjectId:deleted.scope.platformOwnerId,leaseToken:claim.leaseToken,check:async()=>{await deletion.listSecureShopResetIds({jobId:admitted.jobId,subjectId:deleted.scope.platformOwnerId,leaseToken:claim.leaseToken});}};
 const cleanup=lifecycle.createStudentDeletionCleanup(deletion),deletedResult=await cleanup(deletionInput);assert.equal(deletedResult.completed,true);assert.deepEqual(await cleanup(deletionInput),deletedResult);
 assert.equal((await am.query('SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[deleted.targetId])).rows[0].n,0);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[deleted.targetId])).rows,deleteBefore.operations);await assert.rejects(direct({...deleted,operationId:randomUUID()},prepareSend(message)));
 assert.deepEqual(await snapshot(sibling),siblingBefore);
 fs.writeFileSync(process.env.MAIL_RESULT,JSON.stringify({status:'passed',credentialChangeRejectsOldSession:true,wrongAuthorityVersionRejected:true,canonicalRoleBanRejectOldBindings:true,cleanupFailureRollsBackOriginalReceipt:true,canonicalRecovery:true,publicationReset:{blocking,sendOutcome,resetOutcome,retainedReceipts:raceEvidence.length},studentDeletionSecureShopStage:deletedResult,deletionReplay:true,immutableEvidencePreserved:true,siblingUnchanged:true,limitations:['No actor/model/browser/Judge','Student deletion SecureShop stage only, not all application-store deletion stages']},null,2));
 }finally{await Promise.all(pools.map(p=>p.end()));}
})().catch(error=>{console.error(error);process.exitCode=1;});
