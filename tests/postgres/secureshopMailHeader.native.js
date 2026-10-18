'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID,randomBytes}=require('node:crypto'),{Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
(async()=>{
 assert.equal(process.env.MAIL_NATIVE,'1');const pools=[];
 const pool=(label,role)=>{const u=new URL(process.env[`MAIL_${label}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_mail_[a-f0-9]+_/);const p=new Pool({connectionString:u.href,max:4,statement_timeout:10000});pools.push(p);return p;};
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
 if(process.env.MAIL_REPLY_AUTHORITY_ACTUAL==='1'){await require('./secureshopMailReplyAuthorityActual.cohort').runReplyAuthorityActual({identity,im,agents,am,review,owner,mail,auth,templates,authority,launches,lifecycle});return;}
 if(process.env.MAIL_REPLY_AUTHORITY_NATIVE==='1'){await require('./secureshopMailReplyAuthority.cohort').runReplyAuthority({identity,im,agents,am,review,owner,mail,auth,templates,authority,launches,lifecycle});return;}
 const merchant=templates.find(t=>t.role==='merchant'),customer=templates.find(t=>t.role==='customer');
 const message={from:merchant.email,to:customer.email,subject:'Owned header\r\nX-Training: boundary',body_markdown:'Owned synthetic message'};
 const reader=require('../../server/database/postgres/secureshopMailHeaderEvidenceRepository').createMailHeaderEvidenceRepository({personaAuthority:authority,mailRepository:mail});
 const {buildMailHeaderCandidate}=require('../../server/services/secureshopMailHeaderEvidence');
 const first=await owner(),sibling=await owner();await mail.send(sibling,{...message,subject:'Sibling ordinary'});
 const siblingBefore=(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[sibling.targetId])).rows;
 const sent=await mail.send(first,message),appended={...first,operationId:randomUUID()};await mail.send(appended,{...message,threadId:sent.thread_id});
 const count=async()=>Number((await agents.query('SELECT count(*) n FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1',[first.targetId])).rows[0].n),beforeReads=await count();
 const freshEvidence=await reader.readHeader(first),appendEvidence=await reader.readHeader(appended);
 assert.equal(Object.hasOwn(freshEvidence.payload,'threadId'),false);assert.equal(appendEvidence.payload.threadId,sent.thread_id);assert.equal(await count(),beforeReads);assert.equal(freshEvidence.payload.subject,message.subject);assert.equal(freshEvidence.payload.headers_raw,prepareSend(message).headers_raw);assert(buildMailHeaderCandidate(freshEvidence));
 for(const body of [{...message,subject:'ordinary'},{...message,subject:'ordinary',body_markdown:'\r\nBcc: body only'}]){const binding={...first,operationId:randomUUID()};await mail.send(binding,body);assert.equal(buildMailHeaderCandidate(await reader.readHeader(binding)),null);}
 await assert.rejects(mail.send({...first,mode:'fixed',operationId:randomUUID()},message));
 for(const binding of [{...first,operationId:randomUUID()},{...first,targetId:sibling.targetId},{...first,personaSession:{...first.personaSession,sessionId:randomUUID()}},{...first,persona:{id:customer.id,role:'customer'}}])await assert.rejects(reader.readHeader(binding));
 await assert.rejects(agents.query('SELECT * FROM secureshop_agents.lab_mail_messages'));
 // Deliberate isolated migration-role corruption checks prove both stored IDs
 // and full content hashes matter; each patch is restored before continuation.
 const original=(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE message_id=$1',[sent.email_id])).rows[0];
 for(const [column,value] of [['subject','tampered'],['thread_id',999999],['headers_raw','tampered']]){
  try{await am.query(`UPDATE secureshop_agents.lab_mail_messages SET ${column}=$2 WHERE message_id=$1`,[sent.email_id,value]);await assert.rejects(reader.readHeader(first));}
  finally{await am.query(`UPDATE secureshop_agents.lab_mail_messages SET ${column}=$2 WHERE message_id=$1`,[sent.email_id,original[column]]);}
 }
 const beforeNoop=(await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts ORDER BY operation_id')).rows;
 assert.deepEqual(await migrate(am,'db/postgres/workshop-migrations/secureshop_agents'),[]);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts ORDER BY operation_id')).rows,beforeNoop);
 // Canonical persisted grading with a controlled provider, not actual semantic
 // qualification. Eligibility changes exist only in this frozen disposable copy.
 assert.equal(require('../../server/config/secureshopCurriculum').isQualifiedObjective('ss_mail_header_construction'),true);
 await im.query("UPDATE workshop_platform.exercises SET catalog_active=true,is_visible=true WHERE workshop_key='secureshop_agent_security'");
 assert.equal((await im.query("UPDATE workshop_platform.objectives SET catalog_active=true,is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_mail_header_construction'")).rowCount,1);
 let unavailable=true,invalidSupport=false,wireVersion=3,judgeCalls=0;
 const witness=buildMailHeaderCandidate(freshEvidence).evidence[1].content.boundaries[0].description;
 const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{async chat(){judgeCalls++;if(unavailable)throw Error('Controlled unavailable');return {provider:'controlled-native-header',model:'controlled',response:JSON.stringify(wireVersion===1?{verdict:'pass',explanation:'Controlled legacy header proof.',criteria:[{id:'stored_header_boundary',satisfied:true,evidenceRefs:['mail_header'],citations:[{evidenceId:'mail_header',quote:message.subject}]}]}:{satisfied:true,citations:[{evidenceId:'header_boundary',quote:invalidSupport?message.subject:witness}]})};}}});
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
 const grading=await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({identityPool:identity,agentsPool:agents,progress,resetComposition:lifecycle,judge,expectedIdentityDatabase:new URL(process.env.MAIL_IDENTITY_RUNTIME_URL).pathname.slice(1),expectedAgentsDatabase:new URL(process.env.MAIL_AGENTS_RUNTIME_URL).pathname.slice(1)});
 const assessment=require('../../server/services/secureshopMailHeaderAssessment').createMailHeaderAssessment({...grading.assessmentDependencies,judge,identityPool:identity,launches,conversationRepository:lifecycle.conversations,coordinator:lifecycle.runCoordinator,journal:lifecycle.journal,personaAuthority:authority,evidenceRepository:reader});
 const assessed=await assessment.runAttempt({binding:first,requestId:randomUUID()});assert.equal(assessed.completed,false);assert.equal(assessed.judgment.verdict,'unavailable');assert.equal(assessed.judgment.canRetry,true);
 const evaluationId=assessed.judgment.evaluationId;assert(evaluationId);const originalPacket=(await identity.query('SELECT packet FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2',[first.scope.platformOwnerId,evaluationId])).rows[0].packet;unavailable=false;
 const retryId=randomUUID(),retried=await assessment.runAttempt({binding:first,requestId:retryId,evaluationId});assert.equal(retried.completed,true);assert.equal(retried.judgment.verdict,'pass');assert.equal(retried.judgment.evidenceDigest,assessed.judgment.evidenceDigest);assert.equal((await identity.query('SELECT packet FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2',[first.scope.platformOwnerId,evaluationId])).rows[0].packet,originalPacket);
 const calls=judgeCalls;assert.equal((await assessment.runAttempt({binding:first,requestId:retryId,evaluationId})).replayed,true);assert.equal(judgeCalls,calls);
 // Verify invalid raw-positive audit survives actual SQL storage and SQL readback.
 const negative=await owner();await mail.send(negative,message);invalidSupport=true;
 const rejected=await assessment.runAttempt({binding:negative,requestId:randomUUID()});assert.equal(rejected.completed,false);assert.equal(rejected.judgment.verdict,'unavailable');
 const storedInvalid=(await identity.query('SELECT result_json FROM workshop_platform.objective_judgments WHERE user_id=$1 AND evaluation_id=$2',[negative.scope.platformOwnerId,rejected.judgment.evaluationId])).rows[0].result_json;
 assert.equal(storedInvalid.scopedCriteria[0].boundarySelection.length,2);assert(storedInvalid.scopedCriteria[0].boundarySelection.every(a=>a.rawSatisfied===true&&a.validationReason==='INVALID_BOUNDARY_SUPPORT'));
 invalidSupport=false;
 assert.equal((await identity.query("SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND objective_id='ss_mail_header_construction'",[negative.scope.platformOwnerId])).rows[0].n,0);
 const legacyRetries=[];
 for(const version of [1,2]){
  const evidenceModule=require('../../server/services/secureshopMailHeaderEvidence'),file=require.resolve('../../server/services/secureshopMailHeaderAssessment'),Module=require('node:module'),loaded=new Module(file,module);loaded.filename=file;loaded.paths=module.paths;const originalRequire=Module.createRequire(file);
  loaded.require=name=>name==='./secureshopMailHeaderEvidence'?{...evidenceModule,MAIL_HEADER_RUBRIC:version===1?evidenceModule.LEGACY_MAIL_HEADER_RUBRIC:evidenceModule.V2_MAIL_HEADER_RUBRIC,buildMailHeaderCandidate:version===1?evidenceModule.buildLegacyMailHeaderCandidate:evidenceModule.buildV2MailHeaderCandidate}:originalRequire(name);
  loaded._compile(fs.readFileSync(file,'utf8'),file);
  const legacy=loaded.exports.createMailHeaderAssessment({...grading.assessmentDependencies,judge,identityPool:identity,launches,conversationRepository:lifecycle.conversations,coordinator:lifecycle.runCoordinator,journal:lifecycle.journal,personaAuthority:authority,evidenceRepository:reader});
  const binding=await owner();await mail.send(binding,message);wireVersion=version;unavailable=true;const parent=await legacy.runAttempt({binding,requestId:randomUUID()});assert.equal(parent.judgment.verdict,'unavailable');
  const query=()=>identity.query('SELECT packet FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2',[binding.scope.platformOwnerId,parent.judgment.evaluationId]);const before=(await query()).rows[0].packet;assert.equal(JSON.parse(before).rubric.version,`secureshop-mail-header-v${version}`);
  unavailable=false;const child=await assessment.runAttempt({binding,requestId:randomUUID(),evaluationId:parent.judgment.evaluationId});assert.equal(child.judgment.verdict,'pass');assert.equal((await query()).rows[0].packet,before);assert.equal(child.judgment.evidenceDigest,parent.judgment.evidenceDigest);legacyRetries.push({version,parent,child,packetUnchanged:true});
 }
 wireVersion=3;
 const lifecycleEvidence=await require('./secureshopMailHeaderLifecycle.cohort').runHeaderLifecycle({owner,mail,message,reader,assessment,makeAssessment:scopedJudge=>require('../../server/services/secureshopMailHeaderAssessment').createMailHeaderAssessment({...grading.assessmentDependencies,judge:scopedJudge,identityPool:identity,launches,conversationRepository:lifecycle.conversations,coordinator:lifecycle.runCoordinator,journal:lifecycle.journal,personaAuthority:authority,evidenceRepository:reader}),judge,identity,im,agents,am,users,lifecycle,sibling});
 const judgments=(await identity.query('SELECT evaluation_id,verdict,disposition,evidence_digest,result_json FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[first.scope.platformOwnerId])).rows;
 const persistedPass=judgments.find(r=>r.verdict==='pass');assert.deepEqual(persistedPass.result_json.scopedCriteria,retried.judgment.scopedCriteria);assert.equal(persistedPass.result_json.scopedCriteria[0].boundarySelection.at(-1).validationReason,'VALID');assert.equal(persistedPass.result_json.scopedCriteria[0].boundarySelection.at(-1).rawSatisfied,true);
 assert(judgments.some(r=>r.verdict==='unavailable'));assert(judgments.some(r=>r.verdict==='pass'&&['awarded','already_complete'].includes(r.disposition)));
 assert.equal((await identity.query("SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND objective_id='ss_mail_header_construction'",[first.scope.platformOwnerId])).rows[0].n,1);
 const retained=(await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[first.targetId])).rows;
 const gradePackets=async()=>(await identity.query('SELECT evaluation_id,packet FROM workshop_platform.grade_packets WHERE user_id=$1 ORDER BY evaluation_id',[first.scope.platformOwnerId])).rows;const packetsBeforeReset=await gradePackets();
 const beforeResetCalls=judgeCalls;
 const reset=await lifecycle.launchResetCoordinator.reset({...first.scope,expectedGeneration:first.scope.generation,idempotencyKey:randomUUID()});
 await assert.rejects(reader.readHeader(first));await assert.rejects(assessment.runAttempt({binding:first,requestId:randomUUID(),evaluationId}));assert.equal(judgeCalls,beforeResetCalls);assert.deepEqual(await gradePackets(),packetsBeforeReset);
 assert.equal((await am.query('SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[first.targetId])).rows[0].n,0);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[first.targetId])).rows,retained);
 assert.deepEqual((await identity.query('SELECT evaluation_id,verdict,disposition,evidence_digest,result_json FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[first.scope.platformOwnerId])).rows,judgments);
 assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[sibling.targetId])).rows,siblingBefore);
 await lifecycle.personaInbox.repository.readCleanupReceipt({...first.scope,targetId:first.targetId},{operationId:reset.resetId});
 fs.writeFileSync(process.env.MAIL_RESULT,JSON.stringify({status:'passed',scope:'Native header readback and canonical persisted controlled grading; no real model/browser/SMTP',sqlPayloadForms:['new-thread','explicit-thread'],freshEvidence,appendEvidence,lifecycleEvidence,noExtraReadReceipts:true,ordinaryAndBodyOnlyDenied:true,fixedNewlineDenied:true,wrongBindingDenied:true,tamperCases:3,populatedNoopPreserved:true,privateMessageSelectDenied:true,controlledJudgeCalls:judgeCalls,invalidRawPositiveAudit:storedInvalid,legacyRetries,actualModelCalls:0,assessment:assessed,retry:retried,judgments,resetId:reset.resetId,immutableReceiptsAndJudgmentsPreserved:true,siblingPreserved:true,limitations:['No genuine Judge capability or rendered/catalog qualification','Release qualification remains disabled']},null,2));
 }finally{await Promise.all(pools.map(p=>p.end()));}
})().catch(error=>{console.error(error);process.exitCode=1;});
