'use strict';
// Genuine provider instances and unchanged graph/Judge. Never substitute model output.
const assert=require('node:assert/strict'),fs=require('node:fs'),{randomUUID,createHash}=require('node:crypto');
const casesModule=require('../fixtures/secureshopMailReplyAuthorityActualCases');
const hash=value=>createHash('sha256').update(value).digest('hex');
async function runReplyAuthorityActual(c){
 const {identity,im,agents,am,review,owner,mail,auth,templates,authority,launches,lifecycle}=c;
 const {OllamaProvider}=require('../../server/services/secureshop/providers/ollamaProvider');
 const assessmentModule=require('../../server/services/secureshopMailReplyAssessment');
 const {authenticateMailPersona,mailSourceEnvelope}=require('../fixtures/secureshopMailQualificationContracts');
 const scenarios=casesModule.buildCases(templates),state={status:'running',scope:'Actual v15 owned graph and canonical grading; no HTTP UI/browser/SMTP',bounds:casesModule.BOUNDS,prospectiveCases:scenarios,cases:[],http:[],controlledProviderReplacement:false};
 const record=()=>fs.writeFileSync(process.env.MAIL_RESULT,JSON.stringify(state,null,2));record();
 assert.equal(require('../../server/config/secureshopCurriculum').isQualifiedObjective('ss_mail_reply_redirect'),true,'Private candidate eligibility required');
 await im.query("UPDATE workshop_platform.exercises SET catalog_active=true,is_visible=true WHERE workshop_key='secureshop_agent_security'");
 assert.equal((await im.query("UPDATE workshop_platform.objectives SET catalog_active=true,is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_mail_reply_redirect'")).rowCount,1);
 const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
 const promptPolicyRepository=require('../../server/database/postgres/secureshopBoundPromptPolicyRepository').createBoundPromptPolicyRepository({pool:agents,personaAuthority:authority,audit:audit.agents,checkRunBinding:require('../../server/services/secureshopPromptPolicyRunBinding').createPromptPolicyRunBinding({identityPool:identity})});await promptPolicyRepository.checkReadiness();
 const toolPolicyRepository=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({personaAuthority:authority,audit:audit.agents});
 const reader=require('../../server/database/postgres/secureshopMailEvidenceRepository').createMailEvidenceRepository({personaAuthority:authority,mailRepository:mail});
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
 const sibling=await owner(),siblingRows=async()=>(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[sibling.targetId])).rows;
 await mail.send(sibling,{from:templates.find(p=>p.role==='merchant').email,to:templates.find(p=>p.role==='customer').email,subject:'Sibling baseline',body_markdown:'Unchanged owned sibling'});const siblingBefore=await siblingRows();assert(siblingBefore.length>0);
 const immutable=async userId=>({judgments:(await identity.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[userId])).rows,packets:(await identity.query('SELECT * FROM workshop_platform.grade_packets WHERE user_id=$1 ORDER BY evaluation_id',[userId])).rows});
 const completions=async userId=>(await identity.query("SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND objective_id='ss_mail_reply_redirect'",[userId])).rows[0].n;
 for(const scenario of scenarios){
  const row={id:scenario.id,mode:scenario.mode,bodySha256:scenario.bodySha256,status:'starting',calls:[]};state.cases.push(row);record();let transport;
  try{
   transport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:casesModule.BOUNDS.httpPerCase,record:value=>{row.calls=value.calls;row.modelDigest=value.modelDigest;state.http=state.cases.flatMap(r=>r.calls.map(call=>({...call,caseId:r.id})));assert(state.http.length<=casesModule.BOUNDS.totalHttp);record();}});
   assert.equal(transport.model,casesModule.MODEL);assert.equal(transport.digest,casesModule.MODEL_DIGEST);
   const provider=new OllamaProvider({baseUrl:transport.actorUrl,model:transport.model});assert.equal(provider.chat,OllamaProvider.prototype.chat);assert.equal(provider.finalResponse,OllamaProvider.prototype.finalResponse);
   const qualifyModel=require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider);
   const judgeModel=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:transport.model,baseURL:transport.judgeUrl});
   const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:judgeModel,timeoutMs:casesModule.BOUNDS.judgeMilliseconds,contextTokens:32768});
   const grading=await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({identityPool:identity,agentsPool:agents,progress,resetComposition:lifecycle,judge,expectedIdentityDatabase:new URL(process.env.MAIL_IDENTITY_RUNTIME_URL).pathname.slice(1),expectedAgentsDatabase:new URL(process.env.MAIL_AGENTS_RUNTIME_URL).pathname.slice(1)});
   const graph=require('../../server/services/secureshopBoundMailGraph').createBoundMailGraph({launches,personaAuthority:authority,conversationRepository:lifecycle.conversations,journal:lifecycle.journal,coordinator:lifecycle.runCoordinator,provider,mailRepository:mail,listPersonas:async()=>templates,promptPolicyRepository,toolPolicyRepository});
   const assessment=assessmentModule.createMailReplyAssessment({...grading.assessmentDependencies,judge,identityPool:identity,launches,conversationRepository:lifecycle.conversations,coordinator:lifecycle.runCoordinator,journal:lifecycle.journal,personaAuthority:authority,evidenceRepository:reader,listPersonas:async()=>templates,qualifyModel});
   const binding={...await owner(),mode:scenario.mode};row.scope=binding.scope;assert.equal(await completions(binding.scope.platformOwnerId),0);
   const sender={...binding,...await authenticateMailPersona({auth,scope:binding.scope,templates,role:'customer'}),operationId:randomUUID()};
   const envelope=mailSourceEnvelope({templates,context:sender,recipientRole:'merchant',subject:scenario.subject,body_markdown:scenario.body});assert.equal(hash(envelope.body_markdown),scenario.bodySha256);
   const sent=await mail.send(sender,envelope);row.source={...envelope,messageId:sent.email_id,threadId:sent.thread_id};record();
   const started=Date.now();try{row.actor=await graph.run({...binding,threadId:sent.thread_id});}catch(error){row.actorError={code:error.code||null,message:error.message};}row.actorMilliseconds=Date.now()-started;record();
   const saved=(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[binding.targetId])).rows;row.saved=saved;
   // Scope contains one source plus at most one actual reply; no unrelated send is credited.
   const replies=saved.filter(m=>Number(m.message_id)!==sent.email_id);assert(replies.length<=1);const savedRecipientId=replies.length?Number(replies[0].recipient_id):null;
   if(row.actor){const count=transport.calls.length;row.actorReplay=await graph.run({...binding,threadId:sent.thread_id});assert.equal(row.actorReplay.replayed,true);assert.equal(transport.calls.length,count);}
   if(row.actor?.taskMetadata?.mail?.decision==='saved'){
    const observed=await reader.readReply({...binding,threadId:sent.thread_id});row.observed=observed;
    assert.deepEqual(observed.source.map(m=>m.id),[sent.email_id]);assert.equal(observed.turn.metadata.trustedTask.originalSenderId,scenario.originalSenderId);assert.equal(observed.send.recipientId,savedRecipientId);assert.equal(observed.send.email_id,Number(replies[0].message_id));assert(qualifyModel(observed.turn.metadata.decisionModel));assert(qualifyModel(observed.turn.metadata.finalModel));
    if(binding.mode==='vuln'&&savedRecipientId!==scenario.originalSenderId)assert(assessmentModule.buildMailReplyCandidate(observed,templates,qualifyModel),'Actual selected/read/saved provenance must admit');
    const disabledBefore=await immutable(binding.scope.platformOwnerId),disabledCalls=transport.calls.length;
    await im.query("UPDATE workshop_platform.objectives SET is_enabled=false WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_mail_reply_redirect'");
    try{const denied=await assessment.runAttempt({binding,threadId:sent.thread_id,requestId:randomUUID()});assert.equal(denied.status,'disabled');assert.equal(denied.completed,false);assert.equal(denied.modelEvaluated,false);assert.equal(transport.calls.length,disabledCalls);assert.deepEqual(await immutable(binding.scope.platformOwnerId),disabledBefore);row.disabledCatalogNoEvaluation=true;}
    finally{await im.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_mail_reply_redirect'");}
    const requestId=randomUUID(),beforeJudge=transport.calls.length,gradeStarted=Date.now();row.assessment=await assessment.runAttempt({binding,threadId:sent.thread_id,requestId});row.judgeMilliseconds=Date.now()-gradeStarted;
    if(binding.mode==='fixed'||savedRecipientId===scenario.originalSenderId)assert.equal(transport.calls.length,beforeJudge,'Ineligible effect must use zero Judge calls');
    const count=transport.calls.length;row.assessmentReplay=await assessment.runAttempt({binding,threadId:sent.thread_id,requestId});assert.equal(row.assessmentReplay.replayed,true);assert.equal(transport.calls.length,count);
    const snapshots=await immutable(binding.scope.platformOwnerId);row.immutableBeforeReset=snapshots;
    if(row.assessment.judgment){const packetRow=snapshots.packets.find(p=>p.evaluation_id===row.assessment.judgment.evaluationId),judgmentRow=snapshots.judgments.find(p=>p.evaluation_id===row.assessment.judgment.evaluationId);require('../fixtures/secureshopMailActualJudgmentContract').verifyActualReplyJudgment({packetRow,judgmentRow,judgment:row.assessment.judgment,completed:row.assessment.completed===true,recipientId:savedRecipientId,model:casesModule.MODEL,binding,threadId:sent.thread_id,observed});row.canonicalV15ReadbackVerified=true;}
   }
   const count=transport.calls.length;
   for(const changed of [{...binding,scope:sibling.scope},{...binding,personaSession:{...binding.personaSession,sessionId:randomUUID()}}]){await assert.rejects(graph.run({...changed,threadId:sent.thread_id}));assert.equal(transport.calls.length,count);}
   const completed=row.assessment?.completed===true;assert.equal(await completions(binding.scope.platformOwnerId),completed?1:0);
   row.interpretation=casesModule.classifyCase(scenario,{savedRecipientId,completed,verdict:row.assessment?.judgment?.verdict,actorUnavailable:Boolean(row.actorError)});
   if(binding.mode==='fixed')assert.equal(completed,false);
   assert.equal(await auth.revokeOwnedSession({scope:binding.scope,shopPersona:binding.persona,currentSessionId:binding.personaSession.sessionId,authorityVersion:binding.personaSession.authorityVersion,sessionId:binding.personaSession.sessionId}),true);
   await assert.rejects(graph.run({...binding,threadId:sent.thread_id}));await assert.rejects(assessment.runAttempt({binding,threadId:sent.thread_id,requestId:randomUUID()}));assert.equal(transport.calls.length,count);row.revokedOriginalPersonaDenied=true;
   const before=await immutable(binding.scope.platformOwnerId);const reset=await lifecycle.launchResetCoordinator.reset({...binding.scope,expectedGeneration:binding.scope.generation,idempotencyKey:randomUUID()});assert.equal(reset.status,'committed');
   await assert.rejects(graph.run({...binding,threadId:sent.thread_id}));assert.equal(transport.calls.length,count);assert.equal(await completions(binding.scope.platformOwnerId),0);assert.deepEqual(await immutable(binding.scope.platformOwnerId),before);assert.deepEqual(await siblingRows(),siblingBefore);
   row.reset={status:reset.status,immutablePreserved:true,completionAfter:0,siblingPreserved:true};row.callCounts=casesModule.countCalls(transport.calls);row.actorHttp=row.callCounts.actor;row.judgeHttp=row.callCounts.judge;assert(row.actorHttp<=casesModule.BOUNDS.actorHttpPerCase);assert(row.judgeHttp<=casesModule.BOUNDS.judgeHttpPerCase);
   const tags=await fetch('http://127.0.0.1:11434/api/tags',{signal:AbortSignal.timeout(5000)});assert(tags.ok);assert((await tags.json()).models.some(m=>(m.name===casesModule.MODEL||m.model===casesModule.MODEL)&&m.digest===casesModule.MODEL_DIGEST));row.finalDigestVerified=true;row.status=row.interpretation.qualification;record();
  }catch(error){row.status='invariant_failure';row.failure={message:error.message,code:error.code||null};state.status='failed';record();throw error;}finally{await transport?.close();row.transportClosed=true;record();}
 }
 state.status=state.cases.every(c=>c.interpretation?.matched)?'passed':'observed_negative';state.actualHttpCalls=state.http.length;state.limitations=['No rendered or HTTP route qualification; catalog toggles are isolated canonical configuration checks, not admin HTTP authorization proof','No historical85069 reinterpretation','No SMTP delivery','Fixed no-credit is not independently sufficient defense proof','Unavailable retry recovery remains controlled-native proof unless naturally observed here'];record();
}
module.exports={runReplyAuthorityActual};
