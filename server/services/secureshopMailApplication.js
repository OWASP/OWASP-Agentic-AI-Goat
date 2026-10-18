'use strict';
const {isDeepStrictEqual}=require('node:util');
const {captureFeatureMode,projectFeatureMode}=require('./secureshopFeatureModeAuthority');
const {validateMailInput,invalidMailInput}=require('./secureshopMailErrors');
const {normalize,prepareSend}=require('../database/postgres/secureshopBoundMailRepository');
const {operationId}=require('./secureshopBoundMailGraph');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function createMailApplication({resolveTarget,readExistingTarget,mailRepository,graph,readReadiness,recoveryRepository,uncertainRepository,assessment,headerAssessment,disclosureAssessment,browserAssessment,htmlInjectionAssessment,mode,modeAuthority}={}){
 if(typeof resolveTarget!=='function'||typeof readReadiness!=='function'||!['vuln','fixed'].includes(mode)
  ||['send','browse','recover'].some(k=>typeof mailRepository?.[k]!=='function')||typeof graph?.run!=='function')throw TypeError('Mail application dependencies required');
 const tokens=new WeakMap();
 async function checked(binding,work){const token=tokens.get(binding);await token.assertCurrent();const result=await work();await token.assertCurrent();return result;}
 const unavailable=()=>Object.assign(Error('Bound mail unavailable'),{code:'MAIL_UNAVAILABLE'});
 async function admitted(context,requestId){
  if(typeof requestId!=='string'||!UUID.test(requestId))return invalidMailInput();
  if((await readReadiness(context))?.ready!==true)throw unavailable();
  const token=await captureFeatureMode(modeAuthority,context.scope,'mail',mode);
  const target=await resolveTarget(context);await token.assertCurrent();const binding=normalize({scope:context.scope,persona:context.persona,personaSession:context.personaSession,targetId:target.targetId,target,mode:token.snapshot.mode,operationId:requestId});tokens.set(binding,token);return binding;
 }
 function targetScene(target){
  const held=require('./secureshopMailSceneBinding').productScene(target);
  const scene=held?.scene||target?.scene;
  return {targetId:target?.targetId,sceneId:scene?.sceneId,
   sceneGeneration:scene?.sceneGeneration};
 }
 async function retained(context,requestId,expectedTarget){
  if(typeof requestId!=='string'||!UUID.test(requestId))return invalidMailInput();
  if(typeof readExistingTarget!=='function')throw unavailable();
  const token=await captureFeatureMode(modeAuthority,context.scope,'mail',mode);
  const target=await readExistingTarget(context.scope);await token.assertCurrent();
  if(expectedTarget&&!isDeepStrictEqual(targetScene(target),expectedTarget))throw unavailable();
  const binding=normalize({scope:context.scope,persona:context.persona,
   personaSession:context.personaSession,targetId:target.targetId,target,
   mode:token.snapshot.mode,operationId:requestId});tokens.set(binding,token);return binding;
 }
 async function exactSavedReply(binding,sendOperationId){
  if(typeof mailRepository.readSavedSend!=='function')throw unavailable();
  const saved=await checked(binding,()=>mailRepository.readSavedSend({...binding,operationId:sendOperationId}));
  if(!saved||!Number.isSafeInteger(saved.recipientId)||saved.recipientId<1
   ||typeof saved.to!=='string'||typeof saved.subject!=='string'
   ||typeof saved.body_markdown!=='string')throw unavailable();
  return saved;
 }
 async function savedAutoReply(binding,requestId,receipt,modeCapability){
  if(receipt.action!=='send'||receipt.operationId!==operationId(requestId,'reply')
   ||!Number.isSafeInteger(receipt.receipt?.email_id)||receipt.receipt.email_id<1
   ||!Number.isSafeInteger(receipt.receipt?.thread_id)||receipt.receipt.thread_id<1)throw unavailable();
  const savedReply=await exactSavedReply(binding,receipt.operationId);
  if(savedReply.recipientId!==receipt.receipt.recipientId)throw unavailable();
  return {ok:true,status:'saved',requestId,sent_email_id:receipt.receipt.email_id,
   sendOperationId:receipt.operationId,thread_id:receipt.receipt.thread_id,savedReply,
   assessmentStatus:'pending',...(modeCapability?{modeCapability}:{})};
 }
 const expectedSourceMatches=(expected,metadata,decision='saved')=>expected===undefined
  ||metadata?.decision===decision&&metadata.threadId===expected.threadId
   &&isDeepStrictEqual(metadata.expectedSource,expected);
 function terminalNoSend(metadata,binding,requestId,threadId,stopReason){
  return stopReason==='end_turn'&&metadata?.version===2&&metadata.decision==='declined'
   &&metadata.operationId===requestId&&metadata.targetId===binding.targetId
   &&metadata.threadId===threadId&&metadata.mode===binding.mode
   &&Object.hasOwn(metadata,'sendPayload')&&metadata.sendPayload===null
   &&Object.hasOwn(metadata,'sendOperationId')&&metadata.sendOperationId===null
   &&Object.hasOwn(metadata,'sendReceipt')&&metadata.sendReceipt===null;
 }
 return Object.freeze({
  readiness:readReadiness,
  // Fresh no-send preparation may establish the caller's existing mail scene
  // grant. Saved operation readback continues through readRetainedTarget only.
  async prepareTarget(context,{requestId},options){
   options?.signal?.throwIfAborted();await options?.beforeEffect?.();
   const binding=await admitted(context,requestId);
   await options?.beforeEffect?.();await tokens.get(binding).assertCurrent();
   options?.signal?.throwIfAborted();
   const mailTarget=targetScene(binding.target);
   if(context.target&&(mailTarget.sceneId!==context.target.scene?.sceneId
    ||mailTarget.sceneGeneration!==context.target.scene?.sceneGeneration))throw unavailable();
   return mailTarget;
  },
  async readRetainedTarget(context){if(typeof readExistingTarget!=='function')throw unavailable();
   const token=await captureFeatureMode(modeAuthority,context.scope,'mail',mode);
   const target=await readExistingTarget(context.scope);await token.assertCurrent();return targetScene(target);},
  async read(context,{requestId,userId}){const binding=await admitted(context,requestId);return checked(binding,()=>mailRepository.browse(binding,userId));},
  async send(context,{requestId,...message},options){validateMailInput(()=>prepareSend(message));
   options?.signal?.throwIfAborted();const binding=options?.expectedTarget
    ?await retained(context,requestId,options.expectedTarget):await admitted(context,requestId);
   await options?.beforeEffect?.();options?.signal?.throwIfAborted();
   return checked(binding,()=>mailRepository.send(binding,message));},
  async reply(context,{requestId,threadId},options){options?.signal?.throwIfAborted();
   const binding=options?.expectedTarget?await retained(context,requestId,options.expectedTarget):await admitted(context,requestId);
   await options?.beforeEffect?.();options?.signal?.throwIfAborted();
   const result=await checked(binding,()=>graph.run({...binding,threadId},options)),m=result.taskMetadata?.mail;
   if(m?.decision!=='saved'){
    const sendOperationId=operationId(requestId,'reply');
    const receipt=await checked(binding,()=>mailRepository.recover({...binding,operationId:sendOperationId}));
    if(receipt.found){const saved=await savedAutoReply(binding,requestId,receipt,result.modeCapability);
     if(saved.thread_id!==threadId)throw unavailable();
     return {...saved,replayed:result.replayed,
      ...(expectedSourceMatches(options?.expectedSource,m)?{}:{status:'saved_unattributed'})};}
    if(!terminalNoSend(m,binding,requestId,threadId,result.stopReason))
     return {ok:true,status:'unconfirmed',requestId,canRetrySameId:false};
    return {ok:true,status:'declined',requestId,threadId,terminalNoSend:true,replayed:result.replayed,
     ...(result.modeCapability?{modeCapability:result.modeCapability}:{})};
   }
   if(m.sendOperationId!==operationId(requestId,'reply'))throw unavailable();
   const savedReply=await exactSavedReply(binding,m.sendOperationId);
   if(savedReply.recipientId!==m.sendReceipt?.recipientId)throw unavailable();
   return {ok:true,status:expectedSourceMatches(options?.expectedSource,m)?'saved':'saved_unattributed',
    requestId,sendOperationId:m.sendOperationId,replayed:result.replayed,sent_email_id:m.sendReceipt.email_id,
    thread_id:m.sendReceipt.thread_id,savedReply,assessmentStatus:'pending',
    ...(result.modeCapability?{modeCapability:result.modeCapability}:{})};},
  async assess(context,{requestId,replyOperationId,threadId,evaluationId},options){
   validateMailInput(()=>{if(!UUID.test(requestId)||!UUID.test(replyOperationId)||requestId===replyOperationId||!Number.isSafeInteger(threadId)||threadId<1||(evaluationId!==undefined&&!UUID.test(evaluationId)))invalidMailInput();});
   if(typeof assessment?.runAttempt!=='function')throw unavailable();
   const binding=await admitted(context,replyOperationId);
   return {ok:true,...await checked(binding,()=>assessment.runAttempt({binding,threadId,requestId,evaluationId,signal:options?.signal}))};
  },
  async assessHeader(context,{requestId,sendOperationId,evaluationId},options){
   validateMailInput(()=>{if(!UUID.test(requestId)||!UUID.test(sendOperationId)||requestId===sendOperationId||(evaluationId!==undefined&&!UUID.test(evaluationId)))invalidMailInput();});
   if(typeof headerAssessment?.runAttempt!=='function')throw unavailable();
   const binding=await admitted(context,sendOperationId);
   return {ok:true,...await checked(binding,()=>headerAssessment.runAttempt({binding,requestId,evaluationId,signal:options?.signal}))};
  },
  async disclose(context,{requestId,userId},options){
   validateMailInput(()=>{if(!Number.isSafeInteger(userId)||userId<1)invalidMailInput();});
   if(typeof mailRepository.read!=='function')throw unavailable();
   options?.signal?.throwIfAborted();const binding=await admitted(context,requestId);
   const result=await checked(binding,()=>mailRepository.read(binding,userId));options?.signal?.throwIfAborted();
   return {...result,assessmentStatus:'pending',mailModeCapability:projectFeatureMode(tokens.get(binding))};
  },
  // Saved RoleChat turns project the original read receipt; they never read the mailbox again.
  async projectDisclosure(context,{requestId,messageId=null,offset=0},options){
   validateMailInput(()=>{if(!UUID.test(requestId||''))invalidMailInput();});
   if(typeof readExistingTarget!=='function')throw unavailable();
   options?.signal?.throwIfAborted();
   const token=await captureFeatureMode(modeAuthority,context.scope,'mail',mode);
   const target=await readExistingTarget(context.scope);await token.assertCurrent();
   const binding=normalize({scope:context.scope,persona:context.persona,
    personaSession:context.personaSession,targetId:target.targetId,target,
    mode:token.snapshot.mode,operationId:requestId});tokens.set(binding,token);
   if(typeof mailRepository.projectRead!=='function')throw unavailable();
   const projected=await checked(binding,()=>mailRepository.projectRead(binding,{messageId,offset}));
   options?.signal?.throwIfAborted();
   return {...projected,mailModeCapability:projectFeatureMode(token)};
  },
  async assessDisclosure(context,{requestId,readOperationId,evaluationId},options){
   validateMailInput(()=>{if(!UUID.test(requestId)||!UUID.test(readOperationId)||requestId===readOperationId||(evaluationId!==undefined&&!UUID.test(evaluationId)))invalidMailInput();});
   if(typeof disclosureAssessment?.runAttempt!=='function')throw unavailable();
   const binding=await admitted(context,readOperationId);
   return {ok:true,...await checked(binding,()=>disclosureAssessment.runAttempt({binding,requestId,evaluationId,signal:options?.signal}))};
  },
  async assessBrowser(context,{requestId,sendOperationId,messageId,evaluationId},options){
   validateMailInput(()=>{if(!UUID.test(requestId)||!UUID.test(sendOperationId)||requestId===sendOperationId||(evaluationId!==undefined&&!UUID.test(evaluationId))||!Number.isSafeInteger(messageId)||messageId<1)invalidMailInput();});
   if(typeof browserAssessment?.runAttempt!=='function')throw unavailable();
   const binding=await admitted(context,sendOperationId);
   return {ok:true,...await checked(binding,()=>browserAssessment.runAttempt({binding,requestId,messageId,evaluationId,signal:options?.signal}))};
  },
  async assessHtmlInjection(context,{requestId,sourceSessionId,sourceRequestId,sendOperationId,messageId},options){
   validateMailInput(()=>{if(!UUID.test(requestId)||!UUID.test(sourceSessionId)||!UUID.test(sourceRequestId)
    ||!UUID.test(sendOperationId)||new Set([requestId,sourceSessionId,sourceRequestId,sendOperationId]).size!==4
    ||!Number.isSafeInteger(messageId)||messageId<1)invalidMailInput();});
   if(typeof htmlInjectionAssessment?.runAttempt!=='function')throw unavailable();
   const binding=await admitted(context,sendOperationId);
   return {ok:true,...await checked(binding,()=>htmlInjectionAssessment.runAttempt({binding,requestId,
    sourceSessionId,sourceRequestId,messageId,signal:options?.signal}))};
  },
  async readHtmlInjectionAssessment(context,{requestId,sourceSessionId,sourceRequestId,sendOperationId,messageId},options){
   validateMailInput(()=>{if(!UUID.test(requestId)||!UUID.test(sourceSessionId)||!UUID.test(sourceRequestId)
    ||!UUID.test(sendOperationId)||new Set([requestId,sourceSessionId,sourceRequestId,sendOperationId]).size!==4
    ||!Number.isSafeInteger(messageId)||messageId<1)invalidMailInput();});
   if(typeof htmlInjectionAssessment?.readOutcome!=='function')throw unavailable();
   const binding=await retained(context,sendOperationId);
   return {ok:true,...await checked(binding,()=>htmlInjectionAssessment.readOutcome({binding,requestId,
    sourceSessionId,sourceRequestId,messageId,signal:options?.signal}))};
  },
  async recover(context,{requestId,action}){
   if(!['send','autoReply'].includes(action))return invalidMailInput();
   const binding=await admitted(context,requestId),result=await checked(binding,()=>mailRepository.recover({...binding,operationId:action==='autoReply'?operationId(requestId,'reply'):requestId}));
   const terminal=action==='autoReply'&&recoveryRepository?await checked(binding,()=>recoveryRepository.readTerminal(binding)):null;
   if(!result.found){
    if(terminal?.decision==='declined'&&terminal.terminalNoSend===true)
     return {ok:true,status:'declined',requestId,threadId:terminal.threadId,terminalNoSend:true,
      ...(terminal.modeCapability?{modeCapability:terminal.modeCapability}:{})};
    const rejected=action==='autoReply'&&uncertainRepository
     ?await checked(binding,()=>uncertainRepository.readRejected(binding)):null;
    if(rejected)return {ok:true,status:'rejected_before_execution',requestId,terminalRejected:true};
    return {ok:true,status:'unconfirmed',requestId,canRetrySameId:action==='send'};
   }
   if(action==='autoReply')return savedAutoReply(binding,requestId,result,terminal?.modeCapability);
   if(result.action!=='send')throw unavailable();
   return {ok:true,status:'saved',requestId,email_id:result.receipt.email_id,thread_id:result.receipt.thread_id,
    assessmentStatus:'pending',...(terminal?.modeCapability?{modeCapability:terminal.modeCapability}:{})};
  },
  async recoverRetained(context,{requestId,action,expectedTarget,expectedSource,expectedSend},options){
   if(!['send','autoReply'].includes(action))return invalidMailInput();
   if(expectedSend!==undefined&&action!=='send')return invalidMailInput();
   if(expectedSource!==undefined&&(action!=='autoReply'||!expectedSource
    ||Object.getPrototypeOf(expectedSource)!==Object.prototype
    ||Object.keys(expectedSource).sort().join(',')!=='messageId,sha256,threadId'
    ||!Number.isSafeInteger(expectedSource.threadId)||expectedSource.threadId<1
    ||!Number.isSafeInteger(expectedSource.messageId)||expectedSource.messageId<1
    ||typeof expectedSource.sha256!=='string'||! /^[0-9a-f]{64}$/.test(expectedSource.sha256)))
    return invalidMailInput();
   options?.signal?.throwIfAborted();const binding=await retained(context,requestId,expectedTarget);
   const operation=action==='autoReply'?operationId(requestId,'reply'):requestId;
   const result=await checked(binding,()=>mailRepository.recover({...binding,operationId:operation}));
   const terminal=action==='autoReply'&&recoveryRepository
    ?await checked(binding,()=>recoveryRepository.readTerminal(binding)):null;
   options?.signal?.throwIfAborted();
   if(!result.found){
    if(terminal?.decision==='declined'&&terminal.terminalNoSend===true
     &&expectedSourceMatches(expectedSource,terminal,'declined'))
     return {ok:true,status:'declined',requestId,threadId:terminal.threadId,terminalNoSend:true,
      ...(terminal.modeCapability?{modeCapability:terminal.modeCapability}:{})};
    const rejected=action==='autoReply'&&uncertainRepository
     ?await checked(binding,()=>uncertainRepository.readRejected(binding)):null;
    if(rejected&&expectedSource===undefined)
     return {ok:true,status:'rejected_before_execution',requestId,terminalRejected:true};
    // The existing preexecution rejection proves a thread, not which selected
    // message SHA initiated it. A Q49 proposal cannot borrow that terminal.
    return {ok:true,status:'unconfirmed',requestId,canRetrySameId:action==='send'};
   }
   if(action==='autoReply'){
    const saved=await savedAutoReply(binding,requestId,result,terminal?.modeCapability);
    return expectedSourceMatches(expectedSource,terminal)&&terminal?.threadId===saved.thread_id
     ?saved:{...saved,status:'saved_unattributed'};
   }
   if(result.action!=='send'||result.operationId!==requestId)throw unavailable();
   const savedSend=await exactSavedReply(binding,requestId);
   if(savedSend.recipientId!==result.receipt?.recipientId)throw unavailable();
   const expectedHash=expectedSend===undefined?null:await checked(binding,()=>{
    if(typeof mailRepository.hashSendRequest!=='function')throw unavailable();
    return mailRepository.hashSendRequest(binding,expectedSend);
   });
   return {ok:true,status:expectedHash===null||expectedHash===result.requestSha256?'saved':'saved_unattributed',
    requestId,email_id:result.receipt.email_id,
    thread_id:result.receipt.thread_id,savedSend,assessmentStatus:'pending'};
  },
  async keepUnresolved(context,{requestId,threadId}){
   validateMailInput(()=>{if(!Number.isSafeInteger(threadId)||threadId<1||threadId>2147483647)invalidMailInput();});
   if(typeof uncertainRepository?.keepUnresolved!=='function')throw unavailable();
   const binding=await admitted(context,requestId);
   await checked(binding,()=>uncertainRepository.keepUnresolved(binding,threadId));
   return {ok:true,status:'kept_unresolved',requestId,threadId};
  },
 });
}
module.exports={createMailApplication};
