'use strict';
const {isDeepStrictEqual}=require('node:util');
const {canonicalDigest}=require('./mcp/protocolContext');
const {captureFeatureMode,projectFeatureMode}=require('./secureshopFeatureModeAuthority');
const {validateMailChatResult,validateMailRecipientSnapshot}=require('./secureshopRoleMailRead');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {operationId:replyOperationId}=require('./secureshopBoundMailGraph');

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA=/^[0-9a-f]{64}$/;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');
const fail=(code='ROLE_MAIL_ACTION_INVALID')=>Object.assign(Error('Merchant mail action unavailable'),{code});
const bounded=(value,max,empty=false)=>typeof value==='string'&&(empty||value.length>0)
 &&value.isWellFormed()&&!value.includes('\0')&&Buffer.byteLength(value,'utf8')<=max;
const id=value=>typeof value==='string'&&UUID.test(value);
const positive=value=>Number.isSafeInteger(value)&&value>0&&value<=2147483647;
function uuidFrom(hash){return `${hash.slice(0,8)}-${hash.slice(8,12)}-5${hash.slice(13,16)}-a${hash.slice(17,20)}-${hash.slice(20,32)}`;}
function mailMode(value){return exact(value,['version','featureId','policyVersion','effectiveMode','scope'])
 &&value.version===1&&value.featureId==='mail'&&value.policyVersion==='owned-mail-recipient-header-and-html-v1'
 &&['vuln','fixed'].includes(value.effectiveMode)&&exact(value.scope,['kind','id'])
 &&value.scope.kind==='launch_feature'&&value.scope.id==='mail';}
function actor(value){try{return validateMailRecipientSnapshot(value)===value}catch{return false}}
function sceneFrom(context){const target=context?.target,scene=target?.scene;
 if(!id(target?.targetId)||!id(scene?.sceneId)||!positive(scene?.sceneGeneration))throw fail('ROLE_MAIL_SCENE_STALE');
 return {targetId:target.targetId.toLowerCase(),sceneId:scene.sceneId.toLowerCase(),sceneGeneration:scene.sceneGeneration};
}
function createMailActionProposal({context,source,origin,selected,action,input={},modeCapability,mailModeCapability,sender,mailScene}={}){
 if(context?.persona?.role!=='merchant'||!positive(context.persona.id)||!actor(sender)
  ||sender.id!==context.persona.id||!id(context.personaSession?.sessionId)
  ||typeof context.personaSession.authorityVersion!=='string'
  ||!/^[1-9]\d{0,15}$/.test(context.personaSession.authorityVersion)
  ||!id(source?.sessionId)||!id(source?.requestId)
  ||!Number.isSafeInteger(origin?.step)||origin.step<1||origin.step>10
  ||!bounded(origin?.callId,128)||!['send','reply'].includes(action)
  ||!modeCapability||typeof modeCapability!=='object'||!mailMode(mailModeCapability)
  ||!exact(selected,['version','kind','choiceId','sourceId','snapshotSha256','snapshot','card'])
  ||selected.version!==1||!id(selected.choiceId)||!positive(selected.sourceId)
  ||selected.snapshotSha256!==canonicalDigest(selected.snapshot))throw fail();
 const packet=validateMailChatResult(selected.snapshot);
 if(!isDeepStrictEqual(packet.mailModeCapability,mailModeCapability))throw fail('SECURESHOP_FEATURE_MODE_STALE');
 const expectedKind=action==='send'?'merchant_mail_recipient':'merchant_mail_message';
 if(selected.kind!==expectedKind)throw fail('ROLE_MAIL_CHOICE_INVALID');
 let recipient=null,expectedSource=null,send=null,sourceCard=null;
 if(action==='send'){
  if(packet.kind!=='recipients'||!exact(input,['subject','body_markdown'])
   ||!bounded(input.subject,512)||!bounded(input.body_markdown,8192,true))throw fail('INVALID_TOOL_ARGUMENTS');
  recipient=packet.recipients.find(row=>row.id===selected.sourceId);
  if(!recipient)throw fail('ROLE_MAIL_CHOICE_INVALID');
  send={from:sender.email,to:recipient.email,subject:input.subject,body_markdown:input.body_markdown};
 }else{
  if(packet.kind!=='list'||packet.recipient.id!==context.persona.id||!exact(input,[]))
   throw fail('ROLE_MAIL_SOURCE_UNAVAILABLE');
  const header=packet.headers.find(row=>row.id===selected.sourceId);
  if(!header)throw fail('ROLE_MAIL_CHOICE_INVALID');
  expectedSource={threadId:header.threadId,messageId:header.id,sha256:header.sha256};
  sourceCard={from:header.from,subject:header.subject,createdAt:header.createdAt};
 }
 if(!exact(mailScene,['targetId','sceneId','sceneGeneration'])||!id(mailScene.targetId)
  ||!id(mailScene.sceneId)||!positive(mailScene.sceneGeneration))throw fail('ROLE_MAIL_SCENE_STALE');
 const base={version:1,kind:'merchant_mail_proposal',action,
  source:{sessionId:source.sessionId.toLowerCase(),requestId:source.requestId.toLowerCase(),step:origin.step,callId:origin.callId},
  scopeSha256:canonicalDigest(createLaunchScope(context.scope)),scene:sceneFrom(context),mailScene,
  persona:{id:sender.id,role:'merchant',sessionId:context.personaSession.sessionId.toLowerCase(),
   authorityVersion:context.personaSession.authorityVersion},
  modeCapability,mailModeCapability,
  choice:{choiceId:selected.choiceId.toLowerCase(),sourceId:selected.sourceId,snapshotSha256:selected.snapshotSha256},
  sender,recipient,expectedSource,send,sourceCard};
 return validateMailActionProposal({...base,proposalId:uuidFrom(canonicalDigest(['merchant-mail-action-v1',base]))});
}
function validateMailActionProposal(value){
 if(!exact(value,['version','kind','action','proposalId','source','scopeSha256','scene','mailScene','persona',
  'modeCapability','mailModeCapability','choice','sender','recipient','expectedSource','send','sourceCard'])
  ||value.version!==1||value.kind!=='merchant_mail_proposal'||!['send','reply'].includes(value.action)
  ||!id(value.proposalId)||!exact(value.source,['sessionId','requestId','step','callId'])
  ||!id(value.source.sessionId)||!id(value.source.requestId)
  ||!Number.isSafeInteger(value.source.step)||value.source.step<1||value.source.step>10
  ||!bounded(value.source.callId,128)||!SHA.test(value.scopeSha256)
  ||!exact(value.scene,['targetId','sceneId','sceneGeneration'])
  ||!id(value.scene.targetId)||!id(value.scene.sceneId)||!positive(value.scene.sceneGeneration)
  ||!exact(value.mailScene,['targetId','sceneId','sceneGeneration'])
  ||!id(value.mailScene.targetId)||!id(value.mailScene.sceneId)||!positive(value.mailScene.sceneGeneration)
  ||!exact(value.persona,['id','role','sessionId','authorityVersion'])
  ||!positive(value.persona.id)||value.persona.role!=='merchant'||!id(value.persona.sessionId)
  ||typeof value.persona.authorityVersion!=='string'||!/^[1-9]\d{0,15}$/.test(value.persona.authorityVersion)
  ||!value.modeCapability||typeof value.modeCapability!=='object'||!mailMode(value.mailModeCapability)
  ||!exact(value.choice,['choiceId','sourceId','snapshotSha256'])
  ||!id(value.choice.choiceId)||!positive(value.choice.sourceId)||!SHA.test(value.choice.snapshotSha256)
  ||!actor(value.sender)||value.sender.id!==value.persona.id)throw fail();
 if(value.action==='send'){
  if(!actor(value.recipient)||value.recipient.id!==value.choice.sourceId
   ||value.expectedSource!==null||value.sourceCard!==null
   ||!exact(value.send,['from','to','subject','body_markdown'])
   ||value.send.from!==value.sender.email||value.send.to!==value.recipient.email
   ||!bounded(value.send.subject,512)||!bounded(value.send.body_markdown,8192,true))throw fail();
 }else if(value.recipient!==null||value.send!==null
  ||!exact(value.expectedSource,['threadId','messageId','sha256'])
  ||!positive(value.expectedSource.threadId)||!positive(value.expectedSource.messageId)
  ||value.expectedSource.messageId!==value.choice.sourceId||!SHA.test(value.expectedSource.sha256)
  ||!exact(value.sourceCard,['from','subject','createdAt'])
  ||!bounded(value.sourceCard.from,512)||!bounded(value.sourceCard.subject,512)
  ||typeof value.sourceCard.createdAt!=='string'||!Number.isFinite(Date.parse(value.sourceCard.createdAt)))throw fail();
 const {proposalId,...base}=value;
 if(proposalId!==uuidFrom(canonicalDigest(['merchant-mail-action-v1',base])))throw fail('ROLE_MAIL_PROPOSAL_MISMATCH');
 return value;
}
function projectMailActionProposal(value){validateMailActionProposal(value);
 return {version:1,kind:'merchant_mail_proposal',action:value.action,proposalId:value.proposalId,
  recipient:value.action==='send'?{username:value.recipient.username,email:value.recipient.email}:null,
  subject:value.action==='send'?value.send.subject:null,
  body_markdown:value.action==='send'?value.send.body_markdown:null,
  source:value.action==='reply'?value.sourceCard:null};
}
function validateMailActionOperation(value){
 if(!exact(value,['version','kind','action','proposalId','status','sendOperationId','emailId','threadId','savedSend','canRetrySameId'])
  ||value.version!==1||value.kind!=='merchant_mail_operation'||!['send','reply'].includes(value.action)
  ||!id(value.proposalId)||!['saved','saved_unattributed','declined','rejected_before_execution','unconfirmed'].includes(value.status)
  ||value.action==='send'&&['declined','rejected_before_execution'].includes(value.status)
  ||typeof value.canRetrySameId!=='boolean'||value.canRetrySameId!==(value.status==='unconfirmed'&&value.action==='send'))throw fail('ROLE_MAIL_OPERATION_INVALID');
 if(['saved','saved_unattributed'].includes(value.status)){
  if(value.sendOperationId!==(value.action==='reply'?replyOperationId(value.proposalId,'reply'):value.proposalId)
   ||!positive(value.emailId)||!positive(value.threadId)
   ||!exact(value.savedSend,['recipientId','to','subject','body_markdown'])
   ||!positive(value.savedSend.recipientId)||!bounded(value.savedSend.to,512)
   ||!bounded(value.savedSend.subject,512)||!bounded(value.savedSend.body_markdown,32768,true))throw fail('ROLE_MAIL_OPERATION_INVALID');
 }else if(value.sendOperationId!==null||value.emailId!==null||value.threadId!==null||value.savedSend!==null)
  throw fail('ROLE_MAIL_OPERATION_INVALID');
 return value;
}
function createBoundMailActions({mailApplication,listMailActors,modeAuthority,mode:defaultMode='vuln'}={}){
 if(!['vuln','fixed'].includes(defaultMode)||typeof listMailActors!=='function'
  ||['readiness','readRetainedTarget','send','reply','recoverRetained'].some(name=>typeof mailApplication?.[name]!=='function'))
  throw TypeError('Merchant mail action dependencies required');
 async function current(context,expected){
  const token=await captureFeatureMode(modeAuthority,context.scope,'mail',defaultMode);
  await token.assertCurrent();const projected=projectFeatureMode(token);
  if(expected&&!isDeepStrictEqual(projected,expected))throw fail('SECURESHOP_FEATURE_MODE_STALE');
  return {token,projected};
 }
 async function actors(context){const rows=await listMailActors(context.scope);
  if(!Array.isArray(rows)||rows.length>128||rows.some(row=>!actor(row))
   ||new Set(rows.map(row=>row.id)).size!==rows.length)throw fail('ROLE_MAIL_RECIPIENT_INVALID');
  const sender=rows.find(row=>row.id===context.persona.id);
  if(!sender||sender.role!=='merchant')throw fail('SHOP_AUTH_INVALID');return {rows,sender};
 }
 async function check(context,proposal,{signal,beforeEffect,forEffect=false}={}){
  validateMailActionProposal(proposal);signal?.throwIfAborted();await beforeEffect?.();
  if(proposal.scopeSha256!==canonicalDigest(createLaunchScope(context.scope))
   ||!isDeepStrictEqual(proposal.scene,sceneFrom(context))
   ||proposal.persona.id!==context.persona?.id||proposal.persona.role!==context.persona?.role
   ||proposal.persona.sessionId!==context.personaSession?.sessionId
   ||proposal.persona.authorityVersion!==context.personaSession?.authorityVersion)throw fail('ROLE_MAIL_PROPOSAL_STALE');
  const {token}=await current(context,proposal.mailModeCapability);
  const mailScene=await mailApplication.readRetainedTarget(context);
  if(!isDeepStrictEqual(mailScene,proposal.mailScene))throw fail('ROLE_MAIL_SCENE_STALE');
  if(forEffect){
   const readiness=await mailApplication.readiness(context);
   if(readiness?.ready!==true||!isDeepStrictEqual(readiness.modeCapability,proposal.mailModeCapability))throw fail('MAIL_UNAVAILABLE');
   const {rows,sender}=await actors(context);if(!isDeepStrictEqual(sender,proposal.sender))throw fail('ROLE_MAIL_RECIPIENT_STALE');
   if(proposal.action==='send'&&!rows.some(row=>isDeepStrictEqual(row,proposal.recipient)))throw fail('ROLE_MAIL_RECIPIENT_STALE');
  }
  await token.assertCurrent();signal?.throwIfAborted();return token;
 }
 function operation(proposal,result){
  const status=result?.status||(result?.ok===true&&result?.receipt?.email_id?'saved':'unconfirmed');
  const saved=status==='saved'||status==='saved_unattributed';
  return validateMailActionOperation({version:1,kind:'merchant_mail_operation',action:proposal.action,
   proposalId:proposal.proposalId,status,
   sendOperationId:saved?(proposal.action==='reply'?replyOperationId(proposal.proposalId,'reply'):proposal.proposalId):null,
   emailId:saved?(result.sent_email_id??result.email_id):null,
   threadId:saved?(result.thread_id??result.receipt?.thread_id):null,
   savedSend:saved?(result.savedReply??result.savedSend):null,
   canRetrySameId:status==='unconfirmed'&&proposal.action==='send'});
 }
 return Object.freeze({
  async prepare({context,source,origin,selected,action,input={},modeCapability,signal,beforeEffect}={}){
   signal?.throwIfAborted();await beforeEffect?.();
   const {token,projected}=await current(context,selected?.snapshot?.mailModeCapability);
   const readiness=await mailApplication.readiness(context);
   if(readiness?.ready!==true||!isDeepStrictEqual(readiness.modeCapability,projected))throw fail('MAIL_UNAVAILABLE');
   const {sender}=await actors(context);
   if(typeof mailApplication.prepareTarget!=='function')throw fail('MAIL_UNAVAILABLE');
   const mailScene=await mailApplication.prepareTarget(context,{requestId:source?.requestId},
    {signal,beforeEffect});
   await token.assertCurrent();signal?.throwIfAborted();
   return createMailActionProposal({context,source,origin,selected,action,input,modeCapability,
    mailModeCapability:projected,sender,mailScene});
  },
  async reconstruct({context,source,origin,selected,action,input={},modeCapability,mailModeCapability,
   savedProposal,signal,beforeEffect}={}){
   signal?.throwIfAborted();await beforeEffect?.();
   validateMailActionProposal(savedProposal);
   const {token,projected}=await current(context,mailModeCapability);
   // The saved sender is a frozen part of this confirmed proposal. Display
   // profile edits do not erase a prior immutable send receipt on GET.
   const sender=savedProposal.sender,mailScene=await mailApplication.readRetainedTarget(context);
   await token.assertCurrent();signal?.throwIfAborted();
   return createMailActionProposal({context,source,origin,selected,action,input,modeCapability,
    mailModeCapability:projected,sender,mailScene});
  },
  async confirm({context,proposal,signal,beforeEffect}={}){
   const token=await check(context,proposal,{signal,beforeEffect,forEffect:true});let result;
   if(proposal.action==='send'){
    result=await mailApplication.send(context,{requestId:proposal.proposalId,...proposal.send},
     {signal,expectedTarget:proposal.mailScene,beforeEffect});
    if(result?.ok===true&&result.receipt?.email_id){
     result=await mailApplication.recoverRetained(context,{requestId:proposal.proposalId,
      action:'send',expectedTarget:proposal.mailScene,expectedSend:proposal.send},{signal});
    }
   }else result=await mailApplication.reply(context,{requestId:proposal.proposalId,
    threadId:proposal.expectedSource.threadId},{signal,beforeEffect,
    expectedSource:proposal.expectedSource,expectedTarget:proposal.mailScene});
   await token.assertCurrent();signal?.throwIfAborted();return operation(proposal,result);
  },
  async recover({context,proposal,signal,beforeEffect}={}){
   const token=await check(context,proposal,{signal,beforeEffect});
   const result=await mailApplication.recoverRetained(context,{requestId:proposal.proposalId,
    action:proposal.action==='reply'?'autoReply':'send',expectedTarget:proposal.mailScene,
    ...(proposal.action==='reply'?{expectedSource:proposal.expectedSource}:{expectedSend:proposal.send})},{signal});
   await token.assertCurrent();signal?.throwIfAborted();return operation(proposal,result);
  },
 });
}
module.exports={createBoundMailActions,createMailActionProposal,validateMailActionProposal,
 projectMailActionProposal,validateMailActionOperation};
