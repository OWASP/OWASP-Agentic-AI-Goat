'use strict';

const {isDeepStrictEqual}=require('node:util');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const mailScene=require('../../services/secureshopMailSceneBinding');

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX=/^[0-9a-f]{64}$/;
const CALL=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const fail=code=>Object.assign(Error('Mail inline binding unavailable'),{code,executionBoundary:true});
const own=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
  &&Object.keys(value).every(key=>keys.includes(key));
function id(value){if(typeof value!=='string'||!UUID.test(value))throw fail('INVALID_ARGUMENT');return value.toLowerCase();}
function hash(value){if(typeof value!=='string'||!HEX.test(value))throw fail('INVALID_ARGUMENT');return value;}
function positive(value){if(!Number.isSafeInteger(value)||value<1||value>2147483647)throw fail('INVALID_ARGUMENT');return value;}
function text(value,max){if(typeof value!=='string'||!value.length||Buffer.byteLength(value)>max)throw fail('INVALID_ARGUMENT');return value;}
function copyBinding(raw){
 if(!own(raw,['scope','targetId','target','persona','personaSession','mode','operationId']))throw fail('INVALID_ARGUMENT');
 const scope=createLaunchScope(raw.scope),targetId=id(raw.targetId),operationId=id(raw.operationId);
 if(raw.target!==undefined&&id(raw.target?.targetId)!==targetId)throw fail('INVALID_ARGUMENT');
 if(!own(raw.persona,['id','role'])||!['customer','merchant','admin'].includes(raw.persona.role)
  ||!own(raw.personaSession,['sessionId','authorityVersion'])||typeof raw.personaSession.authorityVersion!=='string'
  ||! /^[1-9]\d{0,15}$/.test(raw.personaSession.authorityVersion)||!Number.isSafeInteger(Number(raw.personaSession.authorityVersion))
  ||!['vuln','fixed'].includes(raw.mode))throw fail('INVALID_ARGUMENT');
 return mailScene.copy(raw.target||raw,{scope,targetId,operationId,persona:{id:positive(raw.persona.id),role:raw.persona.role},
  personaSession:{sessionId:id(raw.personaSession.sessionId),authorityVersion:raw.personaSession.authorityVersion},mode:raw.mode});
}
function reservation(value){
 if(!own(value,['issuanceId','listenerTargetId','nonceSha256','path','resourceKind','urlSha256']))throw fail('INVALID_ARGUMENT');
 const out={issuanceId:id(value.issuanceId),listenerTargetId:id(value.listenerTargetId),nonceSha256:hash(value.nonceSha256),
  path:text(value.path,1024),resourceKind:value.resourceKind,urlSha256:hash(value.urlSha256)};
 if(!/^\/[A-Za-z0-9._~/-]*$/.test(out.path)||out.resourceKind!=='mail_inline_image_v1')throw fail('INVALID_ARGUMENT');
 return Object.freeze(out);
}
function sameReservation(left,right){
 return ['issuanceId','listenerTargetId','nonceSha256','path','resourceKind','urlSha256']
  .every(key=>left[key]===right[key]);
}
function payload(value){
 if(!own(value,['from','to','subject','body_markdown','body_html','headers_raw','threadId']))throw fail('INVALID_ARGUMENT');
 const out={from:text(value.from,512),to:text(value.to,512),subject:text(value.subject,512),
  body_markdown:typeof value.body_markdown==='string'&&Buffer.byteLength(value.body_markdown)<=32768?value.body_markdown:null,
  body_html:typeof value.body_html==='string'&&Buffer.byteLength(value.body_html)<=65536?value.body_html:null,
  headers_raw:typeof value.headers_raw==='string'&&Buffer.byteLength(value.headers_raw)<=2048?value.headers_raw:null};
 if(out.body_markdown===null||out.body_html===null||out.headers_raw===null)throw fail('INVALID_ARGUMENT');
 if(value.threadId!==undefined)out.threadId=positive(value.threadId);
 return Object.freeze(out);
}
function source(value){
 if(!own(value,['messageId','messageSha256','recipientId']))throw fail('INVALID_ARGUMENT');
 return Object.freeze({messageId:positive(value.messageId),messageSha256:hash(value.messageSha256),recipientId:positive(value.recipientId)});
}
function output(value){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||!own(value,['issuanceId','sendOperationId','targetId','messageId','messageSha256','threadId','recipientId','listenerTargetId','nonceSha256','path','resourceKind','urlSha256']))throw fail('MAIL_INLINE_BINDING_INVALID');
 const b=reservation({issuanceId:value.issuanceId,listenerTargetId:value.listenerTargetId,nonceSha256:value.nonceSha256,path:value.path,resourceKind:value.resourceKind,urlSha256:value.urlSha256});
 return Object.freeze({...b,sendOperationId:id(value.sendOperationId),targetId:id(value.targetId),messageId:positive(value.messageId),
  messageSha256:hash(value.messageSha256),threadId:positive(value.threadId),recipientId:positive(value.recipientId)});
}
function exact(value,keys){return value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));}
function frozenText(value,max){return text(value,max);}
function invocation(value){
 if(!exact(value,['version','binding','source','targetReceipt','runId','ownerKey','generation','sessionId',
  'summaryRequestId','callId','effectKey','parsedResultSha256','observationSha256'])||value.version!==1)throw fail('MAIL_INLINE_INVOCATION_INVALID');
 const binding=output(value.binding);
 if(!exact(value.source,['readOperationId','receiptSha256','bodyHtmlSha256'])
  ||!exact(value.targetReceipt,['version','issuanceId','sendOperationId','targetId','listenerTargetId','nonceSha256',
   'path','resourceKind','urlSha256','method','status','responseSha256','receiptSha256'])
  ||value.targetReceipt.version!==1||value.targetReceipt.method!=='GET'||value.targetReceipt.status!==200
  ||value.targetReceipt.issuanceId!==binding.issuanceId||value.targetReceipt.sendOperationId!==binding.sendOperationId
  ||value.targetReceipt.targetId!==binding.targetId||value.targetReceipt.listenerTargetId!==binding.listenerTargetId
  ||value.targetReceipt.nonceSha256!==binding.nonceSha256||value.targetReceipt.path!==binding.path
  ||value.targetReceipt.resourceKind!==binding.resourceKind||value.targetReceipt.urlSha256!==binding.urlSha256)
  throw fail('MAIL_INLINE_INVOCATION_INVALID');
 const source=Object.freeze({readOperationId:id(value.source.readOperationId),receiptSha256:hash(value.source.receiptSha256),bodyHtmlSha256:hash(value.source.bodyHtmlSha256)});
 const targetReceipt=Object.freeze({...value.targetReceipt,responseSha256:hash(value.targetReceipt.responseSha256),receiptSha256:hash(value.targetReceipt.receiptSha256)});
 const generation=typeof value.generation==='string'&&/^(0|[1-9]\d{0,15})$/.test(value.generation)&&Number.isSafeInteger(Number(value.generation))?value.generation:null;
 if(!generation||!CALL.test(value.callId)||typeof value.effectKey!=='string'||!value.effectKey||Buffer.byteLength(value.effectKey)>1024)throw fail('MAIL_INLINE_INVOCATION_INVALID');
 return Object.freeze({version:1,binding,source,targetReceipt,runId:id(value.runId),ownerKey:frozenText(value.ownerKey,1024),generation,
  sessionId:id(value.sessionId),summaryRequestId:id(value.summaryRequestId),callId:value.callId,effectKey:value.effectKey,
  parsedResultSha256:hash(value.parsedResultSha256),observationSha256:hash(value.observationSha256)});
}
function createSecureShopMailInlineBindingRepository({pool,personaAuthority,verifyPendingReservation}={}){
 if(typeof pool?.connect!=='function'||typeof personaAuthority?.capture!=='function'||typeof verifyPendingReservation!=='function')throw TypeError('Mail inline binding dependencies required');
 async function withCurrent(raw,work){
 const b=copyBinding(raw),fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  // V55 is a merchant-owned Inbox teaching-message flow. Keep its private
  // reservation and later retained read unavailable to other Mail roles.
  if(b.persona.role!=='merchant')throw fail('SHOP_AUTH_INVALID');
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
  if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function'||!fence.binding
   ||Object.keys(expected).some(key=>fence.binding[key]!==expected[key]))throw fail('SHOP_AUTH_INVALID');
  return mailScene.withLease(b,async()=>{
   try{return await fence.withPersonaEffect(async client=>{
    await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
    await mailScene.assertGrant(client,b);
    const result=await work(client,b);
    await mailScene.assertGrant(client,b);
    return result;
   });}finally{await fence.assertRemoteAdmission();}
  });
 }
 async function saveTeachingMessage(raw,{reservation:pending,payload:mail}={}){
  const r=reservation(pending),p=payload(mail);
  return withCurrent(raw,async(client,b)=>{
   // The opaque listener capability is server-held. A well-formed descriptor
   // supplied from another target, after activation, or from a caller cache is
   // not sufficient to attach an inline source to an immutable mail receipt.
   const held=reservation(await verifyPendingReservation(b,r));
   if(!sameReservation(held,r))throw fail('MAIL_INLINE_BINDING_INVALID');
   const s=b.scope,scene=mailScene.productScene(b);if(!scene)throw fail('MAIL_SCENE_STALE');
   const row=(await client.query(`SELECT secureshop_agents.save_bound_mail_inline(
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16,$17::bytea,$18,$19,$20::bytea
   ) AS result`,[b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,b.persona.id,
    b.personaSession.sessionId,b.persona.role,b.personaSession.authorityVersion,b.mode,b.operationId,scene.scene.grantId,
    JSON.stringify(p),r.issuanceId,r.listenerTargetId,Buffer.from(r.nonceSha256,'hex'),r.path,r.resourceKind,Buffer.from(r.urlSha256,'hex')])).rows[0]?.result;
   if(!row||Object.getPrototypeOf(row)!==Object.prototype||!own(row,['send','binding'])||!row.send||typeof row.send!=='object'
    ||row.send.operationId!==b.operationId||typeof row.send.replayed!=='boolean')throw fail('MAIL_INLINE_BINDING_INVALID');
   const binding=output(row.binding),receipt=row.send.receipt;
   if(!receipt||Object.getPrototypeOf(receipt)!==Object.prototype
    ||!Number.isSafeInteger(receipt.email_id)||!Number.isSafeInteger(receipt.thread_id)
    ||!Number.isSafeInteger(receipt.recipientId)||typeof receipt.contentSha256!=='string')throw fail('MAIL_INLINE_BINDING_INVALID');
   if(binding.targetId!==b.targetId||binding.sendOperationId!==b.operationId||binding.issuanceId!==r.issuanceId
    ||binding.listenerTargetId!==r.listenerTargetId||binding.nonceSha256!==r.nonceSha256||binding.path!==r.path
    ||binding.resourceKind!==r.resourceKind||binding.urlSha256!==r.urlSha256||binding.messageId!==receipt.email_id
    ||binding.threadId!==receipt.thread_id||binding.recipientId!==receipt.recipientId||binding.messageSha256!==receipt.contentSha256)
    throw fail('MAIL_INLINE_BINDING_INVALID');
   return Object.freeze({send:Object.freeze(row.send),binding});
  });
 }
 async function readBound(raw,selected){
  const s=source(selected);
  return withCurrent(raw,async(client,b)=>{
   const e=b.scope,scene=mailScene.productScene(b);if(!scene)throw fail('MAIL_SCENE_STALE');
   const row=(await client.query(`SELECT secureshop_agents.read_bound_mail_inline_binding(
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::bytea,$14
   ) AS result`,[b.targetId,e.launchId,e.scenarioId,e.generation,e.platformOwnerId,e.platformSessionId,b.persona.id,
    b.personaSession.sessionId,b.persona.role,b.personaSession.authorityVersion,scene.scene.grantId,s.messageId,
    Buffer.from(s.messageSha256,'hex'),s.recipientId])).rows[0]?.result;
   if(row===null||row===undefined)return null;
   const binding=output(row);
   if(binding.targetId!==b.targetId||binding.messageId!==s.messageId||binding.messageSha256!==s.messageSha256||binding.recipientId!==s.recipientId)throw fail('MAIL_INLINE_BINDING_INVALID');
   return binding;
  });
 }
 async function recordInvocation(raw,candidate){
  const record=invocation(candidate);
  return withCurrent(raw,async(client,b)=>{
   if(b.operationId!==record.summaryRequestId)throw fail('MAIL_INLINE_INVOCATION_INVALID');
   const s=b.scope,scene=mailScene.productScene(b);if(!scene)throw fail('MAIL_SCENE_STALE');
   const q=`SELECT secureshop_agents.record_bound_mail_inline_http_invocation(
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::bytea,$21::bytea,
    $22,$23,$24,$25::bytea,$26,$27,$28,$29::bytea,$30,$31,$32::bytea,$33::bytea,$34::bytea,$35::bytea,$36::bytea
   ) AS result`;
   const row=(await client.query(q,[b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,b.persona.id,
    b.personaSession.sessionId,b.persona.role,b.personaSession.authorityVersion,scene.scene.grantId,
    record.summaryRequestId,record.runId,record.ownerKey,Number(record.generation),record.sessionId,record.callId,record.effectKey,
    record.source.readOperationId,Buffer.from(record.source.receiptSha256,'hex'),Buffer.from(record.source.bodyHtmlSha256,'hex'),
    record.binding.issuanceId,record.binding.sendOperationId,record.binding.messageId,Buffer.from(record.binding.messageSha256,'hex'),
    record.binding.threadId,record.binding.recipientId,record.binding.listenerTargetId,Buffer.from(record.binding.nonceSha256,'hex'),
    record.binding.path,record.binding.resourceKind,Buffer.from(record.binding.urlSha256,'hex'),
    Buffer.from(record.targetReceipt.receiptSha256,'hex'),Buffer.from(record.targetReceipt.responseSha256,'hex'),
    Buffer.from(record.parsedResultSha256,'hex'),Buffer.from(record.observationSha256,'hex')])).rows[0]?.result;
   const saved=invocation(row);if(!isDeepStrictEqual(saved,record))throw fail('MAIL_INLINE_RECORD_UNCERTAIN');
   return saved;
  });
 }
 async function readInvocation(raw,{summaryRequestId}={}){
  const expected=id(summaryRequestId);
  return withCurrent(raw,async(client,b)=>{
   if(b.operationId!==expected)throw fail('MAIL_INLINE_INVOCATION_INVALID');
   const s=b.scope,scene=mailScene.productScene(b);if(!scene)throw fail('MAIL_SCENE_STALE');
   const row=(await client.query(`SELECT secureshop_agents.read_bound_mail_inline_http_invocation(
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
   ) AS result`,[b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,b.persona.id,
    b.personaSession.sessionId,b.persona.role,b.personaSession.authorityVersion,scene.scene.grantId,expected])).rows[0]?.result;
   return row===null||row===undefined?null:invocation(row);
  });
 }
 return Object.freeze({saveTeachingMessage,readBound,recordInvocation,readInvocation});
}
module.exports={createSecureShopMailInlineBindingRepository};
