'use strict';
const {isDeepStrictEqual}=require('node:util');
const {captureFeatureMode,projectFeatureMode}=require('./secureshopFeatureModeAuthority');

const SHA=/^[0-9a-f]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES=new Set(['customer','merchant','admin']);
const fail=(code='ROLE_MAIL_INVALID')=>Object.assign(Error('Merchant mail inspection unavailable'),{code});
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');
const bytes=value=>Buffer.byteLength(value,'utf8');
const bounded=(value,max,allowEmpty=false)=>typeof value==='string'&&(allowEmpty||value.length>0)&&bytes(value)<=max;
const positive=value=>Number.isSafeInteger(value)&&value>0;
function recipient(value){return exact(value,['id','username','email','role'])&&positive(value.id)&&value.id<=2147483647
 &&bounded(value.username,256)&&bounded(value.email,512)&&ROLES.has(value.role);}
function mode(value){return exact(value,['version','featureId','policyVersion','effectiveMode','scope'])
 &&value.version===1&&value.featureId==='mail'
 &&value.policyVersion==='owned-mail-recipient-header-and-html-v1'
 &&['vuln','fixed'].includes(value.effectiveMode)
 &&exact(value.scope,['kind','id'])&&value.scope.kind==='launch_feature'&&value.scope.id==='mail';}
function header(value){return exact(value,['id','threadId','from','to','subject','createdAt','sha256'])
 &&positive(value.id)&&positive(value.threadId)&&bounded(value.from,512)
 &&bounded(value.to,512)&&bounded(value.subject,512)
 &&typeof value.createdAt==='string'&&Number.isFinite(Date.parse(value.createdAt))
 &&SHA.test(value.sha256);}
function validateMailRecipientSnapshot(value){
 if(!recipient(value))throw fail('ROLE_MAIL_RECIPIENT_INVALID');return value;
}
function validateMailChatResult(value){
 if(!value||value.version!==1||!mode(value.mailModeCapability))throw fail();
 if(value.kind==='recipients'){
  if(!exact(value,['version','kind','recipients','hasMore','mailModeCapability'])
   ||!Array.isArray(value.recipients)||value.recipients.length>5
   ||value.recipients.some(row=>!recipient(row))
   ||new Set(value.recipients.map(row=>row.id)).size!==value.recipients.length
   ||typeof value.hasMore!=='boolean'||value.hasMore&&value.recipients.length!==5)throw fail();
  return value;
 }
 const base=['version','kind','readOperationId','mailModeCapability','receiptSha256','recipient'];
 if(!UUID.test(value.readOperationId||'')||!SHA.test(value.receiptSha256||'')
  ||!recipient(value.recipient))throw fail();
 if(value.kind==='list'){
  if(!exact(value,[...base,'offset','total','hasMore','headers'])
   ||!Number.isSafeInteger(value.offset)||value.offset<0||value.offset>1020||value.offset%5!==0
   ||!Number.isSafeInteger(value.total)||value.total<0||value.total>1024
   ||!Array.isArray(value.headers)||value.headers.length>5
   ||value.headers.some(row=>!header(row))
   ||new Set(value.headers.map(row=>row.id)).size!==value.headers.length
   ||typeof value.hasMore!=='boolean'||value.hasMore!==(value.offset+value.headers.length<value.total))throw fail();
  return value;
 }
 if(value.kind==='detail'){
  if(!exact(value,[...base,'messageId','messageSha256','status','message'])
   ||!positive(value.messageId)||!SHA.test(value.messageSha256||'')
   ||!['complete','oversized'].includes(value.status))throw fail();
  const message=value.message;
  // A saved answer may suppress a complete source when JSON escaping would
  // exceed the model observation budget. Its receipt-bound identity remains.
  if(message===null&&value.status==='oversized')return value;
  if(!message||!exact(message,['id','threadId','from','to','subject','createdAt','sha256',
   'bodyMarkdown','bodyHtml','headersRaw','sourceBytes','oversized'])
   ||!header(Object.fromEntries(Object.entries(message).filter(([key])=>
    ['id','threadId','from','to','subject','createdAt','sha256'].includes(key))))
   ||message.id!==value.messageId||message.sha256!==value.messageSha256
   ||!Number.isSafeInteger(message.sourceBytes)||message.sourceBytes<0||message.sourceBytes>100352
   ||message.oversized!==(value.status==='oversized'))throw fail();
  if(message.oversized){
   if(message.sourceBytes<=16384||message.bodyMarkdown!==null
    ||message.bodyHtml!==null||message.headersRaw!==null)throw fail();
  }else if(!bounded(message.bodyMarkdown,32768,true)
   ||!bounded(message.bodyHtml,65536,true)||!bounded(message.headersRaw,2048,true)
   ||bytes(message.bodyMarkdown)+bytes(message.bodyHtml)+bytes(message.headersRaw)!==message.sourceBytes
   ||message.sourceBytes>16384)throw fail();
  return value;
 }
 throw fail();
}
function createBoundMailChat({mailApplication,listMailActors,modeAuthority,mode:defaultMode='vuln'}={}){
 if(!['vuln','fixed'].includes(defaultMode)||typeof listMailActors!=='function'
  ||['readiness','disclose','projectDisclosure'].some(name=>typeof mailApplication?.[name]!=='function'))
  throw TypeError('Merchant mail read dependencies required');
 async function capture(context){
  if(context?.persona?.role!=='merchant'||!positive(context.persona.id))throw fail('SHOP_AUTH_INVALID');
  const token=await captureFeatureMode(modeAuthority,context.scope,'mail',defaultMode);
  await token.assertCurrent();return token;
 }
 async function current(token,expected){await token.assertCurrent();
  const projected=projectFeatureMode(token);
  if(expected&&!isDeepStrictEqual(projected,expected))throw fail('SECURESHOP_FEATURE_MODE_STALE');
  return projected;
 }
 async function actors(context,token){
  const rows=await listMailActors(context.scope);await token.assertCurrent();
  if(!Array.isArray(rows)||rows.length>128||rows.some(row=>!recipient(row))
   ||new Set(rows.map(row=>row.id)).size!==rows.length
   ||!rows.some(row=>row.id===context.persona.id))throw fail('ROLE_MAIL_RECIPIENT_INVALID');
  return rows;
 }
 async function projection(context,packet,{messageId=null,offset=0,signal,beforeEffect}={}){
  const token=await capture(context);validateMailChatResult(packet);
  await current(token,packet.mailModeCapability);
  signal?.throwIfAborted();await beforeEffect?.();await token.assertCurrent();
  const result=await mailApplication.projectDisclosure(context,{requestId:packet.readOperationId,messageId,offset},{signal});
  await current(token,result.mailModeCapability);signal?.throwIfAborted();
  if(result.readOperationId!==packet.readOperationId||result.recipientId!==packet.recipient.id
   ||result.receiptSha256!==packet.receiptSha256)throw fail('ROLE_MAIL_RECEIPT_MISMATCH');
  return result;
 }
 function listPacket(result,recipientRow,mailModeCapability){
  if(result.kind!=='page'||!Array.isArray(result.headers)||result.headers.length>5
   ||!Number.isSafeInteger(result.total)||result.total<0||result.total>1024
   ||!Number.isSafeInteger(result.offset)||result.offset<0||result.offset%5!==0
   ||!(result.nextOffset===null||result.nextOffset===result.offset+5))throw fail();
  return validateMailChatResult({version:1,kind:'list',readOperationId:result.readOperationId,
   mailModeCapability,receiptSha256:result.receiptSha256,recipient:recipientRow,
   offset:result.offset,total:result.total,hasMore:result.nextOffset!==null,headers:result.headers});
 }
 function detailPacket(result,packet){
  if(result.kind!=='detail'||!result.message)throw fail();
  return validateMailChatResult({version:1,kind:'detail',readOperationId:result.readOperationId,
   mailModeCapability:packet.mailModeCapability,receiptSha256:result.receiptSha256,
   recipient:packet.recipient,messageId:result.message.id,
   messageSha256:result.message.sha256,status:result.message.oversized?'oversized':'complete',
   message:result.message});
 }
 return Object.freeze({
  async recipients({context,search='',signal,beforeEffect}={}){
   if(!bounded(search,128,true))throw fail('INVALID_TOOL_ARGUMENTS');
   const token=await capture(context);signal?.throwIfAborted();
   await beforeEffect?.();await token.assertCurrent();
   const readiness=await mailApplication.readiness(context);
   if(readiness?.ready!==true)throw fail('MAIL_UNAVAILABLE');
   await current(token,readiness.modeCapability);
   await beforeEffect?.();await token.assertCurrent();
   const rows=await actors(context,token),needle=search.toLocaleLowerCase();
   const found=rows.filter(row=>[row.username,row.email,row.role].some(text=>text.toLocaleLowerCase().includes(needle)));
   return validateMailChatResult({version:1,kind:'recipients',recipients:found.slice(0,5),
    hasMore:found.length>5,mailModeCapability:await current(token)});
  },
  async list({context,recipient:chosen,requestId,mailModeCapability,signal,beforeEffect}={}){
   if(!UUID.test(requestId||''))throw fail('INVALID_TOOL_ARGUMENTS');
   const token=await capture(context);
   if(mailModeCapability!==undefined)await current(token,mailModeCapability);
   const rows=await actors(context,token);
   const selected=chosen===undefined||chosen===null
    ?rows.find(row=>row.id===context.persona.id)
    :rows.find(row=>isDeepStrictEqual(row,validateMailRecipientSnapshot(chosen)));
   if(!selected)throw fail('ROLE_MAIL_RECIPIENT_STALE');
   signal?.throwIfAborted();await beforeEffect?.();
   await current(token,mailModeCapability);
   const disclosure=await mailApplication.disclose(context,{requestId,userId:selected.id},{signal});
   await current(token,disclosure.mailModeCapability);
   if(mailModeCapability!==undefined)await current(token,mailModeCapability);
   if(disclosure?.receipt?.userId!==selected.id||!Array.isArray(disclosure.receipt.messages)
    ||disclosure.receipt.messages.length>1024)throw fail('ROLE_MAIL_RECEIPT_MISMATCH');
   // The read returned bodies for the existing Inbox route. Only the immutable
   // receipt and a protected five-header projection enter RoleChat state.
   const projected=await mailApplication.projectDisclosure(context,{requestId,offset:0},{signal});
   await current(token,projected.mailModeCapability);
   if(projected.recipientId!==selected.id||projected.total!==disclosure.receipt.messages.length
    ||projected.headers?.some((row,index)=>{
     const saved=disclosure.receipt.messages[disclosure.receipt.messages.length-1-index];
     return row.id!==saved?.id||row.sha256!==saved?.sha256;
    }))throw fail('ROLE_MAIL_RECEIPT_MISMATCH');
   return listPacket(projected,selected,await current(token));
  },
  async page({context,packet,offset,signal,beforeEffect}={}){
   if(packet?.kind!=='list'||!Number.isSafeInteger(offset)||offset!==packet.offset+5
    ||!packet.hasMore)throw fail('INVALID_TOOL_ARGUMENTS');
   const result=await projection(context,packet,{offset,signal,beforeEffect});
   return listPacket(result,packet.recipient,packet.mailModeCapability);
  },
  async detail({context,packet,messageId,signal,beforeEffect}={}){
   if(packet?.kind!=='list'||!positive(messageId))throw fail('INVALID_TOOL_ARGUMENTS');
   const result=await projection(context,packet,{messageId,signal,beforeEffect});
   if(result.message?.id!==messageId)throw fail('ROLE_MAIL_RECEIPT_MISMATCH');
   return detailPacket(result,packet);
  },
  async verify({context,packet,signal,beforeEffect}={}){
   validateMailChatResult(packet);
   if(packet.kind==='recipients'){
    const token=await capture(context);signal?.throwIfAborted();await beforeEffect?.();
    await current(token,packet.mailModeCapability);signal?.throwIfAborted();return packet;
   }
   const result=await projection(context,packet,{offset:packet.kind==='list'?packet.offset:0,
    messageId:packet.kind==='detail'?packet.messageId:null,signal,beforeEffect});
   const currentPacket=packet.kind==='list'
    ?listPacket(result,packet.recipient,packet.mailModeCapability):detailPacket(result,packet);
   if(packet.kind==='detail'&&packet.status==='oversized'&&packet.message===null){
    if(currentPacket.messageId!==packet.messageId||currentPacket.messageSha256!==packet.messageSha256
     ||currentPacket.receiptSha256!==packet.receiptSha256)throw fail('ROLE_MAIL_RECEIPT_MISMATCH');
    return packet;
   }
   if(!isDeepStrictEqual(currentPacket,packet))throw fail('ROLE_MAIL_RECEIPT_MISMATCH');
   return packet;
  },
 });
}
module.exports={createBoundMailChat,validateMailChatResult,validateMailRecipientSnapshot};
