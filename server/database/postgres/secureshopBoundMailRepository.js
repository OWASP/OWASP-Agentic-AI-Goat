'use strict';
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const mailScene=require('../../services/secureshopMailSceneBinding');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=code=>Object.assign(new Error('Bound lab mail unavailable'),{code});
function id(value){if(typeof value!=='string'||!UUID.test(value))throw fail('INVALID_ARGUMENT');return value.toLowerCase();}
function text(value,max,empty=false){if(typeof value!=='string'||(!empty&&!value.length)||Buffer.byteLength(value)>max)throw fail('INVALID_ARGUMENT');return value;}
function positive(value){if(!Number.isSafeInteger(value)||value<1||value>2147483647)throw fail('INVALID_ARGUMENT');return value;}
function plain(value,allowed){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).some(k=>!allowed.includes(k)))throw fail('INVALID_ARGUMENT');return value;}
function normalize(raw){
 plain(raw,['scope','targetId','target','persona','personaSession','mode','operationId']);
 const scope=createLaunchScope(raw.scope),targetId=id(raw.targetId),operationId=id(raw.operationId);
 if(raw.target!==undefined&&id(raw.target?.targetId)!==targetId)throw fail('INVALID_ARGUMENT');
 const persona=plain(raw.persona,['id','role']),session=plain(raw.personaSession,['sessionId','authorityVersion']);
 if(!['customer','merchant','admin'].includes(persona.role)||!['vuln','fixed'].includes(raw.mode)
  ||typeof session.authorityVersion!=='string'||! /^[1-9]\d{0,15}$/.test(session.authorityVersion)||!Number.isSafeInteger(Number(session.authorityVersion)))throw fail('INVALID_ARGUMENT');
 const normalized={scope,targetId,...(raw.target===undefined?{}:{target:raw.target}),operationId,
  persona:{id:positive(persona.id),role:persona.role},
  personaSession:{sessionId:id(session.sessionId),authorityVersion:session.authorityVersion},mode:raw.mode};
 return mailScene.copy(raw.target||raw,normalized);
}
// @intentional-vulnerability html-injection
// @intentional-vulnerability xss-stored-email
// A bounded lab-only renderer preserves raw markup in vulnerable mode.
function renderMail(source){return source.split(/\n\s*\n/).map(block=>/^\s*</.test(block)?block:`<p>${block.replace(/\n/g,'<br>')}</p>`).join('\n');}
function prepareSend(input){
 plain(input,['from','to','subject','body_markdown','threadId']);
 const from=text(input.from,512),to=text(input.to,512),subject=text(input.subject,512),body=text(input.body_markdown,32768,true);
 // @intentional-vulnerability email-header-injection: retain CRLF in owned stored headers.
 const headers=`From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}`;
 return {from,to,subject,body_markdown:body,body_html:text(renderMail(body),65536,true),headers_raw:text(headers,2048),
  ...(input.threadId===undefined?{}:{threadId:positive(input.threadId)})};
}
function validateExpectedSource(value){
 if(value===undefined)return null;
 plain(value,['threadId','messageId','sha256']);
 const threadId=positive(value.threadId),messageId=positive(value.messageId);
 if(typeof value.sha256!=='string'||! /^[0-9a-f]{64}$/.test(value.sha256))throw fail('INVALID_ARGUMENT');
 return {threadId,messageId,sha256:value.sha256};
}
function createBoundMailRepository({pool,personaAuthority,checkCleanup}={}){
 if(typeof pool?.query!=='function'||typeof personaAuthority?.capture!=='function'||typeof checkCleanup!=='function')throw TypeError('Bound mail dependencies required');
 async function execute(raw,action,payload,{expectedSource}={}){
  const source=action==='send'?validateExpectedSource(expectedSource):null;
  if(action!=='send'&&expectedSource!==undefined)throw fail('INVALID_ARGUMENT');
  if(source&&payload.threadId!==source.threadId)throw fail('INVALID_ARGUMENT');
  const b=normalize(raw),fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
  if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function'||!fence.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k]))throw fail('SHOP_AUTH_INVALID');
  return mailScene.withLease(b,async()=>{const observed=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   await mailScene.assertGrant(client,b);
   const s=b.scope;
   const scene=mailScene.productScene(b);
   const call=async(requestAction,requestPayload)=>
    (await client.query(`SELECT secureshop_agents.bound_lab_mail($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb${scene?',$15::uuid':''}) AS result`,
    [b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,b.persona.id,b.personaSession.sessionId,
     b.persona.role,b.personaSession.authorityVersion,b.mode,b.operationId,requestAction,JSON.stringify(requestPayload),
     ...(scene?[scene.scene.grantId]:[])])).rows[0]?.result;
   if(source){
    // bound_lab_mail holds the target FOR UPDATE through this whole persona
    // transaction. A committed replay wins before source freshness is tested.
    const prior=await call('recover',{});
    if(!prior||typeof prior.found!=='boolean')throw fail('MAIL_RECEIPT_INVALID');
    if(!prior.found){
     const browse=await call('browse',{userId:b.persona.id});
     if(browse?.ok!==true||browse.receipt?.userId!==b.persona.id
      ||!Array.isArray(browse.emails)||!Array.isArray(browse.receipt.messages))throw fail('MAIL_RECEIPT_INVALID');
     const latest=browse.emails.filter(message=>message.thread_id===source.threadId).at(-1);
     const member=browse.receipt.messages.find(message=>message.id===latest?.id);
     if(!latest||latest.id!==source.messageId||member?.sha256!==source.sha256)
      throw Object.assign(fail('MAIL_SOURCE_STALE'),{executionBoundary:true});
    }
   }
   // Even for a prior receipt, send checks the original request hash. Never
   // claim this proposal caused a direct-route operation with different bytes.
   const result=await call(action,payload);
   if(!result||typeof result!=='object'||(action==='recover'?typeof result.found!=='boolean':result.ok!==true))throw fail('MAIL_RECEIPT_INVALID');
   if(action!=='recover'&&(result.operationId!==b.operationId||typeof result.replayed!=='boolean'||!result.receipt
     ||(action==='send'&&(!Number.isSafeInteger(result.email_id)||result.email_id<1||result.email_id!==result.receipt.email_id
       ||!Number.isSafeInteger(result.thread_id)||result.thread_id<1||result.thread_id!==result.receipt.thread_id))
     ||(['read','browse'].includes(action)&&(!Array.isArray(result.emails)||result.receipt.userId!==payload.userId))))throw fail('MAIL_RECEIPT_INVALID');
   if(action==='recover'&&result.found&&(result.operationId!==b.operationId||!['send','read'].includes(result.action)
     ||!result.receipt||! /^[0-9a-f]{64}$/.test(result.requestSha256)))throw fail('MAIL_RECEIPT_INVALID');
   await mailScene.assertGrant(client,b);
   return Object.freeze(result);
  });
  // The agents transaction may serialize before retirement while identity has
  // already begun reset. Never return its now-stale saved/read result as current.
  await fence.assertRemoteAdmission();
  return observed;});
 }
 return Object.freeze({
  send:(binding,input,options)=>execute(binding,'send',prepareSend(input),options),
  read:(binding,userId)=>execute(binding,'read',{userId:positive(userId)}),
  browse:(binding,userId)=>execute(binding,'browse',{userId:positive(userId)}),
  recover:binding=>execute(binding,'recover',{}),
  async hashSendRequest(raw,input){
   const payload=prepareSend(input),b=normalize(raw),scene=mailScene.productScene(b);
   if(!scene)throw fail('MAIL_RECEIPT_INVALID');
   const fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,
    role:b.persona.role,...b.personaSession});
   const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
   if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function'
    ||!fence.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k]))throw fail('SHOP_AUTH_INVALID');
   return mailScene.withLease(b,async()=>{
    const digest=await fence.withPersonaEffect(async client=>{
     await client.query("SET LOCAL statement_timeout='3000ms'");
     await client.query("SET LOCAL lock_timeout='3000ms'");
     await mailScene.assertGrant(client,b);
     // This is the same normalized JSONB request hash used by bound_lab_mail.
     // It reads no message and never invokes the send action.
     const row=(await client.query(`SELECT encode(sha256(convert_to(jsonb_build_array('send',
       CASE WHEN $2='fixed' THEN jsonb_set(
         jsonb_set($1::jsonb,'{headers_raw}',to_jsonb('From: '||($1::jsonb->>'from')||chr(13)||chr(10)||
           'To: '||($1::jsonb->>'to')||chr(13)||chr(10)||'Subject: '||($1::jsonb->>'subject'))),
         '{body_html}',to_jsonb('<pre>'||replace(replace(replace($1::jsonb->>'body_markdown','&','&amp;'),'<','&lt;'),'>','&gt;')||'</pre>'))
       ELSE jsonb_set($1::jsonb,'{headers_raw}',to_jsonb('From: '||($1::jsonb->>'from')||chr(13)||chr(10)||
         'To: '||($1::jsonb->>'to')||chr(13)||chr(10)||'Subject: '||($1::jsonb->>'subject'))) END
       )::text,'UTF8')),'hex') AS request_sha256`,[JSON.stringify(payload),b.mode])).rows[0];
     if(typeof row?.request_sha256!=='string'||! /^[0-9a-f]{64}$/.test(row.request_sha256))
      throw fail('MAIL_RECEIPT_INVALID');
     await mailScene.assertGrant(client,b);return row.request_sha256;
    });
    await fence.assertRemoteAdmission();return digest;
   });
  },
  async projectRead(raw,{messageId=null,offset=0}={}){
   const b=normalize(raw),scene=mailScene.productScene(b);
   if(!scene||!(messageId===null||Number.isSafeInteger(messageId)&&messageId>0)
    ||!Number.isSafeInteger(offset)||offset<0||offset>1020||offset%5!==0)throw fail('INVALID_ARGUMENT');
   const fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,
    role:b.persona.role,...b.personaSession});
   const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
   if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function'
    ||!fence.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k]))throw fail('SHOP_AUTH_INVALID');
   return mailScene.withLease(b,async()=>{
    const projected=await fence.withPersonaEffect(async client=>{
     await client.query("SET LOCAL statement_timeout='3000ms'");
     await client.query("SET LOCAL lock_timeout='3000ms'");
     await mailScene.assertGrant(client,b);
     const s=b.scope;
     const result=(await client.query(`SELECT secureshop_agents.project_bound_lab_mail_read(
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) AS projected`,
      [b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,
       b.persona.id,b.personaSession.sessionId,b.persona.role,b.personaSession.authorityVersion,
       b.mode,b.operationId,scene.scene.grantId,messageId,offset])).rows[0]?.projected;
     if(!result||typeof result!=='object'||!['page','detail'].includes(result.kind)
      ||result.readOperationId!==b.operationId||! /^[0-9a-f]{64}$/.test(result.receiptSha256||''))
      throw fail('MAIL_RECEIPT_INVALID');
     await mailScene.assertGrant(client,b);return Object.freeze(result);
    });
    await fence.assertRemoteAdmission();return projected;
   });
  },
  async readSavedSend(raw){
   const b=normalize(raw),fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,
    role:b.persona.role,...b.personaSession});
   const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
   if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function'
    ||!fence.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k]))throw fail('SHOP_AUTH_INVALID');
   return mailScene.withLease(b,async()=>{
    const saved=await fence.withPersonaEffect(async client=>{
     await client.query("SET LOCAL statement_timeout='3000ms'");
     await client.query("SET LOCAL lock_timeout='3000ms'");
     await mailScene.assertGrant(client,b);
     const s=b.scope,scene=mailScene.productScene(b);
     if(!scene)throw fail('MAIL_RECEIPT_INVALID');
     const result=(await client.query(`SELECT secureshop_agents.project_bound_lab_mail_send(
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) AS saved`,
      [b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,
       b.persona.id,b.personaSession.sessionId,b.persona.role,b.personaSession.authorityVersion,
       b.mode,b.operationId,scene.scene.grantId])).rows[0]?.saved;
     if(result===null||result===undefined)return null;
     if(typeof result!=='object'||!Number.isSafeInteger(result.recipientId)
      ||result.recipientId<1||typeof result.to!=='string'
      ||typeof result.subject!=='string'||typeof result.body_markdown!=='string'
      ||Object.keys(result).sort().join(',')!=='body_markdown,recipientId,subject,to')
      throw fail('MAIL_RECEIPT_INVALID');
     await mailScene.assertGrant(client,b);
     return Object.freeze(result);
    });
    await fence.assertRemoteAdmission();
    return saved;
   });
  },
  async verifyCleanup(raw,operationId){
   const scope=createLaunchScope(raw),targetId=id(raw.targetId),operation=id(operationId);
   await checkCleanup({...scope,targetId,operationId:operation});
   const result=(await pool.query('SELECT secureshop_agents.verify_bound_lab_mail_cleanup($1,$2) AS result',[targetId,operation])).rows[0]?.result;
   if(!result||typeof result.provisioned!=='boolean'||(result.provisioned&&(result.targetId!==targetId||result.operationId!==operation
    ||!Number.isSafeInteger(result.deletedMessageCount)||!Number.isSafeInteger(result.retainedOperationCount)
    ||! /^[0-9a-f]{64}$/.test(result.evidenceSha256)||! /^[0-9a-f]{64}$/.test(result.receiptSha256))))throw fail('MAIL_CLEANUP_MISMATCH');
   return Object.freeze(result);
  },
 });
}
module.exports={createBoundMailRepository,prepareSend,renderMail,normalize};
