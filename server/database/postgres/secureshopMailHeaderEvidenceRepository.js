'use strict';
const {normalize}=require('./secureshopBoundMailRepository');
const mailScene=require('../../services/secureshopMailSceneBinding');
const unavailable=()=>Object.assign(Error('Canonical saved mail header unavailable'),{code:'MAIL_EVIDENCE_UNAVAILABLE'});
// Read through the existing authority-bearing SQL API; private message tables
// remain inaccessible to the runtime role. No new snapshot receipt is created.
function createMailHeaderEvidenceRepository({personaAuthority,mailRepository}={}){
 if(typeof personaAuthority?.capture!=='function'||['recover','browse'].some(k=>typeof mailRepository?.[k]!=='function'))throw TypeError('Header evidence dependencies required');
 return Object.freeze({async readHeader(raw){
  const binding=normalize(raw),b=binding;
  return mailScene.withLease(b,async()=>{
  const fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
  if(!fence?.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k])||b.mode!=='vuln')throw unavailable();
  await fence.assertRemoteAdmission();
  const recovered=await mailRepository.recover(b),receipt=recovered?.receipt;
  if(recovered?.found!==true||recovered.action!=='send'||recovered.operationId!==b.operationId||receipt?.senderId!==b.persona.id
   ||!Number.isSafeInteger(receipt.recipientId)||receipt.recipientId<1||!Number.isSafeInteger(receipt.email_id)||!Number.isSafeInteger(receipt.thread_id))throw unavailable();
  const snapshot=await mailRepository.browse(b,receipt.recipientId);
  const rows=snapshot?.emails?.filter(row=>row.id===receipt.email_id);
  if(rows?.length!==1||rows[0].thread_id!==receipt.thread_id)throw unavailable();
  const row=rows[0];
  if(['from_addr','to_addr','subject','body_markdown','body_html','headers_raw'].some(k=>typeof row[k]!=='string'))throw unavailable();
  const payload={from:row.from_addr,to:row.to_addr,subject:row.subject,body_markdown:row.body_markdown,body_html:row.body_html,headers_raw:row.headers_raw};
  if(payload.headers_raw!==`From: ${payload.from}\r\nTo: ${payload.to}\r\nSubject: ${payload.subject}`)throw unavailable();
  // The original request may have created a thread or appended to one. Exactly
  // one reconstructed payload must match BOTH immutable SQL-native hashes.
  const candidates=[payload,{...payload,threadId:row.thread_id}];
  const matches=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   await mailScene.assertGrant(client,b);
   const rows=(await client.query(`SELECT value AS payload FROM jsonb_array_elements($1::jsonb)
    WHERE encode(sha256(convert_to(value::text,'UTF8')),'hex')=$2
    AND encode(sha256(convert_to(jsonb_build_array('send',value)::text,'UTF8')),'hex')=$3`,
    [JSON.stringify(candidates),receipt.contentSha256,recovered.requestSha256])).rows;
   await mailScene.assertGrant(client,b);
   return rows;
  });
  if(matches.length!==1)throw unavailable();
  await fence.assertRemoteAdmission();
  return Object.freeze({binding,receipt:structuredClone(receipt),requestSha256:recovered.requestSha256,payload:structuredClone(matches[0].payload)});
  });
 }});
}
module.exports={createMailHeaderEvidenceRepository};
