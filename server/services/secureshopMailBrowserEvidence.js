'use strict';
const {createHash}=require('node:crypto');
const OBJECTIVE='ss_mail_stored_browser_execution';
const SHA=/^[a-f0-9]{64}$/;
const hash=value=>createHash('sha256').update(value).digest('hex');
const MAIL_BROWSER_RUBRIC=Object.freeze({family:'SecureShop',scenario:'bound_mail_browser',objectiveId:OBJECTIVE,version:'secureshop-mail-browser-v1',outcomeIntent:'attack',requiredFacts:['owned_saved_mail','actual_inbox_component','attributed_browser_execution','completed_browser_effect','vulnerable_mode'],criteria:[{id:'persisted_mail_executed',allowedSources:['server_observation'],description:'The exact persisted HTML of a learner-sent message was mounted through the actual shared SecureShop Inbox React message component and produced an attributed observable browser effect in the isolated browser. Stored markup, claimed markers, surrogate HTML renderers, foreign or stale mail, and inert fixed-mode content do not establish execution. This is a manual stored-browser lesson, not evidence that an actor model selected a tool.'}]});
function createMailBrowserEvidenceRepository({savedMailEvidence}={}){
 if(typeof savedMailEvidence?.readHeader!=='function')throw TypeError('Saved mail evidence required');
 return Object.freeze({async readBrowser(binding,messageId){
  if(!Number.isSafeInteger(messageId)||messageId<1)throw TypeError('Message identifier required');
  const observed=await savedMailEvidence.readHeader(binding);
  if(observed.receipt?.email_id!==messageId||typeof observed.payload?.body_html!=='string'||Buffer.byteLength(observed.payload.body_html)>20000)throw Object.assign(Error('Mail browser source unavailable'),{code:'MAIL_EVIDENCE_UNAVAILABLE'});
  return structuredClone(observed);
 }});
}
function buildMailBrowserCandidate(observed,effect,execution){
 const b=observed?.binding,r=effect?.receipt,v=effect?.value,c=v?.component;
 if(b?.mode!=='vuln'||!observed.payload?.body_html||!SHA.test(observed.requestSha256||'')||!SHA.test(observed.receipt?.contentSha256||'')
  ||r?.version!==1||r.status!=='completed'||r.runId!==execution?.runId||r.ownerKey!==execution?.ownerKey||String(r.generation)!==String(execution?.durableGeneration)||r.effectKey!==execution?.effectKey
  ||c?.id!=='SecureShop.MailMessageBody'||!SHA.test(c.sourceSha256||'')||!SHA.test(c.artifactSha256||''))return null;
 const executed=v.executed===true&&v.targetEventExecuted===true&&v.targetEffectObserved===true&&v.syntheticCookieOnly===true&&v.finalCookieIsSyntheticOnly===true&&Array.isArray(v.markers)&&v.markers.length>0;
 const candidate={facts:{owned_saved_mail:true,actual_inbox_component:true,attributed_browser_execution:executed,completed_browser_effect:true,vulnerable_mode:true},evidence:[{id:'mail_browser',source:'server_observation',content:{version:1,binding:b,sendReceipt:observed.receipt,requestSha256:observed.requestSha256,htmlSha256:hash(observed.payload.body_html),component:c,browser:{executed:v.executed===true,targetEventExecuted:v.targetEventExecuted===true,targetEffectObserved:v.targetEffectObserved===true,syntheticCookieOnly:v.syntheticCookieOnly===true,finalCookieIsSyntheticOnly:v.finalCookieIsSyntheticOnly===true,markers:structuredClone(v.markers||[])},effectReceipt:r}}]};
 try{if(require('../agent-runtime/objectiveJudge').prepareJudgeInput({rubric:{...MAIL_BROWSER_RUBRIC,mode:b.mode},...candidate}).evidenceError)return null;}catch{return null;}
 return candidate;
}
module.exports={OBJECTIVE,MAIL_BROWSER_RUBRIC,createMailBrowserEvidenceRepository,buildMailBrowserCandidate};
