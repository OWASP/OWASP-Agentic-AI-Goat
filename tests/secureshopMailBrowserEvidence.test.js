'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const {createMailBrowserEvidenceRepository,buildMailBrowserCandidate}=require('../server/services/secureshopMailBrowserEvidence');
const sha='a'.repeat(64),observed={binding:{mode:'vuln'},receipt:{email_id:3,contentSha256:sha},requestSha256:sha,payload:{body_html:'<b>mail</b>'}};
const execution={runId:'run',ownerKey:'owner',durableGeneration:2,effectKey:'request:mail-browser:3'};
const effect={receipt:{version:1,status:'completed',runId:'run',ownerKey:'owner',generation:2,effectKey:execution.effectKey},value:{component:{id:'SecureShop.MailMessageBody',sourceSha256:sha,artifactSha256:sha},executed:true,targetEventExecuted:true,targetEffectObserved:true,syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,markers:['controlled']}};
test('saved source exact identifier and byte cap; no caller HTML substitution',async()=>{
 const reader=createMailBrowserEvidenceRepository({savedMailEvidence:{readHeader:async()=>observed}});assert.deepEqual(await reader.readBrowser({},3),observed);await assert.rejects(reader.readBrowser({},4));await assert.rejects(reader.readBrowser({},'3'));
 const large=createMailBrowserEvidenceRepository({savedMailEvidence:{readHeader:async()=>({...observed,payload:{body_html:'x'.repeat(20001)}})}});await assert.rejects(large.readBrowser({},3));
});
test('controlled browser effect creates candidate only with exact component and owned completed receipt',()=>{
 assert.ok(buildMailBrowserCandidate(observed,effect,execution));
 for(const change of [{runId:'other'},{ownerKey:'other'},{generation:3},{status:'pending'},{effectKey:'other'}])assert.equal(buildMailBrowserCandidate(observed,{...effect,receipt:{...effect.receipt,...change}},execution),null);
 assert.equal(buildMailBrowserCandidate(observed,{...effect,value:{...effect.value,component:{...effect.value.component,id:'surrogate'}}},execution),null);
 assert.equal(buildMailBrowserCandidate({...observed,binding:{mode:'fixed'}},effect,execution),null);
});
test('claimed marker without independently attributed effect cannot satisfy execution fact',()=>{
 for(const key of ['executed','targetEventExecuted','targetEffectObserved','syntheticCookieOnly','finalCookieIsSyntheticOnly']){
  const result=buildMailBrowserCandidate(observed,{...effect,value:{...effect.value,[key]:false}},execution);assert.equal(result.facts.attributed_browser_execution,false);
 }
});
test('released browser objective still requires real catalog, transport and Judge gates',()=>{
 const {mailObjectiveReadiness}=require('../server/services/secureshopMailObjectiveReadiness');const target='ss_mail_stored_browser_execution';const ready={transportReady:true,judgeReady:true,catalog:{[target]:true}};assert.equal(mailObjectiveReadiness(ready)[target],true);for(const change of [{catalog:{}},{transportReady:false},{judgeReady:false}])assert.equal(mailObjectiveReadiness({...ready,...change})[target],false);
});
