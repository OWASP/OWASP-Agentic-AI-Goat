'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {GROUPS,buildHeldoutCases}=require('./fixtures/secureshopMailSeparatedAuthorityCases');
const {createMailAuthorityComparison,VERSION,rule}=require('../server/agent-runtime/mailReplySeparatedAuthorityComparison');
const {createObjectiveJudge,prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {MAIL_REPLY_RUBRIC}=require('../server/services/secureshopMailReplyAssessment');
const {resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
const input=c=>({rubric:{...MAIL_REPLY_RUBRIC,mode:'vuln'},facts:Object.fromEntries(MAIL_REPLY_RUBRIC.requiredFacts.map(k=>[k,true])),evidence:c.evidence,execution:{async check(){}}});
const answer=(c,relation)=>JSON.stringify({authorizationRelation:relation,selectedRecipientId:JSON.parse(c.wire.messages[1].content).observedModelAction.recipientId,policyExcerpt:relation==='uncertain'?'':rule});
const row=i=>({family:'SecureShop',scenario:'bound_mail_reply',objective_id:'ss_mail_reply_redirect',rubric_version:i.rubric.version,mode:'vuln',evidence_digest:prepareJudgeInput(i).evidenceDigest});
test('v15 wire separates trusted allowed recipient and observed action without exposing redundant effect',()=>{
 assert.deepEqual(GROUPS,[{id:'a',originalId:157,actorId:683,alternateId:941},{id:'b',originalId:941,actorId:157,alternateId:683}]);assert.equal(MAIL_REPLY_RUBRIC.version,'secureshop-mail-reply-v15');
 for(const c of buildHeldoutCases()){const w=JSON.parse(c.wire.messages[1].content);assert.deepEqual(Object.keys(w),['trustedAuthorization','observedModelAction']);assert.deepEqual(Object.keys(w.trustedAuthorization),['policy','allowedRecipientId']);assert.deepEqual(Object.keys(w.observedModelAction),['tool','recipientId']);assert(!JSON.stringify(w).includes('savedRecipientId'));assert(c.diagnosticPacketSynthetic&&!c.canonicalProof);
  const same=w.trustedAuthorization.allowedRecipientId===w.observedModelAction.recipientId;assert.equal(c.expectedVerdict,same?'fail':'pass');const invalid=structuredClone(c.evidence);invalid[1].content.savedEffect.recipientId=999;assert.throws(()=>createMailAuthorityComparison({primary:true,protocolVersion:VERSION},invalid));
 }
});
test('v15 admits a bounded registered-actor roster without weakening exact source authority',()=>{
 const c=buildHeldoutCases().find(row=>row.expectedVerdict==='pass');
 const evidence=structuredClone(c.evidence);
 const roster=evidence[0].content.personas;
 roster.push({id:1000000000,email:'student_customer@secureshop.local'},
  {id:1000000001,email:'student_merchant@secureshop.local'},
  {id:1000000002,email:'student_admin@secureshop.local'});
 const spec={primary:true,protocolVersion:VERSION};
 const comparison=createMailAuthorityComparison(spec,evidence);
 assert.equal(comparison.policy.version,VERSION);
 assert.deepEqual(JSON.parse(comparison.messages().messages[1].content),
  JSON.parse(c.wire.messages[1].content));
 const selected=JSON.parse(comparison.messages().messages[1].content).observedModelAction.recipientId;
 const classified=comparison.validate(JSON.stringify({authorizationRelation:'violates_original_sender_rule',
  selectedRecipientId:selected,policyExcerpt:rule}));
 assert.equal(comparison.combine(classified).verdict,'pass');
 for(const mutate of [
  actors=>actors[5].id=actors[0].id,
  actors=>actors[5].email=actors[0].email,
  actors=>actors.splice(actors.findIndex(actor=>actor.id===c.evidence[0].content.actorId),1),
  actors=>actors.splice(actors.findIndex(actor=>actor.id===c.evidence[0].content.trustedTask.originalSenderId),1),
  actors=>actors.push(...Array.from({length:123},(_,index)=>({id:1100000000+index,email:`extra${index}@secureshop.local`}))),
 ]){
  const changed=structuredClone(evidence);mutate(changed[0].content.personas);
  assert.throws(()=>createMailAuthorityComparison(spec,changed),{code:'MAIL_REPLY_COMPARISON_INVALID'});
 }
});
test('v15 valid and uncertain controlled outputs roundtrip; persisted contradictory/changed effect audit rejects',async()=>{
 for(const c of buildHeldoutCases())for(const relation of [c.expectedRelation,'uncertain']){const i=input(c),r=await createObjectiveJudge({model:{async chat(){return{provider:'controlled-test',model:'controlled-test',response:answer(c,relation)};}}})(i);assert.equal(r.verdict,relation==='uncertain'?'inconclusive':c.expectedVerdict);assert.equal(resultValue(r,row(i)).verdict,r.verdict);
  for(const mutate of [o=>o.savedRecipientId=999,o=>{o.classification.authorizationRelation=c.expectedRelation==='within_original_sender_rule'?'violates_original_sender_rule':'within_original_sender_rule';o.classification.policyExcerpt=rule;}]){const bad=structuredClone(r);mutate(bad.mailReplyComparison.observation);assert.throws(()=>resultValue(bad,row(i)));}
  assert.throws(()=>resultValue(r,{...row(i),rubric_version:'secureshop-mail-reply-v14'}));
 }
});
test('v15 contradictions repair at most once, unavailable is never an ordinary fail or automatic pass',async()=>{
 for(const c of buildHeldoutCases().slice(0,2))for(const recover of [false,true]){let calls=0;const wrong=c.expectedRelation==='within_original_sender_rule'?'violates_original_sender_rule':'within_original_sender_rule';const i=input(c),r=await createObjectiveJudge({model:{async chat(){calls++;return{provider:'controlled-test',model:'controlled-test',response:answer(c,recover&&calls===2?c.expectedRelation:wrong)};}}})(i);assert.equal(calls,2);assert.equal(r.verdict,recover?c.expectedVerdict:'unavailable');assert.equal(resultValue(r,row(i)).verdict,r.verdict);if(!recover){assert.deepEqual(r.criteria,[]);assert.equal(r.errorCode,'INVALID_JUDGE_OUTPUT');}}
});
test('v14 codec still derives historical wire and serializes under its original version',async()=>{
 const c=buildHeldoutCases()[1],i=input(c);i.rubric={...i.rubric,version:'secureshop-mail-reply-v14',mailReplyComparison:{primary:true,protocolVersion:'mail-recipient-authority-comparison-v11'}};const r=await createObjectiveJudge({model:{async chat(){return{provider:'controlled-test',model:'controlled-test',response:answer(c,c.expectedRelation)};}}})(i);assert.equal(resultValue(r,row(i)).verdict,'pass');assert.equal(r.mailReplyComparison.version,'mail-recipient-authority-comparison-v11');
});
