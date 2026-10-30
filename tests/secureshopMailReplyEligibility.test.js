'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const c=require('../server/config/secureshopCurriculum');
const {MAIL_OBJECTIVE_QUALIFICATION:q,mailObjectiveReadiness}=require('../server/services/secureshopMailObjectiveReadiness');
test('reply eligibility preserves fresh disabled defaults and all unrelated mail release gates',()=>{
 assert.deepEqual(q,{ss_mail_reply_redirect:true,ss_mail_header_construction:true,ss_mail_cross_persona_read:true,ss_mail_stored_browser_execution:true,ss_mail_agent_html_injection:true,ss_mail_agent_cross_persona_read:true});
 assert.equal(c.CHALLENGE.defaultVisible,true);
 for(const id of Object.keys(q))assert.equal(c.OBJECTIVES.find(x=>x.id===id).defaultEnabled,false);
 assert.equal(c.isQualifiedObjective('ss_mail_reply_redirect'),true);
 assert.doesNotMatch(c.HINTS.ss_mail_reply_redirect.hints.join(' '),/not yet available/);
 assert.doesNotMatch(c.SOLUTIONS.ss_mail_reply_redirect.approach,/Unavailable/);
 assert.match(c.SOLUTIONS.ss_mail_reply_redirect.examples[0].explanation,/single trace does not prove counterfactual causation/);
});
test('reply readiness still requires transport, Judge and canonical instructor catalog admission',()=>{
 const id='ss_mail_reply_redirect',ready={transportReady:true,judgeReady:true,catalog:{[id]:true}};
 assert.equal(mailObjectiveReadiness(ready)[id],true);
 for(const deny of [{transportReady:false},{judgeReady:false},{catalog:{}},{catalog:{[id]:false}}])assert.equal(mailObjectiveReadiness({...ready,...deny})[id],false);
 assert.equal(mailObjectiveReadiness(ready).ss_mail_cross_persona_read,false);
});

test('qualified V09 mail HTML readiness still requires every canonical dependency',()=>{
 const id='ss_mail_agent_html_injection',ready={transportReady:true,judgeReady:true,catalog:{[id]:true}};
 assert.equal(mailObjectiveReadiness(ready)[id],true);
 for(const deny of [{transportReady:false},{judgeReady:false},{catalog:{}},{catalog:{[id]:false}}])assert.equal(mailObjectiveReadiness({...ready,...deny})[id],false);
 assert.equal(c.OBJECTIVES.find(row=>row.id===id).defaultEnabled,false);
});

test('qualified V11 mail detail readiness requires every canonical dependency',()=>{
 const id='ss_mail_agent_cross_persona_read',ready={transportReady:true,judgeReady:true,catalog:{[id]:true}};
 assert.equal(mailObjectiveReadiness(ready)[id],true);
 for(const deny of [{transportReady:false},{judgeReady:false},{catalog:{}},{catalog:{[id]:false}}])assert.equal(mailObjectiveReadiness({...ready,...deny})[id],false);
 assert.equal(c.OBJECTIVES.find(row=>row.id===id).defaultEnabled,false);
});
