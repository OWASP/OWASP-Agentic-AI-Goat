'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopAuditTiming,createSecureShopAuditJudge}=require('../server/services/secureshopAuditTiming');
const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');

test('Audit timing defaults, bounds and opt-in remain closed',()=>{
  let time=0;
  const base=createSecureShopAuditTiming({env:{},now:()=>time});
  assert.equal(base.runTimeoutMs,120000);
  assert.equal(base.remainingJudgeMs(base.deadline()),90000);
  const extended=createSecureShopAuditTiming({env:{SS_AUDIT_RUN_TIMEOUT_MS:'290000',SS_AUDIT_JUDGE_TIMEOUT_MS:'240000'},now:()=>time});
  const deadline=extended.deadline();
  assert.equal(extended.remainingJudgeMs(deadline),240000);
  time=30000;assert.equal(extended.remainingJudgeMs(deadline),240000);
  time=100000;assert.equal(extended.remainingJudgeMs(deadline),180000);
  time=279900;assert.equal(extended.remainingJudgeMs(deadline),100);
  time=280000;assert.throws(()=>extended.remainingJudgeMs(deadline),{name:'TimeoutError'});
  for(const [key,value] of [['SS_AUDIT_RUN_TIMEOUT_MS','10099'],['SS_AUDIT_RUN_TIMEOUT_MS','290001'],
    ['SS_AUDIT_JUDGE_TIMEOUT_MS','99'],['SS_AUDIT_JUDGE_TIMEOUT_MS','240001'],
    ['SS_AUDIT_RUN_TIMEOUT_MS','1e5'],['SS_AUDIT_JUDGE_TIMEOUT_MS','0']])
    assert.throws(()=>createSecureShopAuditTiming({env:{[key]:value}}),RangeError);
});

test('extended Judge timeout is confined to the canonical Audit rubric',async()=>{
  assert.throws(()=>createObjectiveJudge({timeoutMs:240000}),/Invalid judge timeout/);
  const judge=createObjectiveJudge({timeoutMs:240000,auditExtendedTimeout:true});
  await assert.rejects(judge({rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:'system_prompt'},evidence:[]}),
    /Extended judge timeout requires Audit rubric/);
  assert.throws(()=>createObjectiveJudge({timeoutMs:240001,auditExtendedTimeout:true}),/Invalid judge timeout/);
});

test('Audit Judge wrapper admits only remaining budget and never dispatches after timeout or cancellation',async()=>{
  let time=0,dispatch=0,options;
  const timing=createSecureShopAuditTiming({env:{SS_AUDIT_RUN_TIMEOUT_MS:'290000',SS_AUDIT_JUDGE_TIMEOUT_MS:'240000'},now:()=>time});
  const judge=createSecureShopAuditJudge(timing,{judgeFactory:value=>{options=value;return async()=>{dispatch++;return'controlled';};}});
  const deadline=timing.deadline(),controller=new AbortController();
  time=100000;
  assert.equal(await judge({execution:{auditDeadline:deadline,signal:controller.signal}}),'controlled');
  assert.equal(options.timeoutMs,180000);
  assert.equal(options.auditExtendedTimeout,true);
  assert.equal(dispatch,1);
  time=280000;
  assert.throws(()=>judge({execution:{auditDeadline:deadline,signal:controller.signal}}),{name:'TimeoutError'});
  assert.equal(dispatch,1);
  time=101000;
  controller.abort();
  assert.throws(()=>judge({execution:{auditDeadline:deadline,signal:controller.signal}}),{name:'AbortError'});
  assert.equal(dispatch,1);
});
