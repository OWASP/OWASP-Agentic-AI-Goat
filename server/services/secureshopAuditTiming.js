'use strict';
const {performance}=require('node:perf_hooks');

const parse=(value,fallback,min,max,name)=>{
  if(value===undefined)return fallback;
  if(typeof value!=='string'||!/^[1-9][0-9]*$/.test(value))throw new RangeError(`Invalid ${name}`);
  const number=Number(value);
  if(!Number.isSafeInteger(number)||number<min||number>max)throw new RangeError(`Invalid ${name}`);
  return number;
};

function createSecureShopAuditTiming({env=process.env,now=()=>performance.now(),profile='instruction'}={}){
  if(!['instruction','unbounded'].includes(profile))throw new TypeError('Invalid audit timing profile');
  const runTimeoutMs=profile==='unbounded'
    ?parse(env.SS_AUDIT_UNBOUNDED_RUN_TIMEOUT_MS,290000,125000,290000,'SS_AUDIT_UNBOUNDED_RUN_TIMEOUT_MS')
    :parse(env.SS_AUDIT_RUN_TIMEOUT_MS,120000,10100,290000,'SS_AUDIT_RUN_TIMEOUT_MS');
  const judgeTimeoutMs=profile==='unbounded'?90000
    :parse(env.SS_AUDIT_JUDGE_TIMEOUT_MS,90000,100,240000,'SS_AUDIT_JUDGE_TIMEOUT_MS');
  if(typeof now!=='function')throw new TypeError('Audit clock required');
  return Object.freeze({runTimeoutMs,judgeTimeoutMs,
    deadline(){return now()+runTimeoutMs;},
    remainingWorkerMs(deadline){
      if(profile!=='unbounded'||!Number.isFinite(deadline))throw new TypeError('Unbounded audit deadline required');
      // Keep the existing 90-second Judge allocation plus 15 seconds for
      // post-worker evidence, publication and assessment handoff.
      const remaining=Math.min(190000,Math.floor(deadline-now()-105000));
      if(remaining<20000)throw Object.assign(new Error('Audit worker deadline exhausted'),{name:'TimeoutError'});
      return remaining;
    },
    remainingJudgeMs(deadline){
      if(!Number.isFinite(deadline))throw new TypeError('Audit deadline required');
      const remaining=Math.floor(deadline-now()-10000);
      if(remaining<100)throw Object.assign(new Error('Audit Judge deadline exhausted'),{name:'TimeoutError'});
      return Math.min(judgeTimeoutMs,remaining);
    },
  });
}
function createSecureShopAuditJudge(timing,{judgeFactory}={}){
  if(typeof timing?.remainingJudgeMs!=='function')throw new TypeError('Audit timing required');
  const factory=judgeFactory||require('../agent-runtime/objectiveJudge').createObjectiveJudge;
  if(typeof factory!=='function')throw new TypeError('Audit Judge factory required');
  return packet=>{
    packet.execution?.signal?.throwIfAborted();
    const timeoutMs=timing.remainingJudgeMs(packet.execution?.auditDeadline);
    packet.execution?.signal?.throwIfAborted();
    return factory({timeoutMs,auditExtendedTimeout:true})(packet);
  };
}
module.exports={createSecureShopAuditTiming,createSecureShopAuditJudge};
