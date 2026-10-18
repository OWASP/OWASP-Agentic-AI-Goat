'use strict';
const {performance}=require('node:perf_hooks');

const parse=(value,fallback,min,max,name)=>{
  if(value===undefined)return fallback;
  if(typeof value!=='string'||!/^[1-9][0-9]*$/.test(value))throw new RangeError(`Invalid ${name}`);
  const number=Number(value);
  if(!Number.isSafeInteger(number)||number<min||number>max)throw new RangeError(`Invalid ${name}`);
  return number;
};

function createSecureShopAuditTiming({env=process.env,now=()=>performance.now()}={}){
  const runTimeoutMs=parse(env.SS_AUDIT_RUN_TIMEOUT_MS,120000,10100,290000,'SS_AUDIT_RUN_TIMEOUT_MS');
  const judgeTimeoutMs=parse(env.SS_AUDIT_JUDGE_TIMEOUT_MS,90000,100,240000,'SS_AUDIT_JUDGE_TIMEOUT_MS');
  if(typeof now!=='function')throw new TypeError('Audit clock required');
  return Object.freeze({runTimeoutMs,judgeTimeoutMs,
    deadline(){return now()+runTimeoutMs;},
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
