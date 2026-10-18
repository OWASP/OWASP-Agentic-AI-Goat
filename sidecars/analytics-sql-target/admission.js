'use strict';
const {fail}=require('./contract');
// One instance per private service, never one instance per learner. No queue:
// callers retry admission without starting a target connection or SQL effect.
function createAdmission(limit=2){
 if(!Number.isSafeInteger(limit)||limit<1||limit>8)throw TypeError('Bounded global admission required');
 let active=0;
 return Object.freeze({async run(work,{signal}={}){
  signal?.throwIfAborted();if(active>=limit)throw fail('ANALYTICS_CAPACITY');active++;
  try{return await work();}finally{active--;}
 },get active(){return active;}});
}
// Factory must construct a new max-one target pool. The service never caches it.
async function withTargetPool(createPool,configuration,work){
 const pool=createPool({...configuration,max:1,connectionTimeoutMillis:1500,idleTimeoutMillis:1000});
 let poolError;pool.on?.('error',error=>{poolError=error;});
 let result;try{result=await work(pool);}finally{let timer;try{await Promise.race([pool.end(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('ANALYTICS_POOL_DRAIN_UNCERTAIN')),1500);})]);}finally{clearTimeout(timer);}}
 if(poolError)throw Object.assign(fail('ANALYTICS_POOL_DRAIN_UNCERTAIN'),{cause:poolError});
 return result;
}
module.exports={createAdmission,withTargetPool};
