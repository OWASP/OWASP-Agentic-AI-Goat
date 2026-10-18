'use strict';
const os=require('node:os');
const {createLoginAdmission}=require('./loginAdmission');
const {createPasswordComparisonWorkerPool}=require('./passwordComparisonWorkerPool');
function createLoginAuthenticationProduction({concurrency=Math.max(1,Math.min(4,os.availableParallelism())),queueLimit=256,closeTimeoutMs=5000,admission,passwordPool}={}){
 if(!Number.isInteger(closeTimeoutMs)||closeTimeoutMs<10||closeTimeoutMs>30000)throw new RangeError('Invalid login runtime close timeout');
 const gate=admission||createLoginAdmission({concurrency,queueLimit}),pool=passwordPool||createPasswordComparisonWorkerPool({size:concurrency,queueLimit});let closed=false,closing;
 const check=signal=>{if(closed)throw Object.assign(new Error('Login service is closed'),{code:'LOGIN_RUNTIME_CLOSED'});signal?.throwIfAborted();};
 return Object.freeze({run(signal,work){if(typeof work!=='function')return Promise.reject(new TypeError('Login work required'));try{check(signal);}catch(error){return Promise.reject(error);}return gate.run(signal,()=>work({compare:(password,hash)=>{check(signal);return pool.compare(password,hash,{signal});},check:()=>check(signal)}));},snapshot:()=>({closed,admission:gate.snapshot(),passwords:pool.snapshot()}),close(){if(closing)return closing;closed=true;const operations=[gate.close(),pool.close({timeoutMs:closeTimeoutMs})];closing=(async()=>{let timer;const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(new Error('Login runtime close timed out'),{code:'LOGIN_RUNTIME_CLOSE_FAILED'})),closeTimeoutMs);});try{const results=await Promise.race([Promise.allSettled(operations),timeout]);const errors=results.filter(r=>r.status==='rejected').map(r=>r.reason);if(errors.length)throw Object.assign(new AggregateError(errors,'Login runtime close failed'),{code:'LOGIN_RUNTIME_CLOSE_FAILED'});}finally{clearTimeout(timer);}})();return closing;}});
}
let singleton;
function getLoginAuthenticationProduction(){if(!singleton)singleton=createLoginAuthenticationProduction();return singleton;}
module.exports={createLoginAuthenticationProduction,getLoginAuthenticationProduction};
