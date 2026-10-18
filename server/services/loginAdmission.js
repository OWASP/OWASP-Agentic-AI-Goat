'use strict';
const { AsyncResource } = require('node:async_hooks');
function coded(code,message){return Object.assign(new Error(message),{code});}
function createLoginAdmission({concurrency=4,queueLimit=256}={}){
 if(!Number.isInteger(concurrency)||concurrency<1||concurrency>64||!Number.isInteger(queueLimit)||queueLimit<0||queueLimit>4096)throw new RangeError('Invalid login admission bounds');
 const queue=[];let active=0,closed=false,closing;
 function settleClose(){if(closed&&active===0&&!queue.length)closing?.resolve();}
 function pump(){while(!closed&&active<concurrency&&queue.length){const job=queue.shift();job.signal?.removeEventListener('abort',job.abort);if(job.signal?.aborted){job.resource.emitDestroy();job.reject(job.signal.reason);continue;}active++;Promise.resolve().then(()=>job.resource.runInAsyncScope(job.work)).then(job.resolve,job.reject).finally(()=>{job.resource.emitDestroy();active--;pump();settleClose();});}settleClose();}
 return Object.freeze({
  run(signal,work){if(typeof work!=='function')return Promise.reject(new TypeError('Login admission work required'));if(closed)return Promise.reject(coded('LOGIN_RUNTIME_CLOSED','Login service is closed'));if(signal?.aborted)return Promise.reject(signal.reason);if(queue.length>=queueLimit&&active>=concurrency)return Promise.reject(coded('LOGIN_QUEUE_FULL','Login service is busy'));return new Promise((resolve,reject)=>{const job={signal,work,resolve,reject,resource:new AsyncResource('dvaia-login-admission'),abort:null};job.abort=()=>{const i=queue.indexOf(job);if(i<0)return;queue.splice(i,1);signal.removeEventListener('abort',job.abort);job.resource.emitDestroy();reject(signal.reason);settleClose();};queue.push(job);signal?.addEventListener('abort',job.abort,{once:true});pump();});},
  snapshot:()=>({active,queued:queue.length,concurrency,queueLimit,closed}),
  close(){if(closing)return closing.promise;closed=true;let resolve;const promise=new Promise(r=>{resolve=r;});closing={promise,resolve};while(queue.length){const job=queue.shift();job.signal?.removeEventListener('abort',job.abort);job.resource.emitDestroy();job.reject(coded('LOGIN_RUNTIME_CLOSED','Login service is closed'));}settleClose();return promise;}
 });
}
module.exports={createLoginAdmission};
