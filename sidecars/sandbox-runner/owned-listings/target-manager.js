'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {createListingListener}=require('./http-listener');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/,fail=code=>Object.assign(new Error('Listings manager unavailable'),{code});
const hash=v=>crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
const LIMITS=Object.freeze({maxPersistedTargets:200,maxResidentTargets:32,maxConcurrentExecutions:4,maxQueuedExecutions:16});
function binding(raw){
 if(!raw||Object.keys(raw).sort().join(',')!=='mode,scope,targetId'||!UUID.test(raw.targetId||'')||!['vuln','fixed'].includes(raw.mode))throw fail('LISTINGS_TARGET_INVALID');
 const s=raw.scope,keys=['launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
 if(!s||Object.keys(s).sort().join(',')!==keys.sort().join(',')||!UUID.test(s.launchId||'')||!UUID.test(s.scenarioId||'')||['generation','platformOwnerId','platformSessionId'].some(k=>!Number.isSafeInteger(s[k])||s[k]<1))throw fail('LISTINGS_TARGET_INVALID');
 return {scope:{launchId:s.launchId,scenarioId:s.scenarioId,generation:s.generation,platformOwnerId:s.platformOwnerId,platformSessionId:s.platformSessionId},targetId:raw.targetId,mode:raw.mode};
}
async function createListingsTargetManager({directory,origin,namespace}={}){
 if(!path.isAbsolute(directory||'')||new URL(origin).origin!==origin||typeof namespace?.checkReadiness!=='function'||typeof namespace?.execute!=='function')throw TypeError('Owned manager bootstrap required');
 const stat=await fs.lstat(directory);if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o077))throw fail('LISTINGS_MANAGER_DIRECTORY');
 const ready=await namespace.checkReadiness();if(ready.ready!==true||!SHA.test(ready.runtimeDigest))throw fail('LISTINGS_MANAGER_NOT_READY');
 const retirementTasks=new Map(),records=new Map(),residents=new Map(),busy=new Map(),queue=[];let running=0,closing=false,mutex=Promise.resolve();
 const lock=work=>{const p=mutex.then(work);mutex=p.catch(()=>{});return p;};
 const targetDirectory=id=>path.join(directory,id);
 async function persist(row){const dir=targetDirectory(row.targetId);await fs.mkdir(dir,{recursive:true,mode:0o700});const file=path.join(dir,'registration.json'),tmp=file+'.'+crypto.randomUUID();let fd;
  try{fd=await fs.open(tmp,'wx',0o600);const {stateSha256,...body}=row;await fd.writeFile(JSON.stringify({...body,stateSha256:hash(body)}));await fd.sync();await fd.close();fd=null;await fs.rename(tmp,file);const d=await fs.open(dir,'r');try{await d.sync();}finally{await d.close();}}
  finally{await fd?.close();await fs.unlink(tmp).catch(e=>{if(e.code!=='ENOENT')throw e;});}
  records.set(row.targetId,row);
 }
 async function removeForgotten(dir,id){
  const st=await fs.lstat(dir);if(!st.isDirectory()||st.isSymbolicLink())throw fail('LISTINGS_MANAGER_STATE');
  const files=await fs.readdir(dir);if(files.some(v=>!['registration.json','journal'].includes(v)))throw fail('LISTINGS_MANAGER_STATE');
  if(files.includes('registration.json')){
   const fd=await fs.open(path.join(dir,'registration.json'),require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW|require('node:fs').constants.O_NONBLOCK);let registration;
   try{const rs=await fd.stat();if(!rs.isFile()||rs.size>16384)throw fail('LISTINGS_MANAGER_STATE');registration=JSON.parse(await fd.readFile('utf8'));}finally{await fd.close();}
   const {stateSha256,...body}=registration;if(registration.targetId!==id||registration.state!=='retired'||hash(body)!==stateSha256)throw fail('LISTINGS_MANAGER_STATE');
  }
  if(files.includes('journal')){const journal=path.join(dir,'journal'),js=await fs.lstat(journal);if(!js.isDirectory()||js.isSymbolicLink()||(await fs.readdir(journal)).some(v=>!/^([0-9a-f-]{36})\.retired\.json$/.test(v)))throw fail('LISTINGS_MANAGER_STATE');}
  await fs.rm(dir,{recursive:true});
 }
 for(const id of await fs.readdir(directory)){
  const forgotten=/^\.forgotten-([a-f0-9-]{36})$/.exec(id);if(forgotten&&UUID.test(forgotten[1])){await removeForgotten(path.join(directory,id),forgotten[1]);continue;}
  if(!UUID.test(id))throw fail('LISTINGS_MANAGER_STATE');const dir=targetDirectory(id),ds=await fs.lstat(dir);if(!ds.isDirectory()||ds.isSymbolicLink()||(ds.mode&0o077))throw fail('LISTINGS_MANAGER_STATE');
  const fd=await fs.open(path.join(dir,'registration.json'),require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW|require('node:fs').constants.O_NONBLOCK);
  let row;try{const st=await fd.stat();if(!st.isFile()||st.size>16384||(st.mode&0o077))throw fail('LISTINGS_MANAGER_STATE');row=JSON.parse(await fd.readFile('utf8'));}finally{await fd.close();}
  const {stateSha256,...body}=row;if(hash(body)!==stateSha256)throw fail('LISTINGS_MANAGER_STATE');
  const b=binding({scope:row.scope,targetId:row.targetId,mode:row.mode});
  if(row.targetId!==id||row.bindingSha256!==hash(b)||row.runtimeDigest!==ready.runtimeDigest||!['active','retiring','retired'].includes(row.state)||!UUID.test(row.executorId)||!SHA.test(row.identity)||row.runtimeIdentity!==hash({identity:row.identity,runtimeDigest:ready.runtimeDigest})||!SHA.test(row.tokenSha256)||row.state!=='retired'&&(!/^[A-Za-z0-9_-]{43}$/.test(row.token||'')||hash(row.token)!==row.tokenSha256))throw fail('LISTINGS_MANAGER_STATE');
  records.set(id,row);
 }
 if(records.size>400)throw fail('LISTINGS_TARGET_CAPACITY');
 function drain(){if(closing)return;while(running<LIMITS.maxConcurrentExecutions&&queue.length){const job=queue.shift();clearTimeout(job.timer);job.signal?.removeEventListener('abort',job.abort);running++;Promise.resolve().then(job.work).then(job.resolve,job.reject).finally(()=>{running--;drain();});}}
 function execute(work,signal){if(closing)return Promise.reject(fail('LISTINGS_MANAGER_CLOSED'));if(signal?.aborted)return Promise.reject(fail('LISTINGS_OPERATION_ABORTED'));if(running>=LIMITS.maxConcurrentExecutions&&queue.length>=LIMITS.maxQueuedExecutions)return Promise.reject(fail('LISTINGS_EXECUTION_CAPACITY'));return new Promise((resolve,reject)=>{const job={work,resolve,reject,signal};job.abort=()=>{const index=queue.indexOf(job);if(index>=0){queue.splice(index,1);clearTimeout(job.timer);signal?.removeEventListener('abort',job.abort);reject(fail('LISTINGS_OPERATION_ABORTED'));}};job.timer=setTimeout(()=>{const index=queue.indexOf(job);if(index>=0){queue.splice(index,1);signal?.removeEventListener('abort',job.abort);reject(fail('LISTINGS_QUEUE_TIMEOUT'));}},15000);queue.push(job);signal?.addEventListener('abort',job.abort,{once:true});if(signal?.aborted)job.abort();drain();});}

 function match(raw){const b=binding(raw),row=records.get(b.targetId);if(!row||row.bindingSha256!==hash(b))throw fail('LISTINGS_TARGET_MISMATCH');return row;}
 async function handler(row){
  if(residents.has(row.targetId)){const h=residents.get(row.targetId);residents.delete(row.targetId);residents.set(row.targetId,h);return h;}
  if(residents.size>=LIMITS.maxResidentTargets){const candidate=[...residents.keys()].find(id=>!busy.get(id)&&records.get(id)?.state==='active');if(!candidate)throw fail('LISTINGS_RESIDENT_CAPACITY');await residents.get(candidate).close();residents.delete(candidate);}
  const journal=path.join(targetDirectory(row.targetId),'journal');await fs.mkdir(journal,{mode:0o700,recursive:true});
  const h=await createListingListener({token:row.token,directory:journal,mode:row.mode,identity:row.identity,namespace:{checkReadiness:()=>namespace.checkReadiness(),execute:(input,options)=>execute(()=>namespace.execute(input,options),options?.signal)}});
  residents.set(row.targetId,h);return h;
 }
 const configuration=row=>({scope:structuredClone(row.scope),targetId:row.targetId,mode:row.mode,origin,token:row.token,runtimeIdentity:row.runtimeIdentity,runtimeDigest:row.runtimeDigest,executorId:row.executorId});
 return Object.freeze({
  async health(){const current=await namespace.checkReadiness();if(closing||current.ready!==true||current.runtimeDigest!==ready.runtimeDigest)throw fail('LISTINGS_MANAGER_NOT_READY');return{version:1,ready:true,capability:'owned-listings-manager.v1',runtimeDigest:ready.runtimeDigest,limits:LIMITS};},
  async register(raw){const b=binding(raw);return lock(async()=>{if(closing)throw fail('LISTINGS_MANAGER_CLOSED');let row=records.get(b.targetId);if(row){match(b);if(row.state!=='active')throw fail('LISTINGS_TARGET_RETIRED');return configuration(row);}
   if([...records.values()].filter(v=>v.state!=='retired').length>=LIMITS.maxPersistedTargets||records.size>=400)throw fail('LISTINGS_TARGET_CAPACITY');
   const identity=hash({binding:b,instanceId:crypto.randomUUID()}),token=crypto.randomBytes(32).toString('base64url');row={version:1,...b,bindingSha256:hash(b),identity,token,tokenSha256:hash(token),executorId:crypto.randomUUID(),runtimeDigest:ready.runtimeDigest,runtimeIdentity:hash({identity,runtimeDigest:ready.runtimeDigest}),state:'active'};await persist(row);return configuration(row);});},
  async inspect(raw){return lock(()=>{const row=match(raw);if(row.state!=='active')throw fail('LISTINGS_TARGET_RETIRED');return configuration(row);});},
  async handleTarget(req,res){const supplied=req.headers.authorization;if(typeof supplied!=='string'||!supplied.startsWith('Bearer '))throw fail('LISTINGS_TARGET_UNAUTHORIZED');const tokenHash=hash(supplied.slice(7));let h,id;
   await lock(async()=>{if(closing)throw fail('LISTINGS_MANAGER_CLOSED');const row=[...records.values()].find(v=>v.tokenSha256===tokenHash);if(!row||row.state!=='active')throw fail('LISTINGS_TARGET_UNAUTHORIZED');id=row.targetId;h=await handler(row);busy.set(id,(busy.get(id)||0)+1);});
   try{await h.handle(req,res);}finally{busy.set(id,busy.get(id)-1);}
  },
  async retire(raw,{operationId,canonicalReceiptSha256}={}){
   if(!UUID.test(operationId||'')||!SHA.test(canonicalReceiptSha256||''))throw fail('LISTINGS_RETIRE_INVALID');
   const b=binding(raw),key=hash({binding:b,operationId,canonicalReceiptSha256}),existing=retirementTasks.get(b.targetId);
   if(existing){if(existing.key!==key)throw fail('LISTINGS_RETIRE_CONFLICT');return existing.promise;}
   const promise=(async()=>{let row,h;
   await lock(async()=>{row=match(raw);if(row.retirement&&(row.retirement.operationId!==operationId||row.retirement.canonicalReceiptSha256!==canonicalReceiptSha256))throw fail('LISTINGS_RETIRE_CONFLICT');if(row.state==='retired')return;
    row={...row,state:'retiring',retirement:{operationId,canonicalReceiptSha256}};await persist(row);h=await handler(row);});
   if(row.state==='retired')return row.retirement;
   const tombstones=await h.retireAll();const receipt={version:1,operationId,targetId:row.targetId,bindingSha256:row.bindingSha256,canonicalReceiptSha256,operationCount:tombstones.length,tombstonesSha256:hash(tombstones),retired:true};
   await lock(async()=>{await h.close();residents.delete(row.targetId);const retired={...row,state:'retired',retirement:receipt};delete retired.token;await persist(retired);});return receipt;})();
   retirementTasks.set(b.targetId,{key,promise});try{return await promise;}finally{retirementTasks.delete(b.targetId);}
  },
  async forget(raw,{operationId,canonicalReceiptSha256}={}){
   const b=binding(raw);if(!UUID.test(operationId||'')||!SHA.test(canonicalReceiptSha256||''))throw fail('LISTINGS_RETIRE_INVALID');
   return lock(async()=>{const row=records.get(b.targetId),receipt={version:1,targetId:b.targetId,operationId,canonicalReceiptSha256,forgotten:true,replayed:!row};
    if(!row){const trash=path.join(directory,'.forgotten-'+b.targetId);try{await removeForgotten(trash,b.targetId);}catch(error){if(error.code!=='ENOENT')throw error;}return receipt;}match(b);if(row.state!=='retired'||row.retirement.operationId!==operationId||row.retirement.canonicalReceiptSha256!==canonicalReceiptSha256)throw fail('LISTINGS_FORGET_DENIED');
    const trash=path.join(directory,'.forgotten-'+b.targetId);await fs.rename(targetDirectory(b.targetId),trash);const d=await fs.open(directory,'r');try{await d.sync();}finally{await d.close();}records.delete(b.targetId);await removeForgotten(trash,b.targetId);const parent=await fs.open(directory,'r');try{await parent.sync();}finally{await parent.close();}return receipt;
   });
  },
  async close(){closing=true;for(const job of queue.splice(0)){clearTimeout(job.timer);job.signal?.removeEventListener('abort',job.abort);job.reject(fail('LISTINGS_MANAGER_CLOSED'));}await lock(async()=>{await Promise.all([...residents.values()].map(h=>h.close()));residents.clear();});}
 });
}
module.exports={createListingsTargetManager,LIMITS};
