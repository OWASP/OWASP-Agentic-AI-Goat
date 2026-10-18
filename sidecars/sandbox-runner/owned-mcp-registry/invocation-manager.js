'use strict';
// Unwired manager. The injected supervisor must prove containment/drain; no PID
// inference, process spawning, model call or remote application configuration here.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const C=require('../../../server/services/secureshopOwnedMcpInvocationContract');
const W=require('../../../server/services/secureshopOwnedMcpInvocationWire');
const fail=code=>Object.assign(Error(code),{code});
const same=(a,b)=>C.digest(a)===C.digest(b);
const lookup=q=>({invocationId:q.invocationId,requestSha256:C.digest(q.request),managerInstanceId:q.managerInstanceId,runtimeSha256:q.runtimeSha256});
function createInvocationManager({stateRoot,managerInstanceId,runtimeSha256,supervisor,assets,initialize=false,maxClaims=32,maxFences=64,timeoutMs=15000,stateLease}={}){
 W.lookup({invocationId:managerInstanceId,requestSha256:runtimeSha256,managerInstanceId,runtimeSha256});
 if(typeof stateRoot!=='string'||!path.isAbsolute(stateRoot)||typeof supervisor?.start!=='function'||typeof supervisor?.reconcile!=='function'||!assets||!Number.isSafeInteger(maxClaims)||maxClaims<1||maxClaims>256||!Number.isSafeInteger(maxFences)||maxFences<1||maxFences>256||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000)throw TypeError('Private manager dependencies required');
 const assetMap=new Map(Object.entries(assets));for(const [id,a]of assetMap)if(!/^[a-z][a-z0-9-]{0,63}$/.test(id)||typeof a?.authorize!=='function')throw TypeError('Closed synthetic asset resolver required');
 const stat=fs.lstatSync(stateRoot);if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o077))throw fail('MCP_INVOCATION_STATE_UNSAFE');
 const lock=path.join(stateRoot,'manager.lock'),file=path.join(stateRoot,'state.json');
 const privateLease=stateLease!==undefined;const checkLease=()=>{if(privateLease)require('./invocation-private-lease').assertPrivateLease(stateLease);};checkLease();
 if(!privateLease)try{fs.mkdirSync(lock,{mode:0o700});}catch{throw fail('MCP_INVOCATION_MANAGER_LOCKED');}
 let state,persistenceFailed=false,closed=false,closePromise,queue=Promise.resolve(),initialized=false;const running=new Map(),bootId=crypto.randomUUID();
 const locked=work=>{const result=queue.then(work);queue=result.catch(()=>{});return result;};
 function syncDir(){const fd=fs.openSync(stateRoot,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 function save(){checkLease();if(persistenceFailed)throw fail('MCP_INVOCATION_STATE_UNCERTAIN');try{const bytes=JSON.stringify(C.bounded(state,4194304))+'\n',temp=path.join(stateRoot,'state.'+crypto.randomUUID()+'.tmp');let fd;try{fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{if(fd!==undefined)fs.closeSync(fd);}fs.renameSync(temp,file);syncDir();}catch(error){persistenceFailed=true;throw error;}}
 try{
  if(fs.readdirSync(stateRoot).some(n=>n.endsWith('.tmp')))throw fail('MCP_INVOCATION_STATE_UNCERTAIN');
  if(fs.existsSync(file)){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)||s.size>4194304)throw fail('MCP_INVOCATION_STATE_UNSAFE');const bytes=fs.readFileSync(fd,'utf8');state=JSON.parse(bytes);if(bytes!==JSON.stringify(C.bounded(state,4194304))+'\n')throw fail('MCP_INVOCATION_STATE_INVALID');}finally{fs.closeSync(fd);}}
  else{if(initialize!==true)throw fail('MCP_INVOCATION_STATE_MISSING');state={version:1,managerInstanceId,runtimeSha256,claims:{},fences:{}};save();}
  if(state.version!==1||state.managerInstanceId!==managerInstanceId||state.runtimeSha256!==runtimeSha256||!state.claims||!state.fences||Object.keys(state).sort().join()!=='claims,fences,managerInstanceId,runtimeSha256,version')throw fail('MCP_INVOCATION_STATE_INVALID');
  if(Object.keys(state.claims).length>maxClaims||Object.keys(state.fences).length>maxFences)throw fail('MCP_INVOCATION_STATE_INVALID');
  for(const [id,row]of Object.entries(state.claims)){W.claim(row.claim);if(Object.keys(row).sort().join()!==['claim','identity','intent','state','drained',...(Object.hasOwn(row,'result')?['result']:[])].sort().join()||!row.intent||Object.keys(row.intent).sort().join()!=='bootId,invocationId,workerId'||row.intent.invocationId!==id||!['bootId','workerId'].every(k=>typeof row.intent[k]==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(row.intent[k]))||['completed','failed_before_effect'].includes(row.state)&&(!row.drained||!Object.hasOwn(row,'result'))||row.state==='running'&&(row.drained||Object.hasOwn(row,'result'))||row.state==='uncertain'&&!row.drained&&Object.hasOwn(row,'result'))throw fail('MCP_INVOCATION_STATE_INVALID');if(Object.hasOwn(row,'result'))C.bounded(row.result,65536);if(id!==row.claim.invocationId||row.claim.managerInstanceId!==managerInstanceId||row.claim.runtimeSha256!==runtimeSha256||!same(row.identity,lookup(row.claim))||!['running','completed','failed_before_effect','uncertain'].includes(row.state)||typeof row.drained!=='boolean')throw fail('MCP_INVOCATION_STATE_INVALID');}
  for(const [id,row]of Object.entries(state.fences)){W.fence(row.request);if(Object.keys(row).sort().join()!=='drained,request')throw fail('MCP_INVOCATION_STATE_INVALID');if(id!==row.request.fenceId||row.request.managerInstanceId!==managerInstanceId||row.request.runtimeSha256!==runtimeSha256||typeof row.drained!=='boolean')throw fail('MCP_INVOCATION_STATE_INVALID');}
 }catch(error){try{if(!privateLease)fs.rmdirSync(lock);}catch(cleanupError){throw new AggregateError([error,cleanupError],'Invocation state rejected; lock cleanup failed',{cause:error});}throw error;}
 function identity(q){if(q.managerInstanceId!==managerInstanceId||q.runtimeSha256!==runtimeSha256)throw fail('MCP_INVOCATION_MANAGER_MISMATCH');}
 function matches(q,f){const b=q.request.binding;return b.platformOwnerId===f.platformOwnerId&&(f.kind==='owner_deletion'||['launchId','scenarioId','generation','platformSessionId'].every(k=>b[k]===f[k]));}
 function view(row){return C.freeze(C.bounded({...row.identity,state:row.state,drained:row.drained,...(row.result===undefined?{}:{result:row.result,resultSha256:C.digest(row.result)})},196608));}
 async function bounded(promise){let t;try{return await Promise.race([promise,new Promise((_,reject)=>{t=setTimeout(()=>reject(fail('MCP_INVOCATION_DRAIN_UNCERTAIN')),timeoutMs);})]);}finally{clearTimeout(t);}}
 function drainedProof(value,intent){if(!value||!same(value,{...intent,drained:true}))throw fail('MCP_INVOCATION_DRAIN_UNCERTAIN');}
 async function ready(){return locked(async()=>{if(closed||persistenceFailed)throw fail('MCP_INVOCATION_MANAGER_CLOSED');if(initialized)return;for(const row of Object.values(state.claims))if(!row.drained){const proof=await bounded(Promise.resolve().then(()=>supervisor.reconcile(C.freeze({...row.intent}))));drainedProof(proof,row.intent);row.state='uncertain';row.drained=true;save();}initialized=true;});}
 function assertOpen(){checkLease();if(closed||persistenceFailed||!initialized)throw fail('MCP_INVOCATION_MANAGER_UNAVAILABLE');}
 async function claim(raw){const q=W.claim(raw);await ready();let completion;
  const result=await locked(()=>{assertOpen();identity(q);const prior=state.claims[q.invocationId];if(prior){if(!same(prior.claim,q))throw fail('MCP_INVOCATION_CONFLICT');return view(prior);}
   if(Object.values(state.fences).some(f=>matches(q,f.request)))throw fail('MCP_INVOCATION_RETIRED');
   if(Object.keys(state.claims).length>=maxClaims)throw fail('MCP_INVOCATION_CAPACITY');
   const asset=assetMap.get(q.assetId);if(!asset||asset.authorize(q)!==true)throw fail('MCP_INVOCATION_ASSET_DENIED');
   const intent={invocationId:q.invocationId,workerId:crypto.randomUUID(),bootId};
   const row={claim:q,identity:lookup(q),intent,state:'running',drained:false};state.claims[q.invocationId]=row;save();
   let worker;try{worker=supervisor.start(C.freeze({intent,claim:q}));if(typeof worker?.stop!=='function'||!worker.completion||typeof worker.completion.then!=='function')throw fail('MCP_INVOCATION_SUPERVISOR_INVALID');}catch(error){row.state='uncertain';save();throw error;}
   completion=Promise.resolve(worker.completion).then(value=>locked(()=>{if(!value||!['completed','failed_before_effect','uncertain'].includes(value.state))throw fail('MCP_INVOCATION_RESULT_INVALID');drainedProof(value.proof,intent);const result=C.bounded(value.result??null,65536);row.state=value.state;row.drained=true;row.result=result;save();return view(row);})).catch(()=>locked(()=>{process.stderr.write('DVAIA_MANAGER_FAILURE phase=completion category=rejected\n');row.state='uncertain';save();return view(row);}));
   // Keep handles private; successful stop must include exact intent identity.
   running.set(q.invocationId,{worker,intent,completion});completion.catch(()=>{}).finally(()=>{if(row.drained)running.delete(q.invocationId);});return null;
  });return result||bounded(completion);
 }
 async function status(raw){const q=W.lookup(raw);await ready();return locked(()=>{assertOpen();identity(q);const row=state.claims[q.invocationId];if(!row)return C.freeze({...q,state:'absent',drained:false});if(!same(q,row.identity))throw fail('MCP_INVOCATION_CONFLICT');return view(row);});}
 async function retire(raw){const q=W.fence(raw);await ready();let toDrain;
  await locked(()=>{assertOpen();identity(q);const existing=state.fences[q.fenceId];if(existing&&!same(existing.request,q))throw fail('MCP_INVOCATION_CONFLICT');
   const rows=Object.values(state.claims).filter(r=>matches(r.claim,q));if(rows.some(r=>!q.invocationIds.includes(r.claim.invocationId)))throw fail('MCP_INVOCATION_FENCE_SET_MISMATCH');
   if(!existing){if(Object.keys(state.fences).length>=maxFences)throw fail('MCP_INVOCATION_CAPACITY');state.fences[q.fenceId]={request:q,drained:false};save();}
   toDrain=rows.filter(r=>!r.drained);
  });
  for(const row of toDrain){const active=running.get(row.claim.invocationId);const proof=await bounded(Promise.resolve().then(()=>active?active.worker.stop():supervisor.reconcile(C.freeze({...row.intent}))));drainedProof(proof,row.intent);if(active)await bounded(active.completion);await locked(()=>{if(!row.drained){row.state='uncertain';row.drained=true;save();}running.delete(row.claim.invocationId);});}
  return locked(()=>{if(Object.values(state.claims).some(r=>matches(r.claim,q)&&!r.drained))throw fail('MCP_INVOCATION_DRAIN_UNCERTAIN');state.fences[q.fenceId].drained=true;save();return C.freeze({...q,retired:true,drained:true});});
 }
 function close(){return closePromise ||= (async()=>{await locked(()=>{closed=true;});for(const [id,active]of running){const proof=await bounded(Promise.resolve().then(()=>active.worker.stop()));drainedProof(proof,active.intent);await bounded(active.completion);await locked(()=>{const r=state.claims[id];if(!r.drained){r.state='uncertain';r.drained=true;save();}});}for(const row of Object.values(state.claims))if(!row.drained){const proof=await bounded(Promise.resolve().then(()=>supervisor.reconcile(C.freeze({...row.intent}))));drainedProof(proof,row.intent);await locked(()=>{row.state='uncertain';row.drained=true;save();});}await locked(()=>{if(!privateLease)fs.rmdirSync(lock);syncDir();});})();}
 return Object.freeze({ready,claim,status,retire,close});
}
module.exports={createInvocationManager};
