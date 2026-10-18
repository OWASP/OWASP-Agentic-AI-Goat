'use strict';
// Cleanup remains active independently of serving eligibility. The manager is
// a private authenticated transport dependency, never a request-supplied object.
const C=require('./secureshopOwnedMcpInvocationContract');
const {createLaunchScope}=require('./secureshopConversationBinding');
const fail=()=>Object.assign(Error('Owned MCP invocation drain unavailable'),{code:'MCP_INVOCATION_DRAIN_REQUIRED'});
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function createOwnedMcpInvocationLifecycle({journal,cleanupAuthority,manager,timeoutMs=15000}={}){
 if(typeof journal?.existing!=='function'||typeof journal?.recordFence!=='function'||typeof cleanupAuthority?.getOperation!=='function'
  ||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000)throw new TypeError('Invocation cleanup dependencies required');
 async function drain(scope,fenceId,kind,check,signal){
  if(typeof fenceId!=='string'||!UUID.test(fenceId))throw fail();
  signal?.throwIfAborted();await check();
  const rows=await journal.existing(scope,{ownerOnly:kind==='owner_deletion'});
  // Older registry-only installations need no new manager or remote endpoint.
  if(rows.length===0)return;
  if(typeof manager?.retire!=='function')throw fail();
  const groups=new Map();for(const row of rows){
   if(typeof row.invocation_id!=='string'||!UUID.test(row.invocation_id)||typeof row.manager_instance_id!=='string'||!UUID.test(row.manager_instance_id)
    ||typeof row.runtime_sha256!=='string'||!/^[0-9a-f]{64}$/.test(row.runtime_sha256))throw fail();
   const group=groups.get(row.manager_instance_id)||{runtime:row.runtime_sha256,ids:[]};
   if(group.runtime!==row.runtime_sha256||group.ids.includes(row.invocation_id))throw fail();
   group.ids.push(row.invocation_id);groups.set(row.manager_instance_id,group);
  }
  for(const [managerInstanceId,group]of groups){
   await check();signal?.throwIfAborted();
   const request=C.freeze({version:'owned-mcp-invocation-fence-v1',kind,fenceId,...scope,managerInstanceId,runtimeSha256:group.runtime,invocationIds:group.ids.sort()});
   const controller=new AbortController();let timer;
   const aborted=()=>controller.abort(signal.reason);signal?.addEventListener('abort',aborted,{once:true});
   try{
    const raw=await Promise.race([Promise.resolve().then(()=>manager.retire(request,{signal:controller.signal})),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(fail());},timeoutMs);})]);
    const receipt=C.bounded(raw,65536);
    if(C.digest(receipt)!==C.digest({...request,retired:true,drained:true}))throw fail();
    // A hash comparison binds fields; authentication is the pinned transport's
    // responsibility. No receipt supplied by a browser is accepted here.
    await check();signal?.throwIfAborted();await journal.recordFence(receipt);
   }finally{clearTimeout(timer);signal?.removeEventListener('abort',aborted);}
  }
  await check();signal?.throwIfAborted();
 }
 async function beforeRetirement(resetId,{signal}={}){
  const original=await cleanupAuthority.getOperation(resetId);
  if(original?.resetId!==resetId||!['fenced','committed','aborted'].includes(original.status))throw fail();
  const scope=createLaunchScope(original.binding);
  const check=async()=>{const current=await cleanupAuthority.getOperation(resetId);if(current?.resetId!==resetId||!['fenced','committed','aborted'].includes(current.status)||C.digest(current.binding)!==C.digest(original.binding))throw fail();};
  await drain(scope,resetId,'retirement',check,signal);
 }
 async function beforeDeletion({jobId,subjectId,check,signal}){
  if(!Number.isSafeInteger(subjectId)||subjectId<1||typeof check!=='function')throw fail();
  await drain({platformOwnerId:subjectId},jobId,'owner_deletion',check,signal);
 }
 return Object.freeze({beforeRetirement,beforeDeletion});
}
module.exports={createOwnedMcpInvocationLifecycle};
