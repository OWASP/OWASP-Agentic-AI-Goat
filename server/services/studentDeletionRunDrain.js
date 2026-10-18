'use strict';
const { RUN_FAMILIES }=require('../database/postgres/agentRunReadRepository');

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const fail=(code,message)=>Object.assign(new Error(message||code),{code});

function createStudentDeletionRunDrain({pool,ledger,timeoutMs=120000}){
 if(!pool||typeof pool.query!=='function'||!ledger||typeof ledger.invalidate!=='function')throw new TypeError('Run-drain database and ledger required');
 if(!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>300000)throw new TypeError('Invalid run-drain timeout');
 const codePointOrder=(a,b)=>a<b?-1:a>b?1:0;
 const families=Object.freeze([...RUN_FAMILIES].sort(codePointOrder));
 return async function drainStudentRuns({subjectId,jobId,check,signal}={}){
  if(!Number.isSafeInteger(subjectId)||subjectId<1||subjectId>2147483647||typeof jobId!=='string'||!UUID.test(jobId)||typeof check!=='function')throw new TypeError('Deletion job, owner and lease check required');
  if(signal!==undefined&&(!signal||typeof signal.addEventListener!=='function'||typeof signal.aborted!=='boolean'))throw new TypeError('Valid abort signal required');
  const timeout=AbortSignal.timeout(timeoutMs);
  const boundedSignal=signal?AbortSignal.any([signal,timeout]):timeout;
  const current=async()=>{boundedSignal.throwIfAborted();await check();boundedSignal.throwIfAborted();};
  const ownerKeys=families.map(family=>JSON.stringify([family,String(subjectId)]));

  await current();
  const installed=(await pool.query('SELECT owner_key FROM identity.student_deletion_run_blocks WHERE job_id=$1',[jobId])).rows.map(row=>row.owner_key).sort(codePointOrder);
  const expected=[...ownerKeys].sort(codePointOrder);
  if(installed.length!==expected.length||installed.some((ownerKey,index)=>ownerKey!==expected[index])){
   throw fail('DELETION_RUN_BLOCK_MISMATCH','Deletion run blocks are incomplete');
  }
  await current();

  // Fence every family before waiting on any active lease. No connection is
  // retained by invalidate(); each returned handle acquires only when drained.
  const handles=[];
  for(const ownerKey of ownerKeys){
   await current();
   handles.push({ownerKey,handle:await ledger.invalidate({ownerKey,signal:boundedSignal})});
  }
  await current();

  // Stable serial acquisition avoids reserving one pool connection per family.
  for(const {handle} of handles){
   await current();
   let acquired=false;
   try{
    await handle.acquire();acquired=true;
    await current();
   }finally{
    if(acquired)await handle.release();
   }
   await current();
  }
  return{completed:true,invalidatedOwners:ownerKeys.length};
 };
}

module.exports={createStudentDeletionRunDrain};
