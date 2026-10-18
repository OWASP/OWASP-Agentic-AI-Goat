'use strict';
const {canonicalDurableGeneration}=require('../agent-runtime/durableGeneration');

// Admin whole-workshop reset only. The caller owns student lifecycle admission;
// this service never reacquires that lock. Student progress-only/profile reset
// have different semantics and must not use this composition.
function createXssParentReset({journal,childJournal,store,runs}={}) {
 if(!['begin','claim','assertCurrent','acknowledgeChild','acknowledgeClear','finalize','fail']
   .every(key=>typeof journal?.[key]==='function')
   ||typeof childJournal?.read!=='function'||typeof store?.retireOrRead!=='function'
   ||typeof store?.clearParent!=='function'||typeof runs?.reset!=='function')
  throw new TypeError('Complete XSS parent reset dependencies required');
 return async function reset({ownerId,operationId,lifecycle}) {
  if(!Number.isSafeInteger(ownerId)||ownerId<1||ownerId>2147483647
   ||lifecycle?.ownerId!==ownerId||typeof lifecycle?.check!=='function')
   throw new TypeError('Protected XSS reset lifecycle authority required');
  await lifecycle.check();
  const operation=await journal.begin({ownerId,operationId});
  await lifecycle.check();
  if(operation.ownerId!==ownerId||operation.operationId!==operationId)
   throw new Error('XSS parent reset operation mismatch');
  // Lost-response retry must return the retained receipt without another graph
  // reset, store clear, or canonical progress-generation increment.
  if(operation.status==='completed')return operation;
  const claimed=await journal.claim({ownerId,operationId});
  if(!claimed?.lease?.token)throw new Error('XSS parent reset is already leased');
  const key={operationId,leaseToken:claimed.lease.token};
  let result;
  try{
   await lifecycle.check();await journal.assertCurrent(key);await lifecycle.check();
   await runs.reset(String(ownerId),async execution=>{
   if(execution?.ownerKey!==JSON.stringify(['XSS',String(ownerId)])
    ||typeof execution?.check!=='function')throw new TypeError('Protected XSS graph reset required');
   const graphGeneration=canonicalDurableGeneration(execution.durableGeneration);
   const authority=async()=>{await lifecycle.check();await execution.check();await lifecycle.check();};
   await authority();
   const check=async()=>{await authority();await journal.assertCurrent(key);await authority();};
    await check();
    if(claimed.childOperationId){
     const child=await childJournal.read(claimed.childOperationId);await check();
     if(!child||child.ownerId!==ownerId
       ||BigInt(graphGeneration)<=BigInt(canonicalDurableGeneration(child.graphParentGeneration)))
      throw new Error('XSS child reset is not superseded by this parent');
     const outcome=await store.retireOrRead({operationId:child.operationId,ownerId,
      graphParentGeneration:child.graphParentGeneration,workshopGeneration:child.workshopGeneration,
      children:child.children});await check();
     await journal.acknowledgeChild({...key,outcome});await check();
    }
    const receipt=await store.clearParent({operationId,ownerId});await check();
    await journal.acknowledgeClear({...key,receipt});await check();
    // Canonical reset, child reconciliation and completed receipt share one
    // identity transaction; neither an external callback nor HTTP can supply it.
    result=await journal.finalize({...key,graphGeneration});
    await authority();
   });
  }catch(error){
   try{await journal.fail({...key,code:error.code});}catch(journalError){error.resetJournalError=journalError;}
   throw error;
  }
  return result;
 };
}
module.exports={createXssParentReset};
