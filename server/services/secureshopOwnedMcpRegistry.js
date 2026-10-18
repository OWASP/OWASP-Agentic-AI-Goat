'use strict';

function failure(code,message='Owned MCP registry unavailable'){return Object.assign(new Error(message),{code});}
function createOwnedMcpRegistry({repository,executor,readMode}={}){
  if(typeof repository?.prepare!=='function'||typeof repository?.beginPrepared!=='function'||typeof repository?.activeEntries!=='function'||typeof repository?.publish!=='function'||typeof repository?.finish!=='function'||typeof repository?.read!=='function'
    ||typeof executor?.execute!=='function'||typeof readMode!=='function')throw new TypeError('Owned MCP registry dependencies required');
  async function mutate(raw,{signal}={}){
    // Snapshot and close public data before mode authority or SQL awaits.
    const prepared=repository.prepare(raw),mode=await readMode(prepared.scope);if(!['vuln','fixed'].includes(mode))throw failure('MCP_REGISTRY_MODE_UNAVAILABLE');
    const admission=await repository.beginPrepared(prepared,{mode});
    if(!admission.newlyAdmitted)return admission.operation;
    try{
      signal?.throwIfAborted();
      await admission.fence.assertRemoteAdmission();
    }catch(cause){await repository.finish(admission,'failed');throw cause;}
    let activeEntries;
    try{activeEntries=await repository.activeEntries(admission);}
    catch(cause){await repository.finish(admission,'failed').catch(()=>{});throw cause;}
    let changes;
    try{
      changes=await executor.execute(admission.prepared.request,{signal,activeEntries,mode,assertCurrent:()=>admission.fence.assertRemoteAdmission()});
    }catch(cause){
      const state=cause?.effectNotStarted===true?'failed':'unknown';
      await repository.finish(admission,state).catch(()=>{});
      if(state==='unknown'){
        const error=failure('MCP_REGISTRY_OUTCOME_UNCERTAIN');error.executionBoundary=true;error.automaticRetry=false;Object.defineProperty(error,'cause',{value:cause});throw error;
      }
      throw cause;
    }
    try{return await repository.publish(admission,changes);}
    catch(cause){if(cause?.code==='MCP_REGISTRY_OUTCOME_UNCERTAIN')throw cause;await repository.finish(admission,'unknown').catch(()=>{});const error=failure('MCP_REGISTRY_OUTCOME_UNCERTAIN');error.executionBoundary=true;error.automaticRetry=false;Object.defineProperty(error,'cause',{value:cause});throw error;}
  }
  return Object.freeze({mutate,read:raw=>repository.read(raw)});
}
module.exports={createOwnedMcpRegistry};
