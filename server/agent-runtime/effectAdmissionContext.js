'use strict';
// Server-only scope of the already-claimed durable effect. Never derived from
// request/model arguments. Async descendants lose access when work settles.
const {AsyncLocalStorage}=require('node:async_hooks');
const storage=new AsyncLocalStorage();
async function withEffectAdmission(context,key,work){
 const state={ownerKey:context.ownerKey,runId:context.runId,generation:String(context.durableGeneration),key,active:true};
 try{return await storage.run(state,work);}finally{state.active=false;}
}
function currentEffectAdmission(execution){
 const s=storage.getStore();
 if(!s?.active||s.ownerKey!==execution?.ownerKey||s.runId!==execution?.runId||s.generation!==String(execution?.durableGeneration))throw Object.assign(Error('Current durable effect admission required'),{code:'PROTECTED_EFFECT_ADMISSION_REQUIRED'});
 return Object.freeze({ledgerEffectKey:s.key});
}
module.exports={withEffectAdmission,currentEffectAdmission};
