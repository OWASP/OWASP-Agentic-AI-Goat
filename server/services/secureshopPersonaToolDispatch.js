'use strict';
// Candidate adapter: each locally transactional tool must use the supplied
// client exclusively for its short effect+audit. No network/model work there.
function createPersonaToolDispatch({fence,binding,localTools,pool,modes}={}){
 const fail=()=>Object.assign(new Error('Persona dispatch authority unavailable'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
 if(!fence||typeof fence.withPersonaEffect!=='function'||typeof fence.assertRemoteAdmission!=='function'
  ||!fence.binding||!binding||['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k=>fence.binding[k]!==binding[k])
  ||fence.binding.personaId!==binding.shopUserId||fence.binding.role!==binding.role||!modes||typeof modes!=='object')throw fail();
 const entries=localTools instanceof Map?[...localTools]:Object.entries(localTools||{}),wrapped=new Map();
 const current=async()=>{try{await fence.assertRemoteAdmission();}catch(e){e.executionBoundary=true;throw e;}};
 const projectRecoverableToolError=typeof pool?.projectRecoverableToolError==='function'
  ?pool.projectRecoverableToolError.bind(pool):null;
 for(const [name,fn] of entries){
  if(typeof fn!=='function'||!Object.hasOwn(modes,name)||!['local_transaction','remote_admission'].includes(modes[name]))throw fail();
  const mode=modes[name];
  wrapped.set(name,async (args,invocation)=>{
   try{
    if(mode==='local_transaction') {
     let callbackError;
     try{return await fence.withPersonaEffect(async(client,authority)=>{try{return await fn(args,Object.freeze({client,authority,invocation}));}catch(e){callbackError=e;throw e;}});}
     catch(e){if(e!==callbackError)e.executionBoundary=true;throw e;}
    }
    await current();const result=await fn(args,invocation);await current();return result;
   }catch(e){if(e?.code==='SHOP_AUTH_INVALID')e.executionBoundary=true;throw e;}
  });
 }
 return Object.freeze({localTools:wrapped,pool:Object.freeze({
  async callTool(...args){
   await current();let result;
   try{result=await pool.callTool(...args);}
   catch(error){await current();throw error;}
   await current();return result;
  },
  ...(projectRecoverableToolError?{projectRecoverableToolError(error){
   if(error?.executionBoundary===true||error?.code==='SHOP_AUTH_INVALID')return null;
   return projectRecoverableToolError(error);
  }}:{})
 }),check:current});
}
module.exports={createPersonaToolDispatch};
