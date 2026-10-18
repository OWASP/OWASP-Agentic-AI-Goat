'use strict';
const {verifyReceipt}=require('../database/postgres/secureshopAuditQueryRepository');
const {createLaunchScope}=require('./secureshopConversationBinding');
const witnesses=new WeakMap();
function uncertain(cause){if(cause?.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN')return cause;const error=Object.assign(Error('Owned audit effect outcome uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});Object.defineProperty(error,'cause',{value:cause});return error;}
function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
function createOwnedAuditQueryAdapter({repository,client}){
 if(['begin','complete'].some(key=>typeof repository?.[key]!=='function')||['search','receipt'].some(key=>typeof client?.[key]!=='function'))throw TypeError('Durable query dependencies required');
 return Object.freeze({async execute({request,execution},fence){
  // Snapshot before the first await so caller mutation cannot change admitted SQL.
  const identity=freeze(structuredClone(request));
  if(fence!==undefined){
   const b=fence?.binding,scope=createLaunchScope(identity.binding),actual=createLaunchScope(b);
   if(typeof fence.assertRemoteAdmission!=='function'||Object.keys(scope).some(key=>scope[key]!==actual[key])
    ||!Number.isSafeInteger(b.personaId)||b.personaId<1||b.role!=='admin'
    ||typeof b.sessionId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(b.sessionId)
    ||typeof b.authorityVersion!=='string'||!/^[1-9][0-9]*$/.test(b.authorityVersion))throw TypeError('Owned audit persona fence mismatch');
  }
  const check=async()=>{await execution.check();if(fence!==undefined){await fence.assertRemoteAdmission();await execution.check();}};
  if(fence!==undefined)await check();
  let effectMayExist=false;
  try {
  const admission=await repository.begin({request:identity,execution});
  effectMayExist=admission.state==='pending'||admission.state==='completed';
  if(fence!==undefined)await check();
  const body={binding:identity.binding,operationId:identity.operationId,username:identity.username};
  let receipt;
  if(admission.state==='completed')receipt=admission.receipt;
  else{
   // A pending central intent can only inspect the durable service record. A
   // missing service receipt is uncertain, never permission to repeat SQL.
   if(fence!==undefined)await check();
   effectMayExist=true;
   receipt=admission.state==='pending'?await client.receipt(body):await client.search(body);
   if(fence!==undefined)await check();
   verifyReceipt(receipt,identity);
   if(fence!==undefined)await check();
   receipt=await repository.complete({request:identity,execution,receipt});
  }
  await check();
  const result=freeze(structuredClone(receipt.result));
  witnesses.set(result,freeze({version:1,request:identity,receipt:structuredClone(receipt),runId:execution.runId,ownerKey:execution.ownerKey,durableGeneration:String(execution.durableGeneration),modelProvenance:false}));
  return result;
  }catch(error){if(fence!==undefined&&effectMayExist)throw uncertain(error);throw error;}
 }});
}
const witnessFor=result=>witnesses.get(result)||null;
module.exports={createOwnedAuditQueryAdapter,witnessFor};
