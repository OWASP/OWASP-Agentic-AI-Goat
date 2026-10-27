'use strict';
const {createConversationBinding} = require('./secureshopConversationBinding');
const {captureFeatureMode} = require('./secureshopFeatureModeAuthority');
const capabilities = new WeakMap();
const LIMITS = Object.freeze({toolResultBytes:32768,providerInputBytes:131072});
const fail = () => Object.assign(new Error('Customer consumption authority unavailable'),
  {code:'CUSTOMER_CONSUMPTION_AUTHORITY',executionBoundary:true});
const exceeded = () => Object.assign(new Error('Customer consumption byte budget exceeded'),
  {code:'CUSTOMER_CONSUMPTION_LIMIT',executionBoundary:true});
function createCustomerConsumptionAuthority({modeAuthority,launches,personaAuthority,conversations}) {
  for (const fn of [modeAuthority?.capture,modeAuthority?.assertToken,launches?.assertCurrent,
    personaAuthority?.capture,conversations?.assertOwned]) if(typeof fn!=='function')throw fail();
  return Object.freeze({async capture({scope,persona,personaSession,sessionId,signal}) {
    const binding=createConversationBinding(scope,persona);
    const boundPersona=Object.freeze({id:binding.shopUserId,role:binding.role});
    if(binding.role!=='customer'||typeof sessionId!=='string'||!sessionId)throw fail();
    const credential=Object.freeze({...personaSession});
    const mode=await captureFeatureMode(modeAuthority,binding,'customer_consumption');
    const fence=await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:'customer',...credential});
    const expected={...binding,personaId:binding.shopUserId,sessionId:credential.sessionId,authorityVersion:credential.authorityVersion};
    if(!fence?.binding||typeof fence.assertRemoteAdmission!=='function'||
      ['launchId','scenarioId','generation','platformOwnerId','platformSessionId','personaId','role','sessionId','authorityVersion']
        .some(key=>fence.binding[key]!==expected[key])||!credential.sessionId||
        typeof credential.authorityVersion!=='string'||!/^[1-9]\d*$/.test(credential.authorityVersion))throw fail();
    const check=async()=>{try{signal?.throwIfAborted();await launches.assertCurrent(binding);
      await conversations.assertOwned(sessionId,binding,boundPersona);await mode.assertCurrent();
      await fence.assertRemoteAdmission();await mode.assertCurrent();signal?.throwIfAborted();}
      catch(cause){if(signal?.aborted)throw cause;throw Object.assign(new Error('Customer consumption authority unavailable',{cause}),
        {code:cause?.code||'CUSTOMER_CONSUMPTION_AUTHORITY',executionBoundary:true});}};
    await check();
    const cap=Object.freeze({});
    capabilities.set(cap,{binding,sessionId,check,fixed:mode.snapshot.mode==='fixed',mode:mode.snapshot});
    return cap;
  }});
}
function consumptionFor(cap,{sessionId,role,callerId}) {
  const record=capabilities.get(cap);
  if(!record||record.sessionId!==sessionId||role!=='customer'||record.binding.shopUserId!==callerId)throw fail();
  let input=null;
  function validate(value) {
    if(record.fixed&&Buffer.byteLength(JSON.stringify(value),'utf8')>LIMITS.providerInputBytes)throw exceeded();
  }
  return Object.freeze({check:record.check,fixed:record.fixed,
    input(value){if(!record.fixed)return;validate(value);input=structuredClone(value);},
    append(message){if(!record.fixed)return;if(!input)throw fail();
      const next={...input,messages:[...input.messages,message]};validate(next);input=next;},
    tool(value){if(record.fixed&&Buffer.byteLength(value,'utf8')>LIMITS.toolResultBytes)throw exceeded();},
    mode:record.mode});
}
module.exports={createCustomerConsumptionAuthority,consumptionFor,LIMITS};
