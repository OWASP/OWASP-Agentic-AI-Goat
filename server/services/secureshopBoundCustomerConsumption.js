'use strict';
const {createCustomerConsumptionAuthority}=require('./secureshopCustomerConsumptionAuthority');
// Server-composition seam for the original customer supervisor, not a new task
// or prompt. The route must supply authenticated scope/persona/session records.
function createBoundCustomerConsumption({modeAuthority,launches,personaAuthority,conversations,
  provider,pool,manifest}) {
  const authority=createCustomerConsumptionAuthority({modeAuthority,launches,personaAuthority,conversations});
  if(typeof conversations?.runExclusive!=='function')throw TypeError('Owned conversation serialization required');
  return Object.freeze({async run({scope,persona,personaSession,sessionId,message,signal,stream}) {
    if(typeof message!=='string'||!message.trim())throw TypeError('Message required');
    return conversations.runExclusive(sessionId,scope,persona,async()=>{
      const consumptionCapability=await authority.capture({scope,persona,personaSession,sessionId,signal});
      const {customerSupervisor}=require('./secureshop/supervisors/customerSupervisor');
      return customerSupervisor.run(sessionId,message,{provider,pool,manifest,signal,stream,
        callerRole:'customer',callerId:persona.id,role:'customer',consumptionRequired:true,consumptionCapability});
    });
  }});
}
module.exports={createBoundCustomerConsumption};
