'use strict';
// Server-composed application only. Recovery/history never invoke query/model.
function createAnalyticsApplication({foundation,requests,ownedQuery,launches,personaAuthority}){
 if(['query','recover'].some(k=>typeof foundation?.[k]!=='function')||typeof requests?.history!=='function'||typeof ownedQuery?.topProducts!=='function'||typeof launches?.assertCurrent!=='function'||typeof personaAuthority?.capture!=='function')throw TypeError('Owned Analytics application dependencies required');
 return Object.freeze({
  async describe({scope,persona,personaSession,signal}){
   signal?.throwIfAborted();await launches.assertCurrent(scope);const fence=await personaAuthority.capture({scope,personaId:persona.id,role:persona.role,...personaSession});
   const expected={...scope,personaId:persona.id,role:persona.role,...personaSession};
   if(!['merchant','admin'].includes(persona.role)||typeof fence?.assertRemoteAdmission!=='function'||Object.keys(expected).some(k=>fence.binding?.[k]!==expected[k]))throw Object.assign(Error('Shop authentication required'),{code:'SHOP_AUTH_INVALID'});
   await fence.assertRemoteAdmission();signal?.throwIfAborted();await launches.assertCurrent(scope);
   const scopeKey=require('node:crypto').createHash('sha256').update(JSON.stringify(['secureshop-owned-analytics.v1',scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId,persona.id,persona.role,personaSession.sessionId,personaSession.authorityVersion])).digest('hex');
   return Object.freeze({ok:true,analytics:Object.freeze({capability:'secureshop-owned-analytics.v1',scopeKey})});
  },
  async query(input){const result=await foundation.query(input);return result?.status?result:Object.freeze({status:'completed',...result});},
  recover:input=>foundation.recover(input),
  async history({scope,persona,personaSession,limit,cursor,signal}){
   signal?.throwIfAborted();await launches.assertCurrent(scope);const page=await requests.history({scope,persona,personaSession,limit,cursor});
   const entries=[];for(const item of page.requests){signal?.throwIfAborted();const result=await foundation.recover({scope,persona,personaSession,requestId:item.requestId,signal});if(result)entries.push({...result,createdAt:item.createdAt});}
   signal?.throwIfAborted();await launches.assertCurrent(scope);return Object.freeze({entries,nextCursor:page.nextCursor});
  },
  topProducts:({scope,persona,personaSession,limit,signal})=>ownedQuery.topProducts({scope,persona,personaSession,limit,signal,checkCurrent:()=>launches.assertCurrent(scope)}),
 });
}
module.exports={createAnalyticsApplication};
