'use strict';
const mailScene=require('./secureshopMailSceneBinding');
// Same agents transaction: never call the pool-backed read under this lease.
function createPersonaInboxEffect({fence,repository}){
 if(typeof fence?.withPersonaEffect!=='function'||typeof repository?.readWithClient!=='function')throw TypeError('Client-aware inbox authority required');
 return Object.freeze({...repository,async read(scope,persona,args){
 const current=mailScene.current(scope);
 if(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k=>current[k]!==fence.binding[k])||persona.id!==fence.binding.personaId||persona.role!==fence.binding.role)throw Object.assign(Error('Inbox authority unavailable'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
 return mailScene.withLease(scope,()=>fence.withPersonaEffect(async client=>{await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");return repository.readWithClient(client,scope,persona,mailScene.productScene(scope)?{...args,personaSession:{sessionId:fence.binding.sessionId,authorityVersion:fence.binding.authorityVersion}}:args);}));
 },async advanceAcl(scope,args,persona){const current=mailScene.current(scope);if(typeof repository.advanceAclWithClient!=='function'||['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k=>current[k]!==fence.binding[k])||persona.id!==fence.binding.personaId||persona.role!==fence.binding.role)throw Object.assign(Error('Inbox authority unavailable'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});return mailScene.withLease(scope,()=>fence.withPersonaEffect(async client=>{await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");return repository.advanceAclWithClient(client,scope,args,persona);}));}
 });
}
module.exports={createPersonaInboxEffect};
