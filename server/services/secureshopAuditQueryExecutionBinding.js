'use strict';
const {createLaunchScope}=require('./secureshopConversationBinding');
const {canonicalDigest}=require('./mcp/protocolContext');
function createAuditQueryExecutionBinding({repository,conversations}){
 if(typeof repository?.getBoundSession!=='function'||typeof conversations?.assertOwned!=='function')throw TypeError('Canonical bound conversation authority required');
 return async(binding,execution)=>{
  let owner;try{owner=JSON.parse(execution.ownerKey);}catch{}
  if(!Array.isArray(owner)||owner.length!==2||owner[0]!=='SecureShopBoundConversation'||typeof owner[1]!=='string'||! /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(owner[1]))throw Object.assign(new Error('Audit conversation execution unavailable'),{code:'AUDIT_QUERY_STALE'});
  const session=await repository.getBoundSession(owner[1]);
  if(session?.state!=='active'||session.binding?.role!=='admin'||canonicalDigest(createLaunchScope(session.binding))!==canonicalDigest(createLaunchScope(binding)))throw Object.assign(new Error('Audit conversation execution unavailable'),{code:'AUDIT_QUERY_STALE'});
  await conversations.assertOwned(owner[1],binding,{id:session.binding.shopUserId,role:session.binding.role},session.purpose);
 };
}
module.exports={createAuditQueryExecutionBinding};
