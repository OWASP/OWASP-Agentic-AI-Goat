'use strict';
const { createLaunchScope } = require('./secureshopConversationBinding');
const { validateTaskPolicySnapshot } = require('./secureshopPromptPolicyTaskSnapshot');
const HASH=/^[a-f0-9]{64}$/,UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function unavailable(){return Object.assign(new Error('Bound policy search unavailable'),{code:'POLICY_SEARCH_UNAVAILABLE'});}
function createSecureShopBoundPolicySearch({repository,checkCurrent}={}){
 if(typeof repository?.searchPolicies!=='function'||typeof checkCurrent!=='function')throw new TypeError('Bound policy search dependencies required');
 return Object.freeze({async search(raw){const input=structuredClone(raw),scope=createLaunchScope(input.scope),persona=input.persona,snapshot=validateTaskPolicySnapshot(input.policySnapshot);
  if(persona?.role!=='customer'||!Number.isSafeInteger(persona.id)||persona.id<1||snapshot.role!=='customer'||snapshot.recipient!=='summarizer'
   ||typeof input.query!=='string'||!input.query.isWellFormed()||input.query.includes('\0')||Buffer.byteLength(input.query,'utf8')<1||Buffer.byteLength(input.query,'utf8')>4096)throw unavailable();
  await checkCurrent(scope);const value=await repository.searchPolicies({scope,persona:{id:persona.id,role:'customer'},query:input.query,limit:4,policyVersion:snapshot.policyVersion,policySnapshotSha256:snapshot.sha256});await checkCurrent(scope);
  if(!value||value.policyVersion!==snapshot.policyVersion||value.policySnapshotSha256!==snapshot.sha256||!UUID.test(value.revisionId)||!Array.isArray(value.results)||value.results.length>4)throw unavailable();
  const results=value.results.map(row=>{if(!row||typeof row.name!=='string'||typeof row.text!=='string'||!HASH.test(row.sourceSha256)||!Number.isFinite(row.score))throw unavailable();return Object.freeze({name:row.name,text:row.text,sourceSha256:row.sourceSha256,score:row.score});});
  // Rendered policy text is intentionally returned verbatim to the next model turn.
  return Object.freeze({revisionId:value.revisionId,policyVersion:value.policyVersion,policySnapshotSha256:value.policySnapshotSha256,results:Object.freeze(results)});
 }});
}
module.exports={createSecureShopBoundPolicySearch};
