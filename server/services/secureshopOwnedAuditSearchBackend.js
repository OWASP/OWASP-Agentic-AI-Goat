'use strict';
const {createHash}=require('node:crypto');
const {canonicalDigest}=require('./mcp/protocolContext');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {createAuditSourceManifest}=require('./secureshopAuditSourceManifest');
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const exact=(value,keys)=>{if(!value||Object.keys(value).sort().join(',')!==[...keys].sort().join(','))throw TypeError('Invalid private request');};
// Authentication is the daemon's responsibility. This adapter receives only
// server-composed requests, never browser/model-selected binding authority.
function createOwnedAuditBackend({journal,service,checkReadiness}){
 return Object.freeze({
  async readiness(body){exact(body,[]);return checkReadiness();},
  async target(body){exact(body,['binding']);const binding=createLaunchScope(body.binding);return journal.withLock(binding,async()=>{const current=await journal.get(binding);if(!current)return{missing:true};if(current.state!=='ready')throw Error('Target requires reconciliation');return{target:current.target,sourceSha256:current.sourcesSha256,payloadSha256:current.payloadSha256};});},
  async provision(body){
   exact(body,['binding','rows','sources']);await checkReadiness();const binding=createLaunchScope(body.binding);
   const manifest=createAuditSourceManifest(body.sources);
   const rows=body.sources.map(r=>({id:r.id,actor:r.actor,action:r.action,target:r.target,params_json:r.params_json,ts:r.ts}));
   if(digest(rows)!==digest(body.rows)||rows.length>200||Buffer.byteLength(JSON.stringify(rows))>16*1024*1024)throw TypeError('Snapshot mismatch');
   const receipt={binding,payloadSha256:digest(rows),sourcesSha256:manifest.sourcesSha256};
   return journal.withLock(binding,async()=>{
    const previous=await journal.get(binding);
    if(previous){if(previous.payloadSha256!==receipt.payloadSha256||previous.sourcesSha256!==receipt.sourcesSha256||previous.state!=='ready')throw Error('Reconciliation or conflict');return{target:previous.target};}
    const {target}=await journal.begin(binding,receipt);await service.provision({target,rows,payloadSha256:receipt.payloadSha256});await journal.ready(binding,target);return{target};
   });
  },
  async search(body){
   exact(body,['binding','username','operationId']);
   if(typeof body.operationId!=='string'||! /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(body.operationId)||typeof body.username!=='string'||Buffer.byteLength(body.username)>8192)throw TypeError('Invalid query operation');
   await checkReadiness();const binding=createLaunchScope(body.binding);
   return journal.withLock(binding,async()=>{
    const target=await journal.get(binding);if(!target)throw Error('Target unavailable');
    const requestSha256=digest([binding,target.target,body.operationId,body.username]);
    const prior=await journal.getQuery(target.target,body.operationId);
    const unavailable=code=>Object.assign(Error(code),{code});
    if(prior){
     if(prior.request_sha256!==requestSha256)throw unavailable('AUDIT_QUERY_CONFLICT');
     if(prior.state!=='completed')throw unavailable('AUDIT_QUERY_UNCERTAIN');
     if(target.state!=='ready')throw unavailable('AUDIT_QUERY_RETIRED');
     if(prior.receipt?.requestSha256!==requestSha256||prior.receipt?.resultSha256!==canonicalDigest(prior.receipt.result))throw unavailable('AUDIT_QUERY_UNCERTAIN');
     return prior.receipt;
    }
    if(target.state!=='ready')throw unavailable('AUDIT_QUERY_RETIRED');
    await journal.beginQuery(target.target,body.operationId,requestSha256);
    try{
     const result=await service.search(target.target,body.username);
     const extraction=service.extractionEffect?.(result);
     const timing=service.timingEffect?.(result);
     const receipt={version:1,operationId:body.operationId,binding,target:target.target,
      requestSha256,sourceSha256:target.sourcesSha256,payloadSha256:target.payloadSha256,
      resultSha256:canonicalDigest(result),result,...(extraction?{extraction}:{}),
      ...(timing?{timing}:{})};
     if(Buffer.byteLength(JSON.stringify(receipt))>17*1024*1024)throw Error('Result exceeds receipt budget');
     await journal.completeQuery(target.target,body.operationId,receipt);
     return receipt;
    }catch{throw unavailable('AUDIT_QUERY_UNCERTAIN');}
   });
  },
  async receipt(body){
   exact(body,['binding','username','operationId']);const binding=createLaunchScope(body.binding);
   if(typeof body.operationId!=='string'||! /^[a-f0-9-]{36}$/.test(body.operationId)||typeof body.username!=='string'||Buffer.byteLength(body.username)>8192)throw TypeError('Invalid receipt request');
   return journal.withLock(binding,async()=>{
    const target=await journal.get(binding);const prior=target&&await journal.getQuery(target.target,body.operationId);
    const fail=code=>{throw Object.assign(Error(code),{code});};
    if(!prior||prior.state!=='completed')fail('AUDIT_QUERY_UNCERTAIN');
    if(prior.request_sha256!==digest([binding,target.target,body.operationId,body.username]))fail('AUDIT_QUERY_CONFLICT');
    if(prior.receipt?.resultSha256!==canonicalDigest(prior.receipt.result))fail('AUDIT_QUERY_UNCERTAIN');
    return prior.receipt;
   });
  },
  async retire(body){exact(body,['binding']);const binding=createLaunchScope(body.binding);return journal.withLock(binding,async()=>{const current=await journal.get(binding);if(!current){await journal.begin(binding,{binding,retirementOnly:true});await journal.retired(binding);return{};}if(current.state==='retired')return{};await journal.retiring(binding);await service.retire(current.target);await journal.retired(binding);return{};});},
  async destroy(body){exact(body,['binding']);const binding=createLaunchScope(body.binding);return journal.withLock(binding,async()=>{const current=await journal.get(binding);if(!current){await journal.begin(binding,{binding,retirementOnly:true});await journal.retired(binding);return{destroyed:true};}if(current.state!=='retired'){await journal.retiring(binding);await service.retire(current.target);await journal.retired(binding);}await journal.redactQueries(current.target);return{destroyed:true,target:current.target};});},
  close:()=>service.close(),
 });
}
module.exports={createOwnedAuditBackend};
