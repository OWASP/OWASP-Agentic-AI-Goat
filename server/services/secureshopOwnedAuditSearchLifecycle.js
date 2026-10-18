'use strict';
const { receiptFor } = require('./secureshopOwnedAuditSearchSnapshot');
// Unmounted lifecycle foundation. journal.withLock must hold a durable exclusive
// target lease until its callback settles; service calls must join child cleanup.
function createOwnedAuditSearchLifecycle({journal,service,assertCurrent}={}) {
 for(const [object,names] of [[journal,['withLock','get','begin','ready','retiring','retired']],
   [service,['provision','retire']]]) for(const name of names) if(typeof object?.[name]!=='function') throw new TypeError(`Required ${name}`);
 if(typeof assertCurrent!=='function')throw new TypeError('Current launch validator required');
 const uncertain=()=>Object.assign(new Error('Owned audit target requires lifecycle reconciliation'),{code:'AUDIT_SEARCH_TARGET_UNCERTAIN'});
 return Object.freeze({
  async provision(snapshot){
   const receipt=receiptFor(snapshot);if(!receipt)throw new TypeError('Private audit snapshot required');
   const binding=receipt.binding;
   return journal.withLock(binding,async()=>{
    await assertCurrent(binding);
    const previous=await journal.get(binding);
    if(previous){
     if(previous.payloadSha256!==receipt.payloadSha256||previous.sourcesSha256!==receipt.sourcesSha256)
      throw Object.assign(new Error('Owned audit snapshot conflicts with admitted generation'),{code:'AUDIT_SEARCH_TARGET_CONFLICT'});
     if(previous.state==='ready')return previous.target;
     throw uncertain(); // Never retry network provisioning after an unknown outcome.
    }
    const admission=await journal.begin(binding,receipt);
    if(typeof admission?.target!=='string'||!/^audit_[a-f0-9]{32}$/.test(admission.target))throw uncertain();
    // Only teaching rows cross the service boundary. No source pool, platform
    // credentials, journal records or owner identifiers are passed to the target.
    const target=admission.target;
    await service.provision({target,rows:snapshot.rows,payloadSha256:receipt.payloadSha256});
    try { await assertCurrent(binding);await journal.ready(binding,target); }
    catch(error){
     // Preserve pending uncertainty if retirement or journal persistence fails.
     await service.retire(target);
     throw error;
    }
    return target;
   });
  },
  async search(binding,username){
   if(typeof service.search!=='function')throw new TypeError('Owned query service required');
   return journal.withLock(binding,async()=>{
    await assertCurrent(binding);
    const current=await journal.get(binding);
    if(current?.state!=='ready')throw uncertain();
    const result=await service.search(current.target,username);
    // The SQL promise must drain before this lease can release. A reset that
    // changed generation during execution suppresses publication, not cleanup.
    await assertCurrent(binding);
    return result;
   });
  },
  async retire(binding){
   return journal.withLock(binding,async()=>{
    const current=await journal.get(binding);
    if(!current||current.state==='retired')return;
    if(!current.target)throw uncertain();
    await journal.retiring(binding);
    await service.retire(current.target);
    await journal.retired(binding);
   });
  }
 });
}
module.exports={createOwnedAuditSearchLifecycle};
