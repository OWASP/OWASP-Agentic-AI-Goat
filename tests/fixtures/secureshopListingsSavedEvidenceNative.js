'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
async function qualifySavedEvidence({create,request,admissionOwner,sibling,review,personaAuthority,capabilityKey,products,launches}){
 const {prepareListingAdmission}=require('../../server/services/secureshopListingJournalContract');
 const listingJournal=require('../../server/database/postgres/secureshopListingJournalRepository').createListingJournalRepository({pool:review,personaAuthority,capabilityKey});
 const saver=require('../../server/database/postgres/secureshopListingRewriteSaveRepository').createListingRewriteSaveRepository({pool:review,personaAuthority,capabilityKey});
 const deadlineChecks=[];
 const inspectClient=client=>({release:(...args)=>client.release(...args),async query(...args){
  const text=String(args[0]);if(text.includes('FROM secureshop_agents.turn_requests tr')||text.includes('FROM secureshop_review.owned_listing_rewrite_saves s')){
   const limits=(await client.query("SELECT current_setting('statement_timeout') statement_timeout,current_setting('lock_timeout') lock_timeout")).rows[0];
   assert.deepEqual(limits,{statement_timeout:'3s',lock_timeout:'3s'});deadlineChecks.push(text.includes('turn_requests')?'agents':'review');
  }return client.query(...args);
 }});
 const observedAuthority={capture(input){const fence=personaAuthority.capture(input);return{...fence,withPersonaEffect:work=>fence.withPersonaEffect(client=>work(inspectClient(client)))};}};
 const observedReview={connect:async()=>inspectClient(await review.connect())};
 const factory=require('../../server/database/postgres/secureshopListingsEvidenceRepository').createListingsEvidenceRepository;
 const repository=factory({reviewPool:observedReview,personaAuthority:observedAuthority,listingJournal});
 const item={name:request.request.title,description:request.request.description,price:5,category:null,images:[],templateSource:null};
 const siblingBefore=(await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id',[sibling.targetId])).rows;
 const outcome=await create().run(request);assert.equal(outcome.operation.state,'completed');
 const admission=prepareListingAdmission(request),saveOperationId=randomUUID();
 const save=await saver.save({admission,saveOperationId,productId:null,item});
 const started=performance.now(),evidence=await repository.readSaved({admission,saveOperationId}),readMs=performance.now()-started;
 assert.deepEqual(evidence.save,save);assert.equal(evidence.operation.receipt.html,evidence.source.html);
 assert.equal(evidence.turn.result.text,evidence.source.html);assert.equal(evidence.turn.result.taskMetadata.listings.model.callId,evidence.operation.receipt.callId);
 assert.equal(evidence.turn.requestId,admission.request.operationId);assert.equal(evidence.turn.status,'completed');
 const cases=['native graph completed turn exact hash/purpose plus0024 savedHTML provenance readback'];
 await assert.rejects(repository.readSaved({admission,saveOperationId:randomUUID()}));
 const invalids=[{...request,scope:sibling.scope},{...request,targetId:sibling.targetId},{...request,personaSession:sibling.personaSession},
  {...request,scope:{...request.scope,generation:request.scope.generation+1}}, {...request,request:{...request.request,title:'Different title'}}];
 for(const raw of invalids)await assert.rejects(repository.readSaved({admission:prepareListingAdmission(raw),saveOperationId}));
 cases.push('missing save siblingowner target personasession stalegeneration and changedrequest rejected');
 const currentRevision=(await review.query('SELECT revision::text FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=$1',[admissionOwner.targetId])).rows[0].revision;
 const otherRequest={...request,catalogRevision:currentRevision,request:{...request.request,operationId:randomUUID()}};
 const otherResult=await create().run(otherRequest),otherAdmission=prepareListingAdmission(otherRequest),otherSaveId=randomUUID();
 const otherSave=await saver.save({admission:otherAdmission,saveOperationId:otherSaveId,productId:null,item});
 const otherEvidence=await repository.readSaved({admission:otherAdmission,saveOperationId:otherSaveId});
 assert.equal(otherResult.operation.receipt.html,outcome.operation.receipt.html);
 assert.notEqual(otherEvidence.turn.result.taskMetadata.listings.model.callId,evidence.turn.result.taskMetadata.listings.model.callId);
 await assert.rejects(repository.readSaved({admission,saveOperationId:otherSaveId}));
 await assert.rejects(repository.readSaved({admission:otherAdmission,saveOperationId}));
 const mismatchedJournal={get:async raw=>{const value=await listingJournal.get(raw);return{...value,receipt:{...value.receipt,callId:otherEvidence.operation.receipt.callId}};}};
 await assert.rejects(factory({reviewPool:observedReview,personaAuthority:observedAuthority,listingJournal:mismatchedJournal}).readSaved({admission,saveOperationId}),error=>error.code==='LISTING_EVIDENCE_UNAVAILABLE');
 cases.push('real persisted canonicalturn rejects injected identicalHTML donorcallId receipt without mutating journal');
 cases.push('identicalHTML independently completed operations have distinct canonicalcallIDs; crosssave binding rejected both directions');
 const target={...admissionOwner.scope,targetId:admissionOwner.targetId};
 await products.updateListing(target,admissionOwner.persona.id,save.productId,{price:6});
 assert.equal((await repository.readSaved({admission,saveOperationId})).source.html,evidence.source.html);
 await products.updateListing(target,admissionOwner.persona.id,save.productId,{description:'Changed current description'});
 await assert.rejects(repository.readSaved({admission,saveOperationId}));
 await products.updateListing(target,admissionOwner.persona.id,save.productId,{description:item.description});
 await assert.rejects(repository.readSaved({admission,saveOperationId}));
 assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_generated_products WHERE target_id=$1 AND product_id=$2',[admissionOwner.targetId,save.productId])).rows[0].n,0);
 assert.equal((await repository.readSaved({admission:otherAdmission,saveOperationId:otherSaveId})).save.productId,otherSave.productId);
 await products.archiveListing(target,admissionOwner.persona.id,otherSave.productId);
 await assert.rejects(repository.readSaved({admission:otherAdmission,saveOperationId:otherSaveId}));
 cases.push('matching priceoverlay accepted; source edit permanently invalidates provenance even after restore; independent valid product archivedoverlay rejected');
 await launches.beginReset({...admissionOwner.scope,expectedGeneration:admissionOwner.scope.generation,idempotencyKey:randomUUID()});
 await assert.rejects(repository.readSaved({admission:otherAdmission,saveOperationId:otherSaveId}),error=>error.code==='STALE_LAUNCH');
 assert.deepEqual((await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id',[sibling.targetId])).rows,siblingBefore);
 cases.push('canonical beginReset rejects prior saved evidence; sibling product snapshot unchanged');
 assert.ok(deadlineChecks.includes('agents')&&deadlineChecks.includes('review'));
 return {actualModelCalls:0,cases,readMs,deadlineChecks,operationId:admission.request.operationId,saveOperationId,productId:save.productId,
  htmlSha256:evidence.source.htmlSha256,turnRequestHash:evidence.turn.requestHash,callId:evidence.operation.receipt.callId,
  otherOperationId:otherAdmission.request.operationId,otherCallId:otherEvidence.operation.receipt.callId,
  limitations:['Controlled provider metadata is synthetic and gives no model qualification','No browser or Judge/objectivecredit qualification']};
}
module.exports={qualifySavedEvidence};
