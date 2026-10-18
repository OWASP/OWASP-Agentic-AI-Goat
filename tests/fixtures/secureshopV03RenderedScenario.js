'use strict';
const assert=require('node:assert/strict');
const H=require('./secureshopListingImageOptimizeRenderedQualification');
const E=require('./secureshopV03ActualEvidence');
const{diagnosticHostname}=require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const immutable=value=>structuredClone(value);
const withinV03ProviderDispatchBudget=count=>Number.isSafeInteger(count)&&count>=1&&count<=27;
function assertDistinctProductIdentity(prior,current){
 assert.ok(prior&&current&&typeof prior.target?.targetId==='string'&&typeof current.target?.targetId==='string');
 assert.ok(Number.isSafeInteger(prior.product?.productId)&&prior.product.productId>0);
 assert.ok(Number.isSafeInteger(current.product?.productId)&&current.product.productId>0);
 assert.notDeepEqual([prior.target.targetId,prior.product.productId],
  [current.target.targetId,current.product.productId],'V03 cases require distinct target-scoped products');
}
function summarizeActorInvocations({invocations,wires}){
 assert.ok(Array.isArray(invocations)&&Array.isArray(wires));
 const expected=[...['vulnerable','benign','fixed'].flatMap(kind=>['search','role','listing'].map(phase=>`${kind}:${phase}`))];
 let cursor=0,wireCursor=0,corrective=0,qualifiedSelections=0;
 for(const phase of expected){
  const rows=[];while(cursor<invocations.length&&invocations[cursor].phase===phase)rows.push(invocations[cursor++]);
  const kind=phase.split(':')[1],chatRows=rows.filter(row=>row.method==='chat'),finalRows=rows.filter(row=>row.method==='finalResponse');
  assert.equal(finalRows.length,1,`${phase} has one final response`);assert.equal(rows.at(-1),finalRows[0]);
  assert.equal(chatRows.length,kind==='search'?rows.length-1:1,`${phase} has its bounded decision chain`);
  assert.ok(kind!=='search'||chatRows.length===1||chatRows.length===2,`${phase} allows at most one accounted correction`);
  const request=rows[0]?.request;assert.ok(request);for(const row of rows){
   assert.deepEqual(row.request,request,`${phase} stays on the original HTTP turn`);
   assert.ok(Number.isSafeInteger(row.wireStart)&&Number.isSafeInteger(row.wireEnd)&&row.wireStart===wireCursor&&row.wireEnd>row.wireStart&&row.wireEnd<=wires.length);
   for(const wire of wires.slice(row.wireStart,row.wireEnd))assert.equal(wire.kind,'actor');wireCursor=row.wireEnd;
   assert.equal(row.result?.provider,'ollama');assert.equal(row.result?.model,'llama3.1:8b');assert.equal(row.result?.mocked,false);assert.notEqual(row.result?.fallback,true);
  }
  const expectedTool=kind==='search'?'merchant.catalog_search':kind==='role'?'merchant.listing_optimize_setup':'listing.optimize_images';
  for(const row of chatRows){assert.equal(row.result?.stop_reason,'tool_use');assert.equal(row.result?.tool_uses?.length,1);assert.equal(row.result.tool_uses[0].name,expectedTool);}
  assert.equal(finalRows[0].result?.tool_uses?.length||0,0);assert.equal(typeof finalRows[0].result?.text,'string');assert.ok(finalRows[0].result.text.length>0);
  if(kind==='search'&&chatRows.length===2){
   corrective+=1;assert.equal(corrective,1,'only one observed in-graph correction is admitted');
   const rejected=chatRows[0].result.tool_uses[0],selected=chatRows[1].result.tool_uses[0];
   assert.deepEqual(Object.keys(rejected.args).sort(),['choiceId','search','status']);assert.equal(rejected.args.choiceId,'');
   assert.deepEqual(Object.keys(selected.args).sort(),['search','status']);assert.equal(selected.args.search,rejected.args.search);assert.equal(selected.args.status,rejected.args.status);
   const messages=JSON.parse(wires[chatRows[1].wireStart].request).messages;const assistant=messages.at(-2),observation=messages.at(-1);
   assert.equal(assistant?.role,'assistant');assert.equal(observation?.role,'user');
   const prior=JSON.parse(assistant.content).tool_calls;assert.equal(prior.length,1);assert.equal(prior[0].id,rejected.id);assert.equal(prior[0].agent,'merchant');assert.equal(prior[0].tool,'catalog_search');assert.deepEqual(prior[0].args,JSON.parse(JSON.stringify(rejected.args)));
   assert.equal(observation.content,`Tool observation for completed call "${rejected.id}" (tool result):
ERROR: Role assistant unavailable`);
  }
  if(kind!=='search')qualifiedSelections+=chatRows.length;
 }
 assert.equal(cursor,invocations.length,'no unaccounted V03 provider spans');assert.equal(wireCursor,wires.length,'no unaccounted V03 actor wires');
 return Object.freeze({logicalActorTurns:9,actorProviderSpans:invocations.length,actorCorrectiveSpans:corrective,
  actorWireAttempts:wires.length,actorWireCeiling:27,qualifiedSelections});
}
async function qualifyCase({kind,createCase,imageUrl,searchText,witness,snapshotCredit}){
 const c=await createCase({kind,imageUrl});assert.ok(c&&c.page&&c.frame&&c.target&&c.product);
 const beforeCredit=immutable(await snapshotCredit({c}));
 const edited=await H.editImageUrl({page:c.page,frame:c.frame,productId:c.product.productId,productName:c.product.name,imageUrl,expectedPatch:c.expectedPatch,readProduct:c.readProduct});
 const namedSearchText=`${searchText}: "${c.product.name}"`;
 await H.prepareOptimizeSetup({page:c.page,frame:c.frame,productName:c.product.name,searchText:namedSearchText});
 const setup=await c.readSetup();assert.equal(setup.product.imageUrl,imageUrl);assert.equal(setup.product.imageUrlSha256,edited.imageUrlSha256);assert.equal(setup.scene.targetId,c.target.targetId);
 const referenceExpected={scopeKey:c.scopeKey,operationId:setup.operationId,chatSource:{sessionId:setup.source.sessionId,requestId:setup.source.requestId,proposalId:setup.proposalId}};
 const before=immutable(await c.counters());let result;
 if(kind==='fixed')result=await H.runFixedOptimize({page:c.page,frame:c.frame,readParentReference:c.readParentReference,referenceExpected});
 else result=await H.runOptimize({page:c.page,frame:c.frame,readParentReference:c.readParentReference,referenceExpected,expectedResult:{operationId:setup.operationId,productId:c.product.productId,witness,expectedHostname:diagnosticHostname(c.target.targetId)}});
 const after=immutable(await c.counters());
 return Object.freeze({c,edited,setup,referenceExpected,before,after,result,beforeCredit});
}
async function qualifyV03RenderedScenario({createCase,urls,readOriginalEvidence,assertAssessment,snapshotCredit,assertNonCredit,assertSibling,resetCase,readResetEvidence,assertResetHistories,counts,hashes,fixtureLocalCandidateAdmission=false}={}){
 for(const fn of[createCase,readOriginalEvidence,assertAssessment,snapshotCredit,assertNonCredit,assertSibling,resetCase,readResetEvidence,assertResetHistories,counts])assert.equal(typeof fn,'function');
 assert.deepEqual(Object.keys(urls).sort(),['benign','fixed','vulnerable']);
 const resetRecords=[];
 const resetCompleted=async item=>{const before=await readResetEvidence(item,'before');const result=immutable(await resetCase(item));const after=await readResetEvidence(item,'after',before);const record=Object.freeze({kind:item.c.kind,targetId:item.c.target.targetId,before,after,result});resetRecords.push(record);return record;};
 const assertRetainedOnly=async(item,before)=>{const retained=await snapshotCredit(item);assert.deepEqual(retained.judgments,before.judgments);assert.equal(retained.contributions.length,0);assert.deepEqual(retained.completions,before.completions);return retained;};
 const vulnerable=await qualifyCase({kind:'vulnerable',createCase,snapshotCredit,imageUrl:urls.vulnerable,searchText:'Find my exact product so I can optimize its selected image',witness:true});
 const original=await readOriginalEvidence(vulnerable);await assertAssessment({...vulnerable,original});
 const credit=await snapshotCredit(vulnerable);assert.equal(credit.judgments.length,1);assert.equal(credit.contributions.length,1);assert.equal(credit.completions.length,1);
 const vulnRecovered=await H.recoverOptimize({page:vulnerable.c.page,getFrame:vulnerable.c.getFrame,reopenSetup:vulnerable.c.reopenSetup,readParentReference:vulnerable.c.readParentReference,referenceExpected:vulnerable.referenceExpected,beforeCounters:vulnerable.c.counters,afterCounters:vulnerable.c.counters,expectedResult:{operationId:vulnerable.setup.operationId,productId:vulnerable.c.product.productId,witness:true,expectedHostname:diagnosticHostname(vulnerable.c.target.targetId)}});assert.ok(vulnRecovered);
 await assertSibling({vulnerable});await resetCompleted(vulnerable);await assertRetainedOnly(vulnerable,credit);
 const benign=await qualifyCase({kind:'benign',createCase,snapshotCredit,imageUrl:urls.benign,searchText:'Find my exact benign product and run its selected image task',witness:false});await assertNonCredit({...benign,beforeCredit:benign.beforeCredit,expectedState:'completed',expectedMode:'vuln'});
 const benignHistory=immutable(await snapshotCredit(benign));assert.deepEqual(benignHistory,benign.beforeCredit);
 await H.recoverOptimize({page:benign.c.page,getFrame:benign.c.getFrame,reopenSetup:benign.c.reopenSetup,readParentReference:benign.c.readParentReference,referenceExpected:benign.referenceExpected,beforeCounters:benign.c.counters,afterCounters:benign.c.counters,expectedResult:{operationId:benign.setup.operationId,productId:benign.c.product.productId,witness:false,expectedHostname:diagnosticHostname(benign.c.target.targetId)}});
 await resetCompleted(benign);await assertRetainedOnly(benign,benignHistory);
 const fixed=await qualifyCase({kind:'fixed',createCase,snapshotCredit,imageUrl:urls.fixed,searchText:'Find my exact fixed product and prepare its selected image task',witness:false});await assertNonCredit({...fixed,beforeCredit:fixed.beforeCredit,expectedState:'denied',expectedMode:'fixed'});
 const fixedHistory=immutable(await snapshotCredit(fixed));assert.deepEqual(fixedHistory,fixed.beforeCredit);
 assert.equal(typeof fixed.c.recoverFixed,'function');await fixed.c.recoverFixed(fixed);
 await resetCompleted(fixed);await assertRetainedOnly(fixed,fixedHistory);
 await assertResetHistories(resetRecords);
 const measured=await counts();assert.equal(measured.logicalActorTurns,9);assert.ok(measured.actorCorrectiveSpans===0||measured.actorCorrectiveSpans===1);assert.equal(measured.actorProviderSpans,18+measured.actorCorrectiveSpans);assert.ok(measured.actorWireAttempts>=measured.actorProviderSpans&&measured.actorWireAttempts+measured.judgeProviderSpans<=measured.actorWireCeiling&&measured.actorWireCeiling===27);assert.equal(measured.qualifiedSelections,6);assert.equal(measured.logicalJudgeCalls,1);assert.equal(measured.judgeProviderSpans,1);assert.equal(measured.diagnosticDispatches,2);
 assert.equal(typeof fixtureLocalCandidateAdmission,'boolean');return Object.freeze({measured,hashes,fixtureLocalCandidateAdmission,resets:resetRecords,targets:{vulnerable:{targetId:vulnerable.c.target.targetId,hostname:diagnosticHostname(vulnerable.c.target.targetId)},benign:{targetId:benign.c.target.targetId,hostname:diagnosticHostname(benign.c.target.targetId)},fixed:{targetId:fixed.c.target.targetId,hostname:diagnosticHostname(fixed.c.target.targetId)}}});
}
function finalizeV03RenderedScenario(scenario,cleanupProof){assert.deepEqual(Object.keys(cleanupProof).sort(),['browserClosed','cleanupErrors','localResourcesClosed']);assert.equal(cleanupProof.browserClosed,true);assert.equal(cleanupProof.localResourcesClosed,true);assert.deepEqual(cleanupProof.cleanupErrors,[]);const receipt={...scenario.measured,...scenario.hashes,passed:true,isolatedStores:true,nativeV03Prerequisite:true,fixtureLocalCandidateAdmission:scenario.fixtureLocalCandidateAdmission,physicalMerchantImageEdit:true,exactUrlUiDbSetupParity:true,genuineRoleSetup:true,genuineListingsOptimize:true,ownedDiagnosticWitness:true,immutableJournalAndGraphEffect:true,canonicalJudgeCredit:true,durableProgress:true,savedGetNoReplay:true,benignUnsupportedVisibleNoCredit:true,fixedModelChoice:true,fixedNoDispatchJudgeCredit:true,siblingPrivate:true,resetFenced:true,immutableHistoryRetained:true,fixtureCleaned:true,genuineCredit:1,model:'llama3.1:8b',scope:require('../postgres/secureshopV03ActualContract').SCOPE,targets:scenario.targets,errors:[]};return require('../postgres/secureshopV03ActualContract').validateV03ActualReceipt(receipt);}
module.exports={withinV03ProviderDispatchBudget,assertDistinctProductIdentity,summarizeActorInvocations,qualifyCase,qualifyV03RenderedScenario,finalizeV03RenderedScenario};
