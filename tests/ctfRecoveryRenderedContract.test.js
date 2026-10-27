'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const read=p=>fs.readFileSync(p,'utf8');
const helper=read('tests/postgres/support/ctfRecoveryRenderedCases.js');
test('rendered branch retains ordinary application and direct SQL recovery fixture branches',()=>{
 const fixture=read('tests/postgres/ctfAuthorityApplication.integration.test.js');
 assert(fixture.includes("CTF_RECOVERY_RENDERED_ISOLATED==='1'"));
 assert(fixture.includes("require('./support/ctfRecoveryRenderedCases')"));
 assert(fixture.includes("require('./support/ctfPredefenseRecoveryCases')"));
 assert(fixture.includes('all thirty-two HTTP surfaces'));
});
test('rendered entry imports actual page and obtains actual authenticated stage projection',()=>{
 const entry=read('tests/postgres/support/ctfRecoveryRenderedEntry.jsx');
 assert(entry.includes("import CTFChallenge from './src/pages/CTFChallenge'"));
 assert(entry.includes("fetch('/api/ctf/stages'"));assert(entry.includes('state: { stage }'));
 assert(!/mock|interceptResponse|setRequestHandler/.test(entry));
 assert(helper.includes('initial recovery is read-only'));assert(helper.includes("body.blocked,true"));assert(helper.includes('body.success,false'));
 assert(helper.includes("UPDATE identity.user_sessions SET is_active=0"));assert(helper.includes("mutate(admin,'owner_reset'"));
 assert(helper.includes("assert.equal(ledger.length,calls"));assert(helper.includes('beforeSibling'));
});
test('browser remains in owned process group with bounded endpoint, network, and cancellation cleanup',()=>{
 assert(!helper.includes('detached:true'));assert(helper.includes('--remote-debugging-address=127.0.0.1'));
 assert(helper.includes('--disable-extensions'));assert(helper.includes('Owned browser endpoint deadline'));
 assert(helper.includes("child.once('error',errorHandler)"));assert(helper.includes("child.once('exit',exitHandler)"));
 assert(helper.includes('r.abort()'));assert(helper.includes('cancelled=true;reject'));
 assert(helper.includes("active();const owner"));assert(helper.includes('casesTask.then(()=>true,()=>true)'));
 assert(helper.includes("throw new AggregateError([primary,error]"));
 assert(helper.includes("lateHintRace:'component control only'"));
});

test('closed full-App content receipt distinguishes projections from genuine credit and enforces ceilings',()=>{
 const {assertContentReceipt,CONTENT_LIMITS}=require('./postgres/support/ctfRecoveryRenderedCases');
 const receipt={version:1,profile:'ctf-ten-content',modelCalls:0,judgeCalls:0,genuineCredit:0,controlledProjectionCount:55,controlledProjectionCountPerStore:55,controlledProjectionCountTotal:110,projectionStoreCount:2,prerequisiteProjectionCount:45,displayProjectionCount:10,cases:Array.from({length:10},(_,n)=>({stage:n+1,label:true,hints:true,adminSolution:true})),browserActions:CONTENT_LIMITS.browserActions,apiRequests:CONTENT_LIMITS.apiRequests,unexpectedApiPaths:[]};
 for(const k of ['hintGate','adminMutation','progressParity','restored','siblingPreserved','populatedReadback','sessionDenied','ownerReset','immutablePreserved','browserRetired'])receipt[k]=true;
 assert.doesNotThrow(()=>assertContentReceipt(receipt));
 for(const change of [{genuineCredit:1},{modelCalls:1},{controlledProjectionCount:10},{apiRequests:1201},{browserActions:1601},{cases:receipt.cases.slice(1)},{restored:false},{unexpectedApiPaths:[{path:'/api/unknown'}]}])assert.throws(()=>assertContentReceipt({...receipt,...change}));
});
test('content API closure admits canonical bootstrap and paid-hint routes, denies inference and unrelated mutation',()=>{
 const {contentApiAllowed}=require('./postgres/support/ctfRecoveryRenderedCases');
 for(const path of ['/api/auth/status','/api/workshop/config/snapshot','/api/changes/revisions','/api/ctf/admin/solutions','/api/admin/xss-workshop/objective-solutions'])assert(contentApiAllowed('GET',path),path);
 assert(contentApiAllowed('POST','/api/ctf/stage/10/hint'));
 for(const kind of ['technique','payload'])assert(contentApiAllowed('POST',`/api/ctf/admin/blocklists/${kind}/clear`));
 assert(contentApiAllowed('POST','/api/ctf/admin/participants/3010/reset'));
 assert.equal(contentApiAllowed('POST','/api/ctf/admin/participants/3011/reset'),false);
 assert(contentApiAllowed('POST','/api/ctf/admin/participants/3010/remove'));
 assert.equal(contentApiAllowed('POST','/api/ctf/register'),false,'re-registration is supported HTTP outside the browser admission');
 assert.equal(contentApiAllowed('POST','/api/ctf/admin/participants/3011/remove'),false);
 assert.equal(contentApiAllowed('GET','/api/ctf/admin/participants/3010/remove'),false);
 assert.equal(contentApiAllowed('PUT','/api/ctf/admin/stages/2/content'),true);
 assert.equal(contentApiAllowed('PUT','/api/ctf/admin/stages/2'),true);
 assert.equal(contentApiAllowed('DELETE','/api/ctf/admin/stages/14'),false,'stage DELETE starts closed');
 assert.equal(contentApiAllowed('DELETE','/api/ctf/admin/stages/14',14),true);
 for(const [route,id] of [['/api/ctf/admin/stages/13',14],['/api/ctf/admin/stages/1',14],
  ['/api/ctf/admin/stages/14/extra',14],['/api/ctf/admin/stages/014',14],
  ['/api/ctf/admin/stages/14','14'],['/api/ctf/admin/stages/14',10]])
  assert.equal(contentApiAllowed('DELETE',route,id),false,`unexpected stage DELETE ${route}`);
 for(const [method,path] of [['POST','/api/ctf/admin/stages/2/content'],['GET','/api/ctf/admin/stages/2/content'],['PUT','/api/ctf/admin/stages/3/content'],['PUT','/api/ctf/admin/stages/2/content/extra'],['POST','/api/ctf/admin/stages/2'],['GET','/api/ctf/admin/stages/2'],['PUT','/api/ctf/admin/stages/3'],['PUT','/api/ctf/admin/stages/2/extra']])assert.equal(contentApiAllowed(method,path),false,method+' '+path);
 for(const [method,path]of [['POST','/api/ctf/stage/10/attempt'],['GET','/api/ctf/admin/secrets'],['POST','/api/admin/users/1/delete'],['GET','/api/unknown'],['GET','/api/ctf/admin/solutions/extra'],['GET','/api/ctf/admin/blocklists/technique/clear'],['POST','/api/ctf/admin/blocklists/payload/clear/extra']])assert.equal(contentApiAllowed(method,path),false,path);
});
test('Advanced Save, Teaching Save, Stage Active, and Stage Delete use separate receipts and sequential admitted pages',()=>{
 assert(helper.includes("require('./ctfAdvancedStageSaveRenderedCases')"));
 assert(helper.includes('process.env.CTF_ADVANCED_STAGE_SAVE_Q05_RECEIPT'));
 assert(helper.includes("'ctf-advanced-stage-save-q05-result.json'"));
 assert(helper.includes('assertAdvancedStageSaveReceipt(JSON.parse(fs.readFileSync(advancedSaveReceiptPath)))'));
 assert(helper.includes("'adaptive_mode','level_score','feedback_mode'])assert.deepEqual(row[field],expected[field])"));
 assert(helper.includes("require('./ctfTeachingSaveRenderedCases')"));
 assert(helper.includes('process.env.CTF_TEACHING_SAVE_Q05_RECEIPT'));
 assert(helper.includes("'ctf-teaching-save-q05-result.json'"));
 assert(helper.includes('assertTeachingSaveReceipt(JSON.parse(fs.readFileSync(teachingSaveReceiptPath)))'));
 assert(helper.includes("require('./ctfStageActiveRenderedCases')"));
 assert(helper.includes('process.env.CTF_STAGE_ACTIVE_Q05_RECEIPT'));
 assert(helper.includes("'ctf-stage-active-q05-result.json'"));
 assert(helper.includes('assertStageActiveReceipt(JSON.parse(fs.readFileSync(stageActiveReceiptPath)))'));
 assert(helper.includes("require('./ctfStageDeleteRenderedCases')"));
 assert(helper.includes('process.env.CTF_STAGE_DELETE_Q05_RECEIPT'));
 assert(helper.includes("'ctf-stage-delete-q05-result.json'"));
 assert(helper.includes('assertStageDeleteReceipt(JSON.parse(fs.readFileSync(stageDeleteReceiptPath)))'));
 assert(helper.indexOf("step('q05-blocklist-rendered')")<helper.indexOf("step('q05-teaching-save-rendered')"));
 const blocklistDone=helper.indexOf('await contentBlocklistCases({i,c,origin,instructor');
 const remount=helper.indexOf("step('q05-teaching-save-remount')");
 const originalSession=helper.indexOf("localStorage.getItem('token')===token,mounted.adminToken",remount);
 const samePageReload=helper.indexOf("instructor.reload({waitUntil:'domcontentloaded'})",remount);
 const exactNav=helper.indexOf("document.querySelectorAll('nav[aria-label=\"CTF admin sections\"]')",remount);
 const advancedStart=helper.indexOf("step('q05-advanced-stage-save-rendered')");
 const teachingStart=helper.indexOf("step('q05-teaching-save-rendered')");
 assert(blocklistDone<remount&&remount<originalSession&&originalSession<samePageReload&&samePageReload<exactNav&&exactNav<advancedStart&&advancedStart<teachingStart,'retired admin panel must be remounted before Advanced Save and Teaching Save');
 assert(helper.includes("assert.equal(new URL(instructor.url()).pathname,'/admin/ctf-management')"));
 assert(helper.includes("button.textContent.trim()==='Levels'&&button.getClientRects().length"));
 assert(helper.indexOf("localStorage.getItem('token')===token,mounted.adminToken",samePageReload)>samePageReload,'original session is rechecked after remount');
 assert(helper.includes('finalizeAdvancedSave=await runAdvancedStageSaveRenderedFacet({i,c,origin,instructor,action,click,pointer:contentPointerClick,admin,mounted,adapter,request,ledger,receiptPath:advancedSaveReceiptPath,unexpectedApiPaths:r.unexpectedApiPaths,runtimeDirectory:process.env.CTF_CONTENT_RUNTIME_DIRECTORY})'));
 const advancedClose=helper.indexOf('await actorPages.closePage(instructor)',advancedStart);
 const advancedFinalize=helper.indexOf('await finishAdvancedSave()',advancedClose);
 const teachingPage=helper.indexOf('const teachingInstructor=await page(teachingToken)',advancedFinalize);
 assert(advancedStart<advancedClose&&advancedClose<advancedFinalize&&advancedFinalize<teachingPage&&teachingPage<teachingStart);
 assert(helper.includes('const teachingAuthority=await adapter.validateSession(teachingToken)'));
 assert(helper.includes('assert.equal(String(teachingAuthority?.session?.id),String(mountedAdminAuthority.session.id))'));
 assert(helper.includes('finalizeTeachingSave=await runTeachingSaveRenderedFacet({i,c,origin,instructor:teachingInstructor,action,click,pointer:contentPointerClick,admin,mounted:{adminToken:teachingToken},adapter,request,userRequest,ledger,receiptPath:teachingSaveReceiptPath,unexpectedApiPaths:r.unexpectedApiPaths,runtimeDirectory:process.env.CTF_CONTENT_RUNTIME_DIRECTORY})'));
 assert(helper.indexOf("step('q05-teaching-save-rendered')")<helper.indexOf('await actorPages.closePage(teachingInstructor)'));
 const teachingClose=helper.indexOf('await actorPages.closePage(teachingInstructor)',teachingStart);
 const teachingFinalize=helper.indexOf('await finishTeachingSave()',teachingClose);
 const stageActivePage=helper.indexOf('const stageActiveInstructor=await page(stageActiveToken)',teachingFinalize);
 const stageActiveStart=helper.indexOf("step('q05-stage-active-rendered')",stageActivePage);
 const stageActiveClose=helper.indexOf('await actorPages.closePage(stageActiveInstructor)',stageActiveStart);
 assert(teachingStart<teachingClose&&teachingClose<teachingFinalize&&teachingFinalize<stageActivePage&&stageActivePage<stageActiveStart&&stageActiveStart<stageActiveClose);
 assert(helper.includes('const stageActiveAuthority=await adapter.validateSession(stageActiveToken)'));
 assert(helper.includes('assert.equal(String(stageActiveAuthority?.user?.id),String(mountedAdminAuthority.user.id))'));
 assert(helper.includes('assert.equal(String(stageActiveAuthority?.session?.id),String(mountedAdminAuthority.session.id))'));
 assert(helper.includes('finalizeStageActive=await runStageActiveRenderedFacet({i,c,origin,instructor:stageActiveInstructor,action,click,pointer:contentPointerClick,admin,mounted:{adminToken:stageActiveToken},adapter,request,ledger,receiptPath:stageActiveReceiptPath,unexpectedApiPaths:r.unexpectedApiPaths,runtimeDirectory:process.env.CTF_CONTENT_RUNTIME_DIRECTORY})'));
 const stageActiveFinalize=helper.indexOf('await finishStageActive()',stageActiveClose);
 const stageDeletePage=helper.indexOf('const stageDeleteInstructor=await page(stageDeleteToken)',stageActiveFinalize);
 const stageDeleteStart=helper.indexOf("step('q05-stage-delete-rendered')",stageDeletePage);
 const stageDeleteClose=helper.indexOf('await actorPages.closePage(stageDeleteInstructor)',stageDeleteStart);
 const stageDeleteFinalize=helper.indexOf('await finishStageDelete()',stageDeleteClose);
 assert(stageActiveClose<stageActiveFinalize&&stageActiveFinalize<stageDeletePage&&
  stageDeletePage<stageDeleteStart&&stageDeleteStart<stageDeleteClose&&
  stageDeleteClose<stageDeleteFinalize);
 assert(helper.includes('const stageDeleteAuthority=await adapter.validateSession(stageDeleteToken)'));
 assert(helper.includes('assert.equal(String(stageDeleteAuthority?.session?.id),String(mountedAdminAuthority.session.id))'));
 assert(helper.includes('mounted:{adminToken:stageDeleteToken}'));
 assert(helper.includes('onOwnedStageCreated:id=>{assert.equal(ownedStageDeleteId,null)'));
 const ownedHelper=read('tests/postgres/support/ctfStageDeleteRenderedCases.js');
 assert(ownedHelper.indexOf('assert.equal((await binding(createdId))?.active, true)')<
  ownedHelper.indexOf('onOwnedStageCreated(createdId)'));
 assert(helper.includes('finalizeContentFacets([finalizeBan,finalizeReset,finalizeRemove,finalizeAdvancedSave,finalizeTeachingSave,finalizeStageActive,finalizeStageDelete])'));
 assert(helper.includes("'adaptive_mode','level_score','feedback_mode','is_active'])assert.deepEqual(currentStages[n][key],stages[n][key])"));
 assert(helper.indexOf('await Promise.allSettled([browser?.close(),stop(child)])')<helper.indexOf('await finalizeContentFacets([finalizeBan,finalizeReset'));
 const receipt=helper.slice(helper.indexOf('function assertContentReceipt('),helper.indexOf('function assertContentBlocklistReceipt('));
 assert(!receipt.includes('TeachingSave')&&!receipt.includes('teachingSave')&&!receipt.includes('AdvancedSave')&&!receipt.includes('advancedSave')&&!receipt.includes('StageActive')&&!receipt.includes('stageActive')&&!receipt.includes('StageDelete')&&!receipt.includes('stageDelete'));
});
test('facet finalization attempts later receipts after an earlier finalizer fails',async()=>{
 const {finalizeContentFacets}=require('./postgres/support/ctfRecoveryRenderedCases');
 const order=[];const primary=Error('Teaching receipt failed');
 await assert.rejects(finalizeContentFacets([
  async()=>{order.push('teaching');throw primary;},
  async()=>{order.push('stage-active');},
  async()=>{order.push('stage-delete');},
 ]),error=>error instanceof AggregateError&&error.errors.length===1&&error.errors[0]===primary);
 assert.deepEqual(order,['teaching','stage-active','stage-delete']);
});
test('participant removal has a separate strict receipt for physical Cancel, ABA, one removal and fresh re-registration',()=>{
 const {assertContentParticipantRemoveReceipt,assertContentParticipantRemoveOutbox}=require('./postgres/support/ctfRecoveryRenderedCases');
 const operationId='12345678-1234-4234-8234-123456789abc',registrationId='22345678-1234-4234-8234-123456789abc';
 const facts={cancelNoPost:true,cancelStateUnchanged:true,modalAbaNoPost:true,modalAbaStateUnchanged:true,removedCurrentCtfState:true,oldRegistrationInactive:true,historicalIdentityRetained:true,sharedPayloadPreserved:true,siblingPreserved:true,reregisteredFresh:true,noMutationReplay:true};
 const receipt={version:1,profile:'ctf-participant-remove-q05',modelCalls:0,judgeCalls:0,targetId:3010,oldParticipantId:3010,newParticipantId:3012,mountedActorId:'909',mountedSessionId:'707',comparisonActorId:'1002',learnerSessionId:'808',preRemovalRows:{participant:1,progress:1,attempts:0,technique:0,leaderboard:1,events:2,sessions:1,binding:1,currentIdentityProgress:1},browserPosts:1,removeOutboxCount:1,originalPostStatus:200,facts,dialogTimeAba:{noPost:true,eventsObserved:2},removeOutbox:{operationId,kind:'owner_remove',ownerId:'3010',actorId:'909',sessionId:'707'},registrationOutbox:{operationId:registrationId,kind:'register',ownerId:'3010',actorId:'3010',sessionId:'808',disposition:'reactivate',oldParticipantId:'3010'},generationBefore:'2',generationRemoved:'3',generationReregistered:'4',unexpectedApiPaths:[],stage:'complete'};
 assert.doesNotThrow(()=>assertContentParticipantRemoveReceipt(receipt));
 for(const change of [{version:2},{modelCalls:1},{judgeCalls:1},{browserPosts:2},{removeOutboxCount:0},{originalPostStatus:503},{newParticipantId:3010},{mountedActorId:'1002'},{mountedSessionId:'708'},{learnerSessionId:'809'},{preRemovalRows:{...receipt.preRemovalRows,progress:0}},{generationRemoved:'2'},{generationReregistered:'3'},{facts:{...facts,cancelNoPost:false}},{facts:{...facts,reregisteredFresh:false}},{dialogTimeAba:{noPost:true,eventsObserved:1}},{unexpectedApiPaths:[{method:'POST',path:'/api/other'}]},{removeOutbox:{...receipt.removeOutbox,kind:'owner_reset'}},{registrationOutbox:{...receipt.registrationOutbox,sessionId:'809'}}])assert.throws(()=>assertContentParticipantRemoveReceipt({...receipt,...change}));
 assert.throws(()=>assertContentParticipantRemoveReceipt({...receipt,sameIdRecovery:true}),'unproved response-loss facet must not enter this receipt');
 const mounted={user:{id:909},session:{id:707}},comparison={user:{id:1002}};
 const row={operation_id:operationId,actor_id:'909',session_id:'707',kind:'owner_remove',canonical_command:JSON.stringify({operationId,kind:'owner_remove',actorId:'909',scope:{ownerId:'3010',participantId:'3010'}})};
 assert.deepEqual(assertContentParticipantRemoveOutbox(row,mounted,comparison),receipt.removeOutbox);
 for(const bad of [{actor_id:'1002'},{session_id:'708'},{kind:'owner_reset'},{canonical_command:JSON.stringify({operationId,kind:'owner_remove',scope:{ownerId:'1001',participantId:'3010'}})},{canonical_command:JSON.stringify({operationId,kind:'owner_remove',scope:{ownerId:'3010',participantId:'1001'}})}])assert.throws(()=>assertContentParticipantRemoveOutbox({...row,...bad},mounted,comparison));
 assert(helper.includes("step('q05-participant-remove-rendered')"));
 assert(helper.includes("assertContentParticipantRemoveReceipt(JSON.parse(fs.readFileSync(removeReceiptPath)))"));
 assert(helper.indexOf("step('q05-participant-reset-rendered')")<helper.indexOf("step('q05-participant-remove-rendered')"));
 assert(helper.indexOf("step('q05-participant-remove-rendered')")<helper.indexOf("step('q05-blocklist-rendered')"));
 const facet=helper.slice(helper.indexOf('async function contentParticipantRemoveCases('),helper.indexOf('async function contentBlocklistCases('));
 assert(facet.includes("await click(instructor,'[role=\"dialog\"] button','Cancel')"));
 assert(facet.includes("await click(instructor,'[role=\"dialog\"] button','Remove from CTF')"));
 assert(facet.includes("const registered=await mutate(learner,'register',{})"));
 assert(!facet.includes('firstOperationReadLost')&&!facet.includes('sameIdRecovery'));
});
test('participant removal seeds a real active-recovery CTF session before stage start',()=>{
 const {assertContentActiveRecoverySetup}=require('./postgres/support/ctfRecoveryRenderedCases');
 const operationId='12345678-1234-4234-8234-123456789abc',learner={user:{id:3010},identitySession:{id:808}};
 const before={generation:'1',participant:JSON.stringify([{id:3010}]),sessions:'[]'};
 const after={generation:'1',participant:JSON.stringify([{id:3010}]),sessions:JSON.stringify([{id:33,participant_id:3010,is_active:1,session_token:'synthetic-session'}])};
 const registered={status:200,body:{message:'Successfully registered for CTF',participantId:3010,sessionToken:'synthetic-session'}};
 const row={operation_id:operationId,actor_id:'3010',session_id:'808',kind:'register',registration_disposition:'active_recovery',registration_participant_before:'3010',owner_generation_after:'1',canonical_command:JSON.stringify({operationId,kind:'register',actorId:'3010',scope:{ownerId:'3010',participantId:null},body:{teachingSessionToken:'synthetic-session'}})};
 const evidence={registered,before,after,beforeOperations:[],afterOperations:[row],learner};
 assert.doesNotThrow(()=>assertContentActiveRecoverySetup(evidence));
 for(const change of [{after:{...after,generation:'2'}},{after:{...after,sessions:'[]'}},{afterOperations:[{...row,registration_disposition:'reactivate'}]},{afterOperations:[{...row,actor_id:'1002'}]},{afterOperations:[{...row,session_id:'809'}]},{afterOperations:[{...row,owner_generation_after:'2'}]},{registered:{...registered,body:{...registered.body,sessionToken:'other-synthetic-session'}}}])assert.throws(()=>assertContentActiveRecoverySetup({...evidence,...change}));
 const facet=helper.slice(helper.indexOf('async function contentParticipantRemoveCases('),helper.indexOf('async function contentBlocklistCases('));
 assert(facet.indexOf("mutate(learner,'register',{})")<facet.indexOf("mutate(learner,'start',{stageId:'1'})"));
 assert(facet.includes('assertContentActiveRecoverySetup({registered:registeredRecovery'));
 assert(facet.includes("'sessions','binding','currentIdentityProgress'])assert"),'the nonvacuous session assertion must remain');
});
test('participant reset receipt requires exact one POST, real same-ID recovery, generation and no model credit',()=>{
 const {assertContentParticipantResetReceipt}=require('./postgres/support/ctfRecoveryRenderedCases');
 const operationId='12345678-1234-4234-8234-123456789abc';
 const receipt={version:2,profile:'ctf-participant-reset-q05',modelCalls:0,judgeCalls:0,targetId:3010,browserPosts:1,serverPosts:1,facts:{cancelNoPost:true,cancelStateUnchanged:true,modalAbaNoPost:true,modalAbaStateUnchanged:true,currentProgressClearedBothStores:true,registrationRetained:true,sharedPayloadPreserved:true,siblingPreserved:true,sameIdRecoveryNoSecondPost:true},operationId,commitAckLost:true,firstOperationReadLost:true,firstOperationReadStatus:202,firstOperationReadFinished:true,operationReadDrops:1,browserReadFailureObserved:true,parkedBeforeCheck:true,originalPostStatus:202,outbox:{operationId,kind:'owner_reset',ownerId:'3010'},sameIdGets:2,unexpectedApiPaths:[],generationBefore:'0',generationAfter:'1',stage:'complete'};
 assert.doesNotThrow(()=>assertContentParticipantResetReceipt(receipt));
 for(const patch of [{version:1},{browserPosts:2},{serverPosts:0},{modelCalls:1},{judgeCalls:1},{originalPostStatus:200},{commitAckLost:false},{firstOperationReadLost:false},{firstOperationReadFinished:false},{operationReadDrops:2},{browserReadFailureObserved:false},{parkedBeforeCheck:false},{sameIdGets:1},{generationAfter:'0'},{outbox:{...receipt.outbox,ownerId:'1001'}},{unexpectedApiPaths:[{method:'POST',path:'/api/other'}]},{facts:{...receipt.facts,siblingPreserved:false}}])assert.throws(()=>assertContentParticipantResetReceipt({...receipt,...patch}));
 assert(helper.includes("step('q05-participant-reset-rendered')"));
 assert(helper.includes("SELECT owner_generation::text AS n FROM identity.ctf_authority WHERE scope_key='owner:3010'"));
 assert(helper.includes("WHERE owner_id=3010 AND owner_generation=$1"));
});
test('background cross-tab observers keep exact ABA criteria without relying on animation frames',()=>{
 const reset=helper.slice(helper.indexOf('async function contentParticipantResetCases('),helper.indexOf('async function contentParticipantRemoveCases('));
 const remove=helper.slice(helper.indexOf('async function contentParticipantRemoveCases('),helper.indexOf('async function contentBlocklistCases('));
 const blocklist=helper.slice(helper.indexOf('async function contentBlocklistCases('),helper.indexOf('function assertContentHintDenied('));
 assert(reset.includes("(window.__ctfResetStorageEvents||0)>=2,{polling:100,timeout:15000}"));
 assert(reset.includes("assert.equal(await action(()=>instructor.evaluate(()=>window.__ctfResetStorageEvents||0)),2"));
 assert(reset.includes("'Reset participant progress'),{polling:100,timeout:15000}"));
 assert(remove.includes("(window.__ctfRemoveStorageEvents||0)>=2,{polling:100,timeout:15000}"));
 assert(remove.includes('assert.equal(r.dialogTimeAba.eventsObserved,2)'));
 assert(remove.includes("'Remove participant from CTF'),{polling:100,timeout:15000}"));
 assert(blocklist.includes("(window.__ctfBlocklistStorageEvents||0)>=n+2,{polling:100,timeout:10000}"));
 assert(blocklist.includes("(window.__ctfBlocklistStorageEvents||0)>=2,{polling:100,timeout:10000}"));
 assert(blocklist.includes('assert.equal(r.dialogTimeAba.eventsObserved,2)'));
 for(const facet of [reset,remove,blocklist]){
  assert(facet.includes("path:location.pathname==='/admin/ctf-management'?location.pathname:'[other]'"));
  assert(facet.includes("visibilityState:['visible','hidden','prerender'].includes(document.visibilityState)?document.visibilityState:'other'"));
  assert(facet.includes('storageEvents:Number.isSafeInteger('));
  assert(facet.includes('modalVisible:'));
 }
 assert(remove.includes("receiptPath+'.diagnostics.json'"));
});
test('participant reset fault is one-shot after exact committed command; first same-ID GET alone loses its original response',()=>{
 const {createContentParticipantResetFaults}=require('./postgres/support/ctfRecoveryRenderedCases');
 const f=createContentParticipantResetFaults(),operationId='12345678-1234-4234-8234-123456789abc';
 const sql='SELECT identity.enqueue_ctf_user_command($1,$2,$3,$4,$5)',args=[null,null,null,null,JSON.stringify({kind:'owner_reset',scope:{ownerId:'3010'},operationId})];
 assert.equal(f.matchEnqueue(sql,args),false);f.arm();
 assert.equal(f.matchEnqueue(sql,[null,null,null,null,JSON.stringify({kind:'owner_reset',scope:{ownerId:'1001'},operationId})]),false);
 assert.equal(f.matchEnqueue(sql,args),true);assert.equal(f.stats.operationId,operationId);
 assert.throws(()=>f.afterSuccessfulCommit(true),e=>e.code==='ECONNRESET');assert.equal(f.stats.commitAckLost,true);
 let next=0;const response=()=>({statusCode:202,once(event,fn){assert.equal(event,'finish');this.finish=fn;}});
 const first=response(),concurrent=response(),wrong=response();
 f.middleware({method:'GET',path:'/api/ctf/operations/'+operationId},first,()=>next++);
 f.middleware({method:'GET',path:'/api/ctf/operations/'+operationId},concurrent,()=>next++);
 f.middleware({method:'GET',path:'/api/ctf/operations/other'},wrong,()=>next++);
 assert.equal(next,3);assert.equal(f.stats.operationReadRequests,2);assert.equal(typeof first.finish,'function');assert.equal(concurrent.finish,undefined);assert.equal(wrong.finish,undefined);
 first.finish();assert.equal(f.stats.firstOperationReadFinished,true);assert.equal(f.stats.firstOperationReadStatus,202);
 f.markBrowserDrop(202);assert.equal(f.stats.firstOperationReadLost,true);assert.equal(f.stats.operationReadDrops,1);
 assert.equal(f.afterSuccessfulCommit(false),undefined);
 assert.throws(()=>f.matchEnqueue(sql,args),/single-flight/);
});
test('participant reset CDP loss fails exactly one matching GET response and continues wrong origin, method, UUID and second read',async()=>{
 const {EventEmitter}=require('node:events');const {createContentParticipantResetFaults,createContentParticipantResetBrowserLoss}=require('./postgres/support/ctfRecoveryRenderedCases');
 const origin='http://127.0.0.1:54321',id='12345678-1234-4234-8234-123456789abc',faults=createContentParticipantResetFaults();faults.arm();
 assert(faults.matchEnqueue('SELECT identity.enqueue_ctf_user_command(',[null,null,null,null,JSON.stringify({kind:'owner_reset',scope:{ownerId:'3010'},operationId:id})]));
 const response={statusCode:200,once(_event,fn){this.finish=fn;}};faults.middleware({method:'GET',path:'/api/ctf/operations/'+id},response,()=>{});response.finish();
 const session=new EventEmitter(),calls=[];session.send=async(command,args)=>{calls.push({command,args});};session.detach=async()=>{calls.push({command:'detach'});};
 const loss=createContentParticipantResetBrowserLoss({session,origin,faults});await loss.start();
 const emit=(requestId,url,method='GET')=>session.emit('Fetch.requestPaused',{requestId,request:{url,method},responseStatusCode:200});
 emit('wrong-origin','http://127.0.0.1:9999/api/ctf/operations/'+id);
 emit('wrong-id',origin+'/api/ctf/operations/other');emit('wrong-query',origin+'/api/ctf/operations/'+id+'?extra=1');emit('wrong-method',origin+'/api/ctf/operations/'+id,'POST');
 emit('first',origin+'/api/ctf/operations/'+id);emit('second',origin+'/api/ctf/operations/'+id);
 await loss.stop();
 assert.deepEqual(calls.filter(x=>x.command==='Fetch.failRequest').map(x=>x.args.requestId),['first']);
 assert.deepEqual(calls.filter(x=>x.command==='Fetch.continueRequest').map(x=>x.args.requestId).sort(),['second','wrong-id','wrong-method','wrong-origin','wrong-query']);
 assert.deepEqual(loss.observations,{paused:1,failed:1,continued:5,unexpected:3});
 assert.equal(faults.stats.operationReadDrops,1);assert.equal(faults.stats.firstOperationReadLost,true);
 assert.deepEqual(calls.filter(x=>x.command==='Fetch.enable')[0].args,{patterns:[{urlPattern:origin+'/api/ctf/operations/*',requestStage:'Response'}]});
 assert.equal(calls.at(-1).command,'detach');
});
test('blocklist response hold retains original response until explicit release and counts request-side dispatch',async()=>{
 const {createContentBlocklistResponseGate}=require('./postgres/support/ctfRecoveryRenderedCases');
 const gate=createContentBlocklistResponseGate(),original=[];
 const response={statusCode:202,destroyed:false,end(...args){original.push(args);return this;},once(){}};
 let continued=0;const held=gate.arm('payload');
 gate.middleware({method:'POST',path:'/api/ctf/admin/blocklists/payload/clear'},response,()=>continued++);
 await held.requestedPromise;assert.equal(continued,1);assert.deepEqual(gate.counts,{technique:0,payload:1});
 const callback=()=>{};assert.equal(response.end('original bytes','utf8',callback),response);
 assert.deepEqual(await held.responseReadyPromise,{status:202});assert.deepEqual(original,[]);
 held.release();await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(original,[['original bytes','utf8',callback]]);
 gate.middleware({method:'POST',path:'/api/ctf/admin/blocklists/technique/clear'},response,()=>continued++);
 assert.equal(continued,2);assert.deepEqual(gate.counts,{technique:1,payload:1});
 const unused=gate.arm('payload');gate.release();assert.equal(unused.wasReleased(),true);
 let close,lateEnds=0;const late={statusCode:200,destroyed:false,end(){lateEnds++;return this;},once(event,fn){if(event==='close')close=fn;}};
 const aborted=gate.arm('payload');gate.middleware({method:'POST',path:'/api/ctf/admin/blocklists/payload/clear'},late,()=>{});
 late.end('original');late.destroyed=true;close();assert.equal(aborted.closedBeforeRelease,true);
 aborted.release();await new Promise(resolve=>setImmediate(resolve));assert.equal(lateEnds,0,'closed browser response cannot be manufactured');
});
test('separate Q05 blocklist receipt requires physical cancel, two real clears, and honest ABA observations',()=>{
 const {assertContentBlocklistReceipt}=require('./postgres/support/ctfRecoveryRenderedCases');
 const receipt={version:1,profile:'ctf-blocklist-q05',modelCalls:0,judgeCalls:0,postCounts:{technique:1,payload:1},browserPostCounts:{technique:1,payload:1},cancelPostCounts:{browser:{technique:0,payload:0},server:{technique:0,payload:0}},facts:{cancelNoPost:true,cancelStoresUnchanged:true,techniqueClearedBothStores:true,payloadClearedBothStores:true,pendingAbaNoStaleUiOrRecovery:true},dialogTimeAba:{noPost:true,eventsObserved:2,postCounts:{browser:{technique:0,payload:0},server:{technique:0,payload:0}}},pendingAba:{responseReleased:true,componentRetired:false,eventsObserved:2},unexpectedApiPaths:[],siblingPreserved:true,stage:'complete'};
 assert.doesNotThrow(()=>assertContentBlocklistReceipt(receipt));
 assert.throws(()=>assertContentBlocklistReceipt({...receipt,workerSnapshots:[]}));
 assert.throws(()=>assertContentBlocklistReceipt({...receipt,techniqueHttp:{status:503,publicError:'other'}}));
 assert(helper.includes("receiptPath+'.diagnostics.json'"));
 assert(helper.includes("diagnostics.workerSnapshots.push(entry);saveDiagnostics()"));
 assert(helper.includes("diagnostics.techniqueHttp={status:techniqueHttp.status(),publicError:'none'}"));
 for(const changed of [{postCounts:{technique:0,payload:1}},{browserPostCounts:{technique:2,payload:1}},{cancelPostCounts:{browser:{technique:1,payload:0},server:{technique:0,payload:0}}},{facts:{...receipt.facts,cancelNoPost:false}},{dialogTimeAba:{noPost:false,eventsObserved:2}},{pendingAba:{responseReleased:false,componentRetired:false,eventsObserved:2}},{unexpectedApiPaths:[{method:'POST',path:'/api/ctf/admin/reset'}]},{siblingPreserved:false}])assert.throws(()=>assertContentBlocklistReceipt({...receipt,...changed}));
 assert.doesNotThrow(()=>assertContentBlocklistReceipt({...receipt,pendingAba:{...receipt.pendingAba,componentRetired:true}}));
});
test('Q05 synthetic blocklists enter the canonical source bootstrap before activation',()=>{
 const fixture=read('tests/postgres/ctfAuthorityApplication.integration.test.js');
 const begin=fixture.indexOf('if(contentOnly){\n   // These synthetic source rows must enter the normal bootstrap snapshot.');
 const historical=fixture.indexOf("const normalized='long retained payload '");
 const sourceSnapshot=fixture.indexOf('const before=Object.fromEntries(await Promise.all(TABLES.map');
 const preparation=fixture.indexOf('createCtfAuthorityBootstrap({repository}).prepare({operationId})');
 const activation=fixture.indexOf('operator.activate({activationId,bootstrapOperationId:operationId');
 assert(historical>=0&&historical<begin&&begin<sourceSnapshot&&sourceSnapshot<preparation&&preparation<activation);
 const seed=fixture.slice(begin,sourceSnapshot);
 assert(seed.includes("INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES(1001,1,$1)"));
 assert(seed.includes("INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES(1,$1,$2,1001)"));
 assert(fixture.includes("SELECT normalized_payload FROM identity.ctf_adaptive_memory WHERE kind='payload' AND payload_hash=$1"));
 const blocklist=helper.slice(helper.indexOf('async function contentBlocklistCases('),helper.indexOf('function assertContentHintDenied('));
 assert(!/INSERT INTO (?:ctf\.ctf_(?:technique|payload)_blocklist|identity\.ctf_adaptive_memory)/.test(blocklist));
 assert(blocklist.includes('const seeded=await snapshot()'));
});
test('Q05 participant reset uses only controlled prebootstrap activity and a post-COMMIT loss on its exact owner command',()=>{
 const fixture=read('tests/postgres/ctfAuthorityApplication.integration.test.js');
 const attempt=fixture.indexOf("INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response) VALUES(3010,1,1");
 const technique=fixture.indexOf("INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES(3010,1");
 const sourceSnapshot=fixture.indexOf('const before=Object.fromEntries(await Promise.all(TABLES.map');
 const activation=fixture.indexOf('operator.activate({activationId,bootstrapOperationId:operationId');
 assert(attempt>0&&technique>attempt&&technique<sourceSnapshot&&sourceSnapshot<activation);
 assert(fixture.includes("const result=await client.query(sql,args);\n   if(participantResetFaults&&participantResetFaults.matchEnqueue(sql,args))resetMatched=true;\n   if(sql==='COMMIT'&&resetMatched)participantResetFaults.afterSuccessfulCommit(true);"));
 assert(fixture.includes('web.use(participantResetFaults.middleware)'));
 assert(helper.includes('assertContentParticipantResetOutbox(outbox[0],mountedAuthority,admin,r.operationId)'));
 assert(helper.includes("seen.gets.every(p=>p===`/api/ctf/operations/${r.operationId}`)"));
});
test('participant reset outbox binds the mounted instructor actor and session, not the ABA comparison administrator',()=>{
 const {assertContentParticipantResetOutbox}=require('./postgres/support/ctfRecoveryRenderedCases');
 const id='12345678-1234-4234-8234-123456789abc';
 const mounted={user:{id:909},session:{id:707}},comparison={user:{id:1002},identitySession:{id:808}};
 const row={operation_id:id,actor_id:'909',session_id:'707',kind:'owner_reset',canonical_command:JSON.stringify({operationId:id,kind:'owner_reset',scope:{ownerId:'3010'}})};
 assert.deepEqual(assertContentParticipantResetOutbox(row,mounted,comparison,id),{operationId:id,kind:'owner_reset',ownerId:'3010'});
 for(const bad of [{actor_id:'1002'},{session_id:'808'},{operation_id:'other'},{kind:'owner_remove'},{canonical_command:JSON.stringify({operationId:id,kind:'owner_reset',scope:{ownerId:'1001'}})}])assert.throws(()=>assertContentParticipantResetOutbox({...row,...bad},mounted,comparison,id));
 assert.throws(()=>assertContentParticipantResetOutbox(row,{user:{id:1002},session:{id:707}},comparison,id));
});
test('expanded solution oracle requires the exact level card and rejects background payload matches',()=>{
 const {contentSolutionMatches}=require('./postgres/support/ctfRecoveryRenderedCases');
 const old=global.document;
 try{
  const card={children:[{},{}],innerText:'L1 Guardian Defenses: none exact payload'},button={textContent:'L1 Guardian Defenses: none',querySelector:()=>({textContent:'L1'}),parentElement:card};
  global.document={querySelectorAll:()=>[button]};assert(contentSolutionMatches({level:1,values:['exact payload']}));
  assert.equal(contentSolutionMatches({level:2,values:['exact payload']}),false);
  card.children=[{}];assert.equal(contentSolutionMatches({level:1,values:['exact payload']}),false);
  card.children=[{},{}];card.innerText='L1 Guardian Defenses: none';assert.equal(contentSolutionMatches({level:1,values:['exact payload']}),false);
 }finally{if(old===undefined)delete global.document;else global.document=old;}
});

test('challenge back navigation selects the unique top-bar button despite the footer duplicate',()=>{
 const {contentBackButton}=require('./postgres/support/ctfRecoveryRenderedCases');const old=global.document;
 try{
  const top={tagName:'BUTTON',textContent:'Back to Dashboard',getClientRects:()=>[{}]},footer={...top};
  const bar={children:[top,{},{}]},title={textContent:'Guardian',parentElement:{parentElement:bar}};
  global.document={querySelectorAll:selector=>selector==='h1'?[title]:[top,footer]};
  assert.equal(contentBackButton('Guardian'),top);assert.equal(contentBackButton('Other'),null);
  bar.children.push({...top});assert.equal(contentBackButton('Guardian'),null);
  bar.children.pop();top.getClientRects=()=>[];assert.equal(contentBackButton('Guardian'),null);
 }finally{if(old===undefined)delete global.document;else global.document=old;}
});

test('loaded main source closure rejects unpinned and changed modules',()=>{
 const {assertContentLoadedSources}=require('./postgres/support/ctfRecoveryRenderedCases');
 const path=require('node:path'),root=path.resolve(__dirname,'..'),file=__filename,relative=path.relative(root,file),digest=require('node:crypto').createHash('sha256').update(fs.readFileSync(file)).digest('hex');
 assert.equal(assertContentLoadedSources(root,{[relative]:{kind:'file',sha256:digest}},[file]),1);
 assert.throws(()=>assertContentLoadedSources(root,{},[file]));
 assert.throws(()=>assertContentLoadedSources(root,{[relative]:{kind:'file',sha256:'0'.repeat(64)}},[file]));
});

test('content diagnostics retain bounded path/status without URL credentials, query or raw failures',()=>{
 const {contentDiagnosticEvent}=require('./postgres/support/ctfRecoveryRenderedCases');
 const e=contentDiagnosticEvent('failed','http://secret:password@127.0.0.1:1234/assets/app.js?token=private#fragment',{failure:'net::ERR_ABORTED',resourceType:'script',status:404});
 assert.deepEqual(e,{kind:'failed',pathname:'/assets/app.js',status:404,resourceType:'script',failure:'net::ERR_ABORTED'});
 assert.equal(contentDiagnosticEvent('failed','invalid',{failure:'token private'}).failure,'[redacted]');
 assert(contentDiagnosticEvent('response','http://localhost/'+ 'a'.repeat(500)).pathname.length<=180);
});

test('content browser reuses the owned launcher and journals its real identity with close on invalid receipt',async()=>{
 const {launchContentBrowser}=require('./postgres/support/ctfRecoveryRenderedCases');const path=require('node:path'),os=require('node:os');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-browser-contract-')),prior=[process.env.ANALYTICS_BROWSER_EXECUTABLE,process.env.PUPPETEER_EXECUTABLE_PATH];let closes=0;
 try{process.env.ANALYTICS_BROWSER_EXECUTABLE=process.env.PUPPETEER_EXECUTABLE_PATH='/owned/chrome';
  const browser={close:async()=>{closes++;}},records=[];
  const launch=async(directory,label)=>{assert.equal(directory,root);assert.equal(label,'content');fs.writeFileSync(path.join(root,'content-process.json'),JSON.stringify({pid:1234}));return browser;};
  assert.equal(await launchContentBrowser(root,x=>records.push(x),launch),browser);assert.deepEqual(records,[{kind:'browser',pid:1234}]);
  await assert.rejects(launchContentBrowser(root,()=>{},async()=>{fs.writeFileSync(path.join(root,'content-process.json'),'{}');return browser;}));assert.equal(closes,1);
 }finally{for(const [n,v]of [['ANALYTICS_BROWSER_EXECUTABLE',prior[0]],['PUPPETEER_EXECUTABLE_PATH',prior[1]]])if(v===undefined)delete process.env[n];else process.env[n]=v;fs.rmSync(root,{recursive:true,force:true});}
});

test('canonical hint denial and exact instructor bootstrap reads retain closed admission',()=>{
 const {assertContentHintDenied,contentApiAllowed}=require('./postgres/support/ctfRecoveryRenderedCases');
 assert.doesNotThrow(()=>assertContentHintDenied({status:409,body:{error:'Hint availability changed; refresh stage status'}}));
 for(const value of [{status:403,body:{error:'Hint availability changed; refresh stage status'}},{status:409,body:{error:'other'}},{status:200,body:{}}])assert.throws(()=>assertContentHintDenied(value));
 for(const path of ['/api/admin/solutions','/api/admin/activity-stats','/api/admin/activity-logs']){assert(contentApiAllowed('GET',path));assert.equal(contentApiAllowed('POST',path),false);assert.equal(contentApiAllowed('GET',path+'/extra'),false);}
});

test('content cleanup preserves primary failure and restores before closing mounted services',async()=>{
 const {finishContent,contentFailure,contentRuntimeStatus,contentApiAllowed}=require('./postgres/support/ctfRecoveryRenderedCases');
 const primary=Object.assign(new Error('PRIVATE token'),{name:'TimeoutError',code:'PRIVATE'}),events=[],records=[];
 await assert.rejects(finishContent({primary,retire:async()=>events.push('retire'),restore:async()=>{events.push('restore');throw Object.assign(Error('PRIVATE restoration'),{code:'ERR_ASSERTION'});},close:async()=>events.push('close'),finish:async()=>events.push('finish'),record:x=>records.push(x)}),e=>e===primary);
 assert.deepEqual(events,['retire','restore','close','finish']);assert.deepEqual(records.map(({location,...v})=>v),[{phase:'restore',name:'Error',code:'ERR_ASSERTION'}]);assert.equal(records[0].location.file,'ctfRecoveryRenderedCases.js');assert(!JSON.stringify(records).includes('PRIVATE'));assert.deepEqual(contentFailure(primary),{name:'TimeoutError'});
 const secondary=[];await assert.rejects(finishContent({retire:async()=>{throw Error('retire');},restore:async()=>secondary.push('restore'),close:async()=>secondary.push('close'),finish:async()=>secondary.push('finish'),record:()=>{}}),AggregateError);assert.deepEqual(secondary,['restore','close','finish']);
 assert.deepEqual(contentRuntimeStatus({state:'running',requests:2,secret:'PRIVATE',worker:{state:'paused',active:false,lastOutcome:'failed',secret:'PRIVATE'}}),{state:'running',requests:2,worker:{state:'paused',active:false,lastOutcome:'failed'}});
 assert(contentApiAllowed('GET','/api/workshop/time/summary'));assert.equal(contentApiAllowed('POST','/api/workshop/time/summary'),false);assert.equal(contentApiAllowed('GET','/api/workshop/time/summary/extra'),false);
});

test('CTF worker and HTTP diagnostics retain only closed phases, codes and public errors',()=>{
 const {contentRuntimeStatus,contentOutboxKind,contentPublicError}=require('./postgres/support/ctfRecoveryRenderedCases');
 assert.deepEqual(contentRuntimeStatus({state:'running',worker:{state:'paused',lastOutcome:'failed',lastFailurePhase:'projection',lastFailureCode:'55P03',secret:'PRIVATE'}}),
  {state:'running',worker:{state:'paused',lastOutcome:'failed',lastFailurePhase:'projection',lastFailureCode:'55P03'}});
 assert.deepEqual(contentRuntimeStatus({state:'running',worker:{state:'paused',lastOutcome:'failed',lastFailurePhase:'PRIVATE',lastFailureCode:'PRIVATE'}}),
  {state:'running',worker:{state:'paused',lastOutcome:'failed'}});
 assert.equal(contentOutboxKind('blocklist_clear'),'blocklist_clear');assert.equal(contentOutboxKind('PRIVATE'),'other');assert.equal(contentOutboxKind(null),null);
 assert.equal(contentPublicError('CTF temporarily unavailable'),'temporarily_unavailable');
 assert.equal(contentPublicError('PRIVATE token or SQL'),'other');assert.equal(contentPublicError('__proto__'),'other');
});


test('content pointer uses instant scroll and waits for exact hit before one physical click',async()=>{
 const {contentPointerClick}=require('./postgres/support/ctfRecoveryRenderedCases');
 const events=[];let predicate;
 const element={isConnected:true,disabled:false,scrollIntoView:o=>{assert.deepEqual(o,{behavior:'instant',block:'center',inline:'center'});events.push('scroll');},getBoundingClientRect:()=>({x:10,y:10,width:20,height:20}),contains:()=>false};
 const handle={evaluate:async fn=>fn(element),asElement:()=>({click:async()=>events.push('click')})};
 const page={waitForFunction:async(fn,options,target)=>{assert.equal(options.timeout,15000);assert.equal(target,handle);predicate=fn;events.push('wait');return{dispose:async()=>events.push('dispose')};}};
 await contentPointerClick(page,handle,fn=>fn());assert.deepEqual(events,['scroll','wait','dispose','click']);
 const old=[global.document,global.innerWidth,global.innerHeight];
 try{global.innerWidth=100;global.innerHeight=100;global.document={elementFromPoint:()=>element};assert.equal(predicate(element),true);global.document.elementFromPoint=()=>({});assert.equal(predicate(element),false);element.disabled=true;assert.equal(predicate(element),false);}
 finally{for(const [k,v]of [['document',old[0]],['innerWidth',old[1]],['innerHeight',old[2]]])if(v===undefined)delete global[k];else global[k]=v;}
 events.length=0;await assert.rejects(contentPointerClick({...page,waitForFunction:async()=>{throw Error('blocked pointer');}},handle,fn=>fn()),/blocked pointer/);assert.deepEqual(events,['scroll']);
});


test('hint purchase selector binds exact own indexed label and canonical price span',()=>{
 const {contentHintButton}=require('./postgres/support/ctfRecoveryRenderedCases');const old=global.document;
 const make=(label='Unlock Hint 1',price='(-15 pts)')=>({childNodes:[{nodeType:1,textContent:'icon'},{nodeType:3,textContent:' '+label+' '}],children:[{tagName:'svg'},{tagName:'SPAN',textContent:price}],getClientRects:()=>[{}]});
 try{let buttons=[make()];global.document={querySelectorAll:selector=>{assert.equal(selector,'button');return buttons;}};
  assert.equal(contentHintButton({index:1,cost:15}),buttons[0]);assert.equal(contentHintButton({index:2,cost:15}),null);assert.equal(contentHintButton({index:1,cost:25}),null);
  for(const bad of [make('Unlock Hint 10'),make('Other Unlock Hint 1'),make('Unlock Hint 1','(-15 pts) extra'),{...make(),getClientRects:()=>[]}, {...make(),children:[{tagName:'SPAN',textContent:'(-15 pts)'},{tagName:'SPAN',textContent:'extra'}]}]){buttons=[bad];assert.equal(contentHintButton({index:1,cost:15}),null);}
  buttons=[make(),make()];assert.equal(contentHintButton({index:1,cost:15}),null);
 }finally{if(old===undefined)delete global.document;else global.document=old;}
});


test('content actors use separate contexts and retire every context despite failures',async()=>{
 const {contentActorPages}=require('./postgres/support/ctfRecoveryRenderedCases');let next=0;const contexts=[],closed=[];
 const browser={createBrowserContext:async()=>{const id=++next,storage=new Map(),context={newPage:async()=>({id,storage}),close:async()=>{closed.push(id);if(id===3)throw Error('close failed');}};contexts.push(context);return context;}};
 const actors=contentActorPages(browser),admin=await actors.newPage(),learner=await actors.newPage();admin.storage.set('token','admin');learner.storage.set('token','learner');assert.equal(admin.storage.get('token'),'admin');assert.notEqual(admin.id,learner.id);
 await actors.closePage(learner);assert.deepEqual(closed,[2]);await actors.newPage();await actors.newPage();await assert.rejects(actors.close(),AggregateError);assert.deepEqual(closed,[2,1,3,4]);
 const failed=[];const broken=contentActorPages({createBrowserContext:async()=>({newPage:async()=>{throw Error('page failed');},close:async()=>failed.push('closed')})});await assert.rejects(broken.newPage(),/page failed/);await broken.close();assert.deepEqual(failed,['closed']);
});
