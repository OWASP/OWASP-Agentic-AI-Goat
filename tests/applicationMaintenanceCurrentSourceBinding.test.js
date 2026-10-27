'use strict';
// Read-only main-root admission controls. No copied checkout, temp source, or resources.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createRequire}=require('node:module'),{createHash}=require('node:crypto');
const ROOT=path.resolve(__dirname,'..'),file=path.join(ROOT,'server/services/applicationMaintenanceInprocessAdmission.js'),realRequire=createRequire(file);
const activeManifest=fs.readFileSync(file,'utf8').match(/require\('(\.\/applicationMaintenanceInprocessSources-v[0-9]+\.json)'\)/)[1];
function admissionWith(fsOverrides={},manifestOverride,pathOverride,sourceOverride){
 const source=sourceOverride||fs.readFileSync(file,'utf8'),manifestName=source.match(/CURRENT_MANIFEST=require\('(\.\/applicationMaintenanceInprocessSources-v[0-9]+\.json)'\)/)?.[1]||activeManifest;
 const module={exports:{}};const wrapped=vm.runInThisContext(`(function(require,module,exports,__filename,__dirname){${source}\n})`,{filename:file});
 wrapped(name=>name==='node:path'&&pathOverride?pathOverride:name==='node:fs'?new Proxy(fs,{get:(target,key)=>fsOverrides[key]||target[key]}):name===manifestName&&manifestOverride?manifestOverride:realRequire(name),module,module.exports,file,path.dirname(file));return module.exports;
}
function bindingWith(...args){return admissionWith(...args).sourceBinding;}
const denied=fn=>assert.throws(fn,{code:'APPLICATION_MAINTENANCE_PREPARATION_INVALID'});
function assertHistoricalBinding(version,manifest,expectedSource,expectedRecovery){
 const active=fs.readFileSync(file,'utf8'),activeName=activeManifest.slice(2),historicalName=`applicationMaintenanceInprocessSources-v${version}.json`;
 assert.equal(active.split(activeName).length-1,2);
 const frozen=active.replaceAll(activeName,historicalName),digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(frozen.split(historicalName).length-1,2);
 assert.equal(digest(frozen),manifest.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 assert.equal(digest(JSON.stringify(manifest)),expectedSource);
 assert.equal(digest(JSON.stringify(manifest.recoveryFiles.map(name=>[name,manifest.files[name]]))),expectedRecovery);
 denied(()=>admissionWith({},manifest,undefined,frozen).sourceBinding(ROOT));
}







test('v197 historical source binds immutable ticket reference selection and versioned evidence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v196.json'),current=realRequire('./applicationMaintenanceInprocessSources-v197.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const changed=['server/config/secureshopCurriculum.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js','server/services/secureshopTicketAgentProposal.js','server/services/secureshopTicketBrowserAssessment.js','server/services/secureshopTicketBrowserEvidence.js','server/services/secureshopTicketBrowserOriginalReader.js','server/services/secureshopTicketContract.js'];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v196.json'))),'1173824669037c99c2a26d766a0b8847b02ac4124d66901a9163d090b8804ada');
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v197.json'))),'1ddeaf3c2694a4e5dd1a89db32b7fa35a573b6f6d1449ce1f96e7caf4f2b3e53');
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v196 historical source binds lossless user-role ticket presentation',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v195.json'),current=realRequire('./applicationMaintenanceInprocessSources-v196.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js'];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v195.json'))),'cf252fa53db7cc2393b837095be6abd6b30e27141c2ad77b1ae49ecec7da6188');
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v195 historical source includes ticket renderer in fresh and repair setup',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v194.json'),current=realRequire('./applicationMaintenanceInprocessSources-v195.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const changed=['scripts/setup-application.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v194.json'))),'47c0928624d0ea363cbab14a35a45b02610743a07f42e29919e42fdd112fa3b4');
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v194 historical source binds ticket workflow, renderer, recovery and exact refund intent',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v193.json'),current=realRequire('./applicationMaintenanceInprocessSources-v194.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const changed=["client/src/pages/secureshop/bridge/guestRouting.mjs", "client/src/pages/secureshop/bridge/operations.mjs", "client/src/pages/secureshop/bridge/stateChannel.mjs", "client/src/pages/secureshop/bridge/stateStore.mjs", "client/src/pages/secureshop/components/BoundAgentLane.jsx", "client/src/pages/secureshop/components/BoundProductPicker.jsx", "client/src/pages/secureshop/hooks/useAgentStream.js", "client/src/pages/secureshop/utils/shopStorage.mjs", "server/config/secureshopCurriculum.js", "server/database/postgres/secureshopBoundToolPolicyReadiness.js", "server/routes/secureshop/boundGateway.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopAssessmentRecovery.js", "server/services/secureshopBoundAclRegistry.js", "server/services/secureshopBoundApplication.js", "server/services/secureshopBoundCustomerChat.js", "server/services/secureshopBoundCustomerCommerceTools.js", "server/services/secureshopBoundRefundTools.js", "server/services/secureshopBoundReviewComposition.js", "server/services/secureshopCleanupComposition.js", "server/services/secureshopFeatureModeAuthority.js"],added=["client/package-lock.json", "client/package.json", "client/src/pages/secureshop/SecureShopApp.jsx", "client/src/pages/secureshop/components/AdminTicketBody.jsx", "client/src/pages/secureshop/components/CustomerTicketConfirmationCard.jsx", "client/src/pages/secureshop/components/TopNav.jsx", "client/src/pages/secureshop/components/ticketDetailClientRenderer.jsx", "client/src/pages/secureshop/hooks/useAdminTicketAssessment.js", "client/src/pages/secureshop/hooks/useCustomerTicketConfirmation.js", "client/src/pages/secureshop/pages/admin/Tickets.jsx", "client/src/pages/secureshop/utils/adminTicketAssessmentReference.mjs", "client/src/pages/secureshop/utils/adminTicketPresentation.mjs", "client/src/pages/secureshop/utils/customerTicketConfirmationReference.mjs", "client/vite.ticket-renderer.config.mjs", "db/postgres/workshop-migrations/secureshop_agents/0088_customer_ticket_prepare_registry_successor.sql", "db/postgres/workshop-migrations/secureshop_review/0049_bound_support_ticket_receipts.sql", "scripts/verify-release-source-inclusion.js", "server/database/postgres/secureshopTicketBrowserAssessmentReader.js", "server/database/postgres/secureshopTicketRepository.js", "server/routes/secureshop/boundTicketAdmin.js", "server/routes/secureshop/boundTicketAssessment.js", "server/routes/secureshop/boundTicketConfirmation.js", "server/services/secureshopTicketAdministration.js", "server/services/secureshopTicketAgentConfirmation.js", "server/services/secureshopTicketAgentProposal.js", "server/services/secureshopTicketBrowserAssessment.js", "server/services/secureshopTicketBrowserEvidence.js", "server/services/secureshopTicketBrowserOriginalReader.js", "server/services/secureshopTicketBrowserQualification.js", "server/services/secureshopTicketContract.js"];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v193.json'))),'7f58841c83482936b2849da733352dae3746e8b3db667a55223ae23a07c6c1ab');
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1525);assert.equal(current.recoveryFiles.length,1516);
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v193 historical source binds Coupon Agent contract admission and recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v192.json'),current=realRequire('./applicationMaintenanceInprocessSources-v193.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopCouponAgentContract.js'];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v192.json'))),'bf7cfc7319e929f13a6caa5d300c2e0e4b91223e8d03812e872ad8be6013e443');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1495);assert.equal(current.recoveryFiles.length,1486);
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v192 historical source binds IDOR assessment evidence and recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v191.json'),current=realRequire('./applicationMaintenanceInprocessSources-v192.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v192.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v192\.json/g)||[]).length,2);
 assert.equal(digest(frozenAdmissionBytes),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopIdorLessonAssessment.js','server/services/secureshopIdorLessonEvidence.js'];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v191.json'))),'6d21934fcdfa0fd266c8925c2b1f2e98e56fa63862c6aa483e36cddc734d5e26');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1495);assert.equal(current.recoveryFiles.length,1486);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v192.json'))),'bf7cfc7319e929f13a6caa5d300c2e0e4b91223e8d03812e872ad8be6013e443');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v191 historical source binds IDOR assessment evidence and recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v190.json'),current=realRequire('./applicationMaintenanceInprocessSources-v191.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v191.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v191\.json/g)||[]).length,2);
 assert.equal(digest(frozenAdmissionBytes),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopIdorLessonAssessment.js','server/services/secureshopIdorLessonEvidence.js'];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v190.json'))),'3d501bf693b338a891bda58e7855871787ffba560d078bac941d171732fef266');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1495);assert.equal(current.recoveryFiles.length,1486);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v191.json'))),'6d21934fcdfa0fd266c8925c2b1f2e98e56fa63862c6aa483e36cddc734d5e26');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v190 historical source binds reviewed progress, role navigation and bounded IDOR repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v189.json'),current=realRequire('./applicationMaintenanceInprocessSources-v190.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v190.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v190\.json/g)||[]).length,2);
 assert.equal(digest(frozenAdmissionBytes),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changed=["server/applicationServer.js", "server/routes/secureshopStandaloneAuth.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshop/providerRouter.js", "server/services/secureshop/providers/ollamaProvider.js", "server/services/secureshopBoundIdorLessonChat.js", "server/services/secureshopBoundReviewComposition.js"],added=["client/src/pages/secureshop/SecureShopStandaloneAssessmentsControl.jsx", "client/src/pages/secureshop/SecureShopStandaloneBound.jsx", "client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx", "client/src/pages/secureshop/SecureShopStandaloneObjectivesControl.jsx", "client/src/pages/secureshop/SecureShopStandalonePasswordReset.jsx", "client/src/pages/secureshop/SecureShopStandaloneProgressControl.jsx", "client/src/pages/secureshop/bridge/auditCsvExport.mjs", "client/src/pages/secureshop/bridge/cartRefresh.mjs", "client/src/pages/secureshop/bridge/guestCartProtocol.mjs", "client/src/pages/secureshop/bridge/guestRouting.mjs", "client/src/pages/secureshop/bridge/passwordResetIntent.mjs", "client/src/pages/secureshop/bridge/registeredPasswordResetRecovery.mjs", "client/src/pages/secureshop/components/AgentAssist.jsx", "client/src/pages/secureshop/components/ProductCard.jsx", "client/src/pages/secureshop/components/ProductDescription.jsx", "client/src/pages/secureshop/components/Rating.jsx", "client/src/pages/secureshop/components/ReviewCard.jsx", "client/src/pages/secureshop/components/Spinner.jsx", "client/src/pages/secureshop/guestCartImport.mjs", "client/src/pages/secureshop/pages/Product.jsx", "client/src/pages/secureshop/standaloneClient.mjs", "client/src/pages/secureshop/utils/assetUrl.mjs", "client/src/pages/secureshop/utils/boundReviewRequests.mjs", "client/src/pages/secureshop/utils/legacyProductImageDefaults.json", "client/src/pages/secureshop/utils/reviewLifecycle.mjs", "server/database/postgres/secureshopAssessmentProgressRepository.js", "server/services/secureshopAssessmentProgress.js", "server/services/secureshopIdorFinalAnswerContract.js"];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v189.json'))),'cf1b9b79dfb3f0e87652cbdbfdbbd685a71f57e411c2bbf43409236ce06ba4c9');
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v190.json'))),'3d501bf693b338a891bda58e7855871787ffba560d078bac941d171732fef266');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v189 historical source binds the current IDOR browser card and recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v188.json'),current=realRequire('./applicationMaintenanceInprocessSources-v189.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const changed=['client/src/pages/secureshop/components/CustomerIdorLessonCard.jsx','client/src/pages/secureshop/hooks/useCustomerIdorLesson.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v188.json'))),'48f64f08c337c19f4cf51831818c8344b0eabcf4f25f03223cd7e7b07d5ad591');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1467);assert.equal(current.recoveryFiles.length,1458);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v189.json'))),'cf1b9b79dfb3f0e87652cbdbfdbbd685a71f57e411c2bbf43409236ce06ba4c9');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v188 historical source binds mounted IDOR and Coupon authority, evidence and rendered recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v187.json'),current=realRequire('./applicationMaintenanceInprocessSources-v188.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v188.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v188\.json/g)||[]).length,2);
 assert.equal(digest(frozenAdmissionBytes),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changed=["client/src/pages/secureshop/bridge/operations.mjs", "client/src/pages/secureshop/bridge/stateChannel.mjs", "client/src/pages/secureshop/bridge/stateStore.mjs", "client/src/pages/secureshop/components/BoundAgentLane.jsx", "client/src/pages/secureshop/hooks/useAgentStream.js", "client/src/pages/secureshop/pages/Cart.jsx", "client/src/pages/secureshop/utils/shopStorage.mjs", "server/config/secureshopCurriculum.js", "server/database/postgres/secureshopAssessmentSeed.js", "server/database/postgres/secureshopBoundCouponRepository.js", "server/database/postgres/secureshopBoundToolPolicyReadiness.js", "server/routes/secureshop/boundGateway.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopAssessmentRecovery.js", "server/services/secureshopBoundAclRegistry.js", "server/services/secureshopBoundApplication.js", "server/services/secureshopBoundCommerce.js", "server/services/secureshopBoundCoupon.js", "server/services/secureshopBoundCustomerChat.js", "server/services/secureshopBoundCustomerCommerceTools.js", "server/services/secureshopBoundReviewComposition.js", "server/services/secureshopConversationPurpose.js", "server/services/secureshopConversationalCommerceContract.js", "server/services/secureshopCouponProduction.js", "server/services/secureshopFeatureModeAuthority.js", "server/services/secureshopOwnedAnalyticsProduction.js", "sidecars/analytics-sql-target/service.js"];
 const added=["client/src/pages/secureshop/bridge/mailReferences.mjs", "client/src/pages/secureshop/components/AgentLane/Hop.jsx", "client/src/pages/secureshop/components/AgentLane/HopDetailSheet.jsx", "client/src/pages/secureshop/components/AgentLane/Turn.jsx", "client/src/pages/secureshop/components/Badge.jsx", "client/src/pages/secureshop/components/BoundProductPicker.jsx", "client/src/pages/secureshop/components/Button.jsx", "client/src/pages/secureshop/components/Card.jsx", "client/src/pages/secureshop/components/CustomerCartConfirmation.jsx", "client/src/pages/secureshop/components/CustomerCouponProposalCard.jsx", "client/src/pages/secureshop/components/CustomerIdorLessonCard.jsx", "client/src/pages/secureshop/components/EmptyState.jsx", "client/src/pages/secureshop/components/PracticeAddressSetup.jsx", "client/src/pages/secureshop/components/PracticePaymentSetup.jsx", "client/src/pages/secureshop/components/PracticeProfileUpdate.jsx", "client/src/pages/secureshop/hooks/useCustomerCouponConfirmation.js", "client/src/pages/secureshop/hooks/useCustomerIdorLesson.js", "client/src/pages/secureshop/hooks/useProductQuestion.js", "client/src/pages/secureshop/pages/merchant/InventoryPanel.jsx", "client/src/pages/secureshop/pages/merchant/useBoundInventory.js", "client/src/pages/secureshop/utils/addressSetupOperation.mjs", "client/src/pages/secureshop/utils/auditJobReference.mjs", "client/src/pages/secureshop/utils/chatCartReference.mjs", "client/src/pages/secureshop/utils/couponReference.mjs", "client/src/pages/secureshop/utils/customerCards.mjs", "client/src/pages/secureshop/utils/customerChatReferences.mjs", "client/src/pages/secureshop/utils/customerCouponConfirmationReference.mjs", "client/src/pages/secureshop/utils/customerIdorLessonReference.mjs", "client/src/pages/secureshop/utils/customerOrderDetails.mjs", "client/src/pages/secureshop/utils/customerOrderPage.mjs", "client/src/pages/secureshop/utils/practicePaymentOperation.mjs", "client/src/pages/secureshop/utils/profileOperation.mjs", "client/src/pages/secureshop/utils/refundReferences.mjs", "client/src/pages/secureshop/utils/refundSetup.mjs", "db/postgres/workshop-migrations/secureshop_agents/0086_idor_lesson_conversation_purpose.sql", "db/postgres/workshop-migrations/secureshop_agents/0087_customer_coupon_prepare_registry_successor.sql", "db/postgres/workshop-migrations/secureshop_review/0048_owned_idor_lesson_receipts.sql", "server/database/postgres/secureshopBoundIdorLessonRepository.js", "server/database/postgres/secureshopCouponAgentAssessmentReader.js", "server/database/postgres/secureshopIdorLessonTurnReader.js", "server/database/postgres/secureshopSelectedSceneEffect.js", "server/routes/secureshop/boundCouponAgentAssessment.js", "server/routes/secureshop/boundCouponAgentConfirm.js", "server/routes/secureshop/boundIdorLesson.js", "server/services/secureshopBoundIdorLessonChat.js", "server/services/secureshopCouponAgentAssessment.js", "server/services/secureshopCouponAgentConfirmation.js", "server/services/secureshopCouponAgentContract.js", "server/services/secureshopCouponAgentEvidence.js", "server/services/secureshopCouponAgentOriginalReader.js", "server/services/secureshopCouponAgentProposalService.js", "server/services/secureshopIdorLessonAssessment.js", "server/services/secureshopIdorLessonContract.js", "server/services/secureshopIdorLessonEvidence.js", "server/services/secureshopIdorLessonTools.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1467);assert.equal(current.recoveryFiles.length,1458);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v188.json'))),'48f64f08c337c19f4cf51831818c8344b0eabcf4f25f03223cd7e7b07d5ad591');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v187 historical source binds exact empty checkout order options and saved page recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v186.json'),current=realRequire('./applicationMaintenanceInprocessSources-v187.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v186.json'))),'a9f03cac9d16fe1e1b48b9ff8e6ebd88c47ac768222c4fde08c5f4f97919f539');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1412);assert.equal(current.recoveryFiles.length,1403);
 assert.equal(current.files[changed[1]],'65318eab27da24c32b928e59919729e683f56489c45a1b015e22fb76d2893c40');
 assert.equal(current.files[changed[2]],'437d0158c1508398f44f1719fdf19c4a298ec22ceb8a40c2c2b17c120519de84');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v187.json'))),'c55685f6b46d51bc3efca9b5379cf80d0519688019aae2831f0c3f9f5484850d');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v186 historical source binds Pricing comparison context and checkout receipt recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v185.json'),current=realRequire('./applicationMaintenanceInprocessSources-v186.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v185.json'))),'8f798e461d22c71f786447e737b10e3eae6f970f5b559d5a10d7dae22ddcb5b7');
 const changed=['client/src/pages/secureshop/components/CustomerCheckoutCard.jsx','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopPricingEvidence.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1412);assert.equal(current.recoveryFiles.length,1403);
 assert.equal(current.files[changed[0]],'10b0a9ce98c3c66f3ce2952efec9e7c73f7621d892d5f58d8770d799ce64e6ac');
 assert.equal(current.files[changed[2]],'5a83acf1d215148c425fe684ddd4bb52b62078da5576a7e735fae4998e880deb');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v186.json'))),'a9f03cac9d16fe1e1b48b9ff8e6ebd88c47ac768222c4fde08c5f4f97919f539');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v185 historical source binds scene grant locking and refund stream authority restoration',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v184.json'),current=realRequire('./applicationMaintenanceInprocessSources-v185.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v184.json'))),'1a4c840829b40750fc5acdfbe10247f265e2bba98d27fee27af28180617ec625');
 const changed=['client/src/pages/secureshop/components/BoundAgentLane.jsx','server/database/postgres/secureshopSceneProductAuditSource.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1412);assert.equal(current.recoveryFiles.length,1403);
 assert.equal(current.files[changed[0]],'d6d9041348d2d6cf07f31d490ece12401c024ad7444e467cad7ffd27a8d756fb');
 assert.equal(current.files[changed[1]],'b7a9401f8f8da63ea28e6a69950a82ba992e860e0eef29b4ff82db725a0d433f');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v185.json'))),'8f798e461d22c71f786447e737b10e3eae6f970f5b559d5a10d7dae22ddcb5b7');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v184 historical source binds completed checkout restoration without cart replay',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v183.json'),current=realRequire('./applicationMaintenanceInprocessSources-v184.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v183.json'))),'658bfe5e80c4cf6e17568e74afb03f226cb06396d8c8ba3e919e8271144ea601');
 const changed=['client/src/pages/secureshop/components/BoundAgentLane.jsx','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1412);assert.equal(current.recoveryFiles.length,1403);
 assert.equal(current.files['client/src/pages/secureshop/components/BoundAgentLane.jsx'],'8b295c280757609183e1ff0fae1468a5c9f37d77707675adcfb2f04d9ac03810');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v184.json'))),'1a4c840829b40750fc5acdfbe10247f265e2bba98d27fee27af28180617ec625');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v183 historical source binds saved-decline payment refresh and its exact reference codecs',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v182.json'),current=realRequire('./applicationMaintenanceInprocessSources-v183.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v182.json'))),'a05a5834e3becb561e508804bc402da606232f18c5c762a9825d5706a5d4d0b5');
 const changed=['client/src/pages/secureshop/components/BoundAgentLane.jsx','server/services/applicationMaintenanceInprocessAdmission.js'];
 const added=['client/src/pages/secureshop/components/CustomerCheckoutCard.jsx','client/src/pages/secureshop/utils/checkoutReference.mjs','client/src/pages/secureshop/utils/customerTurnOperations.mjs'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1412);assert.equal(current.recoveryFiles.length,1403);
 assert.equal(current.files[added[0]],'87e17c6d78d9e41e6550e1836fe2c221b57cc19a5a0b637c6da2f37fb816ccaa');
 assert.equal(current.files['client/src/pages/secureshop/components/BoundAgentLane.jsx'],'6c8cfd3c85aeb4fdd16da1e26e5e5d7b9de9d32ecf0a4fcd5f79bec85e4ca396');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v183.json'))),'658bfe5e80c4cf6e17568e74afb03f226cb06396d8c8ba3e919e8271144ea601');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v182 historical source binds validated payment continuation and honest denied-tool finalization',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v181.json'),current=realRequire('./applicationMaintenanceInprocessSources-v182.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v181.json'))),'3c004033552b7cd0608b322f9e6fd8c79def88d52a50332e81f5be5eb6377378');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1409);assert.equal(current.recoveryFiles.length,1400);
 assert.equal(current.files['server/services/secureshopBoundCustomerChat.js'],'288abfa4144a2674b0a110dee19b96b973749f87785476e0400223bc63921074');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v182.json'))),'a05a5834e3becb561e508804bc402da606232f18c5c762a9825d5706a5d4d0b5');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v181 historical source binds explicit customer address actions through the closed bridge compiler',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v180.json'),current=realRequire('./applicationMaintenanceInprocessSources-v181.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v180.json'))),'4a39e8547115e3105478af9be2ae5d1bf1fc6cd659c71fc4f76667e255a4f8e3');
 const changed=['client/src/pages/secureshop/bridge/operations.mjs','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1409);assert.equal(current.recoveryFiles.length,1400);
 assert.equal(current.files['client/src/pages/secureshop/bridge/operations.mjs'],'454d3c5b9328ba4836f4228178cfbc92bb762769c848be9232e9bd41ded1ce00');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v181.json'))),'3c004033552b7cd0608b322f9e6fd8c79def88d52a50332e81f5be5eb6377378');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v180 historical source binds explicit customer address actions and canonical raw-listing trace dates',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v179.json'),current=realRequire('./applicationMaintenanceInprocessSources-v180.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v179.json'))),'6e9bbef76a03d94c0416da8ecb6046a8e25681eb05709b11c4be2098a259749e');
 const changed=['client/src/pages/secureshop/components/BoundAgentLane.jsx','client/src/pages/secureshop/hooks/useAgentStream.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js','server/services/secureshopListingRawBrowserEvidence.js'];
 const added=['client/src/pages/secureshop/components/CustomerChoiceCards.jsx'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1409);assert.equal(current.recoveryFiles.length,1400);
 assert.equal(current.files['server/services/secureshopListingRawBrowserEvidence.js'],'a59e2bccea8bb1b86aa2f142c6fe9224dc249ad61bf73d417c0de193e5095c12');
 assert.equal(current.files['server/services/secureshopBoundCustomerChat.js'],'0aa4e5e92cc013ebe9f61981eb849bd60a2a00032983faf9663e7b8a9954bb46');
 assert.equal(current.files['server/services/secureshopBoundCustomerCommerceTools.js'],'4bf8bf38f148777c661ab5dcf9c960ab4c5d855154c4709d1c80a84fc71dbe64');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v180.json'))),'4a39e8547115e3105478af9be2ae5d1bf1fc6cd659c71fc4f76667e255a4f8e3');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v179 historical source binds canonical raw-listing authority without middleware expiry metadata',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v178.json'),current=realRequire('./applicationMaintenanceInprocessSources-v179.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v178.json'))),'25128a993fddd28d853ec6727c880d995d44236ac3069f1fb4d32ab231c2350d');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopListingRawBrowserAssessment.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1408);assert.equal(current.recoveryFiles.length,1399);
 assert.equal(current.files['server/services/secureshopListingRawBrowserAssessment.js'],'bca7e55ae6bd391aa9403646174c44d418c73fd9ec48dfa6ceb179b6f7b7b767');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v179.json'))),'6e9bbef76a03d94c0416da8ecb6046a8e25681eb05709b11c4be2098a259749e');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v178 historical source binds raw-listing Judge guard with closed JSONB semantic comparison',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v177.json'),current=realRequire('./applicationMaintenanceInprocessSources-v178.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v177.json'))),'831882fcc05d390bb2848bf3f1eb6976e4787e8753f93f0ee245cb343c42aad7');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopListingRawBrowserAssessment.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1408);assert.equal(current.recoveryFiles.length,1399);
 assert.equal(current.files['server/services/secureshopListingRawBrowserAssessment.js'],'3f157c3d5253a1e9c791d3ca72bfa448303b3ce7a6b4221e5970fac5126eed8a');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v178.json'))),'25128a993fddd28d853ec6727c880d995d44236ac3069f1fb4d32ab231c2350d');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v177 historical source binds original raw-listing observation with JSONB field-order parity',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v176.json'),current=realRequire('./applicationMaintenanceInprocessSources-v177.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v176.json'))),'42ed51a2c63667129be2df7a3d10ef6a001e9c9be3916f8594f7cf296bd4fb48');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopListingRawBrowserEvidence.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1408);assert.equal(current.recoveryFiles.length,1399);
 assert.equal(current.files['server/services/secureshopListingRawBrowserEvidence.js'],'199f96dede796124b7d2e5cb49ca85a42142ba7288f4bf208477b91cc42f6248');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v177.json'))),'831882fcc05d390bb2848bf3f1eb6976e4787e8753f93f0ee245cb343c42aad7');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v176 historical source binds non-citable protected references and response-only semantic grounding',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v175.json'),current=realRequire('./applicationMaintenanceInprocessSources-v176.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v175.json'))),'fdddeb5baa2cc2e9657a78b78d59fc124e3c2c4f68e804140d48ae58db1b5d4c');
 const changed=['server/agent-runtime/objectiveJudge.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopAnalyticsDisclosureAssessment.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1408);assert.equal(current.recoveryFiles.length,1399);
 assert.equal(current.files['server/services/secureshopAnalyticsDisclosureAssessment.js'],'21d9abfed85dd552bc7c5a57d45899ab627bee6382ecc2fd2d282ca7ba682690');
 assert.equal(current.files['server/agent-runtime/objectiveJudge.js'],'d4480ea1a1cd80475ba77fd2b1c99c5825893d1ce4fc95569d0d359ca768c206');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v176.json'))),'42ed51a2c63667129be2df7a3d10ef6a001e9c9be3916f8594f7cf296bd4fb48');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v175 historical source binds scoped analytics semantic grading while preserving full proof',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v174.json'),current=realRequire('./applicationMaintenanceInprocessSources-v175.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v174.json'))),'30186705daa742af6f06024eeb905be2992f2d7d9b46dde60d4fc786ae6d27f7');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopAnalyticsDisclosureAssessment.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1408);assert.equal(current.recoveryFiles.length,1399);
 assert.equal(current.files['server/services/secureshopAnalyticsDisclosureAssessment.js'],'8c1cc4b0fff0626f795c3d8610316bbcb7cbf45cc864d59460fc8c11859c080e');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v175.json'))),'fdddeb5baa2cc2e9657a78b78d59fc124e3c2c4f68e804140d48ae58db1b5d4c');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v174 historical source binds immutable raw listing creation, assessment and recovery UI',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v173.json'),current=realRequire('./applicationMaintenanceInprocessSources-v174.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v173.json'))),'9217b2f2f0f5738e87f38b2df2f24635513089e132468ba7b40c9960995f8d7e');
 const changed=["client/src/pages/secureshop/bridge/operations.mjs", "client/src/pages/secureshop/hooks/useBoundRoleAssistant.js", "client/src/pages/secureshop/pages/merchant/listingCreateOperation.mjs", "server/config/secureshopCurriculum.js", "server/database/postgres/secureshopBoundProductRepository.js", "server/routes/secureshop/boundGateway.js", "server/routes/secureshop/boundRoleChat.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopBoundCatalog.js", "server/services/secureshopBoundListings.js", "server/services/secureshopBoundReviewComposition.js", "server/services/secureshopBoundRoleChat.js", "server/services/secureshopCleanupComposition.js", "server/services/secureshopListingCreateContract.js", "server/services/secureshopRoleListingCreateProposal.js"],added=["client/src/pages/secureshop/components/MerchantListingCreateConfirmation.jsx", "client/src/pages/secureshop/pages/merchant/listingCreateAssessment.mjs", "client/src/utils/judgeFailureMessage.mjs", "client/src/utils/judgeFeedback.mjs", "db/postgres/workshop-migrations/secureshop_review/0047_owned_listing_create_html_source.sql", "server/services/secureshopListingRawBrowserAssessment.js", "server/services/secureshopListingRawBrowserEvidence.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1408);assert.equal(current.recoveryFiles.length,1399);
 assert.equal(current.files['db/postgres/workshop-migrations/secureshop_review/0047_owned_listing_create_html_source.sql'],'f166c333132da26d84630bc90e8d1ec6b236dc93204b287240364cc31ec1dfdb');
 assert.equal(current.files['server/services/secureshopListingRawBrowserEvidence.js'],'e59ea97cca8e504103397789b69b2c31e367aa7ac40204f988ea48193941f5c5');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v174.json'))),'30186705daa742af6f06024eeb905be2992f2d7d9b46dde60d4fc786ae6d27f7');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v173 historical source binds scene audit provenance, native V24 defaults and physical Pricing instructions',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v172.json'),current=realRequire('./applicationMaintenanceInprocessSources-v173.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v172.json'))),'7aac89f824c495e418fca5524621b2082a363febd3cdf4074d3f719e3f355eb9');
 const changed=["client/src/pages/secureshop/pages/merchant/Pricing.jsx", "server/config/secureshopCurriculum.js", "server/database/postgres/secureshopAssessmentSeed.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopAuditFixedProjection.js", "server/services/secureshopAuditJob.js", "server/services/secureshopAuditObservationSpool.js", "server/services/secureshopAuditRuntime.js", "server/services/secureshopAuditSourceManifest.js", "server/services/secureshopBoundReviewComposition.js"],added=["client/src/pages/secureshop/pages/merchant/PricingRecoveryReferences.jsx", "client/src/pages/secureshop/pages/merchant/pricingRecovery.mjs", "client/src/pages/secureshop/pages/merchant/useBoundPricing.js", "server/database/postgres/secureshopSceneProductAuditSource.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1401);assert.equal(current.recoveryFiles.length,1392);
 assert.equal(current.files['server/database/postgres/secureshopAssessmentSeed.js'],'a27af313c45c3c2ddfbf38aad00d986dfe46c1eb8e43f265f58aa6a4ba023c9b');
 assert.equal(current.files['server/database/postgres/secureshopSceneProductAuditSource.js'],'6e7db5c175c5363646a136aac34bbbeabac90c8222dfb420465f824b43d78f5f');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v173.json'))),'9217b2f2f0f5738e87f38b2df2f24635513089e132468ba7b40c9960995f8d7e');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v172 historical source binds setup command and absent assessment route corrections',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v171.json'),current=realRequire('./applicationMaintenanceInprocessSources-v172.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v171.json'))),'ca583ddc710cf8b34cee1221be9fb09a9875b09d71591de3d1e4e4e1635941d7');
 const changed=['scripts/setup-application.js','server/routes/secureshop/boundGateway.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1397);assert.equal(current.recoveryFiles.length,1388);
 assert.equal(current.files['scripts/setup-application.js'],'3b7f988bf91e18bcdb385b87fafe6e94e55d929156f1c51767146e21d4087079');
 assert.equal(current.files['server/routes/secureshop/boundGateway.js'],'5c941edee999d1ee0e00c01b66bfd0434fe8d69bd3480eee1237be0ffd16900d');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v172.json'))),'7aac89f824c495e418fca5524621b2082a363febd3cdf4074d3f719e3f355eb9');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v171 historical source binds registered impersonation assessment and saved frontend recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v170.json'),current=realRequire('./applicationMaintenanceInprocessSources-v171.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v170.json'))),'ac21cf119677985b0c5359beb79e931e57ed3a9d5b35ac8b8601d14e5e957c07');
 const changed=["client/src/pages/secureshop/SecureShopStandaloneController.mjs", "client/src/pages/secureshop/bridge/operations.mjs", "client/src/pages/secureshop/bridge/stateChannel.mjs", "client/src/pages/secureshop/bridge/stateStore.mjs", "client/src/pages/secureshop/components/BoundAgentLane.jsx", "client/src/pages/secureshop/utils/shopStorage.mjs", "server/config/secureshopCurriculum.js", "server/database/postgres/secureshopOwnedMcpRegistryRepository.js", "server/routes/secureshop/boundAdminChat.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopAssessmentRecovery.js", "server/services/secureshopBoundReviewComposition.js", "server/services/secureshopRegisteredAdminRuntime.js", "server/services/secureshopRegisteredInvocationProduction.js"],added=["client/src/components/workshop/WorkshopExperience.js", "client/src/components/workshop/experience.mjs", "client/src/pages/secureshop/components/RegisteredAdminConversation.jsx", "client/src/pages/secureshop/hooks/useRegisteredAdminStream.js", "client/src/pages/secureshop/utils/registeredAdminChatReference.mjs", "client/src/pages/secureshop/utils/registeredAdminCompletedReference.mjs", "server/services/secureshopMcpImpersonationAssessment.js", "server/services/secureshopMcpImpersonationEvidence.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1397);assert.equal(current.recoveryFiles.length,1388);
 assert.equal(current.files['server/services/secureshopMcpImpersonationEvidence.js'],'ba3d8f3fa445c4d63f2bc81d8fe46e3dd37a1c39568cb653fe186f2ac461a1f5');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v171.json'))),'ca583ddc710cf8b34cee1221be9fb09a9875b09d71591de3d1e4e4e1635941d7');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v170 historical source binds exact registered admin own-turn trace provenance',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v169.json'),current=realRequire('./applicationMaintenanceInprocessSources-v170.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v169.json'))),'f29b2c73a6277008b5d468e201773db1d66e1297a6baf841520286cd4ce1bba8');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopRegisteredAdminRuntime.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1389);assert.equal(current.recoveryFiles.length,1380);
 assert.equal(current.files['server/services/secureshopRegisteredAdminRuntime.js'],'cf5d76ee3bb5a4fed9e3c1b9e2854f97c379ad92dc9fa9cbdd7cf3bbb94bef33');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v170.json'))),'ac21cf119677985b0c5359beb79e931e57ed3a9d5b35ac8b8601d14e5e957c07');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v169 historical source binds policy instruction assessment and qualified Listings package generations',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v168.json'),current=realRequire('./applicationMaintenanceInprocessSources-v169.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v168.json'))),'bb648966252370be933ea207e9733a161bb5653c34406b164b33bf7dbac3f0c2');
 const changed=["client/src/pages/secureshop/bridge/operations.mjs", "client/src/pages/secureshop/components/AdminSavedReads.jsx", "client/src/pages/secureshop/components/BoundRoleAssistant.jsx", "client/src/pages/secureshop/hooks/useBoundRoleAssistant.js", "scripts/install/secureshop-owned-listings-qualified-candidate.js", "server/config/secureshopCurriculum.js", "server/database/postgres/secureshopBoundPromptPolicyRepository.js", "server/routes/secureshop/boundRoleChat.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopBoundReviewComposition.js", "server/services/secureshopBoundRoleChat.js"],added=["scripts/install/manifests/owned-listings-arm64.candidate.json", "scripts/install/qualification/secureshop-listings-package-2026-10-10.json", "scripts/install/qualification/secureshop-listings-package-2026-10-12.json", "scripts/install/qualification/secureshop-listings-runtime-independent-review-2026-09-26.json", "server/services/secureshopPolicyInstructionAssessment.js", "server/services/secureshopPolicyInstructionEvidence.js", "tests/fixtures/secureshopOwnedListingsPackaged.native.cjs"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1389);assert.equal(current.recoveryFiles.length,1380);
 assert.equal(current.files['scripts/install/qualification/secureshop-listings-package-2026-10-12.json'],'2328d6bf0026b497f790cb53f485d8e5fdc1352af550fea46e87bc118c3c9937');
 assert.equal(current.files['scripts/install/qualification/secureshop-listings-package-2026-10-10.json'],'8549e769d30ea468ad83129a6118c77a2672348db0378a97ca1448fb7bea0330');
 assert.equal(current.files['scripts/install/qualification/secureshop-listings-runtime-independent-review-2026-09-26.json'],'269fae83100961c1c6149a2540b10453b9dc4ac30b7fa2772960c1e537ade59c');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v169.json'))),'f29b2c73a6277008b5d468e201773db1d66e1297a6baf841520286cd4ce1bba8');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v168 historical source binds saved assessment bridge and typed fixed XML denial with minimal worker closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v167.json'),current=realRequire('./applicationMaintenanceInprocessSources-v168.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v167.json'))),'0cf686b5e184aca9b718bf3371bf5c97b3f4935e2059ed89087f1a78170580b6');
 const changed=['client/src/pages/secureshop/bridge/operations.mjs','server/services/applicationMaintenanceInprocessAdmission.js'];
 const added=['import-executor.js','json-worker.js','namespace-executor.js','namespace-worker.js','resource-reader.js','xml-parser.js'].map(name=>'sidecars/sandbox-runner/owned-listings/'+name);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1382);assert.equal(current.recoveryFiles.length,1373);
 assert.equal(current.files['client/src/pages/secureshop/bridge/operations.mjs'],'df73aab35e68b31d4150bd380939f0ed6f28444ed35e78c1b226ada17f2318af');
 assert.equal(current.files['sidecars/sandbox-runner/owned-listings/namespace-worker.js'],'de3fdeaae4aa6945200fa7dd5983abbc8b1a81e912925de8a3bcc95a15f73ff5');
 assert.equal(current.files['sidecars/sandbox-runner/owned-listings/namespace-executor.js'],'7f4f14a7099d15a3cb4781d485415e70c66da3bd63f904766c2c113093e7f885');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v168.json'))),'bb648966252370be933ea207e9733a161bb5653c34406b164b33bf7dbac3f0c2');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v167 historical source binds compact guarded System evidence and visible mail subject controls',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v166.json'),current=realRequire('./applicationMaintenanceInprocessSources-v167.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v166.json'))),'bba6bdae5d80d5f11f48972c46556914ec2240ff45568a0de313734f5ff94ca9');
 const changed=['client/src/pages/secureshop/components/MerchantMailConfirmation.jsx','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopSystemConfigEvidence.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1376);assert.equal(current.recoveryFiles.length,1367);
 assert.equal(current.files['server/services/secureshopSystemConfigEvidence.js'],'38555127e97960b89c65f137ce210b7f8a62ba670670e6efe46ebf086588dca9');
 assert.equal(current.files['client/src/pages/secureshop/components/MerchantMailConfirmation.jsx'],'49cd70d19315bfffd918309b30170e87f9a495a2a963fee8dd09c81ce6259dd8');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v167.json'))),'0cf686b5e184aca9b718bf3371bf5c97b3f4935e2059ed89087f1a78170580b6');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v166 historical source binds nonrecursive Listings persona effect admission',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v165.json'),current=realRequire('./applicationMaintenanceInprocessSources-v166.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v165.json'))),'366d3ffe4f3055d13f513b1b3d028aa00efc0fb18dbd3d27d52a370690089e7e');
 const changed=['server/database/postgres/secureshopListingTemplateRepository.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1376);assert.equal(current.recoveryFiles.length,1367);
 assert.equal(current.files['server/database/postgres/secureshopListingTemplateRepository.js'],'91b7831a389bf51166642d16db35ccb47a8aeb121007219238f63e0b760db843');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v166.json'))),'bba6bdae5d80d5f11f48972c46556914ec2240ff45568a0de313734f5ff94ca9');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v165 historical source binds semantic System evidence and private Listings cause preservation',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v164.json'),current=realRequire('./applicationMaintenanceInprocessSources-v165.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v164.json'))),'f48f22e61fc66e3bbc34f3a199068565d2f2c2af7cedce8eaa67582c563f6e79');
 const changed=['server/database/postgres/secureshopListingTemplateRepository.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopSystemConfigEvidence.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1376);assert.equal(current.recoveryFiles.length,1367);
 assert.equal(current.files['server/services/secureshopSystemConfigEvidence.js'],'be8a98030b7193d8c9ed1e8da3a518aaca1a3bf0ee9cd060a652f2748c0f9fe4');
 assert.equal(current.files['server/database/postgres/secureshopListingTemplateRepository.js'],'4d3e069622321d4ffdd6a94e74386c242b217b1f54a6e2444a208e6ac4c2e78c');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v165.json'))),'366d3ffe4f3055d13f513b1b3d028aa00efc0fb18dbd3d27d52a370690089e7e');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v164 historical source binds completed-only role reference conflict recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v163.json'),current=realRequire('./applicationMaintenanceInprocessSources-v164.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v163.json'))),'085e1cc80e554023b5606282c994b786b3c23a7a5a9816b36434429a49e9df0b');
 const changed=['client/src/pages/secureshop/hooks/useBoundRoleAssistant.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1376);assert.equal(current.recoveryFiles.length,1367);
 assert.equal(current.files['client/src/pages/secureshop/hooks/useBoundRoleAssistant.js'],'018e86c24382a6f9753e65c17348ec0e9fa8205c587761ac5f6456c51bb05262');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v164.json'))),'f48f22e61fc66e3bbc34f3a199068565d2f2c2af7cedce8eaa67582c563f6e79');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v163 historical source binds System traversal assessment and fixed containment with exact closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v162.json'),current=realRequire('./applicationMaintenanceInprocessSources-v163.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v162.json'))),'3b34a4abea1a56bf10a59672949b9045379bd130ee2e030220027687042cabb4');
 const changed=["client/src/pages/secureshop/components/BoundRoleAssistant.jsx", "client/src/pages/secureshop/hooks/useBoundRoleAssistant.js", "server/config/secureshopCurriculum.js", "server/database/postgres/secureshopSystemConfigReadRepository.js", "server/routes/secureshop/boundRoleChat.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopAssessmentRecovery.js", "server/services/secureshopBoundReviewComposition.js", "server/services/secureshopBoundRoleChat.js", "server/services/secureshopBoundSystemConfigReadService.js", "server/services/secureshopFeatureModeAuthority.js", "server/services/secureshopRoleSystemReads.js", "server/services/secureshopSystemConfigComposition.js"],added=["client/src/pages/secureshop/bridge/assessmentPanelIntent.mjs", "client/src/pages/secureshop/components/AdminSavedReads.jsx", "server/services/secureshopSystemConfigAssessment.js", "server/services/secureshopSystemConfigEvidence.js", "server/services/secureshopSystemConfigExecution.js", "sidecars/sandbox-runner/owned-system/executor.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1376);assert.equal(current.recoveryFiles.length,1367);
 assert.equal(current.files['server/services/secureshopSystemConfigAssessment.js'],'b9902798ef705caf67028d055f2f60e9095571b7d5ca4e79fe2aa949fd13200e');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v163.json'))),'085e1cc80e554023b5606282c994b786b3c23a7a5a9816b36434429a49e9df0b');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v162 historical source preserves private recoverable external denial through persona dispatch',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v161.json'),current=realRequire('./applicationMaintenanceInprocessSources-v162.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v161.json'))),'d9a7da279ce1b813a41b3f9afe178e37e4de1890325e57491a60cc79ea9a19d0');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopPersonaToolDispatch.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1370);assert.equal(current.recoveryFiles.length,1361);
 assert.equal(current.files['server/services/secureshopPersonaToolDispatch.js'],'209506c1fe55cf08c727a64280314a740deea823b831ab1704546c73cecae91a');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v162.json'))),'3b34a4abea1a56bf10a59672949b9045379bd130ee2e030220027687042cabb4');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of changed)rejectsSimulatedSourceDrift(name);
});

test('v161 historical source binds policy execution and replay integration with exact reviewed closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v160.json'),current=realRequire('./applicationMaintenanceInprocessSources-v161.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v160.json'))),'472142e38b46b89af5db83e220eee1f4af0609503214606a38d79493f9aec953');
 const changed=["client/src/pages/secureshop/components/BoundAgentLane.jsx","scripts/setup-application.js","server/config/secureshopCurriculum.js","server/database/postgres/secureshopBoundConversationsRepository.js","server/database/postgres/secureshopBoundPromptPolicyRepository.js","server/database/postgres/secureshopTurnRequestsRepository.js","server/routes/secureshop/boundGateway.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentRecovery.js","server/services/secureshopBoundAgentRunner.js","server/services/secureshopBoundPolicyChat.js","server/services/secureshopBoundPromptPolicyService.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundRoleChat.js","server/services/secureshopFeatureModeAuthority.js","server/services/secureshopMcpTrustBoundRunner.js","server/services/secureshopMcpTrustProduction.js","server/services/secureshopPolicySandboxRuntime.js","server/services/secureshopPricingEvidence.js","server/services/secureshopPromptPolicyContract.js","sidecars/sandbox-runner/policy-render/executor.js","sidecars/sandbox-runner/policy-render/http-handler.js","sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract.js"];
 const added=["client/src/pages/secureshop/components/AdminPolicyConfirmation.jsx","client/src/pages/secureshop/components/MerchantReviewChat.jsx","client/src/pages/secureshop/components/PageTransition.jsx","client/src/pages/secureshop/context/ToastContext.jsx","client/src/pages/secureshop/pages/admin/Policies.jsx","client/src/pages/secureshop/pages/admin/policyOperation.js","client/src/pages/secureshop/utils/manualReviewOperation.mjs","server/services/secureshopPolicyTemplateAssessment.js","server/services/secureshopPolicyTemplateEvidence.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1370);assert.equal(current.recoveryFiles.length,1361);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v161.json'))),'d9a7da279ce1b813a41b3f9afe178e37e4de1890325e57491a60cc79ea9a19d0');
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v160 historical source binds failed readiness response cancellation',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v159.json'),current=realRequire('./applicationMaintenanceInprocessSources-v160.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v159.json'))),'9ac910da97d976bded6b8b41a8a8c46cf31705a821e55c26798934fe55e3ae34');
 const changed=['client/src/pages/secureshop/components/MerchantMailConfirmation.jsx','client/src/pages/secureshop/components/MerchantPricingConfirmation.jsx','server/services/applicationMaintenanceInprocessAdmission.js'];
 const added=['client/src/pages/secureshop/components/MerchantInventoryConfirmation.jsx'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1361);assert.equal(current.recoveryFiles.length,1352);
 assert.equal(current.files['client/src/pages/secureshop/pages/merchant/useBoundListings.js'],'ed026b5dc1527396fca0016a0304e96cab6e4b7a4dcbb3c2c0cbb7a7ef097acf');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v160.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of [...changed,...added,'client/src/pages/secureshop/pages/merchant/useBoundListings.js'])rejectsSimulatedSourceDrift(name);
});

test('v159 historical intermediate preserves exact Listings hook capture',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v158.json'),current=realRequire('./applicationMaintenanceInprocessSources-v159.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v158.json'))),'7a6ea0e3c6dff50a093fec3c356c8518291137829bcf23c6801d16c2ca8d9ca3');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),['client/src/pages/secureshop/pages/merchant/useBoundListings.js','server/services/applicationMaintenanceInprocessAdmission.js']);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 denied(()=>bindingWith({},current)(ROOT));
});

test('v158 historical source binds the frozen PostgreSQL provision-pool repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v157.json'),current=realRequire('./applicationMaintenanceInprocessSources-v158.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v157.json'))),'7ad9c4efa4e6b0af2263ac0443b0d2ea590c0e0a1876c731d77381942348f4f7');
 const changed=['server/database/postgres/poolBudget.js','server/database/postgres/secureshopSceneRepository.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopCleanupComposition.js'];
 const added=[];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1360);assert.equal(current.recoveryFiles.length,1351);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v158.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v155 historical source binds retained target birth for saved rewrite reads',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v154.json'),current=realRequire('./applicationMaintenanceInprocessSources-v155.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v154.json'))),'ea5c6f776f8b535de3e814a6012eb830a787e63be11ee24f0d8f204ba6729e5d');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),['server/database/postgres/secureshopListingRewriteSaveRepository.js','server/services/applicationMaintenanceInprocessAdmission.js']);
 denied(()=>bindingWith({},current)(ROOT));
 rejectsSimulatedSourceDrift('server/database/postgres/secureshopListingRewriteSaveRepository.js');
});

test('v153 historical source binds Listings chat setup and source-specific recovery',()=>{
 const current=realRequire('./applicationMaintenanceInprocessSources-v153.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v152.json'))),'8e09f0da71a3480e677ee64adafa059ec7e1d097e1270f2264711dd714719ec4');
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of ['server/services/secureshopRoleListingActionSetup.js','client/src/pages/secureshop/components/MerchantListingsSetup.jsx','client/src/pages/secureshop/pages/merchant/Listings.jsx','db/postgres/workshop-migrations/secureshop_agents/0085_merchant_listing_setup_registry_successor.sql'])rejectsSimulatedSourceDrift(name);
});

test('v152 historical successor binds frozen mail hydration and cart recovery fixes',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v151.json'),current=realRequire('./applicationMaintenanceInprocessSources-v152.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v151.json'))),'247db9df6278dffb78eb5555cc300e8c7cf7e9d6a2910ca8c29668be6637afd2');
 const changed=['client/src/pages/secureshop/components/MerchantMailConfirmation.jsx','server/services/applicationMaintenanceInprocessAdmission.js'];
 const added=['client/src/pages/secureshop/context/CartContext.jsx','client/src/pages/secureshop/pages/Cart.jsx'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added.slice().sort());
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1349);assert.equal(current.recoveryFiles.length,1345);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v152.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});

test('v148 historical successor preserves V54 blocked-turn readback repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v147.json'),current=realRequire('./applicationMaintenanceInprocessSources-v148.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v147.json'))),'e6938bc663d5e85ac253c19fe7580ca28fc3a3ec838143eb294cb23322d2f7d3');
 const changed=['server/database/postgres/secureshopPricingRepository.js','server/database/postgres/secureshopTurnModeProjection.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1337);assert.equal(current.recoveryFiles.length,1335);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v148.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},current)(ROOT));denied(()=>bindingWith({},previous)(ROOT));
});

test('v124 current main successor binds the reviewed customer, audit, system, and ACL closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v123.json'),current=realRequire('./applicationMaintenanceInprocessSources-v124.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v123.json'))),'0a9c266c6085822431d134e1643b646a2d741bc5677ca730a194c0f55ec8bbe6');
 const changed=['server/database/postgres/secureshopBoundToolPolicyReadiness.js','server/database/postgres/secureshopConversationalCommerceRepository.js','server/routes/secureshop/boundRoleChat.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundCustomerCommerceTools.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopBoundRoleChat.js','server/services/secureshopConversationalCommerceContract.js'];
 const added=['db/postgres/workshop-migrations/secureshop_agents/0075_admin_audit_system_read_registry_successor.sql','server/services/secureshopBoundAuditChat.js','server/services/secureshopRoleSystemReads.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1276);assert.equal(current.recoveryFiles.length,1274);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v124.json'))),digest(Buffer.from(JSON.stringify(current))));
 assert.equal(digest(Buffer.from(JSON.stringify(current))),digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v124.json'))));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});
test('v123 historical main successor binds the successful audit read terminal boundary',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v122.json'),current=realRequire('./applicationMaintenanceInprocessSources-v123.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v122.json'))),'f19ae3eac59146be25462a64c1cfe241c74b233c2a17361910203da0d1ac1eb1');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundRoleChat.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1273);assert.equal(current.recoveryFiles.length,1271);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v123.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},previous)(ROOT));for(const name of changed)rejectsSimulatedSourceDrift(name);
});
test('v122 historical main successor binds the reviewed audit read adapters and role filters',()=>{

 const previous=realRequire('./applicationMaintenanceInprocessSources-v121.json'),current=realRequire('./applicationMaintenanceInprocessSources-v122.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v121.json'))),'b868450f5c39de5a36abb38a45af74ae29253e71b01f9cab07d486741b36fdbc');
 const changed=['server/database/postgres/secureshopAuditManualRepository.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundRoleChat.js','server/services/secureshopBoundSystemConfigReadService.js','server/services/secureshopOwnedAuditManualAdapter.js','server/services/secureshopOwnedAuditSearchApplication.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1273);assert.equal(current.recoveryFiles.length,1271);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v122.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},current)(ROOT));denied(()=>bindingWith({},previous)(ROOT));
});
test('v121 historical main successor binds only the reviewed explicit order-details repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v120.json'),current=realRequire('./applicationMaintenanceInprocessSources-v121.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v120.json'))),'5192876a344525b23cd208733a2e733396de8ca930a9d3636079d9b0fa21d099');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1273);assert.equal(current.recoveryFiles.length,1271);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v121.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},current)(ROOT));denied(()=>bindingWith({},previous)(ROOT));
});
test('v117 historical main successor binds frozen MCP-registry backend without frontend drift',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v116.json'),current=realRequire('./applicationMaintenanceInprocessSources-v117.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v116.json'))),'91d9754b6cfc933c3be6a85d6b43b1ded0ad913ef2b52c88c8779c7a26a93a0a');
 const changed=['server/database/postgres/secureshopBoundToolPolicyReadiness.js','server/database/postgres/secureshopTurnRequestsRepository.js','server/routes/secureshop/boundAdminChat.js','server/routes/secureshop/boundRoleChat.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundAdmin.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopBoundRoleChat.js','server/services/secureshopOwnedMcpRegistryAdminReadOverlay.js','server/services/secureshopRegisteredAdminRuntime.js','server/services/secureshopRegisteredInvocationProduction.js'];
 const added=['db/postgres/workshop-migrations/secureshop_agents/0074_admin_mcp_registry_successor.sql','server/services/secureshopBoundMcpRegistryChat.js','server/services/secureshopRoleMcpRegistryProposal.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1272);assert.equal(current.recoveryFiles.length,1270);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v117.json'))),digest(Buffer.from(JSON.stringify(current))));
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v117.json'))),digest(Buffer.from(JSON.stringify(current))));
});
test('v116 historical main successor binds frozen policy-chat backend without frontend drift',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v115.json'),current=realRequire('./applicationMaintenanceInprocessSources-v116.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v115.json'))),'c3c78fd5088b8a649ca7c29d5c8d914a8197c25bf9d49757896cb7208e5c538c');
 const changed=['server/database/postgres/secureshopBoundToolPolicyReadiness.js','server/routes/secureshop/boundPromptPolicies.js','server/routes/secureshop/boundRoleChat.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopBoundRoleChat.js'];
 const added=['db/postgres/workshop-migrations/secureshop_agents/0073_admin_policy_registry_successor.sql','server/services/secureshopBoundPolicyChat.js','server/services/secureshopRolePolicyProposal.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1269);assert.equal(current.recoveryFiles.length,1267);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v116.json'))),digest(Buffer.from(JSON.stringify(current))));
});
test('v115 historical main successor binds protected password reset handoff and readiness',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v114.json'),current=realRequire('./applicationMaintenanceInprocessSources-v115.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v114.json'))),'3bc2f73d0675887d135cb4733df00937945fd836719e69612965135fe77671fe');
 const changed=['server/database/postgres/secureshopBoundToolPolicyReadiness.js','server/routes/secureshop/boundRoleChat.js','server/routes/secureshop/boundUserAdministration.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundRoleChat.js','server/services/secureshopBoundUserAdministration.js'];
 const added=['db/postgres/workshop-migrations/secureshop_agents/0072_admin_password_reset_setup_registry_successor.sql'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1266);assert.equal(current.recoveryFiles.length,1264);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v115.json'))),digest(Buffer.from(JSON.stringify(current))));
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});
test('v114 historical main successor binds only the scoped role tool wire contract',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v113.json'),current=realRequire('./applicationMaintenanceInprocessSources-v114.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v113.json'))),'4f53d7625f2a39a7ddbb6b101f588bc41160b319ac97c620f3fe7724174444b0');
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopBoundRoleChat.js"]);
 denied(()=>bindingWith({},previous)(ROOT));rejectsSimulatedSourceDrift('server/services/secureshopBoundRoleChat.js');
});
test('v113 historical main successor binds the exact administrator read terminal repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v112.json'),current=realRequire('./applicationMaintenanceInprocessSources-v113.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v112.json'))),'2b3fb7e50d4b67f6270813cb37d613bd3afddd012de1b03afccd42ed2e00df8f');
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopBoundRoleChat.js"]);
 denied(()=>bindingWith({},previous)(ROOT));rejectsSimulatedSourceDrift('server/services/secureshopBoundRoleChat.js');
});
test('v112 historical main successor binds reviewed administrator proposals and ACL admission',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v111.json'),current=realRequire('./applicationMaintenanceInprocessSources-v112.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v111.json'))),'75a74105dc1ccaf8d22a89c446376367bc94ee719a80a726b04ecf2006d56c4d');
 const changed=["server/database/postgres/secureshopBoundToolPolicyReadiness.js","server/routes/secureshop/boundRoleChat.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopBoundAclRegistry.js","server/services/secureshopBoundAdmin.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundRoleChat.js","server/services/secureshopBoundUserAdministration.js"],added=["db/postgres/workshop-migrations/secureshop_agents/0071_admin_user_prepare_registry_successor.sql","server/services/secureshopRoleUserAdministrationProposal.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1265);assert.equal(current.recoveryFiles.length,1263);
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of [...changed.slice(0,2),...changed.slice(3),...added])rejectsSimulatedSourceDrift(name);
});
test('v111 historical main successor admits only the reviewed Q26 terminal-read repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v110.json'); const current=realRequire('./applicationMaintenanceInprocessSources-v111.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex'); assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v110.json'))),'4a3b7542f96fb45861cb081b69ab3b6a53e93ecd36e328f2baf204c89072c4da');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js']; const added=[];
 assert.equal(current.version,previous.version);assert.equal(current.profile,previous.profile);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1263);assert.equal(current.recoveryFiles.length,1261);
 assert.deepEqual(Object.keys(current.files).filter(name=>!current.recoveryFiles.includes(name)).sort(),['scripts/deploy-fresh.js','scripts/setup-application.js']);
 denied(()=>bindingWith({},previous)(ROOT));rejectsSimulatedSourceDrift(changed[1]);
});
test('v92 historical main successor preserves its reviewed optional draft adapter',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v91.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v92.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v91.json'))),'6b30fd0419509c2dee7e264fbf10c87afa6634cc6f09862e8a3a82f21b2c2ae1');
 assert.equal(current.version,previous.version);assert.equal(current.profile,previous.profile);
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1252);assert.equal(current.recoveryFiles.length,1250);
 assert.deepEqual(Object.keys(current.files).filter(name=>!current.recoveryFiles.includes(name)).sort(),['scripts/deploy-fresh.js','scripts/setup-application.js']);
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of changed.slice(1))rejectsSimulatedSourceDrift(name);
});
test('v91 historical main successor preserves its reviewed split address tools',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v90.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v91.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v90.json'))),'dcec65c11ddb0f87dfbbda99a54f6e63d2409458a054f8230c9711222966fba3');
 assert.equal(current.version,previous.version);assert.equal(current.profile,previous.profile);
 const changed=['server/database/postgres/secureshopBoundToolPolicyReadiness.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js'];
 const added=['db/postgres/workshop-migrations/secureshop_agents/0065_address_edit_setup_registry_successor.sql'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1252);assert.equal(current.recoveryFiles.length,1250);
 assert.deepEqual(Object.keys(current.files).filter(name=>!current.recoveryFiles.includes(name)).sort(),['scripts/deploy-fresh.js','scripts/setup-application.js']);
 denied(()=>bindingWith({},previous)(ROOT));
 rejectsSimulatedSourceDrift(added[0]);
});
test('v90 historical main successor preserves its reviewed selected-address gate',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v89.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v90.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v89.json'))),'e3d8dbef3366db9dbf204699a8dfdd158683f44f4d671b0c9ceb186492b39845');
 assert.equal(current.version,previous.version);assert.equal(current.profile,previous.profile);
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundCustomerCommerceTools.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1251);assert.equal(current.recoveryFiles.length,1249);
 assert.deepEqual(Object.keys(current.files).filter(name=>!current.recoveryFiles.includes(name)).sort(),['scripts/deploy-fresh.js','scripts/setup-application.js']);
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of changed.slice(1))rejectsSimulatedSourceDrift(name);
});
test('v89 historical main successor preserves its reviewed Q17 delta',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v88.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v89.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v88.json'))),'9e0962e0ca10d57543162218f2bf4fb4fedd106b37c29e63ab6929175be40fcd');
 assert.equal(current.version,previous.version);assert.equal(current.profile,previous.profile);
 const changed=[
  'server/database/postgres/secureshopBoundAccountRepository.js',
  'server/database/postgres/secureshopBoundCommerceRepository.js',
  'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
  'server/database/postgres/secureshopConversationalCommerceRepository.js',
  'server/routes/secureshop/boundGateway.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundAclRegistry.js',
  'server/services/secureshopBoundCommerce.js',
  'server/services/secureshopBoundCustomerChat.js',
  'server/services/secureshopBoundCustomerCommerceTools.js',
  'server/services/secureshopConversationalCommerce.js',
 ];
 const added=[
  'db/postgres/workshop-migrations/secureshop_agents/0064_address_setup_registry_successor.sql',
  'db/postgres/workshop-migrations/secureshop_review/0045_customer_address_receipts.sql',
  'server/services/secureshopAddressSetupContract.js',
 ];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1251);assert.equal(current.recoveryFiles.length,1249);
 assert.deepEqual(Object.keys(current.files).filter(name=>!current.recoveryFiles.includes(name)).sort(),['scripts/deploy-fresh.js','scripts/setup-application.js']);
 denied(()=>bindingWith({},previous)(ROOT));
 for(const name of added)rejectsSimulatedSourceDrift(name);
});
test('v88 historical main successor preserves its reviewed Q19 delta',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v87.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v88.json');
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v87.json'))),'b335e1e3c2ee2ae6e25c253406088d35399d64a819ead80cb7dcfcc0a945ea48');
 assert.equal(current.version,previous.version);assert.equal(current.profile,previous.profile);
 const changed=[
  'scripts/install/setup-database-phase.js',
  'scripts/setup-application.js',
  'scripts/start-application.js',
  'server/agent-runtime/secureshopSupervisorGraph.js',
  'server/applicationServer.js',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/secureshopAuditManualRepository.js',
  'server/database/postgres/secureshopAuditQueryRepository.js',
  'server/database/postgres/secureshopAuditTargetAdmissionRepository.js',
  'server/database/postgres/secureshopBoundAclRepository.js',
  'server/database/postgres/secureshopBoundCommerceRepository.js',
  'server/database/postgres/secureshopBoundCouponRepository.js',
  'server/database/postgres/secureshopBoundProductRepository.js',
  'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
  'server/database/postgres/secureshopInventoryHistoryRepository.js',
  'server/database/postgres/secureshopInventoryRecoveryRepository.js',
  'server/database/postgres/secureshopPricingReadiness.js',
  'server/database/postgres/secureshopPricingRepository.js',
  'server/database/postgres/secureshopRegisteredAdminResetRepository.js',
  'server/database/postgres/secureshopSceneRepository.js',
  'server/database/postgres/secureshopStandaloneAuthRepository.js',
  'server/database/postgres/secureshopTurnRequestsRepository.js',
  'server/routes/secureshop/boundGateway.js',
  'server/routes/secureshop/boundInventory.js',
  'server/routes/secureshop/boundListings.js',
  'server/routes/secureshop/boundPricing.js',
  'server/routes/secureshopStandaloneAuth.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshop/providerRouter.js',
  'server/services/secureshop/providers/langchainAdapter.js',
  'server/services/secureshop/providers/ollamaProvider.js',
  'server/services/secureshopBoundAclRegistry.js',
  'server/services/secureshopBoundAgentRunner.js',
  'server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundCatalog.js',
  'server/services/secureshopBoundCommerce.js',
  'server/services/secureshopBoundInventoryGraph.js',
  'server/services/secureshopBoundPricingTools.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopConversationPurpose.js',
  'server/services/secureshopFeatureModeAuthority.js',
  'server/services/secureshopInventoryGradingReadback.js',
  'server/services/secureshopInventoryProduction.js',
  'server/services/secureshopListingsProduction.js',
  'server/services/secureshopPersonaProductEffect.js',
  'server/services/secureshopPricingComposition.js',
  'server/services/secureshopPricingContract.js',
  'server/services/secureshopPricingEvidence.js',
  'server/services/secureshopPricingExecutionConfig.js',
  'server/services/secureshopPricingProduction.js',
  'server/services/secureshopPricingReceipt.js',
  'server/services/secureshopPricingTargetSource.js',
 ];
 const added=[
  'db/postgres/identity-migrations/0150_secureshop_practice_admission.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0055_listing_template_conversation_purpose.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0056_customer_chat_turn_binding.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0057_pricing_experiment_request_v2.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0058_role_chat_turn_binding.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0059_bound_tool_registry_successor.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0060_inventory_prepare_registry_successor.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0061_pricing_prepare_registry_successor.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0062_listing_edit_prepare_registry_successor.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0063_listing_create_prepare_registry_successor.sql',
  'db/postgres/workshop-migrations/secureshop_review/0038_owned_listing_template_execution.sql',
  'db/postgres/workshop-migrations/secureshop_review/0039_owned_listing_template_completed_receipt.sql',
  'db/postgres/workshop-migrations/secureshop_review/0040_owned_product_price_history.sql',
  'db/postgres/workshop-migrations/secureshop_review/0041_conversational_commerce.sql',
  'db/postgres/workshop-migrations/secureshop_review/0042_cart_confirmation_proposals.sql',
  'db/postgres/workshop-migrations/secureshop_review/0043_owned_merchant_listing_edits.sql',
  'db/postgres/workshop-migrations/secureshop_review/0044_owned_merchant_listing_creates.sql',
  'scripts/install/secureshop-owned-listing-template.js',
  'scripts/lib/setup-child-ownership.js',
  'server/database/postgres/secureshopConversationalCommerceRepository.js',
  'server/database/postgres/secureshopCustomerChatBindingRepository.js',
  'server/database/postgres/secureshopListingTemplateRepository.js',
  'server/database/postgres/secureshopPracticeAdmissionRepository.js',
  'server/database/postgres/secureshopPricingHistoryRepository.js',
  'server/database/postgres/secureshopRegisteredUserAdministrationRepository.js',
  'server/database/postgres/secureshopRoleChatBindingRepository.js',
  'server/routes/secureshop/boundAccessControl.js',
  'server/routes/secureshop/boundCustomerChat.js',
  'server/routes/secureshop/boundPromptPolicies.js',
  'server/routes/secureshop/boundRoleChat.js',
  'server/routes/secureshop/boundUserAdministration.js',
  'server/routes/secureshopPlatformLaunch.js',
  'server/routes/secureshopRuntimeReadiness.js',
  'server/services/secureshopBoundCustomerChat.js',
  'server/services/secureshopBoundCustomerCommerceTools.js',
  'server/services/secureshopBoundRoleChat.js',
  'server/services/secureshopConversationalCommerce.js',
  'server/services/secureshopConversationalCommerceContract.js',
  'server/services/secureshopInventoryTaskContract.js',
  'server/services/secureshopListingCreateContract.js',
  'server/services/secureshopListingEditContract.js',
  'server/services/secureshopListingTemplateActivation.js',
  'server/services/secureshopListingTemplateAssessment.js',
  'server/services/secureshopListingTemplateClient.js',
  'server/services/secureshopListingTemplateContract.js',
  'server/services/secureshopListingTemplateExecutorContract.js',
  'server/services/secureshopListingTemplateManagedConfiguration.js',
  'server/services/secureshopListingTemplateWorkflow.js',
  'server/services/secureshopPracticeAdmission.js',
  'server/services/secureshopRoleInventoryProposal.js',
  'server/services/secureshopRoleListingCreateProposal.js',
  'server/services/secureshopRoleListingProposal.js',
  'server/services/secureshopRolePricingProposal.js',
  'server/services/sessionLifetimeConfiguration.js',
  'sidecars/sandbox-runner/listing-template/Dockerfile',
  'sidecars/sandbox-runner/listing-template/Dockerfile.dockerignore',
  'sidecars/sandbox-runner/listing-template/executor.js',
  'sidecars/sandbox-runner/listing-template/http-handler.js',
  'sidecars/sandbox-runner/listing-template/listener.js',
  'sidecars/sandbox-runner/listing-template/secureshopListingTemplateExecutorContract.js',
  'sidecars/sandbox-runner/listing-template/strict-helpers.js',
  'sidecars/sandbox-runner/listing-template/template-init.c',
  'sidecars/sandbox-runner/listing-template/worker.js',
 ];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1248);assert.equal(current.recoveryFiles.length,1246);
 assert.deepEqual(Object.keys(current.files).filter(name=>!current.recoveryFiles.includes(name)).sort(),['scripts/deploy-fresh.js','scripts/setup-application.js']);
 for(const name of ['db/postgres/identity-migrations/0150_secureshop_practice_admission.sql',
   'server/services/secureshopBoundCustomerChat.js','sidecars/sandbox-runner/listing-template/listener.js'])rejectsSimulatedSourceDrift(name);
});
test('v87 historical successor preserves its exact delta',()=>{
 const manifest=realRequire('./applicationMaintenanceInprocessSources-v87.json');
 const previous=realRequire('./applicationMaintenanceInprocessSources-v86.json');
 assert.equal(manifest.profile,previous.profile);assert.equal(manifest.version,previous.version);
  const changed=[
  'package-lock.json',
  'package.json',
  'scripts/install/secureshop-owned-listings-provision.js',
  'scripts/install/secureshop-owned-listings-qualified-candidate.js',
  'scripts/install/secureshop-owned-listings.js',
  'scripts/setup-application.js',
  'scripts/start-application.js',
  'server/applicationServer.js',
  'server/database/postgres/secureshopBoundPersonaRepository.js',
  'server/database/postgres/secureshopBoundUserAdministrationRepository.js',
  'server/database/postgres/secureshopRegisteredAdminResetRepository.js',
  'server/database/postgres/secureshopStandaloneAuthRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/postgresIdentityAdapter.js',
  'server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopBoundUserAdministration.js',
  'server/services/secureshopListingsRuntime.js',
  'server/services/secureshopStandaloneAuth.js',
  'server/services/secureshopStandaloneReset.js'
 ];
 const added=['db/postgres/identity-migrations/0148_secureshop_tenant_administration.sql',
  'db/postgres/identity-migrations/0149_secureshop_admin_operation_kinds.sql'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==manifest.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(manifest.files).filter(name=>!Object.hasOwn(previous.files,name)),added);
 assert.deepEqual(manifest.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(manifest.files).length,1185);assert.equal(manifest.recoveryFiles.length,1183);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v86.json'))).digest('hex'),'f2b272974ce00677d8198fb1d929c21f0b09029cfc7aaf085faae89cc9abe8d3');
 for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
});
function rejectsSimulatedSourceDrift(relativePath){
 const target=path.join(ROOT,relativePath);let altered=false;
 denied(()=>bindingWith({readFileSync(filename,...args){const bytes=fs.readFileSync(filename,...args);if(filename===target){altered=true;return Buffer.concat([bytes,Buffer.from('\n// simulated drift')]);}return bytes;}})(ROOT));assert.equal(altered,true);
}
test('Windows private-state JavaScript and native helper drift deny',()=>{
 for(const name of ['scripts/lib/windows-private-state.js','scripts/windows/windows-private-state.ps1','scripts/windows/windows-private-state.cs'])rejectsSimulatedSourceDrift(name);
});
test('Windows workspace and process identity dependency drift deny',()=>{
 for(const name of ['scripts/lib/application-maintenance-installation.js','scripts/lib/setup-local-process-identity.js','scripts/lib/windows-process-identity.js','scripts/windows/windows-process-identity.ps1','scripts/windows/windows-process-identity.cs'])rejectsSimulatedSourceDrift(name);
});
test('maintenance Windows private configuration and store readers reject source drift',()=>{
 for(const name of ['scripts/lib/application-maintenance-plan-configuration.js','server/database/postgres/applicationMaintenanceStoreInspection.js'])rejectsSimulatedSourceDrift(name);
});
test('explicit maintenance workspace and private journal caller drift denies',()=>{
 for(const name of ['scripts/application-journal-bound-maintenance.js','scripts/application-maintenance-recovery.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/applicationMaintenanceInprocessWorkflow.js','server/services/applicationMaintenanceDirtyProfile.js'])rejectsSimulatedSourceDrift(name);
});
// The finite added closure includes previously unbound imports reached by the
// protected provisioners and their reused modules, plus reviewed COPY inputs.
test('v44 successor binds the exact default Windows setup startup base Audit and wrapper graph',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v43.json'),current=realRequire('./applicationMaintenanceInprocessSources-v44.json');
 const changed=[
  "scripts/install/Windows/host-preflight.ps1",
  "scripts/install/mcp-owned-http.js",
  "scripts/install/mcp-owned-provision.js",
  "scripts/install/mcp-owned-shadow.js",
  "scripts/lib/windows-host-preflight.js",
  "scripts/lib/windows-lab-forward-owner.js",
  "scripts/lib/windows-owned-lab.js",
  "scripts/local-docker-authority.js",
  "scripts/setup-application.js",
  "scripts/start-application.js",
  "server/services/applicationMaintenanceInprocessAdmission.js",
  "server/services/secureshopOwnedAuditProduction.js",
  "sidecars/audit-sql-target/main.js"
];
 const added=[
  "scripts/install/Windows/dependencies.ps1",
  "scripts/install/Windows/dependency-plan.ps1",
  "scripts/install/Windows/install-windows.ps1",
  "scripts/install/Windows/packages.ps1",
  "scripts/install/Windows/prerequisites.ps1",
  "scripts/install/Windows/start_all.ps1",
  "scripts/install/Windows/wrapper-handoff.ps1",
  "scripts/install/audit-sql-activate.js",
  "scripts/install/audit-sql-target.js",
  "scripts/install/windows-base-lab-services.js",
  "scripts/lib/audit-sql-private-state.js",
  "sidecars/audit-sql-target/bootstrap.js",
  "sidecars/audit-sql-target/migrations/0002_query_receipts.sql",
  "sidecars/audit-sql-target/migrations/0003_query_destruction_tombstones.sql",
  "sidecars/audit-sql-target/schema.sql",
  "sidecars/rogue-mcp/Dockerfile",
  "sidecars/rogue-mcp/index.js",
  "sidecars/ssrf-target/Dockerfile",
  "sidecars/ssrf-target/index.js"
];
 assert.equal(createHash('sha256').update(JSON.stringify(previous)).digest('hex'),'17cef1db11e743d5a7a0841230badc86d408463a8dae52a8e6ef41345bc57788');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v43.json'))).digest('hex'),'08f839748c226f6129fdfbf70f2e9ce6486522dc5bfdbf7f21e45d5f5371b23b');
 assert.equal(createHash('sha256').update(JSON.stringify(current)).digest('hex'),'c1ccda30c55b0e9090537cb6d8979947f59da2cb8b88312cde723ce75472adbd');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v44.json'))).digest('hex'),'1149d3c77cbd02e23466ab287b613b0d62224ee85aafd5bb318299c51f84d9b1');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1080);assert.equal(current.recoveryFiles.length,1078);
 assert.deepEqual(Object.keys(current.files).filter(name=>!current.recoveryFiles.includes(name)),['scripts/deploy-fresh.js','scripts/setup-application.js']);
 for(const name of ["sidecars/sandbox-runner/labfs/opt/app/config/.env","sidecars/sandbox-runner/labfs/var/secrets/credentials.json","sidecars/sandbox-runner/labfs/var/secrets/master_key.txt"]){assert.equal(Object.hasOwn(current.files,name),false);assert.equal(current.recoveryFiles.includes(name),false);}
});
test('v45 successor binds only the reviewed SecureShop surface-separation sources and admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v44.json'),current=realRequire('./applicationMaintenanceInprocessSources-v45.json');
 const changed=[
  'server/config/workshopCatalog.js',
  'server/database/postgres/workshopProgressRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js'
 ];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1080);assert.equal(current.recoveryFiles.length,1078);
 for(const name of changed.filter(name=>name!=='server/services/applicationMaintenanceInprocessAdmission.js'))assert.equal(current.files[name],createHash('sha256').update(fs.readFileSync(path.join(ROOT,name))).digest('hex'));
});
test('v46 successor binds only browser retirement and the admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v45.json'),current=realRequire('./applicationMaintenanceInprocessSources-v46.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/xssBrowserQualification.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).sort(),Object.keys(previous.files).sort());
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
});
test('v47 successor binds only bounded browser startup and the admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v46.json'),current=realRequire('./applicationMaintenanceInprocessSources-v47.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/xssBrowserQualification.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).sort(),Object.keys(previous.files).sort());
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
});
test('v48 successor binds only terminal shop session diagnostics and the admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v47.json'),current=realRequire('./applicationMaintenanceInprocessSources-v48.json');
 const changed=['server/database/postgres/secureshopLaunchRepository.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).sort(),Object.keys(previous.files).sort());
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v48.json'))).digest('hex'),'1e50be24ce4de1b4089a27eb5652e952220787a28f753abbbb90f022690c03f7');
});
test('v43 historical successor preserves its exact owned Windows lab and protected service closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v42.json'),current=realRequire('./applicationMaintenanceInprocessSources-v43.json');
 const changed=[
  "scripts/local-docker-authority.js",
  "scripts/local-mailpit.js",
  "scripts/setup-application.js",
  "server/services/applicationMaintenanceInprocessAdmission.js",
  "server/services/mcp/ownedManagedConfiguration.js"
];
 const added=[
  "docker-compose.yml",
  "scripts/install/Windows/owned-hyperv-observer.ps1",
  "scripts/install/mcp-owned-http-activate.js",
  "scripts/install/mcp-owned-http-setup.js",
  "scripts/install/mcp-owned-http.js",
  "scripts/install/mcp-owned-local.js",
  "scripts/install/mcp-owned-provision.js",
  "scripts/install/mcp-owned-service-build-context.js",
  "scripts/install/mcp-owned-service-retry-environment.js",
  "scripts/install/mcp-owned-shadow-activate.js",
  "scripts/install/mcp-owned-shadow-setup.js",
  "scripts/install/mcp-owned-shadow.js",
  "scripts/install/secureshop-owned-listings-provision.js",
  "scripts/install/secureshop-owned-listings-qualified-candidate.js",
  "scripts/install/secureshop-owned-listings.js",
  "scripts/install/secureshop-owned-system-provision.js",
  "scripts/install/secureshop-owned-system.js",
  "scripts/lib/windows-lab-forward-owner.js",
  "scripts/lib/windows-lab-installation.js",
  "scripts/lib/windows-owned-hyperv-observer.js",
  "scripts/lib/windows-owned-lab.js",
  "scripts/render-mcp-sandbox-apparmor.js",
  "server/agent-runtime/codeBotRequestJournal.js",
  "server/agent-runtime/dpiAnswerAudit.js",
  "server/agent-runtime/dpiContentWitnessAudit.js",
  "server/agent-runtime/dpiContentWitnessV12Audit.js",
  "server/agent-runtime/dpiExistentialAudit.js",
  "server/agent-runtime/dpiSelectedResponseConsistencyPolicy.js",
  "server/agent-runtime/dpiSelectedTaskAudit.js",
  "server/agent-runtime/dpiSelectedTaskPersistedAudit.js",
  "server/agent-runtime/dpiSemanticCreditPolicy.js",
  "server/agent-runtime/dpiSideCompactConjunctionCandidate.js",
  "server/agent-runtime/dpiTaskContributionAudit.js",
  "server/agent-runtime/dpiWholeTaskIntentAudit.js",
  "server/agent-runtime/dpiWholeTaskPersistedAudit.js",
  "server/agent-runtime/effectAdmissionContext.js",
  "server/agent-runtime/graphLeaseAdmission.js",
  "server/agent-runtime/inventoryStockAudit.js",
  "server/agent-runtime/mailReplyAudit.js",
  "server/agent-runtime/mailReplyAuthorityAudit.js",
  "server/agent-runtime/mailReplyAuthorityConsistentAudit.js",
  "server/agent-runtime/mailReplyCompactAudit.js",
  "server/agent-runtime/mailReplyConditionalAudit.js",
  "server/agent-runtime/mailReplyGroundedAudit.js",
  "server/agent-runtime/mailReplyKeyedAudit.js",
  "server/agent-runtime/mailReplySeparatedAuthorityAudit.js",
  "server/agent-runtime/mailReplySourceAudit.js",
  "server/agent-runtime/mailReplySparseAudit.js",
  "server/agent-runtime/mailReplyWholeAudit.js",
  "server/agent-runtime/postgresRunLedger.js",
  "server/agent-runtime/ragSemanticCreditPolicy.js",
  "server/agent-runtime/reviewModerationAudit.js",
  "server/agent-runtime/runCoordinator.js",
  "server/agent-runtime/secureshopSupervisorGraph.js",
  "server/database/postgres/mcpHttpLeaseRepository.js",
  "server/database/postgres/mcpHttpReceiptRepository.js",
  "server/database/postgres/mcpShadowLeaseRepository.js",
  "server/database/postgres/mcpShadowReceiptRepository.js",
  "server/database/postgres/objectiveJudgmentRepository.js",
  "server/database/postgres/personaObjectiveJudgmentBindings.js",
  "server/database/postgres/secureshopAnalyticsModeRepository.js",
  "server/database/postgres/secureshopAnalyticsRequestReadiness.js",
  "server/database/postgres/secureshopAnalyticsRequestRepository.js",
  "server/database/postgres/secureshopAuditManualRepository.js",
  "server/database/postgres/secureshopAuditQueryRepository.js",
  "server/database/postgres/secureshopAuditRunReader.js",
  "server/database/postgres/secureshopAuditRunRepository.js",
  "server/database/postgres/secureshopAuditSnapshot.js",
  "server/database/postgres/secureshopAuditTargetAdmissionRepository.js",
  "server/database/postgres/secureshopBoundAccountRepository.js",
  "server/database/postgres/secureshopBoundAclRepository.js",
  "server/database/postgres/secureshopBoundAdminReadRepository.js",
  "server/database/postgres/secureshopBoundAuditRepository.js",
  "server/database/postgres/secureshopBoundCommerceRepository.js",
  "server/database/postgres/secureshopBoundConversationsRepository.js",
  "server/database/postgres/secureshopBoundCouponRepository.js",
  "server/database/postgres/secureshopBoundMailRepository.js",
  "server/database/postgres/secureshopBoundManualIngestRepository.js",
  "server/database/postgres/secureshopBoundMcpRepository.js",
  "server/database/postgres/secureshopBoundPasswordResetRepository.js",
  "server/database/postgres/secureshopBoundPersonaAuthority.js",
  "server/database/postgres/secureshopBoundPersonaRepository.js",
  "server/database/postgres/secureshopBoundProductRepository.js",
  "server/database/postgres/secureshopBoundProductRetrievalRepository.js",
  "server/database/postgres/secureshopBoundPromptPolicyRepository.js",
  "server/database/postgres/secureshopBoundRefundRepository.js",
  "server/database/postgres/secureshopBoundSsrfRepository.js",
  "server/database/postgres/secureshopBoundToolPolicyReadiness.js",
  "server/database/postgres/secureshopBoundUserAdministrationRepository.js",
  "server/database/postgres/secureshopConversationCleanupCheckpointRepository.js",
  "server/database/postgres/secureshopConversationLifecycleRepository.js",
  "server/database/postgres/secureshopEmbeddingRevisionRepository.js",
  "server/database/postgres/secureshopInventoryRecoveryRepository.js",
  "server/database/postgres/secureshopLaunchRepository.js",
  "server/database/postgres/secureshopListingJournalRepository.js",
  "server/database/postgres/secureshopListingRewriteSaveRepository.js",
  "server/database/postgres/secureshopListingsEvidenceRepository.js",
  "server/database/postgres/secureshopMailEvidenceRepository.js",
  "server/database/postgres/secureshopMailHeaderEvidenceRepository.js",
  "server/database/postgres/secureshopMailRecoveryRepository.js",
  "server/database/postgres/secureshopOwnedInventoryRepository.js",
  "server/database/postgres/secureshopOwnedMcpInvocationJournal.js",
  "server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository.js",
  "server/database/postgres/secureshopOwnedMcpRegistryInvocationJournal.js",
  "server/database/postgres/secureshopOwnedMcpRegistryRepository.js",
  "server/database/postgres/secureshopOwnedStock.js",
  "server/database/postgres/secureshopOwnerResetRepository.js",
  "server/database/postgres/secureshopPersonaCredentialWrite.js",
  "server/database/postgres/secureshopPersonaInboxRepository.js",
  "server/database/postgres/secureshopPricingReadiness.js",
  "server/database/postgres/secureshopPricingRepository.js",
  "server/database/postgres/secureshopProgressCleanupCheckpointRepository.js",
  "server/database/postgres/secureshopRefundOperationReceipt.js",
  "server/database/postgres/secureshopRegisteredToolSnapshot.js",
  "server/database/postgres/secureshopResetCleanupAuthorityRepository.js",
  "server/database/postgres/secureshopSyntheticUserDirectoryRepository.js",
  "server/database/postgres/secureshopSystemConfigReadRepository.js",
  "server/database/postgres/secureshopSystemDiagnosticRepository.js",
  "server/database/postgres/secureshopSystemRebuildReadiness.js",
  "server/database/postgres/secureshopSystemRebuildRepository.js",
  "server/database/postgres/secureshopSystemRestartRepository.js",
  "server/database/postgres/secureshopTargetReconciliationRepository.js",
  "server/database/postgres/secureshopTurnModeProjection.js",
  "server/database/postgres/secureshopTurnRequestsRepository.js",
  "server/database/postgres/workshopConfigRepository.js",
  "server/database/postgres/workshopProgressRepository.js",
  "server/database/postgres/workshopProgressTimePredicate.js",
  "server/database/postgres/workshopRevisionRepository.js",
  "server/database/postgres/xssJudgmentBindingRepository.js",
  "server/database/postgres/xssScopeAuthorityRepository.js",
  "server/middleware/auditMetadata.js",
  "server/middleware/bearerToken.js",
  "server/middleware/postgresAdminAuth.js",
  "server/middleware/secureshopLaunch.js",
  "server/routes/secureshop/boundAdminChat.js",
  "server/routes/secureshop/boundAnalytics.js",
  "server/routes/secureshop/boundBrowser.js",
  "server/routes/secureshop/boundInventory.js",
  "server/routes/secureshop/boundListings.js",
  "server/routes/secureshop/boundMail.js",
  "server/routes/secureshop/boundMcpRegistry.js",
  "server/routes/secureshop/boundMcpTrust.js",
  "server/routes/secureshop/boundPersonaInbox.js",
  "server/routes/secureshop/boundPricing.js",
  "server/routes/secureshop/boundRefund.js",
  "server/routes/secureshop/boundReviews.js",
  "server/routes/secureshop/boundSsrf.js",
  "server/routes/secureshop/boundSystemConfig.js",
  "server/routes/secureshop/boundSystemDiagnostic.js",
  "server/routes/secureshop/boundSystemHealth.js",
  "server/routes/secureshop/boundSystemRebuild.js",
  "server/routes/secureshop/boundSystemRestart.js",
  "server/services/applicationLifecycle.js",
  "server/services/embeddingRuntimeFingerprint.js",
  "server/services/mcp/commandOutputReceipt.js",
  "server/services/mcp/config.js",
  "server/services/mcp/ownedHttpCapability.js",
  "server/services/mcp/ownedHttpManagedConfiguration.js",
  "server/services/mcp/ownedHttpReceipt.js",
  "server/services/mcp/ownedHttpServiceClient.js",
  "server/services/mcp/ownedQualification.js",
  "server/services/mcp/ownedShadowManagedConfiguration.js",
  "server/services/mcp/ownedShadowReceipt.js",
  "server/services/mcp/ownedShadowServiceClient.js",
  "server/services/mcp/ownedTargetClient.js",
  "server/services/mcp/protocolContext.js",
  "server/services/mcp/timing.js",
  "server/services/objectiveCompletionService.js",
  "server/services/objectiveGradingCore.js",
  "server/services/objectiveRegradeService.js",
  "server/services/postgresIdentityAdapter.js",
  "server/services/postgresPlatformStores.js",
  "server/services/ragVectorStore.js",
  "server/services/secureshop/providerRouter.js",
  "server/services/secureshop/providers/anthropicProvider.js",
  "server/services/secureshop/providers/bedrockProvider.js",
  "server/services/secureshop/providers/langchainAdapter.js",
  "server/services/secureshop/providers/ollamaProvider.js",
  "server/services/secureshop/providers/openaiProvider.js",
  "server/services/secureshop/sessionStore.js",
  "server/services/secureshop/traceBuffer.js",
  "server/services/secureshopAgentSnapshotPolicies.js",
  "server/services/secureshopAnalyticsApplication.js",
  "server/services/secureshopAnalyticsComposition.js",
  "server/services/secureshopAnalyticsDisclosureAssessment.js",
  "server/services/secureshopAnalyticsExecutionConfig.js",
  "server/services/secureshopAnalyticsLifecycle.js",
  "server/services/secureshopAnalyticsModeAuthority.js",
  "server/services/secureshopAnalyticsPostJournalAssessment.js",
  "server/services/secureshopAnalyticsProtectedEvidence.js",
  "server/services/secureshopAssessmentPersonaCapture.js",
  "server/services/secureshopAssessmentPublicationScope.js",
  "server/services/secureshopAuditArtifactVerification.js",
  "server/services/secureshopAuditAssessment.js",
  "server/services/secureshopAuditCursor.js",
  "server/services/secureshopAuditExecutionConfig.js",
  "server/services/secureshopAuditFixedProjection.js",
  "server/services/secureshopAuditJob.js",
  "server/services/secureshopAuditJudgePacket.js",
  "server/services/secureshopAuditModelChain.js",
  "server/services/secureshopAuditObservationSpool.js",
  "server/services/secureshopAuditPolicyChannel.js",
  "server/services/secureshopAuditQueryExecutionBinding.js",
  "server/services/secureshopAuditRunCleanup.js",
  "server/services/secureshopAuditRunReadiness.js",
  "server/services/secureshopAuditRunner.js",
  "server/services/secureshopAuditRuntime.js",
  "server/services/secureshopAuditRuntimeLifecycle.js",
  "server/services/secureshopAuditSourceManifest.js",
  "server/services/secureshopAuditTiming.js",
  "server/services/secureshopAuditVerifiedEvidence.js",
  "server/services/secureshopAuditWorkerHost.js",
  "server/services/secureshopBoundAccessControl.js",
  "server/services/secureshopBoundAccount.js",
  "server/services/secureshopBoundAclRegistry.js",
  "server/services/secureshopBoundAdmin.js",
  "server/services/secureshopBoundAdminReadAdapter.js",
  "server/services/secureshopBoundAgentRunner.js",
  "server/services/secureshopBoundAnalytics.js",
  "server/services/secureshopBoundAuditCleanup.js",
  "server/services/secureshopBoundAuditComposition.js",
  "server/services/secureshopBoundCatalog.js",
  "server/services/secureshopBoundCommerce.js",
  "server/services/secureshopBoundConversation.js",
  "server/services/secureshopBoundCoupon.js",
  "server/services/secureshopBoundGraphStore.js",
  "server/services/secureshopBoundInventory.js",
  "server/services/secureshopBoundInventoryGraph.js",
  "server/services/secureshopBoundListings.js",
  "server/services/secureshopBoundMailGraph.js",
  "server/services/secureshopBoundManualExtraction.js",
  "server/services/secureshopBoundManualIngestion.js",
  "server/services/secureshopBoundPersonaAuth.js",
  "server/services/secureshopBoundPersonaObservations.js",
  "server/services/secureshopBoundPolicySearch.js",
  "server/services/secureshopBoundPricingTools.js",
  "server/services/secureshopBoundProductAssist.js",
  "server/services/secureshopBoundProductRetrieval.js",
  "server/services/secureshopBoundProductTools.js",
  "server/services/secureshopBoundPromptPolicyService.js",
  "server/services/secureshopBoundRefundRuntime.js",
  "server/services/secureshopBoundRefundTools.js",
  "server/services/secureshopBoundReviewApplication.js",
  "server/services/secureshopBoundReviewComposition.js",
  "server/services/secureshopBoundReviewFixtureProfiles.js",
  "server/services/secureshopBoundReviewRuntime.js",
  "server/services/secureshopBoundReviewTools.js",
  "server/services/secureshopBoundRuntimeHealth.js",
  "server/services/secureshopBoundShutdown.js",
  "server/services/secureshopBoundSystemConfigReadService.js",
  "server/services/secureshopBoundSystemDiagnosticService.js",
  "server/services/secureshopBoundSystemHealthService.js",
  "server/services/secureshopBoundSystemRestartService.js",
  "server/services/secureshopBoundToolPolicyAdmission.js",
  "server/services/secureshopBoundTraceRecord.js",
  "server/services/secureshopBoundTurns.js",
  "server/services/secureshopBoundUserAdministration.js",
  "server/services/secureshopCleanupComposition.js",
  "server/services/secureshopConversationLifecycle.js",
  "server/services/secureshopCouponProduction.js",
  "server/services/secureshopEmbeddingReindex.js",
  "server/services/secureshopFailureDiagnostic.js",
  "server/services/secureshopFeatureModeAuthority.js",
  "server/services/secureshopFileCleanupReceiptReader.js",
  "server/services/secureshopFileTargetCleanup.js",
  "server/services/secureshopGradingBootstrap.js",
  "server/services/secureshopInventoryAssessment.js",
  "server/services/secureshopInventoryGradingProjection.js",
  "server/services/secureshopInventoryGradingReadback.js",
  "server/services/secureshopInventoryJudgeRetry.js",
  "server/services/secureshopInventoryProduction.js",
  "server/services/secureshopInventorySchema.js",
  "server/services/secureshopLaunchResetCoordinator.js",
  "server/services/secureshopListingExecutorBridge.js",
  "server/services/secureshopListingImportReceiptAdapter.js",
  "server/services/secureshopListingJournalContract.js",
  "server/services/secureshopListingRequestContract.js",
  "server/services/secureshopListingRewriteSaveContract.js",
  "server/services/secureshopListingsApplication.js",
  "server/services/secureshopListingsAssessment.js",
  "server/services/secureshopListingsBrowserAssessment.js",
  "server/services/secureshopListingsComposition.js",
  "server/services/secureshopListingsEvidence.js",
  "server/services/secureshopListingsJudgeGuard.js",
  "server/services/secureshopListingsManagedConfiguration.js",
  "server/services/secureshopListingsProduction.js",
  "server/services/secureshopListingsRuntime.js",
  "server/services/secureshopListingsTargetManager.js",
  "server/services/secureshopLoopAssessment.js",
  "server/services/secureshopMailApplication.js",
  "server/services/secureshopMailBrowserAssessment.js",
  "server/services/secureshopMailBrowserEvidence.js",
  "server/services/secureshopMailBrowserQualification.js",
  "server/services/secureshopMailCapabilities.js",
  "server/services/secureshopMailCleanup.js",
  "server/services/secureshopMailComposition.js",
  "server/services/secureshopMailDisclosureAssessment.js",
  "server/services/secureshopMailDisclosureEvidence.js",
  "server/services/secureshopMailErrors.js",
  "server/services/secureshopMailHeaderAssessment.js",
  "server/services/secureshopMailObjectiveReadiness.js",
  "server/services/secureshopMailProduction.js",
  "server/services/secureshopMailReplyAssessment.js",
  "server/services/secureshopManualExecutionConfig.js",
  "server/services/secureshopManualReviewDecision.js",
  "server/services/secureshopMcpControlledServer.js",
  "server/services/secureshopMcpControlledTargetPool.js",
  "server/services/secureshopMcpOwnedFixture.js",
  "server/services/secureshopMcpRegistryContract.js",
  "server/services/secureshopMcpRegistryDiscovery.js",
  "server/services/secureshopMcpSchemaDigest.js",
  "server/services/secureshopMcpSdkTransport.js",
  "server/services/secureshopMcpTrustActivationPolicy.js",
  "server/services/secureshopMcpTrustApplication.js",
  "server/services/secureshopMcpTrustAssessment.js",
  "server/services/secureshopMcpTrustAvailability.js",
  "server/services/secureshopMcpTrustBoundRunner.js",
  "server/services/secureshopMcpTrustComposition.js",
  "server/services/secureshopMcpTrustEvidence.js",
  "server/services/secureshopMcpTrustExecutionConfig.js",
  "server/services/secureshopMcpTrustExternalAdapter.js",
  "server/services/secureshopMcpTrustProduction.js",
  "server/services/secureshopMcpTrustResetAdapter.js",
  "server/services/secureshopMcpTrustTools.js",
  "server/services/secureshopMerchantMetrics.js",
  "server/services/secureshopModelQualification.js",
  "server/services/secureshopOwnedAnalyticsAdapter.js",
  "server/services/secureshopOwnedAnalyticsProduction.js",
  "server/services/secureshopOwnedAuditAssessment.js",
  "server/services/secureshopOwnedAuditComposition.js",
  "server/services/secureshopOwnedAuditDecisionGraph.js",
  "server/services/secureshopOwnedAuditHttpClient.js",
  "server/services/secureshopOwnedAuditLifecycle.js",
  "server/services/secureshopOwnedAuditManualAdapter.js",
  "server/services/secureshopOwnedAuditProduction.js",
  "server/services/secureshopOwnedAuditQueryAdapter.js",
  "server/services/secureshopOwnedAuditSearchApplication.js",
  "server/services/secureshopOwnedAuditSearchBackend.js",
  "server/services/secureshopOwnedAuditSearchSnapshot.js",
  "server/services/secureshopOwnedCompetitorObservation.js",
  "server/services/secureshopOwnedFiles.js",
  "server/services/secureshopOwnedListingsClient.js",
  "server/services/secureshopOwnedMcpInvocationContract.js",
  "server/services/secureshopOwnedMcpInvocationLifecycle.js",
  "server/services/secureshopOwnedMcpRegistry.js",
  "server/services/secureshopOwnedMcpRegistryAdminReadOverlay.js",
  "server/services/secureshopOwnedMcpRegistryClient.js",
  "server/services/secureshopOwnedMcpRegistryComposition.js",
  "server/services/secureshopOwnedMcpRegistryInvocationBridge.js",
  "server/services/secureshopOwnedMcpRegistryLifecycle.js",
  "server/services/secureshopOwnedMcpRegistryProduction.js",
  "server/services/secureshopOwnerResetService.js",
  "server/services/secureshopPasswordResetComposition.js",
  "server/services/secureshopPasswordResetEnvelope.js",
  "server/services/secureshopPersonaInboxActivationPolicy.js",
  "server/services/secureshopPersonaInboxApplication.js",
  "server/services/secureshopPersonaInboxAssessment.js",
  "server/services/secureshopPersonaInboxAvailability.js",
  "server/services/secureshopPersonaInboxComposition.js",
  "server/services/secureshopPersonaInboxEffect.js",
  "server/services/secureshopPersonaInboxEvidence.js",
  "server/services/secureshopPersonaInboxExecutionConfig.js",
  "server/services/secureshopPersonaInboxFinalResponseGate.js",
  "server/services/secureshopPersonaInboxPriorAdvisoryReader.js",
  "server/services/secureshopPersonaInboxRequestAuthority.js",
  "server/services/secureshopPersonaInboxTools.js",
  "server/services/secureshopPersonaProductEffect.js",
  "server/services/secureshopPersonaRefundEffect.js",
  "server/services/secureshopPersonaReviewEffect.js",
  "server/services/secureshopPersonaToolDispatch.js",
  "server/services/secureshopPolicyCorpusSource.js",
  "server/services/secureshopPolicyRetrievalSnapshot.js",
  "server/services/secureshopPricingAssessment.js",
  "server/services/secureshopPricingComposition.js",
  "server/services/secureshopPricingContract.js",
  "server/services/secureshopPricingEvidence.js",
  "server/services/secureshopPricingExecutionConfig.js",
  "server/services/secureshopPricingProduction.js",
  "server/services/secureshopPricingReceipt.js",
  "server/services/secureshopPricingRunBinding.js",
  "server/services/secureshopPricingTargetSource.js",
  "server/services/secureshopProductDescriptionRenderer.js",
  "server/services/secureshopProductEmbedder.js",
  "server/services/secureshopProductExecutionConfig.js",
  "server/services/secureshopPromptPolicyContract.js",
  "server/services/secureshopPromptPolicyRunBinding.js",
  "server/services/secureshopPromptPolicyRunnerOptions.js",
  "server/services/secureshopPromptPolicySnapshot.js",
  "server/services/secureshopPromptPolicyTaskMutation.js",
  "server/services/secureshopPromptPolicyTaskSnapshot.js",
  "server/services/secureshopRecoverableToolError.js",
  "server/services/secureshopRegisteredAdminRuntime.js",
  "server/services/secureshopRegisteredInvocationObservation.js",
  "server/services/secureshopRegisteredInvocationProduction.js",
  "server/services/secureshopRegisteredTurnTools.js",
  "server/services/secureshopReservedFileWriter.js",
  "server/services/secureshopReviewCardRenderer.js",
  "server/services/secureshopReviewCleanupReceiptReader.js",
  "server/services/secureshopReviewContentAssessment.js",
  "server/services/secureshopReviewContentEvidence.js",
  "server/services/secureshopReviewDecisionOperation.js",
  "server/services/secureshopReviewExecutionConfig.js",
  "server/services/secureshopReviewResetCoordinator.js",
  "server/services/secureshopSsrfApplication.js",
  "server/services/secureshopSsrfAssessment.js",
  "server/services/secureshopSsrfAvailability.js",
  "server/services/secureshopSsrfComposition.js",
  "server/services/secureshopSsrfEvidence.js",
  "server/services/secureshopSsrfExecutionConfig.js",
  "server/services/secureshopSsrfExternalAdapter.js",
  "server/services/secureshopSsrfOwnedTarget.js",
  "server/services/secureshopSsrfProduction.js",
  "server/services/secureshopSsrfResetAdapter.js",
  "server/services/secureshopSsrfTargetPool.js",
  "server/services/secureshopStoredBrowserAssessment.js",
  "server/services/secureshopStudentDeletionCleanup.js",
  "server/services/secureshopSystemConfigComposition.js",
  "server/services/secureshopSystemDiagnosticComposition.js",
  "server/services/secureshopSystemRebuildComposition.js",
  "server/services/secureshopSystemRebuildService.js",
  "server/services/secureshopSystemRebuildTarget.js",
  "server/services/secureshopSystemRestartComposition.js",
  "server/services/secureshopSystemRestartLifecycle.js",
  "server/services/secureshopTurnAdmission.js",
  "server/services/secureshopTurnRequest.js",
  "server/services/supplyChain/codeBotProduction.js",
  "server/services/workshopModeService.js",
  "server/services/xssBrowserQualification.js",
  "server/services/xssJudgmentScope.js",
  "sidecars/analytics-sql-target/admission.js",
  "sidecars/analytics-sql-target/bootstrap.js",
  "sidecars/analytics-sql-target/bounded-query.js",
  "sidecars/analytics-sql-target/cluster.js",
  "sidecars/analytics-sql-target/contract.js",
  "sidecars/analytics-sql-target/executor.js",
  "sidecars/analytics-sql-target/fixed-capability.js",
  "sidecars/analytics-sql-target/fixture.js",
  "sidecars/analytics-sql-target/journal.js",
  "sidecars/analytics-sql-target/protected-columns.js",
  "sidecars/analytics-sql-target/service.js",
  "sidecars/audit-sql-target/http.js",
  "sidecars/audit-sql-target/journal.js",
  "sidecars/audit-sql-target/main.js",
  "sidecars/audit-sql-target/readiness.js",
  "sidecars/audit-sql-target/service.js",
  "sidecars/sandbox-runner/Dockerfile",
  "sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in",
  "sidecars/sandbox-runner/entrypoint.sh",
  "sidecars/sandbox-runner/index.js",
  "sidecars/sandbox-runner/labfs/etc/hosts.lab",
  "sidecars/sandbox-runner/labfs/etc/passwd",
  "sidecars/sandbox-runner/labfs/home/mcp-admin/.bash_history",
  "sidecars/sandbox-runner/labfs/home/mcp-admin/notes.txt",
  "sidecars/sandbox-runner/labfs/home/mcp-admin/readme.txt",
  "sidecars/sandbox-runner/labfs/opt/app/config/database.yml",
  "sidecars/sandbox-runner/labfs/opt/app/config/mcp.yml",
  "sidecars/sandbox-runner/labfs/opt/app/package.json",
  "sidecars/sandbox-runner/labfs/opt/app/server.js",
  "sidecars/sandbox-runner/labfs/opt/lab/bin/malicious_postinstall.sh",
  "sidecars/sandbox-runner/labfs/opt/lab/bin/rotate_keys.sh",
  "sidecars/sandbox-runner/labfs/opt/lab/packages/acme-analytics-1.0.0.tgz",
  "sidecars/sandbox-runner/labfs/opt/lab/packages/acme-analytics-1.0.0.tgz.sig",
  "sidecars/sandbox-runner/labfs/opt/lab/packages/acme-package-signing-public.pem",
  "sidecars/sandbox-runner/labfs/opt/lab/packages/analytics-boost-1.0.0.tgz",
  "sidecars/sandbox-runner/labfs/var/log/syslog",
  "sidecars/sandbox-runner/mcpPackageCatalog.js",
  "sidecars/sandbox-runner/mcpProtectedState.js",
  "sidecars/sandbox-runner/mcpSeccompFilter.c",
  "sidecars/sandbox-runner/mcpSeccompProbe.c",
  "sidecars/sandbox-runner/mcpTargets.js",
  "sidecars/sandbox-runner/owned-http/README.md",
  "sidecars/sandbox-runner/owned-http/api.js",
  "sidecars/sandbox-runner/owned-http/buildAssets.js",
  "sidecars/sandbox-runner/owned-http/canonical.js",
  "sidecars/sandbox-runner/owned-http/executor.js",
  "sidecars/sandbox-runner/owned-http/http-profile.apparmor.in",
  "sidecars/sandbox-runner/owned-http/namespace-init.c",
  "sidecars/sandbox-runner/owned-http/network-manifest.json",
  "sidecars/sandbox-runner/owned-http/operationStore.js",
  "sidecars/sandbox-runner/owned-http/process-supervisor.c",
  "sidecars/sandbox-runner/owned-http/profile.js",
  "sidecars/sandbox-runner/owned-http/service.js",
  "sidecars/sandbox-runner/owned-http/worker.js",
  "sidecars/sandbox-runner/owned-mcp-registry/http-handler.js",
  "sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol.js",
  "sidecars/sandbox-runner/owned-pricing-http/network-manifest.json",
  "sidecars/sandbox-runner/owned-shadow/Dockerfile",
  "sidecars/sandbox-runner/owned-shadow/buildAssets.js",
  "sidecars/sandbox-runner/owned-shadow/contract.js",
  "sidecars/sandbox-runner/owned-shadow/executor.js",
  "sidecars/sandbox-runner/owned-shadow/operationStore.js",
  "sidecars/sandbox-runner/owned-shadow/package-lock.json",
  "sidecars/sandbox-runner/owned-shadow/package.json",
  "sidecars/sandbox-runner/owned-shadow/profile.js",
  "sidecars/sandbox-runner/owned-shadow/service.js",
  "sidecars/sandbox-runner/owned-shadow/worker.js",
  "sidecars/sandbox-runner/ownedTargetApi.js",
  "sidecars/sandbox-runner/package.json",
  "sidecars/sandbox-runner/policy-render/assets/NUNJUCKS-LICENSE.txt",
  "sidecars/sandbox-runner/policy-render/assets/nunjucks-3.2.4.js",
  "sidecars/sandbox-runner/policy-render/executor.js",
  "sidecars/sandbox-runner/policy-render/http-handler.js",
  "sidecars/sandbox-runner/policy-render/policy-init.c",
  "sidecars/sandbox-runner/policy-render/process-supervisor.c",
  "sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract.js",
  "sidecars/sandbox-runner/policy-render/worker.js",
  "sidecars/sandbox-runner/protected-operations/operationStore.js",
  "sidecars/sandbox-runner/secureshopFiles.js"
];
 assert.equal(createHash('sha256').update(JSON.stringify(previous)).digest('hex'),'750fc44bb5e545e15fc9cd20989c9cd1387883f2f084632cf8abf847cbea2d3e');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),added);
 assert.deepEqual(current.recoveryFiles,[...previous.recoveryFiles,...added].sort());
 assert.equal(Object.keys(current.files).length,1061);assert.equal(current.recoveryFiles.length,1059);
 // These reviewed masked teaching fixtures have a separate release asset
 // inventory and per-file guest transfer hashes. v43 does not seal their bytes.
 for(const name of ["sidecars/sandbox-runner/labfs/opt/app/config/.env","sidecars/sandbox-runner/labfs/var/secrets/credentials.json","sidecars/sandbox-runner/labfs/var/secrets/master_key.txt"]){assert.equal(Object.hasOwn(current.files,name),false);assert.equal(current.recoveryFiles.includes(name),false);}
});
test('owned Windows lab, protected profile and build dependency drift deny admission',()=>{
 for(const name of [
  "scripts/local-docker-authority.js",
  "scripts/local-mailpit.js",
  "scripts/setup-application.js",
  "server/services/applicationMaintenanceInprocessAdmission.js",
  "server/services/mcp/ownedManagedConfiguration.js",
  "scripts/install/mcp-owned-local.js",
  "scripts/install/mcp-owned-provision.js",
  "scripts/install/mcp-owned-http.js",
  "scripts/install/mcp-owned-shadow.js",
  "scripts/install/mcp-owned-service-build-context.js",
  "scripts/install/mcp-owned-service-retry-environment.js",
  "scripts/lib/windows-owned-lab.js",
  "scripts/lib/windows-owned-hyperv-observer.js",
  "scripts/lib/windows-lab-installation.js",
  "scripts/lib/windows-lab-forward-owner.js",
  "scripts/install/Windows/owned-hyperv-observer.ps1",
  "sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in",
  "sidecars/sandbox-runner/Dockerfile",
  "sidecars/sandbox-runner/owned-shadow/Dockerfile"
])rejectsSimulatedSourceDrift(name);
});
test('new default Windows base Audit and native wrapper source drift denies',()=>{
 for(const name of [
  "scripts/install/Windows/dependencies.ps1",
  "scripts/install/Windows/dependency-plan.ps1",
  "scripts/install/Windows/install-windows.ps1",
  "scripts/install/Windows/packages.ps1",
  "scripts/install/Windows/prerequisites.ps1",
  "scripts/install/Windows/start_all.ps1",
  "scripts/install/Windows/wrapper-handoff.ps1",
  "scripts/install/audit-sql-activate.js",
  "scripts/install/audit-sql-target.js",
  "scripts/install/windows-base-lab-services.js",
  "scripts/lib/audit-sql-private-state.js",
  "sidecars/audit-sql-target/bootstrap.js",
  "sidecars/audit-sql-target/migrations/0002_query_receipts.sql",
  "sidecars/audit-sql-target/migrations/0003_query_destruction_tombstones.sql",
  "sidecars/audit-sql-target/schema.sql",
  "sidecars/rogue-mcp/Dockerfile",
  "sidecars/rogue-mcp/index.js",
  "sidecars/ssrf-target/Dockerfile",
  "sidecars/ssrf-target/index.js"
])rejectsSimulatedSourceDrift(name);
});
test('Windows guardian and job helper drift deny',()=>{
 for(const name of ['scripts/owned-child-guardian.js','scripts/lib/windows-owned-process.js','scripts/windows/windows-owned-process.ps1','scripts/windows/windows-owned-process.cs'])rejectsSimulatedSourceDrift(name);
});
test('Windows owner schema and maintenance admission drift deny',()=>{
 for(const name of ['db/postgres/maintenance-migrations/0005_windows_owner_records.sql','server/database/postgres/applicationMaintenanceControl.js','server/services/applicationMaintenanceExecutionAdmission.js','server/services/applicationMaintenanceLease.js'])rejectsSimulatedSourceDrift(name);
});
test('changed objective judge bytes deny without changing any source file',()=>{
 rejectsSimulatedSourceDrift('server/agent-runtime/objectiveJudge.js');
});
test('changed newly bound pricing grounding verifier bytes deny',()=>{
 rejectsSimulatedSourceDrift('server/agent-runtime/pricingGroundingComparisonVerifier.js');
});
test('changed newly bound selected-task comparison bytes deny',()=>{
 rejectsSimulatedSourceDrift('server/agent-runtime/dpiSelectedTaskComparison.js');
});
test('changed newly bound email curriculum bytes deny',()=>{
 rejectsSimulatedSourceDrift('server/config/xssEmailBuilderCurriculum.js');
});
test('changed frozen package or lockfile bytes deny',()=>{
 for(const name of ['package.json','package-lock.json','node_modules/.package-lock.json'])rejectsSimulatedSourceDrift(name);
});
test('additional and missing SQL inventory both deny before source reads',()=>{
 const directory=path.join(ROOT,'db/postgres/identity-migrations');
 for(const mode of ['added','missing']){let changed=false;denied(()=>bindingWith({readdirSync(dir,options){const rows=fs.readdirSync(dir,options);if(dir!==directory)return rows;changed=true;return mode==='missing'?rows.filter(x=>x.name!=='0001_identity.sql'):[...rows,{name:'9999_simulated.sql',isSymbolicLink:()=>false,isDirectory:()=>false}];}})(ROOT));assert.equal(changed,true);}
});
test('SQL byte drift and symlink inventory deny',()=>{
 const target=path.join(ROOT,'db/postgres/identity-migrations/0001_identity.sql');
 denied(()=>bindingWith({readFileSync(filename,...args){return filename===target?Buffer.from('-- simulated SQL drift'):fs.readFileSync(filename,...args);}})(ROOT));
 denied(()=>bindingWith({readdirSync(dir,options){const rows=fs.readdirSync(dir,options);return dir===path.join(ROOT,'db/postgres')?[...rows,{name:'simulated-link',isSymbolicLink:()=>true}]:rows;}})(ROOT));
});
test('retained predecessor cannot admit current main or relabel historical digest',()=>{
 const previous=JSON.parse(fs.readFileSync(path.join(ROOT,'tests/release-inputs/maintenance-inprocess-sources-predecessor-142d6750.json')));
 const original=realRequire('./applicationMaintenanceInprocessSources.json');
 const v2=realRequire('./applicationMaintenanceInprocessSources-v2.json');
 const v3=realRequire('./applicationMaintenanceInprocessSources-v3.json');
 const v4=realRequire('./applicationMaintenanceInprocessSources-v4.json');
 const v5=realRequire('./applicationMaintenanceInprocessSources-v5.json');
 const v6=realRequire('./applicationMaintenanceInprocessSources-v6.json');
 const v7=realRequire('./applicationMaintenanceInprocessSources-v7.json');
 const v8=realRequire('./applicationMaintenanceInprocessSources-v8.json');
 const v9=realRequire('./applicationMaintenanceInprocessSources-v9.json');
 const v10=realRequire('./applicationMaintenanceInprocessSources-v10.json');
 const v11=realRequire('./applicationMaintenanceInprocessSources-v11.json');
 const v12=realRequire('./applicationMaintenanceInprocessSources-v12.json');
 const v13=realRequire('./applicationMaintenanceInprocessSources-v13.json');
 const v14=realRequire('./applicationMaintenanceInprocessSources-v14.json');
 const v15=realRequire('./applicationMaintenanceInprocessSources-v15.json');
 const v16=realRequire('./applicationMaintenanceInprocessSources-v16.json');
 const v17=realRequire('./applicationMaintenanceInprocessSources-v17.json');
 const v18=realRequire('./applicationMaintenanceInprocessSources-v18.json');
 const v19=realRequire('./applicationMaintenanceInprocessSources-v19.json');
 const v20=realRequire('./applicationMaintenanceInprocessSources-v20.json');
 const v21=realRequire('./applicationMaintenanceInprocessSources-v21.json');
 const v22=realRequire('./applicationMaintenanceInprocessSources-v22.json');
 const v23=realRequire('./applicationMaintenanceInprocessSources-v23.json');
 const v24=realRequire('./applicationMaintenanceInprocessSources-v24.json');
 const v25=realRequire('./applicationMaintenanceInprocessSources-v25.json');
 const v26=realRequire('./applicationMaintenanceInprocessSources-v26.json');
 const v27=realRequire('./applicationMaintenanceInprocessSources-v27.json');
 const v28=realRequire('./applicationMaintenanceInprocessSources-v28.json');
 const v29=realRequire('./applicationMaintenanceInprocessSources-v29.json');
 const v30=realRequire('./applicationMaintenanceInprocessSources-v30.json');
 const v31=realRequire('./applicationMaintenanceInprocessSources-v31.json');
 const v32=realRequire('./applicationMaintenanceInprocessSources-v32.json');
 const v33=realRequire('./applicationMaintenanceInprocessSources-v33.json');
 const v34=realRequire('./applicationMaintenanceInprocessSources-v34.json');
 const v35=realRequire('./applicationMaintenanceInprocessSources-v35.json');
 const v36=realRequire('./applicationMaintenanceInprocessSources-v36.json');
 const v37=realRequire('./applicationMaintenanceInprocessSources-v37.json');
 const v38=realRequire('./applicationMaintenanceInprocessSources-v38.json');
 const v39=realRequire('./applicationMaintenanceInprocessSources-v39.json');
 const v40=realRequire('./applicationMaintenanceInprocessSources-v40.json');
 const v41=realRequire('./applicationMaintenanceInprocessSources-v41.json');
 const v42=realRequire('./applicationMaintenanceInprocessSources-v42.json');
 const v43=realRequire('./applicationMaintenanceInprocessSources-v43.json');
 for(const historical of [previous,original,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15,v16,v17,v18,v19,v20,v21,v22,v23,v24,v25,v26,v27,v28,v29,v30,v31,v32,v33,v34,v35,v36,v37,v38,v39,v40,v41,v42,v43]){
  denied(()=>bindingWith({},historical)(ROOT));assert.notEqual(createHash('sha256').update(JSON.stringify(historical)).digest('hex'),bindingWith()(ROOT));
 }
});
test('recovery closure denies representative transitive JavaScript and SQL drift',()=>{
 const admission=realRequire(file),manifest=realRequire(activeManifest),digest=createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
 assert.match(admission.recoverySourceBinding(ROOT,digest),/^[a-f0-9]{64}$/);
 for(const relativePath of ['server/database/postgres/workshopPlatformSeed.js','db/postgres/identity-migrations/0001_identity.sql','scripts/lib/windows-process-identity.js','scripts/windows/windows-process-identity.ps1','scripts/windows/windows-process-identity.cs','scripts/lib/application-maintenance-installation.js','scripts/lib/setup-local-process-identity.js']){const target=path.join(ROOT,relativePath),read=fs.readFileSync;denied(()=>{const module={exports:{}},wrapped=vm.runInThisContext(`(function(require,module,exports,__filename,__dirname){${read(file,'utf8')}\n})`,{filename:file});wrapped(name=>name==='node:fs'?new Proxy(fs,{get:(value,key)=>key==='readFileSync'?((filename,...args)=>filename===target?Buffer.concat([read(filename,...args),Buffer.from('\n-- drift')]):read(filename,...args)):value[key]}):realRequire(name),module,module.exports,file,path.dirname(file));return module.exports.recoverySourceBinding(ROOT,digest);});}
});

test('Windows separator inventory admits identical bytes and rejects SQL drift',()=>{
 const windowsRoot='C:\\dvaia';
 const local=file=>{const relative=path.win32.relative(windowsRoot,file);assert.ok(relative!==''&&!relative.startsWith('..')&&!path.win32.isAbsolute(relative));return path.join(ROOT,...relative.split('\\'));};
 const filesystem={
  readdirSync(file,options){return fs.readdirSync(local(file),options);},
  realpathSync(file){assert.equal(fs.realpathSync(local(file)),local(file));return file;},
  readFileSync(file,...args){return fs.readFileSync(local(file),...args);},
 };
 assert.equal(bindingWith(filesystem,undefined,path.win32)(windowsRoot),bindingWith()(ROOT));
 let changed=false;
 denied(()=>bindingWith({...filesystem,readFileSync(file,...args){const bytes=filesystem.readFileSync(file,...args);if(file.endsWith('0001_identity.sql')){changed=true;return Buffer.concat([bytes,Buffer.from('\n-- drift')]);}return bytes;}},undefined,path.win32)(windowsRoot));
 assert.equal(changed,true);
});

test('Windows additive publication dependency drift denies admission',()=>{
 for(const name of ['scripts/application-upgrade.js','scripts/lib/windows-private-publication.js','scripts/windows/windows-private-publication.ps1','scripts/windows/windows-private-publication.cs'])rejectsSimulatedSourceDrift(name);
});

test('Windows provisioning persistence dependency drift denies admission',()=>{rejectsSimulatedSourceDrift('scripts/lib/windows-provisioning-journal.js');});

test('CTF delivery provisioning source drift denies admission',()=>{rejectsSimulatedSourceDrift('db/postgres/provision-ctf-delivery.js');});

test('CTF authority setup private-read source drift denies admission',()=>{rejectsSimulatedSourceDrift('scripts/install/ctf-authority-setup.js');});

test('Windows CTF journal caller and native storage dependency drift deny admission',()=>{
 for(const name of ['scripts/install/ctf-authority-journal.js','scripts/lib/windows-ctf-authority-journal-storage.js'])rejectsSimulatedSourceDrift(name);
});

test('v49 preserves prior source membership and binds new storefront lifecycle sources',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v48.json'),current=realRequire('./applicationMaintenanceInprocessSources-v49.json');
 for(const name of Object.keys(previous.files))assert.ok(Object.hasOwn(current.files,name));
 for(const name of ['db/postgres/identity-migrations/0134_secureshop_product_launch_admission.sql','server/database/postgres/secureshopPublicCatalogRepository.js','server/database/postgres/studentDeletionRepository.js','server/database/postgres/secureshopBoundIdentityRepository.js','server/routes/secureshop/boundGateway.js']){
  assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);
 }
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v48.json'))).digest('hex'),'1e50be24ce4de1b4089a27eb5652e952220787a28f753abbbb90f022690c03f7');
});

test('v50 preserves v49 and binds clean legacy journal adoption',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v49.json'),current=realRequire('./applicationMaintenanceInprocessSources-v50.json');
 for(const name of Object.keys(previous.files))assert.ok(Object.hasOwn(current.files,name));
 const helper='scripts/install/ctf-authority-clean-adoption.js';assert.ok(current.recoveryFiles.includes(helper));rejectsSimulatedSourceDrift(helper);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v49.json'))).digest('hex'),'58ae1441c848e576cbdf3da96706bd6e5d12aaf73675a31258ebab7599e3f7d6');
});

test('v51 preserves historical source membership and binds independent shop authority',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v50.json'),current=realRequire('./applicationMaintenanceInprocessSources-v51.json');
 for(const name of Object.keys(previous.files))assert.ok(Object.hasOwn(current.files,name));
 for(const name of previous.recoveryFiles)assert.ok(current.recoveryFiles.includes(name));
 for(const name of ['server/routes/secureshopStandaloneAuth.js','server/services/secureshopStandaloneAuth.js',
  'server/services/secureshopStandaloneBootstrap.js','server/services/secureshopStandaloneCartImport.js',
  'server/database/postgres/secureshopStandaloneSeed.js','server/database/postgres/secureshopStorePublicCatalogRepository.js',
  'db/postgres/identity-migrations/0140_secureshop_tenant_execution_capacity.sql',
  'db/postgres/workshop-migrations/secureshop_review/0033_guest_cart_import.sql']){
  assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);
 }
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v50.json'))).digest('hex'),'1a9dab9231b7e1cc4b533509a66b6aa4b4dc191213191c481243272c25722e02');
});

test('v52 preserves v51 and binds only bootstrap expiry serialization and admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v51.json'),current=realRequire('./applicationMaintenanceInprocessSources-v52.json');
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),
  ['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopStandaloneBootstrap.js']);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v51.json'))).digest('hex'),'d39f194ebba5de6f9dcfbf4f592e89dd623134831cb641f6314d0fe49c844fda');
});

 test('v198 historical source preserves history and binds reviewed manifest disclosure and storefront corrections',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v197.json'),current=realRequire('./applicationMaintenanceInprocessSources-v198.json');
 for(const name of Object.keys(previous.files))assert.ok(Object.hasOwn(current.files,name));
 for(const name of previous.recoveryFiles)assert.ok(current.recoveryFiles.includes(name));
 const additions=Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name));
 assert.equal(additions.length,15);
 const changes=Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]);
 assert.equal(changes.length,16);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v198.json'))).digest('hex'),'ff6ab6da305872e263cef78583167f4c3a359c93a3db9673f65949bc8db078f9');
 for(const name of additions)assert.ok(current.recoveryFiles.includes(name));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
 });

test('v199 historical source binds only manifest assessment bridge operations and admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v198.json'),current=realRequire('./applicationMaintenanceInprocessSources-v199.json');
 const changed=['client/src/pages/secureshop/bridge/operations.mjs','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.equal(Object.keys(current.files).length,1540);assert.equal(current.recoveryFiles.length,1531);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v198.json'))).digest('hex'),'ff6ab6da305872e263cef78583167f4c3a359c93a3db9673f65949bc8db078f9');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v199.json'))).digest('hex'),'78930db2b7aca5085a6baba1bad03e6fd8acc8bc8c83472273f53eb2dc2dbbb1');
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v200 historical source binds only protected manifest request identity adaptation and admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v199.json'),current=realRequire('./applicationMaintenanceInprocessSources-v200.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopMcpManifestAssessment.js'];
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.equal(Object.keys(current.files).length,1540);assert.equal(current.recoveryFiles.length,1531);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v199.json'))).digest('hex'),'78930db2b7aca5085a6baba1bad03e6fd8acc8bc8c83472273f53eb2dc2dbbb1');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v200.json'))).digest('hex'),'bf749bed8af851873032d6e3d18008e20515d4a49a083884215ba4fe1f9b8bd8');
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v201 historical source binds only original manifest ownership admission ordering and pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v200.json'),current=realRequire('./applicationMaintenanceInprocessSources-v201.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopMcpManifestAssessment.js'];
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.equal(Object.keys(current.files).length,1540);assert.equal(current.recoveryFiles.length,1531);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v200.json'))).digest('hex'),'bf749bed8af851873032d6e3d18008e20515d4a49a083884215ba4fe1f9b8bd8');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v201.json'))).digest('hex'),'5b1a5180667ef148220af015528f08d121bae901c18a135e2d15a9231bcc53e4');
 assert.equal(createHash('sha256').update(JSON.stringify(current)).digest('hex'),'dcf79016f8cd4e7ddcda3744bcdd98e548eda79566d4902cee17166479207f2b');
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v202 historical source binds reviewed search echo workflow and rendering correctness closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v201.json'),current=realRequire('./applicationMaintenanceInprocessSources-v202.json');
 const additions=["client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx", "client/src/pages/secureshop/components/RoleSwitcher.jsx", "client/src/pages/secureshop/hooks/useSearchEchoAssessment.js", "client/src/pages/secureshop/pages/Catalog.jsx", "client/src/pages/secureshop/searchEchoClientRenderer.jsx", "client/src/pages/secureshop/utils/customerSearchEchoAssessmentReference.mjs", "client/vite.search-echo-renderer.config.mjs", "server/routes/secureshop/boundSearchEchoAssessment.js", "server/services/secureshopSavedAssessmentOutcomeReader.js", "server/services/secureshopSearchEchoBrowserAssessment.js", "server/services/secureshopSearchEchoBrowserEvidence.js", "server/services/secureshopSearchEchoBrowserQualification.js", "server/services/secureshopSearchEchoOriginalReader.js"],changes=["client/package.json", "client/src/pages/secureshop/bridge/operations.mjs", "client/src/pages/secureshop/bridge/stateChannel.mjs", "client/src/pages/secureshop/bridge/stateStore.mjs", "client/src/pages/secureshop/components/AgentLane/HopDetailSheet.jsx", "client/src/pages/secureshop/components/BoundAgentLane.jsx", "client/src/pages/secureshop/components/TopNav.jsx", "client/src/pages/secureshop/utils/shopStorage.mjs", "scripts/setup-application.js", "scripts/verify-release-source-inclusion.js", "server/config/secureshopCurriculum.js", "server/routes/secureshop/boundGateway.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopAssessmentRecovery.js", "server/services/secureshopBoundApplication.js", "server/services/secureshopBoundCustomerChat.js", "server/services/secureshopBoundReviewComposition.js"];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1553);assert.equal(current.recoveryFiles.length,1544);
 assert.deepEqual([...additions,...changes].filter(name=>name.startsWith('db/postgres/')),[]);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v201.json'))).digest('hex'),'5b1a5180667ef148220af015528f08d121bae901c18a135e2d15a9231bcc53e4');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v202.json'))).digest('hex'),'c925709b5b90ca6125bcfe9d4b2ec6ba2c2320153a1825530b505b50f68edb03');
 assert.equal(createHash('sha256').update(JSON.stringify(current.recoveryFiles.map(name=>[name,current.files[name]]))).digest('hex'),'778f29c8096cda38b5402f890fbad6900d9aed56662e92de4ff4fbcd27f370ba');
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of additions)assert.ok(current.recoveryFiles.includes(name));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v203 historical source binds only manifest saved-child recovery and admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v202.json'),current=realRequire('./applicationMaintenanceInprocessSources-v203.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopMcpManifestAssessment.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1553);assert.equal(current.recoveryFiles.length,1544);
 assert.equal(current.files[changed[1]],'e5ab8cab95cd61cabff09952796d4953893c8e97d97409fdf59c083983375cbc');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v202.json'))).digest('hex'),'c925709b5b90ca6125bcfe9d4b2ec6ba2c2320153a1825530b505b50f68edb03');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v203.json'))).digest('hex'),'99d53bbfb4186c919edfdb72981cca4ad172cf88d68c9e85d67217e6193f9347');
 assert.equal(createHash('sha256').update(JSON.stringify(current.recoveryFiles.map(name=>[name,current.files[name]]))).digest('hex'),'3f9b6f3e08704987f9e002e4f43bc37185389c25bc012e34e49ea9f09200c711');
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v204 historical source binds only live customer session identity and admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v203.json'),current=realRequire('./applicationMaintenanceInprocessSources-v204.json');
 const changed=['client/src/pages/secureshop/hooks/useAgentStream.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1553);assert.equal(current.recoveryFiles.length,1544);
 assert.equal(current.files[changed[0]],'2196dbed0688e9cecd0730012a07d7b5ced72a5a4181394d7c1fa3a0e4bad2bc');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v203.json'))).digest('hex'),'99d53bbfb4186c919edfdb72981cca4ad172cf88d68c9e85d67217e6193f9347');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v204.json'))).digest('hex'),'40140cc917c5f6bb204d82ccecd30af0aa632619707504e7403bf877a24f04b6');
 assert.equal(createHash('sha256').update(JSON.stringify(current.recoveryFiles.map(name=>[name,current.files[name]]))).digest('hex'),'e4daaef6d026fe03c7fc546caf6933f85685e24cc55b8626cdb9401800b68643');
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v205 historical source binds only Express saved-search path parameters and admission pointer',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v204.json'),current=realRequire('./applicationMaintenanceInprocessSources-v205.json');
 const changed=['server/routes/secureshop/boundSearchEchoAssessment.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1553);assert.equal(current.recoveryFiles.length,1544);
 assert.equal(current.files[changed[0]],'523a3756c33aed2d10b935abcb2346c421e325d1cd082d271184c52c7bd4f3cb');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v204.json'))).digest('hex'),'40140cc917c5f6bb204d82ccecd30af0aa632619707504e7403bf877a24f04b6');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v205.json'))).digest('hex'),'0df098640ebc1ea73dd6f70de52a4c7ee32d99d25982f7f2960020178a29d80c');
 assert.equal(createHash('sha256').update(JSON.stringify(current.recoveryFiles.map(name=>[name,current.files[name]]))).digest('hex'),'988504b50b647e9255307724269d315db9d4de163655ca0e3d3941f16a16d227');
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v206 historical source binds only versioned compact search evidence and assessment dispatch',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v205.json'),current=realRequire('./applicationMaintenanceInprocessSources-v206.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopSearchEchoBrowserAssessment.js','server/services/secureshopSearchEchoBrowserEvidence.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1553);assert.equal(current.recoveryFiles.length,1544);
 assert.equal(current.files[changed[1]],'4a87e1bfcc8679e36a939b4210fd0e515775d7dc4c4afe02bc225e9d33387901');
 assert.equal(current.files[changed[2]],'86c46c66ff5d3c59c631f1c1f15bc0e5d52010ae7ba20ea636663a21f3fd0399');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v205.json'))).digest('hex'),'0df098640ebc1ea73dd6f70de52a4c7ee32d99d25982f7f2960020178a29d80c');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v206.json'))).digest('hex'),'92abcf4cc34a11115d5466259e09510d157202414a1f27aa023e3f31eabf7e4f');
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v207 historical source binds manual RAG and product-similar successor closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v206.json'),current=realRequire('./applicationMaintenanceInprocessSources-v207.json');
 const additions=[
  'client/src/pages/secureshop/hooks/useProductSimilar.js',
  'client/src/pages/secureshop/utils/productSimilarReference.mjs',
  'db/postgres/workshop-migrations/secureshop_review/0050_product_embedding_revision_preimages.sql',
  'server/database/postgres/secureshopManualRagSourceAdapter.js',
  'server/routes/secureshop/boundManualRagAssessment.js',
  'server/services/secureshopManualRagAssessment.js',
  'server/services/secureshopManualRagEvidence.js',
  'server/services/secureshopManualRagSourceContract.js',
  'server/services/secureshopManualRagSourceReader.js'
 ];
 const changes=[
  'client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/bridge/stateChannel.mjs',
  'client/src/pages/secureshop/bridge/stateStore.mjs',
  'client/src/pages/secureshop/pages/Product.jsx',
  'client/src/pages/secureshop/utils/shopStorage.mjs',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/secureshopBoundManualIngestRepository.js',
  'server/database/postgres/secureshopEmbeddingRevisionRepository.js',
  'server/database/postgres/secureshopTurnRequestsRepository.js',
  'server/routes/secureshop/boundGateway.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopAssessmentRecovery.js',
  'server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundManualIngestion.js',
  'server/services/secureshopBoundProductAssist.js',
  'server/services/secureshopBoundProductRetrieval.js',
  'server/services/secureshopBoundProductTools.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopSearchEchoBrowserEvidence.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1562);assert.equal(current.recoveryFiles.length,1553);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v206.json'))).digest('hex'),'92abcf4cc34a11115d5466259e09510d157202414a1f27aa023e3f31eabf7e4f');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v207.json'))).digest('hex'),'0e31e11c0f2deeb779e996c3113372e8e92e552640750081619b67f127072dc9');
 assert.equal(createHash('sha256').update(JSON.stringify(current.recoveryFiles.map(name=>[name,current.files[name]]))).digest('hex'),'87b4d39db50c244edfb37fa66bf215492d619d4284d9fae48362edc18ca92f84');
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of additions)assert.ok(current.recoveryFiles.includes(name));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v208 historical source binds the legitimate post-v207 recovery successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v207.json'),current=realRequire('./applicationMaintenanceInprocessSources-v208.json');
 const changed=[
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundCustomerChat.js',
  'server/services/secureshopCouponAgentContract.js',
  'server/services/secureshopIdorLessonEvidence.js',
  'server/services/secureshopSearchEchoBrowserEvidence.js'
 ];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed.slice().sort());
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1562);assert.equal(current.recoveryFiles.length,1553);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v207.json'))).digest('hex'),'0e31e11c0f2deeb779e996c3113372e8e92e552640750081619b67f127072dc9');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v208.json'))).digest('hex'),'dde22332e8173d5e584ca5518d7739a2eb116e1fcfab4d9eaf740207546edd7f');
 for(const name of changed){assert.ok(current.recoveryFiles.includes(name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v209 historical source binds the system diagnostic successor closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v208.json'),current=realRequire('./applicationMaintenanceInprocessSources-v209.json');
 const additions=[
  'db/postgres/workshop-migrations/secureshop_agents/0089_admin_system_diagnostic_prepare_registry_successor.sql',
  'client/src/pages/secureshop/components/AdminSystemDiagnosticConfirmation.jsx',
  'client/src/pages/secureshop/utils/adminSystemDiagnosticReference.mjs',
  'client/src/pages/secureshop/utils/roleSystemDiagnosticOutcome.mjs',
  'client/src/pages/secureshop/utils/roleSystemDiagnosticProposal.mjs',
  'server/services/secureshopBoundSystemDiagnosticChat.js',
  'server/services/secureshopRoleSystemDiagnosticProposal.js'
 ];
 const changes=[
  'client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/bridge/stateChannel.mjs',
  'client/src/pages/secureshop/bridge/stateStore.mjs',
  'client/src/pages/secureshop/components/BoundRoleAssistant.jsx',
  'client/src/pages/secureshop/hooks/useBoundRoleAssistant.js',
  'client/src/pages/secureshop/utils/shopStorage.mjs',
  'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
  'server/routes/secureshop/boundGateway.js',
  'server/routes/secureshop/boundRoleChat.js',
  'server/routes/secureshop/boundSystemDiagnostic.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundAclRegistry.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopBoundRoleChat.js',
  'server/services/secureshopBoundSystemDiagnosticService.js',
  'server/services/secureshopFeatureModeAuthority.js',
  'server/services/secureshopSystemDiagnosticComposition.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1569);assert.equal(current.recoveryFiles.length,1560);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v208.json'))).digest('hex'),'dde22332e8173d5e584ca5518d7739a2eb116e1fcfab4d9eaf740207546edd7f');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v209.json'))).digest('hex'),'dc7191fc20dcc415e7ae3a5489eed85e837e5fdcdd7e4722176d3cdd4ebb561e');
 for(const name of additions)assert.ok(current.recoveryFiles.includes(name));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v210 historical source binds the frontend recovery correction',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v209.json'),current=realRequire('./applicationMaintenanceInprocessSources-v210.json');
 const changes=[
  'client/src/pages/secureshop/components/AdminSystemDiagnosticConfirmation.jsx',
  'server/services/applicationMaintenanceInprocessAdmission.js'
 ];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files),Object.keys(current.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1569);assert.equal(current.recoveryFiles.length,1560);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v209.json'))).digest('hex'),'dc7191fc20dcc415e7ae3a5489eed85e837e5fdcdd7e4722176d3cdd4ebb561e');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v210.json'))).digest('hex'),'8c8d681ca938d39942236dd784170c3a07281581152acae918eab22e73d134bf');
 for(const name of changes)assert.ok(current.recoveryFiles.includes(name));
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v211 historical source binds the cart, listing and audit confirmation closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v210.json'),current=realRequire('./applicationMaintenanceInprocessSources-v211.json');
 const additions=[
  'client/src/pages/secureshop/components/AdminAuditJobConfirmation.jsx',
  'client/src/pages/secureshop/components/MerchantListingEditConfirmation.jsx'
 ];
 const changes=[
  'client/src/pages/secureshop/components/CustomerCartConfirmation.jsx',
  'client/src/pages/secureshop/components/MerchantInventoryConfirmation.jsx',
  'client/src/pages/secureshop/components/MerchantListingCreateConfirmation.jsx',
  'server/services/applicationMaintenanceInprocessAdmission.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1571);assert.equal(current.recoveryFiles.length,1562);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v210.json'))).digest('hex'),'8c8d681ca938d39942236dd784170c3a07281581152acae918eab22e73d134bf');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v211.json'))).digest('hex'),'44c3bc9e3614b94e7333c67db08ede63091d94e77815c075b103ce24bf3d9813');
 for(const name of additions)assert.ok(current.recoveryFiles.includes(name));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v212 historical source binds the catalog paging and customer/role binding closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v211.json'),current=realRequire('./applicationMaintenanceInprocessSources-v212.json');
 const additions=[
  'client/src/pages/secureshop/components/AdminAclConfirmation.jsx',
  'client/src/pages/secureshop/components/AdminAuditRead.jsx',
  'client/src/pages/secureshop/components/AdminSystemRestartConfirmation.jsx',
  'client/src/pages/secureshop/components/AdminUserConfirmation.jsx',
  'client/src/pages/secureshop/components/MerchantManualSearchCard.jsx',
  'client/src/pages/secureshop/pages/admin/aclOperation.js',
  'client/src/pages/secureshop/pages/admin/systemRestartOperation.mjs',
  'client/src/pages/secureshop/pages/admin/systemRestartRecovery.js',
  'client/src/pages/secureshop/pages/admin/userAdminOperation.js',
  'client/src/pages/secureshop/utils/catalogPage.mjs'
 ];
 const changes=[
  'client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/components/BoundAgentLane.jsx',
  'client/src/pages/secureshop/components/BoundRoleAssistant.jsx',
  'client/src/pages/secureshop/hooks/useAgentStream.js',
  'client/src/pages/secureshop/hooks/useBoundRoleAssistant.js',
  'server/database/postgres/secureshopBoundProductRepository.js',
  'server/database/postgres/secureshopConversationalCommerceRepository.js',
  'server/database/postgres/secureshopCustomerChatBindingRepository.js',
  'server/database/postgres/secureshopRoleChatBindingRepository.js',
  'server/routes/secureshop/boundCustomerChat.js',
  'server/routes/secureshop/boundRoleChat.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundCatalog.js',
  'server/services/secureshopBoundCustomerChat.js',
  'server/services/secureshopBoundRoleChat.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1581);assert.equal(current.recoveryFiles.length,1572);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v211.json'))).digest('hex'),'44c3bc9e3614b94e7333c67db08ede63091d94e77815c075b103ce24bf3d9813');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v212.json'))).digest('hex'),'d0fa4eedb89baade07e4f2dba171a5507740fb47a0ae54db064b28752483ac6b');
 for(const name of additions)assert.ok(current.recoveryFiles.includes(name));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v213 historical source binds the System diagnostic assessment closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v212.json'),current=realRequire('./applicationMaintenanceInprocessSources-v213.json');
 const additions=[
  'client/src/pages/secureshop/components/AdminSystemDiagnosticAssessment.jsx',
  'server/services/secureshopSystemDiagnosticAssessment.js',
  'server/services/secureshopSystemDiagnosticEvidence.js'
 ];
 const changes=[
  'client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/components/AdminSystemDiagnosticConfirmation.jsx',
  'server/config/secureshopCurriculum.js',
  'server/routes/secureshop/boundRoleChat.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopAssessmentRecovery.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopBoundRoleChat.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1584);assert.equal(current.recoveryFiles.length,1575);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v212.json'))).digest('hex'),'d0fa4eedb89baade07e4f2dba171a5507740fb47a0ae54db064b28752483ac6b');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v213.json'))).digest('hex'),'3ba4801eed4856f45cc4862fe22a02108683c8900e35565284ecb2a2c0fcd10d');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v213.json'));
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 for(const name of additions)assert.ok(current.recoveryFiles.includes(name));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v214 historical source binds the mobile navigation and customer chat correction',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v213.json'),current=realRequire('./applicationMaintenanceInprocessSources-v214.json');
 const changes=[
  'client/src/pages/secureshop/components/TopNav.jsx',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundCustomerChat.js',
  'server/services/secureshopSearchEchoBrowserEvidence.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1584);assert.equal(current.recoveryFiles.length,1575);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v213.json'))).digest('hex'),'3ba4801eed4856f45cc4862fe22a02108683c8900e35565284ecb2a2c0fcd10d');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v214.json'))).digest('hex'),'4b639f3580698b8ce64ee82e5e97387644d307a5f66aef6bcd9735090eafc1c4');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v214.json'));
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v215 historical source binds the System diagnostic proposal correction',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v214.json'),current=realRequire('./applicationMaintenanceInprocessSources-v215.json');
 const changes=[
  'server/config/secureshopCurriculum.js',
  'server/services/secureshopBoundRoleChat.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopRoleSystemDiagnosticProposal.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1584);assert.equal(current.recoveryFiles.length,1575);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v214.json'))).digest('hex'),'4b639f3580698b8ce64ee82e5e97387644d307a5f66aef6bcd9735090eafc1c4');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v215.json'))).digest('hex'),'2270e7b3addf85def1497d8c6e8b09a0cf263aeb4c17af159e42be866a1b2931');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v215.json'));
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v216 historical source binds the coupon and ticket reader corrections',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v215.json'),current=realRequire('./applicationMaintenanceInprocessSources-v216.json');
 const changes=[
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopCouponAgentOriginalReader.js',
  'server/services/secureshopTicketBrowserOriginalReader.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1584);assert.equal(current.recoveryFiles.length,1575);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v215.json'))).digest('hex'),'2270e7b3addf85def1497d8c6e8b09a0cf263aeb4c17af159e42be866a1b2931');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v216.json'))).digest('hex'),'0740bc6dd8223f08a9ada9eca45eaf2a4f7b2606aa1c8b6e403f1cb3dee3bd2b');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v216.json'));
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v217 historical source binds the role-chat route correction',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v216.json'),current=realRequire('./applicationMaintenanceInprocessSources-v217.json');
 const changes=[
  'server/routes/secureshop/boundRoleChat.js',
  'server/services/applicationMaintenanceInprocessAdmission.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1584);assert.equal(current.recoveryFiles.length,1575);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v216.json'))).digest('hex'),'0740bc6dd8223f08a9ada9eca45eaf2a4f7b2606aa1c8b6e403f1cb3dee3bd2b');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v217.json'))).digest('hex'),'f9748918cc91dcdc5acd81dde78e5a44c23742507da5ad9764a7086724bd3ccd');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v217.json'));
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v218 historical source binds the coupon GET route correction',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v217.json'),current=realRequire('./applicationMaintenanceInprocessSources-v218.json');
 const changes=[
  'server/routes/secureshop/boundCouponAgentAssessment.js',
  'server/services/applicationMaintenanceInprocessAdmission.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1584);assert.equal(current.recoveryFiles.length,1575);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v217.json'))).digest('hex'),'f9748918cc91dcdc5acd81dde78e5a44c23742507da5ad9764a7086724bd3ccd');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v218.json'))).digest('hex'),'3a57a98432f153c1feb6e91cc740eff55e9c31a6d6a39c7ad30bc6c22e62cadf');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v218.json'));
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v219 historical source binds the coupon Judge citation successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v218.json'),current=realRequire('./applicationMaintenanceInprocessSources-v219.json');
 const changes=[
  'server/agent-runtime/objectiveJudge.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopCouponAgentAssessment.js',
  'server/services/secureshopCouponAgentEvidence.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1584);assert.equal(current.recoveryFiles.length,1575);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v218.json'))).digest('hex'),'3a57a98432f153c1feb6e91cc740eff55e9c31a6d6a39c7ad30bc6c22e62cadf');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v219.json'))).digest('hex'),'246f54d85229ead1d2cc07936b18cc128db84fd9911fb02312053ebab8310d18');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v219.json'));
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 denied(()=>bindingWith({},current)(ROOT));
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v220 historical source binds the V36, V52, and V55 closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v219.json'),current=realRequire('./applicationMaintenanceInprocessSources-v220.json');
 const additions=[
    "client/src/pages/secureshop/components/Dialog.jsx",
    "client/src/pages/secureshop/components/Input.jsx",
    "client/src/pages/secureshop/components/MailMessageBody.jsx",
    "client/src/pages/secureshop/components/PersonaInboxLab.jsx",
    "client/src/pages/secureshop/pages/Inbox.jsx",
    "client/src/pages/secureshop/pages/MailAssessment.jsx",
    "client/src/pages/secureshop/pages/MailCapabilityStatus.jsx",
    "client/src/pages/secureshop/pages/admin/Audit.jsx",
    "client/src/pages/secureshop/pages/mailRequests.js",
    "client/src/pages/secureshop/pages/merchant/Inbox.jsx",
    "db/postgres/workshop-migrations/secureshop_agents/0090_bound_mail_inline_binding.sql",
    "db/postgres/workshop-migrations/secureshop_agents/0091_mail_summary_conversation_purpose.sql",
    "db/postgres/workshop-migrations/secureshop_agents/0092_mail_summary_registry_successor.sql",
    "db/postgres/workshop-migrations/secureshop_agents/0093_audit_unbounded_and_timing_purposes.sql",
    "db/postgres/workshop-migrations/secureshop_agents/0094_bound_mail_inline_generation_zero.sql",
    "server/database/postgres/secureshopMailInlineBindingRepository.js",
    "server/database/postgres/secureshopMailInlineEvidenceRepository.js",
    "server/routes/secureshop/boundMailInline.js",
    "server/services/secureshopAuditUnboundedAssessment.js",
    "server/services/secureshopAuditUnboundedEvidence.js",
    "server/services/secureshopAuditUnboundedWitnessReader.js",
    "server/services/secureshopBoundMailSummaryGraph.js",
    "server/services/secureshopMailInlineApplication.js",
    "server/services/secureshopMailInlineAssessment.js",
    "server/services/secureshopMailInlineEvidence.js",
    "server/services/secureshopMailInlineHttpAdapter.js",
    "server/services/secureshopMailInlineProduction.js",
    "server/services/secureshopMailInlineTargetPool.js",
    "server/services/secureshopOwnedAuditTimingAssessment.js"
  ];
 const changes=[
    "client/src/pages/secureshop/bridge/mailReferences.mjs",
    "client/src/pages/secureshop/bridge/operations.mjs",
    "client/src/pages/secureshop/components/BoundRoleAssistant.jsx",
    "client/src/pages/secureshop/components/MerchantMailReadCard.jsx",
    "db/postgres/migrate.js",
    "server/config/secureshopCurriculum.js",
    "server/database/postgres/secureshopAuditQueryRepository.js",
    "server/database/postgres/secureshopBoundToolPolicyReadiness.js",
    "server/routes/secureshop/boundGateway.js",
    "server/services/applicationMaintenanceInprocessAdmission.js",
    "server/services/secureshopAssessmentRecovery.js",
    "server/services/secureshopAuditRunner.js",
    "server/services/secureshopAuditRuntime.js",
    "server/services/secureshopAuditWorkerHost.js",
    "server/services/secureshopBoundAclRegistry.js",
    "server/services/secureshopBoundApplication.js",
    "server/services/secureshopBoundReviewComposition.js",
    "server/services/secureshopBoundShutdown.js",
    "server/services/secureshopCleanupComposition.js",
    "server/services/secureshopConversationPurpose.js",
    "server/services/secureshopMailProduction.js",
    "server/services/secureshopOwnedAuditComposition.js",
    "server/services/secureshopOwnedAuditSearchApplication.js",
    "server/services/secureshopOwnedAuditSearchBackend.js",
    "sidecars/audit-sql-target/service.js"
  ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1613);assert.equal(current.recoveryFiles.length,1604);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v219.json'))).digest('hex'),'246f54d85229ead1d2cc07936b18cc128db84fd9911fb02312053ebab8310d18');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v220.json'))).digest('hex'),'8cc7db37cce5fe452fdcc6114b5d07bd0d6b7f5a9046a4cff70e3454071d06ae');
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v221 historical source binds the post-run UI successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v220.json'),current=realRequire('./applicationMaintenanceInprocessSources-v221.json');
 const changes=[
    "client/src/pages/secureshop/components/BoundAgentLane.jsx",
    "client/src/pages/secureshop/hooks/useAgentStream.js",
    "server/services/applicationMaintenanceInprocessAdmission.js"
  ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1613);assert.equal(current.recoveryFiles.length,1604);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v220.json'))).digest('hex'),'8cc7db37cce5fe452fdcc6114b5d07bd0d6b7f5a9046a4cff70e3454071d06ae');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v221.json'))).digest('hex'),'e0c3577fa14162e55f013886338734e931eb21e1cdd3252ebe31565f89a5381f');
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v222 historical source binds the final BoundAgentLane UI fence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v221.json'),current=realRequire('./applicationMaintenanceInprocessSources-v222.json');
 const changes=[
    "client/src/pages/secureshop/components/BoundAgentLane.jsx",
    "server/services/applicationMaintenanceInprocessAdmission.js"
  ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1613);assert.equal(current.recoveryFiles.length,1604);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v221.json'))).digest('hex'),'e0c3577fa14162e55f013886338734e931eb21e1cdd3252ebe31565f89a5381f');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v222.json'))).digest('hex'),'9402990981609fbc88109cc74e028cb46c3f26e87be1218fafa605ac86183266');
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v223 historical source binds mail phase availability',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v222.json'),current=realRequire('./applicationMaintenanceInprocessSources-v223.json');
 const changes=[
    "server/services/applicationMaintenanceInprocessAdmission.js",
    "server/services/secureshopBoundMailSummaryGraph.js"
  ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1613);assert.equal(current.recoveryFiles.length,1604);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v222.json'))).digest('hex'),'9402990981609fbc88109cc74e028cb46c3f26e87be1218fafa605ac86183266');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v223.json'))).digest('hex'),'765a7493b52ec0fad608639a7df038353c68ce6d2a800c7d33e89ff365ff9076');
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v224 historical source binds mail retry diagnostics and dynamic worker',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v223.json'),current=realRequire('./applicationMaintenanceInprocessSources-v224.json');
 const changes=[
    "server/services/applicationMaintenanceInprocessAdmission.js",
    "server/services/secureshopAuditWorkerHost.js",
    "server/services/secureshopBoundMailSummaryGraph.js"
  ], additions=["server/agent-runtime/workers/secureshopAuditWorker.js"];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1614);assert.equal(current.recoveryFiles.length,1605);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v223.json'))).digest('hex'),'765a7493b52ec0fad608639a7df038353c68ce6d2a800c7d33e89ff365ff9076');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v224.json'))).digest('hex'),'3eb972c2d2d3f88b7a2e1e15b0938b09cce60447f688c016fb09b9db0fba9931');
 for(const name of [...changes,...additions])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v225 historical source binds V55 index-zero evidence and V36 v2 audit closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v224.json'),current=realRequire('./applicationMaintenanceInprocessSources-v225.json');
 const changes=[
    'server/agent-runtime/secureshopAuditSummaryGraph.js',
    'server/agent-runtime/workers/secureshopAuditWorker.js',
    'server/database/postgres/secureshopMailInlineEvidenceRepository.js',
    'server/services/applicationMaintenanceInprocessAdmission.js',
    'server/services/secureshopAuditModelChain.js',
    'server/services/secureshopAuditSummaryObservation.js',
    'server/services/secureshopAuditUnboundedEvidence.js',
    'server/services/secureshopAuditVerifiedEvidence.js',
    'server/services/secureshopMailInlineEvidence.js'
  ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1614);assert.equal(current.recoveryFiles.length,1605);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v224.json'))).digest('hex'),'3eb972c2d2d3f88b7a2e1e15b0938b09cce60447f688c016fb09b9db0fba9931');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v225.json'))).digest('hex'),'814f11f0ecd39f74516aa325196f107575aab51786ec9bda9044bb517e9a43ae');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v226 historical source binds lossless V55 trace references',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v225.json'),current=realRequire('./applicationMaintenanceInprocessSources-v226.json');
 const changes=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopMailInlineEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1614);assert.equal(current.recoveryFiles.length,1605);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v225.json'))).digest('hex'),'814f11f0ecd39f74516aa325196f107575aab51786ec9bda9044bb517e9a43ae');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v226.json'))).digest('hex'),'e8c0a0df06f4ac30e2faf5efa515a718476ebc45d60cbc91ada7df05ee640085');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v227 active source binds lossless V55 duplicate trace identifiers',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v226.json'),current=realRequire('./applicationMaintenanceInprocessSources-v227.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v227.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v227\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changes=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopMailInlineEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes.slice().sort());
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1614);assert.equal(current.recoveryFiles.length,1605);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v226.json'))).digest('hex'),'e8c0a0df06f4ac30e2faf5efa515a718476ebc45d60cbc91ada7df05ee640085');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v227.json'))).digest('hex'),'ed597623af8101de7499cf6f7a7337547be012422453f046c95508ac9fead39e');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v228 active source binds V48 coupon-probe runtime, frontend, and migration closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v227.json'),current=realRequire('./applicationMaintenanceInprocessSources-v228.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v228.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v228\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const additions=[
  'client/src/pages/secureshop/components/CouponProbePanel.jsx',
  'client/src/pages/secureshop/utils/customerCouponProbeReference.mjs',
  'db/postgres/workshop-migrations/secureshop_agents/0095_coupon_probe_conversation_purpose.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0096_coupon_probe_registry_successor.sql',
  'server/database/postgres/secureshopCouponBlindEvidenceRepository.js',
  'server/routes/secureshop/boundCouponProbe.js',
  'server/services/secureshopBoundCouponProbeGraph.js',
  'server/services/secureshopCouponBlindAssessment.js',
  'server/services/secureshopCouponBlindEvidence.js',
  'server/services/secureshopCouponProbeApplication.js',
  'server/services/secureshopCouponProbeComposition.js',
  'server/services/secureshopCouponProbeContract.js',
  'server/services/secureshopCouponProbeProduction.js'
 ].sort();
 const changes=[
  'client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/bridge/stateChannel.mjs',
  'client/src/pages/secureshop/bridge/stateStore.mjs',
  'client/src/pages/secureshop/pages/Cart.jsx',
  'client/src/pages/secureshop/utils/shopStorage.mjs',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
  'server/routes/secureshop/boundGateway.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopAnalyticsLifecycle.js',
  'server/services/secureshopAssessmentRecovery.js',
  'server/services/secureshopBoundAclRegistry.js',
  'server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundCustomerChat.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopConversationPurpose.js',
  'server/services/secureshopMailInlineAssessment.js',
  'server/services/secureshopMailInlineEvidence.js',
  'server/services/secureshopOwnedAnalyticsProduction.js',
  'sidecars/analytics-sql-target/fixture.js',
  'sidecars/analytics-sql-target/service.js'
 ].sort();
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1627);assert.equal(current.recoveryFiles.length,1618);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v227.json'))).digest('hex'),'ed597623af8101de7499cf6f7a7337547be012422453f046c95508ac9fead39e');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v228.json'))).digest('hex'),'918152c53720680cb650a34be9231e7c189035e1e2e9a8222507b92d82064adf');
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v229 historical source binds the corrected never-applied coupon probe registry migration',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v228.json'),current=realRequire('./applicationMaintenanceInprocessSources-v229.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v229.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v229\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changes=[
  'db/postgres/workshop-migrations/secureshop_agents/0096_coupon_probe_registry_successor.sql',
  'server/services/applicationMaintenanceInprocessAdmission.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1627);assert.equal(current.recoveryFiles.length,1618);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v228.json'))).digest('hex'),'918152c53720680cb650a34be9231e7c189035e1e2e9a8222507b92d82064adf');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v229.json'))).digest('hex'),'1aaba9b8f5f9ff55487a5a41ca60f9ee4a8f113601f2251a11576a58658d773f');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v230 historical pre-final candidate binds the V55 v3 evidence and application Node runtime contract',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v229.json'),current=realRequire('./applicationMaintenanceInprocessSources-v230.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v230.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v230\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changes=[
  'package-lock.json',
  'package.json',
  'scripts/application-node-runtime.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopMailInlineAssessment.js',
  'server/services/secureshopMailInlineEvidence.js'
 ];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1627);assert.equal(current.recoveryFiles.length,1618);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v229.json'))).digest('hex'),'1aaba9b8f5f9ff55487a5a41ca60f9ee4a8f113601f2251a11576a58658d773f');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v230.json'))).digest('hex'),'954a1090dd39a44eb5e7b33e3162730410566bfe4210f1fa526ac44ef720f932');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v231 active source binds the corrected V55 v3 source-context evidence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v230.json'),current=realRequire('./applicationMaintenanceInprocessSources-v231.json');
 const changes=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopMailInlineEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1627);assert.equal(current.recoveryFiles.length,1618);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v230.json'))).digest('hex'),'954a1090dd39a44eb5e7b33e3162730410566bfe4210f1fa526ac44ef720f932');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v231.json'))).digest('hex'),'af259edec4a7700eb49f0ad22455bc2a4e7ecc1695634a63c19ae2c748d64ee3');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v235 historical source binds frozen V55 v6, V48 graph, and launcher closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v234.json'),current=realRequire('./applicationMaintenanceInprocessSources-v235.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v235.json'));
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v235\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changes=['server/agent-runtime/objectiveJudge.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCouponProbeGraph.js','server/services/secureshopMailInlineAssessment.js','server/services/secureshopMailInlineEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1627);assert.equal(current.recoveryFiles.length,1618);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v234.json'))).digest('hex'),'dc2d6afcf1c9954d0d243fe31d293864ef4ce3082cb2e7b588d2e9838d685d5b');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v235.json'))).digest('hex'),'06b61a91b621bd97d770f0ae30d8655d73fb05cc17571b240eed6bdfda465fec');
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v236 historical source binds V53 product-search ACL, migration, and rendered recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v235.json'),current=realRequire('./applicationMaintenanceInprocessSources-v236.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v236.json'));
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v236\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const additions=['client/src/pages/secureshop/hooks/useCustomerProductSearchLesson.js','db/postgres/workshop-migrations/secureshop_agents/0097_product_search_union_conversation_purpose.sql','db/postgres/workshop-migrations/secureshop_agents/0098_product_search_union_registry_successor.sql','server/services/secureshopProductSearchComposition.js','server/services/secureshopProductSearchProduction.js','server/services/secureshopProductSearchSqlContract.js'].sort();
 const changes=['client/src/pages/secureshop/bridge/operations.mjs','client/src/pages/secureshop/components/BoundAgentLane.jsx','client/src/pages/secureshop/utils/shopStorage.mjs','server/config/secureshopCurriculum.js','server/database/postgres/secureshopBoundToolPolicyReadiness.js','server/routes/secureshop/boundGateway.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopAnalyticsLifecycle.js','server/services/secureshopAssessmentRecovery.js','server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundApplication.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopConversationPurpose.js','server/services/secureshopFeatureModeAuthority.js','server/services/secureshopOwnedAnalyticsProduction.js','sidecars/analytics-sql-target/service.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1633);assert.equal(current.recoveryFiles.length,1624);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v235.json'))).digest('hex'),'06b61a91b621bd97d770f0ae30d8655d73fb05cc17571b240eed6bdfda465fec');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v236.json'))).digest('hex'),'0992a71f99a913d2ba73ad92a70a8000b5ceb41cf7d1ed2fa003d16b8a686a7a');
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v237 historical source binds product-search bridge state recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v236.json'),current=realRequire('./applicationMaintenanceInprocessSources-v237.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v237.json'));
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v237\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const additions=['client/src/pages/secureshop/utils/customerProductSearchReference.mjs'];
 const changes=['client/src/pages/secureshop/bridge/stateChannel.mjs','client/src/pages/secureshop/bridge/stateStore.mjs','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1634);assert.equal(current.recoveryFiles.length,1625);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v236.json'))).digest('hex'),'0992a71f99a913d2ba73ad92a70a8000b5ceb41cf7d1ed2fa003d16b8a686a7a');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v237.json'))).digest('hex'),'b103028a24a1c841352a88e6186c5db53f49259a95fd058b6797bd7d537b9ee5');
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v238 historical source binds V53 eligibility and V60 diagnostic evidence closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v237.json'),current=realRequire('./applicationMaintenanceInprocessSources-v238.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v238.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v238\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 const additions=[];
 const changes=['client/src/pages/secureshop/components/BoundAgentLane.jsx','client/src/pages/secureshop/hooks/useCustomerProductSearchLesson.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopSearchEchoBrowserEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1634);assert.equal(current.recoveryFiles.length,1625);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v237.json'))).digest('hex'),'b103028a24a1c841352a88e6186c5db53f49259a95fd058b6797bd7d537b9ee5');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v238.json'))).digest('hex'),'66fce57f075541b89e9289f6810400c73e2f683a28a87e4716b7aceb87ad068d');
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v239 historical source binds product-search hook error-body drain recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v238.json'),current=realRequire('./applicationMaintenanceInprocessSources-v239.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v239.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v239\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 const changes=['client/src/pages/secureshop/hooks/useCustomerProductSearchLesson.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1634);assert.equal(current.recoveryFiles.length,1625);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v238.json'))).digest('hex'),'66fce57f075541b89e9289f6810400c73e2f683a28a87e4716b7aceb87ad068d');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v239.json'))).digest('hex'),'178ac36684c951954a15e07ca8da210b4b0564a34bd48e1373e34ba800bb2bfb');
 denied(()=>historical.sourceBinding(ROOT));
 // Historical v239 remains immutable evidence; it must not be asserted against the current v240 checkout.
 assert.equal(current.files['server/services/applicationMaintenanceInprocessAdmission.js'],createHash('sha256').update(frozenAdmissionBytes).digest('hex'));
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v240 active source binds order-status analytics closure and 0099 migration',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v239.json'),current=realRequire('./applicationMaintenanceInprocessSources-v240.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v240.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v240\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 const additions=['client/src/pages/secureshop/hooks/useCustomerOrderStatusLesson.js','client/src/pages/secureshop/utils/customerOrderStatusReference.mjs','db/postgres/bootstrap-admin.js','db/postgres/workshop-migrations/secureshop_agents/0099_order_status_error_conversation_purpose.sql','scripts/install/analytics-activate.js','scripts/install/analytics-setup.js','scripts/install/analytics-target.js','scripts/install/coupons-setup.js','scripts/install/ctf-delivery-setup.js','scripts/install/manifests/secureshop-owned-mcp-registry-build.json','scripts/install/secureshop-owned-mcp-registry-setup.js','scripts/install/secureshop-owned-mcp-registry.js','scripts/install/secureshop-owned-system-activate.js','scripts/install/secureshop-qualified-system-setup.js','scripts/lib/setup-environment-publication.js','scripts/lib/setup-password-reset-key.js','scripts/verify-embedding-runtime.js','server/database/postgres/secureshopOrderStatusErrorEvidenceRepository.js','server/database/postgres/secureshopProductUnionEvidenceRepository.js','server/routes/secureshop/boundOrderStatus.js','server/routes/secureshop/boundProductSearch.js','server/services/applicationDatabaseEngine.js','server/services/secureshopBoundOrderStatusGraph.js','server/services/secureshopBoundProductSearchGraph.js','server/services/secureshopOrderStatusApplication.js','server/services/secureshopOrderStatusComposition.js','server/services/secureshopOrderStatusErrorAssessment.js','server/services/secureshopOrderStatusErrorEvidence.js','server/services/secureshopOrderStatusProduction.js','server/services/secureshopOrderStatusSqlContract.js','server/services/secureshopProductSearchApplication.js','server/services/secureshopProductUnionAssessment.js','server/services/secureshopProductUnionEvidence.js'].sort();
 const changes=['client/src/pages/secureshop/bridge/operations.mjs','client/src/pages/secureshop/bridge/stateChannel.mjs','client/src/pages/secureshop/bridge/stateStore.mjs','client/src/pages/secureshop/components/BoundAgentLane.jsx','client/src/pages/secureshop/utils/shopStorage.mjs','server/agent-runtime/objectiveJudge.js','server/config/secureshopCurriculum.js','server/routes/secureshop/boundGateway.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshop/providers/ollamaProvider.js','server/services/secureshopAnalyticsLifecycle.js','server/services/secureshopAssessmentRecovery.js','server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundApplication.js','server/services/secureshopBoundCustomerChat.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopConversationPurpose.js','server/services/secureshopFeatureModeAuthority.js','server/services/secureshopOwnedAnalyticsProduction.js','server/services/secureshopSearchEchoBrowserEvidence.js','sidecars/analytics-sql-target/executor.js','sidecars/analytics-sql-target/service.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1667);assert.equal(current.recoveryFiles.length,1658);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v239.json'))).digest('hex'),'178ac36684c951954a15e07ca8da210b4b0564a34bd48e1373e34ba800bb2bfb');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v240.json'))).digest('hex'),'5337e4475ff09e4f309933aa690a6153479b35e5623cc51617f4dd8f74855a8d');
 denied(()=>historical.sourceBinding(ROOT));
 // v240 remains immutable historical evidence and is not asserted against the current v241 checkout.
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v241 historical source preserves exact V53 assessment seed transition',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v240.json'),current=realRequire('./applicationMaintenanceInprocessSources-v241.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v241.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v241\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 const additions=[];
 const changes=['server/database/postgres/secureshopAssessmentSeed.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1667);assert.equal(current.recoveryFiles.length,1658);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v240.json'))).digest('hex'),'5337e4475ff09e4f309933aa690a6153479b35e5623cc51617f4dd8f74855a8d');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v241.json'))).digest('hex'),'c94ab93e3151060c2a4c10cc8388d8e72429dcbf66aa73dd69800cc5b3133739');
 denied(()=>historical.sourceBinding(ROOT));
 // v241 remains immutable historical evidence and is not asserted against current v242 checkout.
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v242 historical source preserves V39 description assessment, V50 v2 evidence, and V60 v7 controls',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v241.json'),current=realRequire('./applicationMaintenanceInprocessSources-v242.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v242.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v242\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const additions=['server/database/postgres/secureshopMcpDescriptionEvidenceRepository.js','server/services/secureshopMcpDescriptionAssessment.js','server/services/secureshopMcpDescriptionEvidence.js','tests/secureshopOrderStatusApplication.test.js','tests/secureshopOrderStatusErrorEvidence.test.js','tests/secureshopOrderStatusErrorEvidenceRepository.test.js','tests/secureshopOrderStatusErrorV2Evidence.test.js','tests/secureshopSearchEchoMarkupCounterfactual.test.js'].sort();
 const changes=['client/src/pages/secureshop/bridge/operations.mjs','client/src/pages/secureshop/components/RegisteredAdminConversation.jsx','client/src/pages/secureshop/hooks/useRegisteredAdminStream.js','server/agent-runtime/objectiveJudge.js','server/config/secureshopCurriculum.js','server/database/postgres/secureshopOwnedMcpRegistryRepository.js','server/routes/secureshop/boundAdminChat.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshop/providers/ollamaProvider.js','server/services/secureshopAssessmentRecovery.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopOrderStatusErrorEvidence.js','server/services/secureshopRegisteredAdminRuntime.js','server/services/secureshopRegisteredInvocationProduction.js','server/services/secureshopRegisteredTurnTools.js','server/services/secureshopSearchEchoBrowserEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1675);assert.equal(current.recoveryFiles.length,1666);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v241.json'))).digest('hex'),'c94ab93e3151060c2a4c10cc8388d8e72429dcbf66aa73dd69800cc5b3133739');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v242.json'))).digest('hex'),'c5b6aa276e0f3e9806258d169a3c432442faccf06884be4a4c3093ee7356100a');
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v243 historical source binds the V50 order-status native seed successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v242.json'),current=realRequire('./applicationMaintenanceInprocessSources-v243.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v243.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v243\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const additions=[];
 const changes=['server/config/secureshopCurriculum.js','server/database/postgres/secureshopAssessmentSeed.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1675);assert.equal(current.recoveryFiles.length,1666);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v242.json'))).digest('hex'),'c5b6aa276e0f3e9806258d169a3c432442faccf06884be4a4c3093ee7356100a');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v243.json'))).digest('hex'),'246e7807941dac456011f1940b31e924856fb2e624dd087da607d465c6f7ad6e');
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v244 historical source binds the V48 coupon probe and V60 search echo successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v243.json'),current=realRequire('./applicationMaintenanceInprocessSources-v244.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v244.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v244\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const additions=['server/services/secureshopCouponProbeGuidedProtocol.js','server/services/secureshopCouponProbeRequest.js'].sort();
 const changes=['client/src/pages/secureshop/bridge/operations.mjs','client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx','client/src/pages/secureshop/components/CouponProbePanel.jsx','client/src/pages/secureshop/searchEchoClientRenderer.jsx','server/agent-runtime/objectiveJudge.js','server/database/postgres/secureshopCouponBlindEvidenceRepository.js','server/routes/secureshop/boundCouponProbe.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundCouponProbeGraph.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopCouponProbeApplication.js','server/services/secureshopSearchEchoBrowserAssessment.js','server/services/secureshopSearchEchoBrowserEvidence.js','server/services/secureshopSearchEchoBrowserQualification.js','server/services/xssBrowserQualification.js'].sort();
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1677);assert.equal(current.recoveryFiles.length,1668);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v243.json'))).digest('hex'),'246e7807941dac456011f1940b31e924856fb2e624dd087da607d465c6f7ad6e');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v244.json'))).digest('hex'),'1de86e9b2cb2e2ca3a986e353b8b3ce2eaf0e6cb2d2c83c16ce6cac3979fee99');
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v245 historical source binds only the V39 sidecar build manifest successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v244.json'),current=realRequire('./applicationMaintenanceInprocessSources-v245.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v245.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v245\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changes=['scripts/install/manifests/secureshop-owned-mcp-registry-build.json','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1677);assert.equal(current.recoveryFiles.length,1668);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v244.json'))).digest('hex'),'1de86e9b2cb2e2ca3a986e353b8b3ce2eaf0e6cb2d2c83c16ce6cac3979fee99');
 assert.equal(current.files['scripts/install/manifests/secureshop-owned-mcp-registry-build.json'],'7121b861cb7c7be4eff00d3dbba0446ccabfdce33e98422c76bb5b1823a0d048');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v245.json'))).digest('hex'),'07f4b364aae594cdf10890ce170dfcc6529231d18b7844be34a94b1fa472add2');
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v246 historical source binds only the V60 symmetric V8 Judge successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v245.json'),current=realRequire('./applicationMaintenanceInprocessSources-v246.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v246.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v246\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changes=['server/agent-runtime/objectiveJudge.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1677);assert.equal(current.recoveryFiles.length,1668);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v245.json'))).digest('hex'),'07f4b364aae594cdf10890ce170dfcc6529231d18b7844be34a94b1fa472add2');
 assert.equal(current.files['server/agent-runtime/objectiveJudge.js'],'947af720a507a68217e366014d3e2ce69d20ad22b33d6ca687b9fa3531a8c429');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v246.json'))).digest('hex'),'8c268c9a835fa5d51afa680518f4cdc277581db878da71db4f03b7f3faf50591');
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v247 historical source binds only the V39 evidence endpoint successor',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v246.json'),current=realRequire('./applicationMaintenanceInprocessSources-v247.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v247.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v247\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const changes=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopMcpDescriptionEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1677);assert.equal(current.recoveryFiles.length,1668);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v246.json'))).digest('hex'),'8c268c9a835fa5d51afa680518f4cdc277581db878da71db4f03b7f3faf50591');
 assert.equal(current.files['server/services/secureshopMcpDescriptionEvidence.js'],'4a07e4ab6d543caa2a6a4f53a7ef8ef4e9fa2efd14a913645b23cab9330f626a');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v247.json'))).digest('hex'),'859241f1487b6d765e31e39221874e0105401772d8c5132f975eeaf7110e36f5');
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v248 historical source binds the reviewed V04 restart receipt closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v247.json'),current=realRequire('./applicationMaintenanceInprocessSources-v248.json');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v248.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v248\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const additions=['client/src/pages/secureshop/components/AdminSystemRestartAssessment.jsx',
  'db/postgres/workshop-migrations/secureshop_review/0051_bound_system_restart_full_receipts.sql',
  'server/services/secureshopSystemRestartInjectionAssessment.js',
  'server/services/secureshopSystemRestartInjectionEvidence.js'];
 const changes=['client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/components/AdminSystemRestartConfirmation.jsx',
  'client/src/pages/secureshop/components/BoundRoleAssistant.jsx',
  'client/src/pages/secureshop/utils/roleAssistantCompletedReferences.mjs',
  'client/src/pages/secureshop/utils/roleAssistantReferences.mjs',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/secureshopSystemRestartRepository.js',
  'server/routes/secureshop/boundRoleChat.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopAssessmentRecovery.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopBoundRoleChat.js',
  'server/services/secureshopBoundSystemRestartService.js',
  'server/services/secureshopFeatureModeAuthority.js',
  'server/services/secureshopSystemRestartComposition.js',
  'sidecars/sandbox-runner/owned-system/restart-command-executor.js',
  'sidecars/sandbox-runner/owned-system/restart-wire.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1681);assert.equal(current.recoveryFiles.length,1672);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v247.json'))).digest('hex'),'859241f1487b6d765e31e39221874e0105401772d8c5132f975eeaf7110e36f5');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v248.json'))).digest('hex'),'86ee0c93858e993ef2433d50528cd5fe749d87c126ea36ff11e3226eba63d759');
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v249 historical source binds the V48, V60 V9, and V39 successor closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v248.json'),current=realRequire('./applicationMaintenanceInprocessSources-v249.json');
 const additions=['db/postgres/workshop-migrations/secureshop_agents/0100_coupon_probe_guided_v2_registry_successor.sql',
  'server/services/secureshopCouponProbeArithmetic.js'];
 const changes=['client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/components/CouponProbePanel.jsx',
  'scripts/install/manifests/secureshop-owned-mcp-registry-build.json',
  'server/agent-runtime/objectiveJudge.js',
  'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
  'server/database/postgres/secureshopCouponBlindEvidenceRepository.js',
  'server/routes/secureshop/boundCouponProbe.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundAclRegistry.js',
  'server/services/secureshopBoundCouponProbeGraph.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopCouponBlindEvidence.js',
  'server/services/secureshopCouponProbeApplication.js',
  'server/services/secureshopCouponProbeRequest.js',
  'server/services/secureshopSearchEchoBrowserAssessment.js',
  'server/services/secureshopSearchEchoBrowserEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v248.json'))).digest('hex'),'86ee0c93858e993ef2433d50528cd5fe749d87c126ea36ff11e3226eba63d759');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v249.json'))).digest('hex'),'f8fa6957669f020e5a113bd2fc483411aae192e0bd34015cb5809e1deb0cfae9');
 assert.equal(current.files['server/services/secureshopCouponProbeArithmetic.js'],'e582ca453fc0e2de0f1a2ccc9dea2b2cace80a4a8fad846783e865618480bd68');
 const frozenAdmissionBytes=Buffer.from(fs.readFileSync(file,'utf8').replaceAll(activeManifest.slice(2),'applicationMaintenanceInprocessSources-v249.json'));
 assert.equal((frozenAdmissionBytes.toString('utf8').match(/applicationMaintenanceInprocessSources-v249\.json/g)||[]).length,2);
 assert.equal(createHash('sha256').update(frozenAdmissionBytes).digest('hex'),current.files['server/services/applicationMaintenanceInprocessAdmission.js']);
 const historical=admissionWith({},current,undefined,frozenAdmissionBytes.toString('utf8'));
 denied(()=>historical.sourceBinding(ROOT));
 for(const name of [...additions,...changes])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v250 historical source binds the reviewed 0100 guard correction',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v249.json'),current=realRequire('./applicationMaintenanceInprocessSources-v250.json');
 const changes=['db/postgres/workshop-migrations/secureshop_agents/0100_coupon_probe_guided_v2_registry_successor.sql',
  'server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v249.json'))).digest('hex'),'f8fa6957669f020e5a113bd2fc483411aae192e0bd34015cb5809e1deb0cfae9');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v250.json'))).digest('hex'),'e91a708083e2858d2f03f0cb599b5d83d24c55302f1cdcbcc09cb3e902be6b4a');
 assert.equal(current.files[changes[0]],'a8f4ddce46bffa828ffdaed330b63351628ff3a58ed1fdc6e6ff13522b90e6e4');
 assertHistoricalBinding(250,current,'182156f52c09f552f8f884b22f457c0b2025a645eb5e163b9de1367f7e888429','ff1879e3e5ab36eb73210c1caa695158bdb68a137ededb14118c3cfa1c3d3b0b');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v251 historical source binds reviewed judgment persistence and restart hydration',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v250.json'),current=realRequire('./applicationMaintenanceInprocessSources-v251.json');
 const changes=['client/src/pages/secureshop/components/AdminSystemRestartConfirmation.jsx',
  'server/database/postgres/objectiveJudgmentRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v250.json'))).digest('hex'),'e91a708083e2858d2f03f0cb599b5d83d24c55302f1cdcbcc09cb3e902be6b4a');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v251.json'))).digest('hex'),'b121b672891d4a66938fe193f53208ac986da9e0b4fb5d68e6151da3faaba891');
 assert.equal(current.files[changes[0]],'a16483399fa4832c5f070b53d29beee7d3377229bd14f2fde788540f1bc188fa');
 assert.equal(current.files[changes[1]],'cb26e5facd163def2a33a6e8ba9bac8de8a0fe3c2b7e400857dc1f57882648ac');
 assert.equal(current.files[changes[2]],'43020784cd4ddb7e84e9a9dfb19aa865cb1fb31911a64fa7eb1a398a52f8f834');
 assertHistoricalBinding(251,current,'b6363313b0e0be04320320ddbf44829f1734f2dbe7c8096ee0103b66279a11a0','a780d65ca8acb2e9bb8db727dd8bd5bdeed31e98d2f62259e3038f3e233dde55');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v252 historical source binds reviewed curriculum evidence and role callback cleanup',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v251.json'),current=realRequire('./applicationMaintenanceInprocessSources-v252.json');
 const changes=['client/src/pages/secureshop/components/BoundRoleAssistant.jsx',
  'server/config/secureshopCurriculum.js',
  'server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v251.json'))).digest('hex'),'b121b672891d4a66938fe193f53208ac986da9e0b4fb5d68e6151da3faaba891');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v252.json'))).digest('hex'),'7003f3fcf6b8b6347627bc0c64e1e7be9e2ec93fc018da97bb0749e0bbe27f39');
 assert.equal(current.files[changes[0]],'99e6ddf4bb3f835bbc7a245c6f98f57ee11702891fe78a36b4a16ad8e4be5167');
 assert.equal(current.files[changes[1]],'307e72deef338f29c0b02dc2954b2ed65a72072aefe49022d11bb46fdfba27c2');
 assert.equal(current.files[changes[2]],'1a56e817ca226c46596190c1a5cf5c554e57c174ebf08eccd16f0873678fa095');
 assertHistoricalBinding(252,current,'7003f3fcf6b8b6347627bc0c64e1e7be9e2ec93fc018da97bb0749e0bbe27f39','a865b612243e341cbe43a61049e19a9a81ecab56651fb4a359e53f7f6bb739fe');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v253 historical source binds reviewed coupon continuation, V39 rubric, and V04 promotion',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v252.json'),current=realRequire('./applicationMaintenanceInprocessSources-v253.json');
 const changes=['client/src/pages/secureshop/components/CouponProbePanel.jsx',
  'server/agent-runtime/secureshopSupervisorGraph.js',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/secureshopAssessmentSeed.js',
  'server/database/postgres/secureshopCouponBlindEvidenceRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundAgentRunner.js',
  'server/services/secureshopBoundCouponProbeGraph.js',
  'server/services/secureshopCouponBlindEvidence.js',
  'server/services/secureshopCouponProbeApplication.js',
  'server/services/secureshopCouponProbeContract.js',
  'server/services/secureshopMcpDescriptionEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v252.json'))).digest('hex'),'7003f3fcf6b8b6347627bc0c64e1e7be9e2ec93fc018da97bb0749e0bbe27f39');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v253.json'))).digest('hex'),'95b61f1c6c1d3a9b31e812f93d31f7d91f20c1b55d2f9965b4bc73f3c350fddd');
 const hashes=['a1b9ff5eabd57ee91f7959889684f17b83b5efa41fab302ce6197ad2f5c8074e','234cc33da3d878b268b4e3dd4be98cb86c54e49975e756b66fe1d470d91d667a','3b907b69d0b4189f773c8331a7966b8999e52c6ca7702c9b53f3cb46b949da5c','7542c545d6901a7b853f2bf31d42b03852d1ad3028ef78b0c49aa28f0ff8ca92','d47673eb0707943e8b4a71c09568a257eef82f2f1ff141b870edba04ada68133','36317ae08e66bd79d7153460343d00bd023879d7c00f258285fe55f4a4531017','f59f9096ed2bf544760602b27b6fc6fc1bb062603a2c58df0ca8766b7af2f32f','defd5c5b3bde34fc8081b05f062e542042f51341cba28685e9b3092d497ebe88','64b0cb8472e968c4858cc8593e058caf8f985ecb9170d8792eeca641517209a6','1859957da080801379f9f6ae736bf1483622970640a94dc65c0c7bbb12383662','c5ebfaa78cd92033a91d77dde3acbdb6873841fbca82a055c8f8a1ee03d90537','2722189497b78123718e422a363064283f7cae4a4a36ef66a0c459398a4c72a9'];
 changes.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 assertHistoricalBinding(253,current,'95b61f1c6c1d3a9b31e812f93d31f7d91f20c1b55d2f9965b4bc73f3c350fddd','4770ea54649844336c4103f7f5fae8a54315830fefbfe8c11971ba5f77153c22');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v254 historical source binds reviewed public hexadecimal coupon arithmetic',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v253.json'),current=realRequire('./applicationMaintenanceInprocessSources-v254.json');
 const changes=['server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundCouponProbeGraph.js',
  'server/services/secureshopCouponBlindEvidence.js',
  'server/services/secureshopCouponProbeApplication.js',
  'server/services/secureshopCouponProbeArithmetic.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v253.json'))).digest('hex'),'95b61f1c6c1d3a9b31e812f93d31f7d91f20c1b55d2f9965b4bc73f3c350fddd');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v254.json'))).digest('hex'),'0b19e34cc1515c08a9fa3696fbbcad50a3f76f5a7dddc363a0d4ff7f12578f4d');
 const hashes=['2b60eb65201d482504fe7f3b4d077e471ab6ba01e38a851c721885d1eb6faee6','b117b3f34e40f2c15b65540f383417a78e637e2d22a3ed372eef809ae80362b6','7b517c73c676438461a8f3015f5a5b5d70f95b2a820f2fbc6d8b988c0cc0f6b1','726dbef2e856340ec2bbe3cb0124bb2edbe1a0a29cec99f7e9ad51a8a6095f0e','8f825e2fd399c80ce9618e88f4833507488881dc2ea7284c0a6b6ffe00b17823'];
 changes.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 assertHistoricalBinding(254,current,'0b19e34cc1515c08a9fa3696fbbcad50a3f76f5a7dddc363a0d4ff7f12578f4d','b77d7eed14f23f6ad34881a9b09a1b4e03001544b868db1e8f015fb1160845f2');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v255 historical source binds reviewed V39 causal judgment evidence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v254.json'),current=realRequire('./applicationMaintenanceInprocessSources-v255.json');
 const changes=['server/agent-runtime/judgeErrors.js',
  'server/agent-runtime/objectiveJudge.js',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/objectiveJudgmentRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopMcpDescriptionEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v254.json'))).digest('hex'),'0b19e34cc1515c08a9fa3696fbbcad50a3f76f5a7dddc363a0d4ff7f12578f4d');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v255.json'))).digest('hex'),'91361f70830d7cb8dbe3d258ea5e1783c582907b4f57652a5def87a4fc77b0e7');
 const hashes=['e121de7f218c2ff78abed666d294471032ffaa43cafdd188992639576db4ceaa','577e90265b6b765c00cc73782a4b780e35b70fffb08c4436399609821815b2bc','dfe2299e78937e6692b92ad19fb38437428a25bc0b7e7fcfb351eb667b4cf569','bcad29329b86685107905493cea799345a8e88ceac67e1145ae96ab5008fadd8','720be8c85cc04d9248018b9b1897996f040a9169223a65e17f55960ca9cce6d9','7c18ef0e4c76d831e90fa6f4b1943dce3df6dfafe9a46fcc244fe93327818e7e'];
 changes.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 assertHistoricalBinding(255,current,'91361f70830d7cb8dbe3d258ea5e1783c582907b4f57652a5def87a4fc77b0e7','82ae2c2945502d64bae3e91628411d335d044683dc4e146c30f1764096b54b69');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v256 historical source binds reviewed canonical JSONB coupon arithmetic order',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v255.json'),current=realRequire('./applicationMaintenanceInprocessSources-v256.json');
 const changes=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopCouponProbeArithmetic.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1683);assert.equal(current.recoveryFiles.length,1674);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v255.json'))).digest('hex'),'91361f70830d7cb8dbe3d258ea5e1783c582907b4f57652a5def87a4fc77b0e7');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v256.json'))).digest('hex'),'8a392b163d564dc19ec7dd20bed30ea8fff2a399f7c1537eaa29b6cae16ff531');
 assert.equal(current.files[changes[0]],'2329f4ec77e79e1c2288079f676dc7bdb96156eebabc2fb30b09425a719821f5');
 assert.equal(current.files[changes[1]],'30332253815e32204deae511029de9cc7b4fa11c536c4d23ff1de06868a22388');
 assertHistoricalBinding(256,current,'8a392b163d564dc19ec7dd20bed30ea8fff2a399f7c1537eaa29b6cae16ff531','2e172f8aeede8808b53014fd187d9b5f8ce2bc21d0c9c3188b959115c975d83b');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v257 historical source binds reviewed V39 witness and V01 checkout audit lesson',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v256.json'),current=realRequire('./applicationMaintenanceInprocessSources-v257.json');
 const additions=['server/services/secureshopV01CheckoutAuditLesson.js','server/services/secureshopV01TeachingToken.js'];
 const changes=['server/agent-runtime/objectiveJudge.js',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/objectiveJudgmentRepository.js',
  'server/database/postgres/secureshopBoundAuditRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopMcpDescriptionEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1685);assert.equal(current.recoveryFiles.length,1676);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v256.json'))).digest('hex'),'8a392b163d564dc19ec7dd20bed30ea8fff2a399f7c1537eaa29b6cae16ff531');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v257.json'))).digest('hex'),'b657590f24995bb2133c3e1d6a565f80b13e6237114fc00c838c12d42f3137b9');
 const names=[...changes,...additions],hashes=['4034275b9f4f8dd991e3d0164b8d4a52c819fd23a92e90d79e586259c43309a8','44092d1b7bca92a904b454930eb8e8d28116773b0e7622ad59d3327e4ef71452','0e04ba14d5143447dc553da8589b1d0620e23bf8046b069e7ad2f0cda76ffe63','3de6560d08c1e816c176aaa100ca3941c67a8a5bbe11f4cb0a7fa7df5c59c181','cb63c0fa171540370cf9be5c750aa66aef458c6538268869bdf58cbfed908e88','1566e55cef702d6fe4187f4d2a1b7238d4e6fa61f59c43abaddab8246383e2a2','53c49af09a7360ff73ad45fa319897e08dc550a430a26876be62a4f07b9c562e','0194e8e08b6eb9441d7681daa9b9311bf6bf28011d33870b6c8ab923d2f64f35'];
 names.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 assertHistoricalBinding(257,current,'b657590f24995bb2133c3e1d6a565f80b13e6237114fc00c838c12d42f3137b9','8d9caae4d5f77e4041ad4d482e75362e5f3cd0a02a2a95636804b9abd8dcf83b');
 for(const name of names)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v258 historical source binds reviewed upload journal foundation and coupon promotion defaults',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v257.json'),current=realRequire('./applicationMaintenanceInprocessSources-v258.json');
 const additions=['db/postgres/workshop-migrations/secureshop_review/0052_bound_upload_journal.sql',
  'server/database/postgres/secureshopBoundUploadRepository.js',
  'server/services/secureshopBoundUploadReceipt.js'];
 const changes=['server/config/secureshopCurriculum.js',
  'server/database/postgres/secureshopAssessmentSeed.js',
  'server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1688);assert.equal(current.recoveryFiles.length,1679);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v257.json'))).digest('hex'),'b657590f24995bb2133c3e1d6a565f80b13e6237114fc00c838c12d42f3137b9');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v258.json'))).digest('hex'),'3db57eae787d397b6b91331f2101a26270a430f6204faa8dba0f8f8e1d99ab0c');
 const names=[...changes,...additions],hashes=['24d1f9783bc81f52bbc0f311da202e5474edab33e470675fcad3d4b4f8141ede','75f55c8c4f96f69f68c42df3d2aea3e969df4129217c7466721b5b4eec662f0f','d0d84e43e641cd976e8a559dc14ad7f70b84371dcf418bad2d519de9d814156e','efd810ee1bbf576293755ddaa6e3e963530273c8609727db3685c72ae3792372','b98314fb0ce3d5d18f2618428424edebd996f0719ab5e6647b2266a2745a1b74','ab3b2fa6ed0b7325313c8cd4beb3c41f8a54c873c4cfc71072766cc89a28fe17'];
 names.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 assertHistoricalBinding(258,current,'3db57eae787d397b6b91331f2101a26270a430f6204faa8dba0f8f8e1d99ab0c','5084a4ab2207cb1bd7129cddbbaf3a8e9754651b03a97cd0aa582a62c330034e');
 for(const name of names)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v259 historical source binds reviewed V01 checkout audit application and customer UI',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v258.json'),current=realRequire('./applicationMaintenanceInprocessSources-v259.json');
 const additions=['client/src/pages/secureshop/components/CustomerCheckoutAuditLesson.jsx',
  'client/src/pages/secureshop/utils/customerCheckoutAuditReference.mjs',
  'db/postgres/workshop-migrations/secureshop_agents/0101_checkout_audit_jwt_conversation_purpose.sql',
  'server/database/postgres/secureshopV01AuditTurnReader.js',
  'server/routes/secureshop/boundV01AuditLesson.js',
  'server/services/secureshopV01AuditChat.js'];
 const changes=['client/src/pages/secureshop/bridge/stateStore.mjs',
  'client/src/pages/secureshop/components/BoundAgentLane.jsx',
  'client/src/pages/secureshop/utils/shopStorage.mjs',
  'server/routes/secureshop/boundGateway.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopConversationPurpose.js',
  'server/services/secureshopFeatureModeAuthority.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1694);assert.equal(current.recoveryFiles.length,1685);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v258.json'))).digest('hex'),'3db57eae787d397b6b91331f2101a26270a430f6204faa8dba0f8f8e1d99ab0c');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v259.json'))).digest('hex'),'26e99c6addd564e1357a52d0a08bca51fb7778ab7fea140397e8c24b48e57484');
 const names=[...changes,...additions],hashes=['c63b3deb8d709f8250727bdba252b6ddc277b20fa5ef100e3b53801adc5beb40','4ff5a6a88b94a85e4976095cbdb8dfdb4c46046869299cc53a22c35367bb524a','1bd67c1600556cb6c7f4d440de70215d0d9b9163dd88c8f67bba791b69b09b25','515f997f2bf3af7de9fc986b9b773a72899af08a7cec8e456a175d8d7a2e1c2d','ce50afaf1bddddd9ee35b5ea163dcde0227da1aea109890a0b014f16dc62c062','43135d2964ceeb42716754385bb31cda4ad5560575a8ab1ff18b023a164f169f','9c85d5fc3863fe901148a184462222f41fb36426a76b15662b1e6ae1f4d9a17e','4ce56a7861f3b95f33c0dffe3a2af481c02f4174a99ab9846c007373c83d8dfa','0e780faccabb89aa89d2cd686fa82f20091c3dc9cc66e1e84e3b046f880ed6f4','2d687cb083ed14d4184ca20394b87dba6c0f105d6a071cef00bce77b0fc82766','3114d922378d3a15b7eca2937d41c6393719f22a3afe6f6a44ffc6f14b0b3aa9','7920792f289f20d0290e619fe61357f77a9bba9171ad125cd0988a65efe23489','9bcb7491841898d711721bb1a6c1ca65394397baea7c6c96292774453e3646be','1eacc6dcf05d721ccb398df8a1ee55d8d5bdfd9ec7998e528e03b8d61cab46a7','e0b04980e4b402bc3ec15bd6c671dea0a3014881af3a6dfcb6492e42c35871af'];
 names.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 assertHistoricalBinding(259,current,'26e99c6addd564e1357a52d0a08bca51fb7778ab7fea140397e8c24b48e57484','9b619405f87efbb8531c7650940ccb1289928801c39a4508fea407ff3afd12de');
 for(const name of names)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v260 historical source binds forward-only upload reconciliation alias repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v259.json'),current=realRequire('./applicationMaintenanceInprocessSources-v260.json');
 const addition='db/postgres/workshop-migrations/secureshop_review/0053_bound_upload_reconciliation_aliases.sql';
 const changes=['server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)),[addition]);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,addition])].sort());
 assert.equal(Object.keys(current.files).length,1695);assert.equal(current.recoveryFiles.length,1686);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v259.json'))).digest('hex'),'26e99c6addd564e1357a52d0a08bca51fb7778ab7fea140397e8c24b48e57484');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v260.json'))).digest('hex'),'898e1187ff8f00dc21790e4f307308790457043cea5b1ecf30a9bf13be1343bd');
 assert.equal(current.files[changes[0]],'ef3c26775f2781a83d21956fc39248202227ab7be105beadca9bfd93b29351ed');
 assert.equal(current.files[addition],'6b0541b0279cf6c45e7fca8f3b1e9e22918dc2afed6c388888dca8686b5e201d');
 assertHistoricalBinding(260,current,'898e1187ff8f00dc21790e4f307308790457043cea5b1ecf30a9bf13be1343bd','0febd55f5b5bdbb1b404c035efeaec3396878ba3d270f7844cf75858839aae54');
 for(const name of [...changes,addition])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v261 historical source binds V01 grading and V39 relational evaluator persistence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v260.json'),current=realRequire('./applicationMaintenanceInprocessSources-v261.json');
 const additions=['server/agent-runtime/mcpDescriptionRelationsV5.js',
  'server/services/secureshopV01AuditAssessment.js',
  'server/services/secureshopV01AuditEvidence.js'];
 const changes=['server/agent-runtime/objectiveJudge.js',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/objectiveJudgmentRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopMcpDescriptionEvidence.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1698);assert.equal(current.recoveryFiles.length,1689);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v260.json'))).digest('hex'),'898e1187ff8f00dc21790e4f307308790457043cea5b1ecf30a9bf13be1343bd');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v261.json'))).digest('hex'),'9ea4b84128d117a59eb12891f1bba504511b7eac72f9521f4674ff486c573d34');
 const names=[...changes,...additions],hashes=['b5a3052300434f9bce9f111f3c0173a7e960e28e92b75eef2e54390a242003f5','9319eb865cd0e81638e77bc44eda735a17894a43317ba026a11ade3ef4ff83d8','dd4c4ee89aced3823faaf664ad3c32282dd767b7446e7cc42d4967468854d9e4','1e887e79253fbdf2aa57986962dadc62e0548b7e9aacefa7048ea76a95019bb1','b9e3ef027d4d1347a6309b1e9b6ca18cc41a58bd4e6e7f9a1d25e27f23564c39','b8c159cad579b773a20abd52daff1fcf9f0429718d654828dc7a5c90dd67d471','21d36612bc3387796d919b5439595aac776c0796ac7c22d2a658a7e25ca35721','69ab8686eaf61658d5e234aad8133ac35f1746ebf7507f1bcf53bf2d4b34481d'];
 names.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 assertHistoricalBinding(261,current,'9ea4b84128d117a59eb12891f1bba504511b7eac72f9521f4674ff486c573d34','f6b63726378ebf934ab4eafca789fb2967797fef677f194dcef02c719355fa56');
 for(const name of names)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v262 historical source binds V01 canonical grading UI and qualification launch evidence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v261.json'),current=realRequire('./applicationMaintenanceInprocessSources-v262.json');
 const additions=['client/src/pages/secureshop/hooks/useCustomerCheckoutAuditLesson.js'];
 const changes=['client/src/pages/secureshop/bridge/stateChannel.mjs',
  'client/src/pages/secureshop/bridge/stateStore.mjs',
  'client/src/pages/secureshop/components/CustomerCheckoutAuditLesson.jsx',
  'client/src/pages/secureshop/utils/customerCheckoutAuditReference.mjs',
  'client/src/pages/secureshop/utils/shopStorage.mjs',
  'server/config/secureshopCurriculum.js',
  'server/routes/secureshop/boundV01AuditLesson.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopAssessmentRecovery.js',
  'server/services/secureshopBoundReviewComposition.js'];
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1699);assert.equal(current.recoveryFiles.length,1690);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v261.json'))).digest('hex'),'9ea4b84128d117a59eb12891f1bba504511b7eac72f9521f4674ff486c573d34');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v262.json'))).digest('hex'),'00a4cf06c59c2962f8459f8a31a825b45d591ed250fbe6cd1fcae9db1ab3ffb3');
 const names=[...changes,...additions],hashes=['ca5783e26c6026914bece1887cf702b64433afd0bc560ca30259029e6c21f1ab','b44ceaa95df4bf95b9576492a08beafd9fde7cc9a4b46636fde52e5928f5f322','a2c40ec7584d25b93e164857c19ec705fde0df3381feb665c6f96eedf5a9c9a2','0ce7caceaaa1cf7732f9b47292908150e83045566e6c91bf69ad338cafb6af9d','ab69cc9ec6c779dc50fa1f8c4fa5641c4e3e9049887fc70dac60c1ab10069a08','44a5731f99183390662991c66ece8df7cafede58158a587f2a9ca1b4627df1d9','e9ef02ac3fa4980b7aa81ff647da699da3e20a7787dcaff9112acff951ce2dc2','2dfe4f010c3ec5e7da5d1bb476cd3daa59f9fbcb8cca37122d75f92c1b7fb161','2ce6acd9ce76d7495ef1fd7c66139b504a9fd4ccedf1bcdf0e1c2347fb5c0f6c','c9e24bdd0c170dd4bdac7fce3c4fe79e43e96625b9c335569044a4e60803ff62','41429a34700ce43c16feaa307adb230d0b344483b277045c39e3b404b183268c'];
 names.forEach((name,index)=>assert.equal(current.files[name],hashes[index]));
 denied(()=>bindingWith({},current)(ROOT));
 for(const name of names)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v263 historical source binds the V06 avatar upload closure and forward-only SQL',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v262.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v263.json');
 const additions=[
  'db/postgres/workshop-migrations/secureshop_agents/0102_avatar_upload_conversation_purpose.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0103_avatar_upload_registry_successor.sql',
  'server/database/postgres/secureshopBoundUploadAssetRepository.js',
  'server/database/postgres/secureshopBoundUploadEffectReader.js',
  'server/routes/secureshop/boundAvatarUpload.js',
  'server/services/secureshop/assetPaths.js',
  'server/services/secureshopBoundUploadAdmission.js',
  'server/services/secureshopBoundUploadApplication.js',
  'server/services/secureshopBoundUploadComposition.js',
  'server/services/secureshopBoundUploadGraph.js',
  'server/services/secureshopBoundUploadResetAdapter.js',
  'server/services/secureshopBoundUploadSavedOperation.js',
  'server/services/secureshopUploadAssetCapability.js',
  'server/services/secureshopUploadAssetProduction.js',
  'server/services/secureshopUploadAssetReader.js',
  'server/services/secureshopUploadAssetService.js',
  'server/services/secureshopUploadExecutionConfig.js',
  'server/services/secureshopUploadStorageLifecycle.js',
  'server/services/secureshopUploadWriter.js'];
 const changes=['client/src/pages/secureshop/bridge/operations.mjs','server/applicationServer.js',
  'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
  'server/database/postgres/secureshopBoundUploadRepository.js',
  'server/routes/secureshop/boundGateway.js','server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundAclRegistry.js','server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundReviewComposition.js','server/services/secureshopCleanupComposition.js',
  'server/services/secureshopConversationPurpose.js','server/services/secureshopFeatureModeAuthority.js'];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1718);
 assert.equal(current.recoveryFiles.length,1709);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v262.json'))),
  '00a4cf06c59c2962f8459f8a31a825b45d591ed250fbe6cd1fcae9db1ab3ffb3');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v263.json'))),
  'e43cfee2358ce1b8b3936c1cdddcb19e7bf5987d715ce9710dd70878222d82ab');
 assertHistoricalBinding(263,current,'e43cfee2358ce1b8b3936c1cdddcb19e7bf5987d715ce9710dd70878222d82ab',
  '2764835ca59d834f3a8c456d81b14769ffa87e9be128cdede213a4ea9397a325');
 for(const name of [...changes,...additions])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v264 historical source binds V06 rendered avatar upload and V39 range persistence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v263.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v264.json');
 const additions=['client/src/pages/secureshop/components/CustomerAvatarUploadLesson.jsx',
  'client/src/pages/secureshop/hooks/useCustomerAvatarUploadLesson.js',
  'client/src/pages/secureshop/utils/customerAvatarUploadReference.mjs',
  'server/agent-runtime/mcpDescriptionRangePersistenceV6.js',
  'server/agent-runtime/mcpDescriptionRangeRelationsV6.js'];
 const changes=['client/src/pages/secureshop/bridge/fetchAdapter.mjs',
  'client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/bridge/stateChannel.mjs',
  'client/src/pages/secureshop/bridge/stateStore.mjs',
  'client/src/pages/secureshop/bridge/uploads.mjs',
  'client/src/pages/secureshop/components/BoundAgentLane.jsx',
  'client/src/pages/secureshop/utils/shopStorage.mjs',
  'server/agent-runtime/objectiveJudge.js',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/objectiveJudgmentRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopMcpDescriptionEvidence.js'];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1723);
 assert.equal(current.recoveryFiles.length,1714);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v263.json'))),
  'e43cfee2358ce1b8b3936c1cdddcb19e7bf5987d715ce9710dd70878222d82ab');
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v264.json'))),
  'f74053a328592c73de40098547f14c1bcc52516878008e145fe1f8526b2ff374');
 assertHistoricalBinding(264,current,'f74053a328592c73de40098547f14c1bcc52516878008e145fe1f8526b2ff374',
  '7d54301c0eea444295cf0c6b7cfb9b53eefe106916338a8f7439bf3f8617c6e6');
 for(const name of [...changes,...additions])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v265 historical source binds the V01 protected reader and forward-only avatar registry repair',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v264.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v265.json');
 const changes=["server/database/postgres/secureshopBoundToolPolicyReadiness.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopBoundReviewComposition.js"];
 const additions=["db/postgres/workshop-migrations/secureshop_agents/0104_avatar_upload_registry_guard_repair.sql"];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1724);
 assert.equal(current.recoveryFiles.length,1715);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v264.json'))),'f74053a328592c73de40098547f14c1bcc52516878008e145fe1f8526b2ff374');
 assertHistoricalBinding(265,current,'060a5ae7ee3391dff172f1b57e0ddb26aa728a065a5aacfce0259dd766b300f1',
  '880774e70ed110cfb0333473b28d51c14e27280b39e7a4f9309b5b1eb8646d3c');
 for(const name of [...changes,...additions])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v266 historical source binds canonical upload assessment and acknowledged UI recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v265.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v266.json');
 const changes=["client/src/pages/secureshop/bridge/operations.mjs","client/src/pages/secureshop/bridge/stateChannel.mjs","client/src/pages/secureshop/bridge/stateStore.mjs","client/src/pages/secureshop/components/CustomerAvatarUploadLesson.jsx","client/src/pages/secureshop/hooks/useCustomerAvatarUploadLesson.js","client/src/pages/secureshop/utils/shopStorage.mjs","server/config/secureshopCurriculum.js","server/routes/secureshop/boundAvatarUpload.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentRecovery.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundUploadComposition.js","server/services/secureshopBoundUploadGraph.js"];
 const additions=["client/src/pages/secureshop/utils/customerAvatarUploadAssessmentReference.mjs","server/database/postgres/secureshopV06UploadTurnReader.js","server/services/secureshopV06UploadAssessment.js","server/services/secureshopV06UploadEvidence.js","server/services/secureshopV06UploadSourceReader.js"];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1729);
 assert.equal(current.recoveryFiles.length,1720);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v265.json'))),'060a5ae7ee3391dff172f1b57e0ddb26aa728a065a5aacfce0259dd766b300f1');
 assertHistoricalBinding(266,current,'845b5afaa61b5f5ea118f5a08cb48d2a50f2db64a4b8dfef24aa008b7a84ac40',
  '3400a45e80f788150d11bf11f710651aeb80a6c32c0f935f08e54cc8fcb55132');
 for(const name of [...changes,...additions])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v267 historical source binds the immutable V01 no-argument tool contract',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v266.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v267.json');
 const changes=['server/routes/secureshop/boundV01AuditLesson.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopV01AuditAssessment.js','server/services/secureshopV01AuditChat.js','server/services/secureshopV01AuditEvidence.js','server/services/secureshopV01CheckoutAuditLesson.js'];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1729);
 assert.equal(current.recoveryFiles.length,1720);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v266.json'))),'845b5afaa61b5f5ea118f5a08cb48d2a50f2db64a4b8dfef24aa008b7a84ac40');
 assertHistoricalBinding(267,current,'dc9682a2a4c27d5bb3ef89f01794e3d9ec0c3929c0f587e0fdc2d957b868c32b','ded468911015aa37e732b863550a41119b4358f9653f807aa53526b0b16a8202');
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v268 historical source binds owned listing optimize and complete bridge recovery closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v267.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v268.json');
 const changes=["client/src/pages/secureshop/SecureShopStandaloneController.mjs","client/src/pages/secureshop/bridge/operations.mjs","client/src/pages/secureshop/components/BoundRoleAssistant.jsx","client/src/pages/secureshop/components/MerchantListingsSetup.jsx","client/src/pages/secureshop/hooks/useBoundRoleAssistant.js","client/src/pages/secureshop/pages/merchant/Listings.jsx","client/src/pages/secureshop/pages/merchant/listingsReferences.mjs","client/src/pages/secureshop/pages/merchant/useBoundListings.js","client/src/pages/secureshop/utils/merchantListingsSetup.mjs","server/config/secureshopCurriculum.js","server/database/postgres/secureshopBoundToolPolicyReadiness.js","server/database/postgres/secureshopListingJournalRepository.js","server/routes/secureshop/boundListings.js","server/routes/secureshop/boundRoleChat.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopBoundAclRegistry.js","server/services/secureshopBoundListings.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundRoleChat.js","server/services/secureshopConversationPurpose.js","server/services/secureshopListingJournalContract.js","server/services/secureshopListingRequestContract.js","server/services/secureshopListingsApplication.js","server/services/secureshopListingsAssessment.js","server/services/secureshopListingsComposition.js","server/services/secureshopListingsProduction.js","server/services/secureshopRoleListingActionSetup.js"];
 const additions=["client/src/pages/secureshop/bridge/compiler.mjs","client/src/pages/secureshop/bridge/guestRead.mjs","client/src/pages/secureshop/bridge/handshake.mjs","client/src/pages/secureshop/bridge/seededStateStore.mjs","client/src/pages/secureshop/bridge/transport.mjs","client/src/pages/secureshop/components/UploadZone.jsx","db/postgres/workshop-migrations/secureshop_agents/0105_listing_optimize_conversation_purpose.sql","db/postgres/workshop-migrations/secureshop_agents/0106_listing_optimize_registry_successor.sql","db/postgres/workshop-migrations/secureshop_review/0054_owned_listing_image_optimize.sql","server/services/secureshopListingOptimizeEvidence.js","server/services/secureshopListingOptimizeExecutor.js","server/services/secureshopListingOptimizeJudgeGuard.js","server/services/secureshopRoleListingOptimizeSetup.js"];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1742);
 assert.equal(current.recoveryFiles.length,1733);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v267.json'))),'dc9682a2a4c27d5bb3ef89f01794e3d9ec0c3929c0f587e0fdc2d957b868c32b');
 assertHistoricalBinding(268,current,'8531c7f46e08b7d5c0287937409f8ad4905d1500882eec1cbcd9c1b2647c8fe1','2577c9fafd516829907c0daa83660df7b40ded7a3629646136fd191b895e5f2c');
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v269 historical source binds the uncommitted V03 migration syntax repairs',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v268.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v269.json');
 const changes=["db/postgres/workshop-migrations/secureshop_agents/0106_listing_optimize_registry_successor.sql","db/postgres/workshop-migrations/secureshop_review/0054_owned_listing_image_optimize.sql","server/services/applicationMaintenanceInprocessAdmission.js"];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1742);
 assert.equal(current.recoveryFiles.length,1733);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v268.json'))),'8531c7f46e08b7d5c0287937409f8ad4905d1500882eec1cbcd9c1b2647c8fe1');
 assertHistoricalBinding(269,current,'86b7643086a2e9f2a2cae28a9c25abd4721b815de0bf9ac9009c331d1b4c9c7b','55a68df0b920c21c29f369410b4ff0d83ca9466aaa261b52b405813fe2788f65');
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v270 historical source binds portable isolated upload assets and supported setup closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v269.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v270.json');
 const changes=['scripts/setup-application.js','scripts/start-application.js','server/applicationServer.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopUploadAssetProduction.js','server/services/secureshopUploadAssetService.js'];
 const additions=['scripts/lib/setup-upload-asset-environment.js','server/middleware/applicationCors.js'];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),additions);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...additions])].sort());
 assert.equal(Object.keys(current.files).length,1744);
 assert.equal(current.recoveryFiles.length,1735);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v269.json'))),'86b7643086a2e9f2a2cae28a9c25abd4721b815de0bf9ac9009c331d1b4c9c7b');
 assertHistoricalBinding(270,current,'856125c4cd6f2855de2ed37f9e2f8d4b953b84f0264daf1084e8fed00f556cb8','0d0e99f08d580ae8832d05fecadf838e6be0114c18257af5b437288e07afb30e');
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v271 historical source binds tenant publication authority and readable teaching token',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v270.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v271.json');
 const changes=['client/src/pages/secureshop/components/CustomerCheckoutAuditLesson.jsx','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopBoundReviewComposition.js'];
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1744);
 assert.equal(current.recoveryFiles.length,1735);
 assert.equal(digest(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v270.json'))),'856125c4cd6f2855de2ed37f9e2f8d4b953b84f0264daf1084e8fed00f556cb8');
 assertHistoricalBinding(271,current,'659af3f791e933aaf3db21beb2db192a9a881ae67c521d3f3f9a3127c24d9b3b','05495b6368c7e4531570c22ddbaa78b6322e4da9c056b7d90de865e07ce6a326');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v272 historical source binds canonical avatar upload gateway routes',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v271.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v272.json');
 const changes=['server/routes/secureshop/boundAvatarUpload.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1744);
 assert.equal(current.recoveryFiles.length,1735);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v271.json'))).digest('hex'),'659af3f791e933aaf3db21beb2db192a9a881ae67c521d3f3f9a3127c24d9b3b');
 assertHistoricalBinding(272,current,'5bcc0ef7d8d27da2dc06e60cdced93e3316390601d78eba04501af0afa314b35','4165564641213d2ff867e2b36a8f0988e7def92387138b5b2b01c9a24608376f');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v273 historical source binds versioned upload storage and serving criterion',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v272.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v273.json');
 const changes=['server/config/secureshopCurriculum.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopV06UploadEvidence.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1744);
 assert.equal(current.recoveryFiles.length,1735);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v272.json'))).digest('hex'),'5bcc0ef7d8d27da2dc06e60cdced93e3316390601d78eba04501af0afa314b35');
 assertHistoricalBinding(273,current,'15578fb97736d4f512025049b1b14ba058789c49437712c3122ab453c13af909','dd2fc04cad5d1d9848746cc1fdaaf3ad5a392f02227d776568d75730cdaaac61');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v274 historical source binds qualified default-disabled checkout audit curriculum and guarded seed',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v273.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v274.json');
 const changes=['server/config/secureshopCurriculum.js','server/database/postgres/secureshopAssessmentSeed.js','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1744);
 assert.equal(current.recoveryFiles.length,1735);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v273.json'))).digest('hex'),'15578fb97736d4f512025049b1b14ba058789c49437712c3122ab453c13af909');
 assertHistoricalBinding(274,current,'e40b2fd537d0ac1584c1443012c9b5858eac653db7cf463c0f58442b72288f7d','748f71569e6dff4f3df5dd9e69972e2ab978b582bcbf4b019cc41b45125189b1');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v275 historical source binds create-only attachments and versioned Windows cleanup',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v274.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v275.json');
 const changes=['server/database/postgres/secureshopLaunchRepository.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopFileCleanupReceiptReader.js','sidecars/sandbox-runner/secureshopFiles.js'];
 const added=['server/services/secureshopFileSummaryAttachment.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1745);
 assert.equal(current.recoveryFiles.length,1736);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v274.json'))).digest('hex'),'e40b2fd537d0ac1584c1443012c9b5858eac653db7cf463c0f58442b72288f7d');
 assertHistoricalBinding(275,current,'757a3c7e4a4ee8f6da90b9616ca624c58f974f5cc5bd1897ea0794de647b99f1','a819232f4de2dd8ce984ed9fe2e5bdc49cead8983398e70951e826b55c7922e7');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v276 historical source binds separate SVG browser execution and retained assessment recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v275.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v276.json');
 const changes=['server/config/secureshopCurriculum.js','server/routes/secureshop/boundAvatarUpload.js','server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopAssessmentRecovery.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopBoundUploadComposition.js','server/services/secureshopV06UploadEvidence.js'];
 const added=['server/services/secureshopSvgAssetBrowserQualification.js','server/services/secureshopV08SvgAssessment.js','server/services/secureshopV08SvgEvidence.js','server/services/secureshopV08SvgSourceReader.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1749);assert.equal(current.recoveryFiles.length,1740);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v275.json'))).digest('hex'),'757a3c7e4a4ee8f6da90b9616ca624c58f974f5cc5bd1897ea0794de647b99f1');
 assertHistoricalBinding(276,current,'401e8332e4d48fd369cbec202e6e5e38bd0afd54f9d5bb8e79fcb341735ec534','2c18ddf7bca1f88c0cde2651eff7bbedac3b38119f02651ff90e67977dd3b6b2');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v277 historical source binds file-summary graph and forward registry registration',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v276.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v277.json');
 const changes=["server/database/postgres/secureshopBoundToolPolicyReadiness.js", "server/services/applicationMaintenanceInprocessAdmission.js", "server/services/secureshopBoundAclRegistry.js", "server/services/secureshopBoundReviewComposition.js", "server/services/secureshopConversationPurpose.js", "server/services/secureshopFeatureModeAuthority.js"];
 const added=["db/postgres/workshop-migrations/secureshop_agents/0107_file_summary_conversation_purpose.sql", "db/postgres/workshop-migrations/secureshop_agents/0108_file_summary_registry_successor.sql", "server/services/secureshopBoundFileSummaryGraph.js", "server/services/secureshopFileSummaryComposition.js", "server/services/secureshopFileSummaryExecutionConfig.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1754);assert.equal(current.recoveryFiles.length,1745);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v276.json'))).digest('hex'),'401e8332e4d48fd369cbec202e6e5e38bd0afd54f9d5bb8e79fcb341735ec534');
 assertHistoricalBinding(277,current,'1a1193ee42db7382e8e8ae07ea2f16ea7ed7a69b33dac90d66fb40153414404b','d6f748b091e7a59f1162dd0c0961b8970f0637720827a122a1f00a2417f09ae7');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v278 historical source binds separate SVG assessment UI and acknowledged recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v277.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v278.json');
 const changes=['client/src/pages/secureshop/bridge/operations.mjs','client/src/pages/secureshop/bridge/stateChannel.mjs','client/src/pages/secureshop/bridge/stateStore.mjs','client/src/pages/secureshop/components/CustomerAvatarUploadLesson.jsx','client/src/pages/secureshop/hooks/useCustomerAvatarUploadLesson.js','client/src/pages/secureshop/utils/customerAvatarUploadAssessmentReference.mjs','client/src/pages/secureshop/utils/shopStorage.mjs','server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1754);assert.equal(current.recoveryFiles.length,1745);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v277.json'))).digest('hex'),'1a1193ee42db7382e8e8ae07ea2f16ea7ed7a69b33dac90d66fb40153414404b');
 assertHistoricalBinding(278,current,'85729fb9e05aaed0186f5c9da7ad0ea52a58f2b4dcadfdba21cba687f1cbb707','7f90a9437916bdd10a3e3775c7062638c63dcebc653d17ee89992fb6b562ff6a');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v279 historical source binds canonical file summary assessment and learner recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v278.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v279.json');
 const changes=["client/src/pages/secureshop/bridge/compiler.mjs","client/src/pages/secureshop/bridge/fetchAdapter.mjs","client/src/pages/secureshop/bridge/operations.mjs","client/src/pages/secureshop/bridge/stateChannel.mjs","client/src/pages/secureshop/bridge/stateStore.mjs","client/src/pages/secureshop/bridge/transport.mjs","client/src/pages/secureshop/bridge/uploads.mjs","client/src/pages/secureshop/components/BoundAgentLane.jsx","client/src/pages/secureshop/utils/shopStorage.mjs","server/config/secureshopCurriculum.js","server/routes/secureshop/boundGateway.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentRecovery.js","server/services/secureshopBoundApplication.js","server/services/secureshopBoundReviewComposition.js"];
 const added=["client/src/pages/secureshop/components/CustomerFileSummaryLesson.jsx","client/src/pages/secureshop/hooks/useCustomerFileSummaryLesson.js","client/src/pages/secureshop/utils/customerFileSummaryReference.mjs","server/database/postgres/secureshopV19FileSummaryTurnReader.js","server/routes/secureshop/boundFileSummary.js","server/services/secureshopFileSummaryApplication.js","server/services/secureshopV19FileSummaryAssessment.js","server/services/secureshopV19FileSummaryEvidence.js","server/services/secureshopV19FileSummarySavedTurn.js","server/services/secureshopV19FileSummarySourceReader.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1764);assert.equal(current.recoveryFiles.length,1755);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v278.json'))).digest('hex'),'85729fb9e05aaed0186f5c9da7ad0ea52a58f2b4dcadfdba21cba687f1cbb707');
 assertHistoricalBinding(279,current,'e78254961190c53c05e2f70cfb6a12cb3d13ccc23b01e864204c2cee72e932f0','ecd1fbedfab4e61f4d75f0b3f2b17fb80279993816e26b601f6fe741de2d5cb1');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v280 historical source binds versioned SVG receipt excerpts without weakening grounding',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v279.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v280.json');
 const changes=["server/config/secureshopCurriculum.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopV08SvgEvidence.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1764);assert.equal(current.recoveryFiles.length,1755);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v279.json'))).digest('hex'),'e78254961190c53c05e2f70cfb6a12cb3d13ccc23b01e864204c2cee72e932f0');
 assertHistoricalBinding(280,current,'df57c6d369579592b07b14bdc895cbd650ee57c444ee4cd34ee2dca4ea73f074','101fea05ed41426dd4733df885b853ddf66fa1092de461ca65eccd11596a574f');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v281 historical source binds mail HTML assessment, learner recovery and exact renderer closure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v280.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v281.json');
 const changes=["client/src/pages/secureshop/SecureShopStandaloneController.mjs","client/src/pages/secureshop/bridge/mailReferences.mjs","client/src/pages/secureshop/bridge/operations.mjs","client/src/pages/secureshop/components/MerchantMailConfirmation.jsx","server/config/secureshopCurriculum.js","server/routes/secureshop/boundGateway.js","server/routes/secureshop/boundMail.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentRecovery.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundRoleChat.js","server/services/secureshopMailApplication.js","server/services/secureshopMailBrowserQualification.js","server/services/secureshopMailObjectiveReadiness.js","server/services/secureshopMailProduction.js","server/services/xssBrowserQualification.js"],added=["client/src/pages/secureshop/components/MerchantMailHtmlAssessment.jsx","client/src/pages/secureshop/components/mailMessageClientRenderer.jsx","client/src/pages/secureshop/utils/merchantMailHtmlAssessmentReference.mjs","client/vite.mail-renderer.config.mjs","server/services/secureshopMailHtmlInjectionAssessment.js","server/services/secureshopMailHtmlInjectionEvidence.js","server/services/secureshopMailHtmlInjectionOriginalReader.js","server/services/secureshopMailboxContent.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1772);assert.equal(current.recoveryFiles.length,1763);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v280.json'))).digest('hex'),'df57c6d369579592b07b14bdc895cbd650ee57c444ee4cd34ee2dca4ea73f074');
 assertHistoricalBinding(281,current,'c0ac8a87ce900a1f0ef5eb8a5a39345a786a9314b951d83dfef2256aab6c58d4','80ba94fa3061ad90c14102b4b7cd98025009dddd0456beaa097fb859b8b16580');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v282 historical source binds product upload cleanup',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v281.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v282.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundUploadResetAdapter.js","server/services/secureshopCleanupComposition.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1772);assert.equal(current.recoveryFiles.length,1763);
 assertHistoricalBinding(282,current,'fe64d8b786847ecaeed340a1b1cae3d256b25ad8dca5a611ed88e1cc66ea7b95','c29f2fb4db0a599f06e8afce6381088b7abaceeecdff91da4da8a64cea33d27e');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v283 historical source binds lease-scoped file summary authority',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v282.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v283.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentPublicationScope.js","server/services/secureshopBoundAgentRunner.js","server/services/secureshopBoundFileSummaryGraph.js","server/services/secureshopFileSummaryAttachment.js","server/services/secureshopV19FileSummaryAssessment.js","server/services/secureshopV19FileSummarySavedTurn.js","server/services/secureshopV19FileSummarySourceReader.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1772);assert.equal(current.recoveryFiles.length,1763);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v282.json'))).digest('hex'),'fe64d8b786847ecaeed340a1b1cae3d256b25ad8dca5a611ed88e1cc66ea7b95');
 assertHistoricalBinding(283,current,'e36d76ab5f6b1c1275a3316f529d2437651cb9cf5f6cb586735a3fa24a30fbec','585ac88c1c1419ac17f07a5d2c2dff0e350a9c99a41c1f97eb1bd1a453910ed2');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v284 historical source binds narrow listing trace timestamp normalization',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v283.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v284.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopListingOptimizeEvidence.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1772);assert.equal(current.recoveryFiles.length,1763);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v283.json'))).digest('hex'),'e36d76ab5f6b1c1275a3316f529d2437651cb9cf5f6cb586735a3fa24a30fbec');
 assertHistoricalBinding(284,current,'414c55a7a6ecc9166bf44b1c6af0f90b9b40544e321fb26e0702c99b20e275b9','010f569b9b1a8becc7f67bc3fd0240b68e5c9223bfa862e1730f1eea1aa29247');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v285 historical source binds objective-specific Listings Judge guards',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v284.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v285.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopListingOptimizeJudgeGuard.js","server/services/secureshopListingsAssessment.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1772);assert.equal(current.recoveryFiles.length,1763);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v284.json'))).digest('hex'),'414c55a7a6ecc9166bf44b1c6af0f90b9b40544e321fb26e0702c99b20e275b9');
 assertHistoricalBinding(285,current,'aee0a942bc1dd265903f68de688d79a8502d4ac4765514c78a4728e41be314ed','4efb2558d191cce1ebe523cbe04efda3734d7c0c8f39d184b7dad6261db17d49');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v286 historical source binds original file summary local failure',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v285.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v286.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopBoundFileSummaryGraph.js"];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changes);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assert.equal(Object.keys(current.files).length,1772);assert.equal(current.recoveryFiles.length,1763);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v285.json'))).digest('hex'),'aee0a942bc1dd265903f68de688d79a8502d4ac4765514c78a4728e41be314ed');
 assertHistoricalBinding(286,current,'aa40ee276494ff1239460916ace0617753b48ad29bd3cc1a315ee7ab6958c8fa','67b90da81ed822d61fb25e483cfa012df899597cb36f177a8418640aab503109');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v287 historical source binds agent mail disclosure and bounded principal files admission',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v286.json'),current=realRequire('./applicationMaintenanceInprocessSources-v287.json');
 const changes=["client/src/pages/secureshop/bridge/mailReferences.mjs","client/src/pages/secureshop/bridge/operations.mjs","client/src/pages/secureshop/components/BoundRoleAssistant.jsx","client/src/pages/secureshop/components/MerchantMailReadCard.jsx","server/config/secureshopCurriculum.js","server/database/postgres/secureshopLaunchRepository.js","server/routes/secureshop/boundRoleChat.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentRecovery.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundRoleChat.js"],added=["client/src/pages/secureshop/components/V11MailReadAssessment.jsx","client/src/pages/secureshop/utils/merchantMailReadAssessmentReference.mjs","db/postgres/identity-migrations/0151_secureshop_files_principal_admission.sql","server/services/secureshopMailAgentReadAssessment.js","server/services/secureshopMailAgentReadEvidence.js","server/services/secureshopMailAgentReadOriginalReader.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1778);assert.equal(current.recoveryFiles.length,1769);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v286.json'))).digest('hex'),'aa40ee276494ff1239460916ace0617753b48ad29bd3cc1a315ee7ab6958c8fa');
 assertHistoricalBinding(287,current,'80c481c0883e1a6334b815b1efadefd4042435924370f12157fe7186f7063a50','e34a954b0f5926d01d7bda8dc89efd8c33c7387a56a8de995ebf9816ac563cbc');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v288 historical source binds reviewed NL SQL assessment integration',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v287.json'),current=realRequire('./applicationMaintenanceInprocessSources-v288.json');
 const changes=["server/config/secureshopCurriculum.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAnalyticsComposition.js","server/services/secureshopAnalyticsDisclosureAssessment.js","server/services/secureshopAnalyticsPostJournalAssessment.js","server/services/secureshopAssessmentPersonaCapture.js","server/services/secureshopAssessmentRecovery.js","server/services/secureshopBoundAnalytics.js","server/services/secureshopBoundReviewComposition.js"],added=["server/services/secureshopAnalyticsNlSqlAssessment.js","server/services/secureshopAnalyticsNlSqlEvidence.js","server/services/secureshopAnalyticsNlSqlRetained.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1781);assert.equal(current.recoveryFiles.length,1772);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v287.json'))).digest('hex'),'80c481c0883e1a6334b815b1efadefd4042435924370f12157fe7186f7063a50');
 assertHistoricalBinding(288,current,'f81dae1552e6e08c1be6c250743700aa96aed0ecbe048bf0a1ce4da322e88f67','6e9ee7a691a02bd1937146b311a2f1d583767e4b38f3e32750bb92bd3a17ee90');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v289 historical source binds mail HTML assessment recovery and scene progress cleanup',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v288.json'),current=realRequire('./applicationMaintenanceInprocessSources-v289.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopMailHtmlInjectionAssessment.js","server/services/secureshopMailProduction.js"],added=["db/postgres/identity-migrations/0152_secureshop_scene_assessment_cleanup.sql"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1782);assert.equal(current.recoveryFiles.length,1773);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v288.json'))).digest('hex'),'f81dae1552e6e08c1be6c250743700aa96aed0ecbe048bf0a1ce4da322e88f67');
 assertHistoricalBinding(289,current,'aa1f25a5e5c4c60f4d98e978c52f336d95b57fc63b13d49708085f0b762270b7','9a405eaa88817b55a3031c9645782f22e7ad1db19a7af83ba98364e592280b90');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v290 historical source binds acknowledged standalone mode transitions',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v289.json'),current=realRequire('./applicationMaintenanceInprocessSources-v290.json');
 const changes=["client/src/pages/secureshop/SecureShopStandaloneBound.jsx","client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx","server/services/applicationMaintenanceInprocessAdmission.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1782);assert.equal(current.recoveryFiles.length,1773);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v289.json'))).digest('hex'),'aa1f25a5e5c4c60f4d98e978c52f336d95b57fc63b13d49708085f0b762270b7');
 assertHistoricalBinding(290,current,'9b1feb1131df0a2bcf242d1f1b9c0b843f73fcee55c89e21f8dd69bf25218ed5','88dc8200f6a2b94d34f22c82474edc12d8a3f2100fb692da536de1c643b1ea80');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v291 historical source binds mail assessment eligibility and NL SQL qualification',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v290.json'),current=realRequire('./applicationMaintenanceInprocessSources-v291.json');
 const changes=["server/config/secureshopCurriculum.js","server/database/postgres/secureshopAssessmentSeed.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopMailHtmlInjectionAssessment.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1782);assert.equal(current.recoveryFiles.length,1773);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v290.json'))).digest('hex'),'9b1feb1131df0a2bcf242d1f1b9c0b843f73fcee55c89e21f8dd69bf25218ed5');
 assertHistoricalBinding(291,current,'9e69fed18357b6f2f3ae15db401616fbd02e6392910c293f6151afb044598a4c','7689c3d57aaa8a17b0d5633eccbfa24d41f5af488d80575a46cf29ed3b5dde96');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v292 historical source binds reviewed mail and listing qualification contracts',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v291.json'),current=realRequire('./applicationMaintenanceInprocessSources-v292.json');
 const changes=["server/config/secureshopCurriculum.js","server/database/postgres/secureshopAssessmentSeed.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopMailAgentReadEvidence.js","server/services/secureshopMailObjectiveReadiness.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1782);assert.equal(current.recoveryFiles.length,1773);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v291.json'))).digest('hex'),'9e69fed18357b6f2f3ae15db401616fbd02e6392910c293f6151afb044598a4c');
 assertHistoricalBinding(292,current,'2eb40e71f350be06cb3bdaac1867bb216c04b4d3c89dee5aca28ae0d4d2bf175','4ad20bcc20025788bbc9243c03b0ab64e72e84aa280fc2aaf444a4d3f4fdcbe9');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v293 historical source binds reviewed listing qualification and preserved catalog defaults',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v292.json'),current=realRequire('./applicationMaintenanceInprocessSources-v293.json');
 const changes=["server/config/secureshopCurriculum.js","server/database/postgres/secureshopAssessmentSeed.js","server/services/applicationMaintenanceInprocessAdmission.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1782);assert.equal(current.recoveryFiles.length,1773);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v292.json'))).digest('hex'),'2eb40e71f350be06cb3bdaac1867bb216c04b4d3c89dee5aca28ae0d4d2bf175');
 assertHistoricalBinding(293,current,'ff5e3c4c47f91f35e39b1866af3288670b3087d67346f7aeb43db81d02a4e697','119d1f412ed336b90a05a09f6af287463b485b79b5b0995ec643b6e6b0658f59');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v294 historical source binds exact mail body citation contracts',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v293.json'),current=realRequire('./applicationMaintenanceInprocessSources-v294.json');
 const changes=["server/agent-runtime/objectiveJudge.js","server/config/secureshopCurriculum.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopMailAgentReadEvidence.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1782);assert.equal(current.recoveryFiles.length,1773);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v293.json'))).digest('hex'),'ff5e3c4c47f91f35e39b1866af3288670b3087d67346f7aeb43db81d02a4e697');
 assertHistoricalBinding(294,current,'1d1f7c2d361557bcf52e9bd54fe6508c6382a0a78415b03b2f3014f903f9a9ba','180c53a57cd71d2e8cae6533f72625eb2e98d4056cc19f7ce3493bc82d9f3072');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v295 historical source binds qualified mail disclosure defaults with instructor preservation',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v294.json'),current=realRequire('./applicationMaintenanceInprocessSources-v295.json');
 const changes=["server/config/secureshopCurriculum.js","server/database/postgres/secureshopAssessmentSeed.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopMailObjectiveReadiness.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1782);assert.equal(current.recoveryFiles.length,1773);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v294.json'))).digest('hex'),'1d1f7c2d361557bcf52e9bd54fe6508c6382a0a78415b03b2f3014f903f9a9ba');
 assertHistoricalBinding(295,current,'2fe2edc5cd46949092d6bd6f35b9a012e30085b573070c1bbb97cab9b6d8b698','4b1ac384d3e5bcaecbf583baa7ab7d0a60640cf9967034da0a29201da77175ec');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v296 historical source binds grounded audit witness and versioned summary task',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v295.json'),current=realRequire('./applicationMaintenanceInprocessSources-v296.json');
 const changes=["server/agent-runtime/objectiveJudge.js","server/agent-runtime/secureshopAuditSummaryGraph.js","server/agent-runtime/workers/secureshopAuditWorker.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAuditJob.js","server/services/secureshopAuditRuntime.js","server/services/secureshopAuditUnboundedAssessment.js","server/services/secureshopAuditUnboundedEvidence.js","server/services/secureshopAuditWorkerHost.js"],added=["server/services/secureshopAuditSummaryTaskPrompt.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1783);assert.equal(current.recoveryFiles.length,1774);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v295.json'))).digest('hex'),'2fe2edc5cd46949092d6bd6f35b9a012e30085b573070c1bbb97cab9b6d8b698');
 assertHistoricalBinding(296,current,'bc381693fef96691c4f05a01c1bc0d7009e3c5341353c5bece33bda359881031','64f12da18e89f4366f3861bd2606b749ddd4f6fead70d809371db01c89bf1371');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v297 historical source binds bounded unbounded-audit final response budget',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v296.json'),current=realRequire('./applicationMaintenanceInprocessSources-v297.json');
 const changes=["server/agent-runtime/secureshopAuditSummaryGraph.js","server/services/applicationMaintenanceInprocessAdmission.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1783);assert.equal(current.recoveryFiles.length,1774);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v296.json'))).digest('hex'),'bc381693fef96691c4f05a01c1bc0d7009e3c5341353c5bece33bda359881031');
 assertHistoricalBinding(297,current,'ea0a2b97381b9edf4cbfbc04357642e6c620d5fc47bc3945536be10511472113','6eec03192b28d4d2a9f2227f1ba85be5c465d6a183f148c37eff8a1f0b511bf4');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v298 historical source binds concise source-grounded audit task',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v297.json'),current=realRequire('./applicationMaintenanceInprocessSources-v298.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAuditSummaryTaskPrompt.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1783);assert.equal(current.recoveryFiles.length,1774);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v297.json'))).digest('hex'),'ea0a2b97381b9edf4cbfbc04357642e6c620d5fc47bc3945536be10511472113');
 assertHistoricalBinding(298,current,'c7b16f60a39a024de5a1c22b0cbf5ebac5c1c41160849436550b9660122d1826','380d8ed5eb18e44acaf5e48b8bbc4976f6ac8ef84d93ecf680393ead93866832');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v299 historical source binds original-reference audit grading and pending curriculum',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v298.json'),current=realRequire('./applicationMaintenanceInprocessSources-v299.json');
 const changes=["server/agent-runtime/objectiveJudge.js","server/config/secureshopCurriculum.js","server/database/postgres/objectiveJudgmentRepository.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAuditUnboundedAssessment.js","server/services/secureshopAuditUnboundedEvidence.js"],added=[];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1783);assert.equal(current.recoveryFiles.length,1774);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v298.json'))).digest('hex'),'c7b16f60a39a024de5a1c22b0cbf5ebac5c1c41160849436550b9660122d1826');
 assertHistoricalBinding(299,current,'628e906d1dd01dbdcc1b71f71bdb1017912de1067f3dcb1ef078bcfc8e84b93b','eef5eb66b8fefce6e237def96d67faf4844e75865c173ba66a4de04603b957ef');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});


test('v300 historical source binds product summary and confined traversal workflows with audit focus',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v299.json'),current=realRequire('./applicationMaintenanceInprocessSources-v300.json');
 const changes=["client/src/pages/secureshop/bridge/compiler.mjs","client/src/pages/secureshop/bridge/fetchAdapter.mjs","client/src/pages/secureshop/bridge/operations.mjs","client/src/pages/secureshop/bridge/stateChannel.mjs","client/src/pages/secureshop/bridge/stateStore.mjs","client/src/pages/secureshop/bridge/transport.mjs","client/src/pages/secureshop/bridge/uploads.mjs","client/src/pages/secureshop/components/BoundAgentLane.jsx","client/src/pages/secureshop/pages/Product.jsx","client/src/pages/secureshop/utils/shopStorage.mjs","server/agent-runtime/secureshopAuditSummaryGraph.js","server/agent-runtime/workers/secureshopAuditWorker.js","server/routes/secureshop/boundAvatarUpload.js","server/routes/secureshop/boundGateway.js","server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentRecovery.js","server/services/secureshopAuditExecutionConfig.js","server/services/secureshopAuditModelChain.js","server/services/secureshopAuditPolicyChannel.js","server/services/secureshopAuditSummaryObservation.js","server/services/secureshopAuditUnboundedEvidence.js","server/services/secureshopAuditVerifiedEvidence.js","server/services/secureshopAuditWorkerHost.js","server/services/secureshopBoundApplication.js","server/services/secureshopBoundProductAssist.js","server/services/secureshopBoundReviewComposition.js","server/services/secureshopBoundUploadComposition.js","server/services/secureshopBoundUploadGraph.js","server/services/secureshopBoundUploadSavedOperation.js","server/services/secureshopUploadStorageLifecycle.js","server/services/secureshopV06UploadAssessment.js","server/services/secureshopV06UploadEvidence.js"],added=["agent-host/agents/uploads/tools/index.js","agent-host/shared/vectorStore.js","client/src/pages/secureshop/components/CustomerAvatarTraversalLesson.jsx","client/src/pages/secureshop/hooks/useCustomerAvatarTraversalLesson.js","client/src/pages/secureshop/hooks/useProductSummary.js","client/src/pages/secureshop/utils/customerAvatarTraversalReference.mjs","client/src/pages/secureshop/utils/productSummaryReference.mjs","server/database/postgres/secureshopV46TraversalRepository.js","server/routes/secureshop/boundProductSummaryAssessment.js","server/services/secureshopProductSummaryAssessment.js","server/services/secureshopProductSummaryEvidence.js","server/services/secureshopProductSummarySourceContract.js","server/services/secureshopProductSummarySourceReader.js","server/services/secureshopV46TraversalApplication.js","server/services/secureshopV46TraversalAssessment.js","server/services/secureshopV46TraversalAssetReader.js","server/services/secureshopV46TraversalDestination.js","server/services/secureshopV46TraversalEvidence.js","server/services/secureshopV46TraversalSourceReader.js","server/services/secureshopV46TraversalWriter.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(previous.files,n)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(n=>!Object.hasOwn(current.files,n)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assert.equal(Object.keys(current.files).length,1803);assert.equal(current.recoveryFiles.length,1794);
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(ROOT,'server/services/applicationMaintenanceInprocessSources-v299.json'))).digest('hex'),'628e906d1dd01dbdcc1b71f71bdb1017912de1067f3dcb1ef078bcfc8e84b93b');
 assertHistoricalBinding(300,current,'ceb48bade022e27bdd7e138642c993fb442f386080232088b11528318233b6a6','25d1d3a44fdf29162b07da3d14cbcc25b6509b0fc43e9df54fd5f091f826a3c8');
 for(const name of [...changes,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v301 historical source binds protected traversal destination evidence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v300.json'),current=realRequire('./applicationMaintenanceInprocessSources-v301.json');
 const changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopV46TraversalEvidence.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files),Object.keys(current.files));assert.deepEqual(previous.recoveryFiles,current.recoveryFiles);
 assertHistoricalBinding(301,current,'15c4a9d1ec5f6ef9b2b606f153440db9aece9007d6d5c1c865ac6667d4ffcc2b','af6b82d05a40a4db335324967ccb2804e08bd7e27294f4cd68b54239508fdb01');
 for(const name of changes)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v302 historical source binds closed malformed mail recovery denial',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v301.json'),current=realRequire('./applicationMaintenanceInprocessSources-v302.json'),changes=["server/services/applicationMaintenanceInprocessAdmission.js","server/services/secureshopAssessmentRecovery.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files),Object.keys(current.files));assert.deepEqual(previous.recoveryFiles,current.recoveryFiles);
 assertHistoricalBinding(302,current,'e064a3f4292b67ca821267e9b02b6d717bcd5e49cbca2dab872d4c3546283827','d061dc732c47d7503e8a20b6a5e281a3251226233918c40ca5bedab17ac4d62c');
 for(const name of changes)rejectsSimulatedSourceDrift(name);denied(()=>bindingWith({},previous)(ROOT));
});

test('v303 historical source binds current assessment in traversal retirement callback',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v302.json'),current=realRequire('./applicationMaintenanceInprocessSources-v303.json'),changes=["client/src/pages/secureshop/hooks/useCustomerAvatarTraversalLesson.js","server/services/applicationMaintenanceInprocessAdmission.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files),Object.keys(current.files));assert.deepEqual(previous.recoveryFiles,current.recoveryFiles);
 assertHistoricalBinding(303,current,'6839defd6b2d212762f8c72b08611f752cc93a70667c53cd01313d4143827990','a841d1e89d62ec51a0061790fa715cb6b142a26f309e000123cccfb889caf06c');
 for(const name of changes)rejectsSimulatedSourceDrift(name);denied(()=>bindingWith({},previous)(ROOT));
});

test('v304 historical source binds qualified default-disabled traversal catalog transition',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v303.json'),current=realRequire('./applicationMaintenanceInprocessSources-v304.json'),changes=["server/config/secureshopCurriculum.js","server/database/postgres/secureshopAssessmentSeed.js","server/services/applicationMaintenanceInprocessAdmission.js"];
 assert.deepEqual(Object.keys(previous.files).filter(n=>previous.files[n]!==current.files[n]).sort(),changes);
 assert.deepEqual(Object.keys(previous.files),Object.keys(current.files));assert.deepEqual(previous.recoveryFiles,current.recoveryFiles);
 assertHistoricalBinding(304,current,'ed24d4e7bf671ea74637978cd2120cc8ab33a13b995b68aa0227c58fd9f23868','76a13c508178f191300ec0deaa6e55a38c1ccef92263bc89b1bb201a84c62485');
 for(const name of changes)rejectsSimulatedSourceDrift(name);denied(()=>bindingWith({},previous)(ROOT));
});

test('v305 historical source binds isolated file path summary closure',()=>{
 assertHistoricalBinding(305,realRequire('./applicationMaintenanceInprocessSources-v305.json'),'947a1a3546d9b05938154ed9d79c83ad4b684738c70d91502292ff221078c886','b993010c34b9b61535242f6fe11f2b09b1908ccc6aa68ef1e67161ee359634bc');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v304.json'))(ROOT));
});

test('v306 historical source binds reviewed policy trust, SVG grounding and file lesson startup',()=>{
 assertHistoricalBinding(306,realRequire('./applicationMaintenanceInprocessSources-v306.json'),'c676dea4a816e62179263e678085239c1e3d4e22f4d98e5cd1700d2a48d4177e','6c2099d000750609db85d232e1b5b418e85a0e8081a3dd1c04d4e630b4c65d15');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v305.json'))(ROOT));
});

test('v307 historical source binds fresh and cleared file path summary frame state',()=>{
 assertHistoricalBinding(307,realRequire('./applicationMaintenanceInprocessSources-v307.json'),'03c9250c8999e3e9bde8126da26ba431742916dbf46f7414f169ad115eff27fd','5193895c386837e596c9c23c88fc0ff9ea2f7f987e2f3fd524db0ee08f9ddd18');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v306.json'))(ROOT));
});

test('v308 historical source binds verified SVG catalog promotion',()=>{
 assertHistoricalBinding(308,realRequire('./applicationMaintenanceInprocessSources-v308.json'),'337151a9b74d451b2778f84610d6e5471f0c6a3e9d006a02bf7912c98d8f432d','01fe24593acbae9238fee6410db339fc2cb2d930b525d58bd16fce603a0788cf');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v307.json'))(ROOT));
});

test('v309 historical source binds upload grounding and bounded file final response',()=>{
 assertHistoricalBinding(309,realRequire('./applicationMaintenanceInprocessSources-v309.json'),'b242bb5c3a43a3fac649964d1144307c1dbbad70cce7da913a4bde08f9e37fa8','0633b7f8856f881f7b7bb240f41b3597b295fa937f8228987a4cd2cf3f804db3');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v308.json'))(ROOT));
});

test('v310 historical source binds verified synthetic path catalog promotion',()=>{
 assertHistoricalBinding(310,realRequire('./applicationMaintenanceInprocessSources-v310.json'),'cfc195cf19f8886b856e460b83d67badb65c166027e547e1df35c291ba69d17b','9fc8ca2dc67536a98318051586dee6e89c274f032ca69f9016530969172a7a5c');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v309.json'))(ROOT));
});

test('v311 historical source binds precise synthetic path teaching guidance',()=>{
 assertHistoricalBinding(311,realRequire('./applicationMaintenanceInprocessSources-v311.json'),'5921b877a216c6f055b170d4ce3556053b696caf76191cab51035c400243ffbc','5f3e93546a4dbf39d092347242f3fdbedd1cd9cdb83cc729c577504e79f3b184');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v310.json'))(ROOT));
});

test('v312 historical source binds verified extension storage and serving catalog',()=>{
 assertHistoricalBinding(312,realRequire('./applicationMaintenanceInprocessSources-v312.json'),'e955c43a4c5fed8d6089fe74814200353a3f4ece46060080df8e2f9d02d4b0bb','a06e1c4d8c6341a3b1df0e80d1b3e969dc17431c123ef67a6f52f4ab116eb4ed');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v311.json'))(ROOT));
});

test('v313 historical source binds isolated credential disclosure and current-scene recovery',()=>{
 assertHistoricalBinding(313,realRequire('./applicationMaintenanceInprocessSources-v313.json'),'54e2ab03c2d958958106b91106876c54c21a475b495b08e699a0e0833b62c6ba','22f13f8963f188dd2dd616b2b084959f36953f2102ac7cab1b64ca1019ed7aca');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v312.json'))(ROOT));
});

test('v314 historical source binds verified credential disclosure catalog',()=>{
 assertHistoricalBinding(314,realRequire('./applicationMaintenanceInprocessSources-v314.json'),'0c4a1f78d199abf1522d691aa62546ecb051f16b67350541fc7161e45506cd88','3ed9048861f08d3ef3eb49ae70ccb0e39b0f53bf5a0eeef117a7600cdb04eb6d');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v313.json'))(ROOT));
});

test('v315 historical source binds owned policy final-response flow',()=>{
 assertHistoricalBinding(315,realRequire('./applicationMaintenanceInprocessSources-v315.json'),'c7f5d3840b59aa47ca056733f8cf12593913a114e090186bfab4b7d8867b52fa','90f1394e2c871cd80219b756b11c068ce0e5d3f6d17a5164ce82d9b111201fba');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v314.json'))(ROOT));
});

test('v316 historical source binds owned policy browser adapter composition',()=>{
 assertHistoricalBinding(316,realRequire('./applicationMaintenanceInprocessSources-v316.json'),'9054461f19aad57948f5b36fae89c986657fe0faa933e802123e1ba62022914a','7cb473a9665090c297640856d7dcc157fa0a042393c704f65efcc90dbe162ace');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v315.json'))(ROOT));
});

test('v317 historical source binds owned MCP discovery assessment and persistence',()=>{
 assertHistoricalBinding(317,realRequire('./applicationMaintenanceInprocessSources-v317.json'),'0f0e629ef9cb0b2e00b0a79260f00c879173a6f83f76775865a2bbae0473a620','54f5d981fbb20487b0b2c42199997325f171aae23d267f0cb9c6f0c48d282f34');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v316.json'))(ROOT));
});

test('v318 historical source binds strict invocation receipt package correction',()=>{
 assertHistoricalBinding(318,realRequire('./applicationMaintenanceInprocessSources-v318.json'),'eda2e5e3115c7fee3f95f1350c67a0d639bb0740aa98839e3dd2c783be1341db','4e935dca5653674766134a0c2904bd0c78ddff01c1e5095d855ecce15f616fec');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v317.json'))(ROOT));
});

test('v319 historical source binds authority-fenced fixed-mode assessment recovery',()=>{
 assertHistoricalBinding(319,realRequire('./applicationMaintenanceInprocessSources-v319.json'),'7485d6146e505d50e7db400434c12bf396802bb035b47ef244cf99bebfb7ee2a','95f518ef8cccfe4bcbc3892f6b6d27a96160329aa8b15a25de7660c2637d37ed');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v318.json'))(ROOT));
});

test('v320 historical source binds guarded verified discovery catalog promotion',()=>{
 assertHistoricalBinding(320,realRequire('./applicationMaintenanceInprocessSources-v320.json'),'6186cf09f0526d90abb3d4701146b12de5d5ea77103a38f9e9473d98aaea7353','87f3ca294303fef0c23ecfa223a9da9744c6c3f99bb524ee6146c022445b21e3');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v319.json'))(ROOT));
});

test('v321 historical source binds owned user lookup graph and assessment',()=>{
 assertHistoricalBinding(321,realRequire('./applicationMaintenanceInprocessSources-v321.json'),'3e5ad866a0220a8245835ff7a355602718ecd282a77cbdc3ac9c70453ed157a0','5c45c0f33a8691974bac4782452256c8b642ba9f5d591f5a724eea3932dfd4f9');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v320.json'))(ROOT));
});

test('v322 historical source binds owned polyglot preview graph, package and lifecycle',()=>{
 assertHistoricalBinding(322,realRequire('./applicationMaintenanceInprocessSources-v322.json'),'eaf43510d3366ccbb6a71d7dafc5d96ff08b0c8ac3b1ba66dd89d54f2cef20e2','8c8293813940d82563d0b544ae40dfc33a7158ea2ab4c9fa00656a7a499bfb3d');
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v321.json'))(ROOT));
});

test('v323 historical source binds guarded qualified polyglot catalog promotion',()=>{
 assertHistoricalBinding(323,realRequire('./applicationMaintenanceInprocessSources-v323.json'),
  '3eb23f560f4c373217bb37a71bfe0f827cfd30309bd9de0c32952933e8a5cd66',
  '32ac6ba4c76bcf77e0b267dca316b71e53db663d9120152f17ddf9c67ff31e2c');
 for(const name of ['server/config/secureshopCurriculum.js','server/database/postgres/secureshopAssessmentSeed.js','server/services/secureshopV07UploadPreviewGraph.js','server/services/secureshopV07UploadSourceReader.js','server/services/secureshopV07UploadEvidence.js','server/services/secureshopUploadPreviewClient.js','sidecars/sandbox-runner/owned-system/upload-preview-contract.js','sidecars/sandbox-runner/owned-system/local-package-manifest.json','db/postgres/workshop-migrations/secureshop_agents/0112_upload_preview_registry_successor.sql','scripts/install/secureshop-owned-system-upgrade.js']) rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v322.json'))(ROOT));
});

test('v324 historical source binds authored merchant pricing task and preserves recovery',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v323.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v324.json');
 const changed=['client/src/pages/secureshop/components/MerchantPricingConfirmation.jsx',
  'client/src/pages/secureshop/pages/merchant/pricingOperation.mjs',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundRoleChat.js',
  'server/services/secureshopRolePricingProposal.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(324,current,'20a783bd76d8f08aae17687a9ae4af84c9e76193c9d71bf1bbe9189a8a2f6a4f',
  '9776c655ebc962bc1b1fe9061e6bd8a1224e796e16c59bf45471a6c20e22c7c0');
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v325 historical source binds historical recovery retry fence',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v324.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v325.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js','server/services/secureshopAssessmentRecovery.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(325,current,'1592815497afce075f8daec06b650e28b3a6137932aa1921b3632d237056a01e',
  '332e39d7eeca8c4b5b91c65388881ad6669ee0d8bc0d68f1ab2a7efe424742fe');
 for(const name of changed)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v326 historical source binds owned customer agency role and canonical assessment',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v325.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v326.json');
 const changed=['client/src/pages/secureshop/bridge/operations.mjs',
  'client/src/pages/secureshop/components/BoundAgentLane.jsx',
  'client/src/pages/secureshop/hooks/useAgentStream.js',
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
  'server/routes/secureshop/boundGateway.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopAssessmentRecovery.js',
  'server/services/secureshopBoundAclRegistry.js',
  'server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundCustomerChat.js',
  'server/services/secureshopBoundReviewComposition.js'];
 const added=['db/postgres/workshop-migrations/secureshop_agents/0113_owned_agency_role_state.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0114_customer_agency_role_registry_successor.sql',
  'server/database/postgres/secureshopOwnedAgencyRoleRepository.js',
  'server/routes/secureshop/boundAgencyRoleAssessment.js',
  'server/services/secureshopAgencyRoleAssessment.js',
  'server/services/secureshopAgencyRoleEvidence.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files).filter(name=>!Object.hasOwn(previous.files,name)).sort(),added);
 assert.deepEqual(Object.keys(previous.files).filter(name=>!Object.hasOwn(current.files,name)),[]);
 assert.deepEqual(current.recoveryFiles,[...new Set([...previous.recoveryFiles,...added])].sort());
 assertHistoricalBinding(326,current,'b6d63ad5b719a18c64f11fdcf8a9f941842d18ab01f509e7249a170cc4afc032',
  'e0358c59a350f65932eae54856d13ad3b8a148a9d671661ad06959b5a75a3dc7');
 for(const name of [...changed,...added])rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v327 historical source binds current authenticated customer ID in role tool context',()=>{
  const previous=realRequire('./applicationMaintenanceInprocessSources-v326.json');
  const current=realRequire('./applicationMaintenanceInprocessSources-v327.json');
  const changed=['server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundCustomerChat.js'];
  assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
  assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
  assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(327,current,'6eb7dac060b4a6c6e36a24e868496f0c127b7d2468c6cde3f2765a637a795de7',
  '58c702087a4b808a7ae0b579ac7454a45dad92d9840615179ca37e6fb123bdb6');
 for(const name of changed)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v335 historical source binds report-claim pricing receipt and evidence path',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v334.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v335.json');
 const changed=['server/database/postgres/secureshopPricingRepository.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopBoundPricingTools.js',
  'server/services/secureshopPricingEvidence.js',
  'server/services/secureshopPricingExecutionConfig.js',
  'server/services/secureshopPricingReceipt.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(335,current,'3ed2301435ba80c91e0f24b7d87eaebbc2a4813be3aacc73c47f528bc2e861de',
  '29afdc6cdd058a3931c68eddc6db64822a74ccbd2acf14c63caa80778408b362');
 for(const name of changed)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v336 historical source binds mode-aware pricing report policy admission',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v335.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v336.json');
 const changed=['server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopPricingComposition.js',
  'server/services/secureshopPricingExecutionConfig.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(336,current,'5aa4a51ec1b4c9c853b287f0098ca8b406c6193150ecc6e7c3ab54683e5f3c4b',
  'cdb360b242366c911e2d17ce02bd9e69b0a8693dfbe825071842cb873754639c');
 for(const name of changed)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v337 historical source binds release-excluded assessment objective guards',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v336.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v337.json');
 const changed=['server/config/secureshopCurriculum.js',
  'server/database/postgres/objectiveJudgmentRepository.js',
  'server/database/postgres/secureshopAssessmentProgressRepository.js',
  'server/database/postgres/secureshopAssessmentSeed.js',
  'server/database/postgres/secureshopAssessmentStore.js',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'server/services/secureshopAssessmentCatalog.js',
  'server/services/secureshopAssessmentEligibility.js',
  'server/services/secureshopAssessmentRecovery.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(337,current,'ab532e8fb3b3483d24b899d031ee166923a365f9f63954722f6568584f0ab024',
  '1cb22549c6bacd10b5793f6da2adaf1e676fdb40a063aa8b80b762259e7f2928');
 for(const name of changed)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v338 historical source binds the qualified Listings package candidate',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v337.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v338.json');
 const changed=['scripts/install/manifests/owned-listings-arm64.candidate.json',
  'scripts/install/secureshop-owned-listings-qualified-candidate.js',
  'server/services/applicationMaintenanceInprocessAdmission.js'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(338,current,'9b9eee34757372cdf472140cca13c74fe7adedafab378a15a9f19ef64c991930',
  'b4f0ee15e5ac021cb7c0df2607def073a16a2961026538fad355a2988ec5bfd6');
 for(const name of changed)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v339 historical source binds hardened inventory references and owned local package candidate',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v338.json');
 const current=realRequire('./applicationMaintenanceInprocessSources-v339.json');
 const changed=['client/src/pages/secureshop/pages/merchant/inventoryReference.mjs',
  'server/services/applicationMaintenanceInprocessAdmission.js',
  'sidecars/sandbox-runner/owned-system/local-package-amd64.candidate.json'];
 assert.deepEqual(Object.keys(previous.files).filter(name=>previous.files[name]!==current.files[name]).sort(),changed);
 assert.deepEqual(Object.keys(current.files),Object.keys(previous.files));
 assert.deepEqual(current.recoveryFiles,previous.recoveryFiles);
 assertHistoricalBinding(339,current,'36585449ef212b5ae002b31237ba4bcc538b3c64f8e1fc6820b131297e853831',
  'dc0b75602d749c09e4d15708246d69e08ab2fe1479d67a65f622c6bf4f0927b3');
 for(const name of changed)rejectsSimulatedSourceDrift(name);
 denied(()=>bindingWith({},previous)(ROOT));
});

test('v340 historical declared inventory remains immutable',()=>{
 const current=realRequire('./applicationMaintenanceInprocessSources-v340.json');
 assertHistoricalBinding(340,current,'b0709d3b4ca86a63e403c308f5d52f5f4e8c3a8f2fba91bdc009d49e38bee436','827a55e2b88c05c27c941b2e88570c42e04e00d423318a73c1e84fcf62246bfc');
});

test('v341 historical declared inventory remains immutable',()=>{
 const previous=realRequire('./applicationMaintenanceInprocessSources-v341.json');
 assertHistoricalBinding(341,previous,'99781d32267b5a4a19e887f2e1563c5f7aae878233e70b5d7d10b3ac9d3c006c','325fb9054a737aba403b494bc9e9ef8e10cb94bf8826db5f9b5cfe650f2bda6b');
});

test('v342 current inventory binds and stale v341 denies',()=>{
 const current=realRequire('./applicationMaintenanceInprocessSources-v342.json');
 const source=realRequire(file).sourceBinding(ROOT);
 assert.match(source,/^[a-f0-9]{64}$/);
 assert.match(realRequire(file).recoverySourceBinding(ROOT,source),/^[a-f0-9]{64}$/);
 for(const name of ['server/services/secureshopBoundRoleChat.js','server/services/applicationMaintenanceInprocessAdmission.js']){assert.ok(Object.hasOwn(current.files,name));rejectsSimulatedSourceDrift(name);}
 denied(()=>bindingWith({},realRequire('./applicationMaintenanceInprocessSources-v341.json'))(ROOT));
});
