'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const parser=require('../client/node_modules/@babel/parser');
const manifest=require('../docs/secureshop/supported-action-manifest.json');
const allBindings=[...manifest.reviewedBindings,...manifest.commerceBindings,
 ...manifest.directMutationBindings,...manifest.teachingBindings,...manifest.panelBindings,
 ...manifest.accountDirectBindings,...manifest.uploadBindings,...manifest.credentialBindings,...manifest.manualListingBindings,...manifest.reviewModerationBindings,...manifest.assessmentBindings,
 ...manifest.availabilityBindings,...manifest.labApplicabilityBindings,...manifest.avatarApplicabilityBindings,...manifest.productSummaryBindings,...manifest.productQuestionBindings,...manifest.productReviewCreateBindings,...manifest.publicCatalogReadBindings,...manifest.customerPurchaseReadBindings,...manifest.authAccountLifecycleBindings,...manifest.productSimilarBindings];
const root=path.resolve(__dirname,'..');
const trees=new Map();
function tree(file){
 const full=path.resolve(root,file);
 assert.ok(full.startsWith(root+path.sep)&&fs.realpathSync(full)===full,'Canonical source reference');
 if(!trees.has(file))trees.set(file,parser.parse(fs.readFileSync(full,'utf8'),{sourceType:'unambiguous',plugins:['jsx']}));
 return trees.get(file);
}
function nodes(ast,predicate){
 const found=[];
 function visit(node){if(!node||typeof node!=='object')return;
  if(predicate(node))found.push(node);
  for(const [key,value] of Object.entries(node)){
   if(['loc','start','end','comments','leadingComments','trailingComments','innerComments','extra'].includes(key))continue;
   if(Array.isArray(value))value.forEach(visit);else if(value&&typeof value==='object')visit(value);
  }
 }
 visit(ast);return found;
}
const member=node=>node?.type==='Identifier'?node.name:
 node?.type==='MemberExpression'?`${member(node.object)}.${node.property?.name}`:null;
const calls=(ast,name)=>nodes(ast,n=>n.type==='CallExpression'&&member(n.callee)===name);
const named=(ast,name)=>nodes(ast,n=>(n.type==='FunctionDeclaration'&&n.id?.name===name)
 ||((n.type==='ObjectMethod'||n.type==='ObjectProperty')&&n.key?.name===name));
function functionDeclaration(ast,name){
 const found=nodes(ast,n=>n.type==='FunctionDeclaration'&&n.id?.name===name);
 assert.equal(found.length,1,name);return found[0];
}
function objectMethod(ast,name){
 const found=nodes(ast,n=>n.type==='ObjectMethod'&&n.key?.name===name);
 assert.equal(found.length,1,name);return found[0];
}
function localValue(ast,name){
 const found=nodes(ast,n=>n.type==='VariableDeclarator'&&n.id?.name===name);
 assert.equal(found.length,1,name);return found[0].init;
}
const sqlParts=ast=>nodes(ast,n=>n.type==='TemplateElement'||n.type==='StringLiteral')
 .map(n=>n.type==='TemplateElement'?n.value.cooked:n.value);

test('multipart upload registration binds only the conditional merchant product-manual effect, not Account avatar',async()=>{
 const binding=manifest.uploadBindings[0],source=binding.sourceBinding;
 assert.equal(manifest.uploadBindings.length,2);assert.equal(binding.actionId,'uploads.create');
 assert.equal(binding.supportedShape,'conditional_merchant_product_manual_only');
 const action=manifest.actions.find(row=>row.id===binding.actionId);
 assert.deepEqual([action.method,action.path,action.review],['POST','/api/secureshop/uploads',binding.actionId]);
 const {describeOperations}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 assert.deepEqual(describeOperations().separate.filter(row=>row.name==='uploads.create').map(row=>
  [row.method,row.path,row.bodyKind]),[['POST','/api/secureshop/uploads','multipart']]);
 const zone=functionDeclaration(tree(source.uiFile),'UploadZone');
 const submit=localValue(zone,'upload');
 const uploadButtons=nodes(zone,n=>n.type==='JSXOpeningElement'&&n.name?.name==='button'
  &&n.attributes.some(a=>a.name?.name==='onClick'&&a.value?.expression?.name==='upload'));
 assert.equal(uploadButtons.length,1);
 const disclosures=nodes(zone,n=>n.type==='LogicalExpression'&&n.operator==='&&'
  &&n.left?.type==='BinaryExpression'&&n.left.left?.name==='kind'
  &&n.left.right?.value==='product_manual'&&n.right?.type==='JSXElement'
  &&n.right.openingElement?.name?.name==='p'
  &&n.right.openingElement.attributes.some(a=>a.name?.name==='aria-label'
   &&a.value?.value==='Product manual upload consequence'));
 assert.equal(disclosures.length,1,'Only product manuals receive the scoped consequence disclosure');
 const disclosure=disclosures[0].right;
 const disclosureText=nodes(disclosure,n=>n.type==='JSXText').map(n=>n.value).join(' ');
 for(const phrase of ['stores and indexes this file for product #','may influence later product answers and recommendations',
  'not a confidentiality guarantee'])assert.ok(disclosureText.includes(phrase),phrase);
 assert.equal(nodes(disclosure,n=>n.type==='JSXExpressionContainer'&&n.expression?.name==='scopeId').length,1);
 assert.ok(disclosure.start<uploadButtons[0].start,'Consequence must be shown before explicit Upload');
 assert.equal(binding.confirmation.kind,'scoped_pre_submit_indexing_consequence_text_then_explicit_upload_button_source_traced');
 const requests=calls(submit,'fetch').filter(n=>n.arguments[0]?.value==='/api/secureshop/uploads'
  &&nodes(n.arguments[1],x=>x.type==='ObjectProperty'&&x.key?.name==='method'&&x.value?.value==='POST').length===1
  &&nodes(n.arguments[1],x=>x.type==='ObjectProperty'&&x.key?.name==='body'&&x.value?.name==='fd').length===1);
 assert.equal(requests.length,1);
 for(const [field,value] of [['kind','kind'],['scope_id','String'],['mime',null],['public','String']]){
  const matches=calls(submit,'fd.append').filter(n=>n.arguments[0]?.value===field);
  assert.equal(matches.length,1,`multipart ${field}`);
  if(value==='kind')assert.equal(matches[0].arguments[1]?.name,value);
  if(value==='String')assert.equal(member(matches[0].arguments[1]?.callee),'String');
 }
 assert.equal(calls(submit,'fd.append').filter(n=>n.arguments[0]?.value==='file').length,1);
 assert.equal(calls(submit,'fd.append').filter(n=>n.arguments[0]?.value==='recoveryScopeKey').length,0,
  'Current UploadZone does not yet send the optional scoped POST key');
 const listings=tree(source.merchantUiFile);
 const manualZones=nodes(listings,n=>n.type==='JSXOpeningElement'&&n.name?.name==='UploadZone'
  &&n.attributes.some(a=>a.name?.name==='kind'&&a.value?.value==='product_manual')
  &&n.attributes.some(a=>a.name?.name==='scopeId'&&member(a.value?.expression)==='initial.id'));
 assert.equal(manualZones.length,1);
 for(const [prop,value] of [['authToken','uploadAuthToken'],['merchantId','uploadMerchantId'],['transport','uploadTransport']])
  assert.equal(manualZones[0].attributes.filter(a=>a.name?.name===prop&&member(a.value?.expression)===value).length,1,prop);
 const editBranch=nodes(listings,n=>n.type==='LogicalExpression'&&n.operator==='&&'
  &&nodes(n.right,x=>x===manualZones[0]).length===1
  &&nodes(n.left,x=>x.type==='BinaryExpression'&&x.left?.name==='mode'&&x.right?.value==='edit').length===1
  &&nodes(n.left,x=>x.type==='BinaryExpression'&&member(x.left)==='initial.status'&&x.right?.value==='active').length===1);
 assert.ok(editBranch.length>=1,'Only active listing edit presents product-manual upload');
 const account=tree(source.accountUiFile);
 assert.equal(nodes(account,n=>n.type==='JSXOpeningElement'&&n.name?.name==='UploadZone'
  &&n.attributes.some(a=>a.name?.name==='kind'&&a.value?.value==='avatar')).length,1,
 'Advertised Account avatar reuses endpoint but is not a manual upload');
 const route=tree(source.routeFile);
 const conditional=nodes(route,n=>n.type==='IfStatement'&&n.test?.name==='productManualIngestion'
  &&calls(n.consequent,'router.post').some(call=>call.arguments[0]?.value==='/uploads')
  &&calls(n.alternate,'registerUnavailable').length===1);
 assert.equal(conditional.length,1);
 const uploadRoute=calls(conditional[0].consequent,'router.post').find(n=>n.arguments[0]?.value==='/uploads');
 assert.equal(calls(uploadRoute,'persona').filter(n=>n.arguments[0]?.value==='merchant').length,1);
 assert.equal(calls(uploadRoute,'productManualIngestion.upload').length,1);
 assert.ok(nodes(uploadRoute,n=>n.type==='BinaryExpression'&&n.operator==='!=='
  &&member(n.left)==='body.kind'&&n.right?.value==='product_manual').length,
 'Avatar and other non-manual kinds are rejected by the bound gateway');
 assert.ok(calls(uploadRoute,'resourceId').length);
 const composition=tree(source.compositionFile),application=tree(source.applicationFile);
 assert.equal(calls(composition,'createSecureShopBoundManualIngestion').length,1);
 assert.ok(nodes(composition,n=>n.type==='IfStatement'&&n.test?.name==='files'
  &&calls(n.consequent,'createSecureShopBoundManualIngestion').length===1).length);
 assert.ok(nodes(application,n=>n.type==='ObjectProperty'&&n.key?.name==='productManualIngestion'
  &&member(n.value)==='composition.productManualIngestion').length);
 const service=tree(source.serviceFile),ingest=objectMethod(service,'upload');
 for(const callee of ['catalog.getOwnedMerchantProduct','writer.writeAndReadBack','extractor',
  'embedder.embed','runner.run'])assert.ok(calls(ingest,callee).length,callee);
 assert.ok(calls(ingest,'selectedRepository.appendManual').length);
 assert.ok(calls(ingest,'modelIdentity').length>=2,'Internal model identity checks are not original-actor qualification');
 const writer=objectMethod(tree(source.writerFile),'writeAndReadBack');
 assert.equal(calls(writer,'files.writeFile').length,1);assert.equal(calls(writer,'files.readFile').length,1);
 const append=functionDeclaration(tree(source.repositoryFile),'appendManual');
 assert.ok(calls(append,'withSceneLease').length);assert.ok(calls(append,'assertSceneGrant').length>=2);
 assert.ok(sqlParts(append).some(sql=>sql.includes('append_product_manual_retrieval_attested')));
 assert.equal(binding.runtimeEvidence,null);assert.deepEqual(binding.linkedObjectiveIds,[]);
 assert.equal(binding.recovery.nativeVerified,false);
});

test('manual receipt GET and keyed POST are source-wired without claiming rendered recovery',async()=>{
 const binding=manifest.uploadBindings[1],source=binding.sourceBinding;
 assert.equal(binding.actionId,'uploads.productManual.receipt');
 const action=manifest.actions.find(row=>row.id===binding.actionId);
 assert.deepEqual([action.method,action.path,action.review],
  ['GET','/api/secureshop/uploads/product-manual/receipt',binding.actionId]);
 const {describeOperations}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const registered=describeOperations().operations.filter(row=>row.name===binding.actionId);
 assert.equal(registered.length,1);
 assert.deepEqual([registered[0].method,registered[0].pathTemplate],['GET',action.path]);
 const operation=tree(source.bridgeFile);
 const bridge=nodes(operation,n=>n.type==='ObjectProperty'&&n.key?.value===binding.actionId);
 assert.equal(bridge.length,1);
 const query=nodes(bridge[0],n=>n.type==='ObjectProperty'&&n.key?.name==='query');
 assert.equal(query.length,1);
 assert.deepEqual(query[0].value.elements.map(n=>n.value),
  ['productId','sha256','sizeBytes','filename','mime','public','recoveryScopeKey']);
 const route=tree(source.routeFile);
 const conditional=nodes(route,n=>n.type==='IfStatement'&&n.test?.name==='productManualIngestion'
  &&calls(n.consequent,'router.get').some(c=>c.arguments[0]?.value==='/uploads/product-manual/receipt')
  &&calls(n.alternate,'router.get').some(c=>c.arguments[0]?.value==='/uploads/product-manual/receipt'));
 assert.equal(conditional.length,1,'GET is conditional, with an unavailable fallback');
 const get=calls(conditional[0].consequent,'router.get').find(c=>c.arguments[0]?.value==='/uploads/product-manual/receipt');
 assert.equal(calls(get,'persona').filter(c=>c.arguments[0]?.value==='merchant').length,1);
 assert.equal(calls(get,'productManualIngestion.readReceipt').length,1);
 assert.equal(calls(get,'exactQuery').length,1);
 assert.equal(calls(get,'res.set').filter(c=>c.arguments[0]?.value==='Cache-Control'&&c.arguments[1]?.value==='no-store').length,1);
 const required=localValue(get,'fields');
 assert.deepEqual(required.elements.map(n=>n.value),
  ['productId','sha256','sizeBytes','filename','mime','public','recoveryScopeKey']);
 const post=calls(conditional[0].consequent,'router.post').find(c=>c.arguments[0]?.value==='/uploads');
 assert.equal(calls(post,'manualRecovery.validateManualUploadRecoveryKey').length,1);
 assert.equal(calls(post,'productManualIngestion.upload').length,1);
 const service=objectMethod(tree(source.serviceFile),'readReceipt');
 for(const callee of ['personaAuthority.capture','retained','repository.readReceipt','recovery.manualUploadOperationId'])
  assert.ok(calls(service,callee).length,callee);
 assert.equal(calls(service,'retained').length,2,'Retained owner/scene checks surround repository read');
 for(const callee of ['writer.writeAndReadBack','embedder.embed','runner.run','retrieval.ensureProvisioned'])
  assert.equal(calls(service,callee).length,0,`Readback must not call ${callee}`);
 const repository=objectMethod(tree(source.repositoryFile),'readReceipt');
 for(const callee of ['checkCurrent','withSceneLease','assertSceneGrant','read'])
  assert.ok(calls(repository,callee).length,callee);
 assert.equal(calls(repository,'appendManual').length,0);
 const reference=tree(source.clientReferenceFile);
 const store=functionDeclaration(reference,'createProductManualPendingReferenceStore');
 for(const method of ['reserveInitialPost','reconcile'])assert.equal(nodes(store,n=>n.type==='ObjectMethod'&&n.key?.name===method).length,1);
 for(const callee of ['storage.setItem','storage.removeItem','flush'])assert.ok(calls(store,callee).length,callee);
 const zone=functionDeclaration(tree(source.uiFile),'UploadZone');
 const bound=localValue(zone,'boundManual');
 assert.equal(calls(bound,'getBridgeFetchMetadata').length,1);
 assert.equal(nodes(bound,n=>n.type==='BinaryExpression'&&n.operator==='==='
  &&n.left?.name==='kind'&&n.right?.value==='product_manual').length,1);
 assert.equal(calls(zone,'useProductManualUpload').length,1);
 assert.equal(calls(localValue(zone,'upload'),'manual.uploadManual').length,1);
 assert.equal(nodes(zone,n=>n.type==='JSXOpeningElement'&&n.name?.name==='button'
  &&n.attributes.some(a=>a.name?.name==='onClick'&&member(a.value?.expression)==='manual.checkSaved')).length,1);
 const hook=functionDeclaration(tree(source.clientHookFile),'useProductManualUpload');
 const initial=localValue(hook,'uploadManual'),saved=localValue(hook,'checkSaved');
 const reservation=calls(initial,'storeRef.current.reserveInitialPost');
 const posts=calls(initial,'transport');
 assert.equal(calls(initial,'readReceipt').length,2,'Preflight and post-success readback both use GET');
 assert.equal(reservation.length,1);assert.equal(posts.length,1);
 assert.ok(reservation[0].start<posts[0].start,'Acknowledged reference precedes the only bound POST');
 assert.equal(nodes(initial,n=>n.type==='AwaitExpression'&&n.argument===reservation[0]).length,1);
 assert.equal(nodes(initial,n=>n.type==='AwaitExpression'&&n.argument===posts[0]).length,1);
 assert.equal(calls(initial,'body.append').filter(c=>c.arguments[0]?.value==='recoveryScopeKey').length,1);
 assert.equal(calls(initial,'verifyProductManualLookup').length,2);
 assert.equal(calls(initial,'storeRef.current.reconcile').length,1);
 assert.equal(calls(saved,'readReceipt').length,1);
 assert.equal(calls(saved,'transport').length,0,'Explicit saved recovery cannot POST');
 assert.equal(calls(saved,'storeRef.current.reconcile').length,1);
 const read=functionDeclaration(tree(source.clientHookFile),'readReceipt');
 assert.equal(calls(read,'transport').length,1);
 assert.equal(nodes(read,n=>n.type==='ObjectProperty'&&n.key?.name==='method'&&n.value?.value==='GET').length,1);
 assert.equal(calls(read,'response.json').length,1);
 assert.equal(calls(zone,'fetch').filter(c=>c.arguments[0]?.value===action.path).length,0,
  'UploadZone delegates readback to its bound hook');
 assert.equal(binding.runtimeEvidence,null);
 assert.equal(binding.recovery.nativeVerified,false);
 assert.deepEqual(binding.linkedObjectiveIds,[]);
});

test('manual native observation is limited to API indexing/readback, never rendered or Judge qualification',()=>{
 const [upload,receiptBinding]=manifest.uploadBindings;
 const nativeUpload=upload.nativeApiObservation,nativeReceipt=receiptBinding.nativeApiObservation;
 assert.deepEqual([nativeUpload.suite,nativeReceipt.suite],['manual-private-model','manual-private-model']);
 assert.equal(nativeUpload.fixture,nativeReceipt.fixture);
 assert.equal(nativeUpload.launcher,nativeReceipt.launcher);
 assert.equal(nativeUpload.runId,nativeReceipt.runId);
 assert.equal(nativeUpload.result,'one_native_test_passed_zero_skips');
 assert.equal(nativeUpload.scope,'two_original_keyed_public_and_private_posts_indexed_with_exact_receipt_readback');
 assert.equal(nativeReceipt.scope,'nine_no_store_receipt_gets_with_exact_read_only_snapshots_and_scoped_denials');
 for(const binding of [upload,receiptBinding]){
  assert.deepEqual([binding.nativeApiObservation.renderedUi,binding.nativeApiObservation.judge,
   binding.nativeApiObservation.objectiveCredit,binding.recovery.nativeVerified,binding.runtimeEvidence],
   [false,false,false,false,null]);
 }
 const fixture=tree(nativeUpload.fixture);
 const receiptGet=localValue(fixture,'receiptGet');
 assert.equal(calls(receiptGet,'request').length,1);
 assert.equal(calls(receiptGet,'uploadSnapshot').length,2);
 assert.equal(calls(fixture,'assertManualReceipt').length,3);
 assert.equal(calls(fixture,'judge').length,0);
 const source=fs.readFileSync(path.resolve(root,nativeUpload.fixture),'utf8');
 for(const exact of ["clientAcknowledgementSimulation:'discard-after-successful-response'",
  "assert.equal(record.cacheControl,'no-store')",'assert.equal(judgeAttempts,0)',
  "receiptGet(privateUpload.recoveryLookup,foreign.headers,403)",
  "receiptGet(privateUpload.recoveryLookup,foreignMerchant.headers,401)",
  "receiptGet(privateUpload.recoveryLookup,merchant.headers,409)"])
  assert.ok(source.includes(exact),exact);
 const launcher=fs.readFileSync(path.resolve(root,nativeUpload.launcher),'utf8');
 assert.ok(launcher.includes('"manual-private-model": {'));
 assert.ok(launcher.includes('"test": "tests/postgres/secureshopProtectedManualActual.integration.test.js"'));
});

test('Account direct profile and address writes trace role branch, events, bridge requests and scoped effects',async()=>{
 const ids=['account.profile.update','account.addresses.create','account.addresses.update','account.addresses.delete'];
 assert.deepEqual(manifest.accountDirectBindings.map(row=>row.actionId),ids);
 const {matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const account=tree('client/src/pages/secureshop/pages/Account.jsx');
 const root=functionDeclaration(account,'Account'),profile=functionDeclaration(account,'ProfileTab');
 const general=functionDeclaration(account,'AddressesTab'),bound=functionDeclaration(account,'BoundAddressesTab');
 const editor=functionDeclaration(account,'AddressEditor');
 const auth=tree('client/src/pages/secureshop/context/AuthContext.jsx');
 const gateway=tree('server/routes/secureshop/boundGateway.js');
 const service=tree('server/services/secureshopBoundAccount.js');
 const repo=tree('server/database/postgres/secureshopBoundAccountRepository.js');
 assert.equal(nodes(root,n=>n.type==='ConditionalExpression'&&n.test?.type==='LogicalExpression'
  &&calls(n.test,'getBridgeFetchMetadata').length===1
  &&nodes(n.consequent,x=>x.type==='JSXIdentifier'&&x.name==='BoundAddressesTab').length===1
  &&nodes(n.alternate,x=>x.type==='JSXIdentifier'&&x.name==='AddressesTab').length===1).length,1);
 assert.equal(nodes(profile,n=>n.type==='ConditionalExpression'&&n.test?.type==='BinaryExpression'
  &&n.test.right?.value==='customer'
  &&nodes(n.consequent,x=>x.type==='JSXIdentifier'&&x.name==='PracticeProfileUpdate').length===1
  &&nodes(n.alternate,x=>x.type==='JSXOpeningElement'&&x.name?.name==='form'
   &&x.attributes.some(a=>a.name?.name==='onSubmit'&&a.value?.expression?.name==='save')).length===1).length,1);
 assert.equal(calls(localValue(profile,'save'),'saveProfile').length,1);
 const authSave=localValue(auth,'saveProfile');
 const profileRequest=calls(authSave,'fetch').filter(n=>n.arguments[0]?.type==='TemplateLiteral'
  &&n.arguments[0].expressions[0]?.name==='API_BASE'
  &&n.arguments[0].quasis[1]?.value.cooked==='/users/me');
 assert.equal(profileRequest.length,1);
 assert.equal(nodes(profileRequest[0],n=>n.type==='ObjectProperty'&&n.key?.name==='method'&&n.value?.value==='PUT').length,1);
 assert.equal(nodes(editor,n=>n.type==='JSXOpeningElement'&&n.name?.name==='form'
  &&n.attributes.some(a=>a.name?.name==='onSubmit'&&a.value?.expression?.name==='submit')).length,1);
 const editorSubmit=localValue(editor,'submit');
 const editorRequest=calls(editorSubmit,'fetch');assert.equal(editorRequest.length,1);
 assert.equal(editorRequest[0].arguments[0]?.name,'url');
 const url=localValue(editorSubmit,'url');
 assert.equal(url.type,'ConditionalExpression');assert.equal(url.test?.name,'isNew');
 assert.equal(url.consequent?.value,'/api/secureshop/v2/auth/users/me/addresses');
 assert.equal(url.alternate?.type,'TemplateLiteral');
 assert.equal(url.alternate.expressions[0]?.object?.name,'initial');
 assert.equal(url.alternate.expressions[0]?.property?.name,'id');
 const method=nodes(editorRequest[0].arguments[1],n=>n.type==='ObjectProperty'&&n.key?.name==='method');
 assert.equal(method.length,1);assert.equal(method[0].value?.type,'ConditionalExpression');
 assert.equal(method[0].value.test?.name,'isNew');
 assert.equal(method[0].value.consequent?.value,'POST');assert.equal(method[0].value.alternate?.value,'PUT');
 assert.equal(nodes(editorRequest[0].arguments[1],n=>n.type==='CallExpression'&&member(n.callee)==='JSON.stringify'
  &&n.arguments[0]?.name==='form').length,1);
 for(const tab of [general,bound]){
  assert.equal(calls(tab,'useAddressDeleteConfirmation').length,1);
  assert.equal(nodes(tab,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
   &&calls(n.value?.expression,'stageDelete').length===1).length,1,'Delete button stages selected address');
  const dialogs=nodes(tab,n=>n.type==='JSXOpeningElement'&&n.name?.name==='AccountConsequenceConfirmation'
   &&n.attributes.some(a=>a.name?.name==='onConfirm'&&a.value?.expression?.name==='confirmDelete')
   &&n.attributes.some(a=>a.name?.name==='onCancel'&&calls(a.value?.expression,'setPendingDelete').length===1));
  assert.equal(dialogs.length,1,'Only the staged consequence dialog confirms the effect');
  const refresh=localValue(tab,tab===bound?'refresh':'load');
  assert.equal(calls(refresh,'setPendingDelete').length,1,'Refresh invalidates a staged target');
  assert.equal(calls(refresh,'setDeleteUnresolved').filter(n=>n.arguments[0]?.value===false).length,1,
   'Only successful list readback unlocks an uncertain deletion');
 }
 const deleteHook=functionDeclaration(account,'useAddressDeleteConfirmation');
 const stage=localValue(deleteHook,'stageDelete'),confirm=localValue(deleteHook,'confirmDelete');
 assert.ok(nodes(stage,n=>n.type==='Identifier'&&n.name==='listCurrent').length);
 assert.equal(calls(stage,'setPendingDelete').length,1);
 assert.ok(nodes(confirm,n=>n.type==='Identifier'&&n.name==='pendingDelete').length);
 assert.ok(nodes(confirm,n=>n.type==='Identifier'&&n.name==='requestEpoch').length);
 assert.ok(nodes(confirm,n=>n.type==='Identifier'&&n.name==='deleteUnresolved').length);
 assert.equal(calls(confirm,'setPendingDelete').length,1);
 const deleteRequest=calls(confirm,'intent.transport').filter(n=>n.arguments[0]?.type==='TemplateLiteral'
  &&n.arguments[0].quasis[0]?.value.cooked==='/api/secureshop/v2/auth/users/me/addresses/'
  &&n.arguments[0].expressions[0]?.object?.name==='intent'
  &&n.arguments[0].expressions[0]?.property?.name==='id'
  &&nodes(n.arguments[1],x=>x.type==='ObjectProperty'&&x.key?.name==='method'&&x.value?.value==='DELETE').length===1);
 assert.equal(deleteRequest.length,1);
 assert.ok(nodes(confirm,n=>n.type==='AssignmentExpression'&&member(n.left)==='deletingRef.current'
  &&n.right?.name==='intent'&&n.start<deleteRequest[0].start).length);
 assert.equal(calls(confirm,'refresh').length,1);
 assert.equal(calls(confirm,'setDeleteUnresolved').filter(n=>n.arguments[0]?.value===true).length,1);
 const routes={
  'account.profile.update':['router.put','/v2/auth/users/me'],
  'account.addresses.create':['router.post','/v2/auth/users/me/addresses'],
  'account.addresses.update':['router.put','/v2/auth/users/me/addresses/:id'],
  'account.addresses.delete':['router.delete','/v2/auth/users/me/addresses/:id'],
 };
 for(const binding of manifest.accountDirectBindings){
  const action=manifest.actions.find(row=>row.id===binding.actionId);
  assert.ok(action);assert.equal(action.review,action.id);
  assert.equal(matchOperationRequest({pathname:action.path.replace(':id','11'),method:action.method,
   query:{},body:action.method==='DELETE'?undefined:Object.fromEntries(binding.confirmation.fields.map(key=>
    [key,key==='is_default'?false:key==='line1'?'1 Main St':'value']))})?.name,action.id);
  const [methodName,path]=routes[action.id];
  const route=calls(gateway,methodName).filter(n=>n.arguments[0]?.value===path);
  assert.equal(route.length,1,action.id);assert.equal(calls(route[0],`account.${binding.sourceBinding.serviceMethod}`).length,1);
  assert.equal(calls(route[0],'persona').length,1);
  const domain=objectMethod(service,binding.sourceBinding.serviceMethod);
  assert.equal(calls(domain,`repository.${binding.sourceBinding.repositoryMethod}`).length,1);
  const effect=objectMethod(repo,binding.sourceBinding.repositoryMethod);
  assert.equal(calls(effect,'guarded').length,1);
  assert.deepEqual(binding.linkedObjectiveIds,[]);assert.equal(binding.recovery.nativeVerified,false);
 }
 const guarded=functionDeclaration(repo,'guarded');
 assert.ok(calls(guarded,'checkCurrent').length>=2);assert.ok(calls(guarded,'assertSceneGrant').length>=2);
 assert.equal(calls(objectMethod(repo,'updateProfile'),'saveProfileWithClient').length,1);
 assert.equal(calls(objectMethod(repo,'saveAddress'),'saveAddressWithClient').length,1);
 for(const helper of ['saveProfileWithClient','saveAddressWithClient']){
  const worker=functionDeclaration(repo,helper);
  assert.equal(calls(worker,'lockAccount').length,1);assert.equal(calls(worker,'audit').length,1);
  assert.ok(sqlParts(worker).some(sql=>sql.includes('target_id')&&sql.includes('shop_user_id')));
 }
 const deletion=objectMethod(repo,'deleteAddress');
 assert.ok(sqlParts(deletion).some(sql=>sql.includes('DELETE FROM secureshop_review.product_target_addresses')
  &&sql.includes('target_id=$1 AND shop_user_id=$2 AND address_id=$3')));
 assert.equal(calls(deletion,'audit').length,1);
 assert.equal(nodes(deletion,n=>n.type==='IfStatement'&&n.test?.object?.name==='result'
  &&n.test?.property?.name==='rowCount'&&calls(n.consequent,'audit').length===1).length,1);
 const composition=tree('server/services/secureshopBoundReviewComposition.js');
 assert.equal(calls(composition,'createSecureShopBoundAccount').length,1);
 const application=tree('server/services/secureshopBoundApplication.js');
 assert.ok(nodes(application,n=>n.type==='ObjectProperty'&&n.key?.name==='account'
  &&member(n.value)==='composition.account').length);
});

test('credential controls connect scoped UI callbacks through the closed bridge to exact bound methods',async()=>{
 const {matchOperationRequest,compileOperation}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 for(const binding of manifest.credentialBindings){
  const action=manifest.actions.find(row=>row.id===binding.actionId),source=binding.sourceBinding,trace=binding.uiTrace;
  const component=functionDeclaration(tree(trace.file),trace.component);
  const callback=localValue(component,trace.handler);
  if(trace.requestCallee==='transport')
   assert.equal(member(localValue(component,'transport')),'window.fetch','Captured transport must be the installed bridge fetch');
  const uiEventHandler=trace.stageHandler||trace.handler;
  assert.ok(nodes(component,n=>n.type==='JSXAttribute'&&n.name?.name===trace.event
   &&(n.value?.expression?.name===uiEventHandler||calls(n.value?.expression,uiEventHandler).length)).length);
  const requests=calls(callback,trace.requestCallee).filter(n=>{
   const url=n.arguments[0],literal=url?.type==='StringLiteral'?url.value:
    url?.type==='TemplateLiteral'?url.quasis.map(q=>q.value.cooked).join(''):null;
   return literal===action.path.replace(/:[^/]+/g,'')
    &&n.arguments[1]?.properties?.some(p=>p.key?.name==='method'&&p.value?.value===action.method);
  });
  assert.equal(requests.length,1,binding.actionId);
  const path=action.path.replace(':id','11111111-1111-4111-8111-111111111111');
  const body=binding.confirmation.fields.length?Object.fromEntries(binding.confirmation.fields.map(key=>[key,'controlled-not-a-secret'])):undefined;
  const matched=matchOperationRequest({pathname:path,method:action.method,query:{},body});
  assert.equal(matched.name,action.id);
  const compiled=compileOperation(matched.name,matched.input);
  assert.equal(compiled.path,path);assert.equal(compiled.method,action.method);assert.deepEqual(compiled.body,body);
  const routes=calls(tree(source.routeFile),'router.post').filter(n=>n.arguments[0]?.value===action.path.slice('/api/secureshop'.length));
  assert.equal(routes.length,1);assert.ok(calls(routes[0],`personaAuth.${source.serviceMethod}`).length);
  assert.ok(calls(routes[0],'persona').length);
  const method=objectMethod(tree(source.serviceFile),source.serviceMethod);
  assert.ok(calls(method,`repository.${source.repositoryMethod}`).length);
  assert.ok(calls(method,'launches.assertCurrent').length>=2);
  const effect=objectMethod(tree(source.repositoryFile),source.repositoryMethod);
  assert.ok(calls(effect,'withLaunchLock').length);assert.ok(calls(effect,'audit').length);
  for(const field of ['platform_launch_id','platform_scenario_id','platform_launch_generation',
   'original_platform_owner_id','original_platform_session_id','shop_user_id'])
   assert.ok(sqlParts(effect).some(sql=>sql.includes(field)),`${binding.actionId}: scoped ${field}`);
  assert.equal(nodes(effect,n=>n.type==='Identifier'&&n.name==='operationId').length,0);
  assert.deepEqual(binding.linkedObjectiveIds,[]);assert.equal(binding.recovery.nativeVerified,false);
  assert.equal(trace.runtimeVerified,false);
  for(const file of binding.controlledContracts)tree(file);
 }
 const button=tree('client/src/pages/secureshop/components/Button.jsx');
 assert.ok(nodes(button,n=>n.type==='JSXOpeningElement'&&member(n.name)==='motion.button'
  &&n.attributes.some(a=>a.name?.name==='onClick'&&a.value?.expression?.name==='onClick')).length
  ||nodes(button,n=>n.type==='JSXOpeningElement'&&n.name?.type==='JSXMemberExpression'
   &&n.name.object?.name==='motion'&&n.name.property?.name==='button'
   &&n.attributes.some(a=>a.name?.name==='onClick'&&a.value?.expression?.name==='onClick')).length);
});

test('credential bridge is installed before rendering and the supported application dispatches its gateway',()=>{
 const bridge=manifest.credentialBridge;
 const runtime=functionDeclaration(tree(bridge.frameRuntime),'startShopFrame');
 assert.ok(calls(runtime,'createBridgeFetch').length);
 const assignments=nodes(runtime,n=>n.type==='AssignmentExpression'&&member(n.left)==='frameWindow.fetch'
  &&n.right?.name==='patchedFetch');
 assert.equal(assignments.length,1);assert.ok(assignments[0].start<calls(runtime,'render')[0].start);
 const fetch=tree(bridge.fetchAdapter);
 assert.ok(calls(fetch,'matchOperationRequest').length);assert.ok(calls(fetch,'bridge.request').length);
 assert.ok(calls(functionDeclaration(tree(bridge.compiler),'compileBridgeOperation'),'compileOperation').length);
 assert.ok(calls(tree(bridge.handshake),'createHostTransport').some(n=>
  n.arguments[0].properties.some(p=>p.key?.name==='compileOperation')));
 const execute=functionDeclaration(tree(bridge.transport),'execute');
 assert.ok(calls(execute,'compileOperation').length);
 assert.ok(calls(execute,'headers.set').some(n=>n.arguments[0]?.value==='X-OWASP-AI-GOAT-SecureShop-Launch'));
 assert.ok(calls(execute,'fetchImpl').some(n=>n.arguments[1].properties.some(p=>p.key?.name==='credentials'&&p.value?.value==='omit')));
 const app=tree(bridge.applicationMount);
 assert.ok(calls(app,'app.use').some(n=>n.arguments[0]?.value==='/api/secureshop'
  &&nodes(n,x=>x.type==='CallExpression'&&x.callee?.property?.name==='createSecureShopBoundDispatch').length));
 assert.ok(nodes(app,n=>n.type==='AssignmentExpression'&&member(n.left)==='app.locals.secureshopBoundGateway'
  &&member(n.right)==='bound.gateway').length);
 assert.ok(calls(tree(bridge.boundDispatch),'gateway').length);
 assert.ok(calls(tree(manifest.compositionSource),'createSecureShopBoundPersonaAuth').length);
 assert.ok(nodes(tree(manifest.applicationSource),n=>n.type==='ObjectProperty'&&n.key?.name==='personaAuth'
  &&member(n.value)==='composition.personaAuth').length);
 const lock=functionDeclaration(tree(manifest.credentialBindings[0].sourceBinding.repositoryFile),'withLaunchLock');
 for(const sql of ['BEGIN','COMMIT','ROLLBACK'])assert.ok(sqlParts(lock).includes(sql));
});

test('credential consequence and recovery claims distinguish password, key rotation and session revocation',()=>{
 const source=manifest.credentialBindings[0].sourceBinding,repo=tree(source.repositoryFile),service=tree(source.serviceFile);
 const password=objectMethod(service,'changePassword');
 assert.ok(calls(password,'bcrypt.compare').length);assert.ok(calls(password,'bcrypt.hash').length);
 const effect=objectMethod(repo,'changePassword');
 assert.ok(sqlParts(effect).some(sql=>sql.includes('SET credential_version=$1')));
 assert.ok(sqlParts(effect).some(sql=>sql.includes('session_id<>$7 AND revoked_at IS NULL')));
 const rotation=objectMethod(service,'rotateApiKey');
 assert.ok(calls(rotation,'randomKeyBytes').some(n=>n.arguments[0]?.value===16));
 assert.ok(sqlParts(objectMethod(repo,'rotateApiKey')).some(sql=>sql.includes('SET api_key_plaintext=$7,api_key_sha256=$8,api_key_version=$9')));
 const revoke=objectMethod(repo,'revokeOwnedSession');
 assert.ok(calls(revoke,'assertActor').length);
 assert.ok(sqlParts(revoke).some(sql=>sql.includes('revoked_at IS NULL AND expires_at>clock_timestamp()')));
 const account=tree('client/src/pages/secureshop/pages/Account.jsx');
 const security=functionDeclaration(account,'SecurityTab');
 assert.ok(nodes(security,n=>n.type==='ConditionalExpression'&&n.test?.name==='standalone'
  &&calls(n.consequent,'window.parent.postMessage').some(call=>call.arguments[0]?.properties?.some(p=>p.key?.name==='type'&&p.value?.value==='password-route'))
  &&nodes(n.alternate,x=>x.type==='JSXAttribute'&&x.name?.name==='onSubmit'&&x.value?.expression?.name==='submit').length).length);
 const sessions=functionDeclaration(account,'SessionsTab'),revokeUi=localValue(sessions,'revoke');
 assert.ok(calls(revokeUi,'logout').length);assert.ok(calls(revokeUi,'load').length);assert.ok(calls(revokeUi,'isCurrent').length);
 const keyUi=functionDeclaration(account,'APIKeysTab'),rotateUi=localValue(keyUi,'rotate');
 assert.ok(calls(rotateUi,'setKey').length);assert.ok(calls(rotateUi,'setReveal').length);
 // Source fact only; do not treat a plaintext teaching label as a confirmation exemption.
 assert.equal(manifest.credentialBindings.find(row=>row.actionId==='account.apiKeys.rotate').exceptionReview,
  'plaintext_teaching_storage_does_not_exempt_rotation_confirmation_or_scope_fencing');
});

test('credential dialogs stage scoped intent before one POST and unlock uncertainty only after successful GET',()=>{
 const account=tree('client/src/pages/secureshop/pages/Account.jsx');
 const dialog=functionDeclaration(account,'AccountConsequenceConfirmation');
 assert.ok(nodes(dialog,n=>n.type==='JSXOpeningElement'&&n.name?.name==='Dialog'
  &&n.attributes.some(a=>a.name?.name==='onClose')).length);
 assert.ok(nodes(dialog,n=>n.type==='JSXElement'&&n.openingElement?.name?.name==='Button'
  &&nodes(n,x=>x.type==='JSXText'&&x.value.trim()==='Cancel').length).length);
 for(const [actionId,flag,pending,lock] of [
  ['account.apiKeys.rotate','rotationUnresolved','pendingRotation','rotatingRef.current'],
  ['account.sessions.revoke','revokeUnresolved','pendingRevoke','revokingRef.current'],
 ]){
  const binding=manifest.credentialBindings.find(row=>row.actionId===actionId),trace=binding.uiTrace;
  assert.equal(trace.confirmationComponent,'AccountConsequenceConfirmation');
  const component=functionDeclaration(account,trace.component);
  const stage=localValue(component,trace.stageHandler),confirm=localValue(component,trace.handler);
  assert.equal(stage.type,'ArrowFunctionExpression');assert.equal(confirm.type,'ArrowFunctionExpression');
  assert.equal(calls(stage,'transport').length,0,`${actionId}: stage itself cannot dispatch`);
  assert.ok(nodes(component,n=>n.type==='JSXOpeningElement'&&n.name?.name===trace.confirmationComponent
   &&n.attributes.some(a=>a.name?.name==='onConfirm'&&a.value?.expression?.name===trace.handler)
   &&n.attributes.some(a=>a.name?.name==='onCancel'
    &&calls(a.value?.expression,`set${pending[0].toUpperCase()+pending.slice(1)}`).some(c=>c.arguments[0]?.type==='NullLiteral')
    &&calls(a.value?.expression,'transport').length===0)).length,
   `${actionId}: explicit confirm and zero-POST Cancel`);
  const pendingSetter=`set${pending[0].toUpperCase()+pending.slice(1)}`;
  const staged=calls(stage,pendingSetter);
  assert.equal(staged.length,1);
  const snapshot=staged[0].arguments[0];
  assert.equal(member(snapshot?.callee),'Object.freeze');
  for(const field of ['epoch','authorityKey','transport','bearer','generation'])
   assert.ok(snapshot.arguments[0]?.properties?.some(p=>p.key?.name===field),`${actionId}: ${field} snapshot`);
  assert.ok(nodes(stage,n=>n.type==='IfStatement'
   &&nodes(n.test,x=>x.type==='Identifier'&&x.name===flag).length).length,
   `${actionId}: staged request cannot bypass unresolved result`);
  const guard=nodes(confirm,n=>n.type==='IfStatement'
   &&['epoch','authorityKey','transport','bearer','generation'].every(field=>
    nodes(n.test,x=>member(x)===`intent.${field}`).length)
   &&nodes(n.test,x=>member(x)===lock).length
   &&nodes(n.test,x=>x.type==='Identifier'&&x.name===flag).length);
  assert.equal(guard.length,1,`${actionId}: current-context and single-flight guard`);
  const post=calls(confirm,'transport');
  assert.equal(post.length,1,`${actionId}: no automatic mutation retry`);
  assert.ok(calls(confirm,pendingSetter).some(c=>c.arguments[0]?.type==='NullLiteral'&&c.start<post[0].start));
  const load=localValue(component,'load');
  assert.equal(calls(load,'transport').length,1,`${actionId}: protected GET readback`);
  const success=calls(load,`set${flag[0].toUpperCase()+flag.slice(1)}`)
   .filter(c=>c.arguments[0]?.type==='BooleanLiteral'&&c.arguments[0].value===false);
  assert.equal(success.length,1,`${actionId}: successful read unlocks mutation`);
  assert.ok(nodes(load,n=>n.type==='IfStatement'&&member(n.test?.argument)==='r.ok'
   &&n.consequent?.type==='ThrowStatement'&&n.start<success[0].start).length,
   `${actionId}: failed GET cannot unlock mutation`);
  assert.equal(binding.confirmation.physicalUiVerified,false);
  assert.equal(binding.confirmation.denialNoEffectVerified,false);
  assert.equal(binding.runtimeEvidence,null);
 }
 const key=functionDeclaration(account,'APIKeysTab');
 assert.ok(nodes(key,n=>n.type==='ConditionalExpression'&&n.test?.name==='rotationUnresolved'
  &&nodes(n.consequent,x=>x.type==='JSXText'&&x.value.includes('current API key is unknown')).length).length);
 const sessions=functionDeclaration(account,'SessionsTab');
 const stageRevoke=localValue(sessions,'stageRevoke'),confirmRevoke=localValue(sessions,'revoke');
 for(const field of ['id','isCurrent','userAgent','ip'])
  assert.ok(calls(stageRevoke,'Object.freeze').some(c=>c.arguments[0]?.properties?.some(p=>p.key?.name===field)));
 assert.ok(nodes(confirmRevoke,n=>member(n)==='intent.id').length);
 assert.ok(nodes(confirmRevoke,n=>member(n)==='intent.isCurrent').length);
 assert.ok(nodes(sessions,n=>n.type==='ConditionalExpression'&&member(n.test)==='pendingRevoke.isCurrent'
  &&nodes(n.consequent,x=>x.type==='StringLiteral'&&x.value.includes('sign you out')).length).length);
 assert.equal(manifest.scope.supportedActionDenominatorComplete,false);
});

test('bound registration rejection is an explicit availability record, not supported-action coverage',()=>{
 const binding=manifest.availabilityBindings.find(row=>row.actionId==='auth.register');
 assert.equal(binding.reachability,'bound_rejected_503');assert.equal(binding.sourceBinding.statusCode,503);
 const route=tree(binding.sourceBinding.routeFile);
 const registrations=calls(route,'registerUnavailable').filter(n=>nodes(n.arguments[0],x=>x.type==='ArrayExpression'
  &&x.elements.length===2&&x.elements[0]?.value==='post'&&x.elements[1]?.value==='/v2/auth/register').length);
 assert.equal(registrations.length,1);
 const factory=localValue(route,'registerUnavailable'),fail=localValue(factory,'fail');
 assert.ok(calls(fail,'res.status').some(n=>n.arguments[0]?.value===503));
 assert.ok(nodes(factory,n=>n.type==='CallExpression'&&n.callee?.computed&&n.callee.object?.name==='router'
  &&n.callee.property?.name==='method'&&n.arguments[0]?.name==='path'&&n.arguments[1]?.name==='fail').length);
 assert.equal(calls(route,'router.post').filter(n=>n.arguments[0]?.value==='/v2/auth/register').length,0);
 assert.equal(manifest.scope.supportedActionDenominatorComplete,false);
 assert.equal(manifest.scope.globalDenominatorComplete,false);
});

test('ticket and search-echo terminal fallbacks do not imply unconditional bound rejection',()=>{
 const gateway=tree(manifest.gatewaySource);
 for(const [routerName,paths,ids] of [
  ['ticketAgentRouter',['/admin/tickets/:ticketId/assessment','/admin/tickets/:ticketId/assessment/:requestId'],
   ['admin.tickets.assess','admin.tickets.assessment']],
  ['searchEchoRouter',['/agents/customer/search-echo/assess','/agents/customer/sessions/:sessionId/requests/:requestId/search-echo/:step/assessment'],
   ['agent.customer.searchEchoAssess','agent.customer.searchEchoAssessment']],
 ]){
  const mounts=calls(gateway,'router.use').filter(n=>n.arguments[0]?.name===routerName);
  assert.equal(mounts.length,1);
  for(const routePath of paths){
   const fallback=calls(gateway,'registerUnavailable').filter(n=>nodes(n.arguments[0],x=>
    x.type==='ArrayExpression'&&x.elements.length===2&&x.elements[1]?.value===routePath).length);
   assert.equal(fallback.length,1);
   assert.ok(mounts[0].start<fallback[0].start,'Mounted handler can consume path before fallback');
  }
  for(const id of ids)assert.notEqual(allBindings.find(row=>row.actionId===id)?.reachability,
   'bound_rejected_503','Fallback registration alone cannot exclude a supported action');
 }
});

test('ticket and search-echo assessment bindings follow optional composition, mounted routes and actual UI recovery',async()=>{
 const {matchOperationRequest,compileOperation}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const gateway=tree(manifest.gatewaySource),composition=tree(manifest.compositionSource);
 const application=tree(manifest.applicationSource);
 const samples={ticketId:'7',sessionId:'11111111-1111-4111-8111-111111111111',
  requestId:'22222222-2222-4222-8222-222222222222',step:1};
 assert.equal(manifest.assessmentBindings.length,4);
 for(const binding of manifest.assessmentBindings){
  const action=manifest.actions.find(row=>row.id===binding.actionId);
  assert.ok(action);assert.equal(action.review,binding.actionId);
  const source=binding.sourceBinding,trace=binding.uiTrace;
  const suffix=action.path.slice('/api/secureshop'.length);
  const mounted=calls(gateway,'router.use').filter(n=>n.arguments[0]?.name===source.gatewayArgument);
  assert.equal(mounted.length,1);
  assert.ok(nodes(gateway,n=>n.type==='IfStatement'&&n.test?.name===source.gatewayArgument
   &&n.consequent.start<=mounted[0].start&&n.consequent.end>=mounted[0].end).length,
   'Assessment router is optional, not an unconditional 503');
  const fallback=calls(gateway,'registerUnavailable').filter(n=>nodes(n.arguments[0],x=>
   x.type==='ArrayExpression'&&x.elements[0]?.value===action.method.toLowerCase()
   &&x.elements[1]?.value===suffix).length);
  assert.equal(fallback.length,1);assert.ok(mounted[0].end<fallback[0].start);
  assert.ok(nodes(application,n=>n.type==='ObjectProperty'&&n.key?.name===source.gatewayArgument
   &&member(n.value)===`composition.${source.gatewayArgument==='ticketAgentRouter'?'ticketAgent':'searchEcho'}.router`).length);
  for(const factory of [source.serviceFactory,source.routeFactory])
   assert.equal(nodes(composition,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
    &&n.callee.property?.name===factory&&n.callee.object?.type==='CallExpression'
    &&n.callee.object.callee?.name==='require').length,1,`${binding.actionId}: ${factory}`);
  assert.ok(nodes(composition,n=>n.type==='IfStatement'
   &&nodes(n.test,x=>x.type==='Identifier'&&x.name==='personaBindings').length
   &&nodes(n.consequent,x=>x.type==='CallExpression'&&x.callee?.property?.name===source.routeFactory).length).length,
  `${binding.actionId}: assessment mount requires persona bindings`);
  const route=tree(source.routeFile),routes=calls(route,`router.${action.method.toLowerCase()}`)
   .filter(n=>n.arguments[0]?.value===suffix);
  assert.equal(routes.length,1);
  assert.deepEqual(routes[0].arguments.slice(1,4).map(member),['select','authenticatePersona',
   source.gatewayArgument==='ticketAgentRouter'?'admin':'customer']);
  assert.ok(routes[0].arguments.some(n=>n.type==='CallExpression'&&member(n.callee)==='handle'
   &&n.arguments[0]?.value===source.method));
  assert.ok(nodes(route,n=>n.type==='MemberExpression'&&member(n)==='assessment[method]').length
   ||nodes(route,n=>n.type==='MemberExpression'&&n.computed&&n.object?.name==='assessment'
    &&n.property?.name==='method').length);
  const service=tree(source.serviceFile);
  functionDeclaration(service,source.method);
  assert.ok(calls(service,'createObjectiveCompletionService').length);
  assert.ok(nodes(service,n=>n.type==='ObjectProperty'&&n.key?.name==='objectiveId'
   &&n.value?.name==='OBJECTIVE').length);
  if(source.method==='runAttempt'){
   assert.ok(calls(service,source.gatewayArgument==='ticketAgentRouter'
    ?'browserQualification.qualifyTicket':'browserQualification.qualifySearchEcho').length);
   assert.ok(calls(service,'completion.evaluate').length);
  }
  const pathname=action.path.replace(/:([^/]+)/g,(_,key)=>String(samples[key]));
  const body=action.method==='POST'?Object.fromEntries(binding.confirmation.fields
   .filter(key=>key!=='ticketId').map(key=>[key,samples[key]])):undefined;
  const matched=matchOperationRequest({pathname,method:action.method,query:{},body});
  assert.equal(matched.name,binding.actionId);
  const compiled=compileOperation(matched.name,matched.input);
  assert.equal(compiled.path,pathname);assert.equal(compiled.method,action.method);
  assert.deepEqual(compiled.body,body);
  const hook=tree(trace.hookFile),start=localValue(hook,'start'),readSaved=localValue(hook,'readSaved');
  assert.ok(calls(readSaved,'transport').length===1);
  assert.ok(calls(hook,'current').length,'Auth/transport epoch guard is retained');
  if(source.method==='runAttempt'){
   const saves=calls(start,'referenceStore.save'),posts=calls(start,'transport');
   assert.equal(saves.length,1);assert.equal(posts.length,1);
   assert.ok(nodes(start,n=>n.type==='AwaitExpression'&&n.argument===saves[0]).length);
   assert.ok(nodes(start,n=>n.type==='AwaitExpression'&&n.argument===posts[0]).length);
   assert.ok(saves[0].start<posts[0].start);
   assert.ok(calls(start,'readSaved').some(n=>n.start>posts[0].start));
  }else assert.ok(calls(localValue(hook,'check'),'readSaved').length);
  const reference=tree(trace.referenceFile),save=objectMethod(reference,'save');
  const flushes=calls(save,'flush'),writes=calls(save,'storage.setItem');
  assert.equal(flushes.length,1);assert.equal(writes.length,1);
  assert.ok(nodes(save,n=>n.type==='AwaitExpression'&&n.argument===flushes[0]).length);
  assert.ok(writes[0].start<flushes[0].start);
  const panel=tree(trace.panelFile);
  assert.ok(calls(panel,trace.panelEvent).length>=1,`${binding.actionId}: explicit UI event`);
  assert.equal(binding.runtimeEvidence,null);assert.equal(binding.uiTrace.runtimeVerified,false);
  assert.equal(binding.confirmation.physicalUiVerified,false);
  assert.equal(binding.recovery.nativeVerified,false);
  assert.equal(binding.linkedObjectiveIds[0],source.objectiveId);
 }
 const searchHook=tree('client/src/pages/secureshop/hooks/useSearchEchoAssessment.js');
 const retry=localValue(searchHook,'retryUnconfirmed');
 const reads=calls(retry,'readSaved'),posts=calls(retry,'transport');
 assert.equal(reads.length,2);assert.equal(posts.length,1);
 assert.ok(reads[0].start<posts[0].start&&posts[0].start<reads[1].start);
 assert.equal(manifest.scope.supportedActionDenominatorComplete,false);
 assert.equal(manifest.scope.globalDenominatorComplete,false);
});

test('closed manifest reconciles every current normal and multipart bridge operation',async()=>{
 const {describeOperations}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const value=describeOperations();
 const expected=[...value.operations.map(row=>({id:row.name,method:row.method,path:row.pathTemplate})),
  ...value.separate.map(row=>({id:row.name,method:row.method,path:row.path}))];
 assert.deepEqual(manifest.actions.map(({id,method,path})=>({id,method,path})),expected);
 assert.equal(new Set(manifest.actions.map(row=>row.id)).size,manifest.actions.length);
 assert.equal(manifest.scope.bridgeRegistryComplete,true);
 assert.equal(manifest.scope.supportedActionDenominatorComplete,false);
 assert.equal(manifest.scope.globalDenominatorComplete,false);
 const reviews=new Map(allBindings.map(row=>[row.actionId,row]));
 assert.equal(reviews.size,allBindings.length);
 for(const row of manifest.actions)assert.equal(row.review,reviews.has(row.id)?row.id:null);
 for(const id of ['uploads.avatar.operation','uploads.avatar.create']){
  const source=[...value.operations,...value.separate].find(row=>row.name===id);
  const action=manifest.actions.find(row=>row.id===id);
  assert.ok(source&&action,`current Avatar bridge registration ${id}`);
  assert.equal(action.method,source.method);
  assert.equal(action.path,source.pathTemplate??source.path);
  assert.equal(action.review,id,'source applicability review does not imply native consequence or runtime evidence');
 }
});

test('fourteen lab and two Avatar registrations retain exact source route, activation and non-native applicability',()=>{
 const labs=manifest.labApplicabilityBindings,avatars=manifest.avatarApplicabilityBindings;
 assert.equal(labs.length,14);assert.equal(avatars.length,2);
 assert.deepEqual(new Set(labs.map(row=>row.actionId)),new Set(manifest.actions.filter(row=>row.id.startsWith('lab.')).map(row=>row.id)));
 assert.deepEqual(new Set(avatars.map(row=>row.actionId)),new Set(['uploads.avatar.create','uploads.avatar.operation']));
 const route=(binding,action)=>{
  const source=binding.sourceBinding,ast=tree(source.routeFile),relative=action.path.replace('/api/secureshop','');
  assert.equal(calls(ast,`router.${action.method.toLowerCase()}`).filter(call=>call.arguments[0]?.value===relative).length,1,
   `${action.id} must bind one executable route, not a comment or nearby URL`);
  assert.equal(action.review,binding.actionId);
  assert.equal(binding.runtimeEvidence,null);
  assert.equal(binding.confirmation.physicalUiVerified,false);
  assert.equal(binding.confirmation.denialNoEffectVerified,false);
  assert.deepEqual(binding.linkedObjectiveIds,[],'related objectives are not graded evidence-adapter links');
  assert.deepEqual(binding.evidenceAdapters,[]);
 };
 for(const binding of [...labs,...avatars])route(binding,manifest.actions.find(row=>row.id===binding.actionId));
 const gateway=tree('server/routes/secureshop/boundGateway.js');
 const application=tree('server/services/secureshopBoundApplication.js');
 for(const [family,routerName,applicationName,flag,defaultRequested] of [
  ['lab.personaInbox.','personaInboxRouter','personaInbox','SS_PERSONA_INBOX_READY',true],
  ['lab.mcpTrust.','mcpTrustRouter','mcpTrust','SS_MCP_TRUST_READY',false],
  ['lab.ssrf.','ssrfRouter','ssrf','SS_CONTROLLED_SSRF_READY',false],
  ['lab.policyHtml.','ssrfRouter','ssrf','SS_CONTROLLED_SSRF_READY',false]]){
  const sample=labs.find(row=>row.actionId.startsWith(family));
  const policy=tree(sample.sourceBinding.activationFile);
  assert.ok(nodes(policy,n=>n.type==='StringLiteral'&&n.value===flag).length,`${flag} source flag`);
  const activation=functionDeclaration(policy,'activationPolicy');
  assert.ok(nodes(activation,n=>n.type==='ObjectProperty'&&n.key?.name==='requested'
   &&nodes(n.value,x=>x.type==='BinaryExpression'&&x.operator===(defaultRequested?'!==':'===')
    &&x.left?.name==='value'&&x.right?.value===(defaultRequested?'false':'true')).length===1).length,
   `${flag} must retain its source activation decision`);
  assert.ok(nodes(application,n=>n.type==='ObjectProperty'&&n.key?.name===routerName
   &&member(n.value)===`composition.${applicationName}.router`).length,`${routerName} composed handoff`);
  assert.equal(calls(gateway,'router.use').filter(call=>call.arguments[0]?.name===routerName).length,1,
   `${routerName} conditional mount`);
  assert.ok(nodes(gateway,n=>n.type==='IfStatement'&&n.test?.name===routerName
   &&calls(n.consequent,'router.use').some(call=>call.arguments[0]?.name===routerName)).length);
 }
 assert.ok(labs.filter(row=>row.actionId.startsWith('lab.personaInbox.')).every(row=>row.activation.startsWith('postgres_default_requested')));
 assert.ok(labs.filter(row=>row.actionId.startsWith('lab.mcpTrust.')||row.actionId.startsWith('lab.ssrf.')).every(row=>row.activation.includes('explicit_opt_in')));
 assert.ok(labs.filter(row=>row.actionId.startsWith('lab.policyHtml.')).every(row=>row.activation.startsWith('nested_in_opt_in_ssrf_router')));
 const ssrf=tree('server/routes/secureshop/boundSsrf.js');
 assert.ok(calls(ssrf,'feature.availability.read').some(call=>call.arguments[0]?.value==='ss_policy_final_html_execution'));
 assert.ok(nodes(ssrf,n=>n.type==='UnaryExpression'&&n.operator==='!'
  &&member(n.argument)==='feature.htmlAssessment').length,
  'Policy HTML operation remains gated on composed assessment');
 const avatarMount=nodes(gateway,n=>n.type==='IfStatement'&&n.test?.name==='accountAvatar'
  &&calls(n.consequent,'router.post').some(call=>call.arguments[0]?.value==='/uploads/avatar')
  &&calls(n.consequent,'router.get').some(call=>call.arguments[0]?.value==='/uploads/avatar/operations/:requestId')
  &&calls(n.alternate,'registerUnavailable').length===1);
 assert.equal(avatarMount.length,1,'Avatar source must retain conditional POST/GET and explicit unavailable fallback');
 assert.ok(nodes(application,n=>n.type==='ObjectProperty'&&n.key?.name==='accountAvatar'
  &&member(n.value)==='composition.accountAvatar').length);
 const {OBJECTIVES}=require('../server/config/secureshopCurriculum');
 const objectiveIds=new Set(OBJECTIVES.map(row=>row.id));
 for(const binding of labs)for(const id of binding.relatedObjectiveIds||[])assert.ok(objectiveIds.has(id),id);
 assert.ok(labs.filter(row=>row.actionId.startsWith('lab.policyHtml.')).every(row=>
  row.relatedObjectiveIds.includes('ss_policy_final_html_execution')&&row.q08Applicability.includes('v27')));
 assert.deepEqual(manifest.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
 // Negative controls: a cloned identity or route-path drift cannot pass the executable-source binding.
 for(const changed of [{...manifest.actions.find(row=>row.id==='lab.personaInbox.read'),path:'/api/secureshop/v2/persona-inbox/not-mounted'},
  {...manifest.actions.find(row=>row.id==='uploads.avatar.create'),method:'GET'}]){
  const binding=[...labs,...avatars].find(row=>row.actionId===changed.id);
  assert.throws(()=>route(binding,changed),/must bind one executable route/);
 }
 const inbox=labs.find(row=>row.actionId==='lab.personaInbox.read');
 assert.throws(()=>route({...inbox,sourceBinding:{...inbox.sourceBinding,
  routeFile:'server/routes/secureshop/boundGateway.js'}},
  manifest.actions.find(row=>row.id===inbox.actionId)),/must bind one executable route/,
 'a fallback registration or unrelated source file cannot impersonate the ready lab router');
});

test('bound review moderation click, persisted one-POST batches, GET-only recovery and retained effect bind to their two registrations',()=>{
 const bindings=manifest.reviewModerationBindings;
 assert.deepEqual(bindings.map(row=>row.actionId),
  ['merchant.reviews.moderateAll','merchant.reviews.moderationReceipt']);
 for(const binding of bindings){
  const action=manifest.actions.find(row=>row.id===binding.actionId);
  assert.equal(action?.review,binding.actionId);
  assert.equal(binding.runtimeEvidence,null);
  assert.equal(binding.confirmation.physicalUiVerified,false);
  assert.equal(binding.confirmation.denialNoEffectVerified,false);
  assert.equal(binding.recovery.nativeVerified,false);
  assert.deepEqual(binding.linkedObjectiveIds,[]);
  assert.deepEqual([binding.nativeApiObservation.suite,binding.nativeApiObservation.runId,
   binding.nativeApiObservation.result,binding.nativeApiObservation.lostAcknowledgement],
  ['review-moderation-recovery','run-tal6tlrp','one_native_test_passed_zero_skips',
   'discard_after_successful_response_only']);
  assert.equal(binding.nativeApiObservation.fixture,
   'tests/postgres/secureshopReviewModerationRecoveryActual.integration.test.js');
  assert.equal(binding.nativeApiObservation.launcher,
   'tests/postgres/run-secureshop-bound-review-composition-isolated.py');
  for(const field of ['renderedUi','fixedModelEffect','judge','objectiveCredit'])
   assert.equal(binding.nativeApiObservation[field],false);
 }
 const [post,get]=bindings;
 assert.deepEqual([post.actionId,manifest.actions.find(row=>row.id===post.actionId).method],
  ['merchant.reviews.moderateAll','POST']);
 assert.deepEqual([get.actionId,manifest.actions.find(row=>row.id===get.actionId).method],
  ['merchant.reviews.moderationReceipt','GET']);
 const ui=tree(post.sourceBinding.uiFile), panel=functionDeclaration(ui,'MerchantReviews');
 const start=localValue(panel,'runModerationAll'),bound=localValue(panel,'runBoundModeration');
 const check=localValue(panel,'checkSavedModeration'),receipt=localValue(panel,'moderationReceipt');
 assert.equal(calls(start,'runBoundModeration').length,1);
 assert.equal(nodes(panel,n=>n.type==='JSXOpeningElement'&&n.name?.name==='button'
  &&nodes(n,x=>x.type==='JSXAttribute'&&x.name?.name==='onClick'
   &&x.value?.expression?.name==='runModerationAll').length).length,1);
 for(const phrase of ['approve or reject up to 100','filters only change','displayed list'])
  assert.ok(nodes(panel,n=>n.type==='JSXText'&&n.value.includes(phrase)).length,phrase);
 assert.equal(calls(bound,'moderationReceipt').length,2,'preflight and post-POST readback');
 assert.equal(calls(bound,'moderationStore.current.reserveInitialPost').length,1);
 assert.equal(calls(bound,'moderationStore.current.reserveNextPost').length,1);
 assert.equal(calls(bound,'moderationStore.current.recordCompleted').length,1);
 const postCall=calls(bound,'requests.fetch').filter(n=>n.arguments[0]?.value
  ==='/api/secureshop/merchant/reviews/moderate-all');
 assert.equal(postCall.length,1,'one bound mutation callsite');
 assert.ok(calls(bound,'moderationStore.current.reserveInitialPost')[0].start<postCall[0].start);
 assert.ok(calls(bound,'moderationStore.current.reserveNextPost')[0].start<postCall[0].start);
 assert.ok(calls(bound,'moderationStore.current.observePending')[0].start>postCall[0].start);
 assert.equal(calls(check,'moderationReceipt').length,1);
 assert.equal(calls(check,'requests.fetch').length,0,'Check saved never directly dispatches POST');
 assert.equal(calls(check,'runBoundModeration').length,0);
 assert.equal(calls(receipt,'requests.fetch').length,1);
 assert.ok(nodes(panel,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&n.value?.expression?.name==='checkSavedModeration').length);
 assert.ok(nodes(panel,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&calls(n.value?.expression,'runBoundModeration').some(call=>call.arguments[0]?.value===true)).length);
 const ref=tree(post.sourceBinding.referenceFile);
 const store=functionDeclaration(ref,'createReviewModerationReferenceStore');
 const write=localValue(store,'acknowledgedWrite');
 const flush=calls(write,'flush')[0];
 assert.ok(flush&&nodes(write,n=>n.type==='AwaitExpression'&&n.argument===flush).length,
  'scene reference flush must be acknowledged');
 assert.ok(calls(write,'storage.getItem').some(n=>n.start>flush.start));
 assert.ok(calls(store,'verifyReviewModerationHistory').length>=3);
 assert.ok(nodes(ref,n=>n.type==='NumericLiteral'&&n.value===100).length);
 const operations=tree(post.sourceBinding.bridgeFile);
 for(const [name,path] of [[post.actionId,'/api/secureshop/merchant/reviews/moderate-all'],
  [get.actionId,'/api/secureshop/merchant/reviews/moderation/:requestId']])
  assert.ok(nodes(operations,n=>n.type==='ObjectProperty'&&n.key?.value===name
   &&nodes(n.value,x=>x.type==='StringLiteral'&&x.value===path).length).length,name);
 const router=tree(post.sourceBinding.routeFile);
 assert.equal(calls(router,'router.get').filter(n=>n.arguments[0]?.value==='/merchant/reviews/moderation/:requestId').length,1);
 assert.ok(nodes(router,n=>n.type==='StringLiteral'&&n.value==='/merchant/reviews/moderate-all').length);
 assert.ok(calls(router,'moderation.readModeration').length);
 assert.ok(calls(router,'moderation.moderateReviews').length);
 const runtime=tree(post.sourceBinding.runtimeFile);
 assert.ok(calls(runtime,'createBoundReviewModeration').length);
 assert.ok(calls(runtime,'createBoundReviewsRouter').length);
 assert.ok(calls(runtime,'createSecureShopBoundReviewTools').length);
 const composition=tree(post.sourceBinding.compositionFile);
 assert.ok(calls(composition,'createBoundReviewRuntime').length);
 assert.ok(calls(composition,'reviews.readRetainedSceneTarget').length);
 const application=tree(post.sourceBinding.applicationFile);
 assert.ok(nodes(application,n=>n.type==='ObjectProperty'&&n.key?.name==='reviewsRouter'
  &&member(n.value)==='composition.router').length);
 const gateway=tree(post.sourceBinding.gatewayFile);
 assert.equal(calls(gateway,'router.use').filter(n=>n.arguments[0]?.name==='reviewsRouter').length,1);
 const moderation=tree(post.sourceBinding.moderationFile);
 assert.ok(calls(moderation,'journal.lookupReviewModerationRequest').length>=2);
 assert.ok(calls(moderation,'runner.run').length);
 assert.ok(calls(moderation,'projectBoundReviewModeration').length);
 const recovery=tree(get.sourceBinding.recoveryFile);
 assert.ok(calls(recovery,'createConversationBinding').length);
 assert.ok(calls(recovery,'fence.assertRemoteAdmission').length);
 assert.equal(manifest.scope.supportedActionDenominatorComplete,false);
 assert.deepEqual(manifest.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
});

test('all curriculum identities are retained, without invented objective mappings or qualification',()=>{
 const {OBJECTIVES}=require('../server/config/secureshopCurriculum');
 assert.deepEqual(manifest.curriculumObjectives.map(row=>row.objectiveId).sort(),OBJECTIVES.map(row=>row.id).sort());
 for(const binding of allBindings){
  assert.equal(binding.runtimeEvidence,null);
  assert.equal(binding.confirmation.physicalUiVerified,false);
  assert.equal(binding.confirmation.denialNoEffectVerified,false);
  for(const id of binding.linkedObjectiveIds){
   assert.ok(OBJECTIVES.some(row=>row.id===id));
   const adapters=binding.evidenceAdapters.filter(row=>row.objectiveId===id);
   assert.ok(adapters.length,'Objective link needs its actual evidence source');
   for(const adapter of adapters)assert.ok(nodes(tree(adapter.file),n=>n.type==='StringLiteral'&&n.value===id).length);
  }
 }
 assert.deepEqual(manifest.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
 assert.equal(manifest.actionDefaults.runtimeEvidence,null);
 assert.equal(manifest.actionDefaults.confirmation,'unresolved');
 assert.equal(manifest.actionDefaults.intentionalException,'unresolved');
 assert.equal(manifest.actionDefaults.modelApplicability,'unresolved');
 assert.equal(manifest.actionDefaults.judgeApplicability,'unresolved');
});

test('original V23 direct registration is a separate source-reviewed teaching exception, not whole-chat or native credit',()=>{
 const partition=manifest.roleChatDescriptorPartition;
 assert.equal(partition.advertisedDescriptorCount,51);
 assert.equal(partition.separatelyOfferedDirectEffects.length,1);
 const effect=partition.separatelyOfferedDirectEffects[0],source=effect.sourceBinding;
 assert.deepEqual([effect.toolKey,effect.bridgeActionId,effect.confirmation.kind,effect.runtimeEvidence],
  ['mcp-registry.register','agent.admin.assistant.chat',
   'original_v23_direct_effect_no_separate_post_model_confirmation',null]);
 assert.equal(effect.confirmation.physicalUiVerified,false);
 assert.equal(effect.confirmation.denialNoEffectVerified,false);
 assert.equal(effect.exceptionReview,'v23_original_stdio_direct_effect_without_separate_confirmation_source_reviewed_only');
 assert.equal(effect.q08Applicability,'not_inferred_from_registration_or_model_selection');
 assert.equal(manifest.qualification.Q05,'deferred_unverified');
 assert.equal(manifest.qualification.Q08,'deferred_unverified');
 assert.equal(manifest.actions.find(row=>row.id===effect.bridgeActionId)?.review,null,
  'the shared admin chat route is not globally reviewed by this one tool exception');
 assert.equal(manifest.actions.find(row=>row.id==='admin.mcp.register')?.review,null,
  'the modern registry endpoint is not the original direct effect');
 assert.equal(partition.sourceAccountedDescriptors.some(row=>row.descriptorId===effect.toolKey),false);
 const chat=tree(source.roleChatFile),composition=tree(source.compositionFile);
 assert.ok(nodes(chat,n=>n.type==='VariableDeclarator'&&n.id?.name==='ORIGINAL_REGISTER_TOOL').length===1);
 assert.ok(nodes(composition,n=>n.type==='Identifier'&&n.name==='ORIGINAL_REGISTER_TOOL').length);
 assert.ok(calls(chat,'adapter.invoke').length);
 const original=tree(source.originalToolFile);
 assert.ok(calls(original,'cap.isOwnerScopedRegisterCapability').length);
 assert.ok(calls(original,'capability.execute').length);
 const adapter=tree(source.adapterFile);
 assert.ok(calls(adapter,'launches.admitOwnedMcpRegistration').length);
 assert.ok(calls(adapter,'createOwnerScopedRegisterCapability').length);
 assert.ok(calls(adapter,'client.registrationState').length);
 const capability=tree(source.capabilityFile);
 assert.ok(nodes(capability,n=>n.type==='StringLiteral'&&n.value==='V23_FIXED_STDIO_DENIED').length);
 assert.ok(calls(capability,'dispatch').length);
 const executor=tree(source.executorFile),worker=tree(source.workerFile);
 for(const flag of ['--unshare-user','--unshare-net','--unshare-pid','--seccomp'])
  assert.ok(nodes(executor,n=>n.type==='StringLiteral'&&n.value===flag).length,flag);
 assert.ok(nodes(worker,n=>n.type==='NewExpression'&&n.callee?.name==='StdioClientTransport').length);
});

test('reviewed confirmation boundaries exist in executable source and actual conditional mount chain',()=>{
 const composition=tree(manifest.compositionSource),application=tree(manifest.applicationSource),gateway=tree(manifest.gatewaySource);
 for(const binding of manifest.reviewedBindings){
  const source=binding.sourceBinding,route=tree(source.routeFile),runtime=tree(source.runtimeFile);
  assert.ok(named(route,source.routeFactory).length,source.routeFactory);
  const action=manifest.actions.find(row=>row.id===binding.actionId);
  const handlers=nodes(route,n=>{
   if(n.type!=='CallExpression'||n.callee?.type!=='MemberExpression'||n.callee.object?.name!=='router')return false;
   if(n.callee.property?.name!=='post'&&!(n.callee.computed&&n.callee.property?.name==='method'))return false;
   const routePath=n.arguments[0];
   const suffix=routePath?.type==='StringLiteral'?routePath.value:
    routePath?.type==='TemplateLiteral'?routePath.quasis.map(q=>q.value.cooked).join(''):null;
   return suffix&&action.method==='POST'&&action.path.endsWith(suffix);
  });
  if(source.routeHandlerFactory){
   const routeFactory=nodes(route,n=>n.type==='FunctionDeclaration'&&n.id?.name===source.routeFactory);assert.equal(routeFactory.length,1);
   assert.ok(handlers.some(handler=>handler.arguments.some(arg=>arg.type==='CallExpression'
    &&arg.callee?.name===source.routeHandlerFactory&&arg.arguments.length===1
    &&arg.arguments[0]?.type==='BooleanLiteral'&&arg.arguments[0].value===source.routeHandlerArgument)),
   'POST route must select the mutation handler, not the saved-read handler');
   const definitions=nodes(routeFactory[0],n=>n.type==='VariableDeclarator'&&n.id?.name===source.routeHandlerFactory);
   assert.equal(definitions.length,1,'Unique local handler factory');
   assert.equal(definitions[0].init?.type,'ArrowFunctionExpression');
   assert.ok(nodes(definitions[0].init,n=>n.type==='MemberExpression'
    &&n.property?.name===source.runtimeSymbol).length,'Handler closure calls exact confirmation method');
  }else assert.ok(handlers.some(handler=>nodes(handler,n=>n.type==='MemberExpression'
   &&n.property?.name===source.runtimeSymbol).length),`${binding.actionId}: operation route reaches its confirmation method`);
  const methods=named(runtime,source.runtimeSymbol);assert.ok(methods.length,source.runtimeSymbol);
  if(source.delegatedEffectFactory){
   assert.ok(methods.some(node=>calls(node,source.confirmationCall).length),'Confirmation calls retained proposal service');
   const factories=calls(runtime,source.delegatedEffectFactory);
   assert.ok(factories.some(node=>node.arguments[0]?.properties?.some(property=>
    property.key?.name===source.delegatedEffectProperty&&calls(property,source.effectCall).length)),
   `${binding.actionId}: exact effect callback injected into proposal service`);
  }else assert.ok(methods.some(node=>calls(node,source.effectCall).length),`${binding.actionId}: exact effect call inside confirmation`);
  assert.ok(nodes(composition,n=>n.type==='CallExpression'&&(member(n.callee)===source.compositionFactory
   ||n.callee?.type==='MemberExpression'&&n.callee.property?.name===source.compositionFactory)).length,'Composition factory call');
  assert.ok(nodes(application,n=>n.type==='ObjectProperty'&&n.key?.name===source.gatewayArgument).length,'Conditional gateway argument');
  assert.ok(calls(gateway,'router.use').some(n=>n.arguments[0]?.name===source.gatewayArgument),'Actual router.use mount');
 }
 for(const adapter of manifest.completionAdapters)assert.ok(named(tree(adapter.file),adapter.symbol).length);
});

test('coupon is source-linked despite stale comments; omissions and scoring applicability stay visible',()=>{
 const coupon=manifest.reviewedBindings.find(row=>row.actionId==='agent.customer.coupon.confirm');
 assert.equal(coupon.sourceBinding.effectCall,'applyConfirmedCoupon');
 assert.deepEqual(coupon.linkedObjectiveIds,['ss_sqli_coupon']);
 const user=manifest.reviewedBindings.find(row=>row.actionId==='agent.admin.assistant.userConfirm');
 assert.deepEqual(user.linkedObjectiveIds,[],'Role/ban mutation is not the user-lookup disclosure objective');
 const policy=manifest.reviewedBindings.find(row=>row.actionId==='agent.admin.assistant.policyConfirm');
 assert.deepEqual(policy.linkedObjectiveIds,['ss_policy_template_execution']);
 for(const id of ['account.apiKeys.get','agent.customer.avatarTraversal.run'])
  assert.equal(manifest.actions.find(row=>row.id===id).review,null);
 assert.ok(manifest.scope.unresolved.some(text=>text.includes('non-SecureShop')));
 assert.ok(manifest.actions.some(row=>row.method==='GET'&&row.review===null),'GET does not imply no consequence');
});

test('customer commerce bindings match exact routes; UI endpoint references do not prove click dispatch',()=>{
 assert.equal(manifest.commerceUiEvidence.sourceEvidence,'endpoint_reference_only');
 assert.equal(manifest.commerceUiEvidence.eventToRequestRelation,'unresolved');
 for(const binding of manifest.commerceBindings){
  const action=manifest.actions.find(row=>row.id===binding.actionId),source=binding.sourceBinding;
  const route=tree(source.routeFile),method=source.repositoryMethod;
  if(source.routeKind==='closed_gateway_dispatch_table'){
   const tuples=nodes(route,n=>n.type==='ArrayExpression'&&n.elements.length===4
    &&n.elements[0]?.value===method&&n.elements[1]?.value===action.path.slice('/api/secureshop'.length)
    &&n.elements[2]?.value===action.method.toLowerCase());
   assert.equal(tuples.length,1,`${action.id}: exact dispatch tuple`);
   assert.deepEqual(tuples[0].elements[3].elements.map(n=>n.value),binding.confirmation.fields);
   const loops=nodes(route,n=>n.type==='ForOfStatement'&&nodes(n.right,x=>x===tuples[0]).length);
   assert.equal(loops.length,1);
   assert.ok(nodes(loops[0].body,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
    &&n.callee.computed&&n.callee.object?.name==='router'&&n.callee.property?.name==='verb').length);
   assert.ok(nodes(loops[0].body,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
    &&n.callee.computed&&n.callee.object?.name==='conversationDomain'&&n.callee.property?.name==='method').length);
  }else{
   const routeCalls=calls(route,`router.${action.method.toLowerCase()}`).filter(n=>
    n.arguments[0]?.value===action.path.slice('/api/secureshop'.length));
   assert.equal(routeCalls.length,1);
   const expected=source.routeKind==='customer_chat_profile'?'runtime.confirmProfile':`conversationDomain.${method}`;
   assert.ok(calls(routeCalls[0],expected).length,`${action.id}: exact routed method`);
  }
  const domain=tree(source.domainFile);
  assert.ok(nodes(domain,n=>n.type==='VariableDeclarator'&&n.id?.name==='methods'
   &&n.init?.properties?.some(p=>p.key?.name===method)).length,'Closed domain method selection');
  assert.ok(calls(domain,'commerce.conversational').length);
  assert.ok(nodes(tree(source.boundServiceFile),n=>n.type==='CallExpression'&&n.callee?.computed
   &&member(n.callee.object)==='repository.conversation'&&n.callee.property?.name==='method').length);
  const prefix=action.path.split('/:')[0];
  for(const file of binding.uiSources){
   const ui=tree(file);
   assert.ok(nodes(ui,n=>n.type==='StringLiteral'&&n.value===prefix
    ||n.type==='TemplateElement'&&n.value.cooked.startsWith(prefix)).length,`${action.id}: actual UI endpoint reference`);
  }
  if(source.routeKind==='customer_chat_profile'){
   const methods=named(tree(source.chatFile),source.chatMethod);
   assert.equal(methods.length,1);
   assert.ok(calls(methods[0],source.chatEffectCall).some(n=>n.arguments[0]?.properties?.some(p=>p.key?.name==='method'&&p.value?.value==='saveProfile')));
   assert.ok(calls(tree(manifest.gatewaySource),'router.use').some(n=>n.arguments[0]?.name==='customerChatRouter'));
  }
 }
});

test('commerce effects remain inside the declared scene transaction with exact operation recovery',()=>{
 for(const binding of manifest.commerceBindings){
  const source=binding.sourceBinding,repo=tree(source.repositoryFile);
  const methods=nodes(repo,n=>n.type==='ObjectMethod'&&n.key?.name===source.repositoryMethod);
  assert.equal(methods.length,1,source.repositoryMethod);
  assert.ok(calls(methods[0],'transaction').length);
  for(const effect of source.repositoryEffectCalls)assert.ok(calls(methods[0],effect).length,`${binding.actionId}: ${effect}`);
  if(binding.recovery.controlledContract)tree(binding.recovery.controlledContract);
  assert.equal(binding.recovery.nativeVerified,false);
  assert.equal(binding.runtimeEvidence,null);
  assert.deepEqual(binding.linkedObjectiveIds,[],'Ordinary business operations are not mapped to a nearby vulnerability objective');
 }
 const repo=tree(manifest.commerceBindings[0].sourceBinding.repositoryFile);
 const transaction=nodes(repo,n=>n.type==='VariableDeclarator'&&n.id?.name==='transaction');
 assert.equal(transaction.length,1);assert.ok(calls(transaction[0],'guarded').length);
 const guarded=nodes(tree(manifest.commerceBindings[0].sourceBinding.transactionProvider),n=>n.type==='FunctionDeclaration'&&n.id?.name==='guarded');
 assert.equal(guarded.length,1);assert.ok(calls(guarded[0],'withTransaction').length);assert.ok(calls(guarded[0],'withSceneLease').length);
 const prior=named(repo,'prior');assert.equal(prior.length,1);assert.ok(calls(prior[0],'opLock').length);assert.ok(calls(prior[0],'unpack').length);
 const unpack=named(repo,'unpack');assert.equal(unpack.length,1);
 for(const field of ['context_json','request_json','intent_sha256','proposal_sha256','result_sha256'])
  assert.ok(nodes(unpack[0],n=>n.type==='MemberExpression'&&n.property?.name===field).length);
 const read=nodes(repo,n=>n.type==='ObjectMethod'&&n.key?.name==='readOperation')[0];
 for(const effect of ['saveProfileWithClient','saveAddressWithClient','checkoutWithClient',
  'addCartWithClient','updateCartWithClient','removeCartWithClient','insert','complete'])assert.equal(calls(read,effect).length,0);
});

test('GET choice issuance and persisted checkout preparation are not mislabeled side-effect-free',()=>{
 const bindings=new Map(manifest.commerceBindings.map(row=>[row.actionId,row]));
 assert.equal(bindings.get('customer.commerce.operation').recovery.requestKey,'operationId');
 for(const id of ['customer.commerce.addresses','customer.commerce.paymentMethods.list']){
  assert.equal(bindings.get(id).confirmation.kind,'choice_issuance_no_business_mutation_confirmation');
  assert.match(bindings.get(id).consequence,/durable/);
 }
 const repo=tree(bindings.get('customer.commerce.addresses').sourceBinding.repositoryFile);
 const issue=named(repo,'issue');assert.equal(issue.length,1);
 assert.ok(nodes(issue[0],n=>n.type==='StringLiteral'&&n.value.startsWith('INSERT INTO secureshop_review.chat_commerce_choices')).length);
 assert.equal(bindings.get('customer.commerce.checkout.prepare').confirmation.kind,'persisted_proposal_before_business_confirmation');
 const prepare=nodes(repo,n=>n.type==='ObjectMethod'&&n.key?.name==='prepareCheckout')[0];
 assert.ok(calls(prepare,'insert').length);assert.equal(calls(prepare,'checkoutWithClient').length,0);
 const confirm=nodes(repo,n=>n.type==='ObjectMethod'&&n.key?.name==='confirmCheckout')[0];
 assert.ok(nodes(confirm,n=>n.type==='StringLiteral'&&n.value==='approved').length);
 assert.ok(calls(confirm,'checkoutWithClient').length);
 for(const id of ['cart.add','cart.update','cart.remove','orders.create'])
  assert.ok(manifest.directMutationBindings.some(row=>row.actionId===id),'Separate direct paths need their own source boundary');
});

test('direct cart/order mutations retain distinct request, owner and transaction boundaries',()=>{
 const normalize=route=>route.replace(/:[^/]+/g,':param');
 for(const binding of manifest.directMutationBindings){
  const action=manifest.actions.find(row=>row.id===binding.actionId),source=binding.sourceBinding;
  const routes=calls(tree(source.routeFile),`router.${action.method.toLowerCase()}`).filter(n=>
   n.arguments[0]?.type==='StringLiteral'
   &&normalize(n.arguments[0].value)===normalize(action.path.slice('/api/secureshop'.length)));
  assert.equal(routes.length,1,action.id);
  assert.ok(calls(routes[0],`commerce.${source.serviceMethod}`).length);
  assert.ok(calls(routes[0],'persona').some(n=>n.arguments[0]?.value==='customer'));
  assert.ok(calls(routes[0],'exactBody').some(n=>n.arguments[1]?.type==='ArrayExpression'
   &&JSON.stringify(n.arguments[1].elements.map(e=>e.value))===JSON.stringify(binding.confirmation.fields)));
  const service=objectMethod(tree(source.serviceFile),source.serviceMethod);
  assert.ok(calls(service,'execute').some(n=>calls(n.arguments[1],`repository.${source.repositoryMethod}`).length));
  const repository=tree(source.repositoryFile),method=objectMethod(repository,source.repositoryMethod);
  assert.ok(calls(method,'guarded').some(n=>calls(n.arguments[1],source.effectWorker).length));
  const worker=functionDeclaration(repository,source.effectWorker);
  assert.ok(calls(worker,'lockCart').length);
  assert.ok(sqlParts(worker).some(sql=>sql.includes('target_id=$1 AND shop_user_id=$2')));
  assert.equal(binding.uiIntentRelation,'unresolved');
  assert.equal(binding.confirmation.kind,'direct_request_no_saved_proposal_gate_ui_intent_unresolved');
  assert.deepEqual(binding.linkedObjectiveIds,[]);
  assert.equal(binding.recovery.nativeVerified,false);
 }
 const repository=tree(manifest.directMutationBindings[0].sourceBinding.repositoryFile);
 const guard=functionDeclaration(repository,'guarded');
 assert.ok(calls(guard,'withSceneLease').some(n=>calls(n,'withTransaction').length));
 const add=functionDeclaration(repository,'addCartWithClient');
 assert.ok(sqlParts(add).some(sql=>sql.includes('SET quantity=quantity+$4')));
 for(const name of ['addCartWithClient','updateCartWithClient','removeCartWithClient']){
  const worker=functionDeclaration(repository,name);
  assert.equal(nodes(worker,n=>n.type==='Identifier'&&n.name==='operationId').length,0);
  assert.ok(calls(worker,'audit').length);
 }
 const remove=functionDeclaration(repository,'removeCartWithClient');
 assert.ok(sqlParts(remove).some(sql=>sql.startsWith('DELETE FROM')
  &&sql.includes('WHERE target_id=$1 AND shop_user_id=$2 AND cart_item_id=$3')));
 const checkout=functionDeclaration(repository,'checkoutWithClient');
 for(const operation of ['beginCheckoutWithClient','finishCheckoutWithClient']){
  assert.ok(nodes(checkout,n=>n.type==='IfStatement'&&n.test?.type==='Identifier'
   &&n.test.name==='couponRepository'&&calls(n.consequent,`couponRepository.${operation}`).length).length,
  'Checkout saved-operation handling remains conditional on the injected repository');
 }
 assert.match(manifest.directMutationBindings.find(row=>row.actionId==='cart.add').recovery.semantics,/increment again/);
 assert.match(manifest.directMutationBindings.find(row=>row.actionId==='orders.create').recovery.semantics,/conditional/);
});

test('dedicated IDOR lesson links its selected tool and mode-specific synthetic effect, not direct cart routes',()=>{
 assert.equal(manifest.teachingBindings.length,1);
 const binding=manifest.teachingBindings[0],source=binding.sourceBinding;
 assert.equal(binding.actionId,'agent.customer.idor.chat');
 const route=tree(source.routeFile);
 functionDeclaration(route,source.routeFactory);
 assert.ok(nodes(route,n=>n.type==='VariableDeclarator'&&n.id?.name==='prefix'
  &&n.init?.value===source.routePrefix).length);
 const chat=calls(route,'router.post').filter(n=>n.arguments[0]?.type==='TemplateLiteral'
  &&n.arguments[0].expressions.length===1&&n.arguments[0].expressions[0]?.name==='prefix'
  &&n.arguments[0].quasis.map(q=>q.value.cooked).join('')==='/chat');
 assert.equal(chat.length,1);
 assert.ok(calls(chat[0],'runtime.run').length);
 assert.ok(calls(chat[0],'normalizeIdorLessonSelection').some(n=>member(n.arguments[0])==='req.body.selection'));
 assert.ok(calls(chat[0],'exact').some(n=>member(n.arguments[0])==='req.body'
  &&JSON.stringify(n.arguments[1]?.elements?.map(e=>e.value))===JSON.stringify(binding.confirmation.fields)));
 const runtime=functionDeclaration(tree(source.runtimeFile),source.runtimeFactory);
 assert.ok(calls(runtime,'createBoundAgentRunner').some(n=>calls(n,source.toolFactory).length));
 assert.ok(calls(runtime,'runner.run').length);
 const tool=functionDeclaration(tree(source.toolFile),source.toolFactory);
 assert.ok(calls(tool,'normalizeIdorLessonTurnOrigin').length);
 assert.ok(calls(tool,'withSceneLease').some(n=>calls(n,'personaFence.withCrossStoreEffect')
  .some(fence=>calls(fence,'repository.execute').length)));
 assert.ok(nodes(tool,n=>n.type==='BinaryExpression'&&n.operator==='!=='
  &&member(n.left)==='args.numericId'&&member(n.right)==='choice.numericId').length);
 const repository=tree(source.repositoryFile),execute=functionDeclaration(repository,source.repositoryMethod);
 assert.ok(calls(execute,'operationIdFor').some(n=>n.arguments[0]?.name==='turnOrigin'));
 assert.ok(calls(execute,'withScene').length);
 assert.ok(nodes(execute,n=>n.type==='BinaryExpression'&&n.operator==='!=='
  &&n.left?.name==='numericId'&&n.right?.type==='ConditionalExpression'
  &&member(n.right.consequent)==='birth.cartItemId'&&member(n.right.alternate)==='birth.orderId').length);
 const queries=calls(execute,'client.query').filter(n=>n.arguments[0]?.type==='TemplateLiteral');
 const effectQueries=queries.filter(n=>n.arguments[0].quasis[0].value.cooked.startsWith('DELETE FROM')
  ||n.arguments[0].quasis[0].value.cooked.startsWith('SELECT order_id'));
 assert.equal(effectQueries.length,2);
 for(const query of effectQueries){
  assert.ok(query.arguments[0].expressions.some(n=>n.type==='ConditionalExpression'
   &&n.test?.operator==='==='&&member(n.test.left)==='mode.mode'&&n.test.right?.value==='fixed'
   &&n.consequent?.value==='AND shop_user_id=$3'&&n.alternate?.value===''));
 }
 const prior=nodes(execute,n=>n.type==='IfStatement'&&n.test?.name==='prior');
 assert.equal(prior.length,1);assert.ok(calls(prior[0],'operationReceipt').length);
 assert.ok(sqlParts(prior[0]).includes('IDOR_LESSON_OPERATION_CONFLICT'));
 assert.ok(prior[0].start<Math.min(...effectQueries.map(n=>n.start)),'Replay precedes mutable effect lookup');
 const scene=functionDeclaration(repository,'withScene');
 assert.ok(calls(scene,'withSceneLease').some(n=>calls(n,'withTransaction').length));
 const composition=tree(manifest.compositionSource);
 for(const factory of [source.routeFactory,source.runtimeFactory])
  assert.ok(nodes(composition,n=>n.type==='CallExpression'&&n.callee?.property?.name===factory).length);
 assert.ok(nodes(tree(manifest.applicationSource),n=>n.type==='ObjectProperty'&&n.key?.name===source.gatewayArgument).length);
 assert.ok(calls(tree(manifest.gatewaySource),'router.use').some(n=>n.arguments[0]?.name===source.gatewayArgument));
 const assessment=tree(source.assessmentFile);
 assert.ok(calls(assessment,'createObjectiveCompletionService').some(n=>calls(n,'createIdorLessonJudgeGuard').length));
 for(const file of binding.recovery.controlledContracts)tree(file);
 assert.equal(binding.uiIntentRelation,'unresolved');
 assert.equal(binding.recovery.nativeVerified,false);
 assert.equal(binding.exceptionReview,'reserved_synthetic_victim_owner_filter_omission_in_vulnerable_mode_source_reviewed');
 assert.deepEqual(binding.linkedObjectiveIds,['ss_idor_cart_delete','ss_idor_order_status_disclosure']);
 for(const id of binding.linkedObjectiveIds)assert.equal(manifest.curriculumObjectives.find(row=>row.objectiveId===id)
  .actionBindingStatus,'partial_teaching_source_links');
});

test('merchant direct panel mutations reach owned catalog workers, not the agent confirmation methods',()=>{
 for(const binding of manifest.panelBindings.filter(row=>row.sourceBinding.kind==='merchant_direct')){
  const source=binding.sourceBinding,action=manifest.actions.find(row=>row.id===binding.actionId);
  const routes=calls(tree(source.routeFile),`router.${action.method.toLowerCase()}`)
   .filter(n=>n.arguments[0]?.value===action.path.slice('/api/secureshop'.length));
  assert.equal(routes.length,1);
  assert.ok(calls(routes[0],'persona').some(n=>n.arguments[0]?.value==='merchant'));
  assert.ok(calls(routes[0],`catalog.${source.serviceMethod}`).length);
  const service=objectMethod(tree(source.serviceFile),source.serviceMethod);
  assert.ok(calls(service,`repository.${source.repositoryMethod}`).length);
  assert.ok(calls(service,'effect.listing').some(n=>n.arguments[2]?.value===source.repositoryMethod));
  const adapter=objectMethod(tree(source.effectAdapterFile),'listing');
  assert.ok(calls(adapter,'fence.withCrossStoreEffect').some(n=>nodes(n,x=>x.type==='CallExpression'
   &&x.callee?.computed&&x.callee.object?.name==='repository'&&x.callee.property?.name==='method').length));
  const repo=tree(source.repositoryFile),worker=objectMethod(repo,source.repositoryMethod);
  assert.ok(calls(worker,'online').length);assert.ok(calls(worker,'auditListing').length);
  assert.ok(sqlParts(worker).includes('OWNER_MISMATCH'));
  assert.equal(nodes(worker,n=>n.type==='Identifier'&&n.name==='operationId').length,0);
  const online=functionDeclaration(repo,'online');
  assert.ok(calls(online,'withSceneLease').some(n=>calls(n,'withTransaction').length));
  if(source.repositoryMethod==='createListing'){
   assert.ok(calls(worker,'insertMerchantListing').length);
   assert.ok(sqlParts(functionDeclaration(repo,'insertMerchantListing')).some(sql=>sql.includes('max(product_id),0)+1')));
   assert.match(binding.recovery.semantics,/another listing/);
  }else assert.ok(sqlParts(worker).some(sql=>sql.includes('product_id=$2 AND retailer_id=$3 AND archived_at IS NULL')));
  assert.ok(calls(tree(manifest.compositionSource),'createSecureShopBoundCatalog').length);
  assert.ok(nodes(tree(manifest.applicationSource),n=>n.type==='ObjectProperty'&&n.key?.name==='catalog'
   &&member(n.value)==='composition.catalog').length);
  assert.deepEqual(binding.linkedObjectiveIds,[]);assert.equal(binding.recovery.nativeVerified,false);
 }
});

test('manual listing bridge actions bind preview, explicit confirm, saved readback and owner-scoped effects',async()=>{
 const bindings=manifest.manualListingBindings;
 const ids=['manualReadiness','manualCreatePreview','manualEditPreview','manualCreateConfirm',
  'manualEditConfirm','manualCreateOperation','manualEditOperation'].map(name=>`merchant.listings.${name}`);
 assert.deepEqual(bindings.map(row=>row.actionId),ids);
 const {matchOperationRequest,compileOperation}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const route=tree('server/routes/secureshop/boundGateway.js');
 const catalog=tree('server/services/secureshopBoundCatalog.js');
 const repo=tree('server/database/postgres/secureshopBoundProductRepository.js');
 const hook=tree('client/src/pages/secureshop/pages/merchant/useManualListings.js');
 const panel=tree('client/src/pages/secureshop/pages/merchant/Listings.jsx');
 for(const binding of bindings){
  const action=manifest.actions.find(row=>row.id===binding.actionId),source=binding.sourceBinding;
  assert.equal(action.review,binding.actionId);
  const operation=action.id.endsWith('Readiness')?'readiness':action.id.endsWith('Preview')?'preview':
   action.id.endsWith('Confirm')?'confirm':'read';
  const variant=action.id.includes('Edit')?'Edit':'Create';
  assert.equal(source.routeFile,'server/routes/secureshop/boundGateway.js');
  assert.equal(source.serviceFile,'server/services/secureshopBoundCatalog.js');
  assert.equal(source.serviceMethod,operation==='readiness'?'manualListingReadiness':
   `${operation}ManualMerchantListing${variant}`);
  assert.equal(source.repositoryFile,operation==='readiness'?null:
   'server/database/postgres/secureshopBoundProductRepository.js');
  assert.equal(source.repositoryMethod,operation==='readiness'?null:
   `${operation}ManualListing${variant}`);
  assert.equal(binding.uiTrace.hookFile,'client/src/pages/secureshop/pages/merchant/useManualListings.js');
  assert.equal(binding.uiTrace.panelFile,'client/src/pages/secureshop/pages/merchant/Listings.jsx');
  assert.equal(binding.uiTrace.hookMethod,operation==='readiness'?'readiness':
   operation==='read'?'recover':operation);
  assert.equal(binding.uiTrace.panelEvent,operation==='readiness'?'retryReadiness':
   operation==='read'?'recoverManual':operation==='confirm'?'confirmManualReview':'submitProduct');
  for(const file of [source.routeFile,source.serviceFile,binding.uiTrace.hookFile,binding.uiTrace.panelFile])tree(file);
  if(source.repositoryFile)tree(source.repositoryFile);
  const path=action.path.replace(':operationId','11111111-1111-4111-8111-111111111111');
  const body=action.id.endsWith('Preview')
   ?{...(action.id.includes('Edit')?{productId:1}:{}),listing:{name:'Example',description:'Description',price:1,category:null,images:[],templateSource:null}}
   :action.id.endsWith('Confirm')?{operationId:'11111111-1111-4111-8111-111111111111',preview:{}}:undefined;
  const matched=matchOperationRequest({pathname:path,method:action.method,query:{},body});
  assert.equal(matched.name,action.id);
  const compiled=compileOperation(matched.name,matched.input);
  assert.equal(compiled.path,path);assert.equal(compiled.method,action.method);
  if(body)assert.deepEqual(compiled.body,body);
  assert.equal(binding.runtimeEvidence,null);
  assert.equal(binding.confirmation.physicalUiVerified,false);
  assert.equal(binding.confirmation.denialNoEffectVerified,false);
  assert.equal(binding.recovery.nativeVerified,false);
  assert.deepEqual(binding.linkedObjectiveIds,[]);
  assert.equal(binding.uiTrace.runtimeVerified,false);
  assert.equal(binding.sourceReachability,'conditional_bound_merchant_gateway_source_traced_runtime_unverified');
  assert.equal(binding.q05Applicability,action.id.endsWith('Confirm')
   ?'consequential_listing_write_confirmation_source_reviewed_runtime_unverified'
   :action.id.endsWith('Preview')?'preview_read_no_listing_effect_source_reviewed'
   :action.id.endsWith('Operation')?'saved_read_no_new_listing_effect_source_reviewed'
   :'scope_read_no_listing_effect_source_reviewed');
  assert.match(binding.q08Applicability,/no_original_model_or_judge_proof/);
 }
 const readiness=calls(route,'router.get').filter(n=>n.arguments[0]?.value==='/merchant/listings/manual/readiness');
 assert.equal(readiness.length,1);
 assert.ok(calls(readiness[0],'persona').some(n=>n.arguments[0]?.value==='merchant'));
 assert.ok(calls(readiness[0],'catalog.manualListingReadiness').length);
 const variants=nodes(route,n=>n.type==='ForOfStatement'&&n.left?.declarations?.[0]?.id?.name==='kind'
  &&n.right?.elements?.map(x=>x.value).join(',')==='create,edit');
 assert.equal(variants.length,1);
 const loop=variants[0];
 for(const [method,tail,service] of [['post','/preview','preview'],['post','/confirm','confirm'],
  ['get','/operations/:operationId','read']]){
  const matched=calls(loop,`router.${method}`).filter(n=>n.arguments[0]?.type==='TemplateLiteral'
   &&n.arguments[0].quasis.map(q=>q.value.cooked).join('')===`/merchant/listings/manual//${tail.slice(1)}`);
  assert.equal(matched.length,1,`${service} dynamic route for both kinds`);
  assert.ok(calls(matched[0],'persona').some(n=>n.arguments[0]?.value==='merchant'));
  assert.ok(nodes(matched[0],n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
   &&n.callee.object?.name==='catalog'&&n.callee.computed
   &&n.callee.property?.type==='TemplateLiteral'
   &&n.callee.property.quasis[0]?.value.cooked===`${service}ManualMerchantListing`).length);
 }
 const readinessService=nodes(catalog,n=>n.type==='AssignmentExpression'
  &&member(n.left)==='service.manualListingReadiness');
 assert.equal(readinessService.length,1);
 assert.ok(calls(readinessService[0].right,'existingMerchantAction').length);
 assert.ok(calls(readinessService[0].right,'manual.manualListingStorageScope').length);
 assert.ok(calls(catalog,'effect.listing').some(n=>n.arguments[2]?.name==='repositoryMethod'));
 assert.ok(nodes(catalog,n=>n.type==='CallExpression'&&n.callee?.computed
  &&n.callee.object?.name==='repository'&&n.callee.property?.name==='repositoryMethod').length);
 for(const [name,target] of [['previewManualListingCreate','previewManual'],['previewManualListingEdit','previewManual'],
  ['confirmManualListingCreate','confirmManual'],['confirmManualListingEdit','confirmManual'],
  ['readManualListingCreate','readManual'],['readManualListingEdit','readManual']])
  assert.equal(nodes(repo,n=>n.type==='ObjectProperty'&&n.key?.name===name
   &&calls(n.value,target).length).length,1,name);
 const confirmRepo=functionDeclaration(repo,'confirmManual'),readRepo=functionDeclaration(repo,'readManual');
 for(const call of ['manualOwner','checkCurrent','online','auditListing'])assert.ok(calls(confirmRepo,call).length);
 assert.ok(calls(confirmRepo,'insertMerchantListing').length);
 assert.ok(calls(confirmRepo,'editRevision').length);
 assert.ok(sqlParts(confirmRepo).some(value=>value.includes('LISTING_EDIT_STALE')));
 assert.ok(sqlParts(confirmRepo).some(value=>value.includes('operation_id=$1')));
 assert.ok(sqlParts(readRepo).some(value=>value.includes('persona_session_id=$4 AND scope_key=$5')));
 assert.ok(calls(readRepo,'manualOwner').length);
 const persist=functionDeclaration(hook,'persist'),confirm=functionDeclaration(hook,'confirm');
 const write=calls(persist,'shopStorage.setItem')[0],flush=calls(persist,'flushShopStorage')[0];
 assert.ok(write&&flush&&write.start<flush.start);
 assert.equal(nodes(persist,n=>n.type==='AwaitExpression'&&n.argument===flush).length,1,
  'The storage bridge flush must be awaited before confirmation');
 assert.ok(calls(persist,'shopStorage.getItem').some(n=>n.start>flush.start));
 const saved=calls(confirm,'persist')[0],dispatch=calls(confirm,'context.fetcher')[0];
 assert.ok(saved&&dispatch&&saved.start<dispatch.start,'Flush acknowledgement precedes confirm POST');
 assert.equal(nodes(confirm,n=>n.type==='AwaitExpression'&&n.argument===saved).length,1,
  'Confirmation must await persisted operation identity before POST');
 assert.ok(calls(confirm,'crypto.randomUUID').length);
 assert.ok(calls(confirm,'isCurrent').length>=3);
 assert.ok(calls(functionDeclaration(hook,'recover'),'context.fetcher').length);
 assert.ok(calls(functionDeclaration(hook,'preview'),'context.fetcher').length);
 for(const [name,target] of [['submitProduct','manual.preview'],['confirmManualReview','manual.confirm'],
  ['recoverManual','manual.recover']])assert.ok(calls(localValue(panel,name),target).length,name);
 assert.ok(nodes(panel,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&member(n.value?.expression)==='manual.retryReadiness').length);
 const dialog=nodes(panel,n=>n.type==='JSXElement'&&n.openingElement?.name?.name==='Dialog'
  &&nodes(n,x=>x.type==='JSXAttribute'&&x.name?.name==='onClick'
   &&x.value?.expression?.name==='confirmManualReview').length);
 assert.equal(dialog.length,1);
 for(const phrase of ['REVIEW LISTING CONSEQUENCES','Template source may execute','Existing listing content will be replaced'])
  assert.ok(nodes(dialog[0],n=>n.type==='JSXText'&&n.value.includes(phrase)).length,phrase);
 assert.ok(nodes(dialog[0],n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&n.value?.expression?.name==='cancelManualReview').length);
 assert.equal(manifest.scope.supportedActionDenominatorComplete,false);
 assert.equal(manifest.scope.globalDenominatorComplete,false);
 assert.deepEqual(manifest.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
});

test('admin panel mutations retain actual mount, target-kind dispatch, version and operation boundaries',()=>{
 for(const binding of manifest.panelBindings.filter(row=>row.sourceBinding.kind==='admin_mutation')){
  const source=binding.sourceBinding,route=tree(source.routeFile);
  const tuples=nodes(route,n=>n.type==='ArrayExpression'&&n.elements.length===2
   &&n.elements[0]?.value===source.routeSuffix&&n.elements[1]?.value===source.action);
  assert.equal(tuples.length,1);
  const loops=nodes(route,n=>n.type==='ForOfStatement'&&nodes(n.right,x=>x===tuples[0]).length);
  assert.equal(loops.length,1);
  assert.ok(calls(loops[0].body,'r.post').some(n=>n.arguments[0]?.type==='TemplateLiteral'
   &&n.arguments[0].quasis.map(q=>q.value.cooked).join('')==='/admin/users/:id/'
   &&n.arguments[0].expressions[0]?.name==='path'&&calls(n,'service.mutate').length));
  const service=objectMethod(tree(source.serviceFile),'mutate');
  assert.ok(calls(service,'fence').length);assert.ok(calls(service,'repository.mutate').length);
  const repo=tree(source.repositoryFile),mutate=objectMethod(repo,'mutate');
  assert.ok(calls(mutate,'registeredRepository.isRegistered').length);
  assert.ok(calls(mutate,'registeredRepository.mutate').length);
  assert.ok(calls(mutate,'transaction').length);
  for(const file of [source.repositoryFile,source.registeredRepositoryFile]){
   const worker=objectMethod(tree(file),'mutate');
   for(const code of ['OPERATION_CONFLICT','REVISION_CONFLICT'])assert.ok(sqlParts(worker).includes(code));
   assert.ok(nodes(worker,n=>n.type==='ObjectProperty'&&n.key?.name==='replayed'&&n.value?.value===true).length);
  }
  assert.ok(sqlParts(mutate).some(sql=>sql.includes('revoke_admin_target_api_keys')));
  assert.ok(sqlParts(mutate).some(sql=>sql.includes('bound_persona_sessions SET revoked_at')));
  const registered=objectMethod(tree(source.registeredRepositoryFile),'mutate');
  assert.ok(sqlParts(registered).includes('LAST_TENANT_ADMIN'));
  assert.ok(sqlParts(registered).some(sql=>sql.includes('membership_version=membership_version+1')));
  assert.ok(calls(registered,'fence.withCrossStoreEffect').some(n=>calls(n,'withTransaction').length));
  assert.deepEqual(binding.linkedObjectiveIds,[]);
  assert.equal(binding.exceptionReview,'not_classified_as_intentional_exception_pre_effect_control_source_reviewed');
 }
 const source=manifest.panelBindings.find(row=>row.sourceBinding.kind==='admin_mutation').sourceBinding;
 assert.ok(nodes(tree(manifest.compositionSource),n=>n.type==='CallExpression'&&n.callee?.property?.name===source.compositionFactory).length);
 assert.ok(nodes(tree(manifest.applicationSource),n=>n.type==='ObjectProperty'&&n.key?.name===source.gatewayArgument).length);
 assert.ok(calls(tree(manifest.gatewaySource),'router.use').some(n=>nodes(n,x=>x.type==='CallExpression'
  &&x.callee?.property?.name===source.routeFactory&&x.arguments[0]?.properties?.some(p=>p.key?.name==='service'
   &&p.value?.name===source.gatewayArgument)).length));
});

test('listed panel UI events reach the named callback and exact request, without a physical-UI claim',()=>{
 for(const binding of manifest.panelBindings)for(const trace of binding.uiTraces){
  const ui=tree(trace.file);
  const events=nodes(ui,n=>n.type==='JSXAttribute'&&n.name?.name===trace.event
   &&(n.value?.expression?.name===trace.handler||calls(n.value?.expression,trace.handler).length));
  assert.equal(events.length,1,`${binding.actionId}: precise event callback`);
  const request=localValue(ui,trace.requestFunction);
  if(trace.entry){
   const entry=localValue(ui,trace.entry);
   assert.equal(entry.type,'ArrowFunctionExpression');
   assert.equal(entry.body.type,'CallExpression');
   assert.equal(member(entry.body.callee),trace.stageFunction);
   const stage=localValue(ui,trace.stageFunction);
   assert.ok(calls(stage,'setConfirmation').some(n=>calls(n,'Object.freeze').length));
   for(const name of [trace.requestFunction,'legacyMutation','transport','fetch'])
    assert.equal(calls(stage,name).length,0,'Staging must not send a mutation');
   const confirm=localValue(ui,trace.confirmationHandler);
   assert.ok(nodes(ui,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
    &&n.value?.expression?.name===trace.confirmationHandler).length);
   assert.ok(calls(confirm,'confirmationCurrent').length);
   assert.ok(nodes(confirm,n=>n.type==='IfStatement'&&n.test?.name==='administration'
    &&calls(n.consequent,trace.requestFunction).length&&calls(n.alternate,'legacyMutation').length).length);
   assert.ok(calls(request,'confirmationCurrent').length);
  }else assert.equal(trace.handler,trace.requestFunction);
  const requests=calls(request,trace.requestCallee).filter(n=>{
   const target=n.arguments[0],parts=target?.type==='StringLiteral'?[target.value]:
    target?.type==='TemplateLiteral'?target.quasis.map(q=>q.value.cooked):null;
   return JSON.stringify(parts)===JSON.stringify(trace.quasis)
    &&n.arguments[1]?.properties?.some(p=>p.key?.name==='method'&&p.value?.value===trace.method);
  });
  assert.equal(requests.length,1,`${binding.actionId}: callback's exact request`);
  if(trace.entry){
   const suffix=requests[0].arguments[0].expressions[1];
   assert.equal(suffix.type,'ConditionalExpression');
   assert.equal(suffix.test.left.name,'action');assert.equal(suffix.test.right.value,'ban');
   assert.equal(suffix.consequent.value,'ban');assert.equal(suffix.alternate.value,'role');
   assert.ok(calls(request,'savePending').length);assert.ok(calls(request,'assertReceipt').length);
  }
  assert.equal(trace.proof,'source_event_handler_to_exact_request_only');assert.equal(trace.runtimeVerified,false);
 }
 const listing=tree('client/src/pages/secureshop/pages/merchant/Listings.jsx');
 const dialog=nodes(listing,n=>n.type==='JSXElement'&&n.openingElement?.name?.name==='Dialog'
  &&nodes(n,x=>x.type==='JSXAttribute'&&x.name?.name==='onClick'&&x.value?.expression?.name==='confirmDelete').length);
 assert.equal(dialog.length,1);
 assert.ok(nodes(dialog[0],n=>n.type==='JSXText'&&n.value.includes('Orders that already')).length);
 assert.ok(nodes(dialog[0],n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&calls(n,'setDeleteTarget').some(c=>c.arguments[0]?.type==='NullLiteral')).length);
 const pricing=localValue(tree('client/src/pages/secureshop/pages/merchant/Pricing.jsx'),'acceptSuggestion');
 assert.ok(calls(pricing,'fetch').some(n=>n.arguments[0]?.type==='TemplateLiteral'
  &&n.arguments[0].quasis[0].value.cooked==='/api/secureshop/products/'),'Price acceptance reads back its product');
});

test('admin panel consequence review retains a guarded immutable intent and a no-dispatch Cancel control',()=>{
 const ui=tree('client/src/pages/secureshop/pages/admin/Users.jsx'),stage=localValue(ui,'stageChange');
 const freeze=calls(stage,'Object.freeze');assert.equal(freeze.length,1);
 for(const key of ['targetId','username','expectedVersion','sourceRole','action','role','reason',
  'authToken','transport','scopeKey','queryKey','boundFrame'])
  assert.ok(freeze[0].arguments[0].properties.some(p=>p.key?.name===key));
 const guard=localValue(ui,'confirmationCurrent');
 for(const key of ['authToken','transport','scopeKey','queryKey','boundFrame','expectedVersion','sourceRole'])
  assert.ok(nodes(guard,n=>n.type==='MemberExpression'&&member(n.object)==='change'&&n.property?.name===key).length);
 const confirm=localValue(ui,'confirmChange'),reject=nodes(confirm,n=>n.type==='IfStatement'
  &&n.test?.type==='UnaryExpression'&&n.test.operator==='!'&&calls(n.test,'confirmationCurrent').length);
 assert.equal(reject.length,1);assert.ok(nodes(reject[0].consequent,n=>n.type==='ReturnStatement').length);
 const dispatch=calls(confirm,'mutateUser');assert.equal(dispatch.length,1);assert.ok(reject[0].end<dispatch[0].start);
 const dialogs=nodes(ui,n=>n.type==='JSXElement'&&n.openingElement?.attributes?.some(a=>
  a.name?.name==='aria-label'&&a.value?.value==='Confirm user change'));
 assert.equal(dialogs.length,1);
 const dialog=dialogs[0];
 assert.ok(nodes(dialog,n=>n.type==='TemplateElement'&&n.value.cooked.includes('revoke account access')).length);
 assert.ok(nodes(dialog,n=>n.type==='TemplateElement'&&n.value.cooked.includes('change account access immediately')).length);
 assert.ok(nodes(dialog,n=>n.type==='JSXExpressionContainer'&&member(n.expression)==='confirmation.reason').length);
 const cancels=nodes(dialog,n=>n.type==='JSXElement'&&n.openingElement?.name?.name==='button'
  &&n.children.some(c=>c.type==='JSXText'&&c.value.trim()==='Cancel'));
 assert.equal(cancels.length,1);
 const cancel=cancels[0].openingElement.attributes.find(a=>a.name?.name==='onClick').value.expression;
 assert.equal(cancel.type,'ArrowFunctionExpression');assert.equal(member(cancel.body.callee),'setConfirmation');
 assert.equal(cancel.body.arguments[0].type,'NullLiteral');
 const confirmButton=nodes(dialog,n=>n.type==='JSXOpeningElement'&&n.attributes?.some(a=>
  a.name?.name==='onClick'&&a.value?.expression?.name==='confirmChange'));
 assert.equal(confirmButton.length,1);
 assert.ok(confirmButton[0].attributes.some(a=>a.name?.name==='disabled'&&calls(a,'confirmationCurrent').length));
});

test('manual synthetic lookup preserves deliberate mode projection and durable effects without borrowing actor credit',()=>{
 const binding=manifest.panelBindings.find(row=>row.actionId==='admin.users.lookup'),source=binding.sourceBinding;
 const routes=calls(tree(source.routeFile),'r.post').filter(n=>n.arguments[0]?.value==='/admin/users/lookup');
 assert.equal(routes.length,1);assert.ok(calls(routes[0],'service.lookup').length);
 const service=objectMethod(tree(source.serviceFile),'lookup');
 assert.ok(calls(service,'lookupMode').length);
 assert.ok(calls(service,'authority.withPersonaEffect').some(n=>calls(n,'lookupRepository.lookup').length));
 const repo=tree(source.repositoryFile),lookup=objectMethod(repo,'lookup');
 assert.ok(calls(lookup,'audit.append').length);assert.ok(calls(lookup,'randomUUID').length);
 assert.ok(sqlParts(lookup).some(sql=>sql.includes('INSERT INTO secureshop_agents.bound_synthetic_user_directories')
  &&sql.includes('ON CONFLICT DO NOTHING')));
 const fixed=nodes(lookup,n=>n.type==='IfStatement'&&n.test?.operator==='==='
  &&n.test.left?.name==='mode'&&n.test.right?.value==='fixed');
 assert.equal(fixed.length,1);assert.ok(calls(fixed[0].consequent,'readAgentRow').length);
 assert.ok(calls(fixed[0].alternate,'row.rows_json.find').length);
 const reader=functionDeclaration(repo,'readAgentRow');
 assert.ok(sqlParts(reader).some(sql=>sql.includes("jsonb_build_object('id',u->'id','username',u->'username','role',u->'role')")));
 assert.deepEqual(binding.linkedObjectiveIds,[],'Manual lookup is not original model/tool proof for the agent objective');
 assert.match(binding.recovery.semantics,/fresh audit/);
});
