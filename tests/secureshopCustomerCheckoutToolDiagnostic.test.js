'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { privateOrdersListArguments, privateProfileRecoveryNetworkEvent, privateProfileRecoveryRecord,
  privateProfileRecoveryUiCategory, privateAddressRecoveryUiCategory,
  privateAddressRecoveryButtonGeometry, privateAddressRecoveryEvidence,
  privatePersistAddressRecoveryDiagnostic } = require('./postgres/secureshopCustomerCheckoutRendered.integration.test');

test('address recovery UI diagnostic is a closed category without private field text', () => {
  const category = status => privateAddressRecoveryUiCategory([{status:[status],
    text:'Bearer private address line',buttons:[{text:'Check saved address'}]}]);
  assert.equal(privateAddressRecoveryUiCategory([]),'absent');
  assert.equal(category('An address change is saved. Check its exact outcome before another save.'),'saved-pending');
  assert.equal(category('Saved address lookup failed (503).'),'lookup-failed');
  assert.equal(category('Address outcome is not recorded yet. Check the saved address; the save will not be retried.'),'not-found');
  assert.equal(category('Address saved.'),'completed');
  assert.equal(category('Bearer private address line'),'other');
  assert.doesNotMatch(JSON.stringify({status:category('Bearer private address line')}),/Bearer|private address line/);
});

test('address recovery geometry records bounded center hit and scroll-body bounds only', () => {
  const rect = {left:10,right:110,top:700,bottom:740,width:100,height:40};
  const button = {textContent:'Check saved address',disabled:false,tagName:'BUTTON',
    getBoundingClientRect:()=>rect,getClientRects:()=>[rect],contains:()=>false};
  const body = {getBoundingClientRect:()=>({left:0,right:400,top:100,bottom:680}),
    scrollHeight:1200,clientHeight:580,scrollTop:0,parentElement:null};
  button.parentElement = body;
  let hit = {tagName:'TEXTAREA'};
  const doc = {querySelector:selector => selector === '[aria-label="Address setup"]'
    ? {querySelectorAll:()=>[button]} : selector === '.ss-lane__body' ? body : null,
  elementFromPoint:()=>hit};
  const view = {innerWidth:400,innerHeight:800};
  const before = privateAddressRecoveryButtonGeometry(doc,view,()=>({visibility:'visible'}));
  assert.deepEqual(before,{count:1,viewport:{width:400,height:800},scrollBody:{top:100,bottom:680},
    buttons:[{disabled:false,visible:true,center:{x:60,y:720},size:{width:100,height:40},
      centerInViewport:true,centerInScrollBody:false,centerHit:false,
      scrollAncestors:[{depth:0,visible:{top:100,bottom:680},scrollTop:0,scrollHeight:1200,clientHeight:580}],
      hitKind:'input'}]});
  rect.top = 300; rect.bottom = 340; body.scrollTop = 420; hit = button;
  const after = privateAddressRecoveryButtonGeometry(doc,view,()=>({visibility:'visible'}));
  assert.equal(after.buttons[0].centerInScrollBody,true);
  assert.equal(after.buttons[0].centerHit,true);
  assert.equal(after.buttons[0].hitKind,'button');
  assert.equal(after.buttons[0].scrollAncestors[0].scrollTop,420);
  assert.doesNotMatch(JSON.stringify(after),/Bearer|private|address line|Check saved address/);
});

test('address recovery record retains the same closed metadata on success and failure', async () => {
  const id = '70000000-0000-4000-8000-000000000011';
  const exact = `/customer/commerce/operations/${id}`;
  const diagnostic = {phase:'completed',network:{requests:1,responses:1,failures:0,
    nonexactShape:0,samples:[{kind:'response',shape:'exact',method:'GET',status:200}]},
  beforeScroll:{count:1},afterScroll:{count:1},afterClick:{count:1}};
  const inputs = [diagnostic,{reads:1,faulted:1},id,['foreign',exact,exact],['foreign',exact],
    [{status:['Address saved.'],text:'Bearer private address line'}]];
  const success = privateAddressRecoveryEvidence(...inputs,true);
  assert.deepEqual(success,{...diagnostic,server:{reads:2,faulted:1},uiStatus:'completed',validatedOutcome:true});
  const failed = privateAddressRecoveryEvidence(...inputs,false);
  assert.deepEqual(failed,{...success,validatedOutcome:false});
  assert.doesNotMatch(JSON.stringify(success),/Bearer|private address line|70000000/);
  let published;
  assert.equal(await privatePersistAddressRecoveryDiagnostic(async (...args) => { published = args; },
    '/owned/customer-address-recovery-diagnostic.json',success),true);
  assert.equal(published[2].mode,0o600);
  assert.deepEqual(JSON.parse(published[1]),success);
  assert.equal(await privatePersistAddressRecoveryDiagnostic(async () => { throw Error('private write failure'); },
    '/owned/customer-address-recovery-diagnostic.json',failed),false);
});

test('private orders.list failure evidence retains original optional fields and unexpected keys', () => {
  const cursor = '70000000-0000-4000-8000-000000000011';
  assert.deepEqual(privateOrdersListArguments({ cursor, productName: ' Notebook ' }), {
    complete: true, inputStage: 'later_adapter_or_context', reason: 'static_input_shape_valid',
    args: { cursor, productName: ' Notebook ' },
  });
  assert.deepEqual(privateOrdersListArguments({ cursor: null }), {
    complete: true, inputStage: 'arguments', reason: 'invalid_cursor_shape', args: { cursor: null },
  });
  assert.deepEqual(privateOrdersListArguments({ cursor: '', inventedOrderId: 42 }), {
    complete: true, inputStage: 'arguments', reason: 'unexpected_keys',
    args: { cursor: '', inventedOrderId: 42 },
  });
  assert.deepEqual(privateOrdersListArguments({ productName: ' ' }), {
    complete: true, inputStage: 'arguments', reason: 'invalid_product_name_shape', args: { productName: ' ' },
  });
  assert.deepEqual(privateOrdersListArguments({ authorization: 'Bearer synthetic' }), {
    complete: false, inputStage: 'arguments', reason: 'credential_redacted', keys: ['authorization'],
  });
});

test('profile recovery network evidence admits only the exact owned URL and emits closed metadata', () => {
  const operationId = '70000000-0000-4000-8000-000000000011';
  const origin = 'http://127.0.0.1:39117';
  const url = `${origin}/api/secureshop/customer/commerce/operations/${operationId}`;
  const observed = input => privateProfileRecoveryNetworkEvent({origin,operationId,...input});
  assert.deepEqual(observed({kind:'request',url,method:'GET',headers:{authorization:'Bearer private'},
    body:'private profile value'}), {kind:'request',shape:'exact',method:'GET',status:null});
  assert.deepEqual(observed({kind:'response',url,method:'GET',status:200,body:'private profile value'}),
    {kind:'response',shape:'exact',method:'GET',status:200});
  assert.deepEqual(observed({kind:'failure',url,method:'POST',status:503}),
    {kind:'failure',shape:'exact',method:'POST',status:null});
  assert.deepEqual(observed({kind:'response',url:`${url}?token=private`,method:'Bearer private',status:503}),
    {kind:'response',shape:'query-or-fragment',method:'OTHER',status:503});
  assert.equal(observed({kind:'request',url:`http://127.0.0.1:39118/api/secureshop/customer/commerce/operations/${operationId}`,
    method:'GET'}),null);
  assert.equal(observed({kind:'request',url:`${url}/other`,method:'GET'}),null);
  assert.equal(observed({kind:'request',url:'not a URL',method:'GET'}),null);
  const encoded = JSON.stringify(observed({kind:'response',url,method:'GET',status:200,
    headers:{authorization:'Bearer private'},body:'private profile value'}));
  assert.doesNotMatch(encoded,/Bearer|private|profile value|39117|70000000/);
});

test('profile recovery UI evidence retains only recognized state categories', () => {
  const category = status => privateProfileRecoveryUiCategory([{status:[status],
    text:'private profile value',buttons:[{text:'Check saved profile',disabled:false}]}]);
  assert.equal(privateProfileRecoveryUiCategory([]),'absent');
  assert.equal(category('A profile change is saved. Check its exact outcome before another update.'),'saved-pending');
  assert.equal(category('Saved profile lookup failed (503).'),'lookup-failed');
  assert.equal(category('Profile outcome is not recorded yet. Check the saved profile; the update will not be retried.'),'not-found');
  assert.equal(category('Profile updated.'),'completed');
  assert.equal(category('Bearer private profile value'),'other');
  assert.doesNotMatch(JSON.stringify({status:category('Bearer private profile value')}),/Bearer|private|profile value/);
});

test('profile recovery diagnostic counts remain bounded and exclude private request material', () => {
  const operationId = '70000000-0000-4000-8000-000000000011';
  const origin = 'http://127.0.0.1:39117';
  const url = `${origin}/api/secureshop/customer/commerce/operations/${operationId}`;
  const network = {requests:0,responses:0,failures:0,nonexactShape:0,samples:[]};
  for (let i = 0; i < 1100; i += 1) privateProfileRecoveryRecord(network, {
    kind:'request',url,method:'GET',origin,operationId,
    headers:{authorization:'Bearer private'},body:'private profile value' });
  privateProfileRecoveryRecord(network, {kind:'response',url,method:'GET',status:503,origin,operationId});
  privateProfileRecoveryRecord(network, {kind:'failure',url,method:'GET',origin,operationId});
  privateProfileRecoveryRecord(network, {kind:'request',url:`${url}?token=private`,method:'GET',origin,operationId});
  privateProfileRecoveryRecord(network, {kind:'request',url:`${origin}/other`,method:'GET',origin,operationId});
  assert.deepEqual([network.requests,network.responses,network.failures,network.nonexactShape,
    network.samples.length],[999,1,1,1,12]);
  assert.doesNotMatch(JSON.stringify(network),/Bearer|private|profile value|39117|70000000/);
});
