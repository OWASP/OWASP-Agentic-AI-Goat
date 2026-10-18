import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import {webcrypto} from 'node:crypto';
import {decodeCheckoutAuditAssessment,decodeCheckoutAuditSaved,useCustomerCheckoutAuditLesson}
 from './useCustomerCheckoutAuditLesson.js';
import {createCustomerCheckoutAuditReferenceStore}
 from '../utils/customerCheckoutAuditReference.mjs';
import CustomerCheckoutAuditLesson from '../components/CustomerCheckoutAuditLesson.jsx';

const operationId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const eventId='dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const scopeKey='a'.repeat(64);
const mode=effectiveMode=>({version:1,featureId:'checkout_audit_jwt',
 policyVersion:'owned-checkout-admin-audit-practice-jwt-v1',effectiveMode,
 scope:{kind:'launch_feature',id:'checkout_audit_jwt'}});
const response=value=>({ok:true,status:200,headers:{get:name=>name==='content-type'?'application/json':null},json:async()=>value});
function memoryStore(){const values=new Map();return createCustomerCheckoutAuditReferenceStore({storage:{
 getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}});}
let root,node,current,originalCrypto;
function Harness(props){current=useCustomerCheckoutAuditLesson(props);return null;}
function mount(props){node=document.createElement('div');document.body.append(node);root=createRoot(node);act(()=>root.render(<Harness {...props}/>));return{rerender(next){act(()=>root.render(<Harness {...next}/>));}};}
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;originalCrypto=globalThis.crypto;
 Object.defineProperty(globalThis,'crypto',{configurable:true,value:{...webcrypto,randomUUID:()=>requestId}});});
afterEach(async()=>{if(root)await act(async()=>root.unmount());node?.remove();root=null;node=null;
 Object.defineProperty(globalThis,'crypto',{configurable:true,value:originalCrypto});});

test('uses a genuine checkout receipt, persists IDs before one POST, and resolves a lost stream through GET',async()=>{
 const store=memoryStore(),calls=[];
 const transport=jest.fn(async(path,options)=>{
  calls.push({path,method:options.method,body:options.body,accept:options.headers.accept});
  if(path==='/api/secureshop/orders/operations')return response({scopeKey,operations:[{operationId,orderId:83,createdAt:'2026-10-15T02:00:00.000Z'}]});
  if(path.endsWith(`/orders/operations/${operationId}`))return response({scopeKey,operationId,status:'completed',order:{id:83,total:17.25,subtotal:20,discount:2.75}});
  if(path.endsWith('/practice-token'))return response({orderId:83,operationId,token:'synthetic.teaching.token',modeCapability:mode('vuln')});
  if(path.endsWith('/session'))return response({sessionId});
  if(path.endsWith('/chat'))throw Error('lost stream');
  if(path.endsWith('/assess')&&options.method==='POST')throw Error('lost assessment response');
  if(path.endsWith(`/assess/${sessionId}/${requestId}`))return response({completed:true,
   judgment:{verdict:'pass',evaluationId:eventId,canRetry:false},replayed:true});
  if(path.endsWith(`/operations/${sessionId}/${requestId}`))return response({sessionId,requestId,status:'completed',
   text:'The checkout audit was read through the practice verifier.',checkoutOperationId:operationId,
   modeCapability:mode('vuln'),result:{status:'disclosed',eventId,report:{eventId,
    timestamp:'2026-10-15T02:02:02.000000Z',actor:'customer',action:'checkout',outcome:'completed',orderId:83,total:17.25}}});
  throw Error(`unexpected ${path}`);
 });
 mount({shopUserId:7,authorityKey:'authority-a',transport,referenceStore:store});
 await act(async()=>{await Promise.resolve();await Promise.resolve();});
 expect(current.operations).toHaveLength(1);
 await act(async()=>{expect(await current.prepare(operationId)).toBe(true);});
 expect(current.prepared.token.token).toBe('synthetic.teaching.token');
 await act(async()=>{expect(await current.run('learner.edited.synthetic.token')).toBe(true);});
 const chat=calls.find(call=>call.path.endsWith('/chat'));
 expect(chat.accept).toBe('text/event-stream');
 expect(JSON.parse(chat.body)).toEqual({sessionId,requestId,checkoutOperationId:operationId,
  teachingToken:'learner.edited.synthetic.token',message:expect.stringContaining('synthetic teaching token')});
 expect(store.read(7)).toEqual(expect.objectContaining({sessionId,requestId,checkoutOperationId:operationId}));
 expect(JSON.stringify(store.read(7))).not.toContain('teaching');
 expect(calls.filter(call=>call.path.endsWith('/chat'))).toHaveLength(1);
 expect(current.result.result.report).toMatchObject({orderId:83,total:17.25});
 await act(async()=>{expect(await current.assess()).toBe(false);});
 expect(store.readAssessment(store.read(7))).toEqual(store.read(7));
 expect(current.assessmentKnownUnsent).toBe(false);
 await act(async()=>{expect(await current.assess()).toBe(false);
  expect(await current.recoverAssessment()).toBe(true);});
 expect(calls.filter(call=>call.path.endsWith('/assess')&&call.method==='POST')).toHaveLength(1);
 expect(current.assessment).toMatchObject({completed:true,judgment:{verdict:'pass'}});
});

test('fixed denial remains a denial and no saved result can expose a token or platform field',()=>{
 const reference={sessionId,requestId,checkoutOperationId:operationId};
 expect(decodeCheckoutAuditSaved({sessionId,requestId,status:'completed',text:'Denied.',
  result:{status:'denied'},checkoutOperationId:operationId,modeCapability:mode('fixed')},reference))
  .toMatchObject({result:{status:'denied'},modeCapability:{effectiveMode:'fixed'}});
 expect(()=>decodeCheckoutAuditSaved({sessionId,requestId,status:'completed',text:'bad',
  result:{status:'denied',platformToken:'secret'},checkoutOperationId:operationId,
  modeCapability:mode('fixed')},reference)).toThrow();
 expect(()=>decodeCheckoutAuditSaved({sessionId,requestId,status:'completed',text:'bad',
  result:{status:'disclosed',eventId,report:{eventId,timestamp:'2026-10-15T02:02:02Z',actor:'customer',
   action:'checkout',outcome:'completed',orderId:83,total:17.25,shippingAddress:'private'}},
  checkoutOperationId:operationId,modeCapability:mode('vuln')},reference)).toThrow();
});

test('assessment decoder accepts only the closed canonical progress projection',()=>{
 expect(decodeCheckoutAuditAssessment({completed:false,status:'unconfirmed',modelEvaluated:false}))
  .toEqual({completed:false,status:'unconfirmed',modelEvaluated:false});
 expect(decodeCheckoutAuditAssessment({completed:true,judgment:{verdict:'pass',evaluationId:eventId,
  canRetry:false},replayed:false})).toMatchObject({completed:true,judgment:{verdict:'pass'}});
 expect(decodeCheckoutAuditAssessment({completed:false,judgment:{verdict:'pass',evaluationId:eventId,
  canRetry:true},replayed:false})).toMatchObject({completed:false,judgment:{verdict:'pass'}});
 expect(()=>decodeCheckoutAuditAssessment({completed:true,judgment:{verdict:'fail',evaluationId:eventId,
  canRetry:false},replayed:false})).toThrow();
 expect(()=>decodeCheckoutAuditAssessment({completed:true,judgment:{verdict:'pass',evaluationId:eventId,
  canRetry:false,privateEvidence:'secret'},replayed:false})).toThrow();
});

test('rendered lesson lets the customer edit the synthetic token before the single model POST',async()=>{
 const store=memoryStore(),posts=[];
 const transport=jest.fn(async(path,options)=>{
  if(path==='/api/secureshop/orders/operations')return response({scopeKey,operations:[{operationId,orderId:83,createdAt:'2026-10-15T02:00:00.000Z'}]});
  if(path.endsWith(`/orders/operations/${operationId}`))return response({scopeKey,operationId,status:'completed',order:{id:83,total:17.25,subtotal:20,discount:2.75}});
  if(path.endsWith('/practice-token'))return response({orderId:83,operationId,token:'signed.customer.token',modeCapability:mode('vuln')});
  if(path.endsWith('/session'))return response({sessionId});
  if(path.endsWith('/chat')){posts.push(JSON.parse(options.body));throw Error('lost stream');}
  if(path.endsWith('/assess')&&options.method==='POST')return response({completed:false,
   status:'ineligible',modelEvaluated:false});
  if(path.endsWith(`/operations/${sessionId}/${requestId}`))return response({sessionId,requestId,status:'completed',
   text:'The supplied practice token was denied.',result:{status:'denied'},checkoutOperationId:operationId,
   modeCapability:mode('fixed')});
  throw Error(`unexpected ${path}`);
 });
 node=document.createElement('div');document.body.append(node);root=createRoot(node);
 act(()=>root.render(<CustomerCheckoutAuditLesson shopUserId={7} authorityKey="authority"
  transport={transport} referenceStore={store}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();});
 const button=label=>[...node.querySelectorAll('button')].find(value=>value.textContent.includes(label));
 await act(async()=>button('Get synthetic').click());
 const textarea=node.querySelector('#checkout-audit-teaching-token');
 expect(textarea.value).toBe('signed.customer.token');
 await act(async()=>{
  const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;
  setter.call(textarea,'learner.modified.token');
  textarea.dispatchEvent(new Event('input',{bubbles:true}));
 });
 await act(async()=>button('Ask assistant').click());
 expect(posts).toHaveLength(1);expect(posts[0].teachingToken).toBe('learner.modified.token');
 expect(node.textContent).toContain('Fixed-mode policy denied the protected audit read');
 expect(button('Assess saved checkout audit')).toBeDefined();
 await act(async()=>button('Assess saved checkout audit').click());
 expect(node.textContent).toContain('not eligible for objective credit');
 expect(transport.mock.calls.filter(([path,options])=>path.endsWith('/assess')
  &&options.method==='POST')).toHaveLength(1);
});

test('rendered grading is explicit and shows completion only from the saved canonical assessment',async()=>{
 const store=memoryStore();await store.save({shopUserId:7,sessionId,requestId,
  checkoutOperationId:operationId,startedAt:100});
 const transport=jest.fn(async(path,options)=>{
  if(path==='/api/secureshop/orders/operations')return response({scopeKey,operations:[{operationId,
   orderId:83,createdAt:'2026-10-15T02:00:00.000Z'}]});
  if(path.endsWith(`/operations/${sessionId}/${requestId}`))return response({sessionId,requestId,
   status:'completed',text:'Protected audit returned.',checkoutOperationId:operationId,
   modeCapability:mode('vuln'),result:{status:'disclosed',eventId,report:{eventId,
    timestamp:'2026-10-15T02:02:02.000000Z',actor:'customer',action:'checkout',outcome:'completed',orderId:83,total:17.25}}});
  if(path.endsWith('/assess')&&options.method==='POST')return response({completed:true,
   judgment:{verdict:'pass',evaluationId:eventId,canRetry:false},replayed:false});
  throw Error(`unexpected ${path}`);
 });
 node=document.createElement('div');document.body.append(node);root=createRoot(node);
 act(()=>root.render(<CustomerCheckoutAuditLesson shopUserId={7} authorityKey="authority"
  transport={transport} referenceStore={store}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 expect(node.textContent).not.toContain('Objective completed');
 const assess=[...node.querySelectorAll('button')].find(value=>value.textContent.includes('Assess saved'));
 await act(async()=>assess.click());
 expect(node.textContent).toContain('Objective completed in canonical progress');
 expect(transport.mock.calls.filter(([path])=>path.endsWith('/assess'))).toHaveLength(1);
});

test('known-unsent assessment can be explicitly cleared before one newly authorized POST',async()=>{
 const values=new Map();let flushCount=0;
 const store=createCustomerCheckoutAuditReferenceStore({storage:{
  getItem:key=>values.get(key)??null,
  setItem:(key,value)=>values.set(key,value),
  removeItem:key=>values.delete(key),
 },flush:async()=>{flushCount+=1;if(flushCount===2)throw Error('ack lost after durable write');}});
 await store.save({shopUserId:7,sessionId,requestId,checkoutOperationId:operationId,startedAt:100});
 const transport=jest.fn(async(path,options)=>{
  if(path==='/api/secureshop/orders/operations')return response({scopeKey,operations:[{operationId,
   orderId:83,createdAt:'2026-10-15T02:00:00.000Z'}]});
  if(path.endsWith(`/operations/${sessionId}/${requestId}`))return response({sessionId,requestId,
   status:'completed',text:'Protected audit returned.',checkoutOperationId:operationId,
   modeCapability:mode('vuln'),result:{status:'disclosed',eventId,report:{eventId,
    timestamp:'2026-10-15T02:02:02.000000Z',actor:'customer',action:'checkout',outcome:'completed',orderId:83,total:17.25}}});
  if(path.endsWith(`/assess/${sessionId}/${requestId}`)&&options.method==='GET')
   return response({completed:false,status:'unconfirmed',modelEvaluated:false});
  if(path.endsWith('/assess')&&options.method==='POST')return response({completed:true,
   judgment:{verdict:'pass',evaluationId:eventId,canRetry:false},replayed:false});
  throw Error(`unexpected ${options.method} ${path}`);
 });
 node=document.createElement('div');document.body.append(node);root=createRoot(node);
 act(()=>root.render(<CustomerCheckoutAuditLesson shopUserId={7} authorityKey="authority"
  transport={transport} referenceStore={store}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 const button=label=>[...node.querySelectorAll('button')].find(value=>value.textContent.includes(label));
 await act(async()=>button('Assess saved checkout audit').click());
 expect(transport.mock.calls.filter(([path,options])=>path.endsWith('/assess')
  &&options.method==='POST')).toHaveLength(0);
 expect(button('Assess saved checkout audit')).toBeUndefined();
 expect(button('Check saved checkout-audit assessment')).toBeDefined();
 expect(button('Discard unsent assessment admission')).toBeDefined();
 expect(node.textContent).toContain('Assessment outcome unresolved');
 await act(async()=>button('Check saved checkout-audit assessment').click());
 expect(transport.mock.calls.filter(([path,options])=>path.endsWith(`/assess/${sessionId}/${requestId}`)
  &&options.method==='GET')).toHaveLength(1);
 expect(node.textContent).toContain('Assessment is unconfirmed');
 await act(async()=>button('Discard unsent assessment admission').click());
 expect(button('Check saved checkout-audit assessment')).toBeUndefined();
 expect(button('Discard unsent assessment admission')).toBeUndefined();
 expect(button('Assess saved checkout audit')).toBeDefined();
 await act(async()=>button('Assess saved checkout audit').click());
 expect(transport.mock.calls.filter(([path,options])=>path.endsWith('/assess')
  &&options.method==='POST')).toHaveLength(1);
 expect(node.textContent).toContain('Objective completed in canonical progress');
});
