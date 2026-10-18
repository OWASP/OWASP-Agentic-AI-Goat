import React,{act}from'react';
import{createRoot}from'react-dom/client';
import{webcrypto}from'node:crypto';
import{useCustomerAvatarTraversalLesson}from'./useCustomerAvatarTraversalLesson.js';
import{createCustomerAvatarTraversalReferenceStore,createCustomerAvatarTraversalAssessmentStore}from'../utils/customerAvatarTraversalReference.mjs';
import CustomerAvatarTraversalLesson from'../components/CustomerAvatarTraversalLesson.jsx';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',operationId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const response=value=>({ok:true,headers:{get:name=>name==='content-type'?'application/json':null},json:async()=>value});
function stores(){const values=new Map(),storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush=async()=>{};
 return{reference:createCustomerAvatarTraversalReferenceStore({storage,flush}),assessment:createCustomerAvatarTraversalAssessmentStore({storage,flush})};}
let root,node,current,originalCrypto;function Harness(props){current=useCustomerAvatarTraversalLesson(props);return null;}
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;originalCrypto=globalThis.crypto;Object.defineProperty(globalThis,'crypto',{configurable:true,value:{...webcrypto,randomUUID:()=>requestId}});node=document.createElement('div');document.body.append(node);root=createRoot(node);});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();Object.defineProperty(globalThis,'crypto',{configurable:true,value:originalCrypto});});
test('V46 physical multipart keeps source bytes and logical filename, then lost POST recovers by GET without replay',async()=>{const store=stores(),calls=[];const transport=jest.fn(async(path,options)=>{calls.push([path,options]);if(path.endsWith('/session'))return response({id:sessionId});if(path.endsWith('/run'))throw Error('lost response');if(path.endsWith(`/requests/${requestId}`))return response({operationId,uploadRequestId:requestId,status:'completed',filename:'....//escaped.txt',byteCount:9,bodySha256:'a'.repeat(64),traversal:true,operationRelativePath:'avatars/escaped.txt',escapedAvatarSubdirectory:true});throw Error(path);});
 act(()=>root.render(<Harness shopUserId={46} authorityKey="a" transport={transport} referenceStore={store.reference} assessmentStore={store.assessment}/>));const file=new File(['owned-v46'],'source.txt',{type:'text/plain'});
 await act(async()=>expect(await current.run(file,'Use the supplied logical filename.','....//escaped.txt',false)).toBe(true));const form=calls.find(([path])=>path.endsWith('/run'))[1].body;
 expect(form.get('file')).toBeInstanceOf(File);expect(form.get('file').name).toBe('source.txt');expect(form.get('logicalFilename')).toBe('....//escaped.txt');expect(form.get('public')).toBe('false');expect(calls.filter(([path])=>path.endsWith('/run'))).toHaveLength(1);expect(current.result.traversal).toBe(true);expect(current.result.operationRelativePath).toBe('avatars/escaped.txt');});
test('V46 fixed denial can be assessed without any asset preview',async()=>{const store=stores();await store.reference.saveIntent({shopUserId:46,sessionId,requestId,startedAt:1});await store.reference.acknowledgeOperation(store.reference.read(46),operationId);let posts=0;
 const transport=jest.fn(async(path,options)=>{if(path.endsWith(`/requests/${requestId}`))return response({operationId,uploadRequestId:requestId,status:'denied',filename:'....//escaped.txt',byteCount:9,denialCode:'PATH_TRAVERSAL_DENIED'});if(path.endsWith('/assess')&&options.method==='POST'){posts++;return response({completed:false,status:'ineligible',modelEvaluated:false});}throw Error(path);});
 act(()=>root.render(<Harness shopUserId={46} authorityKey="fixed" transport={transport} referenceStore={store.reference} assessmentStore={store.assessment}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();});await act(async()=>expect(await current.assess()).toBe(true));expect(posts).toBe(1);expect(current.assessment.status).toBe('ineligible');expect(transport.mock.calls.some(([path])=>path.includes('/asset'))).toBe(false);});
test('V46 card exposes a distinct bounded logical-filename field and no preview surface',()=>{const store=stores();act(()=>root.render(<CustomerAvatarTraversalLesson shopUserId={46} authorityKey="a" transport={jest.fn()} referenceStore={store.reference} assessmentStore={store.assessment}/>));expect(node.querySelector('[data-testid="avatar-traversal-filename"]').value).toBe('....//avatar.txt');expect(node.querySelector('iframe')).toBeNull();});
test('V46 completed card shows only the safe operation-relative escaped destination',async()=>{const store=stores();await store.reference.saveIntent({shopUserId:46,sessionId,requestId,startedAt:1});await store.reference.acknowledgeOperation(store.reference.read(46),operationId);
 const transport=jest.fn(async path=>{if(path.endsWith(`/requests/${requestId}`))return response({operationId,uploadRequestId:requestId,status:'completed',filename:'....//escaped.txt',byteCount:9,bodySha256:'a'.repeat(64),traversal:true,operationRelativePath:'avatars/escaped.txt',escapedAvatarSubdirectory:true});throw Error(path);});
 await act(async()=>{root.render(<CustomerAvatarTraversalLesson shopUserId={46} authorityKey="a" transport={transport} referenceStore={store.reference} assessmentStore={store.assessment}/>);await Promise.resolve();await Promise.resolve();});
 expect(node.textContent).toContain('Stored outside the avatar subdirectory at avatars/escaped.txt');expect(node.textContent).not.toContain(operationId);});

test.each(['avatars/.','avatars/..','avatars/escape\\name.txt','avatars/escape\nname.txt','foreign/escaped.txt'])('V46 client rejects unsafe completed destination %p',async operationRelativePath=>{const store=stores();const transport=jest.fn(async path=>{if(path.endsWith('/session'))return response({id:sessionId});if(path.endsWith('/run'))return response({operationId,uploadRequestId:requestId,status:'completed',text:'stored',sourceFilename:'source.txt',filename:'....//escaped.txt',byteCount:9,replayed:false,operationRelativePath,escapedAvatarSubdirectory:true});throw Error(path);});
 act(()=>root.render(<Harness shopUserId={46} authorityKey="a" transport={transport} referenceStore={store.reference} assessmentStore={store.assessment}/>));const file=new File(['owned-v46'],'source.txt',{type:'text/plain'});await act(async()=>expect(await current.run(file,'Use it.','....//escaped.txt',false)).toBe(false));expect(current.result).toBeNull();});

test.each([
 {completed:true,judgment:{verdict:'pass',evaluationId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',canRetry:false},replayed:false},
 {completed:false,status:'ineligible',modelEvaluated:false}
])('V46 visible retirement uses the newly resolved assessment without replay: %p',async outcome=>{
 const store=stores();await store.reference.saveIntent({shopUserId:46,sessionId,requestId,startedAt:1});
 await store.reference.acknowledgeOperation(store.reference.read(46),operationId);
 const saved=store.reference.read(46),calls=[];
 const transport=jest.fn(async(path,options)=>{calls.push([path,options.method]);
  if(path.endsWith(`/requests/${requestId}`))return response({operationId,uploadRequestId:requestId,status:'completed',filename:'....//escaped.txt',byteCount:9,bodySha256:'a'.repeat(64),traversal:true,operationRelativePath:'avatars/escaped.txt',escapedAvatarSubdirectory:true});
  if(path.endsWith('/assess')&&options.method==='POST')return response(outcome);
  throw Error(path);
 });
 await act(async()=>{root.render(<CustomerAvatarTraversalLesson shopUserId={46} authorityKey="a" transport={transport} referenceStore={store.reference} assessmentStore={store.assessment}/>);await Promise.resolve();await Promise.resolve();});
 const button=label=>[...node.querySelectorAll('button')].find(value=>value.textContent===label);
 await act(async()=>button('Assess saved traversal upload').click());
 expect(store.assessment.read(saved)).not.toBeNull();const before=calls.map(value=>[...value]);
 await act(async()=>button('Start another traversal upload').click());
 expect(store.assessment.read(saved)).toBeNull();expect(store.reference.read(46)).toBeNull();
 expect(node.querySelector('[data-testid="avatar-traversal-file"]')).not.toBeNull();expect(calls).toEqual(before);
});

test('V46 visible retirement preserves the submitted reference while assessment remains unconfirmed',async()=>{
 const store=stores();await store.reference.saveIntent({shopUserId:46,sessionId,requestId,startedAt:1});
 await store.reference.acknowledgeOperation(store.reference.read(46),operationId);const saved=store.reference.read(46);
 const transport=jest.fn(async(path,options)=>{
  if(path.endsWith(`/requests/${requestId}`))return response({operationId,uploadRequestId:requestId,status:'completed',filename:'....//escaped.txt',byteCount:9,bodySha256:'a'.repeat(64),traversal:true,operationRelativePath:'avatars/escaped.txt',escapedAvatarSubdirectory:true});
  if(path.endsWith('/assess')&&options.method==='POST')return response({completed:false,status:'unconfirmed',modelEvaluated:false});
  throw Error(path);
 });
 await act(async()=>{root.render(<CustomerAvatarTraversalLesson shopUserId={46} authorityKey="a" transport={transport} referenceStore={store.reference} assessmentStore={store.assessment}/>);await Promise.resolve();await Promise.resolve();});
 const button=label=>[...node.querySelectorAll('button')].find(value=>value.textContent===label);
 await act(async()=>button('Assess saved traversal upload').click());const grade=store.assessment.read(saved),before=transport.mock.calls.length;
 await act(async()=>button('Start another traversal upload').click());
 expect(store.reference.read(46)).toEqual(saved);expect(store.assessment.read(saved)).toEqual(grade);
 expect(node.querySelector('[data-testid="avatar-traversal-file"]')).toBeNull();expect(transport).toHaveBeenCalledTimes(before);
});
