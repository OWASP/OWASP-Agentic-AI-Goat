import React,{act}from'react';
import{createRoot}from'react-dom/client';
import{webcrypto}from'node:crypto';
import{useCustomerAvatarUploadLesson}from'./useCustomerAvatarUploadLesson.js';
import{createCustomerAvatarUploadReferenceStore}from'../utils/customerAvatarUploadReference.mjs';
import{createCustomerAvatarUploadAssessmentStore,createCustomerAvatarSvgAssessmentStore}from'../utils/customerAvatarUploadAssessmentReference.mjs';
import CustomerAvatarUploadLesson from'../components/CustomerAvatarUploadLesson.jsx';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 operationId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const response=value=>({ok:true,headers:{get:name=>name==='content-type'?'application/json':null},json:async()=>value});
function memoryStore(){const values=new Map();return createCustomerAvatarUploadReferenceStore({storage:{
 getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}})}
function assessmentStore(){const values=new Map();return createCustomerAvatarUploadAssessmentStore({storage:{
 getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}})}
function svgAssessmentStore(){const values=new Map();return createCustomerAvatarSvgAssessmentStore({storage:{
 getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}})}
let root,node,current,originalCrypto;function Harness(props){current=useCustomerAvatarUploadLesson(props);return null;}
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;originalCrypto=globalThis.crypto;
 Object.defineProperty(globalThis,'crypto',{configurable:true,value:{...webcrypto,randomUUID:()=>requestId}});
 node=document.createElement('div');document.body.append(node);root=createRoot(node);});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();Object.defineProperty(globalThis,'crypto',{configurable:true,value:originalCrypto});});
test('physical multipart selection persists intent and lost POST response recovers by request GET without replay',async()=>{
 const store=memoryStore(),calls=[];const transport=jest.fn(async(path,options)=>{calls.push([path,options]);
  if(path.endsWith('/session'))return response({id:sessionId});
  if(path.endsWith('/run'))throw Error('lost response');
  if(path.endsWith(`/requests/${requestId}`))return response({operationId,uploadRequestId:requestId,
   status:'completed',filename:'avatar.svg',byteCount:14,bodySha256:'a'.repeat(64)});
  throw Error(`unexpected ${path}`);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={assessmentStore()} svgAssessmentStore={svgAssessmentStore()}/>));
 const file=new File(['<svg></svg>'],'avatar.svg',{type:'image/svg+xml'});
 await act(async()=>expect(await current.run(file,'Upload my selected avatar.',true)).toBe(true));
 const run=calls.find(([path])=>path.endsWith('/run'));expect(run[1].body).toBeInstanceOf(FormData);
 expect(run[1].body.get('file')).toBeInstanceOf(File);expect(run[1].body.get('public')).toBe('true');
 expect(calls.filter(([path])=>path.endsWith('/run'))).toHaveLength(1);
 expect(calls.filter(([path])=>path.endsWith(`/requests/${requestId}`))).toHaveLength(1);
 expect(store.read(7)).toEqual(expect.objectContaining({sessionId,requestId,operationId}));
});
test('preview is explicit and rendered in a cookie-isolated sandbox without same-origin or top navigation',async()=>{
 const store=memoryStore();await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});
 await store.acknowledgeOperation(store.read(7),operationId);
 const transport=jest.fn(async(path,options)=>{
  if(path.endsWith(`/operations/${operationId}`)&&options.method==='GET')return response({operationId,
   uploadRequestId:requestId,status:'completed',filename:'avatar.svg',byteCount:14,bodySha256:'a'.repeat(64)});
  if(path.endsWith(`/operations/${operationId}/asset`)&&options.method==='POST')return response({operationId,
   assetUrl:'http://127.0.0.2:9083/assets/capability',expiresAt:Date.now()+60000});
  throw Error(`unexpected ${path}`);});
 act(()=>root.render(<CustomerAvatarUploadLesson shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={assessmentStore()} svgAssessmentStore={svgAssessmentStore()}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();});
 const open=[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Open sandbox'));
 expect(node.querySelector('iframe')).toBeNull();await act(async()=>open.click());
 const frame=node.querySelector('[data-testid="avatar-upload-preview"]');expect(frame).not.toBeNull();
 expect(frame.getAttribute('sandbox')).toBe('allow-scripts');expect(frame.getAttribute('sandbox')).not.toMatch(/same-origin|top-navigation/);
 expect(transport.mock.calls.filter(([path])=>path.endsWith('/asset'))).toHaveLength(1);
});

test('durable pre-POST intent is explicitly discarded before a new authorized submission',async()=>{
 const values=new Map();let failFlush=true;const store=createCustomerAvatarUploadReferenceStore({storage:{getItem:key=>values.get(key)??null,
  setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{if(failFlush){failFlush=false;throw Error('lost ack')}}});
 let posts=0;const transport=jest.fn(async(path)=>{if(path.endsWith('/session'))return response({id:sessionId});if(path.endsWith('/run')){posts++;return response({operationId,uploadRequestId:requestId,status:'denied',text:'Denied',filename:'a.png',byteCount:1,replayed:false})}throw Error(path)});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={assessmentStore()} svgAssessmentStore={svgAssessmentStore()}/>));
 const file=new File(['x'],'a.png',{type:'image/png'});await act(async()=>expect(await current.run(file,'Upload avatar',true)).toBe(false));
 expect(posts).toBe(0);expect(current.knownUnsent).toBe(true);await act(async()=>expect(await current.discardUnsent()).toBe(true));
 expect(store.read(7)).toBeNull();await act(async()=>expect(await current.run(file,'Upload avatar',true)).toBe(true));expect(posts).toBe(1);
});

test('unreadable saved state latches admission and performs no POST',async()=>{
 const store={read:()=>{throw Error('offline')}};const transport=jest.fn();act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={assessmentStore()} svgAssessmentStore={svgAssessmentStore()}/>));
 const file=new File(['x'],'a.png',{type:'image/png'});await act(async()=>expect(await current.run(file,'Upload avatar',true)).toBe(false));expect(current.admissionLatched).toBe(true);expect(transport).not.toHaveBeenCalled();
});

test('completed preview delivery admits one canonical assessment and saved GET recovery',async()=>{
 const store=memoryStore(),grades=assessmentStore();await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});
 await store.acknowledgeOperation(store.read(7),operationId);let assessPosts=0,assessmentGets=0;
 const verdict={completed:true,judgment:{verdict:'pass',evaluationId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',canRetry:false},replayed:false};
 const transport=jest.fn(async(path,options)=>{
  if(path.endsWith('/operations/'+operationId)&&options.method==='GET')return response({operationId,uploadRequestId:requestId,status:'completed',filename:'avatar.html',byteCount:9,bodySha256:'a'.repeat(64)});
  if(path.endsWith('/operations/'+operationId+'/asset'))return response({operationId,assetUrl:'http://127.0.0.2:9083/a',expiresAt:Date.now()+60000});
  if(path.endsWith('/assess')&&options.method==='POST'){assessPosts++;return response(verdict);}
  if(path.endsWith('/assess/'+sessionId+'/'+requestId)){assessmentGets++;return response(verdict);}
  throw Error(path);
 });
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={grades} svgAssessmentStore={svgAssessmentStore()}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();});expect(current.previewDelivered).toBe(false);
 await act(async()=>expect(await current.preview()).toBe(true));expect(await current.assess()).toBe(false);
 act(()=>current.markPreviewDelivered());await act(async()=>expect(await current.assess()).toBe(true));expect(assessPosts).toBe(1);
 await act(async()=>expect(await current.recoverAssessment()).toBe(true));expect(assessmentGets).toBe(1);
 expect(current.assessment.completed).toBe(true);expect(current.assessmentKnownUnsent).toBe(false);
});
test('fixed denial explicitly assesses to ineligible without preview or Judge completion',async()=>{
 const store=memoryStore(),grades=assessmentStore();await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});
 await store.acknowledgeOperation(store.read(7),operationId);let posts=0;
 const transport=jest.fn(async(path,options)=>{if(path.endsWith('/operations/'+operationId))return response({operationId,uploadRequestId:requestId,status:'denied',filename:'avatar.html',byteCount:9,denialCode:'extension_denied'});
  if(path.endsWith('/assess')&&options.method==='POST'){posts++;return response({completed:false,status:'ineligible',modelEvaluated:false});}throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="fixed" transport={transport} referenceStore={store} assessmentStore={grades} svgAssessmentStore={svgAssessmentStore()}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();});await act(async()=>expect(await current.assess()).toBe(true));
 expect(posts).toBe(1);expect(current.assessment).toEqual({completed:false,status:'ineligible',modelEvaluated:false});
});
test('known-unsent proof survives unconfirmed GET but rejects a same-ID replacement',async()=>{
 const store=memoryStore();await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});
 await store.acknowledgeOperation(store.read(7),operationId);let retained=null,posts=0;
 const grades={read:()=>retained,submit:async(ref,_current,written)=>{retained=Object.freeze({version:1,...ref});written(retained);throw Error('lost flush');},clear:async()=>true};
 const transport=jest.fn(async(path,options)=>{
  if(path.endsWith('/operations/'+operationId)&&options.method==='GET')return response({operationId,uploadRequestId:requestId,status:'denied',filename:'avatar.html',byteCount:9,denialCode:'extension_denied'});
  if(path.endsWith('/assess')&&options.method==='POST'){posts++;throw Error('must not post');}
  if(path.endsWith('/assess/'+sessionId+'/'+requestId))return response({completed:false,status:'unconfirmed',modelEvaluated:false});
  throw Error(path);
 });
 act(()=>root.render(<Harness shopUserId={7} authorityKey="fixed" transport={transport} referenceStore={store} assessmentStore={grades} svgAssessmentStore={svgAssessmentStore()}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();});await act(async()=>expect(await current.assess()).toBe(false));
 expect(posts).toBe(0);expect(current.assessmentKnownUnsent).toBe(true);
 await act(async()=>expect(await current.recoverAssessment()).toBe(true));expect(current.assessment.status).toBe('unconfirmed');
 expect(current.assessmentKnownUnsent).toBe(true);
});
test('same IDs with a different persisted assessment timestamp are not own-write proof',async()=>{
 const store=memoryStore();await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});
 await store.acknowledgeOperation(store.read(7),operationId);let retained=null;
 const grades={read:()=>retained,submit:async(ref,_current,written)=>{const own=Object.freeze({version:1,...ref});written(own);retained=Object.freeze({...own,startedAt:own.startedAt+1});throw Error('replaced');},clear:async()=>true};
 const transport=jest.fn(async(path,options)=>{if(path.endsWith('/operations/'+operationId)&&options.method==='GET')return response({operationId,uploadRequestId:requestId,status:'denied',filename:'avatar.html',byteCount:9,denialCode:'extension_denied'});throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="fixed" transport={transport} referenceStore={store} assessmentStore={grades} svgAssessmentStore={svgAssessmentStore()}/>));
 await act(async()=>{await Promise.resolve();await Promise.resolve();});await act(async()=>expect(await current.assess()).toBe(false));
 expect(current.assessmentKnownUnsent).toBe(false);
});

test('SVG assessment waits for first preview serve, saves IDs only and recovers lost POST with GET only',async()=>{
 const store=memoryStore(),svgGrades=svgAssessmentStore();await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});await store.acknowledgeOperation(store.read(7),operationId);let posts=0,gets=0;
 const verdict={completed:true,judgment:{verdict:'pass',evaluationId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',canRetry:false},replayed:false};
 const transport=jest.fn(async(path,options)=>{if(path.endsWith('/operations/'+operationId)&&options.method==='GET')return response({operationId,uploadRequestId:requestId,status:'completed',filename:'avatar.svg',byteCount:109,bodySha256:'a'.repeat(64)});if(path.endsWith('/operations/'+operationId+'/asset'))return response({operationId,assetUrl:'http://127.0.0.2:9083/a',expiresAt:Date.now()+60000});if(path.endsWith('/svg-assess')&&options.method==='POST'){posts++;throw Error('lost response');}if(path.endsWith('/svg-assess/'+sessionId+'/'+requestId)){gets++;return response(verdict);}throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={assessmentStore()} svgAssessmentStore={svgGrades}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();});expect(await current.assessSvg()).toBe(false);
 await act(async()=>expect(await current.preview()).toBe(true));act(()=>current.markPreviewDelivered());await act(async()=>expect(await current.assessSvg()).toBe(true));expect(posts).toBe(1);expect(gets).toBe(1);expect(current.svgAssessment.completed).toBe(true);expect(svgGrades.read(store.read(7))).toEqual(expect.objectContaining({shopUserId:7,sessionId,requestId}));expect(transport.mock.calls.filter(([path])=>path.endsWith('/svg-assess'))).toHaveLength(1);
});
test('default-disabled SVG assessment retains canonical ineligible DTO and permits exact terminal retirement',async()=>{
 const store=memoryStore(),v06=assessmentStore(),svgGrades=svgAssessmentStore();await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});await store.acknowledgeOperation(store.read(7),operationId);
 const transport=jest.fn(async(path,options)=>{if(path.endsWith('/operations/'+operationId))return response({operationId,uploadRequestId:requestId,status:'completed',filename:'avatar.svg',byteCount:109,bodySha256:'a'.repeat(64)});if(path.endsWith('/operations/'+operationId+'/asset'))return response({operationId,assetUrl:'http://127.0.0.2:9083/a',expiresAt:Date.now()+60000});if(path.endsWith('/svg-assess')&&options.method==='POST')return response({completed:false,status:'ineligible',modelEvaluated:false});throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={v06} svgAssessmentStore={svgGrades}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();});await act(async()=>expect(await current.preview()).toBe(true));act(()=>current.markPreviewDelivered());await act(async()=>expect(await current.assessSvg()).toBe(true));expect(current.svgAssessment).toEqual({completed:false,status:'ineligible',modelEvaluated:false});await act(async()=>expect(await current.startNew()).toBe(true));expect(store.read(7)).toBeNull();expect(svgGrades.read({shopUserId:7,sessionId,requestId})).toBeNull();
});

test('terminal retirement advances a cleared V06 reference before retrying a failed SVG clear',async()=>{
 const saved=Object.freeze({version:1,shopUserId:7,sessionId,requestId,operationId,startedAt:100}),grade=Object.freeze({version:1,shopUserId:7,sessionId,requestId,startedAt:101});let v06Clears=0,svgClears=0,uploadClears=0;
 const store={read:()=>saved,clear:async()=>{uploadClears++;return true}},v06={read:()=>grade,clear:async()=>{v06Clears++;return true}},svg={read:()=>grade,clear:async()=>{svgClears++;if(svgClears===1)throw Error('svg clear unavailable');return true}};
 const verdict={completed:true,judgment:{verdict:'pass',evaluationId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',canRetry:false},replayed:false};
 const transport=jest.fn(async path=>{if(path.endsWith('/operations/'+operationId))return response({operationId,uploadRequestId:requestId,status:'completed',filename:'avatar.svg',byteCount:109,bodySha256:'a'.repeat(64)});if(path.endsWith('/assess/'+sessionId+'/'+requestId)||path.endsWith('/svg-assess/'+sessionId+'/'+requestId))return response(verdict);throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={v06} svgAssessmentStore={svg}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 await act(async()=>expect(await current.startNew()).toBe(false));expect([v06Clears,svgClears,uploadClears]).toEqual([1,1,0]);expect(current.assessmentReference).toBeNull();expect(current.svgAssessmentReference).toBe(grade);expect(current.reference).toBe(saved);
 await act(async()=>expect(await current.startNew()).toBe(true));expect([v06Clears,svgClears,uploadClears]).toEqual([1,2,1]);expect(current.reference).toBeNull();
});
test('terminal retirement advances both assessment references before retrying a failed upload clear',async()=>{
 const saved=Object.freeze({version:1,shopUserId:7,sessionId,requestId,operationId,startedAt:100}),grade=Object.freeze({version:1,shopUserId:7,sessionId,requestId,startedAt:101});let v06Clears=0,svgClears=0,uploadClears=0;
 const store={read:()=>saved,clear:async()=>{uploadClears++;if(uploadClears===1)throw Error('upload clear unavailable');return true}},v06={read:()=>grade,clear:async()=>{v06Clears++;return true}},svg={read:()=>grade,clear:async()=>{svgClears++;return true}};
 const verdict={completed:true,judgment:{verdict:'pass',evaluationId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',canRetry:false},replayed:false};
 const transport=jest.fn(async path=>{if(path.endsWith('/operations/'+operationId))return response({operationId,uploadRequestId:requestId,status:'completed',filename:'avatar.svg',byteCount:109,bodySha256:'a'.repeat(64)});if(path.endsWith('/assess/'+sessionId+'/'+requestId)||path.endsWith('/svg-assess/'+sessionId+'/'+requestId))return response(verdict);throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={store} assessmentStore={v06} svgAssessmentStore={svg}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 await act(async()=>expect(await current.startNew()).toBe(false));expect([v06Clears,svgClears,uploadClears]).toEqual([1,1,1]);expect(current.assessmentReference).toBeNull();expect(current.svgAssessmentReference).toBeNull();expect(current.reference).toBe(saved);
 await act(async()=>expect(await current.startNew()).toBe(true));expect([v06Clears,svgClears,uploadClears]).toEqual([1,1,2]);expect(current.reference).toBeNull();
});

async function polyglotSetup(transport,previewRef,gradeRef){
 const F=await import('../utils/customerAvatarUploadAssessmentReference.mjs');
 const create=factory=>{const values=new Map();return factory({storage:{getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)},flush:async()=>{}});};
 const referenceStore=memoryStore();await referenceStore.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});await referenceStore.acknowledgeOperation(referenceStore.read(7),operationId);
 const polyglotPreviewStore=create(F.createCustomerAvatarPolyglotPreviewStore),polyglotAssessmentStore=create(F.createCustomerAvatarPolyglotAssessmentStore);
 if(previewRef)await polyglotPreviewStore.submit({shopUserId:7,sessionId,requestId,startedAt:200});
 if(gradeRef)await polyglotAssessmentStore.submit({shopUserId:7,sessionId,requestId,startedAt:300});
 const props={shopUserId:7,authorityKey:'a',transport,referenceStore,assessmentStore:assessmentStore(),svgAssessmentStore:svgAssessmentStore(),polyglotPreviewStore,polyglotAssessmentStore};
 return props;
}
const originalUpload={operationId,uploadRequestId:requestId,status:'completed',filename:'avatar.gif',byteCount:56,bodySha256:'a'.repeat(64)};
const previewResult=(status,replayed)=>({operationId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',uploadOperationId:operationId,status,sourceSha256:'a'.repeat(64),text:['pending','unconfirmed'].includes(status)?null:'The saved image preview completed.',replayed});
const settle=async()=>{await Promise.resolve();await Promise.resolve();};
test('legacy preview requires explicit physical action and renders the exact separate model final',async()=>{
 const calls=[],transport=jest.fn(async(path,options)=>{calls.push([path,options]);
  if(path.endsWith('/polyglot-readiness'))return response({ready:true});
  if(path.endsWith('/operations/'+operationId))return response(originalUpload);
  if(path.endsWith('/asset'))return response({operationId,assetUrl:'http://127.0.0.2:9083/assets/capability',expiresAt:Date.now()+60000});
  if(path.endsWith('/polyglot-preview')){expect(JSON.parse(options.body)).toEqual({sessionId,requestId});return response(previewResult('executed',false));}
  throw Error(path);
 });
 const props=await polyglotSetup(transport);await act(async()=>{root.render(<CustomerAvatarUploadLesson {...props}/>);await settle();});
 const legacy=()=>[...node.querySelectorAll('button')].find(button=>button.textContent==='Run legacy preview');
 expect(legacy()).toBeDefined();expect(legacy().disabled).toBe(true);expect(calls.filter(([,o])=>o.method==='POST')).toHaveLength(0);
 await act(async()=>[...node.querySelectorAll('button')].find(button=>button.textContent==='Open sandbox preview').click());
 await act(async()=>node.querySelector('iframe').dispatchEvent(new Event('load')));
 expect(legacy().disabled).toBe(false);await act(async()=>legacy().click());
 expect(node.querySelector('[data-testid="avatar-polyglot-reply"]').textContent).toBe(previewResult('executed',false).text);
 expect(calls.filter(([path])=>path.endsWith('/polyglot-preview'))).toHaveLength(1);
 expect(props.polyglotPreviewStore.read(props.referenceStore.read(7))).not.toBeNull();
});
test('lost preview and grading acknowledgements restore pending references by GET after remount without another POST',async()=>{
 let previewStatus='pending',grading='pending';const calls=[];
 const transport=jest.fn(async(path,options)=>{calls.push([path,options]);
  if(path.endsWith('/polyglot-readiness'))return response({ready:true});
  if(path.endsWith('/operations/'+operationId))return response(originalUpload);
  if(path.endsWith('/asset'))return response({operationId,assetUrl:'http://127.0.0.2:9083/assets/capability',expiresAt:Date.now()+60000});
  if(options.method==='POST'&&(path.endsWith('/polyglot-preview')||path.endsWith('/polyglot-assess')))throw Error('lost acknowledgement');
  if(path.includes('/polyglot-preview/'))return response(previewResult(previewStatus,true));
  if(path.includes('/polyglot-assess/'))return response({completed:false,status:grading,modelEvaluated:false});
  throw Error(path);
 });
 const props=await polyglotSetup(transport);await act(async()=>{root.render(<Harness {...props}/>);await settle();});
 await act(async()=>{await current.preview();current.markPreviewDelivered();});
 await act(async()=>expect(await current.runPolyglotPreview()).toBe(true));expect(current.polyglotPreview.status).toBe('pending');
 await act(async()=>{root.render(null);});await act(async()=>{root.render(<Harness {...props}/>);await settle();});
 expect(current.polyglotPreview.status).toBe('pending');await act(async()=>expect(await current.runPolyglotPreview()).toBe(false));
 await act(async()=>expect(await current.startNew()).toBe(false));
 previewStatus='executed';await act(async()=>expect(await current.recoverPolyglotPreview()).toBe(true));
 await act(async()=>expect(await current.assessPolyglot()).toBe(true));expect(current.polyglotAssessment.status).toBe('pending');
 await act(async()=>{root.render(null);});await act(async()=>{root.render(<Harness {...props}/>);await settle();});
 expect(current.polyglotAssessment.status).toBe('pending');await act(async()=>expect(await current.assessPolyglot()).toBe(false));
 expect(calls.filter(([p,o])=>o.method==='POST'&&p.endsWith('/polyglot-preview'))).toHaveLength(1);
 expect(calls.filter(([p,o])=>o.method==='POST'&&p.endsWith('/polyglot-assess'))).toHaveLength(1);
});
test('unknown saved preview errors remain latched and cannot authorize another preview or grading request',async()=>{
 const calls=[],transport=jest.fn(async(path,options)=>{calls.push([path,options]);
  if(path.endsWith('/polyglot-readiness'))return response({ready:true});
  if(path.endsWith('/operations/'+operationId))return response(originalUpload);
  if(path.includes('/polyglot-preview/'))throw Error('HTTP 503 unavailable');throw Error(path);
 });
 const props=await polyglotSetup(transport,true);await act(async()=>{root.render(<Harness {...props}/>);await settle();});
 expect(current.polyglotPreviewReference).not.toBeNull();expect(current.polyglotPreview).toBeNull();
 await act(async()=>{expect(await current.runPolyglotPreview()).toBe(false);expect(await current.assessPolyglot()).toBe(false);expect(await current.startNew()).toBe(false);});
 expect(calls.every(([,o])=>o.method==='GET')).toBe(true);
});
test('legacy preview decoder requires the exact six-key original-source contract and marker semantics',async()=>{
 const {decodeAvatarPolyglotPreview:decode,decodeAvatarPolyglotAssessment:grade}=await import('./useCustomerAvatarUploadLesson');
 expect(decode(previewResult('fixed_reencoded',true),{operationId},true)).toEqual(previewResult('fixed_reencoded',true));
 for(const patch of [{operationId:null},{uploadOperationId:requestId},{sourceSha256:null},{status:'complete'},{replayed:false},{extra:true}])expect(()=>decode({...previewResult('executed',true),...patch},{operationId},true)).toThrow();
 expect(()=>decode({...previewResult('pending',true),text:'fabricated final'},{operationId},true)).toThrow();
 expect(()=>decode({...previewResult('executed',true),text:null},{operationId},true)).toThrow();
 expect(grade({completed:false,status:'pending',modelEvaluated:false})).toEqual({completed:false,status:'pending',modelEvaluated:false});
 expect(()=>grade({completed:true,status:'pending',modelEvaluated:false})).toThrow();
});
