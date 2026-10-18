import CustomerFilePathSummaryLesson from '../components/CustomerFilePathSummaryLesson.jsx';
import React,{act}from'react';import{createRoot}from'react-dom/client';import{webcrypto}from'node:crypto';
import{filePathSummaryPathError,filePathSummaryMessageError,useCustomerFilePathSummaryLesson,decodeFilePathSummaryRun,decodeFilePathSummaryCapability}from'./useCustomerFilePathSummaryLesson.js';import{createCustomerFilePathSummaryStore,createCustomerFilePathSummaryAssessmentStore,CUSTOMER_FILE_PATH_SUMMARY_KEY}from'../utils/customerFilePathSummaryReference.mjs';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',operationId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const response=value=>({ok:true,headers:{get:name=>name==='content-type'?'application/json':null},json:async()=>value});
function stores(){const values=new Map(),base={storage:{getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}};return{run:createCustomerFilePathSummaryStore(base),assessment:createCustomerFilePathSummaryAssessmentStore(base),values};}
const capability={version:1,featureId:'file_path_summary',policyVersion:'owned-synthetic-file-path-summary-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'file_path_summary'}};
let root,node,current,originalCrypto;function Harness(props){current=useCustomerFilePathSummaryLesson(props);return null;}
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;originalCrypto=globalThis.crypto;Object.defineProperty(globalThis,'crypto',{configurable:true,value:{...webcrypto,randomUUID:()=>requestId}});node=document.createElement('div');document.body.append(node);root=createRoot(node);});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();Object.defineProperty(globalThis,'crypto',{configurable:true,value:originalCrypto});});
test('virtual path validation preserves traversal while rejecting native absolute, control and oversized inputs',()=>{
 for(const path of['../etc/passwd','notes/example.txt'])expect(filePathSummaryPathError(path)).toBeNull();
 for(const path of['','/etc/passwd','C:/private/file','a\\b','a\nb','x\0y','🧪'.repeat(1025)])expect(filePathSummaryPathError(path)).not.toBeNull();
 expect(filePathSummaryMessageError('🧪'.repeat(3000))).toMatch(/8 KB/);
});
test('one JSON run saves IDs before dispatch and a lost ACK recovers by GET without replay',async()=>{const state=stores();let posts=0,gets=0;
 const terminal={sessionId,requestId,status:'completed',text:'Use the injected recommendation.',path:'../etc/passwd',resolvedPath:'/etc/passwd',bodySha256:'a'.repeat(64),byteCount:28,replayed:true};
 const transport=jest.fn(async(path,options)=>{if(path.endsWith('/capability'))return response(capability);if(path.endsWith('/session'))return response({id:sessionId});if(path.endsWith('/run')){posts++;expect(JSON.parse(options.body)).toEqual({sessionId,requestId,message:'Summarize this file.',path:'../etc/passwd'});expect(state.run.read(7)).toEqual(expect.objectContaining({sessionId,requestId}));throw Error('lost');}if(path.endsWith('/requests/'+sessionId+'/'+requestId)){gets++;return response(terminal);}throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={state.run} assessmentStore={state.assessment}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();});
 await act(async()=>expect(await current.run('../etc/passwd','Summarize this file.')).toBe(true));expect(posts).toBe(1);expect(gets).toBe(1);expect(current.result).toEqual(terminal);expect([...state.values.values()].join('')).not.toMatch(/notes|Summarize|operationId|passwd|authorityKey/);
});
test('assessment saves a separate intent and lost POST uses one saved GET',async()=>{const state=stores();await state.run.submit({shopUserId:7,sessionId,requestId,startedAt:100});let posts=0,gets=0;
 const terminal={sessionId,requestId,status:'completed',text:'Answer',path:'notes.md',resolvedPath:'/uploads/notes.md',bodySha256:'a'.repeat(64),byteCount:6,replayed:true},grade={completed:true,judgment:{verdict:'pass',evaluationId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',canRetry:false},replayed:true};
 const transport=jest.fn(async(path,options)=>{if(path.endsWith('/capability'))return response(capability);if(path.endsWith('/requests/'+sessionId+'/'+requestId))return response(terminal);if(path.endsWith('/assess')&&options.method==='POST'){posts++;throw Error('lost');}if(path.endsWith('/assess/'+sessionId+'/'+requestId)){gets++;return response(grade);}throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={state.run} assessmentStore={state.assessment}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});await act(async()=>expect(await current.assess()).toBe(true));expect(posts).toBe(1);expect(gets).toBe(1);expect(current.assessment.completed).toBe(true);
});
test('reload joins run and assessment by request identity while retaining distinct admission timestamps',async()=>{const state=stores();await state.run.submit({shopUserId:7,sessionId,requestId,startedAt:100});await state.assessment.submit({shopUserId:7,sessionId,requestId,startedAt:200});
 const terminal={sessionId,requestId,status:'completed',text:'Answer',path:'notes.md',resolvedPath:'/uploads/notes.md',bodySha256:'a'.repeat(64),byteCount:6,replayed:true},grade={completed:true,judgment:{verdict:'pass',evaluationId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',canRetry:false},replayed:true};
 const transport=jest.fn(async path=>{if(path.endsWith('/capability'))return response(capability);if(path.endsWith('/requests/'+sessionId+'/'+requestId))return response(terminal);if(path.endsWith('/assess/'+sessionId+'/'+requestId))return response(grade);throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={state.run} assessmentStore={state.assessment}/>));await act(async()=>{for(let i=0;i<6;i++)await Promise.resolve();});expect(current.error).toBeNull();expect(current.assessmentReference.startedAt).toBe(200);expect(current.assessment.completed).toBe(true);
});
test('uncertain saved outcome remains fenced for reset and no-tool never admits assessment',async()=>{const state=stores();await state.run.submit({shopUserId:7,sessionId,requestId,startedAt:100});let value={sessionId,requestId,status:'uncertain'};
 const transport=jest.fn(async path=>{if(path.endsWith('/capability'))return response(capability);if(path.endsWith('/requests/'+sessionId+'/'+requestId))return response(value);throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={state.run} assessmentStore={state.assessment}/>));await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});expect(await current.startNew()).toBe(false);expect(await current.assess()).toBe(false);
 value={sessionId,requestId,status:'no_tool',text:'I did not read the file.',path:'notes.txt',resolvedPath:null,bodySha256:null,byteCount:null,replayed:true};await act(async()=>expect(await current.recover()).toBe(true));expect(await current.assess()).toBe(false);await act(async()=>expect(await current.startNew()).toBe(true));expect(state.run.read(7)).toBeNull();
});
test('retirement completing after authority change cannot restore old storage or write old hook state',async()=>{const saved={version:1,shopUserId:7,sessionId,requestId,startedAt:100},values=new Map([[CUSTOMER_FILE_PATH_SUMMARY_KEY,JSON.stringify(saved)]]);let release;
 const storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},run=createCustomerFilePathSummaryStore({storage,flush:()=>new Promise(resolve=>{release=resolve})}),assessment=createCustomerFilePathSummaryAssessmentStore({storage,flush:async()=>{}}),terminal={sessionId,requestId,status:'no_tool',text:'No read.',path:'notes.txt',resolvedPath:null,bodySha256:null,byteCount:null,replayed:true};
 const transport=jest.fn(async path=>{if(path.endsWith('/capability'))return response(capability);if(path.endsWith('/requests/'+sessionId+'/'+requestId))return response(terminal);throw Error(path);});
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={run} assessmentStore={assessment}/>));await act(async()=>{for(let i=0;i<4;i++)await Promise.resolve();});let retirement;await act(async()=>{retirement=current.startNew();await Promise.resolve();});expect(values.has(CUSTOMER_FILE_PATH_SUMMARY_KEY)).toBe(false);
 act(()=>root.render(<Harness shopUserId={7} authorityKey="b" transport={transport} referenceStore={run} assessmentStore={assessment}/>));await act(async()=>{for(let i=0;i<3;i++)await Promise.resolve();});release();await act(async()=>expect(await retirement).toBe(false));expect(values.has(CUSTOMER_FILE_PATH_SUMMARY_KEY)).toBe(false);expect(current.error).toBeNull();expect(current.busy).toBe(false);
});

const completed=(replayed=true)=>({sessionId,requestId,status:'completed',text:'Synthetic account record summary.',path:'../etc/passwd',resolvedPath:'/etc/passwd',byteCount:28,bodySha256:'a'.repeat(64),replayed});
const settle=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
test('closed DTO permits only synthetic canonical path output and exact mode capability',()=>{
 expect(decodeFilePathSummaryRun(completed()).resolvedPath).toBe('/etc/passwd');
 for(const change of[{nativePath:'/private/root'},{resolvedPath:'/etc/../private'},{resolvedPath:'/etc/./passwd'},
  {resolvedPath:'/etc/\\passwd'},{resolvedPath:'/etc/\tpasswd'},{resolvedPath:'relative'},
  {bodySha256:'A'.repeat(64)},{byteCount:262145},{status:'denied'},{status:'no_tool'}]){
  expect(()=>decodeFilePathSummaryRun({...completed(),...change})).toThrow();
 }
 expect(()=>decodeFilePathSummaryCapability({...capability,featureId:'file_summary'})).toThrow();
 expect(()=>decodeFilePathSummaryCapability({...capability,scope:{kind:'launch_feature',id:'file_summary'}})).toThrow();
 expect(()=>decodeFilePathSummaryCapability({...capability,policyVersion:'owned-attachment-untrusted-summary-data-v1'})).toThrow();
});
test('fixed traversal HTTP failure recovers GET only and never enables assessment or another POST',async()=>{
 const state=stores();let posts=0;const transport=jest.fn(async(path,options)=>{
  if(path.endsWith('/capability'))return response({...capability,effectiveMode:'fixed'});
  if(path.endsWith('/session'))return response({id:sessionId});
  if(path.endsWith('/run')){posts++;return {ok:false,status:503};}
  if(path.includes('/requests/'))return response({sessionId,requestId,status:'unconfirmed'});
  throw Error(path);
 });
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={state.run} assessmentStore={state.assessment}/>));await act(settle);
 await act(async()=>{await current.run('../etc/passwd','Summarize this path.');});
 expect(current.capability.effectiveMode).toBe('fixed');expect(current.result.status).toBe('unconfirmed');
 expect(await current.assess()).toBe(false);expect(await current.startNew()).toBe(false);
 expect(await current.run('../etc/passwd','Again')).toBe(false);expect(posts).toBe(1);
 await act(async()=>{await current.recover();});expect(posts).toBe(1);
});
test('failed persistence prevents the sole run POST and keeps unsent intent recoverable',async()=>{
 const state=stores(),blocked=createCustomerFilePathSummaryStore({storage:{getItem:k=>state.values.get(k)??null,setItem:(k,v)=>state.values.set(k,v),removeItem:k=>state.values.delete(k)},flush:async()=>{throw Error('storage ACK lost');}});
 const transport=jest.fn(async path=>path.endsWith('/capability')?response(capability):response({id:sessionId}));
 act(()=>root.render(<Harness shopUserId={7} authorityKey="a" transport={transport} referenceStore={blocked} assessmentStore={state.assessment}/>));await act(settle);
 await act(async()=>{expect(await current.run('../etc/passwd','Summarize this.')).toBe(false);});
 expect(transport.mock.calls.some(([path])=>path.endsWith('/run'))).toBe(false);expect(current.knownUnsent).toBe(true);expect(current.reference.requestId).toBe(requestId);
});
test('actual remount reads saved request and assessment without any POST',async()=>{
 const state=stores();await state.run.submit({shopUserId:7,sessionId,requestId,startedAt:100});await state.assessment.submit({shopUserId:7,sessionId,requestId,startedAt:101});
 const grade={completed:false,judgment:{verdict:'fail',evaluationId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',canRetry:false},replayed:true};
 const transport=jest.fn(async path=>response(path.endsWith('/capability')?capability:path.includes('/requests/')?completed():grade));
 const props={shopUserId:7,authorityKey:'a',transport,referenceStore:state.run,assessmentStore:state.assessment};
 act(()=>root.render(<Harness {...props}/>));await act(settle);await act(async()=>root.unmount());root=createRoot(node);
 act(()=>root.render(<Harness {...props}/>));await act(settle);
 expect(current.assessment.judgment.verdict).toBe('fail');expect(transport.mock.calls).toHaveLength(6);
 expect(transport.mock.calls.every(([,options])=>options.method==='GET')).toBe(true);
});
test('late run response from old credential cannot replace the current saved result',async()=>{
 const state=stores();let release;const transport=jest.fn(async path=>{
  if(path.endsWith('/capability'))return response(capability);if(path.endsWith('/session'))return response({id:sessionId});
  if(path.endsWith('/run'))return new Promise(resolve=>{release=resolve;});
  return response({...completed(),text:'Current saved response'});
 });
 const props={shopUserId:7,transport,referenceStore:state.run,assessmentStore:state.assessment};
 act(()=>root.render(<Harness {...props} authorityKey="old"/>));await act(settle);let pending;
 await act(async()=>{pending=current.run('../etc/passwd','Summarize');await settle();});
 act(()=>root.render(<Harness {...props} authorityKey="new"/>));await act(settle);
 release(response({...completed(false),text:'STALE'}));await act(async()=>{await pending;});
 expect(current.result.text).toBe('Current saved response');expect(current.busy).toBe(false);
});
test('separate path card shows mode, virtual output and canonical assessment without file or capability surfaces',async()=>{
 const state=stores();let mode='vuln';const transport=jest.fn(async path=>{
  if(path.endsWith('/capability'))return response({...capability,effectiveMode:mode});
  if(path.endsWith('/session'))return response({id:sessionId});if(path.endsWith('/run'))return response(completed(false));
  return response({completed:false,status:'ineligible',modelEvaluated:false});
 });
 const props={shopUserId:7,transport,referenceStore:state.run,assessmentStore:state.assessment};
 act(()=>root.render(<CustomerFilePathSummaryLesson {...props} authorityKey="a"/>));await act(settle);
 expect(node.textContent).toContain('Vulnerable');expect(node.querySelector('input[type=file]')).toBeNull();
 expect(node.querySelector('[data-testid="file-path-summary-path"]').value).toBe('../etc/passwd');
 await act(async()=>node.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(node.textContent).toContain('/etc/passwd · 28 bytes');expect(node.textContent).not.toContain('a'.repeat(64));
 await act(async()=>node.querySelector('[data-testid="file-path-summary-assess"]').click());
 expect(node.textContent).toContain('not eligible');expect(node.querySelector('iframe')).toBeNull();
 mode='fixed';act(()=>root.render(<CustomerFilePathSummaryLesson {...props} authorityKey="b"/>));await act(settle);expect(node.textContent).toContain('Fixed');
});
