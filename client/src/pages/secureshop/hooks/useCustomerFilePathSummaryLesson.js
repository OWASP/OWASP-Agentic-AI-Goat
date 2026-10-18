import{useCallback,useEffect,useRef,useState}from'react';
const BASE='/api/secureshop/agents/customer/file-path-summary';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const bounded=(value,bytes)=>typeof value==='string'&&value.isWellFormed()&&!value.includes('\0')
 &&new TextEncoder().encode(value).byteLength<=bytes;
export function filePathSummaryPathError(value){
 if(typeof value!=='string'||!value.trim())return'Enter a virtual path.';
 if(!bounded(value,4096)||value.startsWith('/')||/^[a-zA-Z]:/.test(value)||/[\\\r\n]/.test(value))return'The virtual path must be at most 4 KB and use POSIX separators.';
 return null;
}
export function filePathSummaryMessageError(value){
 if(typeof value!=='string'||!value.trim())return'Enter a request for the file-path-summary agent.';
 if(!bounded(value,8192))return'The request must be at most 8 KB.';
 return null;
}
const invalid=()=>{throw new Error('Path-summary response unavailable');};
async function json(response){if(!response?.ok||typeof response.json!=='function'
 ||!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type')||''))invalid();return response.json();}
export function decodeFilePathSummaryCapability(value){
 if(!exact(value,['version','featureId','policyVersion','effectiveMode','scope'])||value.version!==1
  ||value.featureId!=='file_path_summary'||value.policyVersion!=='owned-synthetic-file-path-summary-v1'
  ||!['vuln','fixed'].includes(value.effectiveMode)||!exact(value.scope,['kind','id'])
  ||value.scope.kind!=='launch_feature'||value.scope.id!=='file_path_summary')invalid();
 return Object.freeze({...value,scope:Object.freeze({...value.scope})});
}
export function decodeFilePathSummarySession(value){if(!exact(value,['id'])||!UUID.test(value.id))invalid();return value.id;}
export function decodeFilePathSummaryRun(value){
 if(exact(value,['sessionId','requestId','status'])&&UUID.test(value.sessionId||'')&&UUID.test(value.requestId||'')
  &&['uncertain','unconfirmed'].includes(value.status))return Object.freeze({...value});
 if(!exact(value,['sessionId','requestId','status','text','path','resolvedPath','byteCount','bodySha256','replayed'])
  ||![value.sessionId,value.requestId].every(id=>typeof id==='string'&&UUID.test(id))
  ||!['completed','no_tool'].includes(value.status)||!bounded(value.text,16384)||filePathSummaryPathError(value.path)
  ||typeof value.replayed!=='boolean')invalid();
 if(value.status==='no_tool'){
  if(value.resolvedPath!==null||value.byteCount!==null||value.bodySha256!==null)invalid();
 }else if(!bounded(value.resolvedPath,4096)||/[\x00-\x1f\x7f]/.test(value.resolvedPath)||!/^\/(?:[^/\\\0\r\n]+\/)*[^/\\\0\r\n]+$/.test(value.resolvedPath)
  ||value.resolvedPath.split('/').some(part=>part==='.'||part==='..')
  ||!Number.isSafeInteger(value.byteCount)||value.byteCount<1||value.byteCount>262144
  ||typeof value.bodySha256!=='string'||! /^[a-f0-9]{64}$/.test(value.bodySha256))invalid();
 return Object.freeze({...value});
}
export function decodeFilePathSummaryAssessment(value){
 if(value?.status==='unavailable'){if(!exact(value,['completed','status','modelEvaluated','reason'])||value.completed!==false
   ||value.modelEvaluated!==false||value.reason!=='evidence_size_limit')invalid();return Object.freeze({...value});}
 if(value?.status){if(!exact(value,['completed','status','modelEvaluated'])||value.completed!==false
   ||!['ineligible','unconfirmed'].includes(value.status)||value.modelEvaluated!==false)invalid();return Object.freeze({...value});}
 if(!exact(value,['completed','judgment','replayed'])||typeof value.completed!=='boolean'||typeof value.replayed!=='boolean'
  ||!exact(value.judgment,['verdict','evaluationId','canRetry'])
  ||!['pass','fail','inconclusive','unavailable'].includes(value.judgment.verdict)||!UUID.test(value.judgment.evaluationId)
  ||typeof value.judgment.canRetry!=='boolean'||value.completed&&value.judgment.verdict!=='pass')invalid();
 return Object.freeze({...value,judgment:Object.freeze({...value.judgment})});
}
const same=(a,b)=>!!a&&!!b&&['version','shopUserId','sessionId','requestId','startedAt'].every(key=>a[key]===b[key]);
const sameRequest=(a,b)=>!!a&&!!b&&['version','shopUserId','sessionId','requestId'].every(key=>a[key]===b[key]);
export function useCustomerFilePathSummaryLesson({shopUserId,authorityKey,transport=globalThis.fetch,referenceStore,assessmentStore}={}){
 const[capability,setCapability]=useState(null),[reference,setReference]=useState(null),[result,setResult]=useState(null);
 const[assessmentReference,setAssessmentReference]=useState(null),[assessment,setAssessment]=useState(null);
 const[status,setStatus]=useState('loading'),[error,setError]=useState(null),[busy,setBusy]=useState(false);
 const[knownUnsent,setKnownUnsent]=useState(false),[assessmentKnownUnsent,setAssessmentKnownUnsent]=useState(false);
 const[admissionLatched,setAdmissionLatched]=useState(false);
 const epoch=useRef(0),active=useRef(null),mounted=useRef(false),savedRef=useRef(null),assessmentRef=useRef(null);
 const current=useCallback((version,controller)=>mounted.current&&epoch.current===version&&active.current===controller&&!controller.signal.aborted,[]);
 const request=useCallback((path,options)=>transport(path,options),[transport]);
 const readRun=useCallback(async(saved,controller,version)=>{const value=decodeFilePathSummaryRun(await json(await request(`${BASE}/requests/${saved.sessionId}/${saved.requestId}`,{method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));
  if(value.sessionId!==saved.sessionId||value.requestId!==saved.requestId
   ||!['uncertain','unconfirmed'].includes(value.status)&&value.replayed!==true)invalid();if(!current(version,controller))return false;
  setResult(value);setStatus(['completed','no_tool'].includes(value.status)?'terminal':'unconfirmed');return true;},[request,current]);
 const readAssessment=useCallback(async(saved,controller,version)=>{const value=decodeFilePathSummaryAssessment(await json(await request(`${BASE}/assess/${saved.sessionId}/${saved.requestId}`,{method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));
  if(value.judgment&&value.replayed!==true)invalid();if(!current(version,controller))return false;if(value.status!=='unconfirmed')setAssessmentKnownUnsent(false);setAssessment(value);return true;},[request,current]);
 useEffect(()=>{
  mounted.current=true;const version=++epoch.current;active.current?.abort();active.current=null;savedRef.current=null;assessmentRef.current=null;
  setCapability(null);setReference(null);setResult(null);setAssessmentReference(null);setAssessment(null);setStatus('loading');setError(null);setBusy(false);setKnownUnsent(false);setAssessmentKnownUnsent(false);setAdmissionLatched(false);
  if(!Number.isSafeInteger(shopUserId)||shopUserId<1||typeof transport!=='function'||!referenceStore||!assessmentStore){setStatus('error');setError('Path-summary lesson unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  let saved,grade;try{saved=referenceStore.read(shopUserId);grade=assessmentStore.read(shopUserId);}catch{setStatus('error');setAdmissionLatched(true);setError('Saved file-path-summary request unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  if(grade&&(!saved||!sameRequest(saved,grade))){setStatus('error');setAdmissionLatched(true);setError('Saved file-path-summary assessment does not match the request.');return()=>{mounted.current=false;++epoch.current;};}
  savedRef.current=saved;assessmentRef.current=grade;setReference(saved);setAssessmentReference(grade);if(saved){setStatus('unconfirmed');setAdmissionLatched(true);}
  const controller=new AbortController();active.current=controller;
  void (async()=>{const mode=decodeFilePathSummaryCapability(await json(await request(BASE+'/capability',{method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));if(!current(version,controller))return;setCapability(mode);
   if(!saved){setStatus('ready');return;}if(!await readRun(saved,controller,version))return;if(grade)await readAssessment(grade,controller,version);
  })().catch(()=>{if(current(version,controller)){setStatus(saved?'unconfirmed':'error');setError(saved?'Check the saved file-path-summary request.':'Path-summary lesson unavailable.');}}).finally(()=>{if(active.current===controller)active.current=null;});
  return()=>{mounted.current=false;++epoch.current;active.current?.abort();active.current=null;};
 },[shopUserId,authorityKey,transport,referenceStore,assessmentStore,request,readRun,readAssessment,current]);
 const run=useCallback(async(path,message)=>{
  if(active.current||savedRef.current||admissionLatched||status!=='ready'||!capability||!mounted.current
   ||filePathSummaryPathError(path)||filePathSummaryMessageError(message))return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);let own=null,postStarted=false;
  try{const sessionId=decodeFilePathSummarySession(await json(await request(BASE+'/session',{method:'POST',signal:controller.signal,headers:{accept:'application/json','content-type':'application/json'},body:'{}'})));
   if(!current(version,controller))return false;const requestId=crypto.randomUUID();if(!UUID.test(requestId))invalid();
   const saved=await referenceStore.submit({shopUserId,sessionId,requestId,startedAt:Date.now()},()=>current(version,controller),value=>{own=value;savedRef.current=value;setReference(value);setAdmissionLatched(true);});
   if(!current(version,controller))return false;postStarted=true;
   try{const value=decodeFilePathSummaryRun(await json(await request(BASE+'/run',{method:'POST',signal:controller.signal,headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({sessionId,requestId,message,path})})));if(value.sessionId!==sessionId||value.requestId!==requestId)invalid();if(!current(version,controller))return false;setResult(value);setStatus(['completed','no_tool'].includes(value.status)?'terminal':'unconfirmed');return true;}
   catch{return await readRun(saved,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=referenceStore.read(shopUserId);}catch{}if(retained){savedRef.current=retained;setReference(retained);setAdmissionLatched(true);setKnownUnsent(Boolean(own&&!postStarted&&same(own,retained)));setStatus('unconfirmed');setError('Path-summary outcome unresolved. Check the saved request.');}else setError('Path-summary request was not admitted.');}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,status,capability,admissionLatched,referenceStore,request,readRun,current]);
 const recover=useCallback(async()=>{const saved=savedRef.current;if(!saved||active.current||!mounted.current)return false;const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await readRun(saved,controller,version);}catch{if(current(version,controller))setError('Saved file-path-summary request unavailable.');return false;}finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}},[readRun,current]);
 const assess=useCallback(async()=>{const saved=savedRef.current;if(!saved||result?.status!=='completed'||assessmentRef.current||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);let own=null,postStarted=false;
  try{const ref=await assessmentStore.submit({shopUserId,sessionId:saved.sessionId,requestId:saved.requestId,startedAt:Date.now()},()=>current(version,controller),value=>{own=value;assessmentRef.current=value;setAssessmentReference(value);});if(!current(version,controller))return false;postStarted=true;
   try{const value=decodeFilePathSummaryAssessment(await json(await request(BASE+'/assess',{method:'POST',signal:controller.signal,headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({sessionId:saved.sessionId,requestId:saved.requestId})})));if(!current(version,controller))return false;setAssessment(value);return true;}
   catch{return await readAssessment(ref,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=assessmentStore.read(shopUserId);}catch{}if(retained){assessmentRef.current=retained;setAssessmentReference(retained);setAssessmentKnownUnsent(Boolean(own&&!postStarted&&same(own,retained)));setError('Path-summary assessment unresolved. Check the saved assessment.');}else setError('Path-summary assessment was not admitted.');}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,result,assessmentStore,request,readAssessment,current]);
 const recoverAssessment=useCallback(async()=>{const saved=assessmentRef.current;if(!saved||active.current||!mounted.current)return false;const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await readAssessment(saved,controller,version);}catch{if(current(version,controller))setError('Saved file-path-summary assessment unavailable.');return false;}finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}},[readAssessment,current]);
 const discard=useCallback(async(kind)=>{const assessmentIntent=kind==='assessment',saved=assessmentIntent?assessmentRef.current:savedRef.current,version=epoch.current;
  if(!saved||active.current||!mounted.current||!(assessmentIntent?assessmentKnownUnsent:knownUnsent))return false;setBusy(true);setError(null);
  const fresh=()=>mounted.current&&epoch.current===version&&(assessmentIntent?assessmentRef.current:savedRef.current)===saved;
  try{const store=assessmentIntent?assessmentStore:referenceStore;await store.clear(saved,fresh);if(!fresh())return false;
   if(assessmentIntent){assessmentRef.current=null;setAssessmentReference(null);setAssessment(null);setAssessmentKnownUnsent(false);}else{savedRef.current=null;setReference(null);setResult(null);setKnownUnsent(false);setAdmissionLatched(false);setStatus('ready');}return true;
  }catch{if(fresh())setError('Unsent file-path-summary request could not be cleared.');return false;}finally{if(mounted.current&&epoch.current===version)setBusy(false);}
 },[knownUnsent,assessmentKnownUnsent,referenceStore,assessmentStore]);
 const startNew=useCallback(async()=>{const saved=savedRef.current,grade=assessmentRef.current,version=epoch.current;const terminalAssessment=!grade||assessment?.judgment||['ineligible','unavailable'].includes(assessment?.status);
  if(!saved||active.current||!mounted.current||!['completed','no_tool'].includes(result?.status)||!terminalAssessment)return false;setBusy(true);setError(null);
  const currentRun=()=>mounted.current&&epoch.current===version&&savedRef.current===saved;
  try{if(grade){await assessmentStore.clear(grade,()=>currentRun()&&assessmentRef.current===grade);if(!currentRun()||assessmentRef.current!==grade)return false;assessmentRef.current=null;setAssessmentReference(null);setAssessment(null);setAssessmentKnownUnsent(false);}
   await referenceStore.clear(saved,currentRun);if(!currentRun())return false;savedRef.current=null;setReference(null);setResult(null);setKnownUnsent(false);setAdmissionLatched(false);setStatus('ready');return true;
  }catch{if(currentRun())setError('Saved file-path-summary request could not be retired.');return false;}finally{if(mounted.current&&epoch.current===version)setBusy(false);}
 },[result,assessment,referenceStore,assessmentStore]);
 return{capability,reference,result,assessmentReference,assessment,status,error,busy,knownUnsent,assessmentKnownUnsent,admissionLatched,run,recover,assess,recoverAssessment,
  discardUnsent:useCallback(()=>discard('run'),[discard]),discardUnsentAssessment:useCallback(()=>discard('assessment'),[discard]),startNew};
}
