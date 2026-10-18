import{useCallback,useEffect,useRef,useState}from'react';
const BASE='/api/secureshop/agents/customer/avatar-upload/path-traversal';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const invalid=()=>{throw new Error('Avatar-traversal response unavailable');};
const safeDestination=value=>{if(typeof value!=='string'||new TextEncoder().encode(value).byteLength>4096)invalid();const match=/^avatars\/([^/\\\0\r\n]+)$/u.exec(value);if(!match||['.','..'].includes(match[1]))invalid();return value;};
async function json(response){if(!response?.ok||!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type')||''))invalid();return response.json();}
export function decodeAvatarTraversalSession(value){if(!exact(value,['id'])||!UUID.test(value.id))invalid();return value.id;}
export function decodeAvatarTraversalOperation(value,{run=false}={}){
 const completed=value?.status==='completed';
 const required=run?['operationId','uploadRequestId','status','text','sourceFilename','filename','byteCount','replayed',...(completed?['operationRelativePath','escapedAvatarSubdirectory']:[])]
  :['operationId','uploadRequestId','status','filename','byteCount'];
 const optional=run?[]:completed?['bodySha256','traversal','operationRelativePath','escapedAvatarSubdirectory']:['denialCode'];
 if(!exact(value,[...required,...optional])||!UUID.test(value.operationId||'')||!UUID.test(value.uploadRequestId||'')
  ||!['completed','denied'].includes(value.status)||typeof value.filename!=='string'||!value.filename
  ||!Number.isSafeInteger(value.byteCount)||value.byteCount<1||run&&(typeof value.sourceFilename!=='string'||!value.sourceFilename
   ||typeof value.text!=='string'||typeof value.replayed!=='boolean')
  ||completed&&(value.escapedAvatarSubdirectory!==true||safeDestination(value.operationRelativePath)!==value.operationRelativePath)
  ||!run&&completed&&(value.traversal!==true||!/^[a-f0-9]{64}$/.test(value.bodySha256||'')))invalid();
 return Object.freeze(value);
}
export function decodeAvatarTraversalAssessment(value){
 if(exact(value,['completed','status','modelEvaluated'])&&value.completed===false&&value.modelEvaluated===false
  &&['ineligible','unconfirmed'].includes(value.status))return Object.freeze(value);
 if(!exact(value,['completed','judgment','replayed'])||typeof value.completed!=='boolean'||typeof value.replayed!=='boolean'
  ||!exact(value.judgment,['verdict','evaluationId','canRetry'])||!UUID.test(value.judgment.evaluationId||'')
  ||!['pass','fail','inconclusive','unavailable'].includes(value.judgment.verdict)
  ||typeof value.judgment.canRetry!=='boolean'||value.completed&&value.judgment.verdict!=='pass')invalid();
 return Object.freeze({...value,judgment:Object.freeze({...value.judgment})});
}
export function useCustomerAvatarTraversalLesson({shopUserId,authorityKey,transport=globalThis.fetch,referenceStore,assessmentStore}){
 const[reference,setReference]=useState(null),[result,setResult]=useState(null),[assessmentReference,setAssessmentReference]=useState(null),
  [assessment,setAssessment]=useState(null),[status,setStatus]=useState('loading'),[error,setError]=useState(null),[busy,setBusy]=useState(false),
  [knownUnsent,setKnownUnsent]=useState(false),[assessmentKnownUnsent,setAssessmentKnownUnsent]=useState(false);
 const mounted=useRef(false),epoch=useRef(0),active=useRef(null),savedRef=useRef(null),assessmentRef=useRef(null);
 const current=useCallback((version,controller)=>mounted.current&&epoch.current===version&&!controller.signal.aborted,[]);
 const request=useCallback((...args)=>transport(...args),[transport]);
 const recoverSaved=useCallback(async(saved,controller,version)=>{
  const value=decodeAvatarTraversalOperation(await json(await request(`${BASE}/requests/${saved.requestId}`,{method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));
  if(!current(version,controller)||value.uploadRequestId!==saved.requestId||saved.operationId&&value.operationId!==saved.operationId)invalid();
  let acknowledged=saved;if(!saved.operationId){acknowledged=await referenceStore.acknowledgeOperation(saved,value.operationId,()=>current(version,controller));savedRef.current=acknowledged;setReference(acknowledged);}
  if(!current(version,controller))return false;setResult(value);setStatus(value.status);setKnownUnsent(false);return true;
 },[request,referenceStore,current]);
 const readAssessment=useCallback(async(saved,controller,version)=>{
  const value=decodeAvatarTraversalAssessment(await json(await request(`${BASE}/assessment/${saved.sessionId}/${saved.requestId}`,{method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));
  if(!current(version,controller))return false;if(value.status!=='unconfirmed')setAssessmentKnownUnsent(false);setAssessment(value);return true;
 },[request,current]);
 useEffect(()=>{mounted.current=true;const version=++epoch.current;active.current?.abort();active.current=null;savedRef.current=null;assessmentRef.current=null;
  setReference(null);setResult(null);setAssessmentReference(null);setAssessment(null);setError(null);setBusy(false);setKnownUnsent(false);setAssessmentKnownUnsent(false);
  if(!Number.isSafeInteger(shopUserId)||shopUserId<1||typeof transport!=='function'||!referenceStore||!assessmentStore){setStatus('error');setError('Avatar-traversal lesson unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  let saved,grade;try{saved=referenceStore.read(shopUserId);grade=saved?assessmentStore.read(saved):null;}catch{setStatus('error');setError('Saved avatar-traversal request unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  if(!saved){setStatus('ready');return()=>{mounted.current=false;++epoch.current;};}
  savedRef.current=saved;assessmentRef.current=grade;setReference(saved);setAssessmentReference(grade);setStatus('unconfirmed');
  const controller=new AbortController();active.current=controller;void recoverSaved(saved,controller,version).then(()=>grade&&readAssessment(grade,controller,version)).catch(()=>{if(current(version,controller)){setStatus('unconfirmed');setError('Check the saved avatar-traversal request.');}}).finally(()=>{if(active.current===controller)active.current=null;});
  return()=>{mounted.current=false;++epoch.current;active.current?.abort();active.current=null;};
 },[shopUserId,authorityKey,transport,referenceStore,assessmentStore,recoverSaved,readAssessment,current]);
 const run=useCallback(async(file,message,logicalFilename,isPublic)=>{
  if(active.current||savedRef.current||!mounted.current||!(file instanceof File)||file.size<1||file.size>20*1024*1024
   ||typeof message!=='string'||!message.trim()||new TextEncoder().encode(message).byteLength>8192
   ||typeof logicalFilename!=='string'||!logicalFilename.includes('....//')||typeof isPublic!=='boolean')return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  let locallyWritten=false,ownWritten=null,postStarted=false;
  try{const sessionId=decodeAvatarTraversalSession(await json(await request(`${BASE}/session`,{method:'POST',signal:controller.signal,headers:{accept:'application/json'}})));
   if(!current(version,controller))return false;const saved=await referenceStore.saveIntent({shopUserId,sessionId,requestId:crypto.randomUUID(),startedAt:Date.now()},()=>current(version,controller),value=>{locallyWritten=true;ownWritten=value;savedRef.current=value;setReference(value);setStatus('unconfirmed');});
   const form=new FormData();form.append('sessionId',saved.sessionId);form.append('requestId',saved.requestId);form.append('message',message);form.append('public',String(isPublic));form.append('logicalFilename',logicalFilename);form.append('file',file,file.name);
   try{postStarted=true;const value=decodeAvatarTraversalOperation(await json(await request(`${BASE}/run`,{method:'POST',signal:controller.signal,headers:{accept:'application/json'},body:form})),{run:true});
    if(value.uploadRequestId!==saved.requestId||value.sourceFilename!==file.name||value.filename!==logicalFilename)invalid();
    const acknowledged=await referenceStore.acknowledgeOperation(saved,value.operationId,()=>current(version,controller));if(!current(version,controller))return false;savedRef.current=acknowledged;setReference(acknowledged);setResult(value);setStatus(value.status);setKnownUnsent(false);return true;
   }catch{return await recoverSaved(saved,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=referenceStore.read(shopUserId);}catch{}if(retained){savedRef.current=retained;setReference(retained);setStatus('unconfirmed');const unsent=locallyWritten&&!postStarted&&ownWritten&&['version','shopUserId','sessionId','requestId','operationId','startedAt'].every(key=>retained[key]===ownWritten[key]);setKnownUnsent(unsent);setError(unsent?'Upload was not submitted. Discard the unsent request or check saved status.':'Upload outcome unresolved. Check the saved request.');}else{setStatus('error');setError('Avatar-traversal lesson unavailable.');}}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,request,referenceStore,recoverSaved,current]);
 const recover=useCallback(async()=>{const saved=savedRef.current;if(!saved||active.current)return false;const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await recoverSaved(saved,controller,version);}catch{if(current(version,controller))setError('Saved avatar-traversal result unavailable.');return false;}finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}},[recoverSaved,current]);
 const assess=useCallback(async()=>{const saved=savedRef.current;if(!saved?.operationId||assessmentRef.current||active.current||!['completed','denied'].includes(result?.status))return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  let own=null,postStarted=false;
  try{const ref=await assessmentStore.submit({shopUserId,sessionId:saved.sessionId,requestId:saved.requestId,startedAt:Date.now()},()=>current(version,controller),value=>{own=value;assessmentRef.current=value;setAssessmentReference(value);});
   try{postStarted=true;const value=decodeAvatarTraversalAssessment(await json(await request(`${BASE}/assess`,{method:'POST',signal:controller.signal,headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({sessionId:saved.sessionId,requestId:saved.requestId})})));if(!current(version,controller))return false;setAssessmentKnownUnsent(false);setAssessment(value);return true;}
   catch{return await readAssessment(ref,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=assessmentStore.read(saved);}catch{}if(retained){assessmentRef.current=retained;setAssessmentReference(retained);setAssessmentKnownUnsent(Boolean(own&&!postStarted&&['version','shopUserId','sessionId','requestId','startedAt'].every(key=>retained[key]===own[key])));}setError('Assessment outcome unresolved. Check the saved assessment.');}return false;}finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,result,assessmentStore,request,readAssessment,current]);
 const recoverAssessment=useCallback(async()=>{const saved=assessmentRef.current;if(!saved||active.current)return false;const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await readAssessment(saved,controller,version);}catch{if(current(version,controller))setError('Saved avatar-traversal assessment unavailable.');return false;}finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}},[readAssessment,current]);
 const discardUnsent=useCallback(async()=>{const saved=savedRef.current;if(!saved||!knownUnsent||active.current)return false;setBusy(true);setError(null);try{await referenceStore.clear(saved,()=>mounted.current&&savedRef.current===saved);savedRef.current=null;setReference(null);setResult(null);setStatus('ready');setKnownUnsent(false);return true;}catch{if(mounted.current)setError('Unsent avatar-traversal request could not be cleared.');return false;}finally{if(mounted.current)setBusy(false);}},[knownUnsent,referenceStore]);
 const discardUnsentAssessment=useCallback(async()=>{const saved=assessmentRef.current;if(!saved||!assessmentKnownUnsent||active.current)return false;setBusy(true);setError(null);try{await assessmentStore.clear(saved,()=>mounted.current&&assessmentRef.current===saved);assessmentRef.current=null;setAssessmentReference(null);setAssessment(null);setAssessmentKnownUnsent(false);return true;}catch{if(mounted.current)setError('Unsent avatar-traversal assessment could not be cleared.');return false;}finally{if(mounted.current)setBusy(false);}},[assessmentKnownUnsent,assessmentStore]);
 const startNew=useCallback(async()=>{const saved=savedRef.current;if(!saved||active.current||!['completed','denied'].includes(result?.status)
  ||assessmentRef.current&&!(assessment?.judgment||assessment?.status==='ineligible'))return false;setBusy(true);setError(null);
  try{if(assessmentRef.current){await assessmentStore.clear(assessmentRef.current,()=>mounted.current&&savedRef.current===saved);assessmentRef.current=null;setAssessmentReference(null);setAssessment(null);setAssessmentKnownUnsent(false);}await referenceStore.clear(saved,()=>mounted.current&&savedRef.current===saved);savedRef.current=null;setReference(null);setResult(null);setStatus('ready');setKnownUnsent(false);return true;}
  catch{if(mounted.current)setError('Saved avatar-traversal request could not be retired.');return false;}finally{if(mounted.current)setBusy(false);}},[result,assessment,referenceStore,assessmentStore]);
 return{reference,result,assessmentReference,assessment,status,error,busy,knownUnsent,assessmentKnownUnsent,run,recover,assess,recoverAssessment,discardUnsent,discardUnsentAssessment,startNew};
}
