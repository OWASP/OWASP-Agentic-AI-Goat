import{useCallback,useEffect,useRef,useState}from'react';
const BASE='/api/secureshop/agents/customer/avatar-upload';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const POLYGLOT_TERMINAL=['executed','image_only','fixed_reencoded','invalid_image','failed'];
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const sameReference=(a,b)=>!!a&&!!b&&['version','shopUserId','sessionId','requestId','operationId','startedAt'].every(key=>a[key]===b[key]);
const bounded=(value,bytes)=>typeof value==='string'&&value.isWellFormed()&&!value.includes('\0')
 &&new TextEncoder().encode(value).byteLength<=bytes;
const invalid=()=>{throw new Error('Avatar-upload response unavailable');};
async function json(response){
 if(!response?.ok||typeof response.json!=='function'
  ||!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type')||''))invalid();
 return response.json();
}
export function decodeAvatarUploadSession(value){
 if(!exact(value,['id'])||!UUID.test(value.id))invalid();return value.id;
}
export function decodeAvatarUploadOperation(value,{run=false}={}){
 const base=['operationId','uploadRequestId','status','filename','byteCount'];
 const runKeys=[...base,'text','replayed'];
 const optional=[];
 if(Object.hasOwn(value||{},'bodySha256'))optional.push('bodySha256');
 if(Object.hasOwn(value||{},'denialCode'))optional.push('denialCode');
 if(Object.hasOwn(value||{},'assetUrl'))optional.push('assetUrl');
 if(Object.hasOwn(value||{},'expiresAt'))optional.push('expiresAt');
 if(!exact(value,[...(run?runKeys:base),...optional])||!UUID.test(value.operationId)
  ||!UUID.test(value.uploadRequestId)||!['completed','denied','unresolved','uncertain'].includes(value.status)
  ||run&&!['completed','denied'].includes(value.status)||!bounded(value.filename,4096)||!value.filename
  ||!Number.isSafeInteger(value.byteCount)||value.byteCount<1||value.byteCount>20*1024*1024)invalid();
 if(run&&(!bounded(value.text,8192)||typeof value.replayed!=='boolean'))invalid();
 if('bodySha256'in value&&(!SHA.test(value.bodySha256)||value.status!=='completed'))invalid();
 if('denialCode'in value&&(!bounded(value.denialCode,256)||!value.denialCode||value.status!=='denied'))invalid();
 if(('assetUrl'in value)!==('expiresAt'in value))invalid();
 if('assetUrl'in value){let url;try{url=new URL(value.assetUrl);}catch{invalid();}
  if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.hash
   ||!Number.isSafeInteger(value.expiresAt)||value.expiresAt<1)invalid();}
 return Object.freeze({operationId:value.operationId,uploadRequestId:value.uploadRequestId,status:value.status,
  filename:value.filename,byteCount:value.byteCount,...(run?{text:value.text,replayed:value.replayed}:{})});
}
export function decodeAvatarUploadAssessment(value){
 if(value?.status){if(!exact(value,['completed','status','modelEvaluated'])||value.completed!==false
  ||!['ineligible','unconfirmed'].includes(value.status)||value.modelEvaluated!==false)invalid();return Object.freeze({...value});}
 if(!exact(value,['completed','judgment','replayed'])||typeof value.completed!=='boolean'||typeof value.replayed!=='boolean'
  ||!exact(value.judgment,['verdict','evaluationId','canRetry'])
  ||!['pass','fail','inconclusive','unavailable'].includes(value.judgment.verdict)||!UUID.test(value.judgment.evaluationId)
  ||typeof value.judgment.canRetry!=='boolean'||value.completed&&value.judgment.verdict!=='pass')invalid();
 return Object.freeze({...value,judgment:Object.freeze({...value.judgment})});
}
export function decodeAvatarPolyglotPreview(value,source,replayed){
 if(!exact(value,['operationId','uploadOperationId','status','sourceSha256','text','replayed'])
  ||!UUID.test(value.operationId||'')||value.uploadOperationId!==source?.operationId
  ||!UUID.test(value.uploadOperationId||'')||!SHA.test(value.sourceSha256||'')||value.replayed!==replayed
  ||![...POLYGLOT_TERMINAL,'pending','unconfirmed'].includes(value.status))invalid();
 if(POLYGLOT_TERMINAL.includes(value.status)?!bounded(value.text,8192):value.text!==null)invalid();
 return Object.freeze({...value});
}
export function decodeAvatarPolyglotAssessment(value){
 if(value?.status==='pending'){if(!exact(value,['completed','status','modelEvaluated'])||value.completed!==false||value.modelEvaluated!==false)invalid();return Object.freeze({...value});}
 return decodeAvatarUploadAssessment(value);
}
export function decodeAvatarAsset(value,operationId,now=Date.now()){
 if(!exact(value,['operationId','assetUrl','expiresAt'])||value.operationId!==operationId
  ||!Number.isSafeInteger(value.expiresAt)||value.expiresAt<=now)invalid();
 let url;try{url=new URL(value.assetUrl);}catch{invalid();}
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.hash)invalid();
 return Object.freeze({...value});
}
export function useCustomerAvatarUploadLesson({shopUserId,authorityKey,transport=globalThis.fetch,
 referenceStore,assessmentStore,svgAssessmentStore,polyglotPreviewStore,polyglotAssessmentStore}={}){
 const[reference,setReference]=useState(null),[result,setResult]=useState(null),[asset,setAsset]=useState(null);
 const[status,setStatus]=useState('ready'),[error,setError]=useState(null),[busy,setBusy]=useState(false);
 const[knownUnsent,setKnownUnsent]=useState(false),[admissionLatched,setAdmissionLatched]=useState(false);
 const[previewDelivered,setPreviewDelivered]=useState(false),[assessment,setAssessment]=useState(null);
 const[assessmentReference,setAssessmentReference]=useState(null),[assessmentKnownUnsent,setAssessmentKnownUnsent]=useState(false);
 const[svgAssessment,setSvgAssessment]=useState(null),[svgAssessmentReference,setSvgAssessmentReference]=useState(null);
 const[svgAssessmentKnownUnsent,setSvgAssessmentKnownUnsent]=useState(false);
 const[polyglotReady,setPolyglotReady]=useState(false),[polyglotPreview,setPolyglotPreview]=useState(null),[polyglotAssessment,setPolyglotAssessment]=useState(null);
 const[polyglotPreviewReference,setPolyglotPreviewReference]=useState(null),[polyglotAssessmentReference,setPolyglotAssessmentReference]=useState(null);
 const[polyglotPreviewKnownUnsent,setPolyglotPreviewKnownUnsent]=useState(false),[polyglotAssessmentKnownUnsent,setPolyglotAssessmentKnownUnsent]=useState(false);
 const polyglotPreviewRef=useRef(null),polyglotAssessmentRef=useRef(null);
 const epoch=useRef(0),active=useRef(null),mounted=useRef(false),savedRef=useRef(null),assessmentRef=useRef(null),svgAssessmentRef=useRef(null);
 const current=useCallback((version,controller)=>mounted.current&&epoch.current===version
  &&active.current===controller&&!controller.signal.aborted,[]);
 const request=useCallback((path,options)=>transport(path,options),[transport]);
 const assessmentRead=useCallback(async(saved,controller,version)=>{
  const value=decodeAvatarUploadAssessment(await json(await request(BASE+'/assess/'+saved.sessionId+'/'+saved.requestId,{
   method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));
  if(!current(version,controller))return false;if(value.status!=='unconfirmed')setAssessmentKnownUnsent(false);setAssessment(value);return true;
 },[request,current]);
 const svgAssessmentRead=useCallback(async(saved,controller,version)=>{
  const value=decodeAvatarUploadAssessment(await json(await request(BASE+'/svg-assess/'+saved.sessionId+'/'+saved.requestId,{
   method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));
  if(!current(version,controller))return false;if(value.status!=='unconfirmed')setSvgAssessmentKnownUnsent(false);setSvgAssessment(value);return true;
 },[request,current]);
 const polyglotRead=useCallback(async(saved,kind,controller,version)=>{
  const suffix=kind==='preview'?'polyglot-preview':'polyglot-assess';
  const raw=await json(await request(`${BASE}/${suffix}/${saved.sessionId}/${saved.requestId}`,{method:'GET',signal:controller.signal,headers:{accept:'application/json'}}));
  const value=kind==='preview'?decodeAvatarPolyglotPreview(raw,savedRef.current,true):decodeAvatarPolyglotAssessment(raw);
  if(!current(version,controller))return false;
  if(kind==='preview'){setPolyglotPreview(value);if(value.status!=='unconfirmed')setPolyglotPreviewKnownUnsent(false);}
  else{setPolyglotAssessment(value);if(value.status!=='unconfirmed')setPolyglotAssessmentKnownUnsent(false);}
  return true;
 },[request,current]);
 useEffect(()=>{
  setPolyglotReady(false);if(!Number.isSafeInteger(shopUserId)||shopUserId<1||!polyglotPreviewStore||!polyglotAssessmentStore)return undefined;
  const controller=new AbortController();
  void request(BASE+'/polyglot-readiness',{method:'GET',signal:controller.signal,headers:{accept:'application/json'}})
   .then(json).then(value=>{if(!exact(value,['ready'])||typeof value.ready!=='boolean')invalid();if(!controller.signal.aborted)setPolyglotReady(value.ready);})
   .catch(()=>{if(!controller.signal.aborted)setPolyglotReady(false);});
  return()=>controller.abort();
 },[shopUserId,authorityKey,request,polyglotPreviewStore,polyglotAssessmentStore]);
 const recoverSaved=useCallback(async(saved,controller,version)=>{
  const suffix=saved.operationId?`operations/${saved.operationId}`:`requests/${saved.requestId}`;
  const value=decodeAvatarUploadOperation(await json(await request(`${BASE}/${suffix}`,{
   method:'GET',signal:controller.signal,headers:{accept:'application/json'}})));
  if(!current(version,controller))return false;
  if(value.uploadRequestId!==saved.requestId||saved.operationId&&value.operationId!==saved.operationId)invalid();
  let acknowledged=saved;
  if(!saved.operationId){acknowledged=await referenceStore.acknowledgeOperation(saved,value.operationId,
    ()=>current(version,controller));if(!current(version,controller))return false;
   savedRef.current=acknowledged;setReference(acknowledged);}
  setResult(value);setStatus(value.status);setKnownUnsent(false);return true;
 },[request,referenceStore,current]);
 useEffect(()=>{
  mounted.current=true;const version=++epoch.current;active.current?.abort();active.current=null;
  savedRef.current=null;assessmentRef.current=null;svgAssessmentRef.current=null;polyglotPreviewRef.current=null;polyglotAssessmentRef.current=null;setPolyglotPreview(null);setPolyglotAssessment(null);setPolyglotPreviewReference(null);setPolyglotAssessmentReference(null);setPolyglotPreviewKnownUnsent(false);setPolyglotAssessmentKnownUnsent(false);setReference(null);setResult(null);setAsset(null);setPreviewDelivered(false);setAssessment(null);setAssessmentReference(null);setAssessmentKnownUnsent(false);setSvgAssessment(null);setSvgAssessmentReference(null);setSvgAssessmentKnownUnsent(false);setStatus('loading');setError(null);setBusy(false);setKnownUnsent(false);setAdmissionLatched(false);
  if(!Number.isSafeInteger(shopUserId)||shopUserId<1||typeof transport!=='function'||!referenceStore||!assessmentStore||!svgAssessmentStore){
   setStatus('error');setError('Avatar-upload lesson unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  let saved;try{saved=referenceStore.read(shopUserId);}catch{setStatus('error');setAdmissionLatched(true);setError('Saved avatar-upload request unavailable.');
   return()=>{mounted.current=false;++epoch.current;};}
  if(!saved){setStatus('ready');return()=>{mounted.current=false;++epoch.current;};}
  let grade,svgGrade;try{grade=assessmentStore.read(saved);}catch{setStatus('error');setAdmissionLatched(true);setError('Saved avatar-upload assessment unavailable.');return()=>{mounted.current=false;++epoch.current;};}try{svgGrade=svgAssessmentStore.read(saved);}catch{setStatus('error');setAdmissionLatched(true);setError('Saved SVG assessment unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  let legacy,polyGrade;try{legacy=polyglotPreviewStore?.read(saved)||null;polyGrade=polyglotAssessmentStore?.read(saved)||null;}
  catch{setStatus('error');setAdmissionLatched(true);setError('Saved legacy-preview reference unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  polyglotPreviewRef.current=legacy;setPolyglotPreviewReference(legacy);polyglotAssessmentRef.current=polyGrade;setPolyglotAssessmentReference(polyGrade);
  savedRef.current=saved;setReference(saved);assessmentRef.current=grade;setAssessmentReference(grade);svgAssessmentRef.current=svgGrade;setSvgAssessmentReference(svgGrade);setStatus('unconfirmed');setAdmissionLatched(true);
  const controller=new AbortController();active.current=controller;
  void recoverSaved(saved,controller,version).then(async()=>{if(grade&&!await assessmentRead(grade,controller,version))return false;if(svgGrade&&!await svgAssessmentRead(svgGrade,controller,version))return false;if(legacy&&!await polyglotRead(legacy,'preview',controller,version))return false;return polyGrade?polyglotRead(polyGrade,'assessment',controller,version):true;}).catch(()=>{if(current(version,controller)){
   setStatus('unconfirmed');setError('Check the saved avatar-upload request.');}}).finally(()=>{
   if(active.current===controller)active.current=null;});
  return()=>{mounted.current=false;++epoch.current;active.current?.abort();active.current=null;};
 },[shopUserId,authorityKey,transport,referenceStore,assessmentStore,svgAssessmentStore,polyglotPreviewStore,polyglotAssessmentStore,recoverSaved,assessmentRead,svgAssessmentRead,polyglotRead,current]);
 const run=useCallback(async(file,message,isPublic)=>{
  if(active.current||savedRef.current||admissionLatched||!mounted.current||!(file instanceof File)||file.size<1
   ||file.size>20*1024*1024||!bounded(message,8192)||!message.trim()||typeof isPublic!=='boolean')return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);setAsset(null);
  let locallyWritten=false,ownWritten=null,postStarted=false;
  try{
   const sessionId=decodeAvatarUploadSession(await json(await request(`${BASE}/session`,{
    method:'POST',signal:controller.signal,headers:{accept:'application/json'}})));
   if(!current(version,controller))return false;
   const saved=await referenceStore.saveIntent({shopUserId,sessionId,requestId:crypto.randomUUID(),startedAt:Date.now()},
    ()=>current(version,controller),value=>{locallyWritten=true;ownWritten=value;setAdmissionLatched(true);});if(!current(version,controller))return false;
   savedRef.current=saved;setReference(saved);setStatus('unconfirmed');
   const form=new FormData();form.append('sessionId',saved.sessionId);form.append('requestId',saved.requestId);
   form.append('message',message);form.append('public',String(isPublic));form.append('file',file,file.name);
   try{
    postStarted=true;
    const value=decodeAvatarUploadOperation(await json(await request(`${BASE}/run`,{
     method:'POST',signal:controller.signal,headers:{accept:'application/json'},body:form})),{run:true});
    if(value.uploadRequestId!==saved.requestId)invalid();
    const acknowledged=await referenceStore.acknowledgeOperation(saved,value.operationId,()=>current(version,controller));
    if(!current(version,controller))return false;savedRef.current=acknowledged;setReference(acknowledged);
    setResult(value);setStatus(value.status);setKnownUnsent(false);return true;
   }catch{return await recoverSaved(saved,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=referenceStore.read(shopUserId);}catch{}
   if(retained){savedRef.current=retained;setReference(retained);setStatus('unconfirmed');const unsent=locallyWritten&&!postStarted&&sameReference(retained,ownWritten);setKnownUnsent(unsent);
    setError(unsent?'Upload was not submitted. Discard the unsent request or check saved status.':'Upload outcome unresolved. Check the saved request.');}
   else{setStatus('error');setError(locallyWritten?'Saved upload intent is unavailable. Reload or reset this lesson before another submission.':'Avatar-upload lesson unavailable.');}}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,request,referenceStore,recoverSaved,current,admissionLatched]);
 const recover=useCallback(async()=>{
  const saved=savedRef.current;if(!saved||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);setAsset(null);
  try{return await recoverSaved(saved,controller,version);}
  catch{if(current(version,controller))setError('Saved avatar-upload result unavailable.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[recoverSaved,current]);
 const preview=useCallback(async()=>{
  const saved=savedRef.current;if(!saved?.operationId||result?.status!=='completed'||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);setAsset(null);
  try{const value=decodeAvatarAsset(await json(await request(`${BASE}/operations/${saved.operationId}/asset`,{
    method:'POST',signal:controller.signal,headers:{accept:'application/json'}})),saved.operationId);
   if(!current(version,controller))return false;setAsset(value);setPreviewDelivered(false);return true;}
  catch{if(current(version,controller))setError('Sandbox preview unavailable.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[result,request,current]);
 const assess=useCallback(async()=>{
  const saved=savedRef.current;if(!saved?.operationId||assessmentRef.current||active.current||!mounted.current
   ||!(result?.status==='denied'||result?.status==='completed'&&previewDelivered))return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  let own=null,postStarted=false;
  try{const ref=await assessmentStore.submit({shopUserId,sessionId:saved.sessionId,requestId:saved.requestId,startedAt:Date.now()},
    ()=>current(version,controller),value=>{own=value;assessmentRef.current=value;setAssessmentReference(value);});
   if(!current(version,controller))return false;postStarted=true;
   try{const value=decodeAvatarUploadAssessment(await json(await request(BASE+'/assess',{method:'POST',signal:controller.signal,
     headers:{accept:'application/json','content-type':'application/json'},
     body:JSON.stringify({sessionId:saved.sessionId,requestId:saved.requestId})})));
    if(!current(version,controller))return false;setAssessment(value);return true;}
   catch{return await assessmentRead(ref,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=assessmentStore.read(saved);}catch{}
    if(retained){assessmentRef.current=retained;setAssessmentReference(retained);
     setAssessmentKnownUnsent(Boolean(own&&!postStarted&&['version','shopUserId','sessionId','requestId','startedAt'].every(key=>retained[key]===own[key])));
     setError('Assessment outcome unresolved. Check the saved assessment.');}
    else setError('Assessment admission unavailable. Reload or reset before another assessment.');}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,result,previewDelivered,assessmentStore,request,assessmentRead,current]);
 const recoverAssessment=useCallback(async()=>{const saved=assessmentRef.current;if(!saved||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await assessmentRead(saved,controller,version);}
  catch{if(current(version,controller))setError('Saved avatar-upload assessment unavailable.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[assessmentRead,current]);
 const discardUnsentAssessment=useCallback(async()=>{const saved=assessmentRef.current;
  if(!saved||!assessmentKnownUnsent||active.current||!mounted.current)return false;setBusy(true);setError(null);
  try{await assessmentStore.clear(saved,()=>mounted.current&&assessmentRef.current===saved);assessmentRef.current=null;
   setAssessmentReference(null);setAssessment(null);setAssessmentKnownUnsent(false);return true;}
  catch{if(mounted.current)setError('Unsent avatar-upload assessment could not be cleared.');return false;}
  finally{if(mounted.current)setBusy(false);}
 },[assessmentKnownUnsent,assessmentStore]);
 const assessSvg=useCallback(async()=>{
  const saved=savedRef.current;if(!saved?.operationId||svgAssessmentRef.current||active.current||!mounted.current
   ||result?.status!=='completed'||!previewDelivered)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  let own=null,postStarted=false;
  try{const ref=await svgAssessmentStore.submit({shopUserId,sessionId:saved.sessionId,requestId:saved.requestId,startedAt:Date.now()},
    ()=>current(version,controller),value=>{own=value;svgAssessmentRef.current=value;setSvgAssessmentReference(value);});
   if(!current(version,controller))return false;postStarted=true;
   try{const value=decodeAvatarUploadAssessment(await json(await request(BASE+'/svg-assess',{method:'POST',signal:controller.signal,
     headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({sessionId:saved.sessionId,requestId:saved.requestId})})));
    if(!current(version,controller))return false;setSvgAssessment(value);return true;}
   catch{return await svgAssessmentRead(ref,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=svgAssessmentStore.read(saved);}catch{}
    if(retained){svgAssessmentRef.current=retained;setSvgAssessmentReference(retained);
     setSvgAssessmentKnownUnsent(Boolean(own&&!postStarted&&['version','shopUserId','sessionId','requestId','startedAt'].every(key=>retained[key]===own[key])));
     setError('SVG assessment outcome unresolved. Check the saved SVG assessment.');}
    else setError('SVG assessment admission unavailable. Reload or reset before another assessment.');}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,result,previewDelivered,svgAssessmentStore,request,svgAssessmentRead,current]);
 const recoverSvgAssessment=useCallback(async()=>{const saved=svgAssessmentRef.current;if(!saved||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await svgAssessmentRead(saved,controller,version);}
  catch{if(current(version,controller))setError('Saved SVG assessment unavailable.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[svgAssessmentRead,current]);
 const discardUnsentSvgAssessment=useCallback(async()=>{const saved=svgAssessmentRef.current;
  if(!saved||!svgAssessmentKnownUnsent||active.current||!mounted.current)return false;setBusy(true);setError(null);
  try{await svgAssessmentStore.clear(saved,()=>mounted.current&&svgAssessmentRef.current===saved);svgAssessmentRef.current=null;
   setSvgAssessmentReference(null);setSvgAssessment(null);setSvgAssessmentKnownUnsent(false);return true;}
  catch{if(mounted.current)setError('Unsent SVG assessment could not be cleared.');return false;}
  finally{if(mounted.current)setBusy(false);}
 },[svgAssessmentKnownUnsent,svgAssessmentStore]);
 const startPolyglot=useCallback(async kind=>{
  const source=savedRef.current,isPreview=kind==='preview',ref=isPreview?polyglotPreviewRef:polyglotAssessmentRef,
   store=isPreview?polyglotPreviewStore:polyglotAssessmentStore;
  if(!store||ref.current||!polyglotReady||!source?.operationId||active.current||!mounted.current
   ||result?.status!=='completed'||isPreview&&!previewDelivered
   ||!isPreview&&!POLYGLOT_TERMINAL.includes(polyglotPreview?.status))return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  let own=null,postStarted=false;
  const setRef=isPreview?setPolyglotPreviewReference:setPolyglotAssessmentReference,
   setValue=isPreview?setPolyglotPreview:setPolyglotAssessment,setUnsent=isPreview?setPolyglotPreviewKnownUnsent:setPolyglotAssessmentKnownUnsent;
  try{
   const saved=await store.submit({shopUserId,sessionId:source.sessionId,requestId:source.requestId,startedAt:Date.now()},()=>current(version,controller),value=>{own=value;ref.current=value;setRef(value);});
   if(!current(version,controller))return false;postStarted=true;
   try{const raw=await json(await request(BASE+(isPreview?'/polyglot-preview':'/polyglot-assess'),{method:'POST',signal:controller.signal,
     headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({sessionId:source.sessionId,requestId:source.requestId})}));
    const value=isPreview?decodeAvatarPolyglotPreview(raw,source,false):decodeAvatarPolyglotAssessment(raw);
    if(!current(version,controller))return false;setValue(value);return true;
   }catch{return await polyglotRead(saved,kind,controller,version);}
  }catch{if(current(version,controller)){let saved=null;try{saved=store.read(source);}catch{}
    if(saved){ref.current=saved;setRef(saved);setUnsent(Boolean(own&&!postStarted&&['version','shopUserId','sessionId','requestId','startedAt'].every(key=>saved[key]===own[key])));
     setError(isPreview?'Legacy preview outcome unresolved. Check the saved preview.':'Polyglot assessment outcome unresolved. Check the saved assessment.');}
    else setError('Legacy preview admission unavailable. Reload or reset before another submission.');}return false;
  }finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[shopUserId,result,previewDelivered,polyglotReady,polyglotPreview,polyglotPreviewStore,polyglotAssessmentStore,request,polyglotRead,current]);
 const recoverPolyglot=useCallback(async kind=>{
  const saved=(kind==='preview'?polyglotPreviewRef:polyglotAssessmentRef).current;
  if(!saved||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await polyglotRead(saved,kind,controller,version);}
  catch{if(current(version,controller))setError(kind==='preview'?'Saved legacy preview unavailable.':'Saved polyglot assessment unavailable.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[polyglotRead,current]);
 const discardUnsentPolyglot=useCallback(async kind=>{
  const isPreview=kind==='preview',ref=isPreview?polyglotPreviewRef:polyglotAssessmentRef,
   store=isPreview?polyglotPreviewStore:polyglotAssessmentStore,saved=ref.current;
  if(!saved||!(isPreview?polyglotPreviewKnownUnsent:polyglotAssessmentKnownUnsent)||active.current||!mounted.current)return false;
  setBusy(true);setError(null);
  try{await store.clear(saved,()=>mounted.current&&ref.current===saved);ref.current=null;
   (isPreview?setPolyglotPreviewReference:setPolyglotAssessmentReference)(null);
   (isPreview?setPolyglotPreview:setPolyglotAssessment)(null);
   (isPreview?setPolyglotPreviewKnownUnsent:setPolyglotAssessmentKnownUnsent)(false);return true;
  }catch{if(mounted.current)setError('Unsent legacy-preview operation could not be discarded.');return false;}
  finally{if(mounted.current)setBusy(false);}
 },[polyglotPreviewStore,polyglotAssessmentStore,polyglotPreviewKnownUnsent,polyglotAssessmentKnownUnsent]);
 const retire=useCallback(async(kind)=>{const saved=savedRef.current;
  if(kind==='terminal'&&polyglotPreviewRef.current&&!POLYGLOT_TERMINAL.includes(polyglotPreview?.status))return false;
  if(kind==='terminal'&&polyglotAssessmentRef.current&&!(polyglotAssessment?.judgment||polyglotAssessment?.status==='ineligible'))return false;
  if(kind==='terminal'&&assessmentRef.current&&!(assessment?.judgment||assessment?.status==='ineligible'))return false;
  if(kind==='terminal'&&svgAssessmentRef.current&&!(svgAssessment?.judgment||svgAssessment?.status==='ineligible'))return false;
  if(active.current||!mounted.current||!saved||(kind==='unsent'?!knownUnsent:!['completed','denied'].includes(result?.status)))return false;
  setBusy(true);setError(null);try{if(assessmentRef.current){await assessmentStore.clear(assessmentRef.current,()=>mounted.current&&savedRef.current===saved);assessmentRef.current=null;setAssessmentReference(null);setAssessment(null);setAssessmentKnownUnsent(false);}
   if(svgAssessmentRef.current){await svgAssessmentStore.clear(svgAssessmentRef.current,()=>mounted.current&&savedRef.current===saved);svgAssessmentRef.current=null;setSvgAssessmentReference(null);setSvgAssessment(null);setSvgAssessmentKnownUnsent(false);}
   for(const [ref,store,setRef,setValue,setUnsent]of [[polyglotPreviewRef,polyglotPreviewStore,setPolyglotPreviewReference,setPolyglotPreview,setPolyglotPreviewKnownUnsent],[polyglotAssessmentRef,polyglotAssessmentStore,setPolyglotAssessmentReference,setPolyglotAssessment,setPolyglotAssessmentKnownUnsent]]){
    if(ref.current){await store.clear(ref.current,()=>mounted.current&&savedRef.current===saved);ref.current=null;setRef(null);setValue(null);setUnsent(false);}}
   await referenceStore.clear(saved,()=>mounted.current&&savedRef.current===saved);savedRef.current=null;setReference(null);setResult(null);setAsset(null);setPreviewDelivered(false);setStatus('ready');setKnownUnsent(false);setAdmissionLatched(false);return true;
  }catch{if(mounted.current)setError('Saved avatar-upload request could not be retired.');return false;}finally{if(mounted.current)setBusy(false);}
 },[knownUnsent,result,assessment,svgAssessment,polyglotPreview,polyglotAssessment,referenceStore,assessmentStore,svgAssessmentStore,polyglotPreviewStore,polyglotAssessmentStore]);
 return{polyglotReady,polyglotPreview,polyglotAssessment,polyglotPreviewReference,polyglotAssessmentReference,polyglotPreviewKnownUnsent,polyglotAssessmentKnownUnsent,runPolyglotPreview:()=>startPolyglot('preview'),assessPolyglot:()=>startPolyglot('assessment'),recoverPolyglotPreview:()=>recoverPolyglot('preview'),recoverPolyglotAssessment:()=>recoverPolyglot('assessment'),discardUnsentPolyglotPreview:()=>discardUnsentPolyglot('preview'),discardUnsentPolyglotAssessment:()=>discardUnsentPolyglot('assessment'),reference,result,asset,previewDelivered,assessmentReference,assessment,assessmentKnownUnsent,svgAssessmentReference,svgAssessment,svgAssessmentKnownUnsent,status,error,busy,knownUnsent,admissionLatched,run,recover,preview,assess,recoverAssessment,discardUnsentAssessment,assessSvg,recoverSvgAssessment,discardUnsentSvgAssessment,markPreviewDelivered:useCallback(()=>setPreviewDelivered(true),[]),
  discardUnsent:useCallback(()=>retire('unsent'),[retire]),startNew:useCallback(()=>retire('terminal'),[retire])};
}
