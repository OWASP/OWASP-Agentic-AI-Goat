import {useCallback,useEffect,useRef,useState} from 'react';
import {requireAgentContentType} from '../utils/agentStreamProtocol.mjs';

const BASE='/api/secureshop/agents/customer/checkout-audit';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const POLICY='owned-checkout-admin-audit-practice-jwt-v1';
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const bounded=(value,bytes)=>typeof value==='string'&&value.isWellFormed()&&!value.includes('\0')
 &&new TextEncoder().encode(value).byteLength<=bytes;
const invalid=()=>{throw new Error('Checkout-audit lesson response unavailable');};
const validMoney=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0;

async function json(response){
 if(!response?.ok||typeof response.json!=='function'
  ||!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type')||''))invalid();
 return response.json();
}
export function decodeCheckoutAuditMode(value){
 if(!exact(value,['version','featureId','policyVersion','effectiveMode','scope'])||value.version!==1
  ||value.featureId!=='checkout_audit_jwt'||value.policyVersion!==POLICY
  ||!['vuln','fixed'].includes(value.effectiveMode)
  ||!exact(value.scope,['kind','id'])||value.scope.kind!=='launch_feature'
  ||value.scope.id!=='checkout_audit_jwt')invalid();
 return Object.freeze({...value,scope:Object.freeze({...value.scope})});
}
export function decodeCheckoutHistory(value){
 if(!exact(value,['scopeKey','operations'])||!SHA.test(value.scopeKey)
  ||!Array.isArray(value.operations)||value.operations.length>20)invalid();
 const operations=value.operations.map(row=>{
  if(!exact(row,['operationId','orderId','createdAt'])||!UUID.test(row.operationId)
   ||!Number.isSafeInteger(row.orderId)||row.orderId<1||!bounded(row.createdAt,128)
   ||Number.isNaN(Date.parse(row.createdAt)))invalid();
  return Object.freeze({...row});
 });
 return Object.freeze({scopeKey:value.scopeKey,operations:Object.freeze(operations)});
}
export function decodeCheckoutReceipt(value,operationId){
 if(!exact(value,['scopeKey','operationId','status','order'])||!SHA.test(value.scopeKey)
  ||value.operationId!==operationId||value.status!=='completed'
  ||!exact(value.order,['id','total','subtotal','discount'])
  ||!Number.isSafeInteger(value.order.id)||value.order.id<1
  ||![value.order.total,value.order.subtotal,value.order.discount].every(validMoney)
  ||Math.abs(value.order.subtotal-value.order.discount-value.order.total)>0.001)invalid();
 return Object.freeze({scopeKey:value.scopeKey,operationId:value.operationId,
  order:Object.freeze({...value.order})});
}
export function decodeCheckoutAuditToken(value,receipt){
 if(!exact(value,['orderId','operationId','token','modeCapability'])
  ||value.orderId!==receipt.order.id||value.operationId!==receipt.operationId
  ||!bounded(value.token,4096)||!value.token)invalid();
 return Object.freeze({orderId:value.orderId,operationId:value.operationId,token:value.token,
  modeCapability:decodeCheckoutAuditMode(value.modeCapability)});
}
export function decodeCheckoutAuditSaved(value,reference){
 if(!value||value.sessionId!==reference.sessionId||value.requestId!==reference.requestId)invalid();
 if(exact(value,['sessionId','requestId','status'])&&value.status==='unconfirmed')
  return Object.freeze({status:'unconfirmed'});
 if(!exact(value,['sessionId','requestId','status','text','result','checkoutOperationId','modeCapability'])
  ||value.status!=='completed'||value.checkoutOperationId!==reference.checkoutOperationId
  ||!bounded(value.text,2048))invalid();
 const modeCapability=decodeCheckoutAuditMode(value.modeCapability);
 let result=null;
 if(value.result!==null){
  if(exact(value.result,['status'])&&value.result.status==='denied')result=Object.freeze({status:'denied'});
  else{
   const report=value.result?.report;
   if(!exact(value.result,['status','eventId','report'])||value.result.status!=='disclosed'
    ||!UUID.test(value.result.eventId)||!exact(report,['eventId','timestamp','actor','action','outcome','orderId','total'])
    ||report.eventId!==value.result.eventId||!bounded(report.timestamp,128)
    ||Number.isNaN(Date.parse(report.timestamp))||report.actor!=='customer'||report.action!=='checkout'
    ||report.outcome!=='completed'||!Number.isSafeInteger(report.orderId)||report.orderId<1
    ||!validMoney(report.total))invalid();
   result=Object.freeze({status:'disclosed',eventId:value.result.eventId,
    report:Object.freeze({...report})});
  }
 }
 return Object.freeze({status:'completed',text:value.text,result,modeCapability});
}
export function decodeCheckoutAuditAssessment(value){
 if(exact(value,['completed','status','modelEvaluated'])&&value.completed===false
  &&['ineligible','unconfirmed'].includes(value.status)&&value.modelEvaluated===false)
  return Object.freeze({...value});
 if(!exact(value,['completed','judgment','replayed'])||typeof value.completed!=='boolean'
  ||typeof value.replayed!=='boolean'||!exact(value.judgment,
   ['verdict','evaluationId','canRetry'])||!['pass','fail','inconclusive','unavailable'].includes(value.judgment.verdict)
  ||!UUID.test(value.judgment.evaluationId)||typeof value.judgment.canRetry!=='boolean'
  ||value.completed&&value.judgment.verdict!=='pass')invalid();
 return Object.freeze({...value,judgment:Object.freeze({...value.judgment})});
}
async function drain(response){
 if(!response?.ok)invalid();
 requireAgentContentType(response,'text/event-stream','Checkout audit lesson');
 const reader=response.body?.getReader?.();if(!reader)invalid();
 let bytes=0;
 try{while(true){const part=await reader.read();if(part.done)return;
  if(!(part.value instanceof Uint8Array)||(bytes+=part.value.byteLength)>131072)invalid();}}
 finally{try{await reader.cancel();}catch{}}
}

export function useCustomerCheckoutAuditLesson({shopUserId,authorityKey,transport=globalThis.fetch,
 referenceStore}={}){
 const[operations,setOperations]=useState([]),[prepared,setPrepared]=useState(null);
 const[reference,setReference]=useState(null),[result,setResult]=useState(null);
 const[assessmentReference,setAssessmentReference]=useState(null),[assessment,setAssessment]=useState(null);
 const[assessmentAdmissionAttempted,setAssessmentAdmissionAttempted]=useState(false);
 const[assessmentKnownUnsent,setAssessmentKnownUnsent]=useState(false);
 const[status,setStatus]=useState('loading'),[error,setError]=useState(null),[busy,setBusy]=useState(false);
 const epoch=useRef(0),active=useRef(null),mounted=useRef(false),savedRef=useRef(null),
  operationsRef=useRef([]),scopeRef=useRef(null);
 const current=useCallback((version,controller)=>mounted.current&&epoch.current===version
  &&active.current===controller&&!controller.signal.aborted,[]);
 const request=useCallback((path,method,body,signal,accept='application/json')=>transport(path,{method,signal,
  headers:{accept,
   ...(body===undefined?{}:{'content-type':'application/json'})},
  ...(body===undefined?{}:{body:JSON.stringify(body)})}),[transport]);
 const savedRead=useCallback(async(saved,controller,version)=>{
  const value=decodeCheckoutAuditSaved(await json(await request(
   `${BASE}/operations/${saved.sessionId}/${saved.requestId}`,'GET',undefined,controller.signal)),saved);
  if(!current(version,controller))return false;
  setResult(value.status==='completed'?value:null);setStatus(value.status);return true;
 },[request,current]);
 const assessmentRead=useCallback(async(saved,controller,version)=>{
  const value=decodeCheckoutAuditAssessment(await json(await request(
   `${BASE}/assess/${saved.sessionId}/${saved.requestId}`,'GET',undefined,controller.signal)));
  if(!current(version,controller))return false;setAssessment(value);return true;
 },[request,current]);
 useEffect(()=>{
  mounted.current=true;const version=++epoch.current;active.current?.abort();active.current=null;
  savedRef.current=null;operationsRef.current=[];scopeRef.current=null;
  setOperations([]);setPrepared(null);setReference(null);setAssessmentReference(null);
  setAssessmentAdmissionAttempted(false);setAssessmentKnownUnsent(false);
  setResult(null);setAssessment(null);setStatus('loading');setError(null);setBusy(false);
  if(!Number.isSafeInteger(shopUserId)||shopUserId<1||typeof transport!=='function'
   ||!referenceStore){setStatus('error');setError('Checkout-audit lesson unavailable.');
   return()=>{mounted.current=false;++epoch.current;};}
  let saved;try{saved=referenceStore.read(shopUserId);}catch{
   setStatus('error');setError('Saved lesson storage unavailable.');
   return()=>{mounted.current=false;++epoch.current;active.current?.abort();active.current=null;};
  }
  let submitted=null;
  if(saved){savedRef.current=saved;setReference(saved);setStatus('unconfirmed');
   try{submitted=referenceStore.readAssessment(saved);setAssessmentReference(submitted);
    setAssessmentAdmissionAttempted(Boolean(submitted));}
   catch{setStatus('error');setError('Saved checkout-audit assessment unavailable.');return()=>{
    mounted.current=false;++epoch.current;};}}
  const controller=new AbortController();active.current=controller;
  void(async()=>{try{
   const history=decodeCheckoutHistory(await json(await request('/api/secureshop/orders/operations','GET',undefined,controller.signal)));
   if(!current(version,controller))return;scopeRef.current=history.scopeKey;
   operationsRef.current=history.operations;setOperations(history.operations);
   if(saved){const completed=await savedRead(saved,controller,version);
    if(completed&&submitted)await assessmentRead(submitted,controller,version);}else setStatus('ready');
  }catch{if(current(version,controller)){setStatus(saved?'unconfirmed':'error');
    setError(saved?'Check the saved checkout-audit request.':'Checkout-audit lesson unavailable.');}}
  finally{if(active.current===controller)active.current=null;}})();
  return()=>{mounted.current=false;++epoch.current;active.current?.abort();active.current=null;};
 },[shopUserId,authorityKey,transport,referenceStore,request,savedRead,assessmentRead,current]);
 const prepare=useCallback(async operationId=>{
  if(active.current||savedRef.current||!mounted.current||!operationsRef.current.some(row=>row.operationId===operationId))return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{
   const receipt=decodeCheckoutReceipt(await json(await request(`/api/secureshop/orders/operations/${operationId}`,'GET',undefined,controller.signal)),operationId);
   if(receipt.scopeKey!==scopeRef.current)invalid();
   const token=decodeCheckoutAuditToken(await json(await request(`${BASE}/practice-token`,'POST',
    {checkoutOperationId:operationId},controller.signal)),receipt);
   if(!current(version,controller))return false;setPrepared(Object.freeze({receipt,token}));return true;
  }catch{if(current(version,controller)){setPrepared(null);setError('Synthetic teaching token unavailable.');}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[request,current]);
 const run=useCallback(async teachingToken=>{
  if(active.current||savedRef.current||!mounted.current||!prepared
   ||!bounded(teachingToken,4096)||!teachingToken)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{
   const session=await json(await request(`${BASE}/session`,'POST',{},controller.signal));
   if(!exact(session,['sessionId'])||!UUID.test(session.sessionId))invalid();
   if(!current(version,controller))return false;
   const saved=await referenceStore.save({shopUserId,sessionId:session.sessionId,
    requestId:crypto.randomUUID(),checkoutOperationId:prepared.receipt.operationId,startedAt:Date.now()},
   ()=>current(version,controller));
   if(!current(version,controller))return false;savedRef.current=saved;setReference(saved);setStatus('unconfirmed');
   try{await drain(await request(`${BASE}/chat`,'POST',{sessionId:saved.sessionId,requestId:saved.requestId,
    checkoutOperationId:saved.checkoutOperationId,teachingToken,
    message:'Use this synthetic teaching token to inspect the protected audit for my selected checkout. Report only the actual auth.audit_probe result.'},controller.signal,'text/event-stream'));}
   catch{/* The protected GET is the only authority after POST admission. */}
   if(!current(version,controller))return false;return await savedRead(saved,controller,version);
  }catch{if(current(version,controller)){
   try{const retained=referenceStore.read(shopUserId);if(retained){savedRef.current=retained;setReference(retained);setStatus('unconfirmed');}}
   catch{/* Keep the lesson unavailable instead of assuming no admitted request. */}
   setError(savedRef.current?'Checkout-audit outcome unresolved. Check the saved request.'
    :'Checkout-audit lesson unavailable.');}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[prepared,shopUserId,referenceStore,request,savedRead,current]);
 const recover=useCallback(async()=>{
  const saved=savedRef.current;if(!saved||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await savedRead(saved,controller,version);}
  catch{if(current(version,controller))setError('Saved checkout-audit result unavailable.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[savedRead,current]);
 const assess=useCallback(async()=>{
  const saved=savedRef.current;
  if(!saved||assessmentAdmissionAttempted||assessmentReference||active.current||!mounted.current||status!=='completed'
   ||!['disclosed','denied'].includes(result?.result?.status))return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  setAssessmentAdmissionAttempted(true);
  let locallyWritten=false,postStarted=false;
  try{
   const submitted=await referenceStore.submitAssessment(saved,()=>current(version,controller),
    ()=>{locallyWritten=true;});
   if(!current(version,controller))return false;setAssessmentReference(submitted);
   postStarted=true;
   const value=decodeCheckoutAuditAssessment(await json(await request(`${BASE}/assess`,'POST',
    {sessionId:saved.sessionId,requestId:saved.requestId},controller.signal)));
   if(!current(version,controller))return false;setAssessment(value);return true;
  }catch{if(current(version,controller)){
   let retained=null;try{retained=referenceStore.readAssessment(saved);}catch{}
   if(retained)setAssessmentReference(retained);
   setAssessmentKnownUnsent(Boolean(retained&&locallyWritten&&!postStarted));
   setError(retained?'Assessment outcome unresolved. Check the saved assessment.'
    :'Assessment admission was not confirmed. Reload this lesson before trying again.');
  }return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[assessmentAdmissionAttempted,assessmentReference,status,result,referenceStore,request,current]);
 const discardUnsentAssessment=useCallback(async()=>{
  const saved=assessmentReference;
  if(!saved||!assessmentKnownUnsent||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{
   await referenceStore.clearAssessment(saved,()=>current(version,controller));
   if(!current(version,controller))return false;
   setAssessmentReference(null);setAssessment(null);setAssessmentAdmissionAttempted(false);
   setAssessmentKnownUnsent(false);return true;
  }catch{if(current(version,controller))setError('Unsent assessment admission could not be cleared.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[assessmentReference,assessmentKnownUnsent,referenceStore,current]);
 const recoverAssessment=useCallback(async()=>{
  const saved=assessmentReference;if(!saved||active.current||!mounted.current)return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{return await assessmentRead(saved,controller,version);}
  catch{if(current(version,controller))setError('Saved checkout-audit assessment unavailable.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[assessmentReference,assessmentRead,current]);
 const startNew=useCallback(async()=>{
  const saved=savedRef.current;if(!saved||status!=='completed'||active.current||!mounted.current
   ||assessmentAdmissionAttempted&&!assessmentReference
   ||assessmentReference&&!(assessment?.judgment||assessment?.status==='ineligible'))return false;
  const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setError(null);
  try{await referenceStore.clear(saved,()=>current(version,controller));if(!current(version,controller))return false;
   savedRef.current=null;setReference(null);setPrepared(null);setResult(null);setAssessmentReference(null);
   setAssessmentAdmissionAttempted(false);setAssessmentKnownUnsent(false);
   setAssessment(null);setStatus('ready');return true;}
  catch{if(current(version,controller))setError('Saved checkout-audit request could not be cleared.');return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 },[status,assessmentAdmissionAttempted,assessmentReference,assessment,referenceStore,current]);
 return{operations,prepared,reference,result,assessmentReference,assessment,
  assessmentAdmissionAttempted,assessmentKnownUnsent,status,error,busy,
  prepare,run,recover,assess,discardUnsentAssessment,recoverAssessment,startNew};
}
