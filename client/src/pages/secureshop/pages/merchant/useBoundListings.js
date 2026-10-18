import { listingsChatSource } from '../../utils/merchantListingsSetup.mjs';
import {shopStorage,flushShopStorage,SHOP_LISTINGS_KEY as KEY} from '../../utils/shopStorage.mjs';
import {decodeListingsReferences,listingsForScope,replaceListingsScope} from './listingsReferences.mjs';
import {useEffect,useRef,useState} from 'react';
import {getBridgeFetchMetadata} from '../../bridge/fetchAdapter.mjs';
import {isStandaloneShopFrame} from '../../bridge/assessmentPanelIntent.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
async function digest(value){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(value))))].map(x=>x.toString(16).padStart(2,'0')).join('');}
export function useBoundListings(authToken,transport){
 const attached=!!getBridgeFetchMetadata(transport),epoch=useRef(0),live=useRef({authToken,transport}),pending=useRef({}),controllers=useRef(new Set());
 live.current={authToken,transport};const [capability,setCapability]=useState(null),[references,setReferences]=useState({}),[busy,setBusy]=useState(false);
 const [readinessChecking,setReadinessChecking]=useState(attached),[readinessError,setReadinessError]=useState(null),[readinessRetry,setReadinessRetry]=useState(0);
 const [templateReady,setTemplateReady]=useState(false),[templateChecking,setTemplateChecking]=useState(attached),[templateError,setTemplateError]=useState(null),[templateRetry,setTemplateRetry]=useState(0);
 const readinessIdentity=useRef(null),capabilityIdentity=useRef(null),readinessRetryQueued=useRef(false);
 const current=(e,token,fetcher)=>e===epoch.current&&live.current.authToken===token&&live.current.transport===fetcher;
 useEffect(()=>{
  const e=++epoch.current,c=new AbortController();controllers.current.add(c);
  const sameIdentity=readinessIdentity.current?.authToken===authToken&&readinessIdentity.current?.transport===transport&&readinessIdentity.current?.attached===attached;
  readinessIdentity.current={authToken,transport,attached};
  capabilityIdentity.current=null;
  setCapability(null);setReadinessError(null);setReadinessChecking(attached);
  if(!sameIdentity){setReferences({});pending.current={};setBusy(false);inFlight.current=false;}
  if(attached)Promise.resolve().then(()=>{
   if(c.signal.aborted||!current(e,authToken,transport))return null;
   return transport('/api/secureshop/merchant/listings/readiness',{signal:c.signal});
  }).then(async r=>{
   if(!r)return;
   if(!r.ok){try{await r.body?.cancel();}catch{}
    if(current(e,authToken,transport))setReadinessError(Number.isInteger(r.status)?`Listing actions could not be verified (HTTP ${r.status}).`:'Listing actions could not be verified.');return;}
   const value=await r.json();if(value?.ready!==true||value.versionedListings!==true||!/^[a-f0-9]{64}$/.test(value.scopeKey||'')){
    if(current(e,authToken,transport))setReadinessError('Listing readiness response could not be verified.');return;
   }
   if(!current(e,authToken,transport))return;
   let saved;try{saved=listingsForScope(decodeListingsReferences(shopStorage.getItem(KEY)),value.scopeKey);}catch{
    setReadinessError('Saved listing references could not be verified. Listing actions remain unavailable.');return;
   }
   pending.current=saved;setReferences(saved);capabilityIdentity.current={authToken,transport,epoch:e};setCapability(value);
  }).catch(()=>{if(current(e,authToken,transport)&&!c.signal.aborted)setReadinessError('Could not check listing actions.');}).finally(()=>{
   controllers.current.delete(c);if(current(e,authToken,transport)){setReadinessChecking(false);readinessRetryQueued.current=false;}
  });
  else {setReadinessChecking(false);readinessRetryQueued.current=false;}
  return()=>{epoch.current++;for(const c of controllers.current)c.abort();controllers.current.clear();};
 },[authToken,transport,attached,readinessRetry]);
 useEffect(()=>{
  const e=epoch.current,c=new AbortController();controllers.current.add(c);
  setTemplateReady(false);setTemplateChecking(attached);setTemplateError(null);
  if(attached)Promise.resolve().then(()=>{
   if(c.signal.aborted||!current(e,authToken,transport))return null;
   return transport('/api/secureshop/merchant/listings/template-readiness',{signal:c.signal});
  }).then(async r=>{
   if(!r)return;
   if(!r.ok){try{await r.body?.cancel();}catch{}
    throw Error(Number.isInteger(r.status)?`Template rendering could not be verified (HTTP ${r.status}).`:'Template rendering could not be verified.');}
   const value=await r.json();if(!current(e,authToken,transport)||c.signal.aborted)return;
   if(!value||typeof value.ready!=='boolean'||Object.keys(value).join(',')!=='ready')throw Error('Template rendering readiness response could not be verified.');
   setTemplateReady(value.ready);
  }).catch(error=>{if(current(e,authToken,transport)&&!c.signal.aborted)setTemplateError(error.message||'Could not check template rendering.');}).finally(()=>{
   controllers.current.delete(c);if(current(e,authToken,transport)){setTemplateChecking(false);templateRetryQueued.current=false;}
  });
  else {setTemplateChecking(false);templateRetryQueued.current=false;}
  return()=>{c.abort();controllers.current.delete(c);};
 },[authToken,transport,attached,readinessRetry,templateRetry]);
 function retryReadiness(){if(!attached||inFlight.current||readinessRetryQueued.current)return;readinessRetryQueued.current=true;setReadinessRetry(value=>value+1);}
 const templateRetryQueued=useRef(false);
 function retryTemplateReadiness(){if(!attached||inFlight.current||templateRetryQueued.current)return;templateRetryQueued.current=true;setTemplateRetry(value=>value+1);}
 async function remember(action,reference,saved){const next={...pending.current,[action]:reference};if(saved){if(next.save?.operationId===saved.saveOperationId)delete next.save;if(next.rewrite?.operationId===saved.rewriteOperationId)delete next.rewrite;}await persist(next);}
 async function persist(next){
  const e=epoch.current,token=authToken,fetcher=transport,scopeKey=capability?.scopeKey;
  if(!scopeKey||!current(e,token,fetcher))throw Error('Listings session changed');
  const stored=decodeListingsReferences(shopStorage.getItem(KEY)),actual=listingsForScope(stored,scopeKey);
  const comparable=value=>JSON.stringify(['rewrite','import','optimize','save','template','assessment'].map(key=>value[key]?.length===0?null:value[key]??null));
  if(comparable(actual)!==comparable(pending.current))throw Error('Saved Listings reference changed. Check its outcome before another action.');
  const raw=JSON.stringify(replaceListingsScope(stored,scopeKey,next));decodeListingsReferences(raw);
  shopStorage.setItem(KEY,raw);await flushShopStorage();
  if(!current(e,token,fetcher))throw Error('Listings session changed');
  if(shopStorage.getItem(KEY)!==raw)throw Error('Saved Listings reference changed. Check its outcome before another action.');
  pending.current=next;setReferences(next);
 }
 const inFlight=useRef(false);
 async function perform(action,payload,command='run'){
  if(!capability||inFlight.current)throw Error('Listings unavailable or busy');
  const e=epoch.current,token=authToken,fetcher=transport,c=new AbortController();controllers.current.add(c);inFlight.current=true;setBusy(true);
  try{
   const sha=payload?await digest(payload):null;if(!current(e,token,fetcher))throw Error('Listings session changed');
   let reference=pending.current[action];
   if(command==='run'){
    if(reference&&reference.digest!==sha)throw Error('Check the saved operation before changing this request.');
    if(reference)command='recover';
    else{const chatSource=payload?.chatSource?listingsChatSource(payload.chatSource):null;
     reference={scopeKey:capability.scopeKey,operationId:chatSource&&action!=='save'?chatSource.proposalId:crypto.randomUUID(),digest:sha,...(chatSource?{chatSource}:{}),...(action==='save'?{rewriteOperationId:payload.rewriteOperationId}:{})};await remember(action,reference);}
   }
   if(!current(e,token,fetcher))throw Error('Listings session changed');
   if(!reference)throw Error('No saved operation');
   const expectedRewrite=action==='save'?(reference.chatSource?.proposalId||reference.rewriteOperationId||payload?.rewriteOperationId||pending.current.rewrite?.operationId):null;
   if(action==='save'&&!UUID.test(expectedRewrite||''))throw Error('Saved rewrite identity unavailable. Open the original listing request to recover.');
   const saveQuery=action==='save'&&command!=='run'?'?'+new URLSearchParams(reference.chatSource||{rewriteOperationId:expectedRewrite}).toString():'';
   const path=action==='save'?(command==='run'?'rewrite-save':`rewrite-saves/${reference.operationId}${saveQuery}`):command==='run'?(action==='rewrite'?'assist-write':action==='optimize'?'optimize-images':'import-bulk'):`operations/${reference.operationId}${command==='resume'?'/resume':''}`;
   const stored=listingsForScope(decodeListingsReferences(shopStorage.getItem(KEY)),capability.scopeKey);
   if(JSON.stringify(stored[action])!==JSON.stringify(reference))throw Error('Saved Listings reference changed.');
   const body=command==='run'?{...(reference.chatSource&&action!=='save'?{chatSource:reference.chatSource}:payload),[action==='save'?'saveOperationId':'operationId']:reference.operationId}:command==='resume'?{}:undefined;
   const response=await fetcher('/api/secureshop/merchant/listings/'+path,{method:body?'POST':'GET',signal:c.signal,...(body?{headers:{'content-type':'application/json'},body:JSON.stringify(body)}:{})});
   const value=await response.json();if(!current(e,token,fetcher))throw Error('Listings session changed');
   if(JSON.stringify(listingsForScope(decodeListingsReferences(shopStorage.getItem(KEY)),capability.scopeKey)[action])!==JSON.stringify(reference))throw Error('Saved Listings reference changed.');
   if(response.status===409&&value?.code==='LISTING_MODE_TARGET_CONFLICT'){
    throw Error('This listings target belongs to another mode. The saved request has no confirmed outcome; switch back to recover earlier work. A shop administrator can reset the shared practice before starting in this mode.');
   }
   if(!response.ok||value[action==='save'?'saveOperationId':'operationId']!==reference.operationId||!['admitted','running','unknown','effect_received','completed','declined','denied','failed'].includes(value.state))throw Error('Listings outcome unresolved; check the saved operation.');
   if(action==='save'&&value.state==='completed'&&(value.ok!==true||Object.keys(value).sort().join(',')!=='ok,productId,rewriteOperationId,saveOperationId,state'||!UUID.test(value.rewriteOperationId)||!Number.isSafeInteger(value.productId)||value.productId<1||expectedRewrite!==value.rewriteOperationId))throw Error('Invalid saved listing receipt');
   if(action==='rewrite'&&value.state==='completed'&&typeof value.html!=='string')throw Error('Invalid rewrite receipt');
   if(action==='optimize'&&value.state==='completed'&&(value.productId<1||typeof value.additionalCommandObserved!=='boolean'||typeof value.hostname!=='string'||!Number.isInteger(value.exitCode)))throw Error('Invalid optimization receipt');
   return {...value,sourceMatches:sha===reference.digest};
  }finally{controllers.current.delete(c);if(current(e,token,fetcher)){inFlight.current=false;setBusy(false);}}
 }
 async function assessSaved(ids){
  if(!capability||inFlight.current)throw Error('Listings unavailable or busy');
  const e=epoch.current,token=authToken,fetcher=transport,c=new AbortController();controllers.current.add(c);inFlight.current=true;setBusy(true);
  try{
   const rows=pending.current.assessment||[];
   let reference;
   if(!ids&&!rows.length&&pending.current.save&&pending.current.rewrite)ids={rewriteOperationId:pending.current.rewrite.operationId,saveOperationId:pending.current.save.operationId};
   if(ids){
    if(Object.keys(ids).sort().join(',')!=='rewriteOperationId,saveOperationId'||!UUID.test(ids.rewriteOperationId)||!UUID.test(ids.saveOperationId))throw Error('Invalid saved listing reference');
    const sha=await digest([ids.rewriteOperationId,ids.saveOperationId]);if(!current(e,token,fetcher))throw Error('Listings session changed');
    reference=rows.find(row=>row.saveOperationId===ids.saveOperationId);
    if(reference&&reference.digest!==sha)throw Error('Saved listing reference changed');
    if(!reference){if(rows.length>=8)throw Error('Check pending saved listings before starting another assessment.');
     reference={scopeKey:capability.scopeKey,requestId:crypto.randomUUID(),rewriteOperationId:ids.rewriteOperationId,saveOperationId:ids.saveOperationId,digest:sha};
     await remember('assessment',[...rows,reference],reference);
    }else await remember('assessment',rows,reference);
   }else reference=isStandaloneShopFrame()?rows.find(row=>!row.evaluationId):rows[0];
   if(!reference)throw Error('No saved listing assessment');
   if(await digest([reference.rewriteOperationId,reference.saveOperationId])!==reference.digest)throw Error('Saved listing reference changed');
   if(!current(e,token,fetcher))throw Error('Listings session changed');
   const retry=!!reference.retryRequestId;
   if(retry&&isStandaloneShopFrame())throw Error('Open saved assessments to review Judge retry eligibility.');
   const response=await fetcher('/api/secureshop/merchant/listings/'+(retry?'browser-retry':'browser-attempt'),{method:'POST',signal:c.signal,headers:{'content-type':'application/json'},body:JSON.stringify({requestId:retry?reference.retryRequestId:reference.requestId,rewriteOperationId:reference.rewriteOperationId,saveOperationId:reference.saveOperationId,...(retry?{evaluationId:reference.evaluationId}:{})})});
   const value=await response.json();if(!current(e,token,fetcher))throw Error('Listings session changed');
   if(retry&&response.status===409&&['EVIDENCE_EXPIRED','RETRY_NOT_ALLOWED','RETRY_EXHAUSTED','MODE_CHANGED'].includes(value.code)){
    await remember('assessment',(pending.current.assessment||[]).filter(row=>row.requestId!==reference.requestId));
    throw Error('Listing saved; this assessment can no longer be retried.');
   }
   if(!response.ok||typeof value.completed!=='boolean')throw Error('Listing saved; assessment unavailable. Use Check saved listing to retry.');
   const deferred=value.status==='disabled',ineligible=value.status==='ineligible';
   if((deferred||ineligible)&&value.completed!==false)throw Error('Invalid listing assessment');
   if(!deferred&&!ineligible&&(value.rewriteOperationId!==reference.rewriteOperationId||value.saveOperationId!==reference.saveOperationId||!Number.isSafeInteger(value.productId)||value.productId<1||!value.judgment))throw Error('Invalid listing assessment');
   if(value.judgment?.verdict==='unavailable'&&value.judgment?.canRetry===true){
    if(retry||!UUID.test(value.judgment.evaluationId)||value.completed)throw Error('Invalid Judge retry receipt');
    const next=(pending.current.assessment||[]).map(row=>row.requestId===reference.requestId?{...row,evaluationId:value.judgment.evaluationId,retryRequestId:crypto.randomUUID()}:row);
    await remember('assessment',next);
   }else if(!deferred){const next=(pending.current.assessment||[]).filter(row=>row.requestId!==reference.requestId);await remember('assessment',next);}
   return value;
  }finally{controllers.current.delete(c);if(current(e,token,fetcher)){inFlight.current=false;setBusy(false);}}
 }
 async function templateOperation(productId){
  if(!capability||inFlight.current||capabilityIdentity.current?.authToken!==authToken
     ||capabilityIdentity.current?.transport!==transport||capabilityIdentity.current?.epoch!==epoch.current)
   throw Error('Listings unavailable or busy');
  const e=epoch.current,token=authToken,fetcher=transport,c=new AbortController();controllers.current.add(c);inFlight.current=true;setBusy(true);
  try{
   let reference=pending.current.template,newlyCreated=false;
   if(reference){
    if(productId!==undefined&&productId!==reference.productId)throw Error('Check the saved template render before starting another product.');
   }else{
    if(!templateReady)throw Error('Template rendering is unavailable.');
    if(!Number.isSafeInteger(productId)||productId<1||productId>2147483647)throw Error('Invalid listing product');
    reference={scopeKey:capability.scopeKey,operationId:crypto.randomUUID(),productId,digest:await digest([productId])};
    if(!current(e,token,fetcher))throw Error('Listings session changed');
    await remember('template',reference);
    newlyCreated=true;
   }
   if(!current(e,token,fetcher))throw Error('Listings session changed');
   if(await digest([reference.productId])!==reference.digest)throw Error('Saved template render reference changed.');
   if(!current(e,token,fetcher))throw Error('Listings session changed');
   // A saved reference always recovers by GET. Only this newly persisted reference may POST.
   const response=await fetcher(newlyCreated?'/api/secureshop/merchant/listings/template-render':
    `/api/secureshop/merchant/listings/template-operations/${reference.operationId}`,
   {method:newlyCreated?'POST':'GET',signal:c.signal,...(newlyCreated?{headers:{'content-type':'application/json'},body:JSON.stringify({operationId:reference.operationId,productId:reference.productId})}:{})});
   const value=await response.json();if(!current(e,token,fetcher))throw Error('Listings session changed');
   if(response.status===409&&value?.code==='LISTING_MODE_TARGET_CONFLICT')
    throw Error('This template belongs to another mode. Switch back to check its saved outcome, or ask a shop administrator to reset the shared practice.');
   if(!response.ok||value?.operationId!==reference.operationId||value.productId!==reference.productId
      ||typeof value.ok!=='boolean'||!['admitted','running','effect_received','unknown','completed','declined','denied'].includes(value.state)
      ||response.status!==(['completed','declined','denied'].includes(value.state)?200:202)
      ||value.ok!==(value.state==='completed')
      ||(value.state==='completed'?typeof value.commandEffectObserved!=='boolean':Object.hasOwn(value,'commandEffectObserved')))
    throw Error('Template render outcome unresolved; check the saved operation.');
   return value;
  }finally{controllers.current.delete(c);if(current(e,token,fetcher)){inFlight.current=false;setBusy(false);}}
 }
 async function clear(action){if(inFlight.current)return;const next={...pending.current};delete next[action];await persist(next);}
 return{attached,ready:!!capability,readinessChecking,readinessError,retryReadiness,
  templateReady,templateChecking,templateError,retryTemplateReadiness,templateOperation,
  busy,references,assessSaved,run:(action,payload)=>perform(action,payload),recover:(action,payload)=>perform(action,payload||null,'recover'),resume:()=>perform('import',null,'resume'),clear};
}
