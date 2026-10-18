import {useEffect,useRef,useState} from 'react';
import {getBridgeFetchMetadata} from '../../bridge/fetchAdapter.mjs';
import {pricingBlockedResult,pricingRequestDigest,pricingResult} from './pricingOperation.mjs';
import {trustedTurnMode} from '../../utils/turnModeCapability.mjs';
import {readPricingReferences,savePricingReference,clearPricingReference,forgetForeignPricingReference} from './pricingRecovery.mjs';
export function useBoundPricing(authToken,transport){
 const attached=!!getBridgeFetchMetadata(transport),epoch=useRef(0),controllers=useRef(new Set()),live=useRef({authToken,transport});
 live.current={authToken,transport};
 const [administration,setAdministration]=useState(null),[references,setReferences]=useState([]),[busy,setBusy]=useState(false),[notice,setNotice]=useState(''),[result,setResult]=useState(null),[unadmitted,setUnadmitted]=useState(null);
 const inFlight=useRef(false),originalRequests=useRef(new Map());
 const valid=(e,token,fetcher)=>epoch.current===e&&live.current.authToken===token&&live.current.transport===fetcher;
 useEffect(()=>{
  const e=++epoch.current,controller=new AbortController();controllers.current.add(controller);
  setAdministration(null);setResult(null);setNotice('');setReferences([]);setUnadmitted(null);setBusy(false);inFlight.current=false;
  originalRequests.current.clear();
  if(attached){
   Promise.resolve().then(()=>{setReferences(readPricingReferences());return transport('/api/secureshop/merchant/pricing/run',{signal:controller.signal});})
    .then(async response=>{const value=await response.json();if(!response.ok||value.ok!==true||value.administration?.versionedPricing!==true||!/^[a-f0-9]{64}$/.test(value.administration.scopeKey))throw Error('Bound Pricing unavailable');if(valid(e,authToken,transport))setAdministration(value.administration);})
    .catch(error=>{if(valid(e,authToken,transport)&&!controller.signal.aborted)setNotice(error.message);}).finally(()=>controllers.current.delete(controller));
  }
  return()=>{epoch.current++;originalRequests.current.clear();for(const c of controllers.current)c.abort();controllers.current.clear();};
 },[authToken,transport,attached]);
 const currentReferences=references.filter(x=>x.scopeKey===administration?.scopeKey);
 async function perform(reference,request){
  const e=epoch.current,token=authToken,fetcher=transport,controller=new AbortController();controllers.current.add(controller);
  const current=()=>valid(e,token,fetcher)&&!controller.signal.aborted;
  try{
   const response=await fetcher(request?'/api/secureshop/merchant/pricing/run':`/api/secureshop/merchant/pricing/operations/${reference.operationId}`,{
    method:request?'POST':'GET',signal:controller.signal,...(request?{headers:{'content-type':'application/json'},body:JSON.stringify(request)}:{})});
   let body=await response.json();if(!current())return;
   if(!response.ok&&![202,404].includes(response.status))throw Error('Pricing outcome is unresolved; use Check saved operation.');
   if(request&&body.state==='blocked'){
    const saved=await fetcher(`/api/secureshop/merchant/pricing/operations/${reference.operationId}`,
     {method:'GET',signal:controller.signal});
    if(!current())return;
    if(!saved.ok)throw Error('Blocked Pricing readback unavailable; use Check saved operation.');
    body=await saved.json();if(!current())return;
   }
   const value=body.state==='blocked'
    ?await pricingBlockedResult(body,reference,request?.competitorUrl):pricingResult(body,reference);
   if(!current())return;
   if(value.state==='completed'||value.state==='not_executed'||value.state==='blocked'){
    const remaining=await clearPricingReference(reference);if(!current())return;setReferences(remaining);
    setUnadmitted(null);
    originalRequests.current.delete(reference.operationId);
    setResult({...value,action:reference.action,productId:reference.productId,modeCapability:trustedTurnMode(body.modeCapability)});
    setNotice(value.state==='blocked'
     ?'Comparison blocked by fixed-mode policy. No competitor request was made.'
     :value.state==='completed'?'Pricing operation completed. Objective completion is shown in Exercise objectives.'
      :'This admitted request was not executed.');
   }else{
    setUnadmitted(!request&&value.state==='not_found'?reference:null);
    setNotice(`Operation ${reference.operationId}: ${value.state}. Readback does not resend the request.`);
   }
  }catch(error){if(current())setNotice(error.message);}
  finally{controllers.current.delete(controller);if(current()){inFlight.current=false;setBusy(false);}}
 }
 async function run(action,productId,message,experiment,competitorUrl){
  if(!administration||inFlight.current||currentReferences.length)return;
  inFlight.current=true;setBusy(true);setResult(null);setUnadmitted(null);setNotice('');
  const e=epoch.current,token=authToken,fetcher=transport;
  const body={operationId:crypto.randomUUID(),productId,message,...(experiment?{experiment}:{}),
   ...(competitorUrl!==undefined?{competitorUrl}:{})};
  try{
   const reference={scopeKey:administration.scopeKey,operationId:body.operationId,productId,action,requestSha256:await pricingRequestDigest(body)};
   if(!valid(e,token,fetcher))return;
   const next=await savePricingReference(reference);if(!valid(e,token,fetcher))return;setReferences(next);
   originalRequests.current.set(reference.operationId,body);
   await perform(reference,body);
  }catch(error){if(valid(e,token,fetcher)){setNotice(error.message);inFlight.current=false;setBusy(false);}}
 }
 async function recover(reference){
  if(!administration||reference.scopeKey!==administration.scopeKey||inFlight.current)return;
  inFlight.current=true;setBusy(true);setUnadmitted(null);await perform(reference);
 }
 async function retryUnadmitted(reference,message,experiment,competitorUrl){
  if(!administration||reference.scopeKey!==administration.scopeKey||inFlight.current
   ||!unadmitted||!['scopeKey','operationId','productId','action','requestSha256']
    .every(key=>reference[key]===unadmitted[key]))return;
  inFlight.current=true;setBusy(true);
  const e=epoch.current,token=authToken,fetcher=transport;
  const body=originalRequests.current.get(reference.operationId)||{operationId:reference.operationId,
   productId:reference.productId,message,...(experiment?{experiment}:{}),
   ...(competitorUrl!==undefined?{competitorUrl}:{})};
  try{
   if(await pricingRequestDigest(body)!==reference.requestSha256)
    throw Error('The original Pricing request cannot be reconstructed. The saved reference is retained.');
   if(!valid(e,token,fetcher))return;
   setUnadmitted(null);
   await perform(reference,body);
  }catch(error){if(valid(e,token,fetcher))setNotice(error.message);}
  finally{if(valid(e,token,fetcher)){inFlight.current=false;setBusy(false);}}
 }
 async function forget(reference){
  if(!administration||inFlight.current)throw Error('Pricing recovery is busy or unavailable');
  const e=epoch.current,token=authToken,fetcher=transport;
  inFlight.current=true;setBusy(true);
  try{
   const next=await forgetForeignPricingReference(reference,administration.scopeKey);
   if(valid(e,token,fetcher)){setReferences(next);setNotice('Local recovery reference forgotten. The server operation is unchanged.');}
  }finally{if(valid(e,token,fetcher)){inFlight.current=false;setBusy(false);}}
 }
 return{attached,ready:!!administration,administration,references:currentReferences,foreignCount:references.length-currentReferences.length,foreignReferences:administration?references.filter(x=>x.scopeKey!==administration.scopeKey):[],forget,busy,notice,result,run,recover,retryUnadmitted,unadmittedOperationId:unadmitted?.operationId||null,locked:attached&&(!administration||busy||currentReferences.length>0)};
}
