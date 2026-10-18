import {useEffect,useRef,useState} from 'react';
import {getBridgeFetchMetadata} from '../../bridge/fetchAdapter.mjs';
import {isStandaloneShopFrame} from '../../bridge/assessmentPanelIntent.mjs';
import {shopStorage,flushShopStorage,SHOP_INVENTORY_KEY} from '../../utils/shopStorage.mjs';
import {decodeInventoryReference,validStockChange,
 sameInventoryReference as sameReference} from './inventoryReference.mjs';
const digest=async message=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(message)))].map(x=>x.toString(16).padStart(2,'0')).join('');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function historyList(value){
 if(value?.ok!==true||!Array.isArray(value.operations)||value.operations.length>20||value.operations.some(row=>
  !UUID.test(row?.requestId||'')||!Number.isFinite(Date.parse(row?.recordedAt))||!['vuln','fixed'].includes(row?.mode)||row?.status!=='completed'))throw Error('Saved inventory history is unavailable.');
 return value.operations;
}
function historyReceipt(value,requestId){
 if(value?.ok!==true||value.status!=='completed'||value.historical!==true||value.requestId!==requestId||
  !['vuln','fixed'].includes(value.mode)||typeof value.answer!=='string'||!Array.isArray(value.operations))throw Error('Saved inventory result is unavailable.');
 return value;
}
export function useBoundInventory(token,transport){
 const attached=!!getBridgeFetchMetadata(transport),epoch=useRef(0),live=useRef({token,transport}),pending=useRef(null),foreign=useRef(null),inflight=useRef(false),historyInflight=useRef(false),controllers=useRef(new Set());live.current={token,transport};
 const [capability,setCapability]=useState(null),[reference,setReference]=useState(null),[foreignReference,setForeignReference]=useState(null),[busy,setBusy]=useState(false),[result,setResult]=useState(null),[error,setError]=useState(null);
 const [history,setHistory]=useState([]),[historyBusy,setHistoryBusy]=useState(false),[historyError,setHistoryError]=useState(null),[historicalResult,setHistoricalResult]=useState(null);
 const current=(e,t,f)=>epoch.current===e&&live.current.token===t&&live.current.transport===f;
 useEffect(()=>{const e=++epoch.current,c=new AbortController();controllers.current.add(c);pending.current=null;foreign.current=null;inflight.current=false;historyInflight.current=false;setCapability(null);setReference(null);setForeignReference(null);setBusy(false);setResult(null);setError(null);setHistory([]);setHistoryBusy(false);setHistoryError(null);setHistoricalResult(null);
  if(attached)transport('/api/secureshop/merchant/inventory/readiness',{signal:c.signal}).then(async r=>{const v=await r.json();if(!current(e,token,transport))return;if(!r.ok||v.ready!==true||!/^[a-f0-9]{64}$/.test(v.scopeKey))return;const saved=decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY));const own=saved?.scopeKey===v.scopeKey?saved:null,prior=saved&&!own?saved:null;pending.current=own;foreign.current=prior;setReference(own);setForeignReference(prior);setCapability(v);setHistoryBusy(true);
   try{const historyResponse=await transport('/api/secureshop/merchant/inventory/history',{signal:c.signal});const historyValue=await historyResponse.json();if(!current(e,token,transport))return;if(!historyResponse.ok)throw Error('Saved inventory history is unavailable.');setHistory(historyList(historyValue));}
   catch(err){if(current(e,token,transport)&&err.name!=='AbortError')setHistoryError('Saved inventory history is unavailable.');}
   finally{if(current(e,token,transport))setHistoryBusy(false);}
  }).catch(err=>{if(current(e,token,transport)&&err.name!=='AbortError')setError('Inventory readiness unavailable.');}).finally(()=>controllers.current.delete(c));
  return()=>{epoch.current++;for(const c of controllers.current)c.abort();controllers.current.clear();};
 },[token,transport,attached]);
 async function readHistory(requestId){
  if(!capability||!UUID.test(requestId||'')||historyInflight.current)throw Error('Saved inventory result is unavailable.');
  const e=epoch.current,t=token,f=transport,c=new AbortController();controllers.current.add(c);historyInflight.current=true;setHistoryBusy(true);setHistoryError(null);
  try{
   const response=await f('/api/secureshop/merchant/inventory/history/'+encodeURIComponent(requestId),{signal:c.signal});const value=await response.json();
   if(!current(e,t,f))throw Error('Inventory session changed.');
   if(!response.ok)throw Error('Saved inventory result is unavailable.');
   const receipt=historyReceipt(value,requestId);setHistoricalResult(receipt);
   if(foreign.current?.requestId===requestId){
   const prior=foreign.current,stored=decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY));
   if(!sameReference(stored,prior))throw Error('Saved inventory reference changed. Check it again.');
    try{
     shopStorage.removeItem(SHOP_INVENTORY_KEY);await flushShopStorage();
     if(!current(e,t,f))throw Error('Inventory session changed.');
     if(decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY)))
      throw Error('Saved inventory reference changed. Check it again.');
    }catch(err){
     if(current(e,t,f))try{
      if(!decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY))){
       shopStorage.setItem(SHOP_INVENTORY_KEY,JSON.stringify(prior));await flushShopStorage();
      }
     }catch{/* The foreign reference remains latched in this hook. */}
     throw err;
    }
    foreign.current=null;setForeignReference(null);
   }
   return receipt;
  }catch(err){if(current(e,t,f))setHistoryError(err.message);throw err;}
  finally{controllers.current.delete(c);if(current(e,t,f)){historyInflight.current=false;setHistoryBusy(false);}}
 }
 async function execute(message,recover=false,retry=false,access='read',stockChange=null){
  if(!capability||inflight.current)throw Error('Inventory unavailable or busy.');
  const e=epoch.current,t=token,f=transport,c=new AbortController();controllers.current.add(c);inflight.current=true;setBusy(true);setError(null);
  const check=()=>{if(!current(e,t,f))throw Error('Inventory session changed.');};
  async function persist(next){
   check();
   const previous=pending.current,stored=decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY));
   if(previous?!sameReference(stored,previous):!!stored)throw Error('Saved inventory reference changed. Check it again.');
   if(next){
    const raw=JSON.stringify(next);decodeInventoryReference(raw);shopStorage.setItem(SHOP_INVENTORY_KEY,raw);
    await flushShopStorage();check();
    if(!sameReference(decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY)),next))
     throw Error('Saved inventory reference changed. Check it again.');
   }else{
    try{
     shopStorage.removeItem(SHOP_INVENTORY_KEY);await flushShopStorage();check();
     if(decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY)))
      throw Error('Saved inventory reference changed. Check it again.');
    }catch(err){
     if(current(e,t,f))try{
      if(!decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY))){
       shopStorage.setItem(SHOP_INVENTORY_KEY,JSON.stringify(previous));await flushShopStorage();
      }
     }catch{/* The exact reference remains latched in this hook. */}
     throw err;
    }
   }
   pending.current=next;setReference(next);
  }
  try{
   let ref=pending.current;
   if(!recover&&!retry){
    if(foreign.current)throw Error('Check the saved prior-session request before sending another inventory request.');
    if(typeof message!=='string'||!message.trim()||new TextEncoder().encode(message).length>8192||!['read','write'].includes(access))throw Error('Enter an inventory request of at most 8192 bytes and choose its access.');
    if(ref&&ref.version!==3)throw Error('This older saved request can be checked but cannot be resent.');
    if(!validStockChange(access,stockChange))throw Error('Select a catalog product and enter its new stock quantity.');
    const admittedChange=access==='write'?{productId:stockChange.productId,quantity:stockChange.quantity}:null;
    const sha=await digest(JSON.stringify({version:3,message,access,stockChange:admittedChange}));check();
    if(ref){if(result?.status!=='not_found'||ref.access!==access||ref.digest!==sha
      ||JSON.stringify(ref.stockChange)!==JSON.stringify(admittedChange))throw Error('Check the saved request before sending another inventory request.');}
    else{ref={version:3,scopeKey:capability.scopeKey,requestId:crypto.randomUUID(),digest:sha,access,stockChange:admittedChange};await persist(ref);}
   }
   check();if(!ref)throw Error('No saved inventory request.');
   if(!sameReference(decodeInventoryReference(shopStorage.getItem(SHOP_INVENTORY_KEY)),ref))
    throw Error('Saved inventory reference changed. Check it again.');
   if(retry&&isStandaloneShopFrame())throw Error('Open saved assessments to review Judge retry eligibility.');
   if(retry&&!ref.evaluationId)throw Error('No saved grading retry.');
   const response=await f('/api/secureshop/merchant/inventory/'+(retry?'judge-retry':recover?'operations/'+ref.requestId:'run'),{method:recover?'GET':'POST',signal:c.signal,...(!recover?{headers:{'content-type':'application/json'},body:JSON.stringify(retry?{requestId:ref.retryRequestId,originalRequestId:ref.requestId,evaluationId:ref.evaluationId}:{requestId:ref.requestId,message,access:ref.access,stockChange:ref.stockChange})}:{})});const value=await response.json();check();
   if(retry&&response.status===409&&['EVIDENCE_EXPIRED','RETRY_NOT_ALLOWED','RETRY_EXHAUSTED','MODE_CHANGED'].includes(value.code)){await persist(null);throw Error('Grading retry is no longer available. Your stock operation was not repeated.');}
   if(!response.ok||value.requestId!==(retry?ref.retryRequestId:ref.requestId)||!['completed','pending','uncertain','not_found'].includes(value.status))throw Error('Inventory outcome unresolved. Check the saved request.');
   if(value.status==='completed'){if(value.ok!==true||(!retry&&(typeof value.answer!=='string'||!Array.isArray(value.operations)))||(retry&&value.originalRequestId!==ref.requestId))throw Error('Invalid inventory receipt.');
    const g=value.grading,j=g?.judgment;
    if(j?.verdict==='unavailable'&&j.canRetry===true){if(retry)throw Error('Invalid grading retry receipt.');const next={...ref,evaluationId:j.evaluationId,retryRequestId:ref.evaluationId===j.evaluationId?ref.retryRequestId:crypto.randomUUID()};decodeInventoryReference(JSON.stringify(next));await persist(next);}
    else if(g?.status!=='disabled'||!ref.evaluationId)await persist(null);
   }
   setResult(retry?prior=>({...prior,status:'completed',grading:value.grading}):value);return value;
  }catch(err){if(current(e,t,f))setError(err.message);throw err;}finally{controllers.current.delete(c);if(current(e,t,f)){inflight.current=false;setBusy(false);}}
 }
 return{attached,ready:!!capability,reference,foreignReference,busy,result,error,history,historyBusy,historyError,historicalResult,readHistory,run:(message,access='read',stockChange=null)=>execute(message,false,false,access,stockChange),recover:()=>execute(null,true),retryGrading:()=>execute(null,false,true)};
}
