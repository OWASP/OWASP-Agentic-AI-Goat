import React,{useCallback,useEffect,useRef,useState}from'react';
import{isStandaloneShopFrame,openStandaloneAssessments}from'../bridge/assessmentPanelIntent.mjs';
import{createMerchantMailReadAssessmentStore}from'../utils/merchantMailReadAssessmentReference.mjs';
import{flushShopStorage,shopStorage}from'../utils/shopStorage.mjs';
const BASE='/api/secureshop/agents/merchant/assistant/mail-read';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const defaults=createMerchantMailReadAssessmentStore({storage:shopStorage,flush:flushShopStorage});
const same=(saved,shopUserId,source)=>saved?.shopUserId===shopUserId&&saved.sessionId===source.sessionId&&saved.requestId===source.requestId;
export function decodeV11MailReadAssessment(value){
 if(value?.status==='unavailable'){if(!exact(value,['completed','status','modelEvaluated','reason'])||value.completed!==false||value.modelEvaluated!==false||value.reason!=='evidence_size_limit')throw Error('Agent mail-read assessment unavailable');return Object.freeze({...value});}
 if(value?.status){if(!exact(value,['completed','status','modelEvaluated'])||value.completed!==false||!['ineligible','unconfirmed'].includes(value.status)||value.modelEvaluated!==false)throw Error('Agent mail-read assessment unavailable');return Object.freeze({...value});}
 if(!exact(value,['completed','judgment','replayed'])||typeof value.completed!=='boolean'||typeof value.replayed!=='boolean'
  ||!exact(value.judgment,['verdict','evaluationId','canRetry'])||!['pass','fail','inconclusive','unavailable'].includes(value.judgment.verdict)
  ||!UUID.test(value.judgment.evaluationId||'')||typeof value.judgment.canRetry!=='boolean'||value.completed&&value.judgment.verdict!=='pass')throw Error('Agent mail-read assessment unavailable');
 return Object.freeze({...value,judgment:Object.freeze({...value.judgment})});
}
async function outcome(response){if(!response?.ok||!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type')||''))throw Error('Agent mail-read assessment unavailable');return decodeV11MailReadAssessment(await response.json());}
export default function V11MailReadAssessment({scopeKey,shopUserId,source,currentTurn=false,locked=false,transport=globalThis.fetch,store=defaults}){
 const[reference,setReference]=useState(null),[result,setResult]=useState(null),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false),[latched,setLatched]=useState(false),[revision,setRevision]=useState(0);
 const mounted=useRef(false),epoch=useRef(0),active=useRef(null),saved=useRef(null);
 const valid=Number.isSafeInteger(shopUserId)&&shopUserId>0&&UUID.test(source?.sessionId||'')&&UUID.test(source?.requestId||'');
 const current=useCallback((version,controller)=>mounted.current&&epoch.current===version&&active.current===controller&&!controller.signal.aborted,[]);
 const read=useCallback(async(ref,controller,version)=>{const value=await outcome(await transport(`${BASE}/assessment/${ref.sessionId}/${ref.requestId}`,{method:'GET',headers:{accept:'application/json'},signal:controller.signal}));if(value.judgment&&value.replayed!==true)throw Error('Agent mail-read assessment unavailable');if(!current(version,controller))return false;setResult(value);return true;},[transport,current]);
 useEffect(()=>{mounted.current=true;const version=++epoch.current;active.current?.abort();active.current=null;saved.current=null;setReference(null);setResult(null);setNotice('');setBusy(false);setLatched(false);
  if(!Number.isSafeInteger(shopUserId)||shopUserId<1||!UUID.test(source?.sessionId||'')||!UUID.test(source?.requestId||''))return()=>{mounted.current=false;++epoch.current;};
  let ref;try{ref=store.read(scopeKey);}catch{setLatched(true);setNotice('Saved agent mail-read assessment unavailable.');return()=>{mounted.current=false;++epoch.current;};}
  if(ref&&!same(ref,shopUserId,source)){if(currentTurn){setLatched(true);setNotice('Finish the saved agent mail-read assessment on its original turn first.');}return()=>{mounted.current=false;++epoch.current;};}
  saved.current=ref;setReference(ref);setLatched(Boolean(ref));if(ref){const controller=new AbortController();active.current=controller;void read(ref,controller,version).catch(()=>{if(current(version,controller))setNotice('Check the saved agent mail-read assessment.');}).finally(()=>{if(active.current===controller)active.current=null;});}
  return()=>{mounted.current=false;++epoch.current;active.current?.abort();active.current=null;};
 },[scopeKey,shopUserId,source?.sessionId,source?.requestId,currentTurn,transport,store,read,current,revision]);
 useEffect(()=>{const changed=event=>{if(event.detail===scopeKey)setRevision(value=>value+1);};window.addEventListener('secureshop-v11-mail-read-assessment',changed);return()=>window.removeEventListener('secureshop-v11-mail-read-assessment',changed);},[scopeKey]);
 const assess=async()=>{if(saved.current||active.current||locked||!mounted.current)return false;const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setNotice('');let own=null;
  try{const ref=await store.submit(scopeKey,{shopUserId,sessionId:source.sessionId,requestId:source.requestId,startedAt:Date.now()},()=>current(version,controller),value=>{own=value;saved.current=value;setReference(value);setLatched(true);});if(!current(version,controller))return false;
   try{const value=await outcome(await transport(`${BASE}/assess`,{method:'POST',headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({sessionId:ref.sessionId,requestId:ref.requestId}),signal:controller.signal}));if(!current(version,controller))return false;setResult(value);return true;}catch{return await read(ref,controller,version);}
  }catch{if(current(version,controller)){let retained=null;try{retained=store.read(scopeKey);}catch{}if(retained&&same(retained,shopUserId,source)){saved.current=retained;setReference(retained);setLatched(true);setNotice('Agent mail-read assessment unresolved. Check the saved assessment.');}else{setLatched(Boolean(own));setNotice('Agent mail-read assessment was not admitted.');}}return false;}
  finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}
 };
 const recover=async()=>{const ref=saved.current;if(!ref||active.current||!mounted.current)return false;const controller=new AbortController(),version=epoch.current;active.current=controller;setBusy(true);setNotice('');try{return await read(ref,controller,version);}catch{if(current(version,controller))setNotice('Saved agent mail-read assessment unavailable.');return false;}finally{if(current(version,controller))setBusy(false);if(active.current===controller)active.current=null;}};
 const terminal=Boolean(result?.judgment||['ineligible','unavailable'].includes(result?.status));
 const retire=async()=>{const ref=saved.current,version=epoch.current;if(!ref||!terminal||active.current||!mounted.current)return false;setBusy(true);setNotice('');const fresh=()=>mounted.current&&epoch.current===version&&saved.current===ref;try{await store.clear(scopeKey,ref,fresh);if(!fresh())return false;saved.current=null;setReference(null);setResult(null);setLatched(false);window.dispatchEvent(new CustomEvent('secureshop-v11-mail-read-assessment',{detail:scopeKey}));return true;}catch{if(fresh())setNotice('Saved agent mail-read assessment cleanup is unavailable.');return false;}finally{if(mounted.current&&epoch.current===version)setBusy(false);}};
 if(!valid)return null;
 if(!currentTurn&&!reference&&!latched&&!notice)return null;
 return <section aria-label="Agent-selected mail assessment" style={{marginTop:10}}>
  {!reference&&!latched&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={busy||locked} onClick={()=>void assess()}>{busy?'Assessing saved agent mail read…':'Assess agent-selected mail'}</button>}
  {reference&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={busy} onClick={()=>void recover()}>{busy?'Checking saved agent mail-read assessment…':'Check saved agent mail-read assessment'}</button>}
  {result?.status==='unconfirmed'&&<p role="status">Assessment is unconfirmed. Check the saved result; grading will not be repeated.</p>}
  {result?.status==='ineligible'&&<p role="status">This agent-selected mail read is not eligible for objective credit.</p>}
  {result?.status==='unavailable'&&<p role="status">The saved mail evidence is too large for grading.</p>}
  {result?.judgment&&<p role="status">{result.judgment.verdict==='unavailable'?'Grading is unavailable.':result.completed?'Objective completed in canonical progress.':'The Judge did not award objective credit.'}</p>}
  {result?.judgment?.canRetry&&isStandaloneShopFrame()&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={()=>openStandaloneAssessments(result.judgment.evaluationId)}>Open saved assessments</button>}
  {terminal&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={busy} onClick={()=>void retire()}>Finish saved agent mail-read assessment</button>}
  {notice&&<p role="alert">{notice}</p>}
 </section>;
}
