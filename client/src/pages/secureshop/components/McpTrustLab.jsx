import React, { useCallback, useEffect, useRef, useState } from 'react';

const ENDPOINT='/api/secureshop/v2/mcp-trust';
const EMPTY=Object.freeze({rogue_registration:false,rug_pull:false});
async function request(path,options){const response=await fetch(`${ENDPOINT}${path}`,options);
  const body=await response.json().catch(()=>({}));if(!response.ok)throw new Error(body.error||'MCP trust exercise unavailable');return body;}
function actionBody(value){return{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)};}

export default function McpTrustLab({showToast=()=>{}}){
  const [state,setState]=useState(null),[error,setError]=useState(null),[busy,setBusy]=useState(null);
  const [observations,setObservations]=useState({});const mounted=useRef(true),generation=useRef(0),pending=useRef(null);
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;generation.current++;pending.current?.abort();};},[]);
  const refresh=useCallback(async()=>{const id=++generation.current;pending.current?.abort();const controller=new AbortController();
    pending.current=controller;setError(null);
    try{const next=await request('/readiness',{signal:controller.signal});if(mounted.current&&id===generation.current)setState(next);}
    catch(cause){if(mounted.current&&id===generation.current&&!controller.signal.aborted)setError(cause.message);}
    finally{if(pending.current===controller)pending.current=null;}},[]);
  useEffect(()=>{void refresh();},[refresh]);
  const act=useCallback(async(key,path,body)=>{if(busy)return;const id=++generation.current;pending.current?.abort();
    const controller=new AbortController();pending.current=controller;setBusy(key);setError(null);
    try{const result=await request(path,{...actionBody(body),signal:controller.signal});if(!mounted.current||id!==generation.current)return;
      setObservations(previous=>({...previous,[key]:result}));showToast('Controlled MCP observation completed','success');
      const next=await request('/readiness',{signal:controller.signal});if(mounted.current&&id===generation.current)setState(next);
    }catch(cause){if(mounted.current&&id===generation.current&&!controller.signal.aborted){setError(cause.message);showToast(cause.message,'error');}}
    finally{if(pending.current===controller)pending.current=null;if(mounted.current&&id===generation.current)setBusy(null);}},[busy,showToast]);
  if(!state?.ready&&!error)return null;
  const enabled=state?.scenarios||EMPTY;
  return <section aria-label="Controlled MCP trust lab" style={{marginBottom:40,border:'1px solid var(--rule)',padding:16}}>
    <div style={{display:'flex',justifyContent:'space-between',gap:16,alignItems:'start'}}>
      <div><div className="ss-card__meta">OWNED TRUST LAB</div><h2 className="ss-shelf__title" style={{margin:'4px 0'}}>Registration and schema trust</h2>
        <p className="ss-mono" style={{fontSize:11,opacity:.72,maxWidth:'80ch',margin:0}}>
          Compare a newly registered unapproved connector with an approved connector whose schema changes under the same server identity.
        </p></div>
      <button className="ss-btn ss-btn--ghost" onClick={refresh} disabled={Boolean(busy)}>refresh availability</button>
    </div>
    {error&&<div role="alert" className="ss-mono" style={{marginTop:12,color:'var(--rust)'}}>{error}</div>}
    {!state?.ready?<p className="ss-mono" style={{fontSize:11,opacity:.65}}>This controlled exercise is currently unavailable.</p>:
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(260px,1fr))',gap:12,marginTop:16}}>
        <Lesson title="Unapproved registration" enabled={enabled.rogue_registration} result={observations.rogue_registration}
          controls={<><button className="ss-btn ss-btn--ghost" disabled={Boolean(busy)||Boolean(error)||!enabled.rogue_registration}
            onClick={()=>act('rogue_registration','/discover',{scenario:'rogue_registration'})}>discover connector</button>
          <button className="ss-btn" disabled={Boolean(busy)||Boolean(error)||!enabled.rogue_registration}
            onClick={()=>act('rogue_registration','/run',{scenario:'rogue_registration',request_id:crypto.randomUUID()})}>ask supervisor</button></>}/>
        <Lesson title="Approved-server rug pull" enabled={enabled.rug_pull} result={observations.rug_pull}
          controls={<><button className="ss-btn ss-btn--ghost" disabled={Boolean(busy)||Boolean(error)||!enabled.rug_pull}
            onClick={()=>act('rug_pull','/discover',{scenario:'rug_pull'})}>discover baseline</button>
          <button className="ss-btn ss-btn--ghost" disabled={Boolean(busy)||Boolean(error)||!enabled.rug_pull}
            onClick={()=>act('rug_pull','/rotate',{})}>publish changed schema</button>
          <button className="ss-btn" disabled={Boolean(busy)||Boolean(error)||!enabled.rug_pull}
            onClick={()=>act('rug_pull','/run',{scenario:'rug_pull',request_id:crypto.randomUUID()})}>ask supervisor</button></>}/>
      </div>}
  </section>;
}

function Lesson({title,enabled,result,controls}){return <article style={{border:'1px solid var(--rule)',padding:12}}>
  <div style={{display:'flex',justifyContent:'space-between',gap:8}}><strong>{title}</strong>
    <span className="ss-mono" style={{fontSize:10,color:enabled?'var(--signal)':'var(--rust)'}}>{enabled?'available':'disabled'}</span></div>
  <div style={{display:'flex',flexWrap:'wrap',gap:8,marginTop:12}}>{controls}</div>
  {result&&<div className="ss-mono" style={{fontSize:11,marginTop:12}}>
    {result.text||`schema v${result.schemaVersion} · #${String(result.schemaSha256||'').slice(0,8)}`}
  </div>}
</article>;}
