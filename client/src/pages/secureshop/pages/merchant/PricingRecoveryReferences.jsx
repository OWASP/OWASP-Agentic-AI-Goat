import React,{useEffect,useRef,useState} from 'react';

export default function PricingRecoveryReferences({references,scopeKey,authToken,busy,forget,panelStyle}){
 const [selected,setSelected]=useState(null),[error,setError]=useState(''),epoch=useRef(0);
 useEffect(()=>{epoch.current++;setSelected(null);setError('');return()=>{epoch.current++;};},[scopeKey,authToken]);
 if(!references.length)return null;
 const confirm=async()=>{const current=epoch.current;try{await forget(selected);if(epoch.current===current){setSelected(null);setError('');}}catch(reason){if(epoch.current===current)setError(reason.message);}};
 return <section style={panelStyle} aria-label="Earlier Pricing recovery references">
  <details>
   <summary>Earlier session recovery references ({references.length})</summary>
   <p>These nonsecret identifiers belong to earlier persona sessions in this launch. Select and copy them before removing a local reference. Original authority may be required for server readback.</p>
   {references.map(reference=><div key={reference.scopeKey+reference.operationId} style={{marginTop:12,overflowWrap:'anywhere'}}>
    <p>Operation: <code style={{userSelect:'text'}}>{reference.operationId}</code><br/>Scope: <code style={{userSelect:'text'}}>{reference.scopeKey}</code><br/>Request digest: <code style={{userSelect:'text'}}>{reference.requestSha256}</code></p>
    <button className="ss-btn" disabled={busy} onClick={()=>{setSelected({...reference});setError('');}}>Review local removal</button>
   </div>)}
  </details>
  {selected&&<div role="dialog" aria-labelledby="pricing-forget-title" aria-describedby="pricing-forget-description" style={{marginTop:16,overflowWrap:'anywhere'}}>
   <h3 id="pricing-forget-title">Forget this local reference?</h3>
   <p id="pricing-forget-description">This does not cancel, publish, verify or delete the server operation. Original authority may be required to recover it. Other references and the current draft stay unchanged.</p>
   <p><code style={{userSelect:'text'}}>{selected.operationId}</code><br/><code style={{userSelect:'text'}}>{selected.scopeKey}</code></p>
   <div style={{display:'flex',flexWrap:'wrap',gap:8}}>
    <button className="ss-btn" autoFocus disabled={busy} onClick={()=>{setSelected(null);setError('');}}>Cancel</button>
    <button className="ss-btn" disabled={busy} onClick={confirm}>Forget local reference</button>
   </div>
   {error&&<p role="alert">{error}</p>}
  </div>}
 </section>;
}
