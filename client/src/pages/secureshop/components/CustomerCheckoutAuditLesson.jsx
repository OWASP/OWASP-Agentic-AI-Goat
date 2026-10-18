import React,{useEffect,useState} from 'react';
import {useCustomerCheckoutAuditLesson} from '../hooks/useCustomerCheckoutAuditLesson.js';
import {createCustomerCheckoutAuditReferenceStore} from '../utils/customerCheckoutAuditReference.mjs';
import {flushShopStorage,shopStorage} from '../utils/shopStorage.mjs';

const references=createCustomerCheckoutAuditReferenceStore({storage:shopStorage,flush:flushShopStorage});
const money=value=>`$${Number(value).toFixed(2)}`;

export default function CustomerCheckoutAuditLesson({shopUserId,authorityKey,
 transport=globalThis.fetch,referenceStore=references}){
 const lesson=useCustomerCheckoutAuditLesson({shopUserId,authorityKey,transport,referenceStore});
 const[teachingToken,setTeachingToken]=useState('');
 useEffect(()=>setTeachingToken(lesson.prepared?.token.token||''),[lesson.prepared]);
 const tokenReady=teachingToken.length>0&&new TextEncoder().encode(teachingToken).byteLength<=4096;
 const mode=lesson.result?.modeCapability.effectiveMode
  ||lesson.prepared?.token.modeCapability.effectiveMode||null;
 return <section aria-label="Checkout audit teaching-token lesson">
  <p>Select one of your completed checkouts, then give its synthetic teaching token to the customer assistant.
   The token works only inside this lesson and cannot sign in or grant platform access.</p>
  <div className="ss-mono" style={{fontSize:11,color:'var(--copper)'}}>
   Synthetic checkout-audit lesson · {mode==='vuln'?'Vulnerable mode':mode==='fixed'?'Fixed mode':'Mode unavailable'}
  </div>
  {lesson.status==='loading'&&<p role="status">Loading your completed checkouts…</p>}
  {!lesson.reference&&lesson.operations.map(operation=><article className="ss-card"
   key={operation.operationId} style={{padding:12,marginTop:8}}>
   <strong>Order #{operation.orderId}</strong>
   <span className="ss-mono" style={{display:'block',fontSize:11}}>
    Completed {new Date(operation.createdAt).toLocaleString()} · {operation.operationId}
   </span>
   <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.prepare(operation.operationId)}>
    Get synthetic teaching token
   </button>
  </article>)}
  {lesson.status==='ready'&&!lesson.operations.length&&<p role="status">
   Complete a storefront checkout before starting this lesson.</p>}
  {lesson.prepared&&!lesson.reference&&<section className="ss-card" style={{padding:12,marginTop:10}}
   aria-label="Synthetic checkout audit token">
   <p>Selected Order #{lesson.prepared.receipt.order.id} · {money(lesson.prepared.receipt.order.total)}</p>
   <label htmlFor="checkout-audit-teaching-token">Editable synthetic teaching token</label>
   <textarea id="checkout-audit-teaching-token" className="ss-lane__input" rows={4}
    value={teachingToken} maxLength={4096} onChange={event=>setTeachingToken(event.target.value)}
    style={{width:'100%',boxSizing:'border-box',marginTop:5}} />
   <p className="ss-mono" style={{fontSize:11}}>
    Edit this practice JWT to test the isolated verifier · no platform credentials
   </p>
   <button type="button" className="ss-btn" disabled={lesson.busy||!tokenReady}
    onClick={()=>void lesson.run(teachingToken)}>
    Ask assistant to inspect checkout audit
   </button>
  </section>}
  {lesson.reference&&<section className="ss-card" style={{padding:12,marginTop:10}}
   aria-label="Saved checkout audit request">
   <p className="ss-mono">Saved checkout-audit request · {lesson.status}</p>
   {lesson.result?.text&&<p role="status" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{lesson.result.text}</p>}
   {lesson.result?.result?.status==='disclosed'&&<p role="status">
    Protected audit read observed for Order #{lesson.result.result.report.orderId}
    {' · '}{money(lesson.result.result.report.total)}.</p>}
   {lesson.result?.result?.status==='denied'&&<p role="status">{mode==='fixed'
    ?'Fixed-mode policy denied the protected audit read.'
    :'The practice verifier denied the supplied synthetic token.'}</p>}
   {lesson.result?.result===null&&lesson.status==='completed'&&<p role="status">
    The assistant completed without using the audit tool.</p>}
   {lesson.status==='completed'&&['disclosed','denied'].includes(lesson.result?.result?.status)
    &&!lesson.assessmentAdmissionAttempted&&!lesson.assessmentReference
    &&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
     disabled={lesson.busy} onClick={()=>void lesson.assess()}>Assess saved checkout audit</button>}
   {lesson.assessmentReference&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.recoverAssessment()}>Check saved checkout-audit assessment</button>}
   {lesson.assessmentKnownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.discardUnsentAssessment()}>
    Discard unsent assessment admission
   </button>}
   {lesson.assessment?.status==='unconfirmed'&&<p role="status">
    Assessment is unconfirmed. Check the saved assessment; the grading request will not be repeated.</p>}
   {lesson.assessment?.status==='ineligible'&&<p role="status">
    This saved request is not eligible for objective credit.</p>}
   {lesson.assessment?.judgment&&<p role="status">{lesson.assessment.judgment.verdict==='unavailable'
    ?'Grading unavailable. The saved request remains available.'
    :lesson.assessment.completed===true&&lesson.assessment.judgment.verdict==='pass'
     ?'Objective completed in canonical progress.'
     :'Assessment recorded without objective credit.'}</p>}
   {lesson.status!=='completed'&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.recover()}>Check saved request</button>}
   {lesson.status==='completed'&&(!lesson.assessmentAdmissionAttempted
    ||lesson.assessmentReference&&(lesson.assessment?.judgment||lesson.assessment?.status==='ineligible'))
    &&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.startNew()}>Start another checkout-audit lesson</button>}
  </section>}
  {lesson.busy&&<p role="status">Checking the original lesson request…</p>}
  {lesson.error&&<p role="alert" style={{color:'var(--rust)'}}>{lesson.error}</p>}
  <p className="ss-mono" style={{fontSize:11}}>This screen reports the saved interaction only. It does not award objective credit.</p>
 </section>;
}
