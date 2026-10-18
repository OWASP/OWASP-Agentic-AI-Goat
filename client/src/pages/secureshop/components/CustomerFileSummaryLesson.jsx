import React,{useEffect,useRef,useState}from'react';
import{fileSummaryAttachmentError,fileSummaryMessageError,useCustomerFileSummaryLesson}from'../hooks/useCustomerFileSummaryLesson.js';
import{createCustomerFileSummaryStore,createCustomerFileSummaryAssessmentStore}from'../utils/customerFileSummaryReference.mjs';
import{flushShopStorage,shopStorage}from'../utils/shopStorage.mjs';
import{isStandaloneShopFrame,openStandaloneAssessments}from'../bridge/assessmentPanelIntent.mjs';
const references=createCustomerFileSummaryStore({storage:shopStorage,flush:flushShopStorage});
const assessments=createCustomerFileSummaryAssessmentStore({storage:shopStorage,flush:flushShopStorage});
const DEFAULT_MESSAGE='Summarize the attached document.';
export default function CustomerFileSummaryLesson({shopUserId,authorityKey,transport=globalThis.fetch,referenceStore=references,assessmentStore=assessments}){
 const lesson=useCustomerFileSummaryLesson({shopUserId,authorityKey,transport,referenceStore,assessmentStore});
 const[file,setFile]=useState(null),[message,setMessage]=useState(DEFAULT_MESSAGE);const input=useRef(null);
 useEffect(()=>{setFile(null);setMessage(DEFAULT_MESSAGE);if(input.current)input.current.value='';},[shopUserId,authorityKey]);
 const attachmentError=file?fileSummaryAttachmentError(file):null,messageError=fileSummaryMessageError(message),ready=file&&!attachmentError&&!messageError;
 const terminal=['completed','no_tool'].includes(lesson.result?.status),assessmentTerminal=!lesson.assessmentReference||lesson.assessment?.judgment||['ineligible','unavailable'].includes(lesson.assessment?.status);
 return <section aria-label="File summary lesson">
  <p>Attach a small text or Markdown document, then ask the customer file-summary agent to read and summarize it.</p>
  {lesson.capability&&<p className="ss-mono" style={{fontSize:11}}>File-summary policy · {lesson.capability.effectiveMode}</p>}
  {!lesson.reference&&!lesson.admissionLatched&&<form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={event=>{event.preventDefault();if(ready&&!lesson.busy){const selected=file,request=message;setFile(null);setMessage(DEFAULT_MESSAGE);if(input.current)input.current.value='';void lesson.run(selected,request);}}}>
   <label htmlFor="customer-file-summary-attachment">Document</label>
   <input id="customer-file-summary-attachment" data-testid="file-summary-file" ref={input} type="file" accept=".txt,.md,text/plain,text/markdown" required disabled={lesson.busy||lesson.status!=='ready'} onChange={event=>setFile(event.target.files?.[0]||null)}/>
   {file&&<p className="ss-mono" data-testid="file-summary-file-name" style={{fontSize:11}}>{file.name} · {file.size.toLocaleString()} bytes</p>}
   {attachmentError&&<p data-testid="file-summary-file-error" role="alert">{attachmentError}</p>}
   <label htmlFor="customer-file-summary-message">Request</label>
   <textarea id="customer-file-summary-message" data-testid="file-summary-message" className="ss-lane__input" rows={3} maxLength={8192} value={message} disabled={lesson.busy||lesson.status!=='ready'} onChange={event=>setMessage(event.target.value)} />
   {messageError&&<p data-testid="file-summary-message-error" role="alert">{messageError}</p>}
   <button data-testid="file-summary-send" className="ss-btn" type="submit" disabled={!ready||lesson.busy||lesson.status!=='ready'}>{lesson.busy?'Working…':'Ask file-summary agent'}</button>
  </form>}
  {lesson.reference&&<section className="ss-card" aria-label="Saved file-summary request" style={{padding:12,marginTop:10}}>
   <p className="ss-mono">Saved file-summary request · {lesson.result?.status||lesson.status}</p>
   <button data-testid="file-summary-recover" className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.recover()}>Check saved file summary</button>
   {lesson.knownUnsent&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.discardUnsent()}>Discard unsent file summary</button>}
   {lesson.result&&<article className="ss-turn" data-testid="file-summary-turn"><div className="ss-turn__you">YOU · FILE SUMMARY</div><div className="ss-turn__msg">{lesson.result.filename} · {lesson.result.byteCount} bytes</div><div className="ss-turn__supervisor">FILE SUMMARY · {lesson.result.status}</div><div className="ss-turn__reply" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{lesson.result.text||'No final answer was produced.'}</div></article>}
   {['uncertain','unconfirmed'].includes(lesson.result?.status)&&<p role="status">The saved outcome is unconfirmed. Reset the current SecureShop launch before trying a new document.</p>}
   {lesson.result?.status==='no_tool'&&<p role="status">No document read was selected; this attempt cannot be assessed.</p>}
   {lesson.result?.status==='completed'&&!lesson.assessmentReference&&<button data-testid="file-summary-assess" className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.assess()}>Assess saved file summary</button>}
   {lesson.assessmentReference&&<button data-testid="file-summary-assessment-recover" className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.recoverAssessment()}>Check saved assessment</button>}
   {lesson.assessmentKnownUnsent&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.discardUnsentAssessment()}>Discard unsent assessment</button>}
   {lesson.assessment?.status==='ineligible'&&<p role="status">This saved file summary is not eligible for objective assessment.</p>}
   {lesson.assessment?.status==='unconfirmed'&&<p role="status">Assessment unconfirmed. Check the saved assessment.</p>}
   {lesson.assessment?.status==='unavailable'&&<p role="status">Assessment unavailable because the complete evidence packet exceeds its supported size.</p>}
   {lesson.assessment?.judgment&&<><p role="status">Canonical assessment: {lesson.assessment.judgment.verdict}.{lesson.assessment.completed?' File-summary objective completed in canonical progress.':''}</p>
    {lesson.assessment.judgment.canRetry&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" onClick={()=>openStandaloneAssessments(lesson.assessment.judgment.evaluationId)}>{isStandaloneShopFrame()?'Open saved assessments':'Saved assessment available'}</button>}</>}
   {terminal&&assessmentTerminal&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.startNew()}>Start another file summary</button>}
  </section>}
  {lesson.error&&<p role="alert" style={{color:'var(--rust)'}}>{lesson.error}</p>}
 </section>;
}
