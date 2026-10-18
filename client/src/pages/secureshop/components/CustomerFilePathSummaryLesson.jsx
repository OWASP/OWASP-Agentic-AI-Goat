import React,{useEffect,useState}from'react';
import{filePathSummaryPathError,filePathSummaryMessageError,useCustomerFilePathSummaryLesson}from'../hooks/useCustomerFilePathSummaryLesson.js';
import{createCustomerFilePathSummaryStore,createCustomerFilePathSummaryAssessmentStore}from'../utils/customerFilePathSummaryReference.mjs';
import{flushShopStorage,shopStorage}from'../utils/shopStorage.mjs';
import{isStandaloneShopFrame,openStandaloneAssessments}from'../bridge/assessmentPanelIntent.mjs';
const references=createCustomerFilePathSummaryStore({storage:shopStorage,flush:flushShopStorage});
const assessments=createCustomerFilePathSummaryAssessmentStore({storage:shopStorage,flush:flushShopStorage});
const DEFAULT_MESSAGE='Summarize the file at the requested virtual path.';
const DEFAULT_PATH='../etc/passwd';
export default function CustomerFilePathSummaryLesson({shopUserId,authorityKey,transport=globalThis.fetch,referenceStore=references,assessmentStore=assessments}){
 const lesson=useCustomerFilePathSummaryLesson({shopUserId,authorityKey,transport,referenceStore,assessmentStore});
 const[path,setPath]=useState(DEFAULT_PATH),[message,setMessage]=useState(DEFAULT_MESSAGE);
 useEffect(()=>{setPath(DEFAULT_PATH);setMessage(DEFAULT_MESSAGE);},[shopUserId,authorityKey]);
 const pathError=filePathSummaryPathError(path),messageError=filePathSummaryMessageError(message),ready=!pathError&&!messageError;
 const terminal=['completed','no_tool'].includes(lesson.result?.status),assessmentTerminal=!lesson.assessmentReference||lesson.assessment?.judgment||['ineligible','unavailable'].includes(lesson.assessment?.status);
 return <section aria-label="Path summary lesson">
  <p>Ask the customer agent to summarize a file in this owned lesson. The path is virtual; the lesson provides synthetic file contents.</p>
  {lesson.capability&&<p className="ss-mono" style={{fontSize:11}}>Path-summary policy · {lesson.capability.effectiveMode==='fixed'?'Fixed':'Vulnerable'}</p>}
  {lesson.capability&&<p>{lesson.capability.effectiveMode==='fixed'?'Fixed mode restricts reads to the allowed virtual directory.':'Vulnerable mode lets the agent follow relative paths outside the virtual uploads directory.'}</p>}
  {!lesson.reference&&!lesson.admissionLatched&&<form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={event=>{event.preventDefault();if(ready&&!lesson.busy)void lesson.run(path,message);}}>
   <label htmlFor="customer-file-path-summary-path">Virtual path</label>
   <input id="customer-file-path-summary-path" data-testid="file-path-summary-path" className="ss-lane__input" value={path} maxLength={4096} required disabled={lesson.busy||lesson.status!=='ready'} onChange={event=>setPath(event.target.value)} aria-describedby="file-path-summary-path-help"/>
   <p id="file-path-summary-path-help">Use a relative POSIX path, such as ../etc/passwd, inside this synthetic lesson.</p>
   {pathError&&<p data-testid="file-path-summary-path-error" role="alert">{pathError}</p>}
   <label htmlFor="customer-file-path-summary-message">Request</label>
   <textarea id="customer-file-path-summary-message" data-testid="file-path-summary-message" className="ss-lane__input" rows={3} maxLength={8192} value={message} disabled={lesson.busy||lesson.status!=='ready'} onChange={event=>setMessage(event.target.value)} />
   {messageError&&<p data-testid="file-path-summary-message-error" role="alert">{messageError}</p>}
   <button data-testid="file-path-summary-send" className="ss-btn" type="submit" disabled={!ready||lesson.busy||lesson.status!=='ready'}>{lesson.busy?'Working…':'Ask path-summary agent'}</button>
  </form>}
  {lesson.reference&&<section className="ss-card" aria-label="Saved file-path-summary request" style={{padding:12,marginTop:10}}>
   <p className="ss-mono">Saved file-path-summary request · {lesson.result?.status||lesson.status}</p>
   <button data-testid="file-path-summary-recover" className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.recover()}>Check saved path summary</button>
   {lesson.knownUnsent&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.discardUnsent()}>Discard unsent path summary</button>}
   {['completed','no_tool'].includes(lesson.result?.status)&&<article className="ss-turn" data-testid="file-path-summary-turn"><div className="ss-turn__you">YOU · PATH SUMMARY</div><div className="ss-turn__msg">Requested path: {lesson.result.path}{lesson.result.status==='completed'&&<><br/>Read: {lesson.result.resolvedPath} · {lesson.result.byteCount} bytes</>}</div><div className="ss-turn__supervisor">PATH SUMMARY · {lesson.result.status}</div><div className="ss-turn__reply" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{lesson.result.text||'No final answer was produced.'}</div></article>}
   {['uncertain','unconfirmed'].includes(lesson.result?.status)&&<p role="status">The saved outcome is unconfirmed. Reset the current SecureShop launch before trying a new path.</p>}
   {lesson.result?.status==='no_tool'&&<p role="status">No file read was selected; this attempt cannot be assessed.</p>}
   {lesson.result?.status==='completed'&&!lesson.assessmentReference&&<button data-testid="file-path-summary-assess" className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.assess()}>Assess saved path summary</button>}
   {lesson.assessmentReference&&<button data-testid="file-path-summary-assessment-recover" className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.recoverAssessment()}>Check saved assessment</button>}
   {lesson.assessmentKnownUnsent&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.discardUnsentAssessment()}>Discard unsent assessment</button>}
   {lesson.assessment?.status==='ineligible'&&<p role="status">This saved path summary is not eligible for objective assessment.</p>}
   {lesson.assessment?.status==='unconfirmed'&&<p role="status">Assessment unconfirmed. Check the saved assessment.</p>}
   {lesson.assessment?.status==='unavailable'&&<p role="status">Assessment unavailable. Check the saved assessment for its current outcome.</p>}
   {lesson.assessment?.judgment&&<><p role="status">Canonical assessment: {lesson.assessment.judgment.verdict}.{lesson.assessment.completed?' Path-summary objective completed in canonical progress.':''}</p>
    {lesson.assessment.judgment.canRetry&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" onClick={()=>openStandaloneAssessments(lesson.assessment.judgment.evaluationId)}>{isStandaloneShopFrame()?'Open saved assessments':'Saved assessment available'}</button>}</>}
   {terminal&&assessmentTerminal&&<button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy} onClick={()=>void lesson.startNew()}>Start another path summary</button>}
  </section>}
  {lesson.error&&<p role="alert" style={{color:'var(--rust)'}}>{lesson.error}</p>}
 </section>;
}
