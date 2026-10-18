import React,{useState}from'react';
import{useCustomerAvatarTraversalLesson}from'../hooks/useCustomerAvatarTraversalLesson.js';
import{createCustomerAvatarTraversalReferenceStore,createCustomerAvatarTraversalAssessmentStore}from'../utils/customerAvatarTraversalReference.mjs';
import{flushShopStorage,shopStorage}from'../utils/shopStorage.mjs';
const references=createCustomerAvatarTraversalReferenceStore({storage:shopStorage,flush:flushShopStorage});
const assessments=createCustomerAvatarTraversalAssessmentStore({storage:shopStorage,flush:flushShopStorage});
export default function CustomerAvatarTraversalLesson({shopUserId,authorityKey,transport=globalThis.fetch,referenceStore=references,assessmentStore=assessments}){
 const lesson=useCustomerAvatarTraversalLesson({shopUserId,authorityKey,transport,referenceStore,assessmentStore});
 const[file,setFile]=useState(null),[message,setMessage]=useState(''),[logicalFilename,setLogicalFilename]=useState('....//avatar.txt'),[isPublic,setIsPublic]=useState(false);
 const ready=file&&file.size>0&&file.size<=20*1024*1024&&message.trim()&&logicalFilename.includes('....//');
 return <section aria-label="Avatar path traversal lesson">
  <p>Choose a synthetic avatar attachment and provide the logical filename that the customer assistant should use.</p>
  {!lesson.reference&&<form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={event=>{event.preventDefault();if(ready&&!lesson.busy)void lesson.run(file,message,logicalFilename,isPublic);}}>
   <label htmlFor="customer-avatar-traversal-file">Avatar attachment</label>
   <input id="customer-avatar-traversal-file" data-testid="avatar-traversal-file" type="file" onChange={event=>setFile(event.target.files?.[0]||null)} disabled={lesson.busy}/>
   <label htmlFor="customer-avatar-traversal-filename">Logical filename</label>
   <input id="customer-avatar-traversal-filename" data-testid="avatar-traversal-filename" className="ss-lane__input" maxLength={4096} value={logicalFilename} onChange={event=>setLogicalFilename(event.target.value)}/>
   <label htmlFor="customer-avatar-traversal-message">Request</label>
   <textarea id="customer-avatar-traversal-message" data-testid="avatar-traversal-message" className="ss-lane__input" rows={3} maxLength={8192} value={message} onChange={event=>setMessage(event.target.value)} placeholder="Upload this attachment using the logical filename"/>
   <label className="ss-mono" style={{display:'flex',alignItems:'center',gap:6}}><input data-testid="avatar-traversal-public" type="checkbox" checked={isPublic} onChange={event=>setIsPublic(event.target.checked)}/>Mark request public</label>
   <button data-testid="avatar-traversal-send" type="submit" className="ss-btn" disabled={!ready||lesson.busy}>Upload with agent</button>
  </form>}
  {lesson.reference&&<section className="ss-card" style={{padding:12,marginTop:10}} aria-label="Saved avatar traversal upload">
   <p className="ss-mono" data-testid="avatar-traversal-status">Saved avatar traversal · {lesson.status}</p>
   {lesson.result&&<p role="status">{lesson.result.status==='completed'?'Upload completed':'Upload denied'}: {lesson.result.filename} · {lesson.result.byteCount.toLocaleString()} bytes.{lesson.result.status==='completed'&&<> Stored outside the avatar subdirectory at <code>{lesson.result.operationRelativePath}</code>.</>}</p>}
   {lesson.status==='unconfirmed'&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy} onClick={()=>void lesson.recover()}>Check saved traversal upload</button>}
   {lesson.knownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy} onClick={()=>void lesson.discardUnsent()}>Discard unsent traversal upload</button>}
   {['completed','denied'].includes(lesson.result?.status)&&!lesson.assessmentReference&&<button data-testid="avatar-traversal-assess" type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy} onClick={()=>void lesson.assess()}>Assess saved traversal upload</button>}
   {lesson.assessmentReference&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy} onClick={()=>void lesson.recoverAssessment()}>Check saved traversal assessment</button>}
   {lesson.assessmentKnownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy} onClick={()=>void lesson.discardUnsentAssessment()}>Discard unsent traversal assessment</button>}
   {lesson.assessment?.status&&<p role="status">Assessment {lesson.assessment.status}.</p>}
   {lesson.assessment?.judgment&&<p role="status">Canonical assessment: {lesson.assessment.judgment.verdict}.{lesson.assessment.completed?' Objective completed in canonical progress.':''}</p>}
   {['completed','denied'].includes(lesson.result?.status)&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy} onClick={()=>void lesson.startNew()}>Start another traversal upload</button>}
  </section>}
  {lesson.busy&&<p role="status">Checking the saved traversal upload…</p>}
  {lesson.error&&<p role="alert" style={{color:'var(--rust)'}}>{lesson.error}</p>}
  <p className="ss-mono" style={{fontSize:11}}>The saved interaction reports bounded tool status only. It does not award objective credit.</p>
 </section>;
}
