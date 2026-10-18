import React,{useRef,useState}from'react';
import{useCustomerAvatarUploadLesson}from'../hooks/useCustomerAvatarUploadLesson.js';
import{createCustomerAvatarUploadReferenceStore}from'../utils/customerAvatarUploadReference.mjs';
import{createCustomerAvatarUploadAssessmentStore,createCustomerAvatarSvgAssessmentStore,createCustomerAvatarPolyglotPreviewStore,createCustomerAvatarPolyglotAssessmentStore}from'../utils/customerAvatarUploadAssessmentReference.mjs';
import{flushShopStorage,shopStorage}from'../utils/shopStorage.mjs';
const references=createCustomerAvatarUploadReferenceStore({storage:shopStorage,flush:flushShopStorage});
const assessments=createCustomerAvatarUploadAssessmentStore({storage:shopStorage,flush:flushShopStorage});
const svgAssessments=createCustomerAvatarSvgAssessmentStore({storage:shopStorage,flush:flushShopStorage});
const polyglotPreviews=createCustomerAvatarPolyglotPreviewStore({storage:shopStorage,flush:flushShopStorage});
const polyglotAssessments=createCustomerAvatarPolyglotAssessmentStore({storage:shopStorage,flush:flushShopStorage});
export default function CustomerAvatarUploadLesson({shopUserId,authorityKey,
 transport=globalThis.fetch,referenceStore=references,assessmentStore=assessments,svgAssessmentStore=svgAssessments,polyglotPreviewStore=polyglotPreviews,polyglotAssessmentStore=polyglotAssessments}){
 const lesson=useCustomerAvatarUploadLesson({shopUserId,authorityKey,transport,referenceStore,assessmentStore,svgAssessmentStore,polyglotPreviewStore,polyglotAssessmentStore});
 const[file,setFile]=useState(null),[message,setMessage]=useState(''),[isPublic,setIsPublic]=useState(true);
 const input=useRef(null),ready=file&&file.size>0&&file.size<=20*1024*1024&&message.trim();
 return <section aria-label="Avatar upload lesson">
  <p>Choose an avatar attachment, then ask the customer assistant to upload it through the bound tool.</p>
  {!lesson.reference&&!lesson.admissionLatched&&<form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={event=>{
   event.preventDefault();if(ready&&!lesson.busy)void lesson.run(file,message,isPublic);}}>
   <label htmlFor="customer-avatar-attachment">Avatar attachment</label>
   <input id="customer-avatar-attachment" data-testid="avatar-upload-file" ref={input} type="file"
    onChange={event=>setFile(event.target.files?.[0]||null)} disabled={lesson.busy}/>
   {file&&<p className="ss-mono" data-testid="avatar-upload-name" style={{fontSize:11}}>
    {file.name} · {file.size.toLocaleString()} bytes</p>}
   <label htmlFor="customer-avatar-message">Request</label>
   <textarea id="customer-avatar-message" data-testid="avatar-upload-message" className="ss-lane__input"
    rows={3} maxLength={8192} value={message} onChange={event=>setMessage(event.target.value)}
    placeholder="Upload this attachment as my avatar" style={{width:'100%',boxSizing:'border-box',marginTop:5}}/>
   <label className="ss-mono" style={{display:'flex',alignItems:'center',gap:6}}>
    <input data-testid="avatar-upload-public" type="checkbox" checked={isPublic}
     onChange={event=>setIsPublic(event.target.checked)}/>Public practice asset</label>
   <button data-testid="avatar-upload-send" type="submit" className="ss-btn"
    disabled={!ready||lesson.busy}>Upload with agent</button>
  </form>}
  {lesson.reference&&<section className="ss-card" style={{padding:12,marginTop:10}} aria-label="Saved avatar upload">
   <p className="ss-mono" data-testid="avatar-upload-status">Saved avatar upload · {lesson.status}</p>
   {lesson.result&&<p role="status">{lesson.result.status==='completed'?'Upload completed':
    lesson.result.status==='denied'?'Upload denied':'Upload outcome unresolved'}: {lesson.result.filename}
    {' · '}{lesson.result.byteCount.toLocaleString()} bytes.</p>}
   {lesson.result?.text&&<p role="status" style={{whiteSpace:'pre-wrap'}}>{lesson.result.text}</p>}
   {lesson.status!=='completed'&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.recover()}>Check saved avatar upload</button>}
   {lesson.knownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy}
    onClick={()=>void lesson.discardUnsent()}>Discard unsent upload request</button>}
   {lesson.status==='completed'&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.preview()}>Open sandbox preview</button>}
   {['completed','denied'].includes(lesson.result?.status)&&!lesson.assessmentReference&&<button type="button"
    className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy||lesson.result.status==='completed'&&!lesson.previewDelivered}
    onClick={()=>void lesson.assess()}>Assess saved avatar upload</button>}
   {lesson.assessmentReference&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.recoverAssessment()}>Check saved avatar-upload assessment</button>}
   {lesson.assessmentKnownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.discardUnsentAssessment()}>Discard unsent avatar-upload assessment</button>}
   {lesson.assessment?.status&&<p role="status">Assessment {lesson.assessment.status}.</p>}
   {lesson.assessment?.judgment&&<p role="status">Canonical assessment: {lesson.assessment.judgment.verdict}.
    {lesson.assessment.completed?' Objective completed in canonical progress.':''}</p>}
   {lesson.result?.status==='completed'&&!lesson.previewDelivered&&<p className="ss-mono" style={{fontSize:11}}>
    Open the saved SVG in the sandbox preview before assessing it.</p>}
   {lesson.result?.status==='completed'&&!lesson.svgAssessmentReference&&<button type="button"
    data-testid="avatar-svg-assess" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy||!lesson.previewDelivered}
    onClick={()=>void lesson.assessSvg()}>Assess saved SVG browser execution</button>}
   {lesson.svgAssessmentReference&&<button type="button" data-testid="avatar-svg-assess-recover" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.recoverSvgAssessment()}>Check saved SVG assessment</button>}
   {lesson.svgAssessmentKnownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.discardUnsentSvgAssessment()}>Discard unsent SVG assessment</button>}
   {lesson.svgAssessment?.status==='ineligible'&&<p role="status">SVG assessment unavailable. This pending objective may be disabled, or the saved upload does not meet its exact SVG and first-response requirements.</p>}
   {lesson.svgAssessment?.status==='unconfirmed'&&<p role="status">SVG assessment unconfirmed. Check the saved SVG assessment.</p>}
   {lesson.svgAssessment?.judgment&&<p role="status">Canonical SVG assessment: {lesson.svgAssessment.judgment.verdict}.
    {lesson.svgAssessment.completed?' SVG objective completed in canonical progress.':''}</p>}
   {(lesson.polyglotReady||lesson.polyglotPreviewReference||lesson.polyglotAssessmentReference)&&<section aria-label="Saved legacy image preview">
    <p>Preview the saved image with the legacy image processor. This makes a separate assistant request.</p>
    {lesson.result?.status==='completed'&&!lesson.polyglotPreviewReference&&<button type="button"
     data-testid="avatar-polyglot-preview" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy||!lesson.polyglotReady||!lesson.previewDelivered}
     onClick={()=>void lesson.runPolyglotPreview()}>Run legacy preview</button>}
    {lesson.polyglotPreviewReference&&<button type="button" data-testid="avatar-polyglot-preview-recover"
     className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy}
     onClick={()=>void lesson.recoverPolyglotPreview()}>Check saved legacy preview</button>}
    {lesson.polyglotPreviewKnownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy}
     onClick={()=>void lesson.discardUnsentPolyglotPreview()}>Discard unsent legacy preview</button>}
    {lesson.polyglotPreview&&<p role="status">Legacy preview: {lesson.polyglotPreview.status}.</p>}
    {lesson.polyglotPreview?.text&&<p data-testid="avatar-polyglot-reply" style={{whiteSpace:'pre-wrap'}}>{lesson.polyglotPreview.text}</p>}
    {['executed','image_only','fixed_reencoded','invalid_image','failed'].includes(lesson.polyglotPreview?.status)&&!lesson.polyglotAssessmentReference&&<button type="button"
     data-testid="avatar-polyglot-assess" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy||!lesson.polyglotReady}
     onClick={()=>void lesson.assessPolyglot()}>Assess saved polyglot execution</button>}
    {lesson.polyglotAssessmentReference&&<button type="button" data-testid="avatar-polyglot-assess-recover"
     className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy}
     onClick={()=>void lesson.recoverPolyglotAssessment()}>Check saved polyglot assessment</button>}
    {lesson.polyglotAssessmentKnownUnsent&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={lesson.busy}
     onClick={()=>void lesson.discardUnsentPolyglotAssessment()}>Discard unsent polyglot assessment</button>}
    {lesson.polyglotAssessment?.status&&<p role="status">Polyglot assessment {lesson.polyglotAssessment.status}.</p>}
    {lesson.polyglotAssessment?.judgment&&<p role="status">Canonical polyglot assessment: {lesson.polyglotAssessment.judgment.verdict}.
     {lesson.polyglotAssessment.completed?' Polyglot objective completed in canonical progress.':''}</p>}
   </section>}
   {['completed','denied'].includes(lesson.result?.status)&&<button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
    disabled={lesson.busy} onClick={()=>void lesson.startNew()}>Start another avatar upload</button>}
  </section>}
  {lesson.asset&&<div className="ss-card" style={{padding:8,marginTop:10}} aria-label="Sandbox avatar preview">
   <iframe data-testid="avatar-upload-preview" title="Sandbox avatar preview" src={lesson.asset.assetUrl}
    sandbox="allow-scripts" referrerPolicy="no-referrer" onLoad={lesson.markPreviewDelivered} style={{width:'100%',minHeight:180,border:'1px solid var(--rule)'}}/>
   <p className="ss-mono" style={{fontSize:11}}>Temporary isolated preview</p>
  </div>}
  {lesson.busy&&<p role="status">Checking the saved avatar upload…</p>}
  {lesson.error&&<p role="alert" style={{color:'var(--rust)'}}>{lesson.error}</p>}
  <p className="ss-mono" style={{fontSize:11}}>The saved interaction reports tool status only. It does not award objective credit.</p>
 </section>;
}
