import React, { useState, useRef, useEffect } from 'react';
import { readResponse } from './mailRequests';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';

export default function MailAssessment({ mail, request, kind = 'reply' }) {
  const reference=kind==='browser'?mail.browserAssessment:kind==='header'?mail.headerAssessment:kind==='disclosure'?mail.disclosureAssessment:mail.assessment;
  if(!reference||(kind==='browser'&&mail.browserAssessmentReady!==true)||(kind==='disclosure'&&!reference.confirmed))return null;
  const identity=JSON.stringify([mail.scopeKey||null,kind,reference.requestId,reference.sendOperationId||reference.replyOperationId||reference.readOperationId,reference.threadId||null,reference.messageId||null,reference.evaluationId||null]);
  return <MailAssessmentState key={identity} mail={mail} request={request} kind={kind} reference={reference} />;
}

function MailAssessmentState({mail,request,kind,reference}) {
  const standalone = isStandaloneShopFrame();
  const [status, setStatus] = useState(reference.evaluationId ? `Grading unavailable. Your ${(kind==='header'||kind==='browser')?'message':kind==='disclosure'?'disclosure':'reply'} remains saved; ${standalone ? 'open saved assessments to review retry eligibility.' : 'retry the retained assessment.'}` : '');
  const [busy, setBusy] = useState(false);
  const active = useRef(false);
  const alive=useRef(true);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  const browser=kind==='browser', header=kind==='header', disclosure=kind==='disclosure', saved=(header||browser)?'message':disclosure?'disclosure':'reply', label=browser?'Check saved message execution':header?'Check saved headers':disclosure?'Check saved disclosure':'Check saved reply';
  if (!(browser?mail.browserAssessment:header?mail.headerAssessment:disclosure?mail.disclosureAssessment:mail.assessment)) return null;
  async function assess() {
    if (active.current) return;
    active.current = true; setBusy(true);
    const work = request();
    try {
      const result = await readResponse(await (browser?mail.assessBrowser(work.signal):header?mail.assessHeader(work.signal):disclosure?mail.assessDisclosure(work.signal):mail.assess(work.signal)));
      if (!alive.current || work.signal.aborted) return;
      setStatus(result.judgment?.verdict === 'unavailable' ? (result.judgment.canRetry === true
        ? standalone ? `Grading unavailable. Your ${saved} remains saved. Open saved assessments to review retry eligibility.`
          : `Grading unavailable. Your ${saved} remains saved; use ${label} to recover or retry.`
        : `Grading unavailable. Your ${saved} remains saved. No objective completion was confirmed. A Judge retry is not available; ask the ${standalone ? 'SecureShop' : 'workshop'} administrator to check the diagnostics.`)
        : result.status === 'disabled' ? `Grading is disabled. Your ${saved} remains saved.`
        : result.status === 'ineligible' ? `This saved ${saved} is not eligible for objective credit.`
        : result.completed === true ? 'Objective completed.' : 'The Judge did not award objective credit.');
    } catch (error) {
      if (alive.current && !work.signal.aborted && error.name!=='AbortError') setStatus(`Grading unavailable. Your ${saved} remains saved; retry to recover the same assessment.`);
    } finally {
      if (alive.current && !work.signal.aborted) { active.current = false; setBusy(false); }
      work.finish();
    }
  }
  if (standalone && reference.evaluationId) return <div>
    <button type="button" className="ss-btn ss-btn--ghost"
      onClick={() => openStandaloneAssessments(reference.evaluationId)}>Open saved assessments</button>
    {status && <div role="status" style={{ fontSize: 12, maxWidth: 280 }}>{status}</div>}
  </div>;
  return <div>
    <button className="ss-btn ss-btn--ghost" disabled={busy} onClick={assess}>{busy ? (browser?'Checking saved message…':header?'Checking saved headers…':disclosure?'Checking saved disclosure…':'Checking saved reply…') : label}</button>
    {status && <div role="status" style={{ fontSize: 12, maxWidth: 280 }}>{status}</div>}
  </div>;
}
