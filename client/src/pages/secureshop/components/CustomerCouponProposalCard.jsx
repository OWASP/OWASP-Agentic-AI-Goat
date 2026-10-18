import React from 'react';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

export function decodeCustomerCouponProposal(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'kind', 'status', 'proposalId', 'code', 'codeSha256'])
    || value.version !== 1 || value.kind !== 'cart.coupon_prepare'
    || value.status !== 'confirmation_required' || !UUID.test(value.proposalId)
    || typeof value.code !== 'string' || !value.code || !value.code.isWellFormed()
    || value.code.includes('\0') || new TextEncoder().encode(value.code).byteLength > 1024
    || !SHA.test(value.codeSha256)) throw new TypeError('Saved coupon proposal unavailable');
  return value;
}

export function decodeSavedCouponResult(value) {
  if (exact(value, ['ok', 'error']) && value.ok === false
    && value.error === 'coupon not found') return value;
  if (exact(value, ['ok', 'code', 'discount_percent', 'subtotal', 'applied_amount'])
    && value.ok === true && typeof value.code === 'string' && value.code
    && value.code.isWellFormed() && new TextEncoder().encode(value.code).byteLength <= 1024
    && Number.isFinite(value.discount_percent) && value.discount_percent >= 0
    && value.discount_percent <= 100 && Number.isFinite(value.subtotal)
    && value.subtotal >= 0 && Number.isFinite(value.applied_amount)
    && value.applied_amount >= 0 && value.applied_amount <= value.subtotal) return value;
  throw new TypeError('Saved coupon result unavailable');
}

export default function CustomerCouponProposalCard({ proposal, reference, status = null,
  result = null, busy = false, error = null, onConfirm, onCheck, onClear,
  nextProposalAvailable = false, assessment = null, onReadAssessment, onRetryAssessment }) {
  let trusted;
  try { trusted = decodeCustomerCouponProposal(proposal); } catch { trusted = null; }
  let savedResult = null;
  try { if (reference && status === 'completed') savedResult = decodeSavedCouponResult(result); }
  catch { /* A malformed response cannot appear as a completed coupon. */ }
  if (!trusted && !reference) return null;
  const pending = !!reference;
  return <section className="ss-card" aria-label="Customer coupon confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>
      SAVED COUPON PROPOSAL · REVIEW BEFORE APPLYING
    </div>
    {trusted && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review coupon</h3>
      <p>Code proposed by the customer agent:</p>
      <p className="ss-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{trusted.code}</p>
      <p className="ss-mono" style={{ fontSize: 11 }}>Your cart is unchanged until you confirm.</p>
    </>}
    {pending && status !== 'completed' && <p role="status">Coupon outcome is unconfirmed. Check the saved operation; confirmation will not be sent again.</p>}
    {pending && status === 'completed' && !savedResult && <p role="status">Saved coupon result unavailable. Check the operation again.</p>}
    {savedResult?.ok === true && <p role="status">Coupon applied from the saved result.</p>}
    {savedResult?.ok === false && <p role="status">Coupon not found. No discount was applied.</p>}
    {savedResult && <div style={{ marginTop: 10 }}>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={busy || typeof onReadAssessment !== 'function'}
        onClick={() => onReadAssessment()}>Check saved assessment</button>
      {assessment?.status === 'unconfirmed' && <>
        <p role="status">No saved objective assessment yet. Checking it will not repeat coupon confirmation.</p>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          disabled={busy || typeof onRetryAssessment !== 'function'}
          onClick={() => onRetryAssessment()}>Check objective</button>
      </>}
      {assessment?.status === 'ineligible' && <p role="status">This coupon result is not eligible for objective credit.</p>}
      {assessment?.judgment && <p role="status">{assessment.judgment.verdict === 'unavailable'
        ? 'Grading unavailable. The saved coupon result remains available.'
        : assessment.completed === true && assessment.judgment.verdict === 'pass'
          ? 'Objective completed.' : 'Assessment recorded without objective credit.'}</p>}
      {assessment?.judgment?.verdict === 'unavailable' &&
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          onClick={() => openStandaloneAssessments(assessment.judgment.evaluationId)}>
          {isStandaloneShopFrame() ? 'Open saved assessments' : 'Saved assessment available'}
        </button>}
    </div>}
    {error && <p role="alert">{error}</p>}
    {pending ? <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy || typeof onCheck !== 'function'} onClick={() => onCheck()}>
      Check saved coupon
    </button> : trusted && <button className="ss-btn" type="button"
      disabled={busy || typeof onConfirm !== 'function'} onClick={() => onConfirm()}>
      Confirm coupon
    </button>}
    {pending && status === 'completed' && savedResult && nextProposalAvailable
      && typeof onClear === 'function' &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy}
        onClick={() => onClear()}>Review newer coupon</button>}
  </section>;
}
