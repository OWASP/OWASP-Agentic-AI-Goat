import React from 'react';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const raw = (value, limit) => typeof value === 'string' && !!value.trim()
  && value.isWellFormed() && new TextEncoder().encode(value).byteLength <= limit;

export function decodeCustomerTicketProposal(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'kind', 'status', 'proposalId', 'subject', 'body',
    'subjectSha256', 'bodySha256']) || value.version !== 1
    || value.kind !== 'support.ticket_prepare' || value.status !== 'confirmation_required'
    || !UUID.test(value.proposalId) || !raw(value.subject, 256) || !raw(value.body, 4096)
    || !SHA.test(value.subjectSha256) || !SHA.test(value.bodySha256))
    throw new TypeError('Saved ticket proposal unavailable');
  return value;
}

export function decodeSavedTicketResult(value) {
  if (!exact(value, ['version', 'kind', 'ticketId', 'operationId', 'requestId', 'runId',
    'proposalId', 'status', 'subjectSha256', 'bodySha256', 'receiptSha256'])
    || value.version !== 1 || value.kind !== 'support_ticket' || value.status !== 'open'
    || typeof value.ticketId !== 'string' || !/^[1-9]\d*$/.test(value.ticketId)
    || ![value.operationId, value.requestId, value.runId, value.proposalId].every(id => UUID.test(id))
    || value.operationId !== value.proposalId
    || ![value.subjectSha256, value.bodySha256, value.receiptSha256].every(digest => SHA.test(digest)))
    throw new TypeError('Saved ticket result unavailable');
  return value;
}

export default function CustomerTicketConfirmationCard({ proposal, reference, status = null,
  result = null, busy = false, error = null, onConfirm, onCheck, onClear,
  nextProposalAvailable = false }) {
  let trusted = null, savedResult = null;
  try { trusted = decodeCustomerTicketProposal(proposal); } catch { /* No untrusted preview. */ }
  try {
    if (reference && status === 'completed') {
      const candidate = decodeSavedTicketResult(result);
      if (candidate.proposalId === reference.proposalId
        && (!trusted || candidate.subjectSha256 === trusted.subjectSha256
          && candidate.bodySha256 === trusted.bodySha256)) savedResult = candidate;
    }
  }
  catch { /* A malformed saved result is never a completed ticket. */ }
  if (!trusted && !reference) return null;
  const pending = !!reference;
  return <section className="ss-card" aria-label="Customer support ticket confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>
      SAVED SUPPORT TICKET PROPOSAL · REVIEW BEFORE OPENING
    </div>
    {trusted && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review support ticket</h3>
      <p className="ss-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{trusted.subject}</p>
      <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{trusted.body}</p>
      <p className="ss-mono" style={{ fontSize: 11 }}>No ticket is opened until you confirm.</p>
    </>}
    {pending && status !== 'completed' &&
      <p role="status">Ticket outcome is unconfirmed. Check the saved operation; confirmation will not be sent again.</p>}
    {pending && status === 'completed' && !savedResult &&
      <p role="status">Saved ticket result unavailable. Check the operation again.</p>}
    {savedResult && <p role="status">Ticket #{savedResult.ticketId} is open.</p>}
    {error && <p role="alert">{error}</p>}
    {pending ? <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy || typeof onCheck !== 'function'} onClick={() => onCheck()}>
      Check saved ticket
    </button> : trusted && <button className="ss-btn" type="button"
      disabled={busy || typeof onConfirm !== 'function'} onClick={() => onConfirm()}>
      Open support ticket
    </button>}
    {pending && status === 'completed' && savedResult && nextProposalAvailable
      && typeof onClear === 'function' &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy}
        onClick={() => onClear()}>Review newer ticket</button>}
  </section>;
}
