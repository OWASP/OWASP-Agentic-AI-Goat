import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import PageTransition from '../../components/PageTransition.jsx';
import AdminTicketBody from '../../components/AdminTicketBody.jsx';
import { decodeAdminTicketList, verifyAdminTicketDetail } from '../../utils/adminTicketPresentation.mjs';
import { useAdminTicketAssessment } from '../../hooks/useAdminTicketAssessment.js';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../../bridge/assessmentPanelIntent.mjs';

const BASE = '/api/secureshop/admin/tickets';
const ticketId = value => typeof value === 'string' && /^[1-9]\d{0,18}$/.test(value);

async function readJson(response) {
  if (!response.ok) {
    const error = Error('Ticket read unavailable'); error.status = response.status; throw error;
  }
  if (!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || ''))
    throw Error('Ticket response unavailable');
  return response.json();
}

export function AdminTicketsView({ transport, authorityKey, shopUserId }) {
  const [tickets, setTickets] = useState([]), [nextCursor, setNextCursor] = useState(null);
  const [selectedId, setSelectedId] = useState(null), [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true), [reading, setReading] = useState(false);
  const [error, setError] = useState(null), [detailError, setDetailError] = useState(null);
  const generation = useRef(0), listAbort = useRef(null), detailAbort = useRef(null);
  const live = useRef({ transport, authorityKey }); live.current = { transport, authorityKey };
  const assessment = useAdminTicketAssessment({ shopUserId, authorityKey, transport });
  const current = (epoch, controller) => generation.current === epoch && !controller.signal.aborted
    && live.current.transport === transport && live.current.authorityKey === authorityKey;
  const clearAuthority = useCallback(() => {
    generation.current += 1; listAbort.current?.abort(); detailAbort.current?.abort();
    listAbort.current = null; detailAbort.current = null;
    setTickets([]); setNextCursor(null); setSelectedId(null); setDetail(null);
    setLoading(false); setReading(false); setError('Administrator ticket access is unavailable.');
    setDetailError(null);
  }, []);
  useEffect(() => { if (assessment.accessLost) clearAuthority(); }, [assessment.accessLost, clearAuthority]);

  const load = useCallback(async (cursor = null) => {
    if (typeof transport !== 'function') return;
    listAbort.current?.abort();
    const controller = new AbortController(), epoch = generation.current;
    listAbort.current = controller; setLoading(true); setError(null);
    try {
      const url = cursor === null ? BASE : `${BASE}?cursor=${encodeURIComponent(cursor)}`;
      const response = await transport(url, { method: 'GET', headers: { accept: 'application/json' },
        signal: controller.signal });
      const value = decodeAdminTicketList(await readJson(response));
      if (!current(epoch, controller)) return;
      setTickets(previous => cursor === null ? value.tickets : [...previous, ...value.tickets]);
      setNextCursor(value.nextCursor);
    } catch (cause) {
      if (!current(epoch, controller)) return;
      if ([401, 403].includes(cause.status)) { clearAuthority(); return; }
      if (cursor === null) { setTickets([]); setNextCursor(null); setSelectedId(null); setDetail(null); }
      setError('Tickets could not be loaded. Try again.');
    } finally {
      if (current(epoch, controller)) setLoading(false);
      if (listAbort.current === controller) listAbort.current = null;
    }
  }, [transport, authorityKey, clearAuthority]);

  const read = useCallback(async id => {
    if (!ticketId(id) || typeof transport !== 'function') return;
    detailAbort.current?.abort();
    const controller = new AbortController(), epoch = generation.current;
    detailAbort.current = controller; setSelectedId(id); setDetail(null);
    setDetailError(null); setReading(true);
    try {
      const response = await transport(`${BASE}/${id}`, { method: 'GET',
        headers: { accept: 'application/json' }, signal: controller.signal });
      const value = await verifyAdminTicketDetail(await readJson(response));
      if (!current(epoch, controller)) return;
      if (value.ticketId !== id || !tickets.some(ticket => ticket.ticketId === id
        && ticket.subject === value.subject)) throw Error('Ticket response does not match the selected row');
      setDetail(value);
    } catch (cause) {
      if (!current(epoch, controller)) return;
      if ([401, 403].includes(cause.status)) { clearAuthority(); return; }
      setDetail(null); setDetailError('Ticket detail could not be verified. Try again.');
    } finally {
      if (current(epoch, controller)) setReading(false);
      if (detailAbort.current === controller) detailAbort.current = null;
    }
  }, [transport, authorityKey, tickets, clearAuthority]);

  useEffect(() => {
    generation.current += 1; setTickets([]); setNextCursor(null); setSelectedId(null);
    setDetail(null); setDetailError(null); setError(null);
    void load();
    return () => { generation.current += 1;
      listAbort.current?.abort(); detailAbort.current?.abort(); };
  }, [authorityKey, transport, load]);

  useEffect(() => {
    const clearDetail = () => { detailAbort.current?.abort(); setSelectedId(null);
      setDetail(null); setDetailError(null); };
    // The parent Shop settings mode selector takes focus outside this frame.
    // A previous vulnerable detail must not remain mounted after a mode change.
    window.addEventListener('blur', clearDetail);
    return () => window.removeEventListener('blur', clearDetail);
  }, []);

  return <PageTransition>
    <section aria-label="Admin support tickets" style={{ display: 'grid', gap: 16 }}>
      <header><div className="ss-card__meta">ADMIN · SUPPORT</div>
        <h1 className="ss-display" style={{ fontSize: 36, margin: '4px 0' }}>Tickets</h1>
        <p>Review customer support tickets in this practice.</p></header>
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          disabled={loading} onClick={() => load()}>Refresh tickets</button>
      </div>
      {loading && <p role="status">Loading tickets…</p>}
      {error && <p role="alert">{error}</p>}
      {!loading && !error && tickets.length === 0 && <p>No tickets in this practice.</p>}
      {tickets.length > 0 && <div className="ss-card" style={{ padding: 16 }}>
        <h2 style={{ fontFamily: 'var(--display)', marginTop: 0 }}>Open tickets</h2>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {tickets.map(ticket => <li key={ticket.ticketId}
            style={{ borderTop: '1px solid var(--rule)', padding: '12px 0' }}>
            <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
              aria-label={`Read ticket ${ticket.ticketId}: ${ticket.subject}`}
              onClick={() => read(ticket.ticketId)}>{ticket.subject}</button>
            <span className="ss-mono" style={{ marginLeft: 10, fontSize: 11 }}>
              #{ticket.ticketId} · {ticket.status} · {new Date(ticket.createdAt).toLocaleString()}
            </span>
          </li>)}
        </ul>
        {nextCursor && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          disabled={loading} onClick={() => load(nextCursor)}>More tickets</button>}
      </div>}
      {!assessment.accessLost && assessment.reference && <section className="ss-card" aria-label="Saved ticket assessment"
        style={{ padding: 16 }}>
        <div className="ss-card__meta">TICKET #{assessment.reference.ticketId} · ASSESSMENT</div>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          disabled={assessment.busy} onClick={() => void assessment.check()}>Check saved assessment</button>
        {assessment.outcome?.status === 'unconfirmed' && <p role="status">Assessment not confirmed. Check the saved result again.</p>}
        {assessment.outcome?.status === 'pending' && <p role="status">Assessment pending. Check the saved result again.</p>}
        {assessment.outcome?.status === 'ineligible' && <p role="status">This ticket is not eligible for objective credit.</p>}
        {assessment.outcome?.status === 'disabled' && <p role="status">This ticket objective is disabled.</p>}
        {assessment.outcome?.judgment && <p role="status">{assessment.outcome.judgment.verdict === 'unavailable'
          ? 'Grading unavailable. The saved ticket remains available.'
          : assessment.outcome.completed ? 'Objective completed.' : 'Assessment completed without objective credit.'}</p>}
        {assessment.outcome?.judgment?.verdict === 'unavailable' && isStandaloneShopFrame()
          && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            onClick={() => openStandaloneAssessments(assessment.outcome.judgment.evaluationId)}>
            Open saved assessments</button>}
        {detail && detail.ticketId !== assessment.reference.ticketId && assessment.outcome
          && !['unconfirmed', 'pending'].includes(assessment.outcome.status)
          && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            disabled={assessment.busy} onClick={() => void assessment.clearCompleted(detail.ticketId)}>
            Switch to selected ticket</button>}
      </section>}
      {assessment.error && <p role="alert">{assessment.error}</p>}
      {selectedId && <section className="ss-card" aria-label="Selected ticket detail"
        style={{ padding: 16 }}>
        {reading && <p role="status">Reading ticket…</p>}
        {detailError && <p role="alert">{detailError}</p>}
        {detail && <>
          <div className="ss-card__meta">TICKET #{detail.ticketId} · {detail.status}</div>
          <h2 style={{ fontFamily: 'var(--display)' }}>{detail.subject}</h2>
          <AdminTicketBody body={detail.body} modeCapability={detail.modeCapability} />
          <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            onClick={() => read(detail.ticketId)}>Refresh ticket detail</button>
          {!assessment.reference && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            disabled={assessment.busy} onClick={() => void assessment.start(detail.ticketId)}>Check ticket</button>}
        </>}
      </section>}
    </section>
  </PageTransition>;
}

export default function AdminTickets() {
  const { user, token } = useAuth() || {};
  const transport = globalThis.fetch;
  const authorityKey = `${user?.id || 0}:${user?.role || ''}:${token || ''}`;
  return <AdminTicketsView key={authorityKey} transport={transport} authorityKey={authorityKey}
    shopUserId={user?.id} />;
}
