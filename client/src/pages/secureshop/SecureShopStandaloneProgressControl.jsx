import React, { useEffect, useRef, useState } from 'react';

const PAGE_SIZE = 25;
const sectionStyle = { borderTop: '1px solid var(--rule)', marginTop: 20, paddingTop: 16 };
const mutedStyle = { fontSize: 12, opacity: 0.72 };

function ProgressSummary({ progress, title }) {
  return <div aria-label={title} style={{ marginTop: 12 }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>
      {progress.completedObjectives} of {progress.totalObjectives} objectives completed
    </div>
    {progress.objectives.length === 0
      ? <p style={mutedStyle}>No enabled, qualified objectives are available.</p>
      : <ul style={{ listStyle: 'none', padding: 0, margin: '9px 0 0' }}>
        {progress.objectives.map(objective => <li key={objective.objectiveId}
          style={{ display: 'flex', gap: 10, alignItems: 'baseline', padding: '7px 0',
            borderTop: '1px solid var(--rule)', fontSize: 13 }}>
          <span aria-hidden="true" style={{ color: objective.completed ? 'var(--copper)' : 'var(--ink)' }}>
            {objective.completed ? '✓' : '○'}
          </span>
          <span>{objective.label}</span>
          <span className="ss-mono" style={{ fontSize: 10, marginLeft: 'auto', opacity: 0.7 }}>
            {objective.completed ? 'Completed' : 'Open'}
          </span>
        </li>)}
      </ul>}
  </div>;
}

export default function SecureShopStandaloneProgressControl({ client, user }) {
  const [self, setSelf] = useState(null);
  const [selfState, setSelfState] = useState('loading');
  const [learners, setLearners] = useState([]);
  const [nextCursor, setNextCursor] = useState(null);
  const [listState, setListState] = useState(user?.role === 'admin' ? 'loading' : 'idle');
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailState, setDetailState] = useState('idle');
  const controllers = useRef({ self: null, list: null, detail: null });

  const clearAuthorization = status => {
    Object.values(controllers.current).forEach(controller => controller?.abort());
    setLearners([]);
    setNextCursor(null);
    setSelected(null);
    setDetail(null);
    setDetailState('idle');
    setListState(status === 401 ? 'signed-out' : 'forbidden');
    setSelf(null);
    setSelfState(status === 401 ? 'signed-out' : 'error');
  };

  const loadSelf = async () => {
    controllers.current.self?.abort();
    const controller = new AbortController();
    controllers.current.self = controller;
    setSelfState('loading');
    try {
      const value = await client.getProgress(controller.signal);
      if (controller.signal.aborted) return;
      if (value.principalId !== user.principalId.toLowerCase() || value.role !== user.role) {
        throw new Error('Current shop progress could not be verified');
      }
      setSelf(value);
      setSelfState('ready');
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error.status === 401) clearAuthorization(401);
      else { setSelf(null); setSelfState('error'); }
    }
  };

  const loadLearners = async (cursor = null) => {
    if (user?.role !== 'admin') return;
    controllers.current.list?.abort();
    if (cursor === null) {
      controllers.current.detail?.abort();
      setSelected(null);
      setDetail(null);
      setDetailState('idle');
    }
    const controller = new AbortController();
    controllers.current.list = controller;
    setListState('loading');
    try {
      const page = await client.getAdminProgressLearners({ limit: PAGE_SIZE, cursor }, controller.signal);
      if (controller.signal.aborted) return;
      if (cursor !== null && (page.learners.some(row => row.shopUserId <= cursor)
        || page.nextCursor !== null && page.nextCursor <= cursor)) {
        throw new Error('Current shop learner list could not be verified');
      }
      setLearners(previous => cursor === null ? page.learners : [...previous, ...page.learners]);
      setNextCursor(page.nextCursor);
      setListState('ready');
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error.status === 401 || error.status === 403) clearAuthorization(error.status);
      else {
        if (cursor === null) { setLearners([]); setNextCursor(null); }
        setListState('error');
      }
    }
  };

  const loadDetail = async row => {
    if (user?.role !== 'admin' || !learners.some(item => item.principalId === row.principalId)) return;
    controllers.current.detail?.abort();
    const controller = new AbortController();
    controllers.current.detail = controller;
    setSelected(row);
    setDetail(null);
    setDetailState('loading');
    try {
      const value = await client.getAdminProgress(row.principalId, controller.signal);
      if (controller.signal.aborted) return;
      if (value.principalId !== row.principalId || value.shopUserId !== row.shopUserId) {
        throw new Error('Current shop learner progress could not be verified');
      }
      setDetail(value);
      setDetailState('ready');
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error.status === 401 || error.status === 403) clearAuthorization(error.status);
      else setDetailState('error');
    }
  };

  useEffect(() => {
    void loadSelf();
    if (user?.role === 'admin') void loadLearners();
    return () => Object.values(controllers.current).forEach(controller => controller?.abort());
  }, [client, user?.principalId, user?.role]);

  return <section aria-label="Shop progress" style={sectionStyle}>
    <strong className="ss-display" style={{ fontSize: 17 }}>Shop progress</strong>
    <p style={{ ...mutedStyle, margin: '6px 0 10px' }}>
      Current practice objectives and saved completions.
    </p>
    {selfState === 'loading' && <p role="status" style={mutedStyle}>Loading your progress…</p>}
    {selfState === 'ready' && self && <ProgressSummary progress={self} title="Your progress" />}
    {['error', 'signed-out'].includes(selfState) && <div role="alert" style={{ color: 'var(--rust)', fontSize: 12 }}>
      {selfState === 'signed-out' ? 'Sign in again to view progress.' : 'Your progress could not be loaded.'}
      <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={loadSelf}
        style={{ marginLeft: 8 }}>Retry progress</button>
    </div>}
    {selfState === 'ready' && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
      onClick={loadSelf} style={{ marginTop: 9 }}>Refresh progress</button>}

    {user?.role === 'admin' && <div style={{ ...sectionStyle, marginTop: 16 }} aria-label="Learner progress">
      <strong className="ss-display" style={{ fontSize: 15 }}>Learners in this shop</strong>
      {listState === 'loading' && <p role="status" style={mutedStyle}>Loading learners…</p>}
      {listState === 'forbidden' && <p role="alert" style={{ color: 'var(--rust)' }}>
        Shop administrator access is required.
      </p>}
      {listState === 'signed-out' && <p role="alert" style={{ color: 'var(--rust)' }}>
        Sign in again to view learner progress.
      </p>}
      {listState === 'error' && <p role="alert" style={{ color: 'var(--rust)' }}>
        Learners could not be loaded. <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
          onClick={() => loadLearners()}>Retry learners</button>
      </p>}
      {listState === 'ready' && learners.length === 0 && <p style={mutedStyle}>No learners found.</p>}
      {learners.length > 0 && <ul style={{ listStyle: 'none', padding: 0, margin: '10px 0' }}>
        {learners.map(row => <li key={row.principalId} style={{ borderTop: '1px solid var(--rule)', padding: '7px 0' }}>
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            aria-pressed={selected?.principalId === row.principalId}
            onClick={() => loadDetail(row)} style={{ width: '100%', textAlign: 'left' }}>
            {row.username} · {row.completedObjectives}/{row.totalObjectives} completed
          </button>
        </li>)}
      </ul>}
      {listState === 'ready' && nextCursor !== null && <button type="button"
        className="ss-btn ss-btn--ghost ss-btn--sm" onClick={() => loadLearners(nextCursor)}>
        More learners
      </button>}
      {selected && <div aria-label={`${selected.username} progress`} style={sectionStyle}>
        <strong style={{ fontSize: 13 }}>{selected.username}</strong>
        {detailState === 'loading' && <p role="status" style={mutedStyle}>Loading learner progress…</p>}
        {detailState === 'ready' && detail && <ProgressSummary progress={detail}
          title={`${selected.username} objectives`} />}
        {['error', 'forbidden'].includes(detailState) && <p role="alert"
          style={{ color: 'var(--rust)', fontSize: 12 }}>
          {detailState === 'forbidden' ? 'Shop administrator access is required.'
            : 'Learner progress could not be loaded.'}
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            onClick={() => loadDetail(selected)} style={{ marginLeft: 8 }}>Retry learner</button>
        </p>}
      </div>}
    </div>}
  </section>;
}
