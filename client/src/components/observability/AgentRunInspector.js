import { judgeFailureMessage, judgeValidationMessage, judgeStageLabel } from '../../utils/judgeFailureMessage.mjs';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import styled from 'styled-components';
import axios from 'axios';
import { FiActivity, FiAlertCircle, FiCheckCircle, FiClock, FiCpu, FiRefreshCw, FiTool } from 'react-icons/fi';
import JudgeRetryButton from '../workshop/JudgeRetryButton';
import { loadAgentRunDetail } from '../../utils/loadAgentRunDetail';

const Shell = styled.section`
  background: #fff; border: 1px solid #e2e8f0; border-radius: 16px; overflow: hidden;
  box-shadow: 0 8px 24px rgba(15, 23, 42, 0.07); color: #1e293b;
`;
const Header = styled.header`
  padding: 1.2rem 1.35rem; border-bottom: 1px solid #e2e8f0; display: flex; gap: 1rem;
  align-items: center; justify-content: space-between; flex-wrap: wrap;
  h2 { margin: 0; font-size: 1.15rem; display: flex; gap: .55rem; align-items: center; }
  p { margin: .3rem 0 0; color: #64748b; font-size: .88rem; }
`;
const Controls = styled.div`display: flex; gap: .6rem; align-items: center; flex-wrap: wrap;`;
const Select = styled.select`
  border: 1px solid #cbd5e1; border-radius: 9px; background: #fff; color: #334155; padding: .55rem .7rem;
`;
const Input = styled.input`
  width: 120px; border: 1px solid #cbd5e1; border-radius: 9px; background: #fff; color: #334155; padding: .55rem .7rem;
`;
const Button = styled.button`
  border: 0; border-radius: 9px; background: #4f46e5; color: white; padding: .58rem .82rem; font-weight: 650;
  display: inline-flex; align-items: center; gap: .4rem; cursor: pointer;
  &:disabled { opacity: .55; cursor: wait; }
`;
const Layout = styled.div`
  display: grid; grid-template-columns: minmax(220px, 34%) 1fr; min-height: 420px;
  @media (max-width: 760px) { grid-template-columns: 1fr; }
`;
const RunList = styled.div`
  border-right: 1px solid #e2e8f0; background: #f8fafc; padding: .65rem; max-height: 620px; overflow: auto;
  @media (max-width: 760px) { border-right: 0; border-bottom: 1px solid #e2e8f0; max-height: 260px; }
`;
const RunButton = styled.button`
  width: 100%; text-align: left; border: 1px solid ${p => p.$active ? '#818cf8' : '#e2e8f0'};
  background: ${p => p.$active ? '#eef2ff' : '#fff'}; border-radius: 11px; padding: .8rem; margin-bottom: .55rem;
  color: #1e293b; cursor: pointer;
  strong { display: block; font-size: .88rem; overflow-wrap: anywhere; }
  span { display: flex; justify-content: space-between; gap: .5rem; margin-top: .45rem; color: #64748b; font-size: .76rem; }
`;
const Detail = styled.div`padding: 1.1rem 1.25rem; min-width: 0;`;
const Summary = styled.div`
  display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: .65rem; margin-bottom: 1.1rem;
`;
const Fact = styled.div`
  border: 1px solid #e2e8f0; border-radius: 10px; padding: .7rem; min-width: 0;
  label { display: block; color: #64748b; font-size: .7rem; text-transform: uppercase; letter-spacing: .04em; }
  strong { display: block; margin-top: .25rem; font-size: .84rem; overflow-wrap: anywhere; }
`;
const Timeline = styled.ol`list-style: none; margin: 0; padding: 0;`;
const Topology = styled.div`
  margin: 0 0 1.1rem; padding: .75rem; border-radius: 10px; background: #f8fafc; border: 1px solid #e2e8f0;
  h3 { margin: 0 0 .5rem; font-size: .84rem; }
  p { margin: .25rem 0; color: #475569; font-size: .76rem; overflow-wrap: anywhere; }
`;
const Event = styled.li`
  position: relative; margin-left: .6rem; padding: 0 0 1rem 1.4rem; border-left: 2px solid #e2e8f0;
  &::before { content: ''; position: absolute; left: -6px; top: 4px; width: 10px; height: 10px; border-radius: 50%; background: ${p => p.$error ? '#ef4444' : p.$tool ? '#f59e0b' : '#6366f1'}; }
  &:last-child { border-left-color: transparent; }
`;
const EventTop = styled.div`
  display: flex; justify-content: space-between; gap: .8rem; align-items: start;
  strong { font-size: .88rem; overflow-wrap: anywhere; }
  time { color: #64748b; font-size: .72rem; flex: none; }
`;
const Chips = styled.div`display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .45rem;`;
const Chip = styled.span`
  background: ${p => p.$error ? '#fef2f2' : '#f1f5f9'}; color: ${p => p.$error ? '#b91c1c' : '#475569'};
  border-radius: 999px; padding: .25rem .5rem; font-size: .72rem; overflow-wrap: anywhere;
`;
const State = styled.div`padding: 2.5rem 1rem; text-align: center; color: ${p => p.$error ? '#b91c1c' : '#64748b'};`;
const Recovery = styled.section`
  padding: .9rem 1.35rem; border-bottom: 1px solid #e2e8f0; background: #fffbeb;
  h3 { margin: 0 0 .25rem; font-size: .92rem; }
  > p { margin: 0 0 .7rem; color: #64748b; font-size: .78rem; }
`;
const RecoveryList = styled.ul`
  list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: .55rem;
`;
const RecoveryItem = styled.li`
  background: #fff; border: 1px solid #fde68a; border-radius: 10px; padding: .7rem;
  strong { display: block; font-size: .84rem; overflow-wrap: anywhere; }
  span { display: block; margin-top: .25rem; color: #64748b; font-size: .74rem; overflow-wrap: anywhere; }
`;
const Judgments = styled.section`
  margin: 0 0 1.1rem; padding: .75rem; border-radius: 10px; background: #f8fafc; border: 1px solid #e2e8f0;
  h3 { margin: 0 0 .55rem; font-size: .84rem; }
`;
const Judgment = styled.div`
  padding: .65rem 0; border-top: 1px solid #e2e8f0;
  &:first-of-type { border-top: 0; padding-top: 0; }
  strong { display: block; font-size: .82rem; overflow-wrap: anywhere; }
  span { display: block; margin-top: .22rem; color: #475569; font-size: .74rem; overflow-wrap: anywhere; }
`;

const FAMILY_LABELS = Object.freeze({
  ARIA: 'ARIA · SQL', NOVA: 'NOVA · NoSQL', 'ARIA:legacy': 'ARIA legacy · SQL',
  'NOVA:legacy': 'NOVA legacy · NoSQL', CodeBot: 'CodeBot · Supply Chain', RAG: 'RAG Injection',
  XSS_EMAIL: 'XSS email builder', DPI: 'Direct prompt injection', IndirectEmail: 'Indirect email',
  ExcessiveAgency: 'Excessive agency', FinFlow: 'FinFlow · Sensitive info',
  LegacySensitiveInfo: 'Legacy sensitive info', SensitiveLookup: 'Sensitive lookup',
  SecureShopBoundConversation: 'SecureShop bound conversation',
});
const DETAIL_ACCESS_DENIAL_STATUSES = new Set([401, 403, 404]);

function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}
function duration(run) {
  if (!run?.startedAt) return '—';
  const end = run.finishedAt ? new Date(run.finishedAt).getTime() : Date.now();
  const millis = end - new Date(run.startedAt).getTime();
  return Number.isFinite(millis) && millis >= 0 ? `${Math.round(millis)} ms` : '—';
}
function runNodeLabel(run) {
  if (run.lastNode) return run.lastNode;
  switch (run.status) {
    case 'queued': return 'Starting';
    case 'running': return 'Running';
    case 'completed': return 'Completed';
    case 'failed': return 'Failed';
    case 'cancelled': return 'Cancelled';
    default: return 'No node recorded';
  }
}

function statusIcon(status) {
  if (status === 'completed') return <FiCheckCircle aria-hidden="true" />;
  if (status === 'failed' || status === 'cancelled') return <FiAlertCircle aria-hidden="true" />;
  return <FiClock aria-hidden="true" />;
}
function judgmentState(judgment) {
  if (!judgment || judgment.disposition === 'pending' || judgment.verdict == null) return 'pending';
  return judgment.disposition || judgment.verdict;
}

function ProtectedOperationReceipt({ operation, admin, onRefresh }) {
  const [pending,setPending]=useState(false),[failure,setFailure]=useState('');
  const controller=useRef(null);
  useEffect(()=>()=>controller.current?.abort(),[]);
  const read=async()=>{
    if(controller.current||admin||!operation.canReconcile)return;
    const active=new AbortController();controller.current=active;setPending(true);setFailure('');
    try{
      const {data}=await axios.post('/api/workshop/mcp/protected-operations/reconcile',{operationId:operation.operationId},{signal:active.signal});
      if(active.signal.aborted)return;
      if(data?.operationId!==operation.operationId||data.originalEffectStatus!=='uncertain'||data.creditGranted!==false||!['completed','uncertain','absent'].includes(data.outcome))throw Error('Invalid recovery metadata');
      onRefresh();
    }catch(error){if(!active.signal.aborted)setFailure(error.response?.status===404?'This operation is unavailable in the current session.':'Receipt readback is unavailable. The original run has not changed.');}
    finally{if(controller.current===active){controller.current=null;if(!active.signal.aborted)setPending(false);}}
  };
  return <Judgment data-protected-operation-id={operation.operationId}>
    <strong>{operation.operation} · Original effect: {operation.originalEffectStatus}</strong>
    <span>Operation: {operation.operationId}</span><span>Origin: {operation.origin}</span>
    <span>Receipt: {operation.outcome||'not checked'}</span>
    {operation.receiptDigest&&<span>Receipt digest: {operation.receiptDigest}</span>}
    {operation.observedAt&&<span>Checked: {formatTime(operation.observedAt)}</span>}
    <span>Receipt readback does not rerun the tool, change the original run, or award objective credit.</span>
    {!admin&&operation.canReconcile&&<Button onClick={read} disabled={pending}><FiRefreshCw />{pending?'Checking receipt…':'Check receipt'}</Button>}
    {!admin&&!operation.canReconcile&&<span>Readback requires the original active session and current exercise generation.</span>}
    {failure&&<span role="alert">{failure}</span>}
  </Judgment>;
}

export default function AgentRunInspector({ admin = false, endpoint }) {
  const resolvedEndpoint = endpoint || (admin ? '/api/admin/agent-runs' : '/api/agent-runs');
  const [family, setFamily] = useState('all');
  const [families, setFamilies] = useState([]);
  const [ownerId, setOwnerId] = useState('');
  const [runs, setRuns] = useState([]);
  const [nextCursor, setNextCursor] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [detailRevision, setDetailRevision] = useState(0);
  const [detailState, setDetailState] = useState({ endpoint: null, runId: null, value: null });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [pollingError, setPollingError] = useState('');
  const [judgments, setJudgments] = useState([]);
  const [judgmentsAvailable, setJudgmentsAvailable] = useState(!admin);
  const [judgmentsError, setJudgmentsError] = useState('');
  const judgmentRequestSequence = useRef(0);

  // A denial invalidates responses already in flight across detail and polling.
  const detailAccessEpoch = useRef(0);
  const runRequestSequence = useRef(0);
  const loadRuns = useCallback(async (before = null, signal) => {
    const requestSequence = ++runRequestSequence.current;
    const isCurrent = () => !signal?.aborted && requestSequence === runRequestSequence.current;
    setLoading(true); setError('');
    try {
      const response = await axios.get(resolvedEndpoint, { params: { ...(family !== 'all' ? { family } : {}),
        ...(admin && ownerId.trim() ? { ownerId: ownerId.trim() } : {}), ...(before ? { before } : {}), limit: 25 }, ...(signal ? { signal } : {}) });
      if (!isCurrent()) return;
      const received = Array.isArray(response.data) ? response.data : response.data.runs || [];
      if (Array.isArray(response.data?.families)) setFamilies(response.data.families);
      const next = received;
      setRuns(current => before ? [...current, ...next.filter(run => !current.some(item => item.runId === run.runId))] : next);
      setNextCursor(response.data?.nextCursor || null);
      if (!before) {
        setSelectedId(current => next.some(run => run.runId === current) ? current : next[0]?.runId || null);
        setDetailRevision(current => current + 1);
      }
    } catch (requestError) {
      if (!isCurrent()) return;
      setError(requestError.response?.data?.error || 'Agent runs could not be loaded.'); setRuns([]); setSelectedId(null);
    } finally { if (isCurrent()) setLoading(false); }
  }, [admin, family, ownerId, resolvedEndpoint]);

  const loadJudgments = useCallback(async (signal) => {
    const requestSequence = ++judgmentRequestSequence.current;
    const isCurrent = () => !signal?.aborted && requestSequence === judgmentRequestSequence.current;
    if (admin) return;
    try {
      const response = await axios.get('/api/agent-runs/judgments', { signal });
      if (!isCurrent()) return;
      setJudgments(Array.isArray(response.data?.judgments) ? response.data.judgments : []);
      setJudgmentsAvailable(true);
      setJudgmentsError('');
    } catch (requestError) {
      if (!isCurrent()) return;
      if (DETAIL_ACCESS_DENIAL_STATUSES.has(requestError.response?.status)) {
        setJudgments([]);
        setJudgmentsError('Recent evaluations are no longer accessible. Refresh after restoring access.');
      } else if (requestError.response?.data?.code === 'GRADE_STORE_NOT_READY') {
        setJudgments([]);
        setJudgmentsAvailable(false);
        setJudgmentsError('');
      } else {
        setJudgmentsError('Recent evaluations could not be loaded. Previously loaded results may be out of date. Use Refresh to retry.');
      }
    }
  }, [admin]);

  useEffect(() => {
    const controller = new AbortController();
    void loadRuns(null, controller.signal);
    return () => {
      controller.abort();
      // Also invalidate manual refresh/pagination responses on filter change or unmount.
      runRequestSequence.current += 1;
    };
  }, [loadRuns]);
  useEffect(() => {
    const controller = new AbortController();
    void loadJudgments(controller.signal);
    return () => { controller.abort(); judgmentRequestSequence.current += 1; };
  }, [loadJudgments]);
  useEffect(() => {
    let live = true;
    setDetailError('');
    setPollingError('');
    if (!selectedId) {
      setDetailState(current => current.endpoint === null && current.runId === null && current.value === null
        ? current : { endpoint: null, runId: null, value: null });
      return () => { live = false; };
    }
    setDetailState(current => current.endpoint === resolvedEndpoint && current.runId === selectedId
      ? current : { endpoint: resolvedEndpoint, runId: selectedId, value: null });
    const controller = new AbortController();
    const accessEpoch = detailAccessEpoch.current;
    loadAgentRunDetail(resolvedEndpoint, selectedId, controller.signal).then(response => {
      if (live && accessEpoch === detailAccessEpoch.current) {
        setDetailState({ endpoint: resolvedEndpoint, runId: selectedId, value: response });
      }
    }).catch(requestError => {
      if (!live || accessEpoch !== detailAccessEpoch.current) return;
      if (DETAIL_ACCESS_DENIAL_STATUSES.has(requestError.response?.status)) {
        detailAccessEpoch.current += 1;
        setDetailState({ endpoint: resolvedEndpoint, runId: selectedId, value: null });
      }
      setDetailError(requestError.response?.data?.error || 'Run detail could not be loaded.');
    });
    return () => { live = false; controller.abort(); };
  }, [resolvedEndpoint, selectedId, detailRevision]);

  const detailInScope = detailState.endpoint === resolvedEndpoint
    && detailState.runId === selectedId ? detailState.value : null;
  const selectedRun = detailInScope?.run || runs.find(run => run.runId === selectedId);
  const showSelectedDetail = Boolean(selectedRun) && (!detailError || detailInScope !== null);
  const events = detailInScope?.events || [];
  const responseRepairCount = events.filter(event => String(event?.node || '').endsWith('respond_repair')).length;
  const lastSequence = events.reduce((maximum, event) => Math.max(maximum, Number(event.seq) || 0), 0);
  const reportedTokens = selectedRun?.tokens ?? selectedRun?.usage?.totalTokens;
  const estimatedTokens = selectedRun?.estimatedTokens ?? selectedRun?.usage?.estimatedTokens;
  const handleRecoveryResult = useCallback(async (result, { signal } = {}) => {
    await Promise.all([loadJudgments(signal), loadRuns(null, signal)]);
    if (signal?.aborted) return;
    if (typeof result.retryRunId === 'string' && result.retryRunId) setSelectedId(result.retryRunId);
  }, [loadJudgments, loadRuns]);
  useEffect(() => {
    if (!selectedId || !['running', 'started', 'pending'].includes(String(selectedRun?.status || '').toLowerCase())) return undefined;
    let live = true;
    let inFlight = false;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      if (inFlight) return;
      inFlight = true;
      const accessEpoch = detailAccessEpoch.current;
      axios.get(`${resolvedEndpoint}/${encodeURIComponent(selectedId)}/events`, { params: { after: lastSequence, limit: 100 }, signal: controller.signal })
        .then(response => {
          if (!live || accessEpoch !== detailAccessEpoch.current) return;
          const nextRun = response.data?.run;
          if (nextRun && !['running', 'started', 'pending'].includes(String(nextRun.status || '').toLowerCase())) {
            // Keep polling active until the final detail (including receipts) arrives.
            // Publishing terminal status first would clean up and abort this refresh.
            return loadAgentRunDetail(resolvedEndpoint, selectedId, controller.signal)
              .then(full => { if (live && accessEpoch === detailAccessEpoch.current) {
                setDetailState({ endpoint: resolvedEndpoint, runId: selectedId, value: full });
                setDetailError(''); setPollingError('');
              } });
          }
          setPollingError('');
          setDetailState(current => {
            if (current.endpoint !== resolvedEndpoint || current.runId !== selectedId || !current.value) return current;
            const received = response.data?.events || [];
            return { ...current, value: { ...current.value, ...(nextRun ? { run: nextRun } : {}), events: [...current.value.events,
              ...received.filter(event => !current.value.events.some(item => item.seq === event.seq))] } };
          });
        }).catch(requestError => {
          if (live && !controller.signal.aborted && accessEpoch === detailAccessEpoch.current) {
            const accessDenied = DETAIL_ACCESS_DENIAL_STATUSES.has(requestError.response?.status);
            if (accessDenied) {
              detailAccessEpoch.current += 1;
              setDetailState({ endpoint: resolvedEndpoint, runId: selectedId, value: null });
              setDetailError(requestError.response?.data?.error || 'Run detail is no longer available.');
              setPollingError('');
            } else {
              setPollingError('Live updates are temporarily unavailable. Showing the last recorded state; retrying automatically.');
            }
          }
        }).finally(() => { inFlight = false; });
    }, 4000);
    return () => { live = false; controller.abort(); window.clearInterval(timer); };
  }, [lastSequence, resolvedEndpoint, selectedId, selectedRun?.status]);
  return <Shell aria-label={admin ? 'Administrator agent run inspector' : 'Your agent run inspector'}>
    <Header><div><h2><FiActivity aria-hidden="true" /> Agent Run Inspector</h2>
      <p>{admin ? 'Review graph execution metadata for workshop agents.' : 'See how your workshop agent moved through its graph.'}</p></div>
      <Controls><label><span className="sr-only">Agent family</span><Select value={family} onChange={event => setFamily(event.target.value)}>
        {[['all', 'All workshop agents'], ...families.map(value => [value, FAMILY_LABELS[value] || value])]
          .map(([value, label]) => <option value={value} key={value}>{label}</option>)}</Select></label>
        {admin && <label><span className="sr-only">Owner ID</span><Input aria-label="Owner ID" inputMode="numeric" placeholder="Owner ID" value={ownerId} onChange={event => setOwnerId(event.target.value)} /></label>}
        <Button type="button" onClick={() => { void loadRuns(); void loadJudgments(); }} disabled={loading}><FiRefreshCw aria-hidden="true" /> Refresh</Button></Controls>
    </Header>
    {!admin && judgmentsError && <State $error role="alert">{judgmentsError}</State>}
    {!admin && judgmentsAvailable && judgments.length > 0 && <Recovery aria-label="Recent evaluation recovery">
      <h3>Recent evaluations</h3>
      <p>Review Judge outcomes and retry a stored unavailable evaluation without resending the workshop action.</p>
      <RecoveryList>{judgments.map(judgment => <RecoveryItem key={judgment.evaluationId}>
        <strong>{judgment.family || 'Workshop'} · {judgment.objectiveId || 'Objective'}</strong>
        <span>Verdict: {judgment.verdict || 'pending'} · State: {judgmentState(judgment)} · Recorded: {formatTime(judgment.createdAt)}</span>
        {judgment.disposition === 'grading_unqualified' && <span>Grading pending qualification; no completion awarded.</span>}
        {judgment.scenario && <span>Scenario: {judgment.scenario}</span>}
        {(judgment.expiresAt || judgment.packetExpiresAt) && <span>Expires: {formatTime(judgment.expiresAt || judgment.packetExpiresAt)}</span>}
        {judgment.verdict === 'unavailable' && judgeFailureMessage(judgment.errorCode) && <span>{judgeFailureMessage(judgment.errorCode)}</span>}
        {judgment.childEvaluationId && <span>Retry recorded: {judgment.childEvaluationId}</span>}
        <JudgeRetryButton evaluationId={judgment.evaluationId} canRetry={judgment.canRetry} onResult={handleRecoveryResult} />
      </RecoveryItem>)}</RecoveryList>
    </Recovery>}
    {error && <State $error role="alert">{error}</State>}
    {!error && <Layout><RunList aria-label="Agent runs">
      {loading && !runs.length ? <State>Loading runs…</State> : runs.length ? <>{runs.map(run => <RunButton type="button" key={run.runId}
        data-run-id={run.runId} $active={run.runId === selectedId} aria-pressed={run.runId === selectedId} onClick={() => setSelectedId(run.runId)}>
        <strong>{run.family || 'Workshop agent'} · {runNodeLabel(run)}</strong>
        <span><span>{statusIcon(run.status)} {run.status || 'unknown'}</span><time>{formatTime(run.startedAt)}</time></span>
      </RunButton>)}{nextCursor && <Button type="button" onClick={() => loadRuns(nextCursor)} disabled={loading}>Load earlier</Button>}</> : <State>No agent runs match this view.</State>}
    </RunList><Detail>
      {pollingError && <State $error role="alert">{pollingError}</State>}
      {detailError && <State $error role="alert">{detailError}</State>}
      {!selectedRun ? !detailError && <State>Select a run to inspect its graph timeline.</State> : showSelectedDetail ? <>
        <Summary>
          <Fact><label>Run</label><strong>{selectedRun.runId}</strong></Fact><Fact><label>Agent</label><strong>{selectedRun.family || '—'}</strong></Fact>
          <Fact><label>Status</label><strong>{selectedRun.status || 'unknown'}</strong></Fact><Fact><label>Duration</label><strong>{duration(selectedRun)}</strong></Fact>
          <Fact><label>Last node</label><strong>{selectedRun.lastNode || '—'}</strong></Fact><Fact><label>Generation</label><strong>{selectedRun.generation ?? '—'}</strong></Fact>
          <Fact><label>Provider</label><strong>{selectedRun.provider || 'unavailable'}</strong></Fact><Fact><label>Model</label><strong>{selectedRun.model || 'unavailable'}</strong></Fact>
          <Fact><label>Decision source</label><strong>{selectedRun.decisionSource || 'unavailable'}</strong></Fact>
          <Fact><label>Token usage</label><strong>{reportedTokens ?? (estimatedTokens !== undefined ? `estimated ${estimatedTokens}` : 'unavailable')}</strong></Fact>
          {responseRepairCount > 0 && <Fact><label>Response assistance</label><strong>{responseRepairCount} bounded model repair{responseRepairCount === 1 ? '' : 's'} used</strong></Fact>}
        </Summary>
        {detailInScope?.protectedOperationsStatus==='unavailable'&&<State $error>Protected operation receipts are unavailable.</State>}
        {Array.isArray(detailInScope?.protectedOperations)&&detailInScope.protectedOperations.length>0&&<Judgments aria-label="Protected operation receipts"><h3>Protected operation receipts</h3>{detailInScope.protectedOperations.map(operation=><ProtectedOperationReceipt key={`${selectedId}:${operation.operationId}`} operation={operation} admin={admin} onRefresh={()=>setDetailRevision(v=>v+1)} />)}</Judgments>}
        {Array.isArray(detailInScope?.judgments) && detailInScope.judgments.length > 0 && <Judgments aria-label="Authoritative Judge receipts">
          <h3>Authoritative Judge receipts</h3>
          {detailInScope.judgments.map(judgment => <Judgment key={judgment.receiptId || judgment.evaluationId || `${judgment.source || 'receipt'}-${judgment.objectiveId || 'objective'}`}>
            <strong>{judgment.family || selectedRun.family || 'Workshop'} · {judgment.objectiveId || 'Objective'} · {judgmentState(judgment)}</strong>
            {judgment.source && <span>Receipt source: {judgment.source}</span>}
            {judgment.scenario && <span>Scenario: {judgment.scenario}</span>}
            <span>Verdict: {judgment.verdict || 'pending'} · Disposition: {judgmentState(judgment)}</span>
        {judgment.disposition === 'grading_unqualified' && <span>Grading pending qualification; no completion awarded.</span>}
            {judgment.serverObservation?.version === 'saved-mail-browser-observation-v1' && <span>
              Server observations: Inbox component mounted: {judgment.serverObservation.componentMounted ? 'yes' : 'no'}
              {' · '}Browser effect completed: {judgment.serverObservation.browserEffectCompleted ? 'yes' : 'no'}
              {' · '}Attributed execution: {judgment.serverObservation.attributedExecution ? 'yes' : 'no'}
              {' · '}Target effect observed: {judgment.serverObservation.targetEffectObserved ? 'yes' : 'no'}
              {' · '}Observation provenance: {judgment.serverObservation.provenanceDigest}
            </span>}
            {judgment.verdict === 'unavailable' && judgeFailureMessage(judgment.errorCode) && <span>{judgeFailureMessage(judgment.errorCode)}</span>}
            {judgment.explanation && !(judgment.verdict === 'unavailable' && judgment.errorCode === 'INVALID_JUDGE_OUTPUT' && judgment.explanation.trim() === 'The judge returned invalid results; please retry.') && <span>{judgment.serverObservation ? 'Model rationale (may contain errors)' : 'Evaluation explanation'}: {judgment.explanation}</span>}
            {Array.isArray(judgment.criteria) && judgment.criteria.map((criterion, index) => <span key={`${criterion.id || 'criterion'}-${index}`}>
              Criterion {criterion.id || 'unknown'}: {criterion.satisfied ? 'satisfied' : 'not satisfied'}{criterion.evidenceRefs?.length ? ` · Evidence: ${criterion.evidenceRefs.join(', ')}` : ''}
              {Array.isArray(criterion.citations) && criterion.citations.map((citation, citationIndex) => <span key={`${citation.evidenceId}-${citationIndex}`}> · Citation {citation.evidenceId}: “{citation.quote}”</span>)}
            </span>)}
            {(judgment.judgeProvider || judgment.judgeModel) && <span>Judge: {judgment.judgeProvider || 'provider unavailable'} · {judgment.judgeModel || 'model unavailable'}</span>}
            {judgment.comparisonVersion && <span>Comparison version: {judgment.comparisonVersion}</span>}
            {Array.isArray(judgment.comparisonStages) && judgment.comparisonStages.map((stage, index) => <span key={`comparison-${index}`}>
              Judge stage: {judgeStageLabel(judgment.comparisonVersion, stage.stage)}
              {' · '}{Number.isInteger(stage.attempts) && stage.attempts >= 0 ? `${stage.attempts} attempt${stage.attempts === 1 ? '' : 's'}` : 'Attempts unavailable'}
              {' · '}{stage.provider || 'Provider unavailable'} · {stage.model || 'Model unavailable'}
              {' · '}{stage.completed === true ? 'Completed' : stage.completed === false ? 'Incomplete' : 'Completion status unavailable'}
            </span>)}
            {judgment.usage && <span>Measured Judge tokens: {judgment.usage.totalTokens ?? judgment.usage.outputTokens ?? 'unavailable'}</span>}
            {judgment.rubricVersion && <span>Rubric: {judgment.rubricVersion}</span>}
            {judgment.evaluationId && <span>Evaluation: {judgment.evaluationId}</span>}
            {judgment.evidenceDigest && <span>Evidence digest: {judgment.evidenceDigest}</span>}
            {judgment.configDigest && <span>Configuration digest: {judgment.configDigest}</span>}
            {judgment.evaluatedAt && <span>Evaluated: {formatTime(judgment.evaluatedAt)}</span>}
            {judgment.childEvaluationId && <span>Retry recorded: {judgment.childEvaluationId}</span>}
          </Judgment>)}
        </Judgments>}
        {detailInScope?.receiptSources?.some(source => source.status === 'unavailable') && <State>A Judge receipt source is temporarily unavailable.</State>}
        {detailInScope && Array.isArray(detailInScope.judgments) && detailInScope.judgments.length === 0 && !detailInScope.receiptSources?.some(source => source.status === 'unavailable') && <State>No Judge receipt is linked to this run.</State>}
        {detailInScope?.graph && <Topology aria-label="Registered graph topology"><h3>Registered graph</h3>
          {Array.isArray(detailInScope.graph.nodes) && detailInScope.graph.nodes.map(node => <p key={typeof node === 'string' ? node : node.id || node.name}>
            Node · {typeof node === 'string' ? node : node.name || node.id}</p>)}
          {Array.isArray(detailInScope.graph.edges) && detailInScope.graph.edges.map((edge, index) => <p key={`${edge.source || edge.from}-${edge.target || edge.to}-${index}`}>
            Edge · {edge.source || edge.from} → {edge.target || edge.to}{edge.condition ? ` · ${edge.condition}` : edge.conditional === true ? ' · conditional' : ''}</p>)}
          {detailInScope.graph.scope === 'registered-current' && <p>Current registered topology; not a historical execution record.</p>}
          {Array.isArray(detailInScope.graph.subgraphs) && detailInScope.graph.subgraphs.filter(child => child && typeof child.id === 'string').map(child => <section key={child.id} aria-label="Conditional registered subgraph">
            <h3>Registered subgraph · {child.id}</h3><p>Invoked by {child.parentNode} · {child.activation}. Registration does not establish execution.</p>
            {Array.isArray(child.nodes) && child.nodes.filter(node => node && typeof node.id === 'string').map(node => <p key={node.id}>Node · {node.id}</p>)}
            {Array.isArray(child.edges) && child.edges.filter(edge => edge && typeof edge.source === 'string' && typeof edge.target === 'string').map((edge,index) => <p key={index}>Edge · {edge.source} → {edge.target}{edge.conditional ? ' · conditional' : ''}</p>)}
          </section>)}
        </Topology>}
        <h3 style={{ fontSize: '.95rem', margin: '0 0 .9rem' }}>Graph timeline</h3>
        {detailInScope === null ? <State>Loading timeline…</State> : events.length ? <Timeline>{events.map(event => {
          const data = { ...event, ...(event.data || {}) }, isError = event.type === 'error' || Boolean(data.errorCode), isTool = event.type === 'tool';
          return <Event key={`${event.seq}-${event.createdAt}`} $error={isError} $tool={isTool}>
            <EventTop><strong>{isTool ? <FiTool aria-hidden="true" /> : <FiCpu aria-hidden="true" />} {event.node || event.type || 'event'}</strong><time>{formatTime(event.createdAt)}</time></EventTop>
            <Chips><Chip>{event.type || 'event'}</Chip>{data.decisionSource && <Chip>decision: {data.decisionSource}</Chip>}
              {data.terminationReason && <Chip>stopped: {data.terminationReason.replaceAll('_', ' ')}</Chip>}{Number.isInteger(data.toolSteps) && <Chip>tool steps: {data.toolSteps}</Chip>}{data.tool && <Chip>tool: {data.tool}</Chip>}{data.provider && <Chip>provider: {data.provider}</Chip>}{data.model && <Chip>model: {data.model}</Chip>}
              {Number.isFinite(data.tokens) && <Chip>tokens: {data.tokens}</Chip>}{Number.isFinite(data.durationMs) && <Chip>{data.durationMs} ms</Chip>}
              {Number.isFinite(data.attempt) && <Chip>attempt: {data.attempt}</Chip>}{(data.judgeVerdict || data.verdict) && <Chip>judge: {data.judgeVerdict || data.verdict}</Chip>}
              {data.objectiveId && <Chip>objective: {data.objectiveId}</Chip>}{data.rubricVersion && <Chip>rubric: {data.rubricVersion}</Chip>}{data.judgeVersion && <Chip>judge policy: {data.judgeVersion}</Chip>}
              {String(event?.node || '').endsWith('respond_repair') && <Chip>assistance: bounded model repair</Chip>}
              {(data.evidenceSummary || data.evidence_summary) && <Chip>evidence: {data.evidenceSummary || data.evidence_summary}</Chip>}{data.errorCode && <Chip $error>error: {data.errorCode}</Chip>}
              {judgeValidationMessage(data.validationCode) ? <Chip $error>{judgeValidationMessage(data.validationCode)}</Chip> : null}</Chips>
          </Event>;
        })}</Timeline> : <State>No timeline events were recorded for this run.</State>}
      </> : null}
    </Detail></Layout>}
  </Shell>;
}

export { duration, formatTime };
