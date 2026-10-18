import React, { useEffect, useRef, useState } from 'react';
import { decodeRoleMcpRegistryProposal } from '../utils/roleMcpRegistry.mjs';
import { sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { administration, assertPendingCurrent, clearPending, readAnyPending,
  savePending, verifyReceipt, verifiedImportEntityReads } from '../pages/admin/mcpRegistryOperation.mjs';
import { adminMcpManifestAssessmentStore } from '../utils/adminMcpManifestAssessmentReference.mjs';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const same = (left, right) => !!left && !!right && JSON.stringify(left) === JSON.stringify(right);
const ASSESSMENT = '/api/secureshop/agents/admin/assistant';
const discoveryAssessment = ref => ref?.kind === 'discovery';
const awaitingAssessment = ref => ['awaiting_import', 'awaiting_registration'].includes(ref?.stage);
const assessmentLabel = ref => discoveryAssessment(ref) ? 'MCP discovery' : 'MCP manifest';
const assessmentRoute = ref => discoveryAssessment(ref) ? 'mcp-discovery' : 'mcp-manifest';
const assessmentOutcome = (value, ref) => {
  const keys = Object.keys(value || {}).sort().join(',');
  if (keys === 'completed,modelEvaluated,status' && value.completed === false
    && value.modelEvaluated === false
    && ['disabled', 'ineligible', 'pending', 'unconfirmed'].includes(value.status)) return value;
  if (keys === 'completed,judgment,replayed' && typeof value.completed === 'boolean'
    && typeof value.replayed === 'boolean'
    && Object.keys(value.judgment || {}).sort().join(',') === 'canRetry,evaluationId,verdict'
    && UUID.test(value.judgment.evaluationId || '')
    && ['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    && typeof value.judgment.canRetry === 'boolean'
    && (!value.completed || value.judgment.verdict === 'pass')) return value;
  throw Error(`Saved ${assessmentLabel(ref)} assessment unavailable.`);
};
const assessmentPath = ref => `${ASSESSMENT}/sessions/${ref.sessionId}/requests/${ref.requestId}`
  + `/${assessmentRoute(ref)}/${ref.proposalId}/assessment`;

function Server({ heading, server }) {
  if (!server) return null;
  return <div className="ss-card" style={{ padding: 10, marginTop: 8 }}>
    <strong>{heading}: {server.name}</strong>
    <p>{server.transport || 'Discovered scenario'} · {server.url || server.stdio_cmd || server.scenario}</p>
  </div>;
}

export function McpEntityReads({ reads = [] }) {
  if (!reads.length) return null;
  return <div className="ss-card" aria-label="Imported MCP entity reads"
    style={{ padding: 10, marginTop: 8 }}>
    <strong>Owned manifest entity reads</strong>
    {reads.map(read => <div key={read.path} style={{ marginTop: 8 }}>
      <div className="ss-mono" style={{ fontSize: 11 }}>{read.path} · {read.bytes} bytes · SHA-256 {read.sha256}</div>
      <pre className="ss-mono" style={{ margin: '4px 0', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
        {JSON.stringify(read.value)}
      </pre>
    </div>)}
  </div>;
}

export default function AdminMcpRegistryConfirmation({ proposal = null, sessionId = null,
  requestId = null, shopUserId = null, authorityKey, transport = globalThis.fetch, locked = false,
  assessmentStore = adminMcpManifestAssessmentStore,
  onOutcomeChange }) {
  const [scope, setScope] = useState(null);
  const [discoveryReady, setDiscoveryReady] = useState(false);
  const [pending, setPending] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [entityReads, setEntityReads] = useState([]);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const [assessmentRef, setAssessmentRef] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [assessmentError, setAssessmentError] = useState('');
  const [assessmentBusy, setAssessmentBusy] = useState(false);
  const [assessmentAccessLost, setAssessmentAccessLost] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false);
  const assessmentActiveRef = useRef(null), savedAssessmentRef = useRef(null);
  useEffect(() => { onOutcomeChange?.(value => value + 1); }, [pending, receipt, notice, onOutcomeChange]);
  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current, controller = new AbortController();
    activeRef.current?.abort(); activeRef.current = null;
    assessmentActiveRef.current?.abort(); assessmentActiveRef.current = null;
    savedAssessmentRef.current = null;
    setScope(null); setDiscoveryReady(false); setPending(null); setReceipt(null); setEntityReads([]); setNotice(''); setBusy(false); setStorageFault(false);
    setAssessmentRef(null); setAssessment(null); setAssessmentError(''); setAssessmentBusy(false); setAssessmentAccessLost(false);
    const current = () => mountedRef.current && epochRef.current === epoch
      && !controller.signal.aborted && globalThis.fetch === transport;
    Promise.resolve().then(async () => {
      const saved = await readAnyPending();
      if (!current()) return;
      if (saved) { setPending(saved); setNotice('A registry operation is saved. Check its exact outcome before another change.'); }
      const assessmentSaved = Number.isSafeInteger(shopUserId) && shopUserId > 0
        ? assessmentStore.read(shopUserId) : null;
      if (!current()) return;
      savedAssessmentRef.current = assessmentSaved; setAssessmentRef(assessmentSaved);
      const response = await transport('/api/secureshop/admin/mcp/servers', { signal: controller.signal });
      if (!response.ok) throw Error('Registry availability is unavailable.');
      const value = await response.json();
      if (!current()) return;
      const head = administration(value?.registry_administration);
      if (!head) throw Error('Registry availability is unavailable.');
      const discovery = value?.registry_discovery_assessment;
      if (discovery !== undefined && (!discovery || Object.getPrototypeOf(discovery) !== Object.prototype
        || Object.keys(discovery).sort().join(',') !== 'ready' || typeof discovery.ready !== 'boolean'))
        throw Error('MCP discovery assessment availability is unavailable.');
      setScope(head);
      setDiscoveryReady(discovery?.ready === true);
      if (assessmentSaved) {
        if (assessmentSaved.scopeKey !== head.scopeKey) {
          await assessmentStore.clear(assessmentSaved, current);
          if (!current()) return;
          savedAssessmentRef.current = null; setAssessmentRef(null);
        } else if (!awaitingAssessment(assessmentSaved)) {
          const read = await transport(assessmentPath(assessmentSaved), {
            method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
          if (!current()) return;
          if (!read.ok) { const error = Error(`Saved ${assessmentLabel(assessmentSaved)} assessment unavailable.`);
            error.status = read.status; throw error; }
          const outcome = assessmentOutcome(await read.json(), assessmentSaved);
          if (current()) setAssessment(outcome);
        }
      }
    }).catch(async error => {
      if (!current()) return;
      if ([401, 403].includes(error.status)) {
        setAssessmentAccessLost(true); setReceipt(null); setEntityReads([]); setScope(null);
        setPending(null); setAssessment(null);
        const stale = savedAssessmentRef.current;
        if (stale) try { await assessmentStore.clear(stale, current);
          if (current()) { savedAssessmentRef.current = null; setAssessmentRef(null); } }
        catch { /* Protected server denial still fences the visible card. */ }
      }
      if (/saved registry|Invalid saved/i.test(error.message)) setStorageFault(true);
      if (/MCP (manifest|discovery) assessment/i.test(error.message)) setAssessmentError(error.message);
      else setNotice(error.message || 'Registry availability is unavailable.');
    });
    return () => { mountedRef.current = false; epochRef.current += 1; controller.abort();
      activeRef.current?.abort(); activeRef.current = null;
      assessmentActiveRef.current?.abort(); assessmentActiveRef.current = null; };
  }, [authorityKey, proposal?.proposalId, requestId, sessionId, shopUserId, transport, assessmentStore]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/admin/mcp/operations/${saved.request.operationId}`, { signal });
    if (response.status === 404) return { state: 'not_found' };
    if (response.status === 202) return { state: 'pending' };
    if (!response.ok) throw Error(`Saved registry lookup failed (${response.status})`);
    const value = verifyReceipt(await response.json(), saved);
    return { state: value.state, receipt: value };
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setBusy(true); setNotice('');
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted
      && globalThis.fetch === transport;
    const finish = async (saved, outcome) => {
      if (!current()) return;
      if (!scope) throw Error('Registry availability is unavailable. Check the saved operation when it returns.');
      if (scope.scopeKey !== saved.scopeKey) throw Error('Saved registry operation belongs to another shop session.');
      if (outcome.state !== 'completed') {
        setPending(saved);
        setNotice(outcome.state === 'failed'
          ? 'The saved registry change was refused. Review it in MCP Registry.'
          : 'Registry outcome is unconfirmed. Check the saved operation; no change will be resent.');
        return;
      }
      const reads = await verifiedImportEntityReads(outcome.receipt);
      if (!current()) return;
      const reference = savedAssessmentRef.current;
      if ((saved.request.action === 'import' && !discoveryAssessment(reference)
        || saved.request.action === 'register' && discoveryAssessment(reference)) && reference
        && reference.scopeKey === saved.scopeKey
        && reference.operationId === saved.request.operationId
        && reference.requestSha256 === saved.requestSha256
        && awaitingAssessment(reference)) {
        const ready = await assessmentStore.advance(reference, 'ready', current);
        if (!current()) return;
        savedAssessmentRef.current = ready; setAssessmentRef(ready);
      }
      await clearPending(saved, current);
      if (!current()) return;
      setPending(null); setReceipt(outcome.receipt); setEntityReads(reads);
      setNotice(`Registry ${saved.request.action} confirmed from the saved receipt.`);
    };
    let saved = null;
    try {
      if (storageFault) throw Error('Saved registry state is unavailable.');
      saved = await readAnyPending();
      if (!current()) return;
      if (saved) {
        setPending(saved);
        if (!scope) throw Error('Registry availability is unavailable. Check the saved operation when it returns.');
        if (scope.scopeKey !== saved.scopeKey) throw Error('Saved registry operation belongs to another shop session.');
        await finish(saved, await readExact(saved, controller.signal));
        return;
      }
      if (!confirm || locked || !proposal || !scope || !UUID.test(sessionId || '')
        || !UUID.test(requestId || '')) return;
      const candidate = await decodeRoleMcpRegistryProposal(proposal);
      if (!current()) return;
      if (candidate.scopeKey !== scope.scopeKey || candidate.request.expectedVersion !== scope.version) {
        throw Error('Registry changed. Request a fresh review.');
      }
      const sourceResponse = await transport(`/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`,
        { signal: controller.signal });
      if (!sourceResponse.ok) throw Error('Saved assistant proposal unavailable. No registry change was submitted.');
      const source = await sourceResponse.json();
      if (!current()) return;
      const actual = await decodeRoleMcpRegistryProposal(source.mcpRegistryProposal);
      if (!current()) return;
      if (source.sessionId !== sessionId || source.requestId !== requestId
        || source.status !== 'completed' || source.replayed !== true
        || source.stopReason !== 'end_turn' || !sameRolePolicyMode(source.modeCapability, candidate.modeCapability)
        || !same(actual, candidate)) throw Error('Saved registry proposal changed. No change was submitted.');
      saved = { scopeKey: candidate.scopeKey, request: candidate.request,
        requestSha256: candidate.requestSha256 };
      const discovery = discoveryReady && candidate.request.action === 'register'
        && ['sse', 'streamable-http'].includes(candidate.request.transport);
      if ((candidate.request.action === 'import' || discovery) && Number.isSafeInteger(shopUserId)
        && shopUserId > 0) {
        const existing = assessmentStore.read(shopUserId);
        if (existing && (existing.scopeKey !== candidate.scopeKey
          || existing.sessionId !== sessionId || existing.requestId !== requestId
          || existing.proposalId !== candidate.proposalId
          || existing.operationId !== candidate.request.operationId
          || existing.requestSha256 !== candidate.requestSha256))
          throw Error(`Check the saved ${assessmentLabel(existing)} assessment before another ${discovery ? 'registration' : 'import'}.`);
        if (!existing) {
          const reference = await assessmentStore.save({ shopUserId, scopeKey: candidate.scopeKey,
            sessionId, requestId, proposalId: candidate.proposalId,
            operationId: candidate.request.operationId,
            requestSha256: candidate.requestSha256,
            ...(discovery ? { version: 2, kind: 'discovery', stage: 'awaiting_registration' } : { stage: 'awaiting_import' }),
            startedAt: Date.now() }, current);
          if (!current()) return;
          savedAssessmentRef.current = reference; setAssessmentRef(reference);
        }
      }
      await savePending(saved, current);
      if (!current()) return;
      assertPendingCurrent(saved); setPending(saved);
      const prior = await readExact(saved, controller.signal);
      if (!current()) return;
      if (prior.state !== 'not_found') { await finish(saved, prior); return; }
      assertPendingCurrent(saved);
      try {
        await transport('/api/secureshop/agents/admin/assistant/mcp/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, requestId, proposalId: candidate.proposalId }),
          signal: controller.signal,
        });
      } catch { /* Only the exact saved operation GET confirms the outcome. */ }
      if (!current()) return;
      await finish(saved, await readExact(saved, controller.signal));
    } catch (error) {
      if (!current()) return;
      try {
        const retained = await readAnyPending();
        if (!current()) return;
        setPending(retained || saved);
      } catch {
        if (!current()) return;
        setStorageFault(true); if (saved) setPending(saved);
      }
      if (!current()) return;
      setNotice(error.message || 'Registry outcome unavailable. Check the saved operation.');
    } finally { if (current()) { activeRef.current = null; setBusy(false); } }
  };

  const checkAssessment = async start => {
    if (assessmentActiveRef.current || activeRef.current || !scope || assessmentAccessLost) return;
    const reference = savedAssessmentRef.current;
    if (!reference || reference.scopeKey !== scope.scopeKey
      || reference.shopUserId !== shopUserId || awaitingAssessment(reference)) return;
    const epoch = epochRef.current, controller = new AbortController();
    assessmentActiveRef.current = controller; setAssessmentBusy(true); setAssessmentError('');
    const current = () => mountedRef.current && epochRef.current === epoch
      && assessmentActiveRef.current === controller && !controller.signal.aborted
      && globalThis.fetch === transport;
    try {
      let saved = reference;
      if (start && saved.stage === 'ready') {
        saved = await assessmentStore.advance(saved, 'submitted', current);
        if (!current()) return;
        savedAssessmentRef.current = saved; setAssessmentRef(saved);
        // The durable IDs and submitted stage precede the only grading POST.
        try { await transport(`${ASSESSMENT}/${assessmentRoute(saved)}/assess`, {
          method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId,
            proposalId: saved.proposalId }), signal: controller.signal,
        }); } catch { /* The exact saved GET resolves an uncertain acknowledgement. */ }
      }
      if (!current()) return;
      const response = await transport(assessmentPath(saved), {
        method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!current()) return;
      if (!response.ok) { const error = Error(`Saved ${assessmentLabel(saved)} assessment unavailable.`);
        error.status = response.status; throw error; }
      const outcome = assessmentOutcome(await response.json(), saved);
      if (current()) setAssessment(outcome);
    } catch (error) {
      if (!current()) return;
      if ([401, 403].includes(error.status)) {
        setAssessmentAccessLost(true); setScope(null); setReceipt(null); setEntityReads([]);
        setPending(null); setAssessment(null);
        try { await assessmentStore.clear(savedAssessmentRef.current, current);
          if (current()) { savedAssessmentRef.current = null; setAssessmentRef(null); } }
        catch { /* Current UI is already fenced; server authority remains authoritative. */ }
      }
      if (current()) setAssessmentError(error.message || `Saved ${assessmentLabel(reference)} assessment unavailable.`);
    } finally { if (current()) setAssessmentBusy(false);
      if (assessmentActiveRef.current === controller) assessmentActiveRef.current = null; }
  };

  const clearCompletedAssessment = async () => {
    if (assessmentActiveRef.current || activeRef.current || !scope || !proposal
      || !assessmentRef || assessmentRef.proposalId === proposal.proposalId
      || !(assessment?.judgment || ['ineligible', 'disabled'].includes(assessment?.status))) return;
    const epoch = epochRef.current, controller = new AbortController();
    assessmentActiveRef.current = controller; setAssessmentBusy(true); setAssessmentError('');
    const current = () => mountedRef.current && epochRef.current === epoch
      && assessmentActiveRef.current === controller && !controller.signal.aborted
      && globalThis.fetch === transport;
    try {
      if (assessmentRef.scopeKey !== scope.scopeKey || assessmentRef.shopUserId !== shopUserId)
        throw Error(`Saved ${assessmentLabel(assessmentRef)} assessment belongs to another shop session.`);
      await assessmentStore.clear(assessmentRef, current);
      if (!current()) return;
      savedAssessmentRef.current = null; setAssessmentRef(null); setAssessment(null);
      setReceipt(null); setEntityReads([]); setNotice('');
    } catch (error) { if (current()) setAssessmentError(error.message || `Saved ${assessmentLabel(assessmentRef)} assessment unavailable.`); }
    finally { if (current()) setAssessmentBusy(false);
      if (assessmentActiveRef.current === controller) assessmentActiveRef.current = null; }
  };

  if (!proposal && !pending && !receipt && !notice && !assessmentRef && !assessmentError) return null;
  return <section className="ss-card" aria-label="Admin MCP registry review"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && !pending && !receipt && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '4px 0 10px' }}>Review MCP {proposal.action}</h3>
      <p><strong>{proposal.request.name || proposal.request.xml_url}</strong> · {proposal.action === 'register'
        && proposal.before ? 'This replaces a registered server after confirmation.' : 'No registry change occurs before confirmation.'}</p>
      <Server heading="Current server" server={proposal.before} />
      {proposal.action === 'register' && <p>Proposed transport: {proposal.request.transport} · {proposal.request.url || proposal.request.stdio_cmd}</p>}
      {proposal.action === 'import' && <p>Manifest URL: {proposal.request.xml_url}</p>}
      {proposal.action === 'retire' && <p>Retire the current registered server after confirmation.</p>}
      <button className="ss-btn" type="button" disabled={busy || locked || !scope || storageFault
        || scope.scopeKey !== proposal.scopeKey} onClick={() => void run(true)}>
        {proposal.action === 'register' ? 'Register MCP server'
          : proposal.action === 'import' ? 'Import MCP manifest' : 'Retire MCP server'}
      </button>
    </>}
    {pending && <button className="ss-btn ss-btn--ghost" type="button"
      disabled={busy || !scope || storageFault} onClick={() => void run(false)}>
      Check saved MCP registry operation
    </button>}
    {receipt && <p role="status">{notice}</p>}
    {receipt && <McpEntityReads reads={entityReads} />}
    {!assessmentAccessLost && assessmentRef?.stage === 'ready' &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={assessmentBusy || busy || !scope} onClick={() => void checkAssessment(true)}>
        Check {assessmentLabel(assessmentRef)} assessment
      </button>}
    {!assessmentAccessLost && assessmentRef?.stage === 'submitted' &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={assessmentBusy || busy || !scope} onClick={() => void checkAssessment(false)}>
        Check saved {assessmentLabel(assessmentRef)} assessment
      </button>}
    {assessment?.status === 'unconfirmed' && <p role="status">Assessment not confirmed. Check the saved result again.</p>}
    {assessment?.status === 'pending' && <p role="status">Assessment pending. Check the saved result again.</p>}
    {assessment?.status === 'ineligible' && <p role="status">This {discoveryAssessment(assessmentRef) ? 'registry discovery' : 'manifest import'} is not eligible for objective credit.</p>}
    {assessment?.status === 'disabled' && <p role="status">This {discoveryAssessment(assessmentRef) ? 'discovery' : 'manifest'} objective is disabled.</p>}
    {assessment?.judgment && <p role="status">{assessment.judgment.verdict === 'unavailable'
      ? `Grading unavailable. The saved ${discoveryAssessment(assessmentRef) ? 'registration' : 'import'} remains available.`
      : assessment.completed ? 'Objective completed.'
        : 'Assessment completed without objective credit.'}</p>}
    {assessment?.judgment?.verdict === 'unavailable' && isStandaloneShopFrame() &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => openStandaloneAssessments(assessment.judgment.evaluationId)}>
        Open saved assessments
      </button>}
    {proposal && assessmentRef && proposal.proposalId !== assessmentRef.proposalId
      && (assessment?.judgment || ['ineligible', 'disabled'].includes(assessment?.status)) &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={busy || assessmentBusy || !scope}
        onClick={() => void clearCompletedAssessment()}>
        Review another MCP {discoveryAssessment(assessmentRef) ? 'registration' : 'import'}
      </button>}
    {assessmentError && <p role="alert">{assessmentError}</p>}
    {notice && !receipt && <p role="status">{notice}</p>}
  </section>;
}
