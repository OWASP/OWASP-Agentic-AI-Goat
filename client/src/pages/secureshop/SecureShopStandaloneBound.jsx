import React, { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { createSecureShopStandaloneController } from './SecureShopStandaloneController.mjs';
import { safeShopRoute } from './bridge/guestRouting.mjs';
import { STANDALONE_SESSION_CHANNEL } from './bridge/standaloneIntents.mjs';
import { ASSESSMENT_PANEL_CHANNEL } from './bridge/assessmentPanelIntent.mjs';
import { PASSWORD_RESET_PANEL_CHANNEL } from './bridge/passwordResetIntent.mjs';
import { EXTERNAL_MAIL_PANEL_CHANNEL } from './bridge/externalMailIntent.mjs';
import { requestBoundCartReadback } from './bridge/cartRefresh.mjs';
import { handleAuditCsvExport } from './bridge/auditCsvExport.mjs';
import { REGISTERED_PASSWORD_RESET_RESOLVED_EVENT, registeredPasswordResetRecoveryState } from './bridge/registeredPasswordResetRecovery.mjs';
import { readSavedGuestCart, prepareGuestCartImport, clearImportedGuestCart, GUEST_CART_IMPORT_REQUEST_KEY } from './guestCartImport.mjs';
import SecureShopStandaloneModeControl from './SecureShopStandaloneModeControl.jsx';
import SecureShopStandaloneObjectivesControl from './SecureShopStandaloneObjectivesControl.jsx';
import SecureShopStandaloneAssessmentsControl from './SecureShopStandaloneAssessmentsControl.jsx';
import SecureShopStandaloneProgressControl from './SecureShopStandaloneProgressControl.jsx';
import SecureShopStandalonePasswordReset from './SecureShopStandalonePasswordReset.jsx';
import SecureShopStandaloneExternalMail from './SecureShopStandaloneExternalMail.jsx';
import './theme.css';

const ROUTE_CHANNEL = 'dvaia-secureshop-bound-route-v1';

function FrameStatus({ message, error, onRetry }) {
  return <div className="ss-root" style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center',
    background: 'var(--paper, #f8f6f1)', color: 'var(--ink, #242422)' }}>
    <div style={{ padding: 24, textAlign: 'center' }}>
      <div className="ss-mono" style={{ fontSize: 12, letterSpacing: '0.12em', marginBottom: 20 }}>SECURESHOP</div>
      {!error && <div className="ss-skel" aria-hidden="true" style={{ width: 96, height: 3, margin: '0 auto 20px' }} />}
      <p role={error ? 'alert' : 'status'}>{message}</p>
      {error && <button type="button" className="ss-btn ss-btn--ghost" onClick={onRetry}>Retry</button>}
    </div>
  </div>;
}

function SceneChoice({ scenes, busy, error, onSelect, onCancel }) {
  return <div className="ss-root" style={{ position: 'absolute', inset: 0, overflowY: 'auto',
    background: 'var(--paper, #f8f6f1)', color: 'var(--ink, #242422)' }}>
    <main style={{ maxWidth: 760, margin: '0 auto', padding: 'clamp(28px, 7vw, 72px) 24px' }}>
      <div className="ss-mono" style={{ fontSize: 12, letterSpacing: '0.12em' }}>SECURESHOP</div>
      <h1 className="ss-display" style={{ margin: '24px 0 12px' }}>Choose a shop practice.</h1>
      <p style={{ maxWidth: '58ch' }}>Select the existing practice you want to open. Your carts and activity stay with their original practice.</p>
      {error && <p role="alert" style={{ color: 'var(--rust)' }}>{error}</p>}
      <div style={{ display: 'grid', gap: 12, marginTop: 28 }}>
        {scenes.map(scene => <button key={scene.id} type="button" disabled={busy} onClick={() => onSelect(scene.id)}
          style={{ border: '1px solid var(--rule)', padding: 18, background: 'transparent',
            color: 'var(--ink)', textAlign: 'left', cursor: busy ? 'wait' : 'pointer' }}>
          <strong style={{ fontFamily: 'var(--display)', fontSize: 19 }}>{scene.label}</strong>
          <span className="ss-mono" style={{ display: 'block', fontSize: 11, opacity: 0.7, marginTop: 6 }}>
            Created {new Date(scene.createdAt).toLocaleDateString()}
          </span>
        </button>)}
      </div>
      {busy && <p role="status">Opening selected practice…</p>}
      {onCancel && <button type="button" className="ss-btn ss-btn--ghost" disabled={busy}
        onClick={onCancel} style={{ marginTop: 20 }}>Return to current practice</button>}
    </main>
  </div>;
}

function ResetRecovery({ recovery, busy, onResume }) {
  return <div className="ss-root" style={{ position: 'absolute', inset: 0, overflowY: 'auto',
    background: 'var(--paper, #f8f6f1)', color: 'var(--ink, #242422)' }}>
    <main style={{ maxWidth: 760, margin: '0 auto', padding: 'clamp(28px, 7vw, 72px) 24px' }}>
      <div className="ss-mono" style={{ fontSize: 12, letterSpacing: '0.12em' }}>SECURESHOP</div>
      <h1 className="ss-display" style={{ margin: '24px 0 12px' }}>Finish a saved practice reset.</h1>
      <p>The reset of <strong>{recovery.scene.label}</strong> needs its protected cleanup checked before this shop can open.
        This shared practice remains closed while its outcome is unresolved.</p>
      {!recovery.sameExecution && <p>The original shop session is no longer active. Recovery can finish cleanup,
        but it cannot reopen the old session.</p>}
      <button type="button" className="ss-btn" disabled={busy} onClick={onResume}>
        {busy ? 'Checking cleanup…' : 'Read and resume saved reset'}
      </button>
    </main>
  </div>;
}

function PracticeRecovery({ practice, busy, message, onCheck, onResume, onRetained }) {
  return <div className="ss-root" style={{ position: 'absolute', inset: 0, overflowY: 'auto',
    background: 'var(--paper, #f8f6f1)', color: 'var(--ink, #242422)' }}>
    <main style={{ maxWidth: 760, margin: '0 auto', padding: 'clamp(28px, 7vw, 72px) 24px' }}>
      <div className="ss-mono" style={{ fontSize: 12, letterSpacing: '0.12em' }}>SECURESHOP</div>
      <h1 className="ss-display" style={{ margin: '24px 0 12px' }}>Check a saved new practice.</h1>
      <p>The new practice request is saved as <span className="ss-mono">{practice.operationId}</span>.
        Checking its status does not start another practice.</p>
      {practice.status === 'retained_unfinished' && <p role="alert">The original shop session ended before this
        practice could finish. Its resources remain retained; it cannot be resumed from this session.</p>}
      {practice.status === 'pending' && <p role="status">This practice is still pending.</p>}
      {practice.status === 'unconfirmed' && <p role="status">The outcome has not been confirmed.</p>}
      {message && <p role="alert">{message}</p>}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 20 }}>
        <button type="button" className="ss-btn" disabled={busy} onClick={onCheck}>Check saved new practice</button>
        {practice.canResume && <button type="button" className="ss-btn ss-btn--ghost" disabled={busy}
          onClick={onResume}>Resume same new practice</button>}
        <button type="button" className="ss-btn ss-btn--ghost" disabled={busy}
          onClick={onRetained}>Open retained practice</button>
      </div>
    </main>
  </div>;
}

export default function SecureShopStandaloneBound({ client, user, onSessionIntent, onRenewNeeded,
  createController = createSecureShopStandaloneController }) {
  const location = useLocation();
  const navigate = useNavigate();
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;
  const sessionIntentRef = useRef(onSessionIntent);
  sessionIntentRef.current = onSessionIntent;
  const renewRef = useRef(onRenewNeeded);
  renewRef.current = onRenewNeeded;
  const route = `${location.pathname}${location.search}${location.hash}`;
  const routeRef = useRef(route);
  routeRef.current = route;
  const host = useRef(null);
  const controller = useRef(null);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState({ status: 'connecting' });
  const [selecting, setSelecting] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const recoveryLock = useRef(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [resetReadiness, setResetReadiness] = useState(null);
  const [resetCheck, setResetCheck] = useState('idle');
  const [resetError, setResetError] = useState('');
  const [resetConfirm, setResetConfirm] = useState(false);
  const [resetPending, setResetPending] = useState(false);
  const resetLock = useRef(false);
  const resetDialog = useRef(null);
  const resetPriorFocus = useRef(null);
  const [assessmentFocusId, setAssessmentFocusId] = useState(null);
  const [passwordResetRequest, setPasswordResetRequest] = useState(null);
  const [externalMailOpen, setExternalMailOpen] = useState(false);
  const storageRef = useRef(null);
  if (!storageRef.current) {
    try { storageRef.current = window.sessionStorage; } catch { /* Guest intent stays unavailable. */ }
  }
  const [savedCart, setSavedCart] = useState(() => {
    try { return readSavedGuestCart(window.sessionStorage); } catch { return null; }
  });
  const [cartBusy, setCartBusy] = useState(false);
  const [cartDismissed, setCartDismissed] = useState(false);
  const [cartError, setCartError] = useState('');
  const [cartIssues, setCartIssues] = useState([]);
  const [cartNotice, setCartNotice] = useState('');
  const [resetRenewalNotice, setResetRenewalNotice] = useState('');
  const checkoutDestination = useRef(null);
  const practiceSwitchAllowed = useRef(null);
  practiceSwitchAllowed.current = () => {
    try {
      return !cartBusy && !resetPending && !recovering
        && storageRef.current?.getItem(GUEST_CART_IMPORT_REQUEST_KEY) === null
        && (user?.role !== 'admin'
          || registeredPasswordResetRecoveryState(storageRef.current, user.principalId) === 'none');
    } catch { return false; }
  };

  const refreshModeAuthority = () => {
    setState({ status: 'connecting' });
    setAttempt(value => value + 1);
  };

  useEffect(() => {
    if (!savedCart || user?.role !== 'customer') {
      checkoutDestination.current = null;
      return;
    }
    if (/^\/secureshop\/(?:v2\/)?checkout\/?$/.test(location.pathname)) {
      checkoutDestination.current = safeShopRoute(route, { publicOnly: false });
    } else if (!/^\/secureshop\/(?:v2\/)?cart\/?$/.test(location.pathname)) {
      checkoutDestination.current = null;
    }
  }, [location.pathname, route, savedCart, user?.role]);

  useEffect(() => {
    if (!host.current) return undefined;
    let mounted = true;
    const instance = createController({ client, shopRole: user?.role, principalId: user?.principalId,
      initialRoute: safeShopRoute(routeRef.current, { publicOnly: false }) || '/secureshop',
      canSwitchPractice: () => practiceSwitchAllowed.current?.() === true,
      onState: next => { if (mounted) setState(next); },
    });
    controller.current = instance;
    instance.start(host.current).catch(error => {
      if (mounted && error?.status === 401) sessionIntentRef.current?.({ type: 'auth-required' });
    });
    return () => { mounted = false; if (controller.current === instance) controller.current = null; instance.close(); };
  }, [attempt, client, createController, user?.role, user?.principalId]);

  useEffect(() => {
    const onMessage = event => {
      const frame = host.current?.firstElementChild;
      if (!frame || frame.tagName !== 'IFRAME' || event.source !== frame.contentWindow
        || event.origin !== 'null' || event.ports.length !== 0) return;
      const data = event.data;
      const nonce = new URL(frame.src).hash.slice(1);
      if (!data || data.nonce !== nonce) return;
      if (Object.keys(data).length === 3 && data.channel === EXTERNAL_MAIL_PANEL_CHANNEL
        && data.type === 'open' && user?.role === 'merchant' && state.status === 'ready') {
        setExternalMailOpen(true);
        return;
      }
      if (handleAuditCsvExport(event, { frame, route: routeRef.current,
        allowed: state.status === 'ready' && user?.role === 'admin' })) return;
      if (Object.keys(data).length === 4 && data.channel === ROUTE_CHANNEL && data.type === 'route') {
        const target = safeShopRoute(data.route, { publicOnly: false });
        if (target && target !== routeRef.current) navigateRef.current(target);
        return;
      }
      if (Object.keys(data).length === 4 && data.channel === ASSESSMENT_PANEL_CHANNEL
        && data.type === 'open' && (data.evaluationId === null
          || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(data.evaluationId))) {
        setAssessmentFocusId(data.evaluationId);
        setSettingsOpen(true);
        return;
      }
      if (Object.keys(data).length === 4 && data.channel === PASSWORD_RESET_PANEL_CHANNEL
        && ['open', 'open-teaching'].includes(data.type) && user?.role === 'admin'
        && state.status === 'ready'
        && Number.isSafeInteger(data.targetId) && data.targetId >= 1 && data.targetId <= 2147483647) {
        setPasswordResetRequest({ kind: data.type === 'open' ? 'registered_manual' : 'teaching_manual',
          targetId: data.targetId });
        setSettingsOpen(true);
        return;
      }
      if (Object.keys(data).length === 6 && data.channel === PASSWORD_RESET_PANEL_CHANNEL
        && data.type === 'open-chat' && user?.role === 'admin' && state.status === 'ready'
        && [data.sessionId, data.requestId, data.choiceId].every(value =>
          typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value))) {
        setPasswordResetRequest({ kind: 'chat', sessionId: data.sessionId,
          requestId: data.requestId, choiceId: data.choiceId });
        setSettingsOpen(true);
        return;
      }
      if (data.channel === STANDALONE_SESSION_CHANNEL && ((Object.keys(data).length === 3
        && ['auth-required', 'password-route'].includes(data.type))
        || (Object.keys(data).length === 4 && data.type === 'logout'
          && /^[a-f0-9]{32}$/i.test(data.requestId))
        || (Object.keys(data).length === 5 && data.type === 'switch-role'
          && /^[a-f0-9]{32}$/i.test(data.requestId)
          && ['customer', 'merchant', 'admin'].includes(data.role)))) {
        sessionIntentRef.current?.({ type: data.type, role: data.role, frame, nonce,
          requestId: data.requestId });
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [state.status, user?.role]);

  useEffect(() => {
    if (state.status !== 'ready') return;
    const frame = host.current?.firstElementChild;
    if (!frame || frame.tagName !== 'IFRAME') return;
    const current = safeShopRoute(route, { publicOnly: false });
    const nonce = new URL(frame.src).hash.slice(1);
    if (current && nonce) frame.contentWindow?.postMessage({ channel: ROUTE_CHANNEL,
      type: 'set-route', nonce, route: current }, '*');
  }, [route, state.status]);

  useEffect(() => {
    if (state.status !== 'ready' || !state.launch?.expiresAt || !renewRef.current) return undefined;
    const expiry = Math.min(Date.parse(state.launch.expiresAt),
      Date.parse(state.personaExpiresAt || state.launch.expiresAt));
    if (!Number.isFinite(expiry)) return undefined;
    let requested = false;
    let recoveryBlocked = false;
    const renewIfDue = () => {
      if (!requested && Date.now() >= expiry - 60000) {
        if (user?.role === 'admin') {
          const recoveryState = registeredPasswordResetRecoveryState(storageRef.current, user.principalId);
          if (recoveryState !== 'none') {
            recoveryBlocked = true;
            setResetRenewalNotice(recoveryState);
            return;
          }
        }
        if (recoveryBlocked) return;
        requested = true;
        setResetRenewalNotice('');
        renewRef.current?.();
      }
    };
    const onVisible = () => { if (document.visibilityState === 'visible') renewIfDue(); };
    const onResetResolved = () => {
      if (registeredPasswordResetRecoveryState(storageRef.current, user?.principalId) !== 'none') return;
      recoveryBlocked = false;
      renewIfDue();
    };
    const timer = window.setTimeout(renewIfDue, Math.max(1000, expiry - Date.now() - 60000));
    window.addEventListener('focus', renewIfDue);
    window.addEventListener(REGISTERED_PASSWORD_RESET_RESOLVED_EVENT, onResetResolved);
    document.addEventListener('visibilitychange', onVisible);
    renewIfDue();
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener('focus', renewIfDue);
      window.removeEventListener(REGISTERED_PASSWORD_RESET_RESOLVED_EVENT, onResetResolved);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [state.status, state.launch?.expiresAt, state.personaExpiresAt, user?.role, user?.principalId]);

  useEffect(() => {
    if (!settingsOpen || state.status !== 'ready' || user?.role !== 'admin') return undefined;
    const controller = new AbortController();
    setResetCheck('loading'); setResetReadiness(null); setResetError('');
    client.getPracticeResetReadiness(controller.signal).then(value => {
      if (controller.signal.aborted) return;
      if (value.launchId !== state.launch?.launchId || value.generation !== state.launch?.generation) {
        throw new Error('The selected practice changed. Reopen SecureShop before resetting it.');
      }
      setResetReadiness(value); setResetCheck(value.available ? 'ready' : 'unavailable');
    }).catch(error => {
      if (!controller.signal.aborted) { setResetCheck('error'); setResetError(error.message || 'Reset readiness unavailable.'); }
    });
    return () => controller.abort();
  }, [settingsOpen, state.status, state.launch?.launchId, state.launch?.generation, user?.role, client]);

  useEffect(() => {
    if (!resetConfirm) return undefined;
    resetPriorFocus.current = document.activeElement;
    resetDialog.current?.querySelector('button[data-confirm-reset]')?.focus();
    const onKey = event => {
      if (event.key === 'Escape' && !resetLock.current) setResetConfirm(false);
      if (event.key !== 'Tab') return;
      const buttons = [...(resetDialog.current?.querySelectorAll('button:not(:disabled)') || [])];
      if (!buttons.length) return;
      const first = buttons[0], last = buttons[buttons.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('keydown', onKey); resetPriorFocus.current?.focus?.(); };
  }, [resetConfirm]);

  const select = async sceneId => {
    if (selecting || !controller.current) return;
    setSelecting(true);
    try { await controller.current.selectScene(sceneId); }
    catch { /* controller keeps the selector and an actionable error */ }
    finally { setSelecting(false); }
  };
  const choosePractice = async () => {
    if (selecting || !controller.current) return;
    setSelecting(true);
    try { await controller.current.choosePractice(); setSettingsOpen(false); }
    catch { /* Existing frame or selector retains saved recovery and error. */ }
    finally { setSelecting(false); }
  };
  const newPractice = async () => {
    if (selecting || !controller.current) return;
    setSelecting(true);
    try { await controller.current.newPractice(); setSettingsOpen(false); }
    catch (error) {
      if (error?.status === 401) sessionIntentRef.current?.({ type: 'auth-required' });
      /* Controller keeps the original scene or saved operation recovery visible. */
    }
    finally { setSelecting(false); }
  };
  const checkPractice = async resume => {
    if (selecting || !controller.current) return;
    setSelecting(true);
    try { await controller.current.checkPractice({ resume }); }
    catch (error) {
      if (error?.status === 401) sessionIntentRef.current?.({ type: 'auth-required' });
      /* Exact saved UUID remains for read-only recovery. */
    }
    finally { setSelecting(false); }
  };
  const openRetainedPractice = async () => {
    if (selecting || !controller.current) return;
    setSelecting(true);
    try { await controller.current.openRetainedPractice(); }
    catch (error) {
      if (error?.status === 401) sessionIntentRef.current?.({ type: 'auth-required' });
      /* Recovery remains available. */
    }
    finally { setSelecting(false); }
  };
  const resumeRecovery = async () => {
    if (recoveryLock.current || !controller.current) return;
    recoveryLock.current = true; setRecovering(true);
    try { await controller.current.resumeResetRecovery(); }
    catch { /* Controller retains the exact journal and publishes an actionable error. */ }
    finally { recoveryLock.current = false; setRecovering(false); }
  };
  const resetPractice = async () => {
    if (resetLock.current || !controller.current || !resetReadiness?.available
      || (!resetConfirm && !state.retryReset)) return;
    resetLock.current = true; setResetPending(true); setResetError('');
    try {
      await controller.current.reset(resetReadiness);
      setResetConfirm(false); setSettingsOpen(false); setResetReadiness(null);
    } catch (error) {
      setResetError(error.message || 'Reset outcome is unknown. Retry the same reset.');
    } finally { resetLock.current = false; setResetPending(false); }
  };
  const importSavedCart = async () => {
    if (cartBusy || !savedCart || !storageRef.current || state.status !== 'ready'
      || user?.role !== 'customer') return;
    setCartBusy(true); setCartError(''); setCartIssues([]); setCartNotice('');
    try {
      const prepared = prepareGuestCartImport(storageRef.current, savedCart);
      const result = await client.importCart(prepared.requestId, prepared.items);
      if (!result.imported) {
        setCartIssues(result.issues);
        setCartError('Saved items could not all be added. Your saved cart is unchanged.');
        return;
      }
      const frame = host.current?.firstElementChild;
      let readbackConfirmed = false;
      if (frame?.tagName === 'IFRAME') {
        const nonce = new URL(frame.src).hash.slice(1);
        if (nonce) {
          try { readbackConfirmed = await requestBoundCartReadback({ frame, nonce,
            requestId: prepared.requestId, items: prepared.items }); }
          catch { /* Retain the exact saved intent until a bound cart readback confirms it. */ }
        }
      }
      if (!readbackConfirmed) {
        setCartError('SecureShop accepted your saved items, but the shop cart could not confirm them. Your saved cart is unchanged. Retry Add saved items to check again.');
        return;
      }
      if (!clearImportedGuestCart(storageRef.current, prepared)) {
        setSavedCart(readSavedGuestCart(storageRef.current));
        setCartError('Items were added, but your saved cart changed before it could be cleared. Review it before retrying.');
        return;
      }
      setSavedCart(null);
      if (checkoutDestination.current) {
        const destination = checkoutDestination.current;
        checkoutDestination.current = null;
        setCartDismissed(true);
        navigate(destination);
      } else {
        setCartNotice('Your saved items are in your shop cart. Prices and stock were checked by SecureShop.');
      }
    } catch (error) {
      setCartError(error.message || 'Cart import could not be confirmed. Your saved cart is unchanged.');
    } finally { setCartBusy(false); }
  };
  const issueText = issue => {
    const item = `Item #${issue.productId}`;
    if (issue.code === 'INSUFFICIENT_STOCK') return `${item}: only ${issue.availableQuantity ?? 0} available`;
    if (issue.code === 'CART_QUANTITY_LIMIT') return `${item}: cart quantity limit reached`;
    return `${item}: unavailable`;
  };
  return <main aria-label="SecureShop" style={{ position: 'fixed', inset: 0, zIndex: 1000,
    background: 'var(--paper, #f8f6f1)' }}>
    <div ref={host} style={{ width: '100%', height: '100dvh' }} />
    {['connecting', 'selecting', 'recovering-reset', 'creating-practice', 'checking-practice'].includes(state.status) &&
      <FrameStatus message={state.status === 'recovering-reset' ? 'Checking saved reset…' : 'Opening SecureShop…'} />}
    {state.status === 'error' && <FrameStatus error message={state.message || 'SecureShop is unavailable.'}
      onRetry={state.retryRecovery ? resumeRecovery : state.retryReset ? resetPractice
        : () => setAttempt(value => value + 1)} />}
    {state.status === 'reset-recovery' && user?.role !== 'admin' &&
      <FrameStatus error message="Shop reset recovery requires a shop administrator." />}
    {state.status === 'reset-recovery' && user?.role === 'admin' && <ResetRecovery recovery={state.recovery}
      busy={recovering} onResume={resumeRecovery} />}
    {state.status === 'practice-recovery' && <PracticeRecovery practice={state.practice}
      busy={selecting} message={state.message} onCheck={() => checkPractice(false)}
      onResume={() => checkPractice(true)} onRetained={openRetainedPractice} />}
    {state.status === 'choose-scene' && <SceneChoice scenes={state.scenes || []} busy={selecting}
      error={state.message} onSelect={select}
      onCancel={state.originalSceneId ? () => select(state.originalSceneId) : undefined} />}
    {state.status === 'ready' && <>
      {resetRenewalNotice && <div role="alert" className="ss-mono" style={{ position: 'absolute', top: 16,
        left: '50%', transform: 'translateX(-50%)', zIndex: 4, width: 'min(620px, calc(100% - 32px))',
        padding: 12, border: '1px solid var(--rust)', color: 'var(--rust)', background: 'var(--paper)',
        boxShadow: 'var(--shadow-md)', fontSize: 11 }}>
        {resetRenewalNotice === 'pending'
          ? 'A registered account reset is awaiting recovery. Automatic session renewal is paused so this administrator session remains available for status and reveal. Finish recovery before the current session expires; access will not be extended automatically.'
          : 'SecureShop cannot verify the saved reset reference. Automatic session renewal is paused to preserve any original administrator session needed for recovery. Check reset recovery before the current session expires; access will not be extended automatically.'}
        <button type="button" className="ss-btn ss-btn--sm" onClick={() => setSettingsOpen(true)}
          style={{ display: 'block', marginTop: 8 }}>Open reset recovery</button>
      </div>}
      <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
        aria-expanded={settingsOpen} aria-controls="secureshop-settings"
        onClick={() => setSettingsOpen(value => !value)} style={{ position: 'absolute', left: 16,
          bottom: 16, zIndex: 3, background: 'var(--paper)', boxShadow: 'var(--shadow-md)' }}>
        Shop settings
      </button>
      {settingsOpen && <aside id="secureshop-settings" className="ss-root" aria-label="Shop settings"
        style={{ position: 'absolute', left: 16, bottom: 64, zIndex: 3,
          width: 'min(360px, calc(100% - 32px))', minHeight: 0, maxHeight: 'calc(100dvh - 80px)',
          overflowY: 'auto', padding: 16, background: 'var(--paper)',
          border: '1px solid var(--rule)', boxShadow: 'var(--shadow-lg)' }}>
        <section aria-label="Retained shop practices" style={{ marginBottom: 16 }}>
          <strong className="ss-display">Retained practices</strong>
          <p>Reopen an existing practice. Carts and activity remain in their original practice.</p>
          {state.practiceError && <p role="alert">{state.practiceError}</p>}
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            disabled={selecting || state.sceneBusy || resetPending || recovering || cartBusy}
            onClick={choosePractice}>Choose retained practice</button>
          {state.practiceWarning && <p role="alert">{state.practiceWarning}</p>}
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            disabled={selecting || state.sceneBusy || resetPending || recovering || cartBusy
              || Boolean(state.practiceWarning)} onClick={newPractice}
            style={{ marginLeft: 8 }}>New practice</button>
          {state.practiceWarning && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            disabled={selecting} onClick={() => checkPractice(false)}>Check saved new practice</button>}
        </section>
        <SecureShopStandaloneModeControl client={client} onModeChanged={refreshModeAuthority} />
        {user?.role === 'admin' && <SecureShopStandaloneObjectivesControl client={client} />}
        <SecureShopStandaloneAssessmentsControl client={client} focusEvaluationId={assessmentFocusId} />
        <SecureShopStandaloneProgressControl
          key={`${user.principalId}:${user.role}:${state.launch?.launchId}:${state.launch?.generation}`}
          client={client} user={user} />
        {user?.role === 'admin' && <SecureShopStandalonePasswordReset key={user.principalId}
          client={client} controller={controller.current} user={user} request={passwordResetRequest}
          onClose={() => setPasswordResetRequest(null)} />}
        {user?.role === 'merchant' && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
          onClick={() => setExternalMailOpen(true)}>Send external test email</button>}
        {user?.role === 'admin' && <section style={{ borderTop: '1px solid var(--rule)', marginTop: 16, paddingTop: 16 }}>
          <strong className="ss-display">Shared practice reset</strong>
          {resetCheck === 'loading' && <p role="status">Checking reset availability…</p>}
          {resetCheck === 'unavailable' && <p>Reset is unavailable for this practice.</p>}
          {resetCheck === 'error' && <p role="alert">{resetError}</p>}
          {resetCheck === 'ready' && <>
            <p>Selected practice: <strong>{resetReadiness.scene.label}</strong></p>
            <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
              onClick={() => { setResetError(''); setResetConfirm(true); }}>Reset shared practice</button>
          </>}
        </section>}
      </aside>}
      {user?.role === 'merchant' && <SecureShopStandaloneExternalMail
        key={`${user.principalId}:${state.launch?.launchId}:${state.launch?.generation}`}
        controller={controller.current} user={user} open={externalMailOpen}
        onClose={() => setExternalMailOpen(false)} />}
    </>}
    {resetConfirm && <div className="ss-root ss-modal-backdrop" style={{ position: 'absolute', zIndex: 5 }}
      onMouseDown={event => { if (event.target === event.currentTarget && !resetLock.current) setResetConfirm(false); }}>
      <div ref={resetDialog} className="ss-modal" role="alertdialog" aria-modal="true"
        aria-labelledby="shop-reset-title" aria-describedby="shop-reset-description">
        <h2 id="shop-reset-title" className="ss-modal__title">Reset shared practice?</h2>
        <p id="shop-reset-description">This clears mutable practice data for every customer and merchant sharing
          <strong> {resetReadiness?.scene.label}</strong>. Historical evidence remains. This cannot be undone.</p>
        {resetError && <p role="alert" style={{ color: 'var(--rust)' }}>{resetError}</p>}
        {state.retryReset && <p>{state.resetCommitted
          ? 'Reset cleanup was confirmed, but SecureShop could not reopen. Retry only reopens this practice.'
          : 'The previous reset outcome is uncertain. Retry uses the same request; it does not start another reset.'}</p>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" className="ss-btn ss-btn--ghost" disabled={resetPending}
            onClick={() => setResetConfirm(false)}>Cancel</button>
          <button type="button" data-confirm-reset className="ss-btn" disabled={resetPending}
            onClick={resetPractice}>{resetPending ? 'Resetting…' : state.resetCommitted
              ? 'Retry opening shop' : state.retryReset ? 'Retry same reset' : 'Confirm shared reset'}</button>
        </div>
      </div>
    </div>}
    {state.status === 'ready' && !settingsOpen && user?.role === 'customer' && !cartDismissed && (savedCart || cartNotice) &&
      <aside className="ss-root" aria-label="Saved guest cart" style={{ position: 'absolute', right: 16, bottom: 16,
        width: 'min(380px, calc(100% - 32px))', minHeight: 0, maxHeight: 'calc(100dvh - 32px)', overflowY: 'auto',
        padding: 20, background: 'var(--paper)',
        border: '1px solid var(--rule)', boxShadow: '0 12px 32px rgba(0,0,0,0.16)', zIndex: 2 }}>
        <div className="ss-mono" style={{ fontSize: 11, letterSpacing: '0.08em', color: 'var(--copper)' }}>SAVED CART</div>
        <p style={{ margin: '8px 0 12px', fontSize: 14 }}>
          {cartNotice || `${savedCart.items.length} item${savedCart.items.length === 1 ? '' : 's'} from browsing before sign-in. Add them to this shop cart? Current prices and stock will be checked.`}
        </p>
        {cartError && <p role="alert" style={{ color: 'var(--rust)', fontSize: 13 }}>{cartError}</p>}
        {cartIssues.length > 0 && <ul style={{ paddingLeft: 20, fontSize: 12 }}>
          {cartIssues.map(issue => <li key={issue.productId}>{issueText(issue)}</li>)}
        </ul>}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {savedCart && <button type="button" className="ss-btn ss-btn--sm" disabled={cartBusy}
            onClick={importSavedCart}>{cartBusy ? 'Checking…' : 'Add saved items'}</button>}
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            onClick={() => setCartDismissed(true)}>{cartNotice ? 'Close' : 'Later'}</button>
        </div>
      </aside>}
  </main>;
}
