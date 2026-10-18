import React, { useCallback, useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { ResetConfirmation } from '../../components/workshop/WorkshopExperience';
import { useAuth } from '../../context/AuthContext';
import { useLocation, useNavigate } from 'react-router-dom';
import { createSecureShopWorkshopController } from './SecureShopWorkshopController.mjs';
import { safeShopRoute } from './bridge/guestRouting.mjs';

const MODE_ENDPOINT = '/api/auth/secureshop-launch/mode';
const BOUND_ROUTE_CHANNEL = 'dvaia-secureshop-bound-route-v1';
const MODE_LABELS = { analytics: 'Analytics', coupons: 'Coupons', mail: 'Mail', pricing: 'Pricing',
  audit: 'Audit', listings: 'Listings', registered_mcp: 'Registered MCP', inventory: 'Inventory',
  product_assist: 'Product questions', audit_summary: 'Audit summary', refund: 'Refund agent',
  review: 'Review moderation', persona_inbox: 'Persona inbox', controlled_ssrf: 'Controlled SSRF',
  mcp_rogue_registration: 'MCP registration', mcp_rug_pull: 'MCP rug pull' };
const settingButton = { border: '1px solid #d1d5db', borderRadius: 8, background: '#fff',
  color: '#20232b', cursor: 'pointer', padding: '0.55rem 0.75rem', fontSize: '0.875rem' };

function validModeResponse(data) {
  return data?.success === true && data.version === 1
    && data.scope?.kind === 'owner' && data.scope.id === 'secureshop_agent_security'
    && ['vuln', 'fixed'].includes(data.effectiveMode) && Array.isArray(data.features)
    && Array.isArray(data.selectableModes);
}

function SecureShopModeControl({ launch, userId }) {
  const [mode, setMode] = useState(null);
  const [status, setStatus] = useState('loading');
  const [error, setError] = useState('');
  const request = useRef({ sequence: 0, controller: null });
  const read = async () => {
    request.current.controller?.abort();
    const controller = new AbortController(), sequence = ++request.current.sequence;
    request.current.controller = controller;
    const token = localStorage.getItem('token');
    setStatus('loading'); setError('');
    try {
      const { data } = await axios.get(MODE_ENDPOINT, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
      if (controller.signal.aborted || sequence !== request.current.sequence || token !== localStorage.getItem('token')) return;
      if (!validModeResponse(data)) throw new Error('Mode capability is unavailable');
      setMode(data); setStatus('ready');
    } catch (cause) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setMode(null); setStatus('error');
      setError(cause.response?.data?.error || cause.message || 'Unable to load mode');
    }
  };
  useEffect(() => { void read(); return () => { request.current.sequence++; request.current.controller?.abort(); }; }, [launch?.launchId, launch?.generation, userId]);
  const select = async nextMode => {
    if (status !== 'ready' || !mode?.selectableModes.includes(nextMode) || nextMode === mode.effectiveMode) return;
    request.current.controller?.abort();
    const controller = new AbortController(), sequence = ++request.current.sequence;
    request.current.controller = controller;
    const token = localStorage.getItem('token');
    setStatus('saving'); setError('');
    try {
      const { data } = await axios.post(MODE_ENDPOINT, { mode: nextMode },
        { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
      if (controller.signal.aborted || sequence !== request.current.sequence || token !== localStorage.getItem('token')) return;
      if (!validModeResponse(data)) throw new Error('Mode change could not be confirmed');
      setMode(data); setStatus('ready');
    } catch (cause) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      if ([401, 403].includes(cause.response?.status)) setMode(null);
      setStatus('error'); setError(cause.response?.data?.error || cause.message || 'Unable to change mode');
    }
  };
  const features = mode?.features?.filter(feature => feature?.scope?.kind === 'launch_feature'
    && feature.scope.id === feature.featureId).map(feature => MODE_LABELS[feature.featureId] || feature.featureId) || [];
  return <div role="group" aria-label="Shop feature mode">
    <strong>Feature mode</strong>
    <p style={{ margin: '0.35rem 0', fontSize: '0.8rem' }}>Applies to the listed features only.</p>
    {mode && <p style={{ margin: '0.35rem 0', fontSize: '0.8rem' }}>Covered: {features.length ? features.join(', ') : 'No feature policies available'}</p>}
    {status === 'loading' && <span role="status">Loading mode…</span>}
    {mode && <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
      {['vuln', 'fixed'].map(value => <button key={value} type="button" style={settingButton}
        aria-pressed={mode.effectiveMode === value}
        disabled={status !== 'ready' || value === mode.effectiveMode || !mode.selectableModes.includes(value)}
        onClick={() => select(value)}>{value === 'vuln' ? 'Vulnerable' : 'Fixed'}</button>)}
      {status === 'saving' && <span role="status">Updating…</span>}
    </div>}
    {error && <p role="alert" style={{ color: '#b42318', marginTop: 8 }}>{error} <button type="button" onClick={read}>Retry mode</button></p>}
  </div>;
}

export default function SecureShopWorkshop({ createController = createSecureShopWorkshopController }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;
  const route = `${location.pathname}${location.search}${location.hash}`;
  const routeRef = useRef(route);
  routeRef.current = route;
  const initialRoute = useRef(safeShopRoute(`${location.pathname}${location.search}${location.hash}`, { publicOnly: false }) || '/secureshop');
  const frameHost = useRef(null);
  const controller = useRef(null);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState({ status: 'connecting' });
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [resetConfirm, setResetConfirm] = useState(false);
  const [resetPending, setResetPending] = useState(false);
  const [resetError, setResetError] = useState('');
  const resetInFlight = useRef(null);
  const resetScope = `${user?.id ?? ''}:${state.launch?.launchId ?? ''}:${state.launch?.generation ?? ''}`;

  useEffect(() => {
    setResetConfirm(false);
    setResetError('');
    setResetPending(false);
  }, [resetScope]);

  useEffect(() => {
    if (!frameHost.current) return undefined;
    let mounted = true;
    initialRoute.current = safeShopRoute(routeRef.current, { publicOnly: false }) || '/secureshop';
    const instance = createController({
      getPlatformToken: () => localStorage.getItem('token'),
      initialRoute: initialRoute.current,
      onState: next => { if (mounted) setState(next); },
    });
    controller.current = instance;
    instance.start(frameHost.current).catch(() => {});
    return () => {
      mounted = false;
      if (resetInFlight.current === instance) resetInFlight.current = null;
      if (controller.current === instance) controller.current = null;
      instance.close();
    };
  }, [attempt, user?.id, createController]);

  useEffect(() => {
    if (state.status !== 'ready') return undefined;
    const onMessage = event => {
      const element = frameHost.current?.firstElementChild;
      if (!element || element.tagName !== 'IFRAME' || event.source !== element.contentWindow
        || event.origin !== 'null' || event.ports.length !== 0) return;
      const data = event.data;
      const nonce = new URL(element.src).hash.slice(1);
      if (!data || Object.keys(data).length !== 4 || data.channel !== BOUND_ROUTE_CHANNEL
        || data.type !== 'route' || data.nonce !== nonce) return;
      const target = safeShopRoute(data.route, { publicOnly: false });
      if (target && target !== routeRef.current) navigateRef.current(target);
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [state.status]);

  useEffect(() => {
    if (state.status !== 'ready') return;
    const element = frameHost.current?.firstElementChild;
    if (!element || element.tagName !== 'IFRAME') return;
    const current = safeShopRoute(route, { publicOnly: false });
    const nonce = new URL(element.src).hash.slice(1);
    if (current && nonce) element.contentWindow?.postMessage({ channel: BOUND_ROUTE_CHANNEL,
      type: 'set-route', nonce, route: current }, '*');
  }, [route, state.status]);

  const reset = async () => {
    const instance = controller.current;
    if (!instance || resetInFlight.current) return;
    resetInFlight.current = instance;
    setResetPending(true);
    setResetError('');
    try {
      await instance.reset();
      if (controller.current === instance) setResetConfirm(false);
    } catch (error) {
      if (controller.current === instance) setResetError(error?.message || 'Reset failed. Retry the existing reset.');
    } finally {
      if (resetInFlight.current === instance) resetInFlight.current = null;
      if (controller.current === instance) setResetPending(false);
    }
  };
  const requestReset = useCallback(() => { setResetError(''); setResetConfirm(true); }, []);
  const cancelReset = useCallback(() => { if (!resetInFlight.current) setResetConfirm(false); }, []);
  const retry = () => setAttempt(value => value + 1);
  const busy = resetPending || ['connecting', 'resetting'].includes(state.status);

  return <main aria-label="SecureShop" style={{ position: 'fixed', inset: 0, zIndex: 1000, background: '#fff' }}>
    <div ref={frameHost} data-testid="secureshop-frame-host" aria-busy={busy}
      style={{ width: '100%', height: '100dvh' }} />
    {busy && <div role="status" style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', background: '#fff' }}>
      Opening SecureShop…
    </div>}
    {state.status === 'error' && <div role="alert" style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', background: '#fff' }}>
      <div style={{ textAlign: 'center' }}><p>{state.message || 'SecureShop connection unavailable.'}</p>
        <button type="button" style={settingButton} onClick={state.terminalLaunch ? logout : state.retryReset ? reset : retry}>
          {state.terminalLaunch ? 'Sign out' : state.retryReset ? 'Retry reset' : state.capacity ? 'Retry availability' : 'Reconnect'}
        </button></div>
    </div>}
    {state.status === 'ready' && <>
      <button type="button" aria-expanded={settingsOpen} aria-controls="secureshop-settings"
        onClick={() => setSettingsOpen(value => !value)} style={{ ...settingButton,
          position: 'absolute', bottom: 16, right: 16, zIndex: 2, boxShadow: '0 2px 12px #0002' }}>
        Shop settings
      </button>
      {settingsOpen && <aside id="secureshop-settings" aria-label="Shop settings" style={{
        position: 'absolute', bottom: 64, right: 16, zIndex: 2, width: 'min(360px, calc(100vw - 32px))',
        maxHeight: 'calc(100dvh - 80px)', overflowY: 'auto', padding: 16, background: '#fff',
        border: '1px solid #d1d5db', borderRadius: 12, boxShadow: '0 8px 32px #0003', color: '#20232b' }}>
        <SecureShopModeControl key={resetScope} launch={state.launch} userId={user?.id} />
        <div style={{ borderTop: '1px solid #e5e7eb', marginTop: 16, paddingTop: 16 }}>
          <button type="button" style={settingButton} onClick={requestReset}
            disabled={busy || !controller.current}>Reset shop</button>
        </div>
      </aside>}
    </>}
    <ResetConfirmation open={resetConfirm} status={resetPending ? 'resetting' : resetError ? 'failed' : 'confirming'}
      title="Reset your shop?"
      description="This clears your shop activity, chats, and progress. Other shoppers' data is preserved."
      error={resetError} onCancel={cancelReset} onConfirm={reset} />
  </main>;
}
