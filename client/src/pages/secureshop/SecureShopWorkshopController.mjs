import { mountShopFrame } from './bridge/handshake.mjs';
import { compileBridgeOperation } from './bridge/compiler.mjs';
import { createScopedShopStateStore } from './bridge/stateStore.mjs';

const BASE = '/api/auth/secureshop-launch';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BEARER = /^[A-Za-z0-9_-]{43}$/;
const abortError = () => new DOMException('SecureShop workshop closed', 'AbortError');

function validLaunch(value) {
  return value && typeof value === 'object' && UUID.test(value.launchId)
    && Number.isSafeInteger(value.generation) && value.generation >= 1
    && Number.isSafeInteger(value.credentialVersion) && value.credentialVersion >= 1
    && typeof value.expiresAt === 'string' && Number.isFinite(Date.parse(value.expiresAt));
}
function validateCredential(value) {
  if (!value || !validLaunch(value.launch) || typeof value.bearer !== 'string'
    || !BEARER.test(value.bearer)) throw new Error('Invalid SecureShop launch response');
  return Object.freeze({ launch: Object.freeze({ ...value.launch }), bearer: value.bearer });
}
function validateReset(value, expected) {
  if (!value || value.cleanupComplete !== true || !UUID.test(value.resetId)
    || !validLaunch(value.launch) || value.launch.launchId.toLowerCase() !== expected.launchId.toLowerCase()
    || value.launch.generation !== expected.generation + 1) {
    throw new Error('SecureShop cleanup did not complete');
  }
  return Object.freeze({ resetId: value.resetId.toLowerCase(), launch: Object.freeze({ ...value.launch }) });
}

export function createSecureShopWorkshopController({
  fetchImpl = globalThis.fetch,
  getPlatformToken,
  storage = globalThis.localStorage,
  documentRef = globalThis.document,
  origin = globalThis.location?.origin,
  frameUrl = '/secureshop-frame.html',
  initialRoute = '/secureshop',
  mountFrame = mountShopFrame,
  compileOperation = compileBridgeOperation,
  createStateStore = createScopedShopStateStore,
  randomUUID = () => globalThis.crypto.randomUUID(),
  now = Date.now,
  setTimer = globalThis.setTimeout,
  clearTimer = globalThis.clearTimeout,
  onState = () => {},
} = {}) {
  if (typeof fetchImpl !== 'function' || typeof getPlatformToken !== 'function'
    || typeof documentRef?.createElement !== 'function' || typeof mountFrame !== 'function'
    || typeof compileOperation !== 'function' || typeof createStateStore !== 'function'
    || typeof randomUUID !== 'function' || typeof onState !== 'function'
    || typeof now !== 'function' || typeof setTimer !== 'function' || typeof clearTimer !== 'function') {
    throw new TypeError('SecureShop workshop controller dependencies required');
  }
  if (typeof initialRoute !== 'string' || !initialRoute.startsWith('/secureshop')) {
    throw new TypeError('Valid SecureShop entry route required');
  }
  const parsedOrigin = new URL(origin);
  if (!['http:', 'https:'].includes(parsedOrigin.protocol) || parsedOrigin.origin !== origin) {
    throw new TypeError('Exact workshop origin required');
  }

  let active = true; let epoch = 0; let container = null; let current = null;
  let pendingReset = null; let resetAttempt = null; let pendingRequest = null;
  // One absolute budget spans metadata/create/recover or reset/recover.
  const operationBudgets = new WeakMap();
  function operationController() {
    const controller = new AbortController();
    operationBudgets.set(controller.signal, { controller, deadline: now() + 60000 });
    return controller;
  }

  let heartbeatTimer=null,heartbeatRequest=null,heartbeatPending=null,heartbeatCycle=0,lastActivity=now();
  const markActive=()=>{lastActivity=now();};
  const activityEvents=['pointerdown','keydown','scroll','touchstart'];
  activityEvents.forEach(type=>documentRef.addEventListener?.(type,markActive,{capture:true,passive:true}));
  function stopHeartbeat(){
    heartbeatCycle++;if(heartbeatTimer!==null)clearTimer(heartbeatTimer);heartbeatTimer=null;
    heartbeatRequest?.abort();heartbeatRequest=null;
    return heartbeatPending?.catch(()=>{});
  }
  function startHeartbeat(state,capturedEpoch,token){
    stopHeartbeat();const cycle=heartbeatCycle;
    const currentCycle=()=>active&&cycle===heartbeatCycle&&epoch===capturedEpoch&&current===state&&state.frame?.isConnected&&getPlatformToken()===token;
    const tick=async()=>{
      if(!currentCycle())return;heartbeatTimer=null;
      if(documentRef.visibilityState==='visible'&&now()-lastActivity<120000){
        const controller=new AbortController(),credential=state.credential;heartbeatRequest=controller;
        const deadline=setTimer(()=>controller.abort(),5000);
        const aborted=new Promise((_,reject)=>controller.signal.addEventListener('abort',()=>reject(abortError()),{once:true}));
        const request=Promise.race([api('/heartbeat',{method:'POST',body:{bearer:credential.bearer,expectedGeneration:credential.launch.generation},signal:controller.signal},token),aborted]);
        heartbeatPending=request;
        try{await request;}
        catch(error){if(currentCycle()&&heartbeatRequest===controller&&state.credential===credential&&!controller.signal.aborted&&[401,403,409].includes(error.status)){detachFrame(state);publish({status:'error',message:'SecureShop connection needs to be renewed. Reconnect to continue.'});return;}}
        finally{clearTimer(deadline);if(heartbeatRequest===controller)heartbeatRequest=null;if(heartbeatPending===request)heartbeatPending=null;}
      }
      if(currentCycle())heartbeatTimer=setTimer(tick,30000);
    };
    heartbeatTimer=setTimer(tick,0);
  }
  let renewalTimer = null;
  let renewal = null;
  function stopRenewalTimer() {
    if (renewalTimer !== null) clearTimer(renewalTimer);
    renewalTimer = null;
  }
  function scheduleRenewal(state, capturedEpoch, token) {
    stopRenewalTimer();
    const remaining = Date.parse(state.credential.launch.expiresAt) - now();
    // Renew with time for transport failures, bounded by the platform session.
    renewalTimer = setTimer(() => {
      renewalTimer = null;
      if (state.noFurtherRenewal && active && capturedEpoch === epoch && current === state) {
        detachFrame(state);
        publish({ status: 'error', message: 'SecureShop session expired. Sign in again to continue.' });
        return;
      }
      void renewCurrent(state, capturedEpoch, token).catch(() => {});
    }, Math.max(0, state.noFurtherRenewal ? remaining : remaining - Math.min(5 * 60 * 1000, remaining / 5)));
    renewalTimer?.unref?.();
  }
  function renewCurrent(state, capturedEpoch, token) {
    if (renewal?.state === state && renewal.epoch === capturedEpoch) return renewal.promise;
    if (!active || capturedEpoch !== epoch || current !== state) return Promise.reject(abortError());
    const controller = operationController(); pendingRequest = controller;
    const expected = state.credential;
    const operation = { state, epoch: capturedEpoch, promise: null };
    renewal = operation;
    const drainedHeartbeat=stopHeartbeat();
    operation.promise = (async () => {
      try {
        if(drainedHeartbeat)await drainedHeartbeat;
        if (!active || capturedEpoch !== epoch || current !== state) throw abortError();
        const credential = validateCredential(await api('', { method: 'PATCH',
          body: { bearer: expected.bearer }, signal: controller.signal }, token));
        if (!active || capturedEpoch !== epoch || current !== state) throw abortError();
        if (credential.launch.launchId !== expected.launch.launchId
          || credential.launch.generation !== expected.launch.generation
          || credential.launch.credentialVersion <= expected.launch.credentialVersion
          || Date.parse(credential.launch.expiresAt) <= now()) {
          throw new Error('SecureShop renewal did not match the active launch');
        }
        state.noFurtherRenewal = Date.parse(credential.launch.expiresAt) <= Date.parse(expected.launch.expiresAt);
        state.credential = credential;
        publish({ status: 'ready', launch: credential.launch });
        scheduleRenewal(state, capturedEpoch, token);
        startHeartbeat(state,capturedEpoch,token);
        return credential.launch;
      } catch (error) {
        if (active && capturedEpoch === epoch && current === state) {
          // A lost response may already have rotated the handle. Stop using it;
          // reconnect recovers current server metadata instead of guessing.
          detachFrame(state);
          publish({ status: 'error', message: 'SecureShop connection needs to be renewed. Reconnect to continue.' });
        }
        throw error;
      } finally {
        if (pendingRequest === controller) pendingRequest = null;
        if (renewal === operation) renewal = null;
      }
    })();
    return operation.promise;
  }
  const publish = value => { if (active) onState(Object.freeze({ ...value })); };
  const currentToken = captured => {
    const token = getPlatformToken();
    if (!active || typeof token !== 'string' || !token || token !== captured) throw abortError();
  };
  async function api(path, { method = 'GET', body, signal } = {}, token) {
    currentToken(token);
    const budget = operationBudgets.get(signal);
    let timer = null; let abort;
    const check = () => {
      currentToken(token);
      if (signal?.aborted) throw signal.reason || abortError();
      if (budget && now() >= budget.deadline) {
        const error = new Error('SecureShop request timed out. Reconnect or retry the existing reset.');
        error.name = 'TimeoutError'; budget.controller.abort(error); throw error;
      }
    };
    check();
    const cancelled = new Promise((_, reject) => {
      abort = () => reject(signal.reason || abortError());
      signal?.addEventListener('abort', abort, { once: true });
      if (budget) timer = setTimer(() => {
        const error = new Error('SecureShop request timed out. Reconnect or retry the existing reset.');
        error.name = 'TimeoutError'; budget.controller.abort(error);
      }, Math.max(0, budget.deadline - now()));
    });
    try {
      const task = (async () => {
        const response = await fetchImpl(`${BASE}${path}`, { method, signal, credentials: 'omit', redirect: 'error',
          headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        check();
        const data = await response.json().catch(() => ({}));
        check();
        if (!response.ok) {
          const error = new Error(data.error || 'SecureShop launch request failed');
          error.status = response.status;
          if (data.code === 'LAUNCH_SESSION_TERMINAL' || data.code === 'LAUNCH_CAPACITY') error.code = data.code;
          throw error;
        }
        return data;
      })();
      const data = await Promise.race([task, cancelled]);
      check();
      return data;
    } finally {
      if (timer !== null) clearTimer(timer);
      signal?.removeEventListener('abort', abort);
    }
  }
  function detachFrame(state = current) {
    stopRenewalTimer();stopHeartbeat();
    if (!state) return;
    state.session?.close();
    state.frame?.remove();
    state.stateStore?.close();
    if (current === state) current = { ...state, session: null, frame: null, stateStore: null };
  }
  async function mountCurrent(credential, capturedEpoch) {
    if (!active || capturedEpoch !== epoch || !container?.isConnected) throw abortError();
    const platformToken = getPlatformToken();
    currentToken(platformToken);
    const frame = documentRef.createElement('iframe');
    frame.title = 'SecureShop';
    frame.setAttribute('aria-label', 'SecureShop storefront');
    Object.assign(frame.style, { width: '100%', height: '100%', border: '0', display: 'block' });
    let retirementConfirmed = false;
    let state = null;
    const stateStore = createStateStore({ storage, scenarioId: credential.launch.launchId,
      generation: credential.launch.generation,
      isCurrent: () => active && capturedEpoch === epoch && state !== null && current === state
        && getPlatformToken() === platformToken,
      canRetire: () => retirementConfirmed,
    });
    state = { credential, frame, stateStore, session: null,
      confirmRetirement() { retirementConfirmed = true; stateStore.retire(); } };
    current = state;
    const onLaunchUnavailable = capturedBearer => {
      if (!active || capturedEpoch !== epoch || current !== state || state.frame !== frame
        || !frame.isConnected || getPlatformToken() !== platformToken
        || capturedBearer !== state.credential.bearer) return;
      detachFrame(state);
      publish({ status: 'error',
        message: 'SecureShop connection needs to be renewed. Reconnect to continue.' });
    };
    const entryUrl = new URL(frameUrl, origin);
    entryUrl.searchParams.set('entry', initialRoute);
    const session = mountFrame({ frame, url: entryUrl.href, origin, compileOperation,
      getLaunchBearer: () => {
        currentToken(platformToken);
        if (!active || capturedEpoch !== epoch || current !== state) throw abortError();
        return state.credential.bearer;
      }, onActivity:()=>{if(active&&capturedEpoch===epoch&&current===state&&state.frame?.isConnected)markActive();}, stateStore,
      transportOptions: { onLaunchUnavailable, publicReadFallback: true } });
    state.session = session;
    container.replaceChildren(frame);
    try {
      await session.ready;
      if (!active || capturedEpoch !== epoch || current !== state) throw abortError();
      lastActivity=now();
      publish({ status: 'ready', launch: credential.launch });
      scheduleRenewal(state, capturedEpoch, platformToken);
      startHeartbeat(state,capturedEpoch,platformToken);
      return state;
    } catch (error) {
      session.close(); frame.remove(); stateStore.close();
      if (current === state) current = null;
      throw error;
    }
  }
  async function obtainCredential(token, signal) {
    const metadata = await api('', { signal }, token);
    if (metadata.launch === null) {
      try { return validateCredential(await api('', { method: 'POST', body: {}, signal }, token)); }
      catch (error) {
        if (error.status !== 409 || error.code === 'LAUNCH_SESSION_TERMINAL' || error.code === 'LAUNCH_CAPACITY') throw error;
        // A concurrent tab may have created this session's launch after GET.
        // The second metadata read remains bound to the same platform session.
        const raced = await api('', { signal }, token);
        if (!validLaunch(raced.launch)) throw error;
        return validateCredential(await api('/recover', { method: 'POST', signal, body: {
          launchId: raced.launch.launchId,
          expectedCredentialVersion: raced.launch.credentialVersion,
        } }, token));
      }
    }
    if (!validLaunch(metadata.launch)) throw new Error('Invalid SecureShop launch metadata');
    return validateCredential(await api('/recover', { method: 'POST', signal, body: {
      launchId: metadata.launch.launchId,
      expectedCredentialVersion: metadata.launch.credentialVersion,
    } }, token));
  }
  async function start(target) {
    if (!active || container || !target || typeof target.replaceChildren !== 'function') {
      throw new TypeError('Fresh SecureShop workshop container required');
    }
    container = target;
    const capturedEpoch = ++epoch;
    pendingRequest?.abort();
    const token = getPlatformToken(); currentToken(token);
    const controller = operationController(); pendingRequest = controller;
    publish({ status: 'connecting' });
    try {
      const credential = await obtainCredential(token, controller.signal);
      currentToken(token);
      if (capturedEpoch !== epoch) throw abortError();
      await mountCurrent(credential, capturedEpoch);
      return credential.launch;
    } catch (error) {
      if (active && capturedEpoch === epoch) publish(error.code === 'LAUNCH_SESSION_TERMINAL'
        ? { status: 'error', terminalLaunch: true,
          message: 'This platform session’s SecureShop launch has ended. Sign out and sign in again to start a new session.' }
        : error.code === 'LAUNCH_CAPACITY'
          ? { status: 'error', capacity: true, message: error.message }
          : { status: 'error', message: error.message });
      throw error;
    } finally {
      if (pendingRequest === controller) pendingRequest = null;
    }
  }
  function reset() {
    if (!active || !current?.credential) return Promise.reject(abortError());
    if (pendingReset) return pendingReset;
    const old = current;
    const expected = old.credential.launch;
    if (!resetAttempt || resetAttempt.launchId !== expected.launchId
      || resetAttempt.generation !== expected.generation) {
      const idempotencyKey = randomUUID();
      if (!UUID.test(idempotencyKey)) return Promise.reject(new TypeError('Secure reset UUID required'));
      resetAttempt = { launchId: expected.launchId, generation: expected.generation,
        idempotencyKey: idempotencyKey.toLowerCase() };
    }
    const token = getPlatformToken();
    try { currentToken(token); } catch (error) {
      epoch += 1; pendingRequest?.abort(); detachFrame(old);
      publish({ status: 'error', message: 'Platform session changed. Sign in again to continue.' });
      return Promise.reject(error);
    }
    const capturedEpoch = ++epoch;
    pendingRequest?.abort();
    detachFrame(old);
    publish({ status: 'resetting', launch: expected });
    const controller = operationController(); pendingRequest = controller;
    pendingReset = (async () => {
      let committed = false;
      try {
        const value = await api('/reset', { method: 'POST', signal: controller.signal, body: {
          launchId: expected.launchId, expectedGeneration: expected.generation,
          idempotencyKey: resetAttempt.idempotencyKey,
        } }, token);
        const receipt = validateReset(value, expected);
        currentToken(token);
        old.confirmRetirement();
        committed = true;
        if (!active || capturedEpoch !== epoch) throw abortError();
        const credential = validateCredential(await api('/recover', { method: 'POST', signal: controller.signal,
          body: { launchId: receipt.launch.launchId,
            expectedCredentialVersion: receipt.launch.credentialVersion } }, token));
        if (credential.launch.launchId !== receipt.launch.launchId
          || credential.launch.generation !== receipt.launch.generation) {
          throw new Error('SecureShop recovery did not match reset');
        }
        current = null;
        await mountCurrent(credential, capturedEpoch);
        resetAttempt = null;
        return receipt.launch;
      } catch (error) {
        if (!committed && active && capturedEpoch === epoch) {
          // A lost response does not mean reset was rolled back. Keep the old
          // frame detached and retry the same journal instead of reactivating
          // an uncertain generation or discarding its idempotency key.
          current = { ...old, session: null, frame: null, stateStore: null };
          publish({ status: 'error', message: error.message, launch: expected, retryReset: true });
        } else if (committed && active && capturedEpoch === epoch) {
          current = null;
          publish({ status: 'error', message: error.message });
        }
        throw error;
      } finally {
        if (pendingRequest === controller) pendingRequest = null;
        pendingReset = null;
      }
    })();
    return pendingReset;
  }
  function close() {
    if (!active) return;
    activityEvents.forEach(type=>documentRef.removeEventListener?.(type,markActive,true));
    active = false; epoch += 1; pendingRequest?.abort(); pendingRequest = null;
    stopRenewalTimer();
    detachFrame(); current = null; container = null;
    publish({ status: 'closed' });
  }
  return Object.freeze({ start, reset, close });
}
