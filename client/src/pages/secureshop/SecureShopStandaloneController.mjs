import { mountShopFrame } from './bridge/handshake.mjs';
import { compileBridgeOperation } from './bridge/compiler.mjs';
import { createSeededShopStateStore } from './bridge/seededStateStore.mjs';
import { createStandaloneShopClient } from './standaloneClient.mjs';
import { validateShopSnapshot } from './bridge/stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_LISTINGS_KEY, SHOP_MAIL_KEY, SHOP_REFUND_KEY,
  SHOP_ROLE_ASSISTANT_KEY, SHOP_ROLE_ASSISTANT_COMPLETED_KEY, SHOP_REGISTERED_ADMIN_COMPLETED_KEY,
  SHOP_CUSTOMER_CHAT_COMPLETED_KEY } from './utils/shopStorage.mjs';
import { decodeListingsReferences } from './pages/merchant/listingsReferences.mjs';
import { decodeMailReferences } from './bridge/mailReferences.mjs';
import { decodeRefundReferences } from './utils/refundReferences.mjs';
import { decodeRoleAssistantReferences } from './utils/roleAssistantReferences.mjs';

const cancelled = () => new DOMException('OWASP AI SecureShop connection closed', 'AbortError');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exactKeys = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const PRIVATE_RESET_OPERATIONS = new Set(['admin.users.resetPassword', 'admin.users.resetRead',
  'admin.users.resetReveal', 'admin.users.resetAcknowledge']);

export function compileStandaloneFrameOperation(name, input) {
  if (PRIVATE_RESET_OPERATIONS.has(name)) throw new TypeError('Password reset is available only in the trusted shop panel');
  return compileBridgeOperation(name, input);
}

export function createSecureShopStandaloneController({
  client = createStandaloneShopClient(), storage = globalThis.localStorage,
  documentRef = globalThis.document, origin = globalThis.location?.origin,
  shopRole = 'customer',
  principalId = null,
  initialRoute = '/secureshop', frameUrl = '/secureshop-frame.html',
  mountFrame = mountShopFrame, createStateStore = createSeededShopStateStore,
  onState = () => {},
  canSwitchPractice = () => true,
} = {}) {
  if (!client || ['bootstrap', 'renew', 'scenes', 'selectScene', 'resetPractice'].some(key => typeof client[key] !== 'function')
    || (shopRole === 'admin' && ['getPracticeResetRecovery', 'resumePracticeReset']
      .some(key => typeof client[key] !== 'function'))
    || typeof storage?.getItem !== 'function' || typeof documentRef?.createElement !== 'function'
    || typeof mountFrame !== 'function' || typeof createStateStore !== 'function'
    || typeof onState !== 'function' || typeof canSwitchPractice !== 'function') throw new TypeError('Standalone shop dependencies required');
  const originUrl = new URL(origin);
  if (!['http:', 'https:'].includes(originUrl.protocol) || originUrl.origin !== origin) throw new TypeError('Exact shop origin required');
  let active = true, epoch = 0, host = null, current = null, pending = null;
  let bootstrap = null, sceneList = null, resetAttempt = null, pendingReset = null;
  let passwordResetContext = null;
  let recovery = null, recoveryReceipt = null, pendingRecovery = null;
  let originalSceneId = null;
  const practiceKey = UUID.test(principalId || '')
    ? `owasp-ai-goat:secureshop:practice-admission:v1:${principalId.toLowerCase()}` : null;
  let practiceAttempt = null, practiceReceipt = null;
  const readPracticeAttempt = () => {
    if (!practiceKey) return null;
    const bytes = storage.getItem(practiceKey);
    if (bytes === null) return null;
    if (typeof bytes !== 'string' || bytes.length > 160) throw new Error('Saved new practice reference could not be verified');
    let value;
    try { value = JSON.parse(bytes); } catch { throw new Error('Saved new practice reference could not be verified'); }
    if (!value || Object.keys(value).length !== 2 || value.version !== 1
      || !UUID.test(value.operationId || '') || value.operationId !== value.operationId.toLowerCase()) {
      throw new Error('Saved new practice reference could not be verified');
    }
    return value.operationId;
  };
  const savePracticeAttempt = operationId => {
    if (!practiceKey || readPracticeAttempt() !== null) throw new Error('Saved new practice reference required');
    const bytes = JSON.stringify({ version: 1, operationId });
    storage.setItem(practiceKey, bytes);
    if (storage.getItem(practiceKey) !== bytes) throw new Error('New practice reference was not saved');
    practiceAttempt = operationId;
    practiceReceipt = null;
  };
  const clearPracticeAttempt = operationId => {
    if (readPracticeAttempt() !== operationId) throw new Error('Saved new practice reference changed');
    storage.removeItem(practiceKey);
    if (storage.getItem(practiceKey) !== null) throw new Error('Saved new practice reference was not cleared');
    practiceAttempt = null;
    practiceReceipt = null;
  };
  const publish = value => { if (active) onState(Object.freeze({ ...value })); };
  const detach = () => {
    current?.session?.close(); current?.frame?.remove(); current?.store?.close(); current = null;
  };
  const fresh = captured => active && captured === epoch;
  const scopeKey = credential => `owasp-ai-goat:secureshop:${credential.launch.launchId.toLowerCase()}:${credential.launch.generation}`;
  const markerKey = credential => `${scopeKey(credential)}:scene-storage-v1`;
  const cartMirrorKey = sceneId => `owasp-ai-goat:secureshop:scene-cart:v1:${principalId.toLowerCase()}:${sceneId.toLowerCase()}`;
  function readCartMirror(sceneId) {
    const bytes = storage.getItem(cartMirrorKey(sceneId));
    if (bytes === null) return null;
    if (typeof bytes !== 'string' || bytes.length > 132 * 1024) throw new Error('Retained practice cart could not be verified');
    let value;
    try { value = JSON.parse(bytes); } catch { throw new Error('Retained practice cart could not be verified'); }
    if (!value || Object.keys(value).length !== 3 || value.version !== 1
      || value.sceneId !== sceneId.toLowerCase()
      || (value.cart !== null && typeof value.cart !== 'string')) {
      throw new Error('Retained practice cart could not be verified');
    }
    return JSON.stringify(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: value.cart }));
  }
  function writeCartMirror(sceneId, snapshot) {
    if (!practiceKey || !UUID.test(sceneId || '')) return;
    const value = validateShopSnapshot(snapshot);
    if (value[SHOP_TOKEN_KEY] !== null) throw new Error('Retained practice cart could not be verified');
    const bytes = JSON.stringify({ version: 1, sceneId: sceneId.toLowerCase(), cart: value[SHOP_CART_KEY] });
    const key = cartMirrorKey(sceneId);
    storage.setItem(key, bytes);
    if (storage.getItem(key) !== bytes) throw new Error('Retained practice cart was not saved');
  }
  function sceneStorage(credential, sceneId) {
    const marker = storage.getItem(markerKey(credential));
    if (marker === null && (!practiceKey || !UUID.test(sceneId || ''))) return storage;
    if ((marker !== null && marker !== '1') || !UUID.test(sceneId || '')) throw new Error('Shop practice storage could not be verified');
    const key = value => {
      if (value !== scopeKey(credential)) throw new TypeError('Exact shop storage scope required');
      return marker === null ? value : `${value}:scene:${sceneId.toLowerCase()}`;
    };
    return Object.freeze({ getItem: value => storage.getItem(key(value)) ?? (practiceKey ? readCartMirror(sceneId) : null),
      setItem: (value, bytes) => {
        const snapshot = validateShopSnapshot(JSON.parse(bytes));
        storage.setItem(key(value), bytes);
        writeCartMirror(sceneId, snapshot);
      },
      removeItem: value => { storage.removeItem(key(value)); if (practiceKey) storage.removeItem(cartMirrorKey(sceneId)); } });
  }
  function readSnapshot(state) {
    const raw = state.storage.getItem(scopeKey(state.credential));
    if (raw !== null && (typeof raw !== 'string' || raw.length > 2 * 1024 * 1024)) {
      throw new Error('Shop saved operations could not be verified');
    }
    const snapshot = validateShopSnapshot(raw === null
      ? { [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null } : JSON.parse(raw));
    const hasSavedReference = ([key, value]) => {
      if (key === SHOP_TOKEN_KEY || key === SHOP_CART_KEY
        || key === SHOP_CUSTOMER_CHAT_COMPLETED_KEY
        || key === SHOP_ROLE_ASSISTANT_COMPLETED_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY || value === null) return false;
      if (key === SHOP_LISTINGS_KEY) {
        const listings = decodeListingsReferences(value);
        return [listings, ...(listings.retained || [])].some(group =>
          ['rewrite', 'import', 'optimize', 'save', 'template', 'manualCreate', 'manualEdit'].some(action => Object.hasOwn(group, action))
          || (group.assessment?.length || 0) > 0);
      }
      if (key === SHOP_MAIL_KEY) {
        return Object.values(decodeMailReferences(value).scopes).some(refs =>
          ['pending', 'assessment', 'headerAssessment', 'disclosureAssessment', 'browserAssessment', 'htmlAssessment']
            .some(kind => refs[kind] != null) || (refs.unresolved?.length || 0) > 0);
      }
      if (key === SHOP_REFUND_KEY) return decodeRefundReferences(value).length > 0;
      if (key === SHOP_ROLE_ASSISTANT_KEY) return decodeRoleAssistantReferences(value).length > 0;
      return true;
    };
    if (canSwitchPractice() !== true || Object.entries(snapshot).some(hasSavedReference)) {
      throw new Error('Check saved operation status before choosing another practice.');
    }
    return { ...snapshot, [SHOP_TOKEN_KEY]: null };
  }
  const readyState = extra => ({ status: 'ready', launch: bootstrap.launch,
    personaExpiresAt: bootstrap.persona.expiresAt,
    ...(practiceAttempt ? { practiceWarning: 'A new practice attempt is unresolved. Check it before starting another.' } : {}),
    ...extra });

  const passwordAuthority = async signal => {
    const state = current, captured = epoch, credential = state?.credential;
    if (shopRole !== 'admin' || !fresh(captured) || !state?.session || !state.sceneId
      || bootstrap !== credential || credential?.persona?.user?.role !== 'admin'
      || !UUID.test(state.sceneId)) throw new Error('Current administrator practice required');
    const scopeKey = await client.getBoundAdminScope(credential.bearer, credential.persona.token, signal);
    let scope;
    try { scope = JSON.parse(scopeKey); } catch { throw new Error('Administrator scope changed'); }
    if (!fresh(captured) || current !== state || bootstrap !== credential
      || !Array.isArray(scope) || scope.length !== 6
      || scope[0] !== credential.launch.launchId || scope[1] !== credential.launch.generation
      || scope[4] !== credential.persona.user.id || !UUID.test(scope[5] || '')) {
      throw new Error('Administrator scope changed');
    }
    return { state, captured, credential, sceneId: state.sceneId, scopeKey };
  };
  const samePasswordAuthority = value => fresh(value.captured) && current === value.state
    && bootstrap === value.credential && current?.sceneId === value.sceneId;

  const merchantMailAuthority = () => {
    const state = current, captured = epoch, credential = state?.credential;
    if (shopRole !== 'merchant' || !fresh(captured) || !state?.session || !UUID.test(state.sceneId || '')
      || bootstrap !== credential || credential?.persona?.user?.role !== 'merchant') {
      throw new Error('Current merchant practice required');
    }
    return { state, captured, credential, sceneId: state.sceneId };
  };
  const sameMerchantMailAuthority = authority => fresh(authority.captured)
    && current === authority.state && bootstrap === authority.credential
    && current?.sceneId === authority.sceneId;
  async function getExternalMailReadiness(signal) {
    const authority = merchantMailAuthority();
    const value = await client.getExternalMailReadiness(authority.credential.bearer,
      authority.credential.persona.token, signal);
    if (!sameMerchantMailAuthority(authority)) throw new Error('Merchant practice changed');
    return value;
  }
  async function externalMailMutation(kind, operation, verifyBeforeDispatch) {
    if (!exactKeys(operation, kind === 'prepare'
      ? ['operationId', 'recipient', 'scopeKey'] : ['operationId', 'requestSha256', 'scopeKey'])) {
      throw new TypeError('Saved external test send required');
    }
    const authority = merchantMailAuthority();
    const readiness = await client.getExternalMailReadiness(authority.credential.bearer,
      authority.credential.persona.token);
    if (!sameMerchantMailAuthority(authority) || readiness.available !== true
      || readiness.scopeKey !== operation.scopeKey || typeof verifyBeforeDispatch !== 'function'
      || verifyBeforeDispatch() !== true) throw new Error('External test send authority changed');
    const args = [authority.credential.bearer, authority.credential.persona.token, operation];
    const value = await (kind === 'prepare' ? client.prepareExternalMail(...args)
      : kind === 'confirm' ? client.confirmExternalMail(...args) : client.cancelExternalMail(...args));
    if (!sameMerchantMailAuthority(authority)) throw new Error('Merchant practice changed');
    return value;
  }
  async function getExternalMailOperation(operationId, scopeKey, signal) {
    const authority = merchantMailAuthority();
    const value = await client.getExternalMailOperation(authority.credential.bearer,
      authority.credential.persona.token, operationId, scopeKey, signal);
    if (!sameMerchantMailAuthority(authority)) throw new Error('Merchant practice changed');
    return value;
  }

  async function preparePasswordReset(request, signal) {
    if (!exactKeys(request, request?.kind === 'chat'
      ? ['kind', 'sessionId', 'requestId', 'choiceId'] : ['kind', 'targetId'])
      || !['chat', 'registered_manual', 'teaching_manual'].includes(request.kind)) {
      throw new TypeError('Trusted password reset request required');
    }
    passwordResetContext = null;
    const authority = await passwordAuthority(signal);
    let targetId, channel, expectedName = null;
    if (request.kind === 'chat') {
      if (![request.sessionId, request.requestId, request.choiceId].every(value => UUID.test(value || '')
        && value === value.toLowerCase())) throw new TypeError('Saved assistant selection required');
      const value = await client.getBoundPasswordResetSetup(authority.credential.bearer,
        authority.credential.persona.token, request.sessionId, request.requestId, signal);
      const setup = value?.passwordResetSetup;
      if (!samePasswordAuthority(authority) || value?.status !== 'completed'
        || value?.replayed !== true || value?.stopReason !== 'end_turn'
        || value?.sessionId !== request.sessionId || value?.requestId !== request.requestId
        || !exactKeys(setup, ['version', 'kind', 'sessionId', 'requestId', 'choiceId',
          'userId', 'username', 'identityKind', 'channel', 'scopeKey'])
        || setup.version !== 1 || setup.kind !== 'password_reset_setup'
        || setup.sessionId !== request.sessionId || setup.requestId !== request.requestId
        || setup.choiceId !== request.choiceId || setup.scopeKey !== authority.scopeKey
        || !Number.isSafeInteger(setup.userId) || setup.userId < 1 || setup.userId > 2147483647
        || typeof setup.username !== 'string' || !setup.username
        || !['registered_account', 'teaching_persona'].includes(setup.identityKind)
        || setup.channel !== (setup.identityKind === 'registered_account'
          ? 'protected_account' : 'bound_persona')) throw new Error('Saved password reset handoff changed');
      targetId = setup.userId; channel = setup.channel; expectedName = setup.username;
    } else {
      if (!Number.isSafeInteger(request.targetId) || request.targetId < 1
        || request.targetId > 2147483647) throw new TypeError('Password reset target required');
      targetId = request.targetId;
      channel = request.kind === 'teaching_manual' ? 'bound_persona' : 'protected_account';
    }
    if (targetId === authority.credential.persona.user.id) throw new Error('Use self-service password change');
    const target = channel === 'bound_persona'
      ? await client.getTeachingResetReadiness(authority.credential.bearer,
        authority.credential.persona.token, targetId, signal)
      : await client.getResetReadiness(targetId, signal);
    if (!samePasswordAuthority(authority) || target?.id !== targetId
      || target.resetAvailable !== true || expectedName !== null && target.username !== expectedName
      || channel === 'bound_persona' && target.channel !== 'bound_persona') {
      throw new Error('Password reset target changed');
    }
    passwordResetContext = { ...authority, targetId, channel, request,
      credentialVersion: target.credentialVersion, authorityVersion: target.authorityVersion,
      membershipVersion: target.membershipVersion ?? null };
    return { ...target, channel, identityKind: channel === 'bound_persona'
      ? 'teaching_persona' : 'registered_account', scopeKey: authority.scopeKey,
      sceneId: authority.sceneId, request };
  }

  async function resetPasswordFromParent(operation, signal, verifyBeforeDispatch) {
    const context = passwordResetContext;
    if (!context || !samePasswordAuthority(context) || operation?.scopeKey !== context.scopeKey
      || operation.sceneId !== context.sceneId || operation.targetId !== context.targetId
      || operation.channel !== context.channel
      || JSON.stringify(operation.source) !== JSON.stringify(context.request)
      || operation.expectedCredentialVersion !== context.credentialVersion
      || operation.expectedAuthorityVersion !== context.authorityVersion
      || (context.channel === 'protected_account'
        ? operation.expectedMembershipVersion !== context.membershipVersion
        : operation.expectedMembershipVersion !== null)
      || !UUID.test(operation.operationId || '')
      || operation.operationId !== operation.operationId.toLowerCase()) {
      throw new Error('Current reviewed password reset required');
    }
    const freshScope = await passwordAuthority(signal);
    if (!samePasswordAuthority(context) || freshScope.scopeKey !== context.scopeKey) {
      throw new Error('Administrator scope changed before password reset');
    }
    if (typeof verifyBeforeDispatch !== 'function' || verifyBeforeDispatch() !== true) {
      throw new Error('Saved reset reference changed before confirmation');
    }
    const result = await (context.channel === 'bound_persona'
      ? client.resetTeachingPassword(context.credential.bearer, context.credential.persona.token,
        context.targetId, operation, signal)
      : client.resetUserPassword(context.targetId, operation, signal));
    if (!samePasswordAuthority(context)) throw new Error('Administrator scope changed');
    return result;
  }

  async function savedPasswordResetFromParent(operation, kind, signal) {
    if (!['read', 'reveal', 'acknowledge'].includes(kind)
      || !operation || operation.version !== 2 || operation.adminPrincipalId !== principalId
      || !UUID.test(operation.operationId || '') || !Number.isSafeInteger(operation.targetId)
      || !['bound_persona', 'protected_account'].includes(operation.channel)) {
      throw new TypeError('Saved password reset reference required');
    }
    const authority = await passwordAuthority(signal);
    if (authority.scopeKey !== operation.scopeKey || authority.sceneId !== operation.sceneId) {
      throw new Error('Saved password reset belongs to another administrator practice');
    }
    const id = operation.targetId, op = operation.operationId;
    let result;
    if (operation.channel === 'bound_persona') {
      const args = [authority.credential.bearer, authority.credential.persona.token, id, op, signal];
      result = await (kind === 'read' ? client.getTeachingResetStatus(...args)
        : kind === 'reveal' ? client.revealTeachingReset(...args)
          : client.acknowledgeTeachingReset(...args));
    } else {
      result = await (kind === 'read' ? client.getPasswordResetStatus(id, op, signal)
        : kind === 'reveal' ? client.revealPasswordReset(id, op, signal)
          : client.acknowledgePasswordReset(id, op, signal));
    }
    if (!samePasswordAuthority(authority)) throw new Error('Administrator scope changed');
    return result;
  }

  function preserveSceneState(state, credential, sceneId, snapshot) {
    const marker = storage.getItem(markerKey(credential));
    if (marker !== null && marker !== '1') throw new Error('Shop practice storage could not be verified');
    writeCartMirror(sceneId, snapshot);
    if (marker !== null) return;
    const key = `${scopeKey(credential)}:scene:${sceneId.toLowerCase()}`;
    const bytes = JSON.stringify(snapshot);
    const retained = storage.getItem(key);
    if (retained !== null && retained !== bytes) throw new Error('Retained practice storage changed');
    storage.setItem(key, bytes);
    if (storage.getItem(key) !== bytes) throw new Error('Shop practice storage was not saved');
    storage.setItem(markerKey(credential), '1');
    if (storage.getItem(markerKey(credential)) !== '1') throw new Error('Shop practice storage was not saved');
  }

  async function bootstrapWithExpiredRenew(signal, captured) {
    try { return await client.bootstrap(signal); }
    catch (error) {
      if (error?.status !== 409 || error?.code !== 'SHOP_LAUNCH_EXPIRED') throw error;
      if (!fresh(captured) || signal.aborted) throw cancelled();
      await client.renew(signal);
      if (!fresh(captured)) throw cancelled();
      return client.bootstrap(signal);
    }
  }

  async function mount(credential, captured, selectedSceneId) {
    if (!fresh(captured) || !host?.isConnected) throw cancelled();
    const frame = documentRef.createElement('iframe');
    frame.title = 'OWASP AI SecureShop';
    frame.setAttribute('aria-label', 'OWASP AI SecureShop storefront');
    Object.assign(frame.style, { width: '100%', height: '100%', border: '0', display: 'block' });
    const sceneId = selectedSceneId || sceneList?.find(row => row.isDefault)?.id
      || (sceneList?.length === 1 ? sceneList[0].id : null);
    if (sceneId !== null && !sceneList?.some(row => row.id === sceneId)) {
      throw new Error('Selected practice is not in the owned scene list');
    }
    const state = { frame, session: null, store: null, credential, sceneId,
      storage: sceneStorage(credential, sceneId) };
    current = state;
    try {
      const store = createStateStore({ storage: state.storage, scenarioId: credential.launch.launchId,
        generation: credential.launch.generation, personaToken: credential.persona.token,
        isCurrent: () => fresh(captured) && current === state && frame.isConnected });
      state.store = store;
      const url = new URL(frameUrl, origin);
      url.searchParams.set('entry', initialRoute);
      url.searchParams.set('standalone', '1');
      const session = mountFrame({ frame, url: url.href, origin, compileOperation: compileStandaloneFrameOperation,
        waitForInitialLoad: true,
        onDisconnect: () => {
          if (!fresh(captured) || current !== state) return;
          detach();
          publish({ status: 'error', message: 'Shop connection changed. Retry to reconnect to your practice.' });
        },
        stateStore: store, getLaunchBearer: () => {
          if (!fresh(captured) || current !== state) throw cancelled();
          return state.credential.bearer;
        }, transportOptions: { publicReadFallback: true,
          onLaunchUnavailable: bearer => {
            if (fresh(captured) && current === state && bearer === state.credential.bearer) {
              detach(); publish({ status: 'error', message: 'Shop session changed. Reopen OWASP AI SecureShop to continue.' });
            }
          } },
      });
      state.session = session;
      host.replaceChildren(frame);
      await session.ready;
      if (!fresh(captured) || current !== state) throw cancelled();
      publish(readyState());
    } catch (error) {
      if (current === state) detach();
      throw error;
    }
  }

  async function choosePractice() {
    if (!active || !current || !bootstrap || pending || pendingReset || pendingRecovery) {
      throw new TypeError('Current shop practice required');
    }
    const state = current;
    const captured = epoch;
    const controller = new AbortController(); pending = controller;
    let stopped = false;
    try {
      readSnapshot(state);
      publish(readyState({ sceneBusy: true }));
      const scenes = await client.scenes(bootstrap.bearer, controller.signal);
      if (!fresh(captured) || current !== state) throw cancelled();
      const sceneId = state.sceneId || scenes.find(row => row.isDefault)?.id
        || (scenes.length === 1 ? scenes[0].id : null);
      if (!scenes.some(row => row.id === sceneId)) throw new Error('Current retained practice could not be verified');
      state.sceneId = sceneId;
      // Closing both ports aborts old requests and prevents further state writes.
      // State writes are synchronous and ACKed before effects are dispatched.
      state.session.close(); stopped = true;
      const snapshot = readSnapshot(state);
      preserveSceneState(state, bootstrap, sceneId, snapshot);
      detach(); ++epoch;
      sceneList = scenes; originalSceneId = sceneId;
      publish({ status: 'choose-scene', scenes, originalSceneId });
    } catch (error) {
      if (fresh(captured)) {
        if (stopped) {
          detach();
          await mount(bootstrap, captured, state.sceneId);
        }
        publish(readyState({ practiceError: error.message || 'Could not list retained practices' }));
      }
      throw error;
    } finally { if (pending === controller) pending = null; }
  }

  async function showPracticeResult(result, captured, signal) {
    if (!practiceAttempt || result.operationId !== practiceAttempt) throw new Error('Saved new practice changed');
    practiceReceipt = result;
    if (result.status !== 'published') {
      if (current) publish(readyState({ practiceWarning: 'The saved new practice remains unresolved. Its status was checked without starting another practice.' }));
      else publish({ status: 'practice-recovery', practice: result });
      return;
    }
    const credential = await bootstrapWithExpiredRenew(signal, captured);
    if (!fresh(captured)) throw cancelled();
    const scenes = await client.scenes(credential.bearer, signal);
    if (!fresh(captured)) throw cancelled();
    if (!scenes.some(row => row.id === result.sceneId && row.isDefault)
      || scenes.filter(row => row.isDefault).length !== 1) {
      throw new Error('Published practice is not the selected owned scene');
    }
    if (current) {
      const state = current;
      readSnapshot(state);
      const previousScenes = await client.scenes(state.credential.bearer, signal);
      if (!fresh(captured) || current !== state) throw cancelled();
      const previousId = state.sceneId || previousScenes.find(row => row.isDefault)?.id
        || (previousScenes.length === 1 ? previousScenes[0].id : null);
      if (!previousScenes.some(row => row.id === previousId)) throw new Error('Current retained practice could not be verified');
      state.session.close(); state.stopped = true;
      const snapshot = readSnapshot(state);
      preserveSceneState(state, state.credential, previousId, snapshot);
    }
    detach();
    bootstrap = credential; sceneList = scenes;
    await mount(credential, captured, result.sceneId);
    if (!fresh(captured)) throw cancelled();
    clearPracticeAttempt(result.operationId);
    publish(readyState());
  }

  async function newPractice() {
    if (!active || !current || !bootstrap || pending || pendingReset || pendingRecovery
      || typeof client.createPractice !== 'function' || !practiceKey) {
      throw new TypeError('Current shop practice without a pending new practice required');
    }
    const state = current, credential = bootstrap, captured = epoch;
    const controller = new AbortController(); pending = controller;
    let stopped = false, saved = false;
    try {
      if (readPracticeAttempt() !== null) throw new Error('Check the saved new practice before starting another');
      readSnapshot(state);
      publish(readyState({ sceneBusy: true }));
      const scenes = await client.scenes(credential.bearer, controller.signal);
      if (!fresh(captured) || current !== state) throw cancelled();
      const sceneId = state.sceneId || scenes.find(row => row.isDefault)?.id
        || (scenes.length === 1 ? scenes[0].id : null);
      if (!scenes.some(row => row.id === sceneId)) throw new Error('Current retained practice could not be verified');
      state.sceneId = sceneId;
      state.session.close(); stopped = true;
      const snapshot = readSnapshot(state);
      preserveSceneState(state, credential, sceneId, snapshot);
      const operationId = globalThis.crypto?.randomUUID?.()?.toLowerCase();
      if (!UUID.test(operationId || '')) throw new Error('New practice identifier unavailable');
      savePracticeAttempt(operationId); saved = true;
      detach();
      publish({ status: 'creating-practice' });
      const result = await client.createPractice(operationId, controller.signal);
      if (!fresh(captured)) throw cancelled();
      await showPracticeResult(result, captured, controller.signal);
    } catch (error) {
      if (fresh(captured)) {
        if (!saved && practiceKey) {
          try {
            const retained = readPracticeAttempt();
            if (retained) { practiceAttempt = retained; saved = true; }
          } catch {
            detach();
            publish({ status: 'error', message: 'Saved new practice storage could not be verified. Reopen OWASP AI SecureShop before starting another practice.' });
            throw error;
          }
        }
        if (saved && !stopped) {
          publish(readyState({ practiceWarning: 'Check the saved new practice before starting another.' }));
        } else if (saved) {
          if (error?.status === 409 && error?.code === 'SHOP_PRACTICE_CAPACITY'
            && error.operationId === practiceAttempt) {
            try { clearPracticeAttempt(practiceAttempt); }
            catch {
              publish({ status: 'practice-recovery', practice: { operationId: practiceAttempt,
                status: 'unconfirmed', sceneId: null, canResume: false },
              message: 'The capacity response was confirmed, but the saved reference could not be cleared. Check the saved new practice before another attempt.' });
              throw error;
            }
            try {
              await mount(credential, captured, state.sceneId);
              publish(readyState({ practiceError: 'Practice capacity is full. Your current practice is unchanged.' }));
            } catch {
              publish({ status: 'error', message: 'Practice capacity is full. Reopen OWASP AI SecureShop to return to a retained practice.' });
            }
          } else publish({ status: 'practice-recovery', practice: practiceReceipt || { operationId: practiceAttempt,
            status: 'unconfirmed', sceneId: null, canResume: false },
            message: error.message || 'New practice outcome is unconfirmed.' });
        } else {
          if (stopped) { detach(); await mount(credential, captured, state.sceneId); }
          publish(readyState({ practiceError: error.message || 'Could not start a new practice' }));
        }
      }
      throw error;
    } finally { if (pending === controller) pending = null; }
  }

  async function checkPractice({ resume = false } = {}) {
    if (!active || !host || pending || !practiceAttempt || typeof client.getPractice !== 'function') {
      throw new TypeError('Saved new practice required');
    }
    const captured = epoch, operationId = practiceAttempt;
    const controller = new AbortController(); pending = controller;
    try {
      publish({ status: 'checking-practice' });
      const result = await client.getPractice(operationId, controller.signal);
      if (!fresh(captured)) throw cancelled();
      if (resume && result.status === 'pending' && result.canResume) {
        if (typeof client.createPractice !== 'function') throw new TypeError('New practice resume unavailable');
        const resumed = await client.createPractice(operationId, controller.signal);
        if (!fresh(captured)) throw cancelled();
        await showPracticeResult(resumed, captured, controller.signal);
      } else await showPracticeResult(result, captured, controller.signal);
    } catch (error) {
      if (fresh(captured)) {
        if (current?.stopped) {
          detach();
          publish({ status: 'practice-recovery', practice: practiceReceipt || { operationId,
            status: 'unconfirmed', sceneId: null, canResume: false },
            message: error.message || 'Saved new practice could not be checked.' });
        } else if (current) publish(readyState({ practiceWarning: 'Saved new practice status is unconfirmed.',
          practiceError: error.message || 'Saved new practice could not be checked.' }));
        else publish({ status: 'practice-recovery', practice: practiceReceipt || { operationId,
          status: 'unconfirmed', sceneId: null, canResume: false },
          message: error.message || 'Saved new practice could not be checked.' });
      }
      throw error;
    } finally { if (pending === controller) pending = null; }
  }

  async function openRetainedPractice() {
    if (!active || !host || !practiceAttempt || pending || current) throw new TypeError('Saved new practice recovery required');
    const captured = epoch;
    const controller = new AbortController(); pending = controller;
    try {
      const credential = await bootstrapWithExpiredRenew(controller.signal, captured);
      if (!fresh(captured)) throw cancelled();
      const scenes = await client.scenes(credential.bearer, controller.signal);
      if (!fresh(captured)) throw cancelled();
      if (!scenes.length) throw new Error('No retained practice is available');
      bootstrap = credential; sceneList = scenes;
      publish({ status: 'choose-scene', scenes,
        message: 'The new practice attempt remains unresolved. Choose a retained practice to continue.' });
    } catch (error) {
      if (fresh(captured)) publish({ status: 'practice-recovery', practice: practiceReceipt || {
        operationId: practiceAttempt, status: 'unconfirmed', sceneId: null, canResume: false },
      message: error?.code === 'LAUNCH_CAPACITY'
        ? 'Shop practice capacity is full. A retained practice cannot open until a valid shop session is available or an instructor resolves retained resources.'
        : error.message || 'Retained practice could not be opened.' });
      throw error;
    } finally { if (pending === controller) pending = null; }
  }

  async function start(target) {
    if (!active || host || !target || typeof target.replaceChildren !== 'function') throw new TypeError('Fresh shop host required');
    host = target;
    const captured = ++epoch;
    const controller = new AbortController(); pending = controller;
    publish({ status: 'connecting' });
    try {
      if (shopRole === 'admin') {
        recovery = await client.getPracticeResetRecovery(controller.signal);
        if (!fresh(captured)) throw cancelled();
        if (recovery && !recovery.cleanupComplete) {
          publish({ status: 'reset-recovery', recovery });
          return;
        }
      }
      practiceAttempt = readPracticeAttempt();
      if (practiceAttempt) {
        const result = await client.getPractice(practiceAttempt, controller.signal);
        if (!fresh(captured)) throw cancelled();
        await showPracticeResult(result, captured, controller.signal);
        return;
      }
      const result = await bootstrapWithExpiredRenew(controller.signal, captured);
      if (!fresh(captured)) throw cancelled();
      const scenes = await client.scenes(result.bearer, controller.signal);
      if (!fresh(captured)) throw cancelled();
      bootstrap = result; sceneList = scenes;
      if (recovery) {
        if (scenes.some(row => row.id === recovery.scene.id)) {
          throw new Error('Retired practice still appears active after reset');
        }
        if (scenes.length) { publish({ status: 'choose-scene', scenes }); return; }
      }
      const defaults = scenes.filter(row => row.isDefault);
      if (defaults.length > 1) throw new Error('Shop practice selection is inconsistent');
      if (scenes.length > 1 && defaults.length === 0) {
        publish({ status: 'choose-scene', scenes }); return;
      }
      try {
        await mount(result, captured);
      } catch (error) {
        // Only an initial document that never received a port may be replaced.
        // Reuse the admitted launch and scene; do not replay API operations.
        if (error?.code !== 'SHOP_FRAME_LOAD_TIMEOUT' || !fresh(captured) || controller.signal.aborted) throw error;
        await mount(result, captured);
      }
    } catch (error) {
      if (fresh(captured)) {
        if (practiceAttempt) publish({ status: 'practice-recovery', practice: practiceReceipt || {
          operationId: practiceAttempt, status: 'unconfirmed', sceneId: null, canResume: false },
        message: error.message || 'Saved new practice could not be checked.' });
        else publish({ status: 'error',
          message: error?.code === 'LAUNCH_CAPACITY'
            ? 'Shop practice capacity is full. Reopen a retained practice from a valid shop session, or ask an instructor to resolve retained resources.'
            : error.message || 'OWASP AI SecureShop unavailable',
          authenticated: error.status !== 401 });
      }
      throw error;
    } finally { if (pending === controller) pending = null; }
  }

  function resumeResetRecovery() {
    if (!active || !host || !recovery) return Promise.reject(cancelled());
    if (pendingRecovery) return pendingRecovery;
    const captured = ++epoch;
    pending?.abort(); detach();
    publish({ status: 'recovering-reset', recovery });
    const controller = new AbortController(); pending = controller;
    pendingRecovery = (async () => {
      try {
        if (!recoveryReceipt) {
          recoveryReceipt = await client.resumePracticeReset(recovery.resetId, controller.signal);
          if (!fresh(captured)) throw cancelled();
        }
        const result = await bootstrapWithExpiredRenew(controller.signal, captured);
        if (!fresh(captured)) throw cancelled();
        const sameLaunch = result.launch.launchId === recovery.launchId;
        if (recoveryReceipt.activated
          ? !sameLaunch || result.launch.generation !== recovery.toGeneration
          : sameLaunch && result.launch.generation <= recovery.toGeneration) {
          throw new Error('Shop recovery did not return a fresh authorized launch');
        }
        const scenes = await client.scenes(result.bearer, controller.signal);
        if (!fresh(captured)) throw cancelled();
        if (scenes.some(row => row.id === recovery.scene.id)) {
          throw new Error('Retired practice still appears active after reset');
        }
        bootstrap = result; sceneList = scenes;
        if (scenes.length) { publish({ status: 'choose-scene', scenes }); return true; }
        await mount(result, captured);
        recovery = null; recoveryReceipt = null;
        return true;
      } catch (error) {
        if (fresh(captured)) publish({ status: 'error', retryRecovery: true,
          recovery, cleanupConfirmed: Boolean(recoveryReceipt), message: error.message || 'Shop reset recovery unavailable' });
        throw error;
      } finally {
        if (pending === controller) pending = null;
        pendingRecovery = null;
      }
    })();
    return pendingRecovery;
  }

  async function selectScene(sceneId) {
    if (!active || !bootstrap || !sceneList?.some(row => row.id === sceneId) || current || pending) {
      throw new TypeError('Listed shop practice required');
    }
    const captured = ++epoch;
    const controller = new AbortController(); pending = controller;
    publish({ status: 'selecting', scenes: sceneList });
    try {
      await client.selectScene(bootstrap.bearer, sceneId, controller.signal);
      if (!fresh(captured)) throw cancelled();
      await mount(bootstrap, captured, sceneId);
      originalSceneId = null;
      if (resetAttempt?.committed) resetAttempt = null;
      if (recoveryReceipt) { recovery = null; recoveryReceipt = null; }
    } catch (error) {
      if (fresh(captured)) publish({ status: 'choose-scene', scenes: sceneList,
        ...(originalSceneId ? { originalSceneId } : {}),
        message: error.message || 'Could not select shop practice' });
      throw error;
    } finally { if (pending === controller) pending = null; }
  }

  function reset(readiness) {
    if (!active || !host) return Promise.reject(cancelled());
    if (pendingReset) return pendingReset;
    if (!resetAttempt) {
      const launch = current?.credential?.launch;
      if (!launch || readiness?.available !== true || readiness.scope !== 'shared_practice'
        || readiness.launchId !== launch.launchId || readiness.generation !== launch.generation
        || !UUID.test(readiness.scene?.id || '')) {
        return Promise.reject(new Error('Current shared practice reset readiness required'));
      }
      const idempotencyKey = globalThis.crypto?.randomUUID?.();
      if (!UUID.test(idempotencyKey || '')) return Promise.reject(new Error('Secure reset identifier unavailable'));
      resetAttempt = { body: { launchId: launch.launchId, expectedGeneration: launch.generation,
        idempotencyKey: idempotencyKey.toLowerCase(), sceneId: readiness.scene.id,
        confirmation: 'RESET_SHARED_PRACTICE' }, committed: false };
    }
    const attempt = resetAttempt;
    const captured = ++epoch;
    pending?.abort();
    detach();
    publish({ status: 'resetting' });
    const controller = new AbortController(); pending = controller;
    pendingReset = (async () => {
      try {
        if (!attempt.committed) {
          await client.resetPractice(attempt.body, controller.signal);
          if (!fresh(captured)) throw cancelled();
          attempt.committed = true;
        }
        const result = await client.bootstrap(controller.signal);
        if (!fresh(captured)) throw cancelled();
        if (result.launch.launchId !== attempt.body.launchId
          || result.launch.generation !== attempt.body.expectedGeneration + 1) {
          throw new Error('Shop reset recovery did not match the confirmed practice');
        }
        const scenes = await client.scenes(result.bearer, controller.signal);
        if (!fresh(captured)) throw cancelled();
        if (scenes.some(row => row.id === attempt.body.sceneId)) {
          throw new Error('Retired practice still appears active after reset');
        }
        bootstrap = result; sceneList = scenes;
        if (scenes.length) {
          publish({ status: 'choose-scene', scenes });
          return true;
        }
        await mount(result, captured);
        resetAttempt = null;
        return true;
      } catch (error) {
        if (fresh(captured)) publish({ status: 'error', retryReset: true,
          resetCommitted: attempt.committed, message: error.message || 'Shop reset could not be confirmed' });
        throw error;
      } finally {
        if (pending === controller) pending = null;
        pendingReset = null;
      }
    })();
    return pendingReset;
  }

  function close() {
    if (!active) return;
    active = false; epoch++; pending?.abort(); pending = null;
    detach(); bootstrap = null; sceneList = null; resetAttempt = null; passwordResetContext = null;
    recovery = null; recoveryReceipt = null; host = null;
  }
  return Object.freeze({ start, choosePractice, selectScene, newPractice,
    checkPractice, openRetainedPractice, reset, resumeResetRecovery,
    preparePasswordReset, resetPasswordFromParent, savedPasswordResetFromParent,
    getExternalMailReadiness, prepareExternalMail: (operation, verify) => externalMailMutation('prepare', operation, verify),
    confirmExternalMail: (operation, verify) => externalMailMutation('confirm', operation, verify),
    cancelExternalMail: (operation, verify) => externalMailMutation('cancel', operation, verify),
    getExternalMailOperation, close });
}
