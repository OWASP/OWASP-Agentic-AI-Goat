import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useLocation } from 'react-router-dom';
import SecureShopStandaloneBound from './SecureShopStandaloneBound.jsx';
import { GUEST_CART_STORAGE_KEY } from './bridge/guestCartProtocol.mjs';
import { GUEST_CART_IMPORT_REQUEST_KEY } from './guestCartImport.mjs';
import { BOUND_CART_REFRESH_CHANNEL } from './bridge/cartRefresh.mjs';
import { ASSESSMENT_PANEL_CHANNEL } from './bridge/assessmentPanelIntent.mjs';
import { PASSWORD_RESET_PANEL_CHANNEL } from './bridge/passwordResetIntent.mjs';
import { EXTERNAL_MAIL_PANEL_CHANNEL } from './bridge/externalMailIntent.mjs';
import { AUDIT_CSV_CHANNEL } from './bridge/auditCsvExport.mjs';
import { REGISTERED_PASSWORD_RESET_KEY } from './bridge/registeredPasswordResetRecovery.mjs';

const requestId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
const saved = { version: 1, revision: 2, items: [{ productId: 125, quantity: 2 }] };
const expiry = new Date(Date.now() + 30 * 60 * 1000).toISOString();
const launchId = 'c0672486-9095-4433-ae75-2db7c40be0e5';
const sceneId = 'b5647777-c51a-47ad-860a-5d3f1318ba10';

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}</output>;
}

function harness(result, role = 'customer', initialRoute = '/secureshop/cart', confirmReadback = true,
  launchExpiry = expiry, personaExpiry = launchExpiry) {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  sessionStorage.clear();
  sessionStorage.setItem(GUEST_CART_STORAGE_KEY, JSON.stringify(saved));
  const previousUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => requestId });
  let activeFrame;
  let readbackConfirmation = confirmReadback;
  const frameMessages = jest.fn(message => {
    if (message.channel !== BOUND_CART_REFRESH_CHANNEL || message.type !== 'refresh') return;
    queueMicrotask(() => window.dispatchEvent(new MessageEvent('message', {
      source: activeFrame.contentWindow, origin: 'null',
      data: { channel: BOUND_CART_REFRESH_CHANNEL, type: 'readback', nonce: message.nonce,
        requestId: message.requestId, confirmed: readbackConfirmation },
    })));
  });
  const resetMock = jest.fn().mockResolvedValue(true);
  const recoveryMock = jest.fn().mockResolvedValue(true);
  const renewMock = jest.fn();
  const chooseMock = jest.fn();
  const selectMock = jest.fn();
  const newPracticeMock = jest.fn().mockResolvedValue();
  const checkPracticeMock = jest.fn().mockResolvedValue();
  const openRetainedMock = jest.fn().mockResolvedValue();
  const sessionIntent = jest.fn();
  const preparePasswordResetMock = jest.fn(async request => ({
    id: request.targetId || 17, username: 'verified_customer', email: 'verified@example.test',
    credentialVersion: '3', authorityVersion: '5', membershipVersion: '2', resetAvailable: true,
    channel: 'protected_account', identityKind: 'registered_account',
    scopeKey: 'b'.repeat(64), sceneId, request,
  }));
  let publishState;
  let switchGuard;
  const controllerCloses = [];
  let controllerStarts = 0;
  const createController = ({ onState, canSwitchPractice }) => {
    switchGuard = canSwitchPractice;
    const close = jest.fn();
    controllerCloses.push(close);
    return {
    async start(host) {
      controllerStarts++;
      publishState = onState;
      const frame = document.createElement('iframe');
      frame.src = `http://localhost/secureshop-frame.html#${'a'.repeat(64)}`;
      host.replaceChildren(frame);
      activeFrame = frame;
      frame.contentWindow.postMessage = frameMessages;
      onState({ status: 'ready', launch: { launchId, generation: 1, expiresAt: launchExpiry },
        personaExpiresAt: personaExpiry });
    },
    choosePractice: chooseMock, selectScene: selectMock, newPractice: newPracticeMock,
    checkPractice: checkPracticeMock, openRetainedPractice: openRetainedMock,
    reset: resetMock, resumeResetRecovery: recoveryMock, close,
    preparePasswordReset: preparePasswordResetMock,
    getExternalMailReadiness: jest.fn().mockResolvedValue({ version: 1, available: false, reason: 'not_configured' }),
  }; };
  const client = { importCart: jest.fn().mockResolvedValue(result),
    getMode: jest.fn().mockResolvedValue({ mode: 'vuln', revision: '1' }), setMode: jest.fn(),
    getPracticeResetReadiness: jest.fn().mockResolvedValue({ available: true, scope: 'shared_practice',
      launchId, generation: 1, scene: { id: sceneId, label: 'Shared practice A' } }),
    getAssessmentObjectives: jest.fn().mockResolvedValue([{ objectiveId: 'ss_inventory_cross_merchant_stock',
      label: 'Owned stock authorization', enabled: false, qualification: 'native-model', revision: '1' }]),
    setAssessmentObjective: jest.fn(), getAssessments: jest.fn().mockResolvedValue([]),
    retryAssessment: jest.fn(), getResetReadiness: jest.fn().mockResolvedValue({ id: 17,
      username: 'verified_customer', email: 'verified@example.test', credentialVersion: '3',
      authorityVersion: '5', membershipVersion: '2', resetAvailable: true }),
    resetUserPassword: jest.fn(), getPasswordResetStatus: jest.fn(),
    revealPasswordReset: jest.fn(), acknowledgePasswordReset: jest.fn() };
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  const render = async () => act(async () => root.render(<MemoryRouter initialEntries={[initialRoute]}>
    <SecureShopStandaloneBound client={client} user={{ role,
      principalId: '4a792aa0-026b-4e76-9520-17ee0252c9aa' }} onSessionIntent={sessionIntent}
      onRenewNeeded={renewMock}
      createController={createController} />
    <LocationProbe />
  </MemoryRouter>));
  const close = async () => {
    await act(async () => root.unmount()); container.remove(); sessionStorage.clear();
    if (previousUuid) Object.defineProperty(global.crypto, 'randomUUID', previousUuid);
    else delete global.crypto.randomUUID;
  };
  return { client, container, frameMessages, resetMock, recoveryMock, renewMock, chooseMock, selectMock,
    newPracticeMock, checkPracticeMock, openRetainedMock, preparePasswordResetMock, sessionIntent,
    canSwitch: () => switchGuard(),
    controllerStarts: () => controllerStarts,
    controllerCloses,
    emitState: value => publishState(value),
    setReadbackConfirmation: value => { readbackConfirmation = value; },
    getFrame: () => activeFrame, render, close };
}

test('merchant iframe can only open an empty parent-owned external send panel with exact source and nonce', async () => {
  const h = harness(null, 'merchant', '/secureshop/merchant/inbox');
  try {
    await h.render();
    const payload = { channel: EXTERNAL_MAIL_PANEL_CHANNEL, type: 'open', nonce: 'a'.repeat(64) };
    const emit = (data, source = h.getFrame().contentWindow, origin = 'null') => act(async () =>
      window.dispatchEvent(new MessageEvent('message', { source, origin, data })));
    await emit({ ...payload, recipient: 'person@sharklasers.com' });
    expect(h.container.querySelector('[aria-labelledby="external-mail-title"]')).toBeNull();
    await emit(payload, window, 'null');
    await emit(payload, h.getFrame().contentWindow, 'http://localhost');
    await emit({ ...payload, nonce: 'b'.repeat(64) });
    expect(h.container.querySelector('[aria-labelledby="external-mail-title"]')).toBeNull();
    await emit(payload);
    expect(h.container.querySelector('[aria-labelledby="external-mail-title"]')).toBeTruthy();
    expect(h.container.textContent).toContain('not configured');
  } finally { await h.close(); }
});

test('confirmed mode change rebuilds the authenticated frame without clearing saved browser state', async () => {
  const h = harness(null, 'merchant', '/secureshop/merchant/inbox');
  sessionStorage.setItem('v09-retained-reference', JSON.stringify({ scopeKey: 'a'.repeat(64) }));
  h.client.getMode.mockResolvedValueOnce({ mode: 'vuln', revision: '3' })
    .mockResolvedValue({ mode: 'fixed', revision: '4' });
  h.client.setMode.mockResolvedValue({ mode: 'fixed', revision: '4' });
  try {
    await h.render();
    expect(h.controllerStarts()).toBe(1);
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Shop settings').click());
    const fixed = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Fixed');
    await act(async () => fixed.click());
    expect(h.client.setMode).toHaveBeenCalledWith('fixed', '3', expect.any(AbortSignal));
    expect(h.controllerCloses[0]).toHaveBeenCalledTimes(1);
    expect(h.controllerStarts()).toBe(2);
    expect(sessionStorage.getItem('v09-retained-reference'))
      .toBe(JSON.stringify({ scopeKey: 'a'.repeat(64) }));
    expect(h.container.textContent).toContain('Current: Fixed');
  } finally { await h.close(); }
});

test('shop settings starts explicit new practice and recovery offers GET check with conditional same-ID resume', async () => {
  const h = harness({ imported: true, items: [], subtotal: 0 });
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Shop settings').click());
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'New practice').click());
    expect(h.newPracticeMock).toHaveBeenCalledTimes(1);
    await act(async () => h.emitState({ status: 'practice-recovery', practice: {
      operationId: requestId, status: 'pending', sceneId: null, canResume: true } }));
    expect(h.container.textContent).toContain(requestId);
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Check saved new practice').click());
    expect(h.checkPracticeMock).toHaveBeenLastCalledWith({ resume: false });
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Resume same new practice').click());
    expect(h.checkPracticeMock).toHaveBeenLastCalledWith({ resume: true });
    await act(async () => h.emitState({ status: 'practice-recovery', practice: {
      operationId: requestId, status: 'retained_unfinished', sceneId: null, canResume: false } }));
    expect(h.container.textContent).toMatch(/cannot be resumed/);
    expect(h.container.textContent).not.toContain('Resume same new practice');
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Open retained practice').click());
    expect(h.openRetainedMock).toHaveBeenCalledTimes(1);
  } finally { await h.close(); }
});

test('expired recovery cookie requests parent sign-in and keeps saved reference UI', async () => {
  const h = harness({ imported: true, items: [], subtotal: 0 });
  try {
    await h.render();
    h.checkPracticeMock.mockRejectedValueOnce(Object.assign(new Error('expired'), { status: 401 }));
    await act(async () => h.emitState({ status: 'practice-recovery', practice: {
      operationId: requestId, status: 'unconfirmed', sceneId: null, canResume: false } }));
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Check saved new practice').click());
    expect(h.sessionIntent).toHaveBeenCalledWith({ type: 'auth-required' });
    expect(h.container.textContent).toContain(requestId);
  } finally { await h.close(); }
});

test('returning to a backgrounded shop near launch expiry requests one parent renewal', async () => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-10-09T12:00:00.000Z'));
  const nearExpiry = new Date(Date.now() + 2 * 60 * 1000).toISOString();
  const h = harness(null, 'merchant', '/secureshop/merchant/inbox', true, nearExpiry);
  try {
    await h.render();
    expect(h.renewMock).not.toHaveBeenCalled();
    // Advance the clock without running the throttled timeout, as in a suspended tab.
    jest.setSystemTime(new Date(Date.now() + 90 * 1000));
    await act(async () => window.dispatchEvent(new Event('focus')));
    await act(async () => document.dispatchEvent(new Event('visibilitychange')));
    expect(h.renewMock).toHaveBeenCalledTimes(1);
    expect(h.client.importCart).not.toHaveBeenCalled();
    expect(h.resetMock).not.toHaveBeenCalled();
  } finally { await h.close(); jest.useRealTimers(); }
});

test('settings offers retained practice reopening and a return action using only controller-listed IDs', async () => {
  const h = harness(null, 'merchant');
  const retained = [{ id: sceneId, label: 'Original practice', createdAt: expiry, isDefault: true },
    { id: requestId, label: 'Earlier practice', createdAt: expiry, isDefault: false }];
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Shop settings').click());
    const chooser = [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Choose retained practice');
    expect(chooser).toBeTruthy();
    h.chooseMock.mockImplementationOnce(async () => h.emitState({ status: 'choose-scene',
      scenes: retained, originalSceneId: sceneId }));
    await act(async () => chooser.click());
    expect(h.chooseMock).toHaveBeenCalledTimes(1);
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent.includes('Earlier practice')).click());
    expect(h.selectMock).toHaveBeenCalledWith(requestId);
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Return to current practice').click());
    expect(h.selectMock).toHaveBeenLastCalledWith(sceneId);
    expect(h.resetMock).not.toHaveBeenCalled();
    expect(h.renewMock).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('protected reset references prevent practice switching and remain available to original admin recovery', async () => {
  const h = harness(null, 'admin');
  try {
    await h.render();
    expect(h.canSwitch()).toBe(true);
    const bytes = JSON.stringify({ adminPrincipalId: '4a792aa0-026b-4e76-9520-17ee0252c9aa', operationId: requestId });
    sessionStorage.setItem(REGISTERED_PASSWORD_RESET_KEY, bytes);
    expect(h.canSwitch()).toBe(false);
    expect(sessionStorage.getItem(REGISTERED_PASSWORD_RESET_KEY)).toBe(bytes);
    sessionStorage.setItem(REGISTERED_PASSWORD_RESET_KEY, '{');
    expect(h.canSwitch()).toBe(false);
  } finally { await h.close(); }
});

test.each(['saved', 'malformed', 'unreadable'])('parent guest cart import reference blocks practice switching: %s', async kind => {
  const h = harness(null);
  let readSpy;
  try {
    await h.render();
    expect(h.canSwitch()).toBe(true);
    const bytes = kind === 'malformed' ? '{' : JSON.stringify({ requestId, fingerprint: 'saved intent' });
    sessionStorage.setItem(GUEST_CART_IMPORT_REQUEST_KEY, bytes);
    if (kind === 'unreadable') {
      const get = Storage.prototype.getItem;
      readSpy = jest.spyOn(Storage.prototype, 'getItem').mockImplementation(function (key) {
        if (key === GUEST_CART_IMPORT_REQUEST_KEY) throw Error('unavailable');
        return get.call(this, key);
      });
    }
    expect(h.canSwitch()).toBe(false);
    readSpy?.mockRestore();
    expect(sessionStorage.getItem(GUEST_CART_IMPORT_REQUEST_KEY)).toBe(bytes);
    expect(h.client.importCart).not.toHaveBeenCalled();
  } finally { readSpy?.mockRestore(); await h.close(); }
});

test('earlier saved persona expiry triggers renewal even while launch remains current', async () => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-10-09T12:00:00.000Z'));
  const launchExpiry = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  const personaExpiry = new Date(Date.now() + 4 * 60 * 1000).toISOString();
  const h = harness(null, 'merchant', '/secureshop/merchant/inbox', true,
    launchExpiry, personaExpiry);
  try {
    await h.render();
    expect(h.renewMock).not.toHaveBeenCalled();
    // The launch has ample time left; only the persona is near expiry.
    jest.setSystemTime(new Date(Date.now() + 3 * 60 * 1000 + 1000));
    await act(async () => window.dispatchEvent(new Event('focus')));
    expect(h.renewMock).toHaveBeenCalledTimes(1);
    expect(h.frameMessages).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'refresh' }), '*');
  } finally { await h.close(); jest.useRealTimers(); }
});

test('pauses automatic renewal and warns before expiry when this administrator has an unresolved registered reset', async () => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-10-09T12:00:00.000Z'));
  const nearExpiry = new Date(Date.now() + 2 * 60 * 1000).toISOString();
  const h = harness(null, 'admin', '/secureshop/admin', true, nearExpiry);
  sessionStorage.setItem(REGISTERED_PASSWORD_RESET_KEY, JSON.stringify({
    adminPrincipalId: '4a792aa0-026b-4e76-9520-17ee0252c9aa',
    operationId: 'opaque-operation-reference',
  }));
  try {
    await h.render();
    jest.setSystemTime(new Date(Date.now() + 61 * 1000));
    await act(async () => window.dispatchEvent(new Event('focus')));
    expect(h.renewMock).not.toHaveBeenCalled();
    expect(h.container.textContent).toContain('Automatic session renewal is paused');
    expect(h.container.textContent).toContain('access will not be extended automatically');
    const recover = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Open reset recovery');
    expect(recover).toBeTruthy();
    await act(async () => recover.click());
    expect(h.container.textContent).toContain('Shared practice reset');
    sessionStorage.removeItem(REGISTERED_PASSWORD_RESET_KEY);
    await act(async () => window.dispatchEvent(new Event('dvaia-secureshop-registered-password-reset-resolved-v1')));
    expect(h.renewMock).toHaveBeenCalledTimes(1);
    expect(h.container.textContent).not.toContain('Automatic session renewal is paused');
  } finally { await h.close(); jest.useRealTimers(); }
});

test('unreadable reset recovery reference pauses renewal with an uncertainty warning', async () => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-10-09T12:00:00.000Z'));
  const nearExpiry = new Date(Date.now() + 2 * 60 * 1000).toISOString();
  const h = harness(null, 'admin', '/secureshop/admin', true, nearExpiry);
  sessionStorage.setItem(REGISTERED_PASSWORD_RESET_KEY, '{broken');
  try {
    await h.render();
    jest.setSystemTime(new Date(Date.now() + 61 * 1000));
    await act(async () => window.dispatchEvent(new Event('focus')));
    expect(h.renewMock).not.toHaveBeenCalled();
    expect(h.container.textContent).toContain('cannot verify the saved reset reference');
    expect(h.container.textContent).not.toContain('A registered account reset is awaiting recovery');
  } finally { await h.close(); jest.useRealTimers(); }
});

test('saved guest cart imports only after customer confirmation, then refreshes owned cart', async () => {
  const h = harness({ requestId, imported: true, replayed: false,
    items: [{ productId: 125, quantity: 2, name: 'Headphones', price: 99.99 }], subtotal: 199.98 });
  try {
    await h.render();
    expect(h.client.importCart).not.toHaveBeenCalled();
    expect(h.container.innerHTML).toContain('Add saved items');
    const button = [...h.container.querySelectorAll('button')].find(value => value.textContent === 'Add saved items');
    expect(button).toBeTruthy();
    await act(async () => button.click());
    expect(h.client.importCart).toHaveBeenCalledWith(requestId, saved.items);
    expect(sessionStorage.getItem(GUEST_CART_STORAGE_KEY)).toBeNull();
    expect(h.frameMessages).toHaveBeenCalledWith(expect.objectContaining({
      channel: BOUND_CART_REFRESH_CHANNEL, type: 'refresh', nonce: 'a'.repeat(64),
    }), '*');
    expect(h.container.textContent).toContain('Your saved items are in your shop cart.');
  } finally { await h.close(); }
});

test('denied import retains exact guest intent and explains stock issue', async () => {
  const h = harness({ requestId, imported: false, replayed: false,
    issues: [{ productId: 125, code: 'INSUFFICIENT_STOCK', availableQuantity: 1 }] });
  try {
    await h.render();
    const button = [...h.container.querySelectorAll('button')].find(value => value.textContent === 'Add saved items');
    await act(async () => button.click());
    expect(JSON.parse(sessionStorage.getItem(GUEST_CART_STORAGE_KEY))).toEqual(saved);
    expect(h.frameMessages).not.toHaveBeenCalledWith(expect.objectContaining({ channel: BOUND_CART_REFRESH_CHANNEL }), '*');
    expect(h.container.textContent).toContain('only 1 available');
  } finally { await h.close(); }
});

test('merchant persona is never offered customer cart import', async () => {
  const h = harness(null, 'merchant');
  try {
    await h.render();
    expect(h.container.textContent).not.toContain('Add saved items');
    expect(h.client.importCart).not.toHaveBeenCalled();
    expect(JSON.parse(sessionStorage.getItem(GUEST_CART_STORAGE_KEY))).toEqual(saved);
  } finally { await h.close(); }
});

test('shop settings opens the standalone mode control without a reset action', async () => {
  const h = harness(null, 'merchant');
  try {
    await h.render();
    const settings = [...h.container.querySelectorAll('button')].find(value => value.textContent === 'Shop settings');
    expect(settings?.getAttribute('aria-expanded')).toBe('false');
    await act(async () => settings.click());
    expect(settings.getAttribute('aria-expanded')).toBe('true');
    expect(h.client.getMode).toHaveBeenCalledTimes(1);
    expect(h.container.textContent).toContain('Current: Vulnerable');
    expect(h.container.textContent).not.toContain('Reset shop');
    expect(h.container.textContent).not.toContain('Assessment objectives');
    expect(h.client.getAssessmentObjectives).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('protected shop admin confirms the named shared practice before one reset', async () => {
  const h = harness(null, 'admin');
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Shop settings').click());
    expect(h.client.getPracticeResetReadiness).toHaveBeenCalledTimes(1);
    const resetButton = [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Reset shared practice');
    expect(resetButton).toBeTruthy();
    await act(async () => resetButton.click());
    const dialog = h.container.querySelector('[role="alertdialog"]');
    expect(dialog.textContent).toContain('Shared practice A');
    expect(dialog.textContent).toContain('every customer and merchant sharing');
    expect(h.resetMock).not.toHaveBeenCalled();
    await act(async () => [...dialog.querySelectorAll('button')]
      .find(button => button.textContent === 'Confirm shared reset').click());
    expect(h.resetMock).toHaveBeenCalledTimes(1);
    expect(h.resetMock).toHaveBeenCalledWith(expect.objectContaining({ scene: {
      id: sceneId, label: 'Shared practice A' }, launchId, generation: 1 }));
  } finally { await h.close(); }
});

test('merchant cannot read protected reset readiness or open reset confirmation', async () => {
  const h = harness(null, 'merchant');
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Shop settings').click());
    expect(h.client.getPracticeResetReadiness).not.toHaveBeenCalled();
    expect(h.container.querySelector('[role="alertdialog"]')).toBeNull();
    expect(h.container.textContent).not.toContain('Reset shared practice');
  } finally { await h.close(); }
});

test('unavailable protected reset cannot open a confirmation or send a mutation', async () => {
  const h = harness(null, 'admin');
  h.client.getPracticeResetReadiness.mockResolvedValue({ available: false, scope: 'shared_practice',
    launchId, generation: 1, scene: { id: sceneId, label: 'Shared practice A' } });
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Shop settings').click());
    expect(h.container.textContent).toContain('Reset is unavailable for this practice.');
    expect(h.container.textContent).not.toContain('Confirm shared reset');
    expect(h.resetMock).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('uncertain reset keeps named readiness and offers the same-operation retry', async () => {
  const h = harness(null, 'admin');
  h.resetMock.mockRejectedValueOnce(new Error('Reset response unavailable'));
  try {
    await h.render();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Shop settings').click());
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Reset shared practice').click());
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Confirm shared reset').click());
    await act(async () => h.emitState({ status: 'error', retryReset: true,
      resetCommitted: false, message: 'Reset response unavailable' }));
    expect(h.container.querySelector('[role="alertdialog"]').textContent).toContain('Shared practice A');
    expect(h.container.textContent).toContain('previous reset outcome is uncertain');
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Retry same reset').click());
    expect(h.resetMock).toHaveBeenCalledTimes(2);
    expect(h.resetMock.mock.calls[1][0]).toEqual(h.resetMock.mock.calls[0][0]);
  } finally { await h.close(); }
});

test('protected admin recovery requires an explicit parent action for the saved reset', async () => {
  const h = harness(null, 'admin');
  try {
    await h.render();
    await act(async () => h.emitState({ status: 'reset-recovery', recovery: {
      resetId: requestId, launchId, fromGeneration: 1, toGeneration: 2,
      status: 'fenced', cleanupComplete: false, sameExecution: false,
      scene: { id: sceneId, label: 'Shop practice' },
    } }));
    expect(h.container.textContent).toContain('Finish a saved practice reset.');
    expect(h.container.textContent).toContain('Shop practice');
    expect(h.container.textContent).toContain('cannot reopen the old session');
    expect(h.recoveryMock).not.toHaveBeenCalled();
    await act(async () => [...h.container.querySelectorAll('button')]
      .find(button => button.textContent === 'Read and resume saved reset').click());
    expect(h.recoveryMock).toHaveBeenCalledTimes(1);
    expect(h.resetMock).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('non-admin cannot invoke protected reset recovery from a controller state', async () => {
  const h = harness(null, 'customer');
  try {
    await h.render();
    await act(async () => h.emitState({ status: 'reset-recovery', recovery: {
      resetId: requestId, launchId, fromGeneration: 1, toGeneration: 2,
      status: 'fenced', cleanupComplete: false, sameExecution: false,
      scene: { id: sceneId, label: 'Shop practice' },
    } }));
    expect(h.container.textContent).toContain('requires a shop administrator');
    expect(h.container.textContent).not.toContain('Read and resume saved reset');
    expect(h.recoveryMock).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('shop administrator sees protected objective controls in existing settings only', async () => {
  const h = harness(null, 'admin');
  try {
    await h.render();
    expect(h.client.getAssessmentObjectives).not.toHaveBeenCalled();
    const settings = [...h.container.querySelectorAll('button')].find(value => value.textContent === 'Shop settings');
    await act(async () => settings.click());
    expect(h.client.getAssessmentObjectives).toHaveBeenCalledTimes(1);
    expect(h.container.textContent).toContain('Assessment objectives');
    expect(h.container.textContent).toContain('Owned stock authorization');
  } finally { await h.close(); }
});

test('current opaque frame can open trusted saved assessments but cannot dispatch a retry', async () => {
  const h = harness(null, 'customer');
  const evaluationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  try {
    await h.render();
    const payload = { channel: ASSESSMENT_PANEL_CHANNEL, type: 'open', nonce: 'a'.repeat(64), evaluationId };
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'http://other.example', data: payload,
    })));
    expect(h.client.getAssessments).not.toHaveBeenCalled();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null', data: payload,
    })));
    expect(h.client.getAssessments).toHaveBeenCalledTimes(1);
    expect(h.container.textContent).toContain('Saved assessments');
    expect(h.client.retryAssessment).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('only the active standalone admin audit frame can request a bounded parent CSV download', async () => {
  const h = harness(null, 'admin', '/secureshop/admin/audit');
  const createObjectURL = URL.createObjectURL;
  const revokeObjectURL = URL.revokeObjectURL;
  const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  URL.createObjectURL = jest.fn(() => 'blob:audit-page');
  URL.revokeObjectURL = jest.fn();
  const payload = { channel: AUDIT_CSV_CHANNEL, type: 'export', nonce: 'a'.repeat(64),
    requestId: 'b'.repeat(32), rows: [{ id: 'agents:1', ts: '2026-10-10T00:00:00Z', actor: 'admin',
      action: 'read', target: 'user:1', params_json: '{}', ip: null, user_agent: null }] };
  try {
    await h.render();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'https://other.example', data: payload,
    })));
    expect(click).not.toHaveBeenCalled();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null', data: payload,
    })));
    expect(click).toHaveBeenCalledTimes(1);
    expect(h.frameMessages).toHaveBeenCalledWith(expect.objectContaining({ channel: AUDIT_CSV_CHANNEL,
      type: 'result', requestId: payload.requestId, ok: true }), '*');
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null', data: payload,
    })));
    expect(click).toHaveBeenCalledTimes(1);
  } finally {
    await h.close(); click.mockRestore(); URL.createObjectURL = createObjectURL; URL.revokeObjectURL = revokeObjectURL;
  }
});

test('only current opaque admin frame may suggest reset target, and parent must confirm', async () => {
  const h = harness(null, 'admin');
  try {
    await h.render();
    const payload = { channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open', nonce: 'a'.repeat(64), targetId: 17 };
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'https://other.example', data: payload,
    })));
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: window, origin: 'null', data: payload,
    })));
    expect(h.preparePasswordResetMock).not.toHaveBeenCalled();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null', data: payload,
    })));
    expect(h.preparePasswordResetMock).toHaveBeenCalledWith(
      { kind: 'registered_manual', targetId: 17 }, expect.any(AbortSignal));
    expect(h.container.textContent).toContain('verified_customer');
    expect(h.client.resetUserPassword).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('customer frame cannot open protected admin reset panel', async () => {
  const h = harness(null, 'customer');
  try {
    await h.render();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null',
      data: { channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open', nonce: 'a'.repeat(64), targetId: 17 },
    })));
    expect(h.preparePasswordResetMock).not.toHaveBeenCalled();
    expect(h.container.textContent).not.toContain('Password reset');
  } finally { await h.close(); }
});

test('only current opaque admin frame can open a saved chat reset handoff', async () => {
  const h = harness(null, 'admin');
  const payload = { channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open-chat', nonce: 'a'.repeat(64),
    sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    choiceId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  try {
    await h.render();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null', data: { ...payload,
        nonce: 'f'.repeat(64) },
    })));
    expect(h.preparePasswordResetMock).not.toHaveBeenCalled();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null', data: payload,
    })));
    expect(h.preparePasswordResetMock).toHaveBeenCalledWith({ kind: 'chat',
      sessionId: payload.sessionId, requestId: payload.requestId, choiceId: payload.choiceId },
    expect.any(AbortSignal));
    expect(h.client.getResetReadiness).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('uncertain response retains intent and retries the same request ID', async () => {
  const receipt = { requestId, imported: true, replayed: true,
    items: [{ productId: 125, quantity: 2, name: 'Headphones', price: 99.99 }], subtotal: 199.98 };
  const h = harness(receipt);
  h.client.importCart.mockRejectedValueOnce(new Error('Shop service unavailable'));
  try {
    await h.render();
    const button = [...h.container.querySelectorAll('button')].find(value => value.textContent === 'Add saved items');
    await act(async () => button.click());
    expect(JSON.parse(sessionStorage.getItem(GUEST_CART_STORAGE_KEY))).toEqual(saved);
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('Shop service unavailable');
    await act(async () => button.click());
    expect(h.client.importCart.mock.calls).toEqual([[requestId, saved.items], [requestId, saved.items]]);
    expect(sessionStorage.getItem(GUEST_CART_STORAGE_KEY)).toBeNull();
  } finally { await h.close(); }
});

test('checkout intent resumes only after saved-cart receipt and bound cart readback', async () => {
  const h = harness({ requestId, imported: true, replayed: false,
    items: [{ productId: 125, quantity: 2, name: 'Headphones', price: 99.99 }], subtotal: 199.98 },
  'customer', '/secureshop/checkout');
  try {
    await h.render();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null',
      data: { channel: 'dvaia-secureshop-bound-route-v1', type: 'route',
        nonce: 'a'.repeat(64), route: '/secureshop/cart' },
    })));
    expect(h.container.querySelector('[data-testid="location"]')?.textContent).toBe('/secureshop/cart');
    expect(h.client.importCart).not.toHaveBeenCalled();
    const button = [...h.container.querySelectorAll('button')].find(value => value.textContent === 'Add saved items');
    await act(async () => button.click());
    expect(h.container.querySelector('[data-testid="location"]')?.textContent).toBe('/secureshop/checkout');
    expect(sessionStorage.getItem(GUEST_CART_STORAGE_KEY)).toBeNull();
  } finally { await h.close(); }
});

test('failed cart readback retains both guest references and retries the same import before checkout', async () => {
  const receipt = { requestId, imported: true, replayed: false,
    items: [{ productId: 125, quantity: 2, name: 'Headphones', price: 99.99 }], subtotal: 199.98 };
  const h = harness(receipt, 'customer', '/secureshop/checkout', false);
  h.client.importCart.mockResolvedValueOnce(receipt)
    .mockResolvedValueOnce({ ...receipt, replayed: true });
  try {
    await h.render();
    await act(async () => window.dispatchEvent(new MessageEvent('message', {
      source: h.getFrame().contentWindow, origin: 'null',
      data: { channel: 'dvaia-secureshop-bound-route-v1', type: 'route',
        nonce: 'a'.repeat(64), route: '/secureshop/cart' },
    })));
    const button = [...h.container.querySelectorAll('button')].find(value => value.textContent === 'Add saved items');
    await act(async () => button.click());
    expect(h.container.querySelector('[data-testid="location"]')?.textContent).toBe('/secureshop/cart');
    expect(JSON.parse(sessionStorage.getItem(GUEST_CART_STORAGE_KEY))).toEqual(saved);
    expect(JSON.parse(sessionStorage.getItem(GUEST_CART_IMPORT_REQUEST_KEY))).toEqual({
      fingerprint: JSON.stringify([saved.revision, saved.items]), requestId,
    });
    expect(h.container.querySelector('[role="alert"]')?.textContent).toContain('cart could not confirm');
    h.setReadbackConfirmation(true);
    await act(async () => button.click());
    expect(h.client.importCart.mock.calls).toEqual([[requestId, saved.items], [requestId, saved.items]]);
    expect(sessionStorage.getItem(GUEST_CART_STORAGE_KEY)).toBeNull();
    expect(sessionStorage.getItem(GUEST_CART_IMPORT_REQUEST_KEY)).toBeNull();
    expect(h.container.querySelector('[data-testid="location"]')?.textContent).toBe('/secureshop/checkout');
  } finally { await h.close(); }
});
