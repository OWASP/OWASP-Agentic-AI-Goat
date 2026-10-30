import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Panel from './SecureShopStandalonePasswordReset.jsx';

const principalId = '4a792aa0-026b-4e76-9520-17ee0252c9aa';
const operationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
const target = { id: 17, username: 'shop_customer', email: 'customer@example.test',
  credentialVersion: '3', authorityVersion: '5', membershipVersion: '2', resetAvailable: true };
const receipt = { operationId, targetId: 17, credentialVersion: '4', authorityVersion: '6',
  receiptSha256: 'a'.repeat(64), expiresAt: new Date(Date.now() + 600000).toISOString() };
const storageKey = 'owasp-ai-goat.secureshop.admin-password-reset.v1';
const user = { role: 'admin', principalId };

function setup(overrides = {}, targetId = 17, storage) {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  sessionStorage.clear();
  const previousUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => operationId });
  const client = { getResetReadiness: jest.fn().mockResolvedValue(target),
    resetUserPassword: jest.fn().mockResolvedValue({ ok: true, receipt, secretAvailable: true, replayed: false }),
    getPasswordResetStatus: jest.fn().mockResolvedValue({ ok: true, receipt, secretAvailable: true }),
    revealPasswordReset: jest.fn().mockResolvedValue({ ok: true, receipt,
      temporaryPassword: 'private-only-temporary-password-123' }),
    acknowledgePasswordReset: jest.fn().mockResolvedValue({ ok: true, receipt, secretAvailable: false }),
    ...overrides };
  const onClose = jest.fn();
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  const render = async id => act(async () => root.render(<Panel client={client} user={user}
    targetId={id} onClose={onClose} storage={storage} />));
  const click = async label => {
    const button = [...container.querySelectorAll('button')].find(value => value.textContent === label);
    expect(button).toBeTruthy();
    await act(async () => button.click());
  };
  const close = async () => {
    await act(async () => root.unmount()); container.remove(); sessionStorage.clear();
    if (previousUuid) Object.defineProperty(global.crypto, 'randomUUID', previousUuid);
    else delete global.crypto.randomUUID;
  };
  return { client, container, onClose, render, click, close, targetId };
}

test('protected readiness shows server identity, then explicit single reset and parent-only reveal', async () => {
  const h = setup();
  try {
    await h.render(17);
    expect(h.client.getResetReadiness).toHaveBeenCalledWith(17, expect.any(AbortSignal));
    expect(h.container.textContent).toContain('shop_customer');
    expect(h.container.textContent).toContain('customer@example.test');
    expect(h.client.resetUserPassword).not.toHaveBeenCalled();
    const confirm = [...h.container.querySelectorAll('button')].find(button => button.textContent === 'Confirm password reset');
    await act(async () => { confirm.click(); confirm.click(); });
    expect(h.client.resetUserPassword).toHaveBeenCalledTimes(1);
    expect(h.client.resetUserPassword).toHaveBeenCalledWith(17, expect.objectContaining({
      operationId, expectedCredentialVersion: '3', expectedAuthorityVersion: '5',
      expectedMembershipVersion: '2',
    }));
    expect(sessionStorage.getItem(storageKey)).not.toContain('temporaryPassword');
    await h.click('Reveal temporary password');
    expect(h.container.querySelector('output[aria-label="Temporary password"]')?.textContent)
      .toBe('private-only-temporary-password-123');
    expect(sessionStorage.getItem(storageKey)).not.toContain('private-only-temporary-password-123');
    await h.click('Acknowledge and clear password');
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(h.container.querySelector('output[aria-label="Temporary password"]')).toBeNull();
  } finally { await h.close(); }
});

test('uncertain reset keeps metadata and restores status without repeating mutation', async () => {
  const h = setup({ resetUserPassword: jest.fn().mockRejectedValue(new Error('Shop service unavailable')) });
  try {
    await h.render(17);
    await h.click('Confirm password reset');
    expect(h.container.textContent).toContain('Shop service unavailable');
    const saved = JSON.parse(sessionStorage.getItem(storageKey));
    expect(saved).toEqual({ adminPrincipalId: principalId, targetId: 17, operationId,
      expectedCredentialVersion: '3', expectedAuthorityVersion: '5', expectedMembershipVersion: '2' });
    await h.click('Read reset status');
    expect(h.client.getPasswordResetStatus).toHaveBeenCalledWith(17, operationId);
    expect(h.client.resetUserPassword).toHaveBeenCalledTimes(1);
    expect(h.container.textContent).toContain('Reset receipt confirmed');
  } finally { await h.close(); }
});

test('foreign saved reference blocks new reset until explicitly dismissed', async () => {
  const h = setup();
  try {
    sessionStorage.setItem(storageKey, JSON.stringify({ adminPrincipalId: '8a792aa0-026b-4e76-9520-17ee0252c9aa',
      targetId: 17, operationId, expectedCredentialVersion: '3', expectedAuthorityVersion: '5',
      expectedMembershipVersion: '2' }));
    await h.render(17);
    expect(h.container.textContent).toContain('another administrator');
    expect(h.client.getResetReadiness).not.toHaveBeenCalled();
    expect(h.client.resetUserPassword).not.toHaveBeenCalled();
    await h.click('Dismiss local reference');
    expect(sessionStorage.getItem(storageKey)).toBeNull();
    expect(h.onClose).toHaveBeenCalledTimes(1);
  } finally { await h.close(); }
});

test('blocked storage read shows bounded unavailable state and sends no reset', async () => {
  const blocked = { getItem: () => { throw new DOMException('private storage denied', 'SecurityError'); },
    setItem: jest.fn(), removeItem: jest.fn() };
  const h = setup({}, 17, blocked);
  try {
    await h.render(17);
    expect(h.container.querySelector('[role="alert"]')?.textContent)
      .toContain('Recovery storage is unavailable');
    expect(h.container.textContent).not.toContain('private storage denied');
    expect(h.container.textContent).not.toContain('Dismiss local reference');
    expect(h.client.getResetReadiness).not.toHaveBeenCalled();
    expect(h.client.resetUserPassword).not.toHaveBeenCalled();
    expect(blocked.setItem).not.toHaveBeenCalled();
  } finally { await h.close(); }
});

test('throwing default sessionStorage getter does not crash parent panel', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const descriptor = Object.getOwnPropertyDescriptor(window, 'sessionStorage');
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  const client = { getResetReadiness: jest.fn(), resetUserPassword: jest.fn() };
  try {
    Object.defineProperty(window, 'sessionStorage', { configurable: true,
      get: () => { throw new DOMException('access denied', 'SecurityError'); } });
    await act(async () => root.render(<Panel client={client} user={user} targetId={17} onClose={() => {}} />));
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Recovery storage is unavailable');
    expect(client.getResetReadiness).not.toHaveBeenCalled();
    expect(client.resetUserPassword).not.toHaveBeenCalled();
  } finally {
    await act(async () => root.unmount()); container.remove();
    if (descriptor) Object.defineProperty(window, 'sessionStorage', descriptor);
  }
});

test('teaching parent reset saves opaque reference, then recovers by exact GET without repeat POST', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  sessionStorage.clear();
  const oldUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => operationId });
  const request = { kind: 'teaching_manual', targetId: 17 };
  const readiness = { ...target, channel: 'bound_persona', identityKind: 'teaching_persona',
    membershipVersion: undefined, scopeKey: 'b'.repeat(64),
    sceneId: 'b5647777-c51a-47ad-860a-5d3f1318ba10', request };
  const controller = { preparePasswordReset: jest.fn().mockResolvedValue(readiness),
    resetPasswordFromParent: jest.fn().mockRejectedValue(new Error('Reset response lost')),
    savedPasswordResetFromParent: jest.fn().mockResolvedValue({ ok: true, receipt, secretAvailable: true }) };
  const client = { resetUserPassword: jest.fn(), getResetReadiness: jest.fn() };
  const container = document.createElement('div'); document.body.appendChild(container);
  let root = createRoot(container);
  const render = async props => act(async () => root.render(<Panel client={client} user={user}
    controller={controller} storage={sessionStorage} onClose={() => {}} {...props} />));
  const click = async label => act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent === label).click());
  try {
    await render({ request });
    expect(container.textContent).toContain('teaching persona');
    await click('Confirm password reset');
    const saved = JSON.parse(sessionStorage.getItem(storageKey));
    expect(saved).toEqual({ version: 2, adminPrincipalId: principalId,
      scopeKey: readiness.scopeKey, sceneId: readiness.sceneId, channel: 'bound_persona',
      source: request, targetId: 17, operationId, expectedCredentialVersion: '3',
      expectedAuthorityVersion: '5', expectedMembershipVersion: null });
    expect(controller.resetPasswordFromParent).toHaveBeenCalledWith(saved, undefined, expect.any(Function));
    expect(client.resetUserPassword).not.toHaveBeenCalled();
    await act(async () => root.unmount());
    root = createRoot(container);
    await render({ request: null });
    expect(container.textContent).toContain('Saved reset for user #17');
    await click('Read reset status');
    expect(controller.savedPasswordResetFromParent).toHaveBeenCalledWith(saved, 'read');
    expect(controller.resetPasswordFromParent).toHaveBeenCalledTimes(1);
    expect(sessionStorage.getItem(storageKey)).toBe(JSON.stringify(saved));
  } finally {
    await act(async () => root.unmount()); container.remove(); sessionStorage.clear();
    if (oldUuid) Object.defineProperty(global.crypto, 'randomUUID', oldUuid);
    else delete global.crypto.randomUUID;
  }
});

test('late reveal never displays a secret after the exact saved reference is replaced', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  sessionStorage.clear();
  const saved = { adminPrincipalId: principalId, targetId: 17, operationId,
    expectedCredentialVersion: '3', expectedAuthorityVersion: '5', expectedMembershipVersion: '2' };
  sessionStorage.setItem(storageKey, JSON.stringify(saved));
  let resolveReveal;
  const client = { getPasswordResetStatus: jest.fn().mockResolvedValue({ ok: true, receipt,
      secretAvailable: true }), revealPasswordReset: jest.fn(() => new Promise(resolve => { resolveReveal = resolve; })) };
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Panel client={client} user={user} storage={sessionStorage}
      onClose={() => {}} />));
    await act(async () => [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Read reset status').click());
    await act(async () => [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Reveal temporary password').click());
    expect(resolveReveal).toEqual(expect.any(Function));
    const replacement = { ...saved, operationId: '8f078c35-0bda-4bb4-9c9f-819807aa2668' };
    sessionStorage.setItem(storageKey, JSON.stringify(replacement));
    await act(async () => resolveReveal({ ok: true, receipt,
      temporaryPassword: 'private-only-temporary-password-123' }));
    expect(container.querySelector('output[aria-label="Temporary password"]')).toBeNull();
    expect(container.textContent).toContain('Saved reset reference changed');
    expect(sessionStorage.getItem(storageKey)).toBe(JSON.stringify(replacement));
  } finally { await act(async () => root.unmount()); container.remove(); sessionStorage.clear(); }
});
