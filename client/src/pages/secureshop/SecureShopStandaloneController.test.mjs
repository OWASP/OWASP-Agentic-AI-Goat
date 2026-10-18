import { createSecureShopStandaloneController, compileStandaloneFrameOperation } from './SecureShopStandaloneController.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_REVIEW_DECISION_KEY,
  SHOP_LISTINGS_KEY, SHOP_MAIL_KEY, SHOP_REFUND_KEY, SHOP_CUSTOMER_CHAT_KEY,
  SHOP_CUSTOMER_CHAT_COMPLETED_KEY,
  SHOP_ROLE_ASSISTANT_KEY, SHOP_ROLE_ASSISTANT_COMPLETED_KEY,
  SHOP_REGISTERED_ADMIN_CHAT_KEY, SHOP_REGISTERED_ADMIN_COMPLETED_KEY,
  SHOP_CHAT_CART_KEY } from './utils/shopStorage.mjs';
import { decodeListingsReferences, replaceListingsScope } from './pages/merchant/listingsReferences.mjs';

const savedScope = 'dvaia:secureshop:c0672486-9095-4433-ae75-2db7c40be0e5:1';
const cleanSnapshot = () => ({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: '[{"id":125,"quantity":2}]' });

const expiry = new Date(Date.now() + 30 * 60 * 1000).toISOString();
const credential = { launch: { launchId: 'c0672486-9095-4433-ae75-2db7c40be0e5',
  generation: 1, credentialVersion: 1, expiresAt: expiry }, bearer: 'a'.repeat(43),
persona: { token: 'signed.persona.token', expiresAt: expiry, user: { id: 7, role: 'customer' } } };
const scenes = [
  { id: 'b5647777-c51a-47ad-860a-5d3f1318ba10', label: 'Shop practice 1', createdAt: expiry, isDefault: false },
  { id: '2abec5ad-1c0f-4384-963d-6fbd81f00eea', label: 'Shop practice 2', createdAt: expiry, isDefault: false },
];

function harness(list, shopRole = 'customer', options = {}) {
  const client = { bootstrap: jest.fn().mockResolvedValue(credential), scenes: jest.fn().mockResolvedValue(list),
    createPractice: jest.fn(), getPractice: jest.fn(),
    renew: jest.fn().mockResolvedValue({ user: { id: 7, role: 'customer' }, expiresAt: expiry }),
    selectScene: jest.fn().mockResolvedValue({ id: scenes[1].id, isDefault: true }),
    resetPractice: jest.fn().mockResolvedValue({ resetId: '11111111-1111-4111-8111-111111111111',
      status: 'committed', cleanupComplete: true }),
    getPracticeResetRecovery: jest.fn().mockResolvedValue(null),
    resumePracticeReset: jest.fn() };
  const mountFrame = jest.fn(({ frame, url }) => { frame.src = url; return { ready: Promise.resolve(), close: jest.fn() }; });
  const createStateStore = jest.fn(() => ({ close: jest.fn(), read: jest.fn(), replace: jest.fn() }));
  const states = [];
  const host = document.createElement('div'); document.body.appendChild(host);
  const controller = createSecureShopStandaloneController({ client, documentRef: document,
    origin: 'http://localhost', storage: localStorage, shopRole, initialRoute: '/secureshop/product/125',
    mountFrame, createStateStore, onState: value => states.push(value), ...options });
  return { client, mountFrame, createStateStore, states, host, controller,
    close() { controller.close(); host.remove(); } };
}

const practiceOperationId = '33333333-3333-4333-8333-333333333333';
const principalId = '4a792aa0-026b-4e76-9520-17ee0252c9aa';
const practiceRefKey = `dvaia:secureshop:practice-admission:v1:${principalId}`;

test('standalone child bridge rejects every teaching reset and reveal operation before transport', async () => {
  for (const name of ['admin.users.resetPassword', 'admin.users.resetRead',
    'admin.users.resetReveal', 'admin.users.resetAcknowledge']) {
    expect(() => compileStandaloneFrameOperation(name, { params: { id: 7 }, body: {} }))
      .toThrow('trusted shop panel');
  }
  expect(compileStandaloneFrameOperation('admin.users.list', {})).toMatchObject({
    path: '/api/secureshop/admin/users', method: 'GET' });
  const h = harness([{ ...scenes[0], isDefault: true }], 'admin', { principalId });
  try {
    await h.controller.start(h.host);
    const compile = h.mountFrame.mock.calls[0][0].compileOperation;
    for (const name of ['admin.users.resetPassword', 'admin.users.resetRead',
      'admin.users.resetReveal', 'admin.users.resetAcknowledge']) {
      expect(() => compile(name, { params: { id: 7 }, body: {} })).toThrow('trusted shop panel');
    }
  } finally { h.close(); }
});

test('parent privately rechecks saved chat handoff and fences reset dispatch and late reveal', async () => {
  const scopeKey = JSON.stringify([credential.launch.launchId, 1, 'admin', 'scope', 7,
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']);
  const adminCredential = { ...credential, persona: { ...credential.persona,
    user: { ...credential.persona.user, role: 'admin' } } };
  const source = { kind: 'chat', sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    choiceId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  const h = harness([{ ...scenes[0], isDefault: true }], 'admin', { principalId });
  h.client.bootstrap.mockResolvedValue(adminCredential);
  h.client.getBoundAdminScope = jest.fn().mockResolvedValue(scopeKey);
  h.client.getBoundPasswordResetSetup = jest.fn().mockResolvedValue({ status: 'completed',
    replayed: true, stopReason: 'end_turn', sessionId: source.sessionId, requestId: source.requestId,
    passwordResetSetup: { version: 1, kind: 'password_reset_setup',
      sessionId: source.sessionId, requestId: source.requestId, choiceId: source.choiceId,
      userId: 17, username: 'verified_customer', identityKind: 'teaching_persona',
      channel: 'bound_persona', scopeKey } });
  h.client.getTeachingResetReadiness = jest.fn().mockResolvedValue({ id: 17,
    username: 'verified_customer', email: 'verified@example.test', resetAvailable: true,
    channel: 'bound_persona', credentialVersion: '3', authorityVersion: '5' });
  h.client.resetTeachingPassword = jest.fn().mockResolvedValue({ ok: true });
  h.client.revealTeachingReset = jest.fn();
  try {
    await h.controller.start(h.host);
    const ready = await h.controller.preparePasswordReset(source);
    expect(ready).toMatchObject({ id: 17, scopeKey, channel: 'bound_persona', sceneId: scenes[0].id });
    expect(h.client.getBoundPasswordResetSetup).toHaveBeenCalledWith(adminCredential.bearer,
      adminCredential.persona.token, source.sessionId, source.requestId, undefined);
    const operation = { version: 2, adminPrincipalId: principalId, targetId: 17,
      operationId: practiceOperationId, expectedCredentialVersion: '3',
      expectedAuthorityVersion: '5', expectedMembershipVersion: null,
      scopeKey, sceneId: scenes[0].id, channel: 'bound_persona', source };
    let confirmScope;
    let savedReference = JSON.stringify(operation);
    h.client.getBoundAdminScope.mockImplementationOnce(() => new Promise(resolve => { confirmScope = resolve; }));
    const blocked = h.controller.resetPasswordFromParent(operation, undefined,
      () => savedReference === JSON.stringify(operation));
    savedReference = null;
    confirmScope(scopeKey);
    await expect(blocked).rejects.toThrow('Saved reset reference changed');
    expect(h.client.resetTeachingPassword).not.toHaveBeenCalled();
    savedReference = JSON.stringify(operation);
    h.client.getBoundAdminScope.mockImplementationOnce(() => new Promise(resolve => { confirmScope = resolve; }));
    const replaced = h.controller.resetPasswordFromParent(operation, undefined,
      () => savedReference === JSON.stringify(operation));
    savedReference = JSON.stringify({ ...operation,
      operationId: '99999999-9999-4999-8999-999999999999' });
    confirmScope(scopeKey);
    await expect(replaced).rejects.toThrow('Saved reset reference changed');
    expect(h.client.resetTeachingPassword).not.toHaveBeenCalled();
    await expect(h.controller.resetPasswordFromParent(operation, undefined, () => true)).resolves.toEqual({ ok: true });
    expect(h.client.resetTeachingPassword).toHaveBeenCalledTimes(1);
    let completeReveal;
    h.client.revealTeachingReset.mockImplementationOnce(() => new Promise(resolve => { completeReveal = resolve; }));
    const late = h.controller.savedPasswordResetFromParent(operation, 'reveal');
    for (let attempt = 0; attempt < 5 && !completeReveal; attempt++) await Promise.resolve();
    expect(completeReveal).toEqual(expect.any(Function));
    h.close();
    completeReveal({ ok: true, temporaryPassword: 'secret-never-returned' });
    await expect(late).rejects.toThrow('Administrator scope changed');
  } finally { h.close(); }
});

test('new practice saves exact parent reference before POST and clears it only after owned published scene opens', async () => {
  localStorage.clear();
  const originalUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => practiceOperationId });
  const list = [{ ...scenes[0], isDefault: true }, scenes[1]];
  const h = harness(list, 'customer', { principalId });
  h.client.scenes.mockResolvedValueOnce(list).mockResolvedValueOnce(list)
    .mockResolvedValueOnce([scenes[0], { ...scenes[1], isDefault: true }]);
  const original = JSON.stringify(cleanSnapshot()); localStorage.setItem(savedScope, original);
  try {
    h.client.createPractice.mockImplementationOnce(async id => {
      expect(id).toBe(practiceOperationId);
      expect(localStorage.getItem(practiceRefKey)).toBe(JSON.stringify({ version: 1,
        operationId: practiceOperationId }));
      return { operationId: id, status: 'published', sceneId: scenes[1].id, canResume: false };
    });
    await h.controller.start(h.host);
    const oldSession = h.mountFrame.mock.results[0].value;
    await h.controller.newPractice();
    expect(oldSession.close).toHaveBeenCalled();
    expect(localStorage.getItem(practiceRefKey)).toBe(null);
    expect(localStorage.getItem(savedScope)).toBe(original);
    expect(localStorage.getItem(`${savedScope}:scene:${scenes[0].id}`)).toBe(JSON.stringify(cleanSnapshot()));
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.mountFrame).toHaveBeenCalledTimes(2);
  } finally {
    h.close(); localStorage.clear();
    if (originalUuid) Object.defineProperty(global.crypto, 'randomUUID', originalUuid);
  }
});

test('new execution keeps only the old owned scene cart across launches and never hydrates a retired scene', async () => {
  localStorage.clear();
  const originalUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => practiceOperationId });
  const nextCredential = { ...credential, launch: { ...credential.launch,
    launchId: '44444444-4444-4444-8444-444444444444' } };
  const newScope = 'dvaia:secureshop:44444444-4444-4444-8444-444444444444:1';
  const oldList = [{ ...scenes[0], isDefault: true }];
  const newList = [scenes[0], { ...scenes[1], isDefault: true }];
  const h = harness(oldList, 'customer', { principalId });
  try {
    localStorage.setItem(savedScope, JSON.stringify(cleanSnapshot()));
    h.client.bootstrap.mockResolvedValueOnce(credential).mockResolvedValue(nextCredential);
    h.client.scenes.mockResolvedValueOnce(oldList).mockResolvedValueOnce(oldList)
      .mockResolvedValue(newList);
    h.client.createPractice.mockResolvedValue({ operationId: practiceOperationId,
      status: 'published', sceneId: scenes[1].id, canResume: false });
    await h.controller.start(h.host);
    await h.controller.newPractice();
    expect(h.mountFrame.mock.calls.at(-1)[0].getLaunchBearer()).toBe(nextCredential.bearer);
    await h.controller.choosePractice();
    await h.controller.selectScene(scenes[0].id);
    const oldSceneStorage = h.createStateStore.mock.calls.at(-1)[0].storage;
    expect(JSON.parse(oldSceneStorage.getItem(newScope))).toEqual(cleanSnapshot());
    expect(localStorage.getItem(`${newScope}:scene:${scenes[1].id}`)).not.toBe(null);
    expect(localStorage.getItem(`${newScope}:scene:${scenes[0].id}`)).toBe(null);
    h.close();
    const freshScene = { ...scenes[1], id: '66666666-6666-4666-8666-666666666666', isDefault: true };
    const retired = harness([freshScene], 'customer', { principalId });
    try {
      retired.client.bootstrap.mockResolvedValue({ ...nextCredential, launch: { ...nextCredential.launch,
        launchId: '55555555-5555-4555-8555-555555555555' } });
      await retired.controller.start(retired.host);
      expect(retired.createStateStore.mock.calls.at(-1)[0].storage.getItem(
        'dvaia:secureshop:55555555-5555-4555-8555-555555555555:1')).toBe(null);
      await expect(retired.controller.selectScene(scenes[0].id)).rejects.toThrow('Listed');
    } finally { retired.close(); }
  } finally {
    h.close(); localStorage.clear();
    if (originalUuid) Object.defineProperty(global.crypto, 'randomUUID', originalUuid);
  }
});

test('lost new-practice acknowledgement retains UUID and reload checks GET without a second POST', async () => {
  localStorage.clear();
  const originalUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => practiceOperationId });
  const list = [{ ...scenes[0], isDefault: true }, scenes[1]];
  const h = harness(list, 'customer', { principalId });
  try {
    h.client.createPractice.mockRejectedValueOnce(new Error('response lost'));
    await h.controller.start(h.host);
    await expect(h.controller.newPractice()).rejects.toThrow('response lost');
    expect(h.states.at(-1).status).toBe('practice-recovery');
    expect(localStorage.getItem(practiceRefKey)).toContain(practiceOperationId);
    h.close();
    const next = harness(list, 'customer', { principalId });
    next.client.scenes.mockResolvedValue([scenes[0], { ...scenes[1], isDefault: true }]);
    try {
      next.client.getPractice.mockResolvedValueOnce({ operationId: practiceOperationId,
        status: 'pending', sceneId: null, canResume: true });
      await next.controller.start(next.host);
      expect(next.client.getPractice).toHaveBeenCalledWith(practiceOperationId, expect.anything());
      expect(next.client.createPractice).not.toHaveBeenCalled();
      expect(next.states.at(-1).status).toBe('practice-recovery');
      next.client.getPractice.mockResolvedValueOnce({ operationId: practiceOperationId,
        status: 'pending', sceneId: null, canResume: true });
      next.client.createPractice.mockResolvedValueOnce({ operationId: practiceOperationId,
        status: 'published', sceneId: scenes[1].id, canResume: false });
      await next.controller.checkPractice({ resume: true });
      expect(next.client.createPractice).toHaveBeenCalledTimes(1);
      expect(next.client.createPractice).toHaveBeenCalledWith(practiceOperationId, expect.anything());
      expect(localStorage.getItem(practiceRefKey)).toBe(null);
      expect(next.states.at(-1).status).toBe('ready');
    } finally { next.close(); }
  } finally {
    h.close(); localStorage.clear();
    if (originalUuid) Object.defineProperty(global.crypto, 'randomUUID', originalUuid);
  }
});

test('retained unfinished new practice remains saved and cannot be resumed after session change', async () => {
  localStorage.clear();
  localStorage.setItem(practiceRefKey, JSON.stringify({ version: 1, operationId: practiceOperationId }));
  const h = harness([{ ...scenes[0], isDefault: true }], 'customer', { principalId });
  try {
    h.client.getPractice.mockResolvedValue({ operationId: practiceOperationId,
      status: 'retained_unfinished', sceneId: null, canResume: false });
    await h.controller.start(h.host);
    expect(h.client.bootstrap).not.toHaveBeenCalled();
    expect(h.states.at(-1).status).toBe('practice-recovery');
    await h.controller.checkPractice({ resume: true });
    expect(h.client.createPractice).not.toHaveBeenCalled();
    await h.controller.openRetainedPractice();
    expect(h.states.at(-1).status).toBe('choose-scene');
    await h.controller.selectScene(scenes[0].id);
    expect(h.states.at(-1).practiceWarning).toMatch(/unresolved/);
    expect(localStorage.getItem(practiceRefKey)).toContain(practiceOperationId);
  } finally { h.close(); localStorage.clear(); }
});

test.each([
  [SHOP_CUSTOMER_CHAT_KEY, JSON.stringify({ version: 1, references: [{
    shopUserId: 7, sessionId: '11111111-1111-4111-8111-111111111111',
    requestId: '22222222-2222-4222-8222-222222222222', startedAt: 1 }] })],
  [SHOP_CHAT_CART_KEY, JSON.stringify({ operationId: '11111111-1111-4111-8111-111111111111',
    intentDigest: 'a'.repeat(64), scopeKey: 'b'.repeat(64) })],
])('published GET cannot switch an active frame with unresolved %s', async (key, saved) => {
  localStorage.clear();
  localStorage.setItem(practiceRefKey, JSON.stringify({ version: 1, operationId: practiceOperationId }));
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]], 'customer', { principalId });
  try {
    h.client.getPractice.mockResolvedValue({ operationId: practiceOperationId,
      status: 'retained_unfinished', sceneId: null, canResume: false });
    await h.controller.start(h.host);
    await h.controller.openRetainedPractice();
    await h.controller.selectScene(scenes[0].id);
    const oldSession = h.mountFrame.mock.results[0].value;
    localStorage.setItem(savedScope, JSON.stringify({ ...cleanSnapshot(), [key]: saved }));
    h.client.getPractice.mockResolvedValueOnce({ operationId: practiceOperationId,
      status: 'published', sceneId: scenes[1].id, canResume: false });
    h.client.scenes.mockResolvedValueOnce([scenes[0], { ...scenes[1], isDefault: true }]);
    await expect(h.controller.checkPractice()).rejects.toThrow('Check saved operation');
    expect(oldSession.close).not.toHaveBeenCalled();
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(practiceRefKey)).toContain(practiceOperationId);
  } finally { h.close(); localStorage.clear(); }
});

test('acknowledged customer chat page permits a practice switch while pending chat still blocks it', async () => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]], 'customer', { principalId });
  const row = { shopUserId: 7, sessionId: '11111111-1111-4111-8111-111111111111',
    requestId: '22222222-2222-4222-8222-222222222222', startedAt: 1 };
  const saved = JSON.stringify({ version: 1, references: [row] });
  try {
    await h.controller.start(h.host);
    localStorage.setItem(savedScope, JSON.stringify({ ...cleanSnapshot(),
      [SHOP_CUSTOMER_CHAT_COMPLETED_KEY]: saved }));
    await h.controller.choosePractice();
    expect(h.states.at(-1).status).toBe('choose-scene');
    await h.controller.selectScene(scenes[0].id);
    h.createStateStore.mock.calls.at(-1)[0].storage.setItem(savedScope, JSON.stringify({ ...cleanSnapshot(),
      [SHOP_CUSTOMER_CHAT_COMPLETED_KEY]: saved, [SHOP_CUSTOMER_CHAT_KEY]: saved }));
    await expect(h.controller.choosePractice()).rejects.toThrow('Check saved operation');
  } finally { h.close(); localStorage.clear(); }
});

test('ready publication can precede pending cleanup and silently reject a chooser action', async () => {
  localStorage.clear();
  const published = [];
  let attempted;
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]], 'customer', {
    onState(value) {
      published.push(value);
      if (value.status === 'ready' && !attempted) attempted = h.controller.choosePractice();
    },
  });
  try {
    await h.controller.start(h.host);
    await expect(attempted).rejects.toThrow('Current shop practice required');
    expect(published.at(-1).status).toBe('ready');
    expect(published.at(-1).practiceError).toBeUndefined();
    expect(h.client.scenes).toHaveBeenCalledTimes(1);
    await h.controller.choosePractice();
    expect(published.at(-1).status).toBe('choose-scene');
  } finally { h.close(); localStorage.clear(); }
});

test('acknowledged role page permits scene switch while unresolved role request blocks it', async () => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]], 'merchant', { principalId });
  const saved = JSON.stringify({ version: 1, references: [{ role: 'merchant', shopUserId: 7,
    sessionId: '11111111-1111-4111-8111-111111111111',
    requestId: '22222222-2222-4222-8222-222222222222', startedAt: 1 }] });
  try {
    await h.controller.start(h.host);
    localStorage.setItem(savedScope, JSON.stringify({ ...cleanSnapshot(),
      [SHOP_ROLE_ASSISTANT_COMPLETED_KEY]: saved }));
    await h.controller.choosePractice();
    expect(h.states.at(-1).status).toBe('choose-scene');
    await h.controller.selectScene(scenes[0].id);
    h.createStateStore.mock.calls.at(-1)[0].storage.setItem(savedScope,
      JSON.stringify({ ...cleanSnapshot(), [SHOP_ROLE_ASSISTANT_COMPLETED_KEY]: saved,
        [SHOP_ROLE_ASSISTANT_KEY]: saved }));
    await expect(h.controller.choosePractice()).rejects.toThrow('Check saved operation');
  } finally { h.close(); localStorage.clear(); }
});

test('completed registered-admin page permits scene switch while pending request blocks it', async () => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]], 'admin', { principalId });
  const saved = JSON.stringify({ version: 1, shopUserId: 7,
    sessionId: '11111111-1111-4111-8111-111111111111',
    requestId: '22222222-2222-4222-8222-222222222222', startedAt: 1 });
  try {
    await h.controller.start(h.host);
    localStorage.setItem(savedScope, JSON.stringify({ ...cleanSnapshot(),
      [SHOP_REGISTERED_ADMIN_COMPLETED_KEY]: saved }));
    await h.controller.choosePractice();
    expect(h.states.at(-1).status).toBe('choose-scene');
    await h.controller.selectScene(scenes[0].id);
    h.createStateStore.mock.calls.at(-1)[0].storage.setItem(savedScope,
      JSON.stringify({ ...cleanSnapshot(), [SHOP_REGISTERED_ADMIN_COMPLETED_KEY]: saved,
        [SHOP_REGISTERED_ADMIN_CHAT_KEY]: saved }));
    await expect(h.controller.choosePractice()).rejects.toThrow('Check saved operation');
  } finally { h.close(); localStorage.clear(); }
});

test('published GET with another caller-selected scene retains exact ref and does not mount mismatched scene', async () => {
  localStorage.clear();
  localStorage.setItem(practiceRefKey, JSON.stringify({ version: 1, operationId: practiceOperationId }));
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]], 'customer', { principalId });
  try {
    h.client.getPractice.mockResolvedValue({ operationId: practiceOperationId,
      status: 'published', sceneId: scenes[1].id, canResume: false });
    await expect(h.controller.start(h.host)).rejects.toThrow('selected owned scene');
    expect(h.mountFrame).not.toHaveBeenCalled();
    expect(h.states.at(-1).status).toBe('practice-recovery');
    await h.controller.openRetainedPractice();
    expect(h.states.at(-1).status).toBe('choose-scene');
    expect(localStorage.getItem(practiceRefKey)).toContain(practiceOperationId);
  } finally { h.close(); localStorage.clear(); }
});

test('saved new practice can report no-bearer capacity without a scene read or another POST', async () => {
  localStorage.clear();
  localStorage.setItem(practiceRefKey, JSON.stringify({ version: 1, operationId: practiceOperationId }));
  const h = harness([scenes[0]], 'customer', { principalId });
  try {
    h.client.getPractice.mockResolvedValue({ operationId: practiceOperationId,
      status: 'retained_unfinished', sceneId: null, canResume: false });
    await h.controller.start(h.host);
    h.client.bootstrap.mockRejectedValueOnce(Object.assign(new Error('capacity'), {
      status: 409, code: 'LAUNCH_CAPACITY' }));
    await expect(h.controller.openRetainedPractice()).rejects.toThrow('capacity');
    expect(h.client.scenes).not.toHaveBeenCalled();
    expect(h.client.createPractice).not.toHaveBeenCalled();
    expect(h.states.at(-1).message).toMatch(/instructor.*retained resources/);
    expect(localStorage.getItem(practiceRefKey)).toContain(practiceOperationId);
  } finally { h.close(); localStorage.clear(); }
});

test('unreadable parent practice storage refuses admission with a visible error and no POST', async () => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }], 'customer', { principalId });
  let getSpy;
  try {
    await h.controller.start(h.host);
    const originalGet = Storage.prototype.getItem;
    getSpy = jest.spyOn(Storage.prototype, 'getItem').mockImplementation(function (key) {
      if (key === practiceRefKey) throw new DOMException('denied', 'SecurityError');
      return originalGet.call(this, key);
    });
    await expect(h.controller.newPractice()).rejects.toMatchObject({ name: 'SecurityError' });
    expect(h.client.createPractice).not.toHaveBeenCalled();
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'error',
      message: expect.stringContaining('storage could not be verified') }));
  } finally { getSpy?.mockRestore(); h.close(); localStorage.clear(); }
});

test('capacity before admission clears exact ref and failed old remount leaves actionable reopen state', async () => {
  localStorage.clear();
  const originalUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => practiceOperationId });
  const h = harness([{ ...scenes[0], isDefault: true }], 'customer', { principalId });
  try {
    await h.controller.start(h.host);
    h.client.createPractice.mockRejectedValueOnce(Object.assign(new Error('capacity'), {
      status: 409, code: 'SHOP_PRACTICE_CAPACITY', operationId: practiceOperationId }));
    h.mountFrame.mockImplementationOnce(() => { throw new Error('expired old launch'); });
    await expect(h.controller.newPractice()).rejects.toThrow('capacity');
    expect(localStorage.getItem(practiceRefKey)).toBe(null);
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'error',
      message: expect.stringContaining('Reopen SecureShop') }));
  } finally {
    h.close(); localStorage.clear();
    if (originalUuid) Object.defineProperty(global.crypto, 'randomUUID', originalUuid);
  }
});

test('capacity with failed parent ACK keeps exact UUID and offers saved-reference recovery', async () => {
  localStorage.clear();
  const originalUuid = Object.getOwnPropertyDescriptor(global.crypto, 'randomUUID');
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => practiceOperationId });
  const h = harness([{ ...scenes[0], isDefault: true }], 'customer', { principalId });
  let removeSpy;
  try {
    await h.controller.start(h.host);
    h.client.createPractice.mockRejectedValueOnce(Object.assign(new Error('capacity'), {
      status: 409, code: 'SHOP_PRACTICE_CAPACITY', operationId: practiceOperationId }));
    const originalRemove = Storage.prototype.removeItem;
    removeSpy = jest.spyOn(Storage.prototype, 'removeItem').mockImplementation(function (key) {
      if (key === practiceRefKey) throw new DOMException('denied', 'SecurityError');
      return originalRemove.call(this, key);
    });
    await expect(h.controller.newPractice()).rejects.toThrow('capacity');
    expect(h.client.createPractice).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(practiceRefKey)).toContain(practiceOperationId);
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'practice-recovery',
      message: expect.stringContaining('could not be cleared') }));
  } finally {
    removeSpy?.mockRestore(); h.close(); localStorage.clear();
    if (originalUuid) Object.defineProperty(global.crypto, 'randomUUID', originalUuid);
  }
});

test('bootstrap capacity without a bearer gives retained-resource guidance and never reads scenes', async () => {
  localStorage.clear();
  const h = harness([scenes[0]], 'customer', { principalId });
  try {
    h.client.bootstrap.mockRejectedValueOnce(Object.assign(new Error('capacity'), {
      status: 409, code: 'LAUNCH_CAPACITY' }));
    await expect(h.controller.start(h.host)).rejects.toThrow('capacity');
    expect(h.client.scenes).not.toHaveBeenCalled();
    expect(h.states.at(-1).message).toMatch(/instructor.*retained resources/);
  } finally { h.close(); localStorage.clear(); }
});

test('explicit retained practice switch fences the old frame and isolates storage across return and reload', async () => {
  localStorage.clear();
  const original = JSON.stringify(cleanSnapshot());
  const siblingKey = 'dvaia:secureshop:11111111-1111-4111-8111-111111111111:1';
  localStorage.setItem(savedScope, original); localStorage.setItem(siblingKey, 'sibling bytes');
  const list = [{ ...scenes[0], isDefault: true }, scenes[1]];
  const h = harness(list);
  let reopened;
  try {
    await h.controller.start(h.host);
    const old = h.mountFrame.mock.calls[0][0];
    const oldSession = h.mountFrame.mock.results[0].value;
    await h.controller.choosePractice();
    expect(oldSession.close).toHaveBeenCalled();
    expect(old.frame.isConnected).toBe(false);
    expect(() => old.getLaunchBearer()).toThrow();
    expect(h.states.at(-1)).toEqual({ status: 'choose-scene', scenes: list, originalSceneId: scenes[0].id });
    expect(localStorage.getItem(savedScope)).toBe(original);
    expect(localStorage.getItem(`${savedScope}:scene-storage-v1`)).toBe('1');
    await h.controller.selectScene(scenes[1].id);
    const next = h.createStateStore.mock.calls.at(-1)[0].storage;
    expect(next.getItem(savedScope)).toBe(null);
    const pending = JSON.stringify({ ...cleanSnapshot(), [SHOP_REVIEW_DECISION_KEY]: 'saved decision' });
    next.setItem(savedScope, pending);
    expect(localStorage.getItem(`${savedScope}:scene:${scenes[1].id}`)).toBe(pending);
    await expect(h.controller.choosePractice()).rejects.toThrow('Check saved operation');
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.client.selectScene).toHaveBeenCalledTimes(1);
    next.setItem(savedScope, JSON.stringify(cleanSnapshot()));
    await h.controller.choosePractice();
    await h.controller.selectScene(scenes[0].id);
    expect(h.createStateStore.mock.calls.at(-1)[0].storage.getItem(savedScope)).toBe(original);
    h.close();
    // Reload uses only scene storage even when legacy bytes later contain refs.
    localStorage.setItem(savedScope, pending);
    reopened = harness(list);
    await reopened.controller.start(reopened.host);
    expect(reopened.createStateStore.mock.calls[0][0].storage.getItem(savedScope)).toBe(original);
    expect(localStorage.getItem(siblingKey)).toBe('sibling bytes');
    expect(h.client.renew).not.toHaveBeenCalled();
    expect(h.client.resetPractice).not.toHaveBeenCalled();
  } finally { h.close(); reopened?.close(); localStorage.clear(); }
});

test.each(['saved', 'malformed', 'unreadable', 'array'])('saved or unverifiable legacy refs block switch without closing recovery: %s', async kind => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]]);
  let readSpy;
  try {
    await h.controller.start(h.host);
    const bytes = kind === 'malformed' ? '{' : JSON.stringify({ ...cleanSnapshot(),
      [SHOP_REVIEW_DECISION_KEY]: kind === 'array' ? '[]' : 'pending' });
    localStorage.setItem(savedScope, bytes);
    if (kind === 'unreadable') {
      const get = Storage.prototype.getItem;
      readSpy = jest.spyOn(Storage.prototype, 'getItem').mockImplementation(function (key) {
        if (key === savedScope) throw Error('unreadable');
        return get.call(this, key);
      });
    }
    await expect(h.controller.choosePractice()).rejects.toThrow();
    expect(h.mountFrame.mock.results[0].value.close).not.toHaveBeenCalled();
    expect(h.mountFrame.mock.calls[0][0].frame.isConnected).toBe(true);
    expect(h.client.scenes).toHaveBeenCalledTimes(1);
    expect(h.client.selectScene).not.toHaveBeenCalled();
    expect(localStorage.getItem(`${savedScope}:scene-storage-v1`)).toBe(null);
  } finally { readSpy?.mockRestore(); h.close(); localStorage.clear(); }
});

test('completed and cleared Listings references permit choosing a retained practice without rewriting legacy bytes', async () => {
  localStorage.clear();
  const listingScope = 'a'.repeat(64);
  const pending = { import: { scopeKey: listingScope, digest: 'b'.repeat(64),
    operationId: '11111111-1111-4111-8111-111111111111' } };
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]]);
  try {
    await h.controller.start(h.host);
    localStorage.setItem(savedScope, JSON.stringify({ ...cleanSnapshot(), [SHOP_LISTINGS_KEY]: JSON.stringify(pending) }));
    await expect(h.controller.choosePractice()).rejects.toThrow('Check saved operation');
    // The supported Listings clear path persists an empty object after readback.
    const cleared = JSON.stringify(replaceListingsScope(decodeListingsReferences(JSON.stringify(pending)), listingScope, {}));
    expect(cleared).toBe('{}');
    const original = JSON.stringify({ ...cleanSnapshot(), [SHOP_LISTINGS_KEY]: cleared });
    localStorage.setItem(savedScope, original);
    await h.controller.choosePractice();
    expect(h.states.at(-1).status).toBe('choose-scene');
    expect(localStorage.getItem(savedScope)).toBe(original);
    expect(localStorage.getItem(`${savedScope}:scene:${scenes[0].id}`)).toBe(original);
    await h.controller.selectScene(scenes[1].id);
    expect(h.createStateStore.mock.calls.at(-1)[0].storage.getItem(savedScope)).toBe(null);
  } finally { h.close(); localStorage.clear(); }
});

test.each([
  [SHOP_LISTINGS_KEY, JSON.stringify({ assessment: [], retained: [] })],
  [SHOP_MAIL_KEY, JSON.stringify({ version: 3, scopes: { ['a'.repeat(64)]: { pending: null, assessment: null, unresolved: [] } } })],
  [SHOP_REFUND_KEY, JSON.stringify({ version: 1, references: [] })],
])('decoder-verified empty reference sets permit switching: %s', async (key, value) => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]]);
  try {
    await h.controller.start(h.host);
    const bytes = JSON.stringify({ ...cleanSnapshot(), [key]: value });
    localStorage.setItem(savedScope, bytes);
    await h.controller.choosePractice();
    expect(h.states.at(-1).status).toBe('choose-scene');
    expect(localStorage.getItem(savedScope)).toBe(bytes);
  } finally { h.close(); localStorage.clear(); }
});

test.each([
  [SHOP_LISTINGS_KEY, '{"unknown":[]}'],
  [SHOP_MAIL_KEY, '[]'],
  [SHOP_REFUND_KEY, '[]'],
  [SHOP_REVIEW_DECISION_KEY, '{}'],
  [SHOP_LISTINGS_KEY, JSON.stringify({ retained: [{ scopeKey: 'a'.repeat(64), import: {
    scopeKey: 'a'.repeat(64), digest: 'b'.repeat(64), operationId: '11111111-1111-4111-8111-111111111111' } }] })],
  [SHOP_MAIL_KEY, JSON.stringify({ version: 3, scopes: { ['a'.repeat(64)]: { pending: null, assessment: null,
    unresolved: [{ action: 'autoReply', requestId: '11111111-1111-4111-8111-111111111111', digest: 'b'.repeat(64), threadId: 1 }] } } })],
  [SHOP_REFUND_KEY, JSON.stringify({ version: 1, references: [{ orderId: 1,
    sessionId: '11111111-1111-4111-8111-111111111111', requestId: '22222222-2222-4222-8222-222222222222' }] })],
])('invalid shapes or populated references still block switching: %s %s', async (key, value) => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]]);
  try {
    await h.controller.start(h.host);
    localStorage.setItem(savedScope, JSON.stringify({ ...cleanSnapshot(), [key]: value }));
    await expect(h.controller.choosePractice()).rejects.toThrow();
    expect(h.mountFrame.mock.results[0].value.close).not.toHaveBeenCalled();
    expect(localStorage.getItem(`${savedScope}:scene-storage-v1`)).toBe(null);
    expect(h.client.selectScene).not.toHaveBeenCalled();
  } finally { h.close(); localStorage.clear(); }
});

test('bridge-close race rereads acknowledged refs and remounts original recovery without a marker', async () => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]]);
  const raced = JSON.stringify({ ...cleanSnapshot(), [SHOP_REVIEW_DECISION_KEY]: 'arrived before shutdown' });
  try {
    await h.controller.start(h.host);
    h.mountFrame.mock.results[0].value.close.mockImplementationOnce(() => localStorage.setItem(savedScope, raced));
    await expect(h.controller.choosePractice()).rejects.toThrow('Check saved operation');
    expect(h.mountFrame).toHaveBeenCalledTimes(2);
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'ready', practiceError: expect.any(String) }));
    expect(h.createStateStore.mock.calls.at(-1)[0].storage.getItem(savedScope)).toBe(raced);
    expect(localStorage.getItem(`${savedScope}:scene-storage-v1`)).toBe(null);
    expect(h.client.selectScene).not.toHaveBeenCalled();
  } finally { h.close(); localStorage.clear(); }
});

test('protected reset recovery is rechecked after the old bridge closes', async () => {
  localStorage.clear();
  const allowed = jest.fn().mockReturnValueOnce(true).mockReturnValueOnce(false);
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]], 'admin', { canSwitchPractice: allowed });
  try {
    await h.controller.start(h.host);
    await expect(h.controller.choosePractice()).rejects.toThrow('Check saved operation');
    expect(allowed).toHaveBeenCalledTimes(2);
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.mountFrame).toHaveBeenCalledTimes(2);
    expect(h.client.selectScene).not.toHaveBeenCalled();
  } finally { h.close(); localStorage.clear(); }
});

test('failed marker ACK and failed select retain the original recovery choice', async () => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]]);
  const set = Storage.prototype.setItem;
  let writeSpy;
  try {
    await h.controller.start(h.host);
    writeSpy = jest.spyOn(Storage.prototype, 'setItem').mockImplementation(function (key, value) {
      if (key.endsWith(':scene-storage-v1')) return;
      set.call(this, key, value);
    });
    await expect(h.controller.choosePractice()).rejects.toThrow('not saved');
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.client.selectScene).not.toHaveBeenCalled();
    writeSpy.mockRestore();
    await h.controller.choosePractice();
    await expect(h.controller.selectScene('ffffffff-ffff-4fff-8fff-ffffffffffff')).rejects.toThrow('Listed');
    h.client.selectScene.mockRejectedValueOnce(Error('selection unavailable'));
    await expect(h.controller.selectScene(scenes[1].id)).rejects.toThrow('selection unavailable');
    expect(h.states.at(-1).originalSceneId).toBe(scenes[0].id);
    await h.controller.selectScene(scenes[0].id);
    expect(h.states.at(-1).status).toBe('ready');
  } finally { writeSpy?.mockRestore(); h.close(); localStorage.clear(); }
});

test('disposal during retained scene selection aborts old work and prevents a late remount', async () => {
  localStorage.clear();
  const h = harness([{ ...scenes[0], isDefault: true }, scenes[1]]);
  let release;
  try {
    await h.controller.start(h.host); await h.controller.choosePractice();
    h.client.selectScene.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
    const selecting = h.controller.selectScene(scenes[1].id);
    await expect(h.controller.selectScene(scenes[0].id)).rejects.toThrow('Listed');
    const signal = h.client.selectScene.mock.calls.at(-1)[2];
    h.controller.close(); release({});
    await expect(selecting).rejects.toMatchObject({ name: 'AbortError' });
    expect(signal.aborted).toBe(true);
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
  } finally { h.close(); localStorage.clear(); }
});

test('a single existing practice opens the verified opaque frame without workshop credentials', async () => {
  const h = harness([scenes[0]]);
  try {
    await h.controller.start(h.host);
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
    const options = h.mountFrame.mock.calls[0][0];
    expect(options.url).toContain('standalone=1');
    expect(options.url).toContain('product%2F125');
    expect(options.url).not.toContain(credential.bearer);
    expect(options.url).not.toContain(credential.persona.token);
    expect(options.getLaunchBearer()).toBe(credential.bearer);
    expect(h.createStateStore).toHaveBeenCalledWith(expect.objectContaining({
      personaToken: credential.persona.token, scenarioId: credential.launch.launchId,
    }));
    expect(h.client.selectScene).not.toHaveBeenCalled();
  } finally { h.close(); }
});

test('multiple practices without a default require explicit selection before frame mount', async () => {
  const h = harness(scenes);
  try {
    await h.controller.start(h.host);
    expect(h.states.at(-1)).toEqual({ status: 'choose-scene', scenes });
    expect(h.mountFrame).not.toHaveBeenCalled();
    await h.controller.selectScene(scenes[1].id);
    expect(h.client.selectScene).toHaveBeenCalledWith(credential.bearer, scenes[1].id, expect.any(AbortSignal));
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
    expect(h.states.at(-1).status).toBe('ready');
  } finally { h.close(); }
});
test('only an exact expired shop launch renews the cookie once before fresh bootstrap', async () => {
  const h = harness([scenes[0]]);
  h.client.bootstrap.mockRejectedValueOnce(Object.assign(Error('expired'), { status: 409, code: 'SHOP_LAUNCH_EXPIRED' }));
  try {
    await h.controller.start(h.host);
    expect(h.client.renew).toHaveBeenCalledTimes(1);
    expect(h.client.bootstrap).toHaveBeenCalledTimes(2);
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
    expect(h.states.at(-1).status).toBe('ready');
  } finally { h.close(); }
});

test.each([{ status: 503, code: 'SHOP_LAUNCH_EXPIRED' },
  { status: 409, code: 'LAUNCH_SESSION_TERMINAL' }])('other bootstrap failure never rotates the cookie: %p', async failure => {
  const h = harness([scenes[0]]);
  h.client.bootstrap.mockRejectedValueOnce(Object.assign(Error('unavailable'), failure));
  try {
    await expect(h.controller.start(h.host)).rejects.toMatchObject(failure);
    expect(h.client.renew).not.toHaveBeenCalled();
    expect(h.client.bootstrap).toHaveBeenCalledTimes(1);
    expect(h.mountFrame).not.toHaveBeenCalled();
  } finally { h.close(); }
});

test('a second expired bootstrap does not trigger another renewal or mount', async () => {
  const h = harness([scenes[0]]);
  const expired = Object.assign(Error('expired'), { status: 409, code: 'SHOP_LAUNCH_EXPIRED' });
  h.client.bootstrap.mockRejectedValueOnce(expired).mockRejectedValueOnce(expired);
  try {
    await expect(h.controller.start(h.host)).rejects.toBe(expired);
    expect(h.client.renew).toHaveBeenCalledTimes(1);
    expect(h.client.bootstrap).toHaveBeenCalledTimes(2);
    expect(h.mountFrame).not.toHaveBeenCalled();
  } finally { h.close(); }
});

test('closing during shop renewal prevents stale bootstrap and frame mount', async () => {
  const h = harness([scenes[0]]);
  let release;
  h.client.bootstrap.mockRejectedValueOnce(Object.assign(Error('expired'), { status: 409, code: 'SHOP_LAUNCH_EXPIRED' }));
  h.client.renew.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  try {
    const pending = h.controller.start(h.host);
    await Promise.resolve();
    await Promise.resolve();
    expect(h.client.renew).toHaveBeenCalledTimes(1);
    h.controller.close(); release({});
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(h.client.bootstrap).toHaveBeenCalledTimes(1);
    expect(h.mountFrame).not.toHaveBeenCalled();
  } finally { h.close(); }
});

test('confirmed shared practice reset detaches old frame and remounts only after fresh bootstrap', async () => {
  const h = harness([scenes[0]]);
  const restored = { ...credential, launch: { ...credential.launch, generation: 2 }, bearer: 'b'.repeat(43) };
  h.client.bootstrap.mockResolvedValueOnce(credential).mockResolvedValueOnce(restored);
  h.client.scenes.mockResolvedValueOnce([scenes[0]]).mockResolvedValueOnce([]);
  const previousUuid = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '7f078c35-0bda-4bb4-9c9f-819807aa2668' });
  try {
    await h.controller.start(h.host);
    const prior = h.host.querySelector('iframe');
    const readiness = { available: true, scope: 'shared_practice', launchId: credential.launch.launchId,
      generation: 1, scene: { id: scenes[0].id, label: scenes[0].label } };
    const reset = h.controller.reset(readiness);
    expect(prior.isConnected).toBe(false);
    await reset;
    expect(h.client.resetPractice).toHaveBeenCalledWith({ launchId: credential.launch.launchId,
      expectedGeneration: 1, idempotencyKey: '7f078c35-0bda-4bb4-9c9f-819807aa2668',
      sceneId: scenes[0].id, confirmation: 'RESET_SHARED_PRACTICE' }, expect.any(AbortSignal));
    expect(h.host.querySelector('iframe')).not.toBe(prior);
    expect(h.mountFrame).toHaveBeenCalledTimes(2);
    expect(h.states.at(-1)).toEqual({ status: 'ready', launch: restored.launch,
      personaExpiresAt: restored.persona.expiresAt });
  } finally {
    h.close();
    if (previousUuid) Object.defineProperty(globalThis.crypto, 'randomUUID', previousUuid);
    else delete globalThis.crypto.randomUUID;
  }
});

test('uncertain shared reset retries identical request and never reuses detached frame', async () => {
  const h = harness([scenes[0]]);
  const restored = { ...credential, launch: { ...credential.launch, generation: 2 } };
  h.client.bootstrap.mockResolvedValueOnce(credential).mockResolvedValueOnce(restored);
  h.client.scenes.mockResolvedValueOnce([scenes[0]]).mockResolvedValueOnce([]);
  h.client.resetPractice.mockRejectedValueOnce(new Error('Response lost'));
  const previousUuid = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '7f078c35-0bda-4bb4-9c9f-819807aa2668' });
  try {
    await h.controller.start(h.host);
    const prior = h.host.querySelector('iframe');
    const readiness = { available: true, scope: 'shared_practice', launchId: credential.launch.launchId,
      generation: 1, scene: { id: scenes[0].id, label: scenes[0].label } };
    await expect(h.controller.reset(readiness)).rejects.toThrow('Response lost');
    expect(prior.isConnected).toBe(false);
    expect(h.host.querySelector('iframe')).toBeNull();
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'error', retryReset: true,
      resetCommitted: false }));
    await h.controller.reset(readiness);
    expect(h.client.resetPractice).toHaveBeenCalledTimes(2);
    expect(h.client.resetPractice.mock.calls[1][0]).toEqual(h.client.resetPractice.mock.calls[0][0]);
    expect(h.mountFrame).toHaveBeenCalledTimes(2);
  } finally {
    h.close();
    if (previousUuid) Object.defineProperty(globalThis.crypto, 'randomUUID', previousUuid);
    else delete globalThis.crypto.randomUUID;
  }
});

test('confirmed cleanup with failed reopen retries bootstrap without a second reset POST', async () => {
  const h = harness([scenes[0]]);
  const restored = { ...credential, launch: { ...credential.launch, generation: 2 } };
  h.client.bootstrap.mockResolvedValueOnce(credential).mockRejectedValueOnce(new Error('Bootstrap unavailable'))
    .mockResolvedValueOnce(restored);
  h.client.scenes.mockResolvedValueOnce([scenes[0]]).mockResolvedValueOnce([]);
  const previousUuid = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '7f078c35-0bda-4bb4-9c9f-819807aa2668' });
  try {
    await h.controller.start(h.host);
    const readiness = { available: true, scope: 'shared_practice', launchId: credential.launch.launchId,
      generation: 1, scene: { id: scenes[0].id, label: scenes[0].label } };
    await expect(h.controller.reset(readiness)).rejects.toThrow('Bootstrap unavailable');
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'error', retryReset: true,
      resetCommitted: true }));
    await h.controller.reset(readiness);
    expect(h.client.resetPractice).toHaveBeenCalledTimes(1);
    expect(h.client.bootstrap).toHaveBeenCalledTimes(3);
    expect(h.states.at(-1).status).toBe('ready');
  } finally {
    h.close();
    if (previousUuid) Object.defineProperty(globalThis.crypto, 'randomUUID', previousUuid);
    else delete globalThis.crypto.randomUUID;
  }
});

test('stale reset readiness does not detach the current storefront or send a mutation', async () => {
  const h = harness([scenes[0]]);
  try {
    await h.controller.start(h.host);
    const frame = h.host.querySelector('iframe');
    await expect(h.controller.reset({ available: true, scope: 'shared_practice',
      launchId: credential.launch.launchId, generation: 2,
      scene: { id: scenes[0].id, label: scenes[0].label } })).rejects.toThrow('readiness required');
    expect(frame.isConnected).toBe(true);
    expect(h.client.resetPractice).not.toHaveBeenCalled();
  } finally { h.close(); }
});

test('surviving practice requires explicit choice after reset instead of silent default switch', async () => {
  const h = harness([scenes[0]]);
  const restored = { ...credential, launch: { ...credential.launch, generation: 2 } };
  h.client.bootstrap.mockResolvedValueOnce(credential).mockResolvedValueOnce(restored);
  h.client.scenes.mockResolvedValueOnce([scenes[0]])
    .mockResolvedValueOnce([{ ...scenes[1], isDefault: true }]);
  const previousUuid = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '7f078c35-0bda-4bb4-9c9f-819807aa2668' });
  try {
    await h.controller.start(h.host);
    await h.controller.reset({ available: true, scope: 'shared_practice', launchId: credential.launch.launchId,
      generation: 1, scene: { id: scenes[0].id, label: scenes[0].label } });
    expect(h.states.at(-1)).toEqual({ status: 'choose-scene', scenes: [{ ...scenes[1], isDefault: true }] });
    expect(h.host.querySelector('iframe')).toBeNull();
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
    await h.controller.selectScene(scenes[1].id);
    expect(h.mountFrame).toHaveBeenCalledTimes(2);
    expect(h.client.resetPractice).toHaveBeenCalledTimes(1);
  } finally {
    h.close();
    if (previousUuid) Object.defineProperty(globalThis.crypto, 'randomUUID', previousUuid);
    else delete globalThis.crypto.randomUUID;
  }
});

test('retired practice in active scene list blocks remount after confirmed cleanup', async () => {
  const h = harness([scenes[0]]);
  const restored = { ...credential, launch: { ...credential.launch, generation: 2 } };
  h.client.bootstrap.mockResolvedValueOnce(credential).mockResolvedValueOnce(restored);
  h.client.scenes.mockResolvedValueOnce([scenes[0]]).mockResolvedValueOnce([{ ...scenes[0], isDefault: true }]);
  const previousUuid = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '7f078c35-0bda-4bb4-9c9f-819807aa2668' });
  try {
    await h.controller.start(h.host);
    await expect(h.controller.reset({ available: true, scope: 'shared_practice',
      launchId: credential.launch.launchId, generation: 1,
      scene: { id: scenes[0].id, label: scenes[0].label } })).rejects.toThrow('Retired practice');
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'error', resetCommitted: true }));
    expect(h.host.querySelector('iframe')).toBeNull();
    expect(h.client.resetPractice).toHaveBeenCalledTimes(1);
  } finally {
    h.close();
    if (previousUuid) Object.defineProperty(globalThis.crypto, 'randomUUID', previousUuid);
    else delete globalThis.crypto.randomUUID;
  }
});

test('admin pre-bootstrap recovery blocks old frame until explicit cleanup-only resume', async () => {
  const h = harness([], 'admin');
  const pending = { resetId: '11111111-1111-4111-8111-111111111111',
    launchId: credential.launch.launchId, fromGeneration: 1, toGeneration: 2,
    status: 'fenced', scene: { id: scenes[0].id, label: 'Shop practice' },
    cleanupComplete: false, sameExecution: false };
  const fresh = { ...credential, launch: { ...credential.launch,
    launchId: 'd0672486-9095-4433-ae75-2db7c40be0e5' } };
  h.client.getPracticeResetRecovery.mockResolvedValue(pending);
  h.client.resumePracticeReset.mockResolvedValue({ resetId: pending.resetId, status: 'aborted',
    cleanupComplete: true, activated: false });
  h.client.bootstrap.mockResolvedValue(fresh);
  try {
    await h.controller.start(h.host);
    expect(h.states.at(-1)).toEqual({ status: 'reset-recovery', recovery: pending });
    expect(h.client.bootstrap).not.toHaveBeenCalled();
    expect(h.host.querySelector('iframe')).toBeNull();
    await h.controller.resumeResetRecovery();
    expect(h.client.resumePracticeReset).toHaveBeenCalledWith(pending.resetId, expect.any(AbortSignal));
    expect(h.states.at(-1)).toEqual({ status: 'ready', launch: fresh.launch,
      personaExpiresAt: fresh.persona.expiresAt });
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
  } finally { h.close(); }
});

test('terminal completed reset preflight bootstraps without repeating recovery POST', async () => {
  const h = harness([], 'admin');
  const pending = { resetId: '11111111-1111-4111-8111-111111111111',
    launchId: credential.launch.launchId, fromGeneration: 1, toGeneration: 2,
    status: 'committed', scene: { id: scenes[0].id, label: 'Shop practice' },
    cleanupComplete: true, sameExecution: true };
  h.client.getPracticeResetRecovery.mockResolvedValue(pending);
  h.client.bootstrap.mockResolvedValue({ ...credential, launch: { ...credential.launch, generation: 2 } });
  try {
    await h.controller.start(h.host);
    expect(h.client.resumePracticeReset).not.toHaveBeenCalled();
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
  } finally { h.close(); }
});

test('historical fenced reset with verified cleanup does not block a later shop visit', async () => {
  const h = harness([], 'admin');
  const pending = { resetId: '11111111-1111-4111-8111-111111111111',
    launchId: credential.launch.launchId, fromGeneration: 1, toGeneration: 2,
    status: 'fenced', scene: { id: scenes[0].id, label: 'Shop practice' },
    cleanupComplete: true, sameExecution: false };
  h.client.getPracticeResetRecovery.mockResolvedValue(pending);
  h.client.bootstrap.mockResolvedValue({ ...credential, launch: { ...credential.launch,
    launchId: 'd0672486-9095-4433-ae75-2db7c40be0e5' } });
  try {
    await h.controller.start(h.host);
    expect(h.client.resumePracticeReset).not.toHaveBeenCalled();
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
  } finally { h.close(); }
});

test('cleanup-only recovery renews once for an expired shop launch before reopening', async () => {
  const h = harness([], 'admin');
  const pending = { resetId: '11111111-1111-4111-8111-111111111111',
    launchId: credential.launch.launchId, fromGeneration: 1, toGeneration: 2,
    status: 'fenced', scene: { id: scenes[0].id, label: 'Shop practice' },
    cleanupComplete: false, sameExecution: true };
  const expired = Object.assign(Error('expired'), { status: 409, code: 'SHOP_LAUNCH_EXPIRED' });
  h.client.getPracticeResetRecovery.mockResolvedValue(pending);
  h.client.resumePracticeReset.mockResolvedValue({ resetId: pending.resetId,
    status: 'fenced', cleanupComplete: true, activated: false });
  h.client.bootstrap.mockRejectedValueOnce(expired).mockResolvedValueOnce({ ...credential,
    launch: { ...credential.launch, launchId: 'd0672486-9095-4433-ae75-2db7c40be0e5' } });
  try {
    await h.controller.start(h.host);
    await h.controller.resumeResetRecovery();
    expect(h.client.renew).toHaveBeenCalledTimes(1);
    expect(h.client.bootstrap).toHaveBeenCalledTimes(2);
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
  } finally { h.close(); }
});

test('cleanup-only recovery accepts current cookie-owned launch at a strictly newer generation', async () => {
  const h = harness([], 'admin');
  const pending = { resetId: '11111111-1111-4111-8111-111111111111',
    launchId: credential.launch.launchId, fromGeneration: 1, toGeneration: 2,
    status: 'fenced', scene: { id: scenes[0].id, label: 'Shop practice' },
    cleanupComplete: false, sameExecution: false };
  h.client.getPracticeResetRecovery.mockResolvedValue(pending);
  h.client.resumePracticeReset.mockResolvedValue({ resetId: pending.resetId,
    status: 'fenced', cleanupComplete: true, activated: false });
  h.client.bootstrap.mockResolvedValue({ ...credential,
    launch: { ...credential.launch, generation: 3 } });
  try {
    await h.controller.start(h.host);
    await h.controller.resumeResetRecovery();
    expect(h.states.at(-1).status).toBe('ready');
    expect(h.mountFrame).toHaveBeenCalledTimes(1);
  } finally { h.close(); }
});

test.each([1, 2])('cleanup-only recovery rejects the historical launch generation %s', async generation => {
  const h = harness([], 'admin');
  const pending = { resetId: '11111111-1111-4111-8111-111111111111',
    launchId: credential.launch.launchId, fromGeneration: 1, toGeneration: 2,
    status: 'fenced', scene: { id: scenes[0].id, label: 'Shop practice' },
    cleanupComplete: false, sameExecution: false };
  h.client.getPracticeResetRecovery.mockResolvedValue(pending);
  h.client.resumePracticeReset.mockResolvedValue({ resetId: pending.resetId,
    status: 'fenced', cleanupComplete: true, activated: false });
  h.client.bootstrap.mockResolvedValue({ ...credential,
    launch: { ...credential.launch, generation } });
  try {
    await h.controller.start(h.host);
    await expect(h.controller.resumeResetRecovery()).rejects.toThrow('fresh authorized launch');
    expect(h.mountFrame).not.toHaveBeenCalled();
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'error',
      retryRecovery: true, cleanupConfirmed: true }));
  } finally { h.close(); }
});

test('recovery receipt loss keeps exact reset ID and never bootstraps before cleanup proof', async () => {
  const h = harness([], 'admin');
  const pending = { resetId: '11111111-1111-4111-8111-111111111111',
    launchId: credential.launch.launchId, fromGeneration: 1, toGeneration: 2,
    status: 'fenced', scene: { id: scenes[0].id, label: 'Shop practice' },
    cleanupComplete: false, sameExecution: true };
  h.client.getPracticeResetRecovery.mockResolvedValue(pending);
  h.client.resumePracticeReset.mockRejectedValueOnce(new Error('Response lost'))
    .mockResolvedValueOnce({ resetId: pending.resetId, status: 'committed',
      cleanupComplete: true, activated: true });
  h.client.bootstrap.mockResolvedValue({ ...credential, launch: { ...credential.launch, generation: 2 } });
  try {
    await h.controller.start(h.host);
    await expect(h.controller.resumeResetRecovery()).rejects.toThrow('Response lost');
    expect(h.client.bootstrap).not.toHaveBeenCalled();
    expect(h.states.at(-1)).toEqual(expect.objectContaining({ status: 'error', retryRecovery: true,
      cleanupConfirmed: false }));
    await h.controller.resumeResetRecovery();
    expect(h.client.resumePracticeReset).toHaveBeenCalledTimes(2);
    expect(h.client.resumePracticeReset.mock.calls[1][0]).toBe(pending.resetId);
    expect(h.states.at(-1).status).toBe('ready');
  } finally { h.close(); }
});
