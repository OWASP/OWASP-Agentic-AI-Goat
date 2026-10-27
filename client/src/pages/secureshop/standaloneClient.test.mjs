import { createStandaloneShopClient, validateShopBootstrap } from './standaloneClient.mjs';

const expiry = new Date(Date.now() + 30 * 60 * 1000).toISOString();
const owner = { id: 7, principalId: '4a792aa0-026b-4e76-9520-17ee0252c9aa',
  username: 'student_customer', email: 'student@example.test', role: 'customer' };
const bootstrap = { launch: { launchId: 'c0672486-9095-4433-ae75-2db7c40be0e5',
  generation: 1, credentialVersion: 1, expiresAt: expiry }, bearer: 'a'.repeat(43),
persona: { token: 'signed.persona.token', user: { id: 7, username: owner.username,
  email: owner.email, role: owner.role, full_name: null, phone: null }, expiresAt: expiry } };

const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
  headers: { get: () => 'application/json; charset=utf-8' }, json: async () => body });

test('shop login and bootstrap use only shop cookie endpoints, with launch secret reserved for scene reads', async () => {
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ authenticated: true, user: owner, expiresAt: expiry }))
    .mockResolvedValueOnce(response(bootstrap))
    .mockResolvedValueOnce(response({ scenes: [{ id: 'b5647777-c51a-47ad-860a-5d3f1318ba10',
      label: 'Shop practice 1', createdAt: expiry, isDefault: true }] }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect((await client.login('student_customer', 'student123')).user).toEqual(owner);
  expect(await client.bootstrap()).toEqual(bootstrap);
  expect((await client.scenes(bootstrap.bearer)).length).toBe(1);
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual(['/api/secureshop/auth/login',
    '/api/secureshop/auth/bootstrap', '/api/secureshop/v2/scenes']);
  expect(fetchImpl.mock.calls[0][1]).toEqual(expect.objectContaining({ credentials: 'include',
    body: JSON.stringify({ username: 'student_customer', password: 'student123' }) }));
  expect(fetchImpl.mock.calls[2][1]).toEqual(expect.objectContaining({ credentials: 'omit',
    headers: expect.objectContaining({ 'X-DVAIA-SecureShop-Launch': bootstrap.bearer }) }));
});

test('external test send requires cookie and parent launch/persona together and accepts only bound receipts', async () => {
  const operationId = '11111111-1111-4111-8111-111111111111';
  const scopeKey = 'a'.repeat(64), requestSha256 = 'b'.repeat(64);
  const preview = { sender: 'merchant@gmail.com', recipient: 'person@sharklasers.com',
    subject: 'SecureShop synthetic delivery test',
    text: `This is a manually requested SecureShop synthetic delivery test.\nNo shop, inbox, account or private document content is included.\nTest operation: ${operationId}\n` };
  const prepared = { version: 1, operationId, scopeKey, requestSha256, state: 'prepared',
    preview, expiresAt: expiry, smtp: null };
  const ready = { version: 1, available: true, scopeKey, sender: preview.sender,
    templateVersion: 'synthetic-test-v1', limits: { ownerPerHour: 3, senderPerHour: 20 } };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response(ready))
    .mockResolvedValueOnce(response(prepared)).mockResolvedValueOnce(response(prepared))
    .mockResolvedValueOnce(response({ ...prepared, state: 'smtp_accepted',
      smtp: { smtpAccepted: true, deliveryConfirmed: false, messageId: 'provider-id',
        acceptedRecipient: preview.recipient } }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getExternalMailReadiness(bootstrap.bearer, bootstrap.persona.token)).toEqual(ready);
  expect(await client.prepareExternalMail(bootstrap.bearer, bootstrap.persona.token,
    { operationId, recipient: preview.recipient, scopeKey })).toEqual(prepared);
  expect(await client.getExternalMailOperation(bootstrap.bearer, bootstrap.persona.token,
    operationId, scopeKey)).toEqual(prepared);
  expect((await client.confirmExternalMail(bootstrap.bearer, bootstrap.persona.token,
    { operationId, requestSha256, scopeKey })).state).toBe('smtp_accepted');
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/auth/external-mail/readiness',
    '/api/secureshop/auth/external-mail/prepare',
    `/api/secureshop/auth/external-mail/operations/${operationId}`,
    '/api/secureshop/auth/external-mail/confirm',
  ]);
  for (const [, options] of fetchImpl.mock.calls) {
    expect(options).toMatchObject({ credentials: 'include', redirect: 'error', headers: {
      'X-DVAIA-SecureShop-Launch': bootstrap.bearer,
      Authorization: `Bearer ${bootstrap.persona.token}` } });
  }
  expect(JSON.parse(fetchImpl.mock.calls[3][1].body)).toEqual({ version: 1, operationId, requestSha256 });
  expect(fetchImpl.mock.calls[3][1].body).not.toContain(preview.text);
});

test('external test send rejects forged acknowledgment and never sends an invalid recipient', async () => {
  const operationId = '11111111-1111-4111-8111-111111111111', scopeKey = 'a'.repeat(64);
  const client = createStandaloneShopClient({ fetchImpl: jest.fn().mockResolvedValue(response({
    version: 1, operationId, scopeKey, requestSha256: 'b'.repeat(64), state: 'smtp_accepted',
    preview: { sender: 'merchant@gmail.com', recipient: 'person@sharklasers.com',
      subject: 'SecureShop synthetic delivery test',
      text: `This is a manually requested SecureShop synthetic delivery test.\nNo shop, inbox, account or private document content is included.\nTest operation: ${operationId}\n` },
    expiresAt: expiry, smtp: { smtpAccepted: true, deliveryConfirmed: true,
      messageId: 'provider-id', acceptedRecipient: 'person@sharklasers.com' },
  })) });
  await expect(client.prepareExternalMail(bootstrap.bearer, bootstrap.persona.token,
    { operationId, recipient: 'person@example.com', scopeKey })).rejects.toThrow('draft required');
  await expect(client.getExternalMailOperation(bootstrap.bearer, bootstrap.persona.token,
    operationId, scopeKey)).rejects.toThrow('not verified');
});

test('external test send accepts only the server terminal expiry DTO, not a client-inferred draft expiry', async () => {
  const operationId = '11111111-1111-4111-8111-111111111111', scopeKey = 'a'.repeat(64);
  const expiryPast = new Date(Date.now() - 60000).toISOString();
  const row = { version: 1, operationId, scopeKey, requestSha256: 'b'.repeat(64), state: 'expired',
    preview: { sender: 'merchant@gmail.com', recipient: 'person@sharklasers.com',
      subject: 'SecureShop synthetic delivery test',
      text: `This is a manually requested SecureShop synthetic delivery test.\nNo shop, inbox, account or private document content is included.\nTest operation: ${operationId}\n` },
    expiresAt: expiryPast, smtp: null };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response(row))
    .mockResolvedValueOnce(response({ ...row, state: 'prepared' }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect((await client.getExternalMailOperation(bootstrap.bearer, bootstrap.persona.token,
    operationId, scopeKey)).state).toBe('expired');
  expect((await client.getExternalMailOperation(bootstrap.bearer, bootstrap.persona.token,
    operationId, scopeKey)).state).toBe('prepared');
  expect(fetchImpl).toHaveBeenCalledTimes(2);
});

test('malformed bootstrap cannot enter the bound frame', () => {
  expect(() => validateShopBootstrap({ ...bootstrap, extra: 'platform-token' })).toThrow('Invalid shop bootstrap');
  expect(() => validateShopBootstrap({ ...bootstrap, persona: { ...bootstrap.persona, user: { ...bootstrap.persona.user,
    role: 'platform-admin' } } })).toThrow('Invalid shop bootstrap');
});

test('new practice uses the shop cookie and accepts only an exact saved operation receipt', async () => {
  const operationId = '11111111-1111-4111-8111-111111111111';
  const pending = { operationId, status: 'pending', sceneId: null, canResume: true };
  const published = { operationId, status: 'published', sceneId: '22222222-2222-4222-8222-222222222222', canResume: false };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response(pending)).mockResolvedValueOnce(response(published));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.createPractice(operationId.toUpperCase())).toEqual(pending);
  expect(await client.getPractice(operationId)).toEqual(published);
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/auth/practices', `/api/secureshop/auth/practices/${operationId}`]);
  expect(fetchImpl.mock.calls[0][1]).toEqual(expect.objectContaining({ method: 'POST',
    credentials: 'include', body: JSON.stringify({ operationId }) }));
  expect(fetchImpl.mock.calls[0][1].headers).not.toHaveProperty('X-DVAIA-SecureShop-Launch');
});

test('new practice rejects mismatched or ambiguous status and preserves exact capacity reference', async () => {
  const operationId = '11111111-1111-4111-8111-111111111111';
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ operationId, status: 'published',
    sceneId: null, canResume: false })).mockResolvedValueOnce(response({ operationId, status: 'pending',
    sceneId: null, canResume: 'true' })).mockResolvedValueOnce(response({
    error: 'Practice capacity is full', code: 'SHOP_PRACTICE_CAPACITY', operationId }, 409));
  const client = createStandaloneShopClient({ fetchImpl });
  await expect(client.getPractice(operationId)).rejects.toThrow('not verified');
  await expect(client.getPractice(operationId)).rejects.toThrow('not verified');
  await expect(client.createPractice(operationId)).rejects.toMatchObject({
    status: 409, code: 'SHOP_PRACTICE_CAPACITY', operationId });
});

test('unavailable shop session does not fabricate an authenticated user', async () => {
  const client = createStandaloneShopClient({ fetchImpl: jest.fn().mockResolvedValue(response({ authenticated: false, user: null })) });
  expect(await client.session()).toBeNull();
});

test('progress GETs use cookie authority and reject malformed or foreign projections', async () => {
  const objective = { objectiveId: 'ss_inventory_cross_merchant_stock', label: 'Owned stock authorization',
    completed: true };
  const own = { principalId: owner.principalId, shopUserId: owner.id, username: owner.username,
    role: owner.role, generation: 2, objectives: [objective], totalObjectives: 1, completedObjectives: 1 };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response(own))
    .mockResolvedValueOnce(response({ learners: [own], nextCursor: null }))
    .mockResolvedValueOnce(response(own))
    .mockResolvedValueOnce(response({ ...own, completedObjectives: 0 }))
    .mockResolvedValueOnce(response({ learners: [own, own], nextCursor: null }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getProgress()).toEqual(own);
  expect(await client.getAdminProgressLearners({ limit: 25, cursor: 4 }))
    .toEqual({ learners: [own], nextCursor: null });
  expect(await client.getAdminProgress(owner.principalId)).toEqual(own);
  expect(fetchImpl.mock.calls.slice(0, 3).map(([path]) => path)).toEqual([
    '/api/secureshop/auth/progress',
    '/api/secureshop/auth/admin/progress/learners?limit=25&cursor=4',
    `/api/secureshop/auth/admin/progress/${owner.principalId}`,
  ]);
  expect(fetchImpl.mock.calls.slice(0, 3).every(([, options]) => options.credentials === 'include'
    && !Object.hasOwn(options.headers, 'Authorization')
    && !Object.hasOwn(options.headers, 'X-DVAIA-SecureShop-Launch'))).toBe(true);
  await expect(client.getProgress()).rejects.toThrow('Invalid shop progress response');
  await expect(client.getAdminProgressLearners()).rejects.toThrow('Invalid shop progress response');
  await expect(client.getAdminProgress('invalid')).rejects.toThrow('Shop learner required');
});

test('session recovery accepts the exact cookie status projection without an expiry', async () => {
  const client = createStandaloneShopClient({ fetchImpl: jest.fn().mockResolvedValue(response({
    authenticated: true, user: owner,
  })) });
  expect(await client.session()).toEqual({ user: owner, expiresAt: null });
});

test('guest cart import uses shop cookie only and accepts canonical replay receipt', async () => {
  const uppercaseId = '7F078C35-0BDA-4BB4-9C9F-819807AA2668';
  const items = [{ productId: 125, quantity: 2 }];
  const fetchImpl = jest.fn().mockResolvedValue(response({ requestId: uppercaseId.toLowerCase(),
    imported: true, replayed: true, items: [{ productId: 125, quantity: 2,
      price: 99.99, name: 'Headphones' }], subtotal: 199.98 }));
  const client = createStandaloneShopClient({ fetchImpl });
  const result = await client.importCart(uppercaseId, items);
  expect(result.imported).toBe(true);
  expect(fetchImpl).toHaveBeenCalledWith('/api/secureshop/auth/cart-import', expect.objectContaining({
    method: 'POST', credentials: 'include',
    body: JSON.stringify({ requestId: uppercaseId.toLowerCase(), items }),
  }));
  expect(fetchImpl.mock.calls[0][1].headers).not.toHaveProperty('Authorization');
});

test('unconfirmed cart receipt cannot clear guest intent', async () => {
  const requestId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  const client = createStandaloneShopClient({ fetchImpl: jest.fn().mockResolvedValue(response({
    requestId, imported: true, replayed: false, items: [], subtotal: 0,
  })) });
  await expect(client.importCart(requestId, [{ productId: 125, quantity: 2 }]))
    .rejects.toThrow('not confirmed');
});

test('shop mode reads and CAS writes only through the cookie authority', async () => {
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ mode: 'vuln', revision: '1' }))
    .mockResolvedValueOnce(response({ mode: 'fixed', revision: '2' }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getMode()).toEqual({ mode: 'vuln', revision: '1' });
  expect(await client.setMode('fixed', '1')).toEqual({ mode: 'fixed', revision: '2' });
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual(['/api/secureshop/auth/mode', '/api/secureshop/auth/mode']);
  expect(fetchImpl.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'include',
    body: JSON.stringify({ mode: 'fixed', expectedRevision: '1' }) }));
  expect(fetchImpl.mock.calls[1][1].headers).not.toHaveProperty('Authorization');
});

test('shared practice reset uses shop cookie, exact confirmation, and verified aggregate receipt', async () => {
  const launchId = bootstrap.launch.launchId, sceneId = 'b5647777-c51a-47ad-860a-5d3f1318ba10';
  const idempotencyKey = '7F078C35-0BDA-4BB4-9C9F-819807AA2668';
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ available: true, scope: 'shared_practice',
    launchId, generation: 1, scene: { id: sceneId, label: 'Shared practice A' } }))
    .mockResolvedValueOnce(response({ resetId: '11111111-1111-4111-8111-111111111111',
      status: 'committed', cleanupComplete: true }));
  const client = createStandaloneShopClient({ fetchImpl });
  const readiness = await client.getPracticeResetReadiness();
  expect(readiness.scene.label).toBe('Shared practice A');
  const body = { launchId, expectedGeneration: 1, idempotencyKey,
    sceneId, confirmation: 'RESET_SHARED_PRACTICE' };
  expect((await client.resetPractice(body)).cleanupComplete).toBe(true);
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/auth/reset-readiness', '/api/secureshop/auth/reset']);
  expect(fetchImpl.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'include',
    body: JSON.stringify({ ...body, idempotencyKey: idempotencyKey.toLowerCase() }) }));
  expect(fetchImpl.mock.calls[1][1].headers).not.toHaveProperty('Authorization');
  await expect(client.resetPractice({ ...body, confirmation: 'RESET' })).rejects.toThrow('Current shared practice');
});

test('unverified shared practice reset receipt cannot be presented as cleanup', async () => {
  const client = createStandaloneShopClient({ fetchImpl: jest.fn().mockResolvedValue(response({
    resetId: '11111111-1111-4111-8111-111111111111', status: 'committed', cleanupComplete: false,
  })) });
  await expect(client.resetPractice({ launchId: bootstrap.launch.launchId, expectedGeneration: 1,
    idempotencyKey: '7f078c35-0bda-4bb4-9c9f-819807aa2668',
    sceneId: 'b5647777-c51a-47ad-860a-5d3f1318ba10', confirmation: 'RESET_SHARED_PRACTICE' }))
    .rejects.toThrow('cleanup was not confirmed');
});

test('protected recovery reads an exact journal and resumes only by its reset ID', async () => {
  const resetId = '11111111-1111-4111-8111-111111111111';
  const pending = { resetId, launchId: bootstrap.launch.launchId, fromGeneration: 1,
    toGeneration: 2, status: 'fenced', scene: { id: 'b5647777-c51a-47ad-860a-5d3f1318ba10',
      label: 'Shop practice' }, cleanupComplete: false, sameExecution: false };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ pending }))
    .mockResolvedValueOnce(response({ resetId, status: 'aborted', cleanupComplete: true,
      activated: false }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getPracticeResetRecovery()).toEqual(pending);
  expect((await client.resumePracticeReset(resetId)).activated).toBe(false);
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/auth/reset-recovery', '/api/secureshop/auth/reset-recovery']);
  expect(fetchImpl.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'include',
    body: JSON.stringify({ resetId }) }));
});

test('reset recovery rejects false cleanup and malformed journal projections', async () => {
  const resetId = '11111111-1111-4111-8111-111111111111';
  const client = createStandaloneShopClient({ fetchImpl: jest.fn()
    .mockResolvedValueOnce(response({ pending: { resetId, status: 'fenced' } }))
    .mockResolvedValueOnce(response({ resetId, status: 'committed', cleanupComplete: false,
      activated: true })) });
  await expect(client.getPracticeResetRecovery()).rejects.toThrow('recovery was not verified');
  await expect(client.resumePracticeReset(resetId)).rejects.toThrow('cleanup was not confirmed');
});

test('invalid or unconfirmed mode revisions are never presented as current', async () => {
  const client = createStandaloneShopClient({ fetchImpl: jest.fn().mockResolvedValue(response({ mode: 'fixed', revision: '0' })) });
  await expect(client.getMode()).rejects.toThrow('Invalid shop mode response');
  await expect(client.setMode('vuln', '9223372036854775808')).rejects.toThrow('Current shop mode required');
});

test('assessment objectives use shop cookie and per-objective revision without a platform token', async () => {
  const row = { objectiveId: 'ss_inventory_cross_merchant_stock', label: 'Owned stock authorization',
    enabled: false, qualification: 'native-model', revision: '1' };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ objectives: [row] }))
    .mockResolvedValueOnce(response({ objectiveId: row.objectiveId, enabled: true,
      qualification: row.qualification, revision: '2' }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getAssessmentObjectives()).toEqual([row]);
  expect(await client.setAssessmentObjective(row.objectiveId, true, '1')).toEqual({
    objectiveId: row.objectiveId, enabled: true, qualification: row.qualification, revision: '2',
  });
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/auth/assessment-objectives', '/api/secureshop/auth/assessment-objectives']);
  expect(fetchImpl.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'include',
    body: JSON.stringify({ objectiveId: row.objectiveId, enabled: true, expectedRevision: '1' }) }));
  expect(fetchImpl.mock.calls[1][1].headers).not.toHaveProperty('Authorization');
});

test('malformed objective settings and unconfirmed enable are rejected', async () => {
  const row = { objectiveId: 'ss_pricing_false_grounding', label: 'Pricing grounding',
    enabled: false, qualification: 'pending', revision: '1' };
  const client = createStandaloneShopClient({ fetchImpl: jest.fn().mockResolvedValueOnce(response({ objectives: [row, row] }))
    .mockResolvedValueOnce(response({ objectiveId: row.objectiveId, enabled: true,
      qualification: 'pending', revision: '2' })) });
  await expect(client.getAssessmentObjectives()).rejects.toThrow('Invalid shop objective response');
  await expect(client.setAssessmentObjective(row.objectiveId, true, '1'))
    .rejects.toThrow('Shop objective change was not confirmed');
  await expect(client.setAssessmentObjective('other', true, '1'))
    .rejects.toThrow('Current shop objective required');
});

test('saved assessment list and retry use independent shop cookie authority', async () => {
  const evaluationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  const childEvaluationId = '9f078c35-0bda-4bb4-9c9f-819807aa2668';
  const row = { evaluationId, objectiveId: 'ss_inventory_cross_merchant_stock',
    verdict: 'unavailable', disposition: 'not_pass', createdAt: expiry, evaluatedAt: null,
    canRetry: true, childEvaluationId: null };
  const receipt = { evaluationId, childEvaluationId, verdict: 'pass', disposition: 'awarded',
    completed: true, replayed: false };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ judgments: [row] }))
    .mockResolvedValueOnce(response(receipt));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getAssessments()).toEqual([row]);
  expect(await client.retryAssessment(evaluationId.toUpperCase())).toEqual(receipt);
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/auth/assessments', '/api/secureshop/auth/assessments/retry']);
  expect(fetchImpl.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'include',
    body: JSON.stringify({ evaluationId }) }));
  expect(fetchImpl.mock.calls[1][1].headers).not.toHaveProperty('Authorization');
});

test('malformed or unconfirmed assessment recovery cannot appear successful', async () => {
  const evaluationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  const row = { evaluationId, objectiveId: 'ss_inventory_cross_merchant_stock',
    verdict: 'unavailable', disposition: 'not_pass', createdAt: expiry, evaluatedAt: null,
    canRetry: true, childEvaluationId: null };
  const client = createStandaloneShopClient({ fetchImpl: jest.fn()
    .mockResolvedValueOnce(response({ judgments: [row, row] }))
    .mockResolvedValueOnce(response({ evaluationId,
      childEvaluationId: '9f078c35-0bda-4bb4-9c9f-819807aa2668', verdict: 'pass',
      disposition: 'not_pass', completed: true, replayed: false })) });
  await expect(client.getAssessments()).rejects.toThrow('Invalid shop assessment response');
  await expect(client.retryAssessment(evaluationId)).rejects.toThrow('not confirmed');
});

test('protected password reset uses parent shop cookie routes and verifies a receipt', async () => {
  const operationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  const person = { id: 17, username: 'shop_customer', email: 'customer@example.test',
    credentialVersion: '3', authorityVersion: '5', membershipVersion: '2', resetAvailable: true };
  const receipt = { operationId, targetId: 17, credentialVersion: '4', authorityVersion: '6',
    receiptSha256: 'a'.repeat(64), expiresAt: expiry };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ ok: true, user: person }))
    .mockResolvedValueOnce(response({ ok: true, receipt, secretAvailable: true, replayed: false }))
    .mockResolvedValueOnce(response({ ok: true, receipt, secretAvailable: true }))
    .mockResolvedValueOnce(response({ ok: true, receipt,
      temporaryPassword: 'private-only-temporary-password-123' }))
    .mockResolvedValueOnce(response({ ok: true, receipt, secretAvailable: false }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getResetReadiness(17)).toEqual(person);
  expect(await client.resetUserPassword(17, { operationId: operationId.toUpperCase(),
    expectedCredentialVersion: '3', expectedAuthorityVersion: '5', expectedMembershipVersion: '2' }))
    .toEqual({ ok: true, receipt, secretAvailable: true, replayed: false });
  await client.getPasswordResetStatus(17, operationId);
  await client.revealPasswordReset(17, operationId);
  await client.acknowledgePasswordReset(17, operationId);
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/auth/admin/users/17/reset-readiness',
    '/api/secureshop/auth/admin/users/17/reset-password',
    `/api/secureshop/auth/admin/users/17/password-resets/${operationId}`,
    `/api/secureshop/auth/admin/users/17/password-resets/${operationId}/reveal`,
    `/api/secureshop/auth/admin/users/17/password-resets/${operationId}/acknowledge`,
  ]);
  expect(fetchImpl.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'include',
    body: JSON.stringify({ operationId, expectedCredentialVersion: '3', expectedAuthorityVersion: '5',
      expectedMembershipVersion: '2' }) }));
  expect(fetchImpl.mock.calls[1][1].headers).not.toHaveProperty('Authorization');
});

test('unverified protected target or receipt is rejected', async () => {
  const operationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  const client = createStandaloneShopClient({ fetchImpl: jest.fn()
    .mockResolvedValueOnce(response({ ok: true, user: { id: 18, username: 'other', email: 'other@example.test',
      credentialVersion: '3', authorityVersion: '5', membershipVersion: '2', resetAvailable: true } }))
    .mockResolvedValueOnce(response({ ok: true, receipt: { operationId, targetId: 18,
      credentialVersion: '4', authorityVersion: '6', receiptSha256: 'a'.repeat(64), expiresAt: expiry },
    secretAvailable: true, replayed: false })) });
  await expect(client.getResetReadiness(17)).rejects.toThrow('not verified');
  await expect(client.resetUserPassword(17, { operationId,
    expectedCredentialVersion: '3', expectedAuthorityVersion: '5', expectedMembershipVersion: '2' }))
    .rejects.toThrow('not verified');
});

test('private teaching reset uses original bound authority and exact receipt without cookie or child bridge', async () => {
  const operationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  const scopeKey = JSON.stringify([bootstrap.launch.launchId, 1, 'admin', 'scope', 7,
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']);
  const readiness = { id: 17, username: 'teaching_user', email: 'teaching@example.test',
    identityKind: 'teaching_persona', channel: 'bound_persona', credentialVersion: '3',
    authorityVersion: '5', resetAvailable: true };
  const receipt = { operationId, targetId: 17, credentialVersion: '4', authorityVersion: '6',
    receiptSha256: 'a'.repeat(64), expiresAt: expiry };
  const fetchImpl = jest.fn().mockResolvedValueOnce(response({ ok: true,
    administration: { scopeKey } })).mockResolvedValueOnce(response({ ok: true, user: readiness }))
    .mockResolvedValueOnce(response({ ok: true, receipt, secretAvailable: true }))
    .mockResolvedValueOnce(response({ ok: true, receipt, secretAvailable: true }))
    .mockResolvedValueOnce(response({ ok: true, receipt, temporaryPassword: 'private-only-temporary-password-123' }))
    .mockResolvedValueOnce(response({ ok: true, receipt, secretAvailable: false }));
  const client = createStandaloneShopClient({ fetchImpl });
  expect(await client.getBoundAdminScope(bootstrap.bearer, bootstrap.persona.token)).toBe(scopeKey);
  expect(await client.getTeachingResetReadiness(bootstrap.bearer, bootstrap.persona.token, 17)).toEqual(readiness);
  await client.resetTeachingPassword(bootstrap.bearer, bootstrap.persona.token, 17,
    { operationId, expectedCredentialVersion: '3', expectedAuthorityVersion: '5' });
  await client.getTeachingResetStatus(bootstrap.bearer, bootstrap.persona.token, 17, operationId);
  expect((await client.revealTeachingReset(bootstrap.bearer, bootstrap.persona.token, 17, operationId))
    .temporaryPassword).toBe('private-only-temporary-password-123');
  await client.acknowledgeTeachingReset(bootstrap.bearer, bootstrap.persona.token, 17, operationId);
  expect(fetchImpl.mock.calls.map(([path]) => path)).toEqual([
    '/api/secureshop/admin/users?page=1&pageSize=1',
    '/api/secureshop/admin/users/17/reset-readiness',
    '/api/secureshop/admin/users/17/reset-password',
    `/api/secureshop/admin/users/17/password-resets/${operationId}`,
    `/api/secureshop/admin/users/17/password-resets/${operationId}/reveal`,
    `/api/secureshop/admin/users/17/password-resets/${operationId}/acknowledge`,
  ]);
  for (const [, options] of fetchImpl.mock.calls) {
    expect(options.credentials).toBe('omit');
    expect(options.headers).toMatchObject({ Authorization: `Bearer ${bootstrap.persona.token}`,
      'X-DVAIA-SecureShop-Launch': bootstrap.bearer });
  }
  expect(fetchImpl.mock.calls[2][1].body).toBe(JSON.stringify({ operationId,
    expectedCredentialVersion: '3', expectedAuthorityVersion: '5' }));
});
