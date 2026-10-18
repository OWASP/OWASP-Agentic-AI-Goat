'use strict';

// Installed behind the standalone shop router's origin, JSON and no-store gates.
// The teaching frame can request opening a panel; it cannot authorize this API.
function installRegisteredAdminResetRoutes(router, { service, authenticated, body, wrap, limit }) {
  const invalid = () => Object.assign(new Error('Invalid reset request'), { code: 'INVALID_ARGUMENT' });
  const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  const uuid = value => typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
  const version = value => typeof value === 'string' && /^[1-9]\d{0,15}$/.test(value)
    && Number.isSafeInteger(Number(value)) && Number(value) < Number.MAX_SAFE_INTEGER;
  function target(req) {
    if (!/^[1-9]\d{0,9}$/.test(req.params.id) || Number(req.params.id) > 2147483647
      || Object.keys(req.query).length) throw invalid();
    return Number(req.params.id);
  }
  function operation(req) {
    if (!uuid(req.params.operationId)) throw invalid();
    return req.params.operationId.toLowerCase();
  }
  async function admin(req) {
    const actor = await authenticated(req);
    if (actor.user.role !== 'admin') throw Object.assign(new Error('Admin required'), { code: 'SHOP_ADMIN_REQUIRED' });
    if (!service) throw new Error('Registered reset unavailable');
    return actor.token;
  }
  function receipt(value, id, op) {
    if (!exact(value, ['operationId', 'targetId', 'credentialVersion', 'authorityVersion', 'receiptSha256', 'expiresAt'])
      || value.operationId !== op || value.targetId !== id || !version(value.credentialVersion)
      || !version(value.authorityVersion) || !/^[a-f0-9]{64}$/.test(value.receiptSha256)
      || typeof value.expiresAt !== 'string' || !Number.isFinite(Date.parse(value.expiresAt))
      || new Date(value.expiresAt).toISOString() !== value.expiresAt) throw new Error('Invalid reset receipt');
    return value;
  }
  const base = '/admin/users/:id';
  router.get(`${base}/reset-readiness`, wrap(async (req, res) => {
    const id = target(req), token = await admin(req);
    const user = await service.preview({ token, targetId: id });
    if (!exact(user, ['id', 'username', 'email', 'credentialVersion', 'authorityVersion', 'membershipVersion', 'resetAvailable'])
      || user.id !== id || typeof user.username !== 'string' || !user.username || user.username.length > 256
      || typeof user.email !== 'string' || user.email.length > 512 || user.resetAvailable !== true
      || !version(user.credentialVersion) || !version(user.authorityVersion) || !version(user.membershipVersion)) {
      throw new Error('Invalid reset readiness');
    }
    res.json({ ok: true, user });
  }));
  router.post(`${base}/reset-password`, limit, wrap(async (req, res) => {
    const id = target(req), input = body(req, ['operationId', 'expectedCredentialVersion', 'expectedAuthorityVersion', 'expectedMembershipVersion']);
    if (!uuid(input.operationId) || !version(input.expectedCredentialVersion)
      || !version(input.expectedAuthorityVersion) || !version(input.expectedMembershipVersion)) throw invalid();
    const token = await admin(req), op = input.operationId.toLowerCase();
    const result = await service.reset({ ...input, token, targetId: id, operationId: op });
    if (!exact(result, ['receipt', 'secretAvailable', 'replayed'])
      || typeof result.secretAvailable !== 'boolean' || typeof result.replayed !== 'boolean') throw new Error('Invalid reset result');
    receipt(result.receipt, id, op);
    res.json({ ok: true, ...result });
  }));
  const operationPath = `${base}/password-resets/:operationId`;
  router.get(operationPath, wrap(async (req, res) => {
    const id = target(req), op = operation(req), token = await admin(req);
    const result = await service.read({ token, targetId: id, operationId: op });
    if (result === null) throw Object.assign(new Error('Reset not found'), { code: 'REGISTERED_RESET_OPERATION_NOT_FOUND' });
    if (!exact(result, ['receipt', 'secretAvailable']) || typeof result.secretAvailable !== 'boolean') throw new Error('Invalid reset status');
    receipt(result.receipt, id, op);
    res.json({ ok: true, ...result });
  }));
  for (const action of ['reveal', 'acknowledge']) {
    router.post(`${operationPath}/${action}`, limit, wrap(async (req, res) => {
      body(req, []);
      const id = target(req), op = operation(req), token = await admin(req);
      const result = await service[action]({ token, targetId: id, operationId: op });
      if (action === 'reveal'
        ? !exact(result, ['receipt', 'temporaryPassword']) || typeof result.temporaryPassword !== 'string'
          || !/^[A-Za-z0-9_-]{43}$/.test(result.temporaryPassword)
        : !exact(result, ['receipt', 'secretAvailable']) || result.secretAvailable !== false) throw new Error('Invalid reset recovery');
      receipt(result.receipt, id, op);
      res.json({ ok: true, ...result });
    }));
  }
}

module.exports = { installRegisteredAdminResetRoutes };
