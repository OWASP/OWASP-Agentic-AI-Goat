const test = require('node:test');
const assert = require('node:assert/strict');

const { createRevisionSnapshotHandler, normalizeWorkshopKeys } = require('../server/routes/changeRevisions');

function createResponse() {
  return {
    statusCode: 200,
    body: undefined,
    headers: {},
    status(code) { this.statusCode = code; return this; },
    set(name, value) { this.headers[name] = value; return this; },
    json(body) { this.body = body; return this; },
  };
}

test('request cannot select another user revision scope', async () => {
  const calls = [];
  const handler = createRevisionSnapshotHandler({ async getSnapshot(input) { calls.push(input); return {}; } });
  const req = { user: { id: 41 }, query: { userId: 99, workshops: 'direct_prompt_injection' } };
  await handler(req, createResponse());
  assert.equal(calls[0].userId, 41);
});

test('polling snapshots normalize bounded workshop scopes and prevent caching', async () => {
  const calls = [];
  const handler = createRevisionSnapshotHandler({
    async getSnapshot(input) { calls.push(input); return { global: {}, workshops: {}, user: {} }; },
  });
  const res = createResponse();
  await handler({ user: { id: 101 }, query: { workshops: 'sql_injection_workshop,sql_injection_workshop,!,mcp_workshop' } }, res);
  assert.deepEqual(calls[0], { userId: 101, workshopKeys: ['sql_injection_workshop', 'mcp_workshop'] });
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.statusCode, 200);
});

test('workshop key normalization preserves wildcard and limits keys', () => {
  const raw = Array.from({ length: 55 }, (_, index) => `workshop_${index}`).concat('*');
  const normalized = normalizeWorkshopKeys(raw);
  assert.equal(normalized.length, 50);
  assert.equal(normalized[0], 'workshop_0');
  assert.equal(normalized.includes('*'), false);
  assert.deepEqual(normalizeWorkshopKeys('*'), ['*']);
});

test('polling snapshot rejects requests without authenticated context', async () => {
  const handler = createRevisionSnapshotHandler({ getSnapshot: async () => ({}) });
  const res = createResponse();
  await handler({ query: {} }, res);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: 'Authentication required' });
});

test('admin progress revision requires current manage_progress permission and never accepts a requested user scope', async () => {
  const calls = [];
  const checks = [];
  let allowed = true;
  const handler = createRevisionSnapshotHandler({
    async getSnapshot(input) { calls.push(input); return { adminProgress: input.includeAdminProgress ? 'opaque' : undefined }; },
  }, { async hasPermission(id, permission) { checks.push([id, permission]); return allowed; } });
  const admin = { user: { id: 41, role: 'admin', admin_level: 1 }, query: { userId: 99 } };
  const response = createResponse();
  await handler(admin, response);
  assert.deepEqual(calls.at(-1), { userId: 41, workshopKeys: [], includeAdminProgress: true });
  assert.deepEqual(checks, [[41, 'manage_progress']]);
  assert.equal(response.body.revisions.adminProgress, 'opaque');

  allowed = false;
  await handler(admin, createResponse());
  assert.deepEqual(calls.at(-1), { userId: 41, workshopKeys: [] });
  await handler({ user: { id: 42, role: 'student', admin_level: 0 }, query: { includeAdminProgress: 'true' } }, createResponse());
  assert.deepEqual(calls.at(-1), { userId: 42, workshopKeys: [] });
  assert.deepEqual(checks, [[41, 'manage_progress'], [41, 'manage_progress']]);
});
