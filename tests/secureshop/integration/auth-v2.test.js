'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'controlled-pg-auth-secret';
const previousSecret = process.env.JWT_SECRET;
process.env.JWT_SECRET = JWT_SECRET;

let nextUserId;
let nextAddressId;
let nextSessionId;
let users;
let addresses;
let sessions;

async function seed() {
  nextUserId = 4;
  nextAddressId = 1;
  nextSessionId = 1;
  addresses = [];
  sessions = [];
  const password = await bcrypt.hash('student123', 4);
  users = [
    { id: 1, username: 'student_c', email: 'c@example.test', password, role: 'customer', full_name: 'Customer', phone: null, api_key: 'sk_ss_c', created_at: 'now' },
    { id: 2, username: 'student_merchant', email: 'm@example.test', password, role: 'merchant', full_name: 'Merchant', phone: null, api_key: 'sk_ss_m', created_at: 'now' },
    { id: 3, username: 'student_admin', email: 'a@example.test', password, role: 'admin', full_name: 'Admin', phone: null, api_key: 'sk_ss_a', created_at: 'now' },
  ];
}

const repository = {
  async findConflict(username, email) { return users.find((row) => row.username === username || row.email === email) || null; },
  async createUser(username, email, password, role, full_name) {
    const row = { id: nextUserId++, username, email, password, role, full_name, phone: null, api_key: null, created_at: 'now' };
    users.push(row); return row;
  },
  async findByUsername(username) { return users.find((row) => row.username === username) || null; },
  async findById(id) { return users.find((row) => row.id === Number(id)) || null; },
  async findCompanion(canonical, legacy, role) {
    return users.find((row) => [canonical, legacy].includes(row.username) && row.role === role) || null;
  },
  async recordLogin(userId, ip, userAgent) {
    sessions.push({ id: nextSessionId++, user_id: userId, ip, user_agent: userAgent, revoked_at: null });
  },
  async recordLogout() {},
  async updateProfile(id, full_name, email, phone) {
    const row = users.find((item) => item.id === Number(id));
    if (!row) return null;
    Object.assign(row, { full_name, email, phone }); return row;
  },
  async changePassword(id, oldHash, newHash) {
    const row = users.find((item) => item.id === Number(id) && item.password === oldHash);
    if (!row) return { rowCount: 0 };
    row.password = newHash; return { rowCount: 1 };
  },
  async listAddresses(userId) { return addresses.filter((row) => row.user_id === Number(userId)); },
  async saveAddress(userId, addressId, fields) {
    if (!users.some((row) => row.id === Number(userId))) return null;
    const [label,line1,line2,city,state,zip,phone,is_default] = fields;
    let row = addressId && addresses.find((item) => item.id === Number(addressId) && item.user_id === Number(userId));
    if (addressId && !row) return null;
    if (!row) { row = { id: nextAddressId++, user_id: Number(userId) }; addresses.push(row); }
    Object.assign(row, { label,line1,line2,city,state,zip,phone,is_default }); return row;
  },
  async deleteAddress(userId, addressId) {
    const before = addresses.length;
    addresses = addresses.filter((row) => !(row.id === Number(addressId) && row.user_id === Number(userId)));
    return { rowCount: before - addresses.length };
  },
  async rotateKey(id, key) { users.find((row) => row.id === Number(id)).api_key = key; },
  async listSessions(userId) { return sessions.filter((row) => row.user_id === Number(userId) && !row.revoked_at); },
  async revokeSession(userId, id) {
    const row = sessions.find((item) => item.id === Number(id) && item.user_id === Number(userId));
    if (row) row.revoked_at = 'now'; return { rowCount: row ? 1 : 0 };
  },
};

let server;
let base;
test.before(async () => {
  await seed();
  const buildAuth = require('../../../server/routes/secureshop/auth');
  const app = express();
  app.use(express.json());
  app.use('/api/secureshop/v2/auth', buildAuth({ repository }));
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}/api/secureshop/v2/auth`;
});
test.beforeEach(seed);
test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  if (previousSecret === undefined) delete process.env.JWT_SECRET;
  else process.env.JWT_SECRET = previousSecret;
});

async function request(method, pathname, body, token) {
  const response = await fetch(base + pathname, {
    method,
    headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}
async function login(username = 'student_c', password = 'student123') {
  return request('POST', '/login', { username, password });
}

test('auth login emits only HS256 identity and records a session; invalid credentials fail', async () => {
  const ok = await login();
  assert.equal(ok.status, 200);
  assert.equal(ok.body.user.role, 'customer');
  assert.equal(JSON.parse(Buffer.from(ok.body.token.split('.')[0], 'base64url')).alg, 'HS256');
  assert.equal(jwt.verify(ok.body.token, JWT_SECRET, { algorithms: ['HS256'] }).username, 'student_c');
  assert.equal(sessions.length, 1);
  assert.equal((await login('student_c', 'wrong')).status, 401);
});

test('registration mutates the repository and duplicate/invalid requests retain error responses', async () => {
  const created = await request('POST', '/register', { username: 'new', email: 'new@example.test', password: 'secret12', role: 'customer' });
  assert.equal(created.status, 200);
  assert.equal((await repository.findByUsername('new')).email, 'new@example.test');
  assert.equal((await request('POST', '/register', { username: 'new', email: 'other@example.test', password: 'secret12' })).status, 409);
  assert.equal((await request('POST', '/register', { username: 'bad', email: 'bad@example.test', password: 'secret12', role: 'root' })).status, 400);
});

test('whoami enforces bearer identity and rejects alg=none', async () => {
  const { body: { token } } = await login();
  assert.equal((await request('GET', '/whoami', undefined, token)).body.user.username, 'student_c');
  assert.equal((await request('GET', '/whoami')).status, 401);
  const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url');
  const payload = Buffer.from('{"id":3,"username":"student_admin","role":"admin"}').toString('base64url');
  assert.equal((await request('GET', '/whoami', undefined, `${header}.${payload}.`)).status, 401);
});

test('role switch requires target-account authentication while same-role refresh preserves identity', async () => {
  const { body: { token } } = await login();
  assert.equal((await request('POST', '/switch-role', { role: 'admin' }, token)).status, 403);
  assert.equal((await request('POST', '/switch-role', { role: 'admin', password: 'wrong' }, token)).status, 403);
  const switched = await request('POST', '/switch-role', { role: 'merchant', password: 'student123' }, token);
  assert.equal(switched.body.user.username, 'student_merchant');
  const same = await request('POST', '/switch-role', { role: 'customer' }, token);
  assert.equal(same.body.user.username, 'student_c');
});

test('profile and password mutations retain validation and persistence behavior', async () => {
  const { body: { token } } = await login();
  assert.equal((await request('PUT', '/users/me', { full_name: 'New Name', email: 'invalid' }, token)).status, 400);
  const profile = await request('PUT', '/users/me', { full_name: 'New Name', email: 'new@example.test', phone: '555' }, token);
  assert.equal(profile.body.user.full_name, 'New Name');
  assert.equal((await request('POST', '/users/me/password', { current_password: 'wrong', new_password: 'newpassword' }, token)).status, 403);
  assert.equal((await request('POST', '/users/me/password', { current_password: 'student123', new_password: 'newpassword' }, token)).status, 200);
  assert.equal((await login('student_c', 'newpassword')).status, 200);
});

test('address CRUD is owner-scoped and reports missing mutations', async () => {
  const { body: { token } } = await login();
  assert.equal((await request('POST', '/users/me/addresses', { label: 'bad' }, token)).status, 400);
  const add = await request('POST', '/users/me/addresses', { label: 'Home', line1: '1 Main', is_default: true }, token);
  assert.ok(add.body.id);
  assert.equal((await request('GET', '/users/me/addresses', undefined, token)).body.addresses.length, 1);
  assert.equal((await request('PUT', `/users/me/addresses/${add.body.id}`, { label: 'Work', line1: '2 Main' }, token)).body.ok, true);
  assert.equal((await request('PUT', '/users/me/addresses/999', { line1: 'missing' }, token)).status, 404);
  assert.equal((await request('DELETE', `/users/me/addresses/${add.body.id}`, undefined, token)).body.ok, true);
});

test('API-key rotation and session revocation persist and require authentication', async () => {
  const { body: { token } } = await login();
  const first = await request('GET', '/users/me/api-keys', undefined, token);
  const rotated = await request('POST', '/users/me/api-keys/rotate', {}, token);
  assert.notEqual(rotated.body.api_key, first.body.api_key);
  const active = await request('GET', '/users/me/sessions', undefined, token);
  assert.equal(active.body.sessions.length, 1);
  assert.equal((await request('POST', `/users/me/sessions/${active.body.sessions[0].id}/revoke`, {}, token)).body.ok, true);
  assert.equal((await request('GET', '/users/me/sessions', undefined, token)).body.sessions.length, 0);
  assert.equal((await request('GET', '/users/me/addresses')).status, 401);
});
