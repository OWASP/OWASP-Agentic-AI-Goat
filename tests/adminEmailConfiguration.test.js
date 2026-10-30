'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const dotenv = require('dotenv');
const { createAdminEmailConfiguration } = require('../server/services/adminEmailConfiguration');
const { createAdminEmailConfigurationRouter } = require('../server/routes/adminEmailConfiguration');
const express = require('express');

async function fixture(source = 'IPI_EMAIL_PROVIDER=mailpit\nXSS_MAIL_PROVIDER=gmail\nGMAIL_USER=sender@example.test\nGMAIL_APP_PASSWORD=initial-password\n', options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-goat-mail-config-'));
  const envPath = path.join(directory, '.env');
  await fs.writeFile(envPath, source, { mode: 0o600 });
  return { directory, envPath, configuration: createAdminEmailConfiguration({ envPath, readProcessEnv: () => ({}), applyRuntime: () => {}, ...options }) };
}

test('admin email configuration reports only safe SMTP status fields', async (t) => {
  const f = await fixture(); t.after(() => fs.rm(f.directory, { recursive: true, force: true }));
  assert.deepEqual(await f.configuration.status(), {
    ipiProvider: 'mailpit', xssProvider: 'gmail', gmailConfigured: true,
    mailpitSigningConfigured: false, mailpitInboxUrl: 'http://127.0.0.1:8025', restartRequired: true,
  });
});

test('saved provider selections are the IPI and XSS startup defaults after restart', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-goat-mail-defaults-'));
  const envPath = path.join(directory, '.env');
  const source = 'IPI_EMAIL_PROVIDER=mailpit\nXSS_MAIL_PROVIDER=gmail\nGMAIL_USER=sender@example.test\nGMAIL_APP_PASSWORD=app-password\nIPI_MAIL_HMAC_SECRET=01234567890123456789012345678901\n';
  await fs.writeFile(envPath, source, { mode: 0o600 });
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const configuration = createAdminEmailConfiguration({ envPath, readProcessEnv: () => dotenv.parse(source) });
  const status = await configuration.status();
  assert.equal(status.ipiProvider, 'mailpit');
  assert.equal(status.xssProvider, 'gmail');
  assert.equal(status.restartRequired, false);
});

test('admin email configuration updates providers and Gmail credentials without returning secrets', async (t) => {
  const f = await fixture(); t.after(() => fs.rm(f.directory, { recursive: true, force: true }));
  const result = await f.configuration.save({ ipiProvider: 'gmail', xssProvider: 'mailpit',
    gmailUser: 'configured@example.test', gmailAppPassword: 'new app password' });
  assert.equal(result.ipiProvider, 'gmail');
  assert.equal(result.xssProvider, 'mailpit');
  assert.equal(JSON.stringify(result).includes('configured@example.test'), false);
  assert.equal(JSON.stringify(result).includes('new app password'), false);
  const saved = dotenv.parse(await fs.readFile(f.envPath));
  assert.equal(saved.GMAIL_USER, 'configured@example.test');
  assert.equal(saved.GMAIL_APP_PASSWORD, 'new app password');
  assert.equal(saved.IPI_EMAIL_PROVIDER, 'gmail');
  assert.equal(saved.XSS_MAIL_PROVIDER, 'mailpit');
  assert.equal((await fs.stat(f.envPath)).mode & 0o777, 0o600);
});

test('runtime providers are refreshed only after a successful private configuration write', async (t) => {
  const applied = [];
  const f = await fixture(undefined, { applyRuntime: updates => applied.push({ ...updates }) });
  t.after(() => fs.rm(f.directory, { recursive: true, force: true }));
  await f.configuration.save({ ipiProvider: 'gmail', xssProvider: 'mailpit' });
  assert.deepEqual(applied, [{
    IPI_EMAIL_PROVIDER: 'gmail', XSS_MAIL_PROVIDER: 'mailpit',
    WORKSHOP_MAILPIT_SMTP_HOST: '127.0.0.1', WORKSHOP_MAILPIT_SMTP_PORT: '1025',
    WORKSHOP_MAILPIT_API_URL: 'http://127.0.0.1:8025',
  }]);
  const broken = await fixture('IPI_EMAIL_PROVIDER=mailpit\nXSS_MAIL_PROVIDER=mailpit\n');
  t.after(() => fs.rm(broken.directory, { recursive: true, force: true }));
  await assert.rejects(() => broken.configuration.save({ ipiProvider: 'gmail', xssProvider: 'mailpit' }));
  assert.equal(applied.length, 1);
});

test('selecting IPI Mailpit provisions its private signing secret', async (t) => {
  const f = await fixture('XSS_MAIL_PROVIDER=mailpit\n'); t.after(() => fs.rm(f.directory, { recursive: true, force: true }));
  await f.configuration.save({ ipiProvider: 'mailpit', xssProvider: 'mailpit' });
  const saved = dotenv.parse(await fs.readFile(f.envPath));
  assert.equal(saved.IPI_EMAIL_PROVIDER, 'mailpit');
  assert.match(saved.IPI_MAIL_HMAC_SECRET, /^[a-f0-9]{64}$/);
  assert.equal(saved.WORKSHOP_MAILPIT_SMTP_HOST, '127.0.0.1');
  assert.equal(saved.WORKSHOP_MAILPIT_SMTP_PORT, '1025');
  assert.equal(saved.WORKSHOP_MAILPIT_API_URL, 'http://127.0.0.1:8025');
});

test('selecting Gmail without credentials is rejected and leaves the private config unchanged', async (t) => {
  const source = 'IPI_EMAIL_PROVIDER=mailpit\nXSS_MAIL_PROVIDER=mailpit\n';
  const f = await fixture(source); t.after(() => fs.rm(f.directory, { recursive: true, force: true }));
  await assert.rejects(() => f.configuration.save({ ipiProvider: 'gmail', xssProvider: 'mailpit' }),
    { code: 'INVALID_EMAIL_CONFIGURATION', field: 'gmailUser' });
  assert.equal(await fs.readFile(f.envPath, 'utf8'), source);
});

test('email configuration route requires level 2 administrator and never serializes SMTP credentials', async (t) => {
  const f = await fixture(); t.after(() => fs.rm(f.directory, { recursive: true, force: true }));
  const pass = (_req, _res, next) => next();
  const auth = { authenticateToken: pass, requireAdminLevel: level => (req, res, next) => {
    if (level !== 2 || req.headers.authorization !== 'Bearer admin') return res.status(403).json({ error: 'Insufficient privileges' });
    next();
  }, requirePermission: () => pass };
  const app = express(); app.use(express.json());
  app.use('/email', createAdminEmailConfigurationRouter({ service: f.configuration, auth }));
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const denied = await fetch(`${origin}/email`);
  assert.equal(denied.status, 403);
  const allowed = await fetch(`${origin}/email`, { headers: { authorization: 'Bearer admin' } });
  assert.equal(allowed.status, 200);
  const payload = await allowed.json();
  assert.equal(JSON.stringify(payload).includes('sender@example.test'), false);
  assert.equal(JSON.stringify(payload).includes('initial-password'), false);
});
