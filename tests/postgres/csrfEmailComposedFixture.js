'use strict';

// Owned app fixture for csrfEmailComposed.integration.test.js. The launcher
// owns PostgreSQL, Mailpit, Ollama and process cleanup; this module only
// composes the production auth/session/CSRF routes around supplied stores.
const express = require('express');
const session = require('express-session');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { configureMailpit, installNetworkGuard, readModelDigest,
  validateFixtureAdapter, REQUIRED_MODEL_DIGEST } = require('./ipiEmailRenderedFixture');

function required(name) {
  const value = process.env[name];
  if (typeof value !== 'string' || !value) throw new Error(`Missing ${name}`);
  return value;
}

function validateShutdownDependencies(fixture, pools) {
  if (!fixture?.csrfRoutes || typeof fixture.csrfRoutes.closeBrowser !== 'function') {
    throw new TypeError('CSRF browser close hook required');
  }
  if (!Array.isArray(pools) || pools.length !== 4 || pools.some(pool => typeof pool?.end !== 'function')) {
    throw new TypeError('All four PostgreSQL pool close handles required');
  }
  return true;
}

function assertDistinctPasswordHashes(ownerHash, siblingHash) {
  if (typeof ownerHash !== 'string' || typeof siblingHash !== 'string' || !ownerHash || !siblingHash || ownerHash === siblingHash) {
    throw new TypeError('Owner and sibling password hashes must be independently generated');
  }
  return true;
}

function assertDistinctPasswordInputs(ownerPassword, siblingPassword) {
  if (typeof ownerPassword !== 'string' || typeof siblingPassword !== 'string'
    || !ownerPassword || !siblingPassword || ownerPassword === siblingPassword) {
    throw new TypeError('Owner and sibling passwords must be distinct inputs');
  }
  return true;
}

function installBrowserLaunchRecorder({ puppeteerModule } = {}) {
  const directory = process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR;
  if (!directory) return () => {};
  const modulePath = require.resolve('puppeteer');
  const puppeteer = puppeteerModule || require('puppeteer');
  const cacheEntry = require.cache[modulePath];
  const original = puppeteer.launch;
  const record = browser => {
    const executablePath = fs.realpathSync(process.env.PUPPETEER_EXECUTABLE_PATH);
    const executableSha256 = crypto.createHash('sha256').update(fs.readFileSync(executablePath)).digest('hex');
    if (executableSha256 !== process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256) throw new Error('Browser executable pin mismatch');
    const pid = browser?.process?.()?.pid;
    if (!Number.isSafeInteger(pid) || pid < 1) throw new Error('Managed browser PID required');
    const startTime = execFileSync('ps', ['-p', String(pid), '-o', 'lstart='], { encoding: 'utf8' }).trim();
    if (!startTime) throw new Error('Managed browser start time required');
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const target = path.join(directory, 'fixture-browser.json');
    let processes = [];
    try { const prior = JSON.parse(fs.readFileSync(target, 'utf8')); if (prior?.schemaVersion === 1 && Array.isArray(prior.processes)) processes = prior.processes; } catch {}
    if (!processes.some(item => item.pid === pid)) processes.push({ kind: 'fixture_browser', pid, startTime, executablePath, executableSha256 });
    const temporary = `${target}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify({ schemaVersion: 1, processes }) + '\n', { mode: 0o600 });
    fs.renameSync(temporary, target);
  };
  const wrappedLaunch = async (...args) => {
    const browser = await original.apply(puppeteer, args);
    try { record(browser); return browser; }
    catch (error) {
      try { await browser.close(); }
      catch (closeError) { throw new AggregateError([error, closeError], 'Browser evidence failure and close failure'); }
      throw error;
    }
  };
  if (puppeteerModule) {
    puppeteer.launch = wrappedLaunch;
    return () => { puppeteer.launch = original; };
  }
  if (!cacheEntry || cacheEntry.exports !== puppeteer) throw new Error('Puppeteer module cache seam unavailable');
  cacheEntry.exports = new Proxy(puppeteer, { get(target, property, receiver) {
    return property === 'launch' ? wrappedLaunch : Reflect.get(target, property, receiver);
  } });
  return () => { cacheEntry.exports = puppeteer; };
}

async function createCsrfEmailApp({ identityRuntime, identityMigration, csrfRuntime, csrfMigration,
  jwtSecret, mailpit, modelMaxCalls = 20 } = {}) {
  if (!identityRuntime || !identityMigration || !csrfRuntime || !csrfMigration) {
    throw new TypeError('Canonical identity and CSRF PostgreSQL pools required');
  }
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
  process.env.IDENTITY_DATABASE_URL = identityRuntime.options.connectionString;
  process.env.CSRF_WORKSHOP_DATABASE_URL = csrfRuntime.options.connectionString;
  process.env.CSRF_WORKSHOP_MIGRATION_DATABASE_URL = csrfMigration.options.connectionString;
  process.env.XSS_MAIL_PROVIDER = 'mailpit';
  process.env.IPI_MAIL_HMAC_SECRET = mailpit.hmacSecret;
  process.env.MAILPIT_API_URL = mailpit.apiUrl;
  process.env.MAILPIT_SMTP_HOST = mailpit.smtpHost;
  process.env.MAILPIT_SMTP_PORT = String(mailpit.smtpPort);
  process.env.AI_PROVIDER = 'ollama';
  process.env.JUDGE_PROVIDER = 'ollama';
  process.env.OLLAMA_MODEL = 'llama3.1:8b';
  const network = installNetworkGuard({ mailpitApiUrl: mailpit.apiUrl,
    ollamaBaseUrl: required('OLLAMA_BASE_URL'), maxCalls: modelMaxCalls });
  let restoreBrowserRecorder = () => {};
  try { restoreBrowserRecorder = installBrowserLaunchRecorder(); }
  catch (error) { network.restore(); throw error; }
  try {
    const identityApi = require('../../server/database/postgres/identityRepository');
  await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
  const csrfStore = require('../../server/database/postgres/csrfWorkshopDb').createCsrfWorkshopDb(csrfRuntime);
  await csrfStore.initialize(csrfMigration);
  const identity = identityApi.createIdentityRepository(identityRuntime);
  const progress = require('../../server/database/postgres/workshopProgressRepository')
    .createWorkshopProgressRepository(identityRuntime);
  const adapter = require('../../server/services/postgresIdentityAdapter')
    .createPostgresIdentityAdapter({ repository: identity, progress, jwtSecret });
  adapter.pool = identityRuntime;
  validateFixtureAdapter(adapter, identityRuntime, progress);
  require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter = () => adapter;

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(session({ secret: 'owned-csrf-email-composed-fixture', resave: false,
    saveUninitialized: false, cookie: { secure: false, httpOnly: false } }));
  app.use(require('../../server/middleware/postgresSessionManager').createPostgresSessionManager(adapter).middleware());
  app.use('/api/auth', require('../../server/routes/auth'));
  app.use('/api/workshop/config', require('../../server/routes/workshopConfig').createWorkshopConfigRouter());
  app.use('/api/workshop', require('../../server/routes/workshop'));
  const csrfRoutes = require('../../server/routes/csrfWorkshop');
  app.use('/api/workshop/csrf', csrfRoutes);
  const provider = require('../../server/services/xssMailProvider').getXssMailProvider();
    return Object.freeze({ app, identity, progress, csrfStore, adapter, network, provider, csrfRoutes, restoreBrowserRecorder,
      modelDigest: REQUIRED_MODEL_DIGEST });
  } catch (error) {
    try { network.restore(); } catch {}
    try { restoreBrowserRecorder(); } catch {}
    throw error;
  }
}

async function shutdownFixture({ fixture, server, pools, readiness, modelDigestBefore } = {}) {
  const failures = [];
  try {
    const modelDigestAfter = await readModelDigest({ ollamaBaseUrl: required('OLLAMA_BASE_URL') });
    if (modelDigestAfter !== modelDigestBefore) throw new Error('Model digest changed during CSRF qualification');
    if (readiness) fs.writeFileSync(`${readiness}.final`, JSON.stringify({ version: 1,
      modelDigestBefore, modelDigestAfter, modelCalls: fixture.network.counters.modelCalls,
      counters: fixture.network.counters }) + '\n', { mode: 0o600 });
  } catch (error) { failures.push(error); }
  // Stop admission first so no request can enter while dependencies close.
  if (server) {
    try { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
    catch (error) { failures.push(error); }
  }
  try { fixture.network.restore(); } catch (error) { failures.push(error); }
  try { fixture.restoreBrowserRecorder?.(); } catch (error) { failures.push(error); }
  try { await fixture.provider?.transport?.close?.(); } catch (error) { failures.push(error); }
  try { await fixture.csrfRoutes?.closeBrowser?.(); } catch (error) { failures.push(error); }
  try { await require('../../server/database/postgres').closePostgresPools(); } catch (error) { failures.push(error); }
  for (const pool of pools || []) {
    try { await pool.end(); } catch (error) { failures.push(error); }
  }
  if (failures.length) throw new AggregateError(failures, 'CSRF composed fixture shutdown failed');
}

async function main() {
  const { Pool } = require('pg');
  const pools = [
    new Pool({ connectionString: required('PG_CSRF_EMAIL_COMPOSED_IDENTITY_RUNTIME_URL'), max: 8 }),
    new Pool({ connectionString: required('PG_CSRF_EMAIL_COMPOSED_IDENTITY_MIGRATION_URL'), max: 2 }),
    new Pool({ connectionString: required('PG_CSRF_EMAIL_COMPOSED_CSRF_RUNTIME_URL'), max: 8 }),
    new Pool({ connectionString: required('PG_CSRF_EMAIL_COMPOSED_CSRF_MIGRATION_URL'), max: 2 }),
  ];
  let fixture; let server; let readiness; let modelDigestBefore;
  try {
    const [identityRuntime, identityMigration, csrfRuntime, csrfMigration] = pools;
    const ownerPassword = required('CSRF_EMAIL_COMPOSED_OWNER_PASSWORD');
    const siblingPassword = required('CSRF_EMAIL_COMPOSED_SIBLING_PASSWORD');
    assertDistinctPasswordInputs(ownerPassword, siblingPassword);
    fixture = await createCsrfEmailApp({ identityRuntime, identityMigration, csrfRuntime, csrfMigration,
      jwtSecret: required('JWT_SECRET'),
      mailpit: configureMailpit({ apiUrl: required('CSRF_EMAIL_COMPOSED_MAILPIT_API_URL'),
        smtpHost: process.env.MAILPIT_SMTP_HOST || '127.0.0.1', smtpPort: Number(required('MAILPIT_SMTP_PORT')),
        hmacSecret: required('IPI_MAIL_HMAC_SECRET') }),
      modelMaxCalls: Number(process.env.CSRF_EMAIL_COMPOSED_MAX_MODEL_CALLS || 20) });
    const bcrypt = require('bcryptjs');
    const ownerPasswordHash = await bcrypt.hash(ownerPassword, 4);
    const siblingPasswordHash = await bcrypt.hash(siblingPassword, 4);
    assertDistinctPasswordHashes(ownerPasswordHash, siblingPasswordHash);
    await fixture.identity.createUser({ username: required('CSRF_EMAIL_COMPOSED_OWNER_USER'), email: 'csrf-composed-owner@fixture.invalid', passwordHash: ownerPasswordHash });
    await fixture.identity.createUser({ username: required('CSRF_EMAIL_COMPOSED_SIBLING_USER'), email: 'csrf-composed-sibling@fixture.invalid', passwordHash: siblingPasswordHash });
    const build = path.resolve(__dirname, '../../client/build');
    if (!fs.existsSync(path.join(build, 'index.html'))) throw new Error('Copied production client build required');
    validateShutdownDependencies(fixture, pools);
    fixture.app.use(express.static(build));
    fixture.app.get('/{*path}', (_req, res) => res.sendFile(path.join(build, 'index.html')));
    server = await new Promise((resolve, reject) => {
      const value = fixture.app.listen(0, '127.0.0.1');
      value.once('error', reject);
      value.once('listening', () => resolve(value));
    });
    readiness = required('CSRF_EMAIL_COMPOSED_READINESS_FILE');
    modelDigestBefore = await readModelDigest({ ollamaBaseUrl: required('OLLAMA_BASE_URL') });
    fs.writeFileSync(readiness, JSON.stringify({ version: 1, pid: process.pid,
      appUrl: `http://127.0.0.1:${server.address().port}`, modelDigestBefore }) + '\n', { mode: 0o600 });
    const close = () => shutdownFixture({ fixture, server, pools, readiness, modelDigestBefore });
    const shutdown = code => close().then(() => process.exit(code)).catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exit(1); });
    process.once('SIGTERM', () => shutdown(0)); process.once('SIGINT', () => shutdown(130));
  } catch (error) {
    try { if (fixture) await shutdownFixture({ fixture, server, pools, readiness, modelDigestBefore }); }
    catch (cleanupError) { error = new AggregateError([error, cleanupError], 'Fixture startup and cleanup failed'); }
    finally { if (!fixture) await Promise.allSettled(pools.map(pool => pool.end())); }
    throw error;
  }
}

if (require.main === module) main().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });

module.exports = { createCsrfEmailApp, shutdownFixture, main, required,
  validateShutdownDependencies, assertDistinctPasswordHashes, assertDistinctPasswordInputs,
  installBrowserLaunchRecorder };
