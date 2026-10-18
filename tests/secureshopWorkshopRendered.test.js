'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

// This is a real compiled UI / opaque-frame transport test with an owned HTTP
// fixture. It does not claim native database effects or actual actor/Judge work.
test('compiled workshop renders canonical help/progress and replaces its frame after reset', {
  skip: process.env.DVAIA_VERIFY_BUILT_SHOP_FRAME !== '1', timeout: 45000,
}, async t => {
  let server, browser, profile;
  t.after(async () => {
    try { await browser?.close(); }
    finally {
      if (server) await new Promise(resolve => server.close(resolve));
      if (profile) await fs.rm(profile, { recursive: true, force: true });
    }
  });
  const key = 'secureshop_agent_security';
  let generation = 2; let completed = true; const resetKeys = []; const shopRequests = [];
  const launch = () => ({ launchId: '10000000-0000-4000-8000-000000000071', generation,
    credentialVersion: generation + 2, expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString() });
  const objective = () => ({ id: 'ss_loop_observation', label: 'Observe a real tool decision',
    text: 'Observe a real tool decision', completed, hintVisible: true, solutionVisible: false });
  const challenge = () => ({ id: key, workshopKey: key, name: 'SecureShop Agent Security', title: 'SecureShop Agent Security',
    route: '/workshop/secureshop', category: 'ai', difficulty: 'Advanced',
    description: 'Owned browser qualification fixture', showHints: true, showSolutions: false,
    objectives: [objective()], exerciseGroups: [{ id: 'ss_agent_loop', title: 'Observe an agent decision loop',
      objectives: [objective()], objectiveCount: 1, completedObjectiveCount: Number(completed) }],
    totalObjectives: 1, completedObjectives: Number(completed) });
  const app = express(); app.use(express.json());
  app.get('/api/auth/status', (_req, res) => res.json({ authenticated: true,
    user: { id: 17, username: 'browser_fixture', role: 'student', admin_level: 0 } }));
  app.get('/api/workshop/challenges', (_req, res) => res.json({ success: true, challenges: [challenge()] }));
  app.get('/api/workshop/config/snapshot', (_req, res) => res.json({ revision: 1, exercises: {
    [key]: { isVisible: true, showHints: true, showSolutions: false, objectives: {
      ss_loop_observation: { isVisible: true, hintVisible: true, solutionVisible: false },
    } },
  } }));
  app.get('/api/workshop/config/revision', (_req, res) => res.json({ revision: 1 }));
  app.get('/api/changes/revisions', (_req, res) => res.json({ revisions: { workshop_progress: generation } }));
  app.get('/api/ctf/config', (_req, res) => res.json({ enabled: false, show_in_nav: false }));
  app.get(`/api/hints/${key}/ss_loop_observation`, (_req, res) => res.json({ success: true,
    hint: { title: 'Observed effect', hints: ['Inspect the completed tool receipt.'] } }));
  app.get('/api/auth/secureshop-launch', (_req, res) => res.json({ preparationOnly: false, launch: launch() }));
  app.post('/api/auth/secureshop-launch/recover', (_req, res) => res.json({ preparationOnly: false,
    launch: launch(), bearer: String.fromCharCode(97 + generation).repeat(43) }));
  app.post('/api/auth/secureshop-launch/reset', (req, res) => {
    if (req.body.expectedGeneration !== generation) return res.sendStatus(409);
    resetKeys.push(req.body.idempotencyKey); generation++; completed = false;
    return res.json({ cleanupComplete: true, resetId: '20000000-0000-4000-8000-000000000071', launch: launch() });
  });
  app.get('/api/secureshop/products', (req, res) => {
    shopRequests.push({ bearer: req.get('x-dvaia-secureshop-launch'), cookie: req.get('cookie') });
    res.json({ products: [{ id: 1, name: 'Isolated browser fixture product', price: 10,
      category: 'Electronics', stock: 1 }], total: 1 });
  });
  app.use('/api', (_req, res) => res.status(404).json({ error: 'Outside UI fixture' }));
  const clientBuild = path.join(__dirname, '../client/build');
  app.use(express.static(clientBuild, {
    setHeaders: res => res.set('Access-Control-Allow-Origin', '*'),
  }));
  app.get(/.*/, (_req, res) => res.sendFile('index.html', { root: clientBuild }));
  server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-workshop-browser-profile-'));
  browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
    ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) });
  const page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
  await page.setRequestInterception(true);
  page.on('request', request => request.url().startsWith(origin + '/') ? request.continue() : request.abort());
  await page.evaluateOnNewDocument(() => {
    try { localStorage.setItem('token', 'owned-browser-fixture-token'); } catch {}
  });
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => {
    if (message.text().startsWith('ErrorBoundary caught')) {
      void message.args()[1]?.evaluate(error => error.stack || error.message || String(error)).then(value => errors.push(value));
    }
  });
  await page.goto(`${origin}/workshop/secureshop`);
  await page.waitForFunction(() => document.body.textContent.includes('1 of 1 objectives completed'), { timeout: 10000 }).catch(async error => {
    t.diagnostic(JSON.stringify({ url: page.url(), body: await page.evaluate(() => document.body.textContent), errors }));
    throw error;
  });
  const oldFrame = await page.$('iframe[title="SecureShop workshop"]');
  const content = await oldFrame.contentFrame();
  await content.waitForFunction(() => document.body.textContent.includes('Isolated browser fixture product'));
  await page.evaluate(() => [...document.querySelectorAll('button')].find(button => button.textContent === 'Hint').click());
  await page.waitForFunction(() => document.querySelector('[role="dialog"]')?.textContent.includes('Inspect the completed tool receipt.'));
  await page.keyboard.press('Escape');
  await page.evaluate(() => [...document.querySelectorAll('button')].find(button => button.textContent.includes('Reset launch')).click());
  await page.waitForFunction(() => document.body.textContent.includes('0 of 1 objectives completed'));
  assert.equal(await oldFrame.evaluate(frame => frame.isConnected), false);
  assert.equal(resetKeys.length, 1); assert.match(resetKeys[0], /^[a-f0-9-]{36}$/);
  const nextFrame = await (await page.$('iframe[title="SecureShop workshop"]')).contentFrame();
  await nextFrame.waitForFunction(() => document.body.textContent.includes('Isolated browser fixture product'));
  assert.equal(await nextFrame.evaluate(() => window.origin), 'null');
  assert.ok(shopRequests.some(request => request.bearer === 'c'.repeat(43)));
  assert.ok(shopRequests.some(request => request.bearer === 'd'.repeat(43)));
  assert.ok(shopRequests.every(request => request.cookie === undefined));
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.deepEqual(errors, []);
  const artifacts = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-workshop-rendered-'));
  await page.screenshot({ path: path.join(artifacts, 'workshop.png'), fullPage: true });
  t.diagnostic(`UI fixture screenshot: ${path.join(artifacts, 'workshop.png')}; no native/model effect claim`);
});
