'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { waitForObservedCount } = require('./helpers/waitForObservedCount');

test('built parent drives login, stored review retry and launch reset through the opaque frame', {
  skip: process.env.DVAIA_VERIFY_BUILT_SHOP_FRAME !== '1', timeout: 45000,
}, async t => {
  let server; let browser; let profile;
  t.after(async () => {
    try { await browser?.close(); }
    finally {
      if (server) await new Promise(resolve => server.close(resolve));
      if (profile) await fs.rm(profile, { recursive: true, force: true });
    }
  });
  const workshop = 'secureshop_agent_security';
  const objectiveId = 'ss_stored_browser_execution';
  const launchId = '10000000-0000-4000-8000-000000000091';
  const platformToken = 'owned-parent-platform-token';
  const shopToken = 'owned-parent-shop-token';
  const payload = '<img src="/owned-parent-missing.png" onerror="alert(\'owned-parent-frame\')">';
  let generation = 1; let stored = null; let completed = false; let reviewPosts = 0;
  let dropAttempt = true; const attempts = [];
  const launch = () => ({ launchId, generation, credentialVersion: generation,
    expiresAt: new Date(Date.now() + 30 * 60000).toISOString() });
  const objective = () => ({ id: objectiveId, label: 'Execute a stored review in ReviewCard',
    text: 'Execute a stored review in ReviewCard', completed,
    hintVisible: false, solutionVisible: false });
  const challenge = () => ({ id: workshop, workshopKey: workshop,
    name: 'SecureShop Agent Security', title: 'SecureShop Agent Security',
    route: '/workshop/secureshop', showHints: false, showSolutions: false,
    objectives: [objective()], exerciseGroups: [{ id: 'ss_browser_sink',
      title: 'Stored browser execution', objectives: [objective()], objectiveCount: 1,
      completedObjectiveCount: Number(completed) }], totalObjectives: 1,
    completedObjectives: Number(completed) });

  const app = express(); app.use(express.json());
  app.get('/api/auth/status', (_req, res) => res.json({ authenticated: true,
    user: { id: 91, username: 'parent_fixture', role: 'student', admin_level: 0 } }));
  app.get('/api/workshop/challenges', (_req, res) => res.json({ success: true,
    challenges: [challenge()] }));
  app.get('/api/workshop/config/snapshot', (_req, res) => res.json({ revision: generation,
    exercises: { [workshop]: { isVisible: true, showHints: false, showSolutions: false,
      objectives: { [objectiveId]: { isVisible: true, hintVisible: false,
        solutionVisible: false } } } } }));
  app.get('/api/workshop/config/revision', (_req, res) => res.json({ revision: generation }));
  app.get('/api/changes/revisions', (_req, res) => res.json({ revisions: {
    workshop_progress: generation * 10 + Number(completed) } }));
  app.get('/api/ctf/config', (_req, res) => res.json({ enabled: false, show_in_nav: false }));
  app.get('/api/auth/secureshop-launch', (_req, res) => res.json({ preparationOnly: false,
    launch: launch() }));
  app.post('/api/auth/secureshop-launch/recover', (_req, res) => res.json({ preparationOnly: false,
    launch: launch(), bearer: String.fromCharCode(96 + generation).repeat(43) }));
  app.post('/api/auth/secureshop-launch/reset', (req, res) => {
    if (req.body.launchId !== launchId || req.body.expectedGeneration !== generation) {
      return res.sendStatus(409);
    }
    generation += 1; stored = null; completed = false;
    return res.json({ cleanupComplete: true,
      resetId: '20000000-0000-4000-8000-000000000091', launch: launch() });
  });
  app.use('/api/secureshop', (req, res, next) => {
    if (req.get('x-dvaia-secureshop-launch')
      !== String.fromCharCode(96 + generation).repeat(43)) return res.sendStatus(401);
    next();
  });
  app.post('/api/secureshop/v2/auth/login', (_req, res) => res.json({ token: shopToken,
    expiresAt: new Date(Date.now() + 30 * 60000).toISOString(),
    user: { id: 11, username: 'student_customer', role: 'customer',
      email: 'student_customer@fixture.invalid', full_name: 'Student Customer' } }));
  app.get('/api/secureshop/v2/auth/whoami', (req, res) =>
    req.get('authorization') === `Bearer ${shopToken}` ? res.json({
      expiresAt: new Date(Date.now() + 30 * 60000).toISOString(),
      user: { id: 11, username: 'student_customer', role: 'customer',
        email: 'student_customer@fixture.invalid', full_name: 'Student Customer' },
    }) : res.sendStatus(401));
  const product = { id: 7, name: 'Owned parent product', description: 'Factual product feedback.',
    price: 10, category: 'Home', stock_quantity: 4, images: [] };
  app.get('/api/secureshop/products', (_req, res) => res.json({ products: [product], total: 1 }));
  app.get('/api/secureshop/products/7', (_req, res) => res.json({ product }));
  app.post('/api/secureshop/products/7/summary', (_req, res) => res.json({ summary: 'Owned summary.' }));
  app.get('/api/secureshop/products/7/similar', (_req, res) => res.json({ results: [] }));
  app.get('/api/secureshop/products/7/reviews', (_req, res) => res.json({
    reviews: stored ? [stored] : [] }));
  app.post('/api/secureshop/products/7/reviews', (req, res) => {
    reviewPosts += 1;
    stored = { id: 51, body: req.body.body, rating: req.body.rating,
      status: 'pending', created_at: '2026-09-13T00:00:00Z' };
    res.json({ ok: true, review_id: 51 });
  });
  app.post('/api/secureshop/products/7/reviews/51/browser-attempt', async (req, res) => {
    attempts.push(req.body); completed = true;
    await new Promise(resolve => setTimeout(resolve, 10000));
    if (dropAttempt) { dropAttempt = false; return res.socket.destroy(); }
    return res.json({ completed: true });
  });
  app.use('/api', (_req, res) => res.status(404).json({ error: 'Outside parent fixture' }));
  const clientBuild = path.join(__dirname, '../client/build');
  app.use(express.static(clientBuild, {
    setHeaders: res => res.set('Access-Control-Allow-Origin', '*'),
  }));
  app.get(/.*/, (_req, res) => res.sendFile('index.html', { root: clientBuild }));
  server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-parent-review-frame-'));
  browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
    ...(process.env.PUPPETEER_EXECUTABLE_PATH
      ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) });
  const page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
  const uiDialogs = [];
  page.on('dialog', dialog => {
    uiDialogs.push(dialog.message());
    dialog.dismiss().catch(() => {});
  });
  await page.setRequestInterception(true);
  page.on('request', request => request.url().startsWith(`${origin}/`)
    ? request.continue() : request.abort());
  await page.evaluateOnNewDocument(token => {
    try { if (window.parent === window) localStorage.setItem('token', token); } catch {}
  }, platformToken);
  await page.goto(`${origin}/workshop/secureshop`);
  await page.waitForFunction(() => document.body.textContent.includes('0 of 1 objectives completed'));
  const oldFrameElement = await page.$('iframe[title="SecureShop workshop"]');
  const frame = await oldFrameElement.contentFrame();
  await frame.waitForSelector('a[href="/secureshop/login"]');
  await frame.click('a[href="/secureshop/login"]');
  await frame.waitForSelector('#ss-login-user');
  await frame.type('#ss-login-user', 'student_customer');
  await frame.type('#ss-login-pw', 'student123');
  await frame.click('button[type="submit"]');
  await frame.waitForSelector('button[aria-label="Account menu"]');
  await frame.click('a[href="/secureshop/catalog"]');
  await frame.waitForSelector('a[href^="/secureshop/product/"]');
  await frame.evaluate(() => document.querySelector('a[href^="/secureshop/product/"]').click());
  await frame.waitForSelector('textarea[aria-label="Review body"]');
  await frame.$eval('textarea[aria-label="Review body"]', (textarea, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
    setter.call(textarea, value); textarea.dispatchEvent(new Event('input', { bubbles: true }));
  }, payload);
  await frame.waitForFunction(value => {
    const textarea = document.querySelector('textarea[aria-label="Review body"]');
    return textarea?.value === value
      && textarea.closest('form')?.querySelector('button[type="submit"]')?.disabled === false;
  }, {}, payload);
  await frame.$eval('textarea[aria-label="Review body"]', textarea =>
    textarea.closest('form').querySelector('button[type="submit"]').click());
  await waitForObservedCount({ read: () => attempts.length, expected: 2, timeoutMs: 30000 });
  await frame.waitForFunction(() => document.querySelector('textarea[aria-label="Review body"]')?.value === '');
  assert.equal(reviewPosts, 1); assert.equal(attempts.length, 2);
  assert.equal(attempts[0].request_id, attempts[1].request_id);
  assert.deepEqual(uiDialogs, [], 'the opaque frame sandbox must suppress native modal UI');
  await page.waitForFunction(() => document.body.textContent.includes('1 of 1 objectives completed'));
  await page.evaluate(() => [...document.querySelectorAll('button')]
    .find(button => button.textContent.includes('Reset launch')).click());
  await page.waitForFunction(() => document.body.textContent.includes('0 of 1 objectives completed'));
  assert.equal(await oldFrameElement.evaluate(node => node.isConnected), false);
  const nextFrame = await (await page.$('iframe[title="SecureShop workshop"]')).contentFrame();
  await nextFrame.waitForSelector('a[href="/secureshop/login"]');
  t.diagnostic('Built parent selector/response-loss replay/reset journey reaches the browser assessment endpoint; fixture-only, no native/Judge claim.');
});
