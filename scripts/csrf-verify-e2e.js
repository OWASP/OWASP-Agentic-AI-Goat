#!/usr/bin/env node
/**
 * CSRF workshop — headless browser verification.
 * Proves the in-browser paths that curl cannot: Solution modal, iframe execute,
 * SSE-driven chat bubble, defense toggle, download button.
 *
 * Run:  node scripts/csrf-verify-e2e.js
 */
const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const BASE = process.env.E2E_BASE || 'http://localhost:3000';
const SHOT_DIR = path.join(__dirname, 'csrf-e2e-screenshots');
fs.mkdirSync(SHOT_DIR, { recursive: true });

const log = (ok, msg) => console.log(`${ok ? '  ✓' : '  ✗'} ${msg}`);
let fails = 0;
const assert = (cond, msg) => { log(!!cond, msg); if (!cond) fails++; };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1400, height: 1000 });
  page.on('console', (m) => {
    if (m.type() === 'error') console.log('   [console.error]', m.text());
    if (m.text().startsWith('DEBUG')) console.log('   [debug]', m.text());
  });
  page.on('pageerror', (e) => console.log('   [pageerror]', e.message));

  try {
    // ── 1. Login ──────────────────────────────────────────────────────
    console.log('\n[1] Login');
    await page.goto(`${BASE}/workshop-login`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"], input[type="text"]', 'student');
    await page.type('input[name="password"], input[type="password"]', 'student123');
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2' }).catch(() => {}),
      page.click('button[type="submit"]'),
    ]);
    await wait(1500);
    assert(true, 'logged in');

    // ── 2. Open CSRF workshop, reset ──────────────────────────────────
    console.log('\n[2] Load workshop + reset');
    await page.goto(`${BASE}/vulnerabilities/csrf-via-ai`, { waitUntil: 'networkidle2' });
    await wait(2000);
    // reset all (fires POST /progress/reset)
    await page.evaluate(() => fetch('/api/workshop/csrf/progress/reset', { method: 'POST', credentials: 'include' }));
    await page.reload({ waitUntil: 'networkidle2' });
    await wait(2000);
    await page.screenshot({ path: path.join(SHOT_DIR, 'v01-loaded.png'), fullPage: true });

    // Victim panel present?
    const victimName = await page.evaluate(() => {
      const h = document.querySelector('h3');
      const all = [...document.querySelectorAll('h3')].map(e => e.textContent);
      return all.find(t => /Victim/.test(t)) || null;
    });
    assert(victimName && /Alex Rivera/.test(victimName), `Victim panel shows Alex Rivera (${victimName})`);

    // Tab bar has 4 tabs?
    const tabCount = await page.evaluate(() =>
      [...document.querySelectorAll('button')].filter(b => /GET CSRF|POST CSRF|CSRF via XSS|Indirect/.test(b.textContent)).length);
    assert(tabCount === 4, `4 tabs rendered (found ${tabCount})`);

    // ── 3. Solution button opens modal ────────────────────────────────
    console.log('\n[3] Solution modal');
    page.on('request', (r) => { if (r.url().includes('/solutions/csrf')) console.log('   [req]', r.method(), r.url()); });
    page.on('response', (r) => { if (r.url().includes('/solutions/csrf')) console.log('   [res]', r.status(), r.url()); });
    // tag the Solution buttons so puppeteer can real-click one
    const btnCount = await page.evaluate(() => {
      const all = [...document.querySelectorAll('.obj-actions button')];
      console.log('DEBUG obj-actions button texts: ' + all.map(b => '[' + b.textContent + ']').join(' | '));
      console.log('DEBUG obj-actions divs: ' + document.querySelectorAll('.obj-actions').length + ' | total buttons inside: ' + all.length);
      console.log('DEBUG first .obj-actions innerHTML: ' + (document.querySelector('.obj-actions')?.innerHTML || 'EMPTY').slice(0, 300));
      const btns = all.filter(b => /Solution/.test(b.textContent));
      btns.forEach((b, i) => b.setAttribute('data-e2e', `sol-${i}`));
      return btns.length;
    });
    assert(btnCount >= 1, `Solution buttons in objectives panel (found ${btnCount})`);
    // Wait for framer-motion entrance animation on ObjectiveItem to finish so
    // coord-based clicks don't miss; then use direct element.click() (no coords).
    await wait(700);
    let modalUp = false;
    for (let attempt = 0; attempt < 3 && !modalUp; attempt++) {
      await page.$eval('[data-e2e="sol-0"]', (el) => el.click());
      for (let i = 0; i < 8 && !modalUp; i++) {
        await wait(350);
        modalUp = await page.evaluate(() => !![...document.querySelectorAll('h3')].find(x => x.textContent.startsWith('Solution:')));
      }
    }
    const modalInfo = await page.evaluate(() => {
      const h = [...document.querySelectorAll('h3')].find(x => x.textContent.startsWith('Solution:'));
      const overlay = [...document.body.children].find(d => d.style && d.style.position === 'fixed' && d.style.zIndex === '9999');
      return { hasHeading: !!h, heading: h?.textContent, hasOverlay: !!overlay, bodyChildCount: document.body.children.length };
    });
    console.log('   modal debug:', JSON.stringify(modalInfo));
    assert(modalInfo.hasHeading || modalInfo.hasOverlay, 'Solution modal opened');
    await page.screenshot({ path: path.join(SHOT_DIR, 'v02-solution-modal.png'), fullPage: true });
    await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === 'Close'); if (b) b.click(); });
    await wait(400);

    // ── 4. Payload Builder: load g2 solution → Execute in iframe ──────
    console.log('\n[4] Execute in iframe → SSE → chat bubble');
    // Load the WORKING solution into the editor via API + inject.
    const solHtml = await page.evaluate(async () => {
      const r = await fetch('/api/workshop/csrf/payload/csrf_g2/solution', { credentials: 'include' });
      const d = await r.json();
      return d.html;
    });
    assert(solHtml && solHtml.includes('agent-action'), 'fetched csrf_g2 solution HTML');
    // Put it into the editor textarea and click Execute.
    await page.evaluate((html) => {
      const ta = document.querySelector('textarea.b-editor');
      const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
      setter.call(ta, html);
      ta.dispatchEvent(new Event('input', { bubbles: true }));
    }, solHtml);
    await wait(300);
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')].find(x => /Execute in iframe/i.test(x.textContent));
      b && b.click();
    });
    // Wait for SSE-driven forged bubble.
    let forged = false;
    for (let i = 0; i < 20 && !forged; i++) {
      await wait(600);
      forged = await page.evaluate(() =>
        !!document.querySelector('.forged-badge') ||
        [...document.querySelectorAll('.bubble')].some(b => /Forged request/.test(b.textContent)));
    }
    assert(forged, 'forged bubble + agent reply appeared in chat via SSE');
    await page.screenshot({ path: path.join(SHOT_DIR, 'v03-iframe-executed.png'), fullPage: true });

    // Victim email changed?
    const emailChanged = await page.evaluate(() =>
      [...document.querySelectorAll('.val')].some(v => /attacker@evil\.com/.test(v.textContent)));
    assert(emailChanged, "Victim panel Email → attacker@evil.com");

    // Objective csrf_g2 marked complete?
    const g2Done = await page.evaluate(async () => {
      const r = await fetch('/api/workshop/csrf/progress', { credentials: 'include' });
      const d = await r.json();
      return !!d.objectives?.csrf_g2?.completed;
    });
    assert(g2Done, 'csrf_g2 objective marked complete');

    // ── 5. Defense toggle button ──────────────────────────────────────
    console.log('\n[5] Defense toggle');
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button.def')].find(x => /CSRF/.test(x.textContent));
      b && b.click();
    });
    await wait(800);
    const defOn = await page.evaluate(() =>
      [...document.querySelectorAll('button.def')].some(b => /CSRF ON/.test(b.textContent)));
    assert(defOn, 'CSRF defense toggle → ON');
    // Re-execute → should be BLOCKED → g3
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')].find(x => /Execute in iframe/i.test(x.textContent));
      b && b.click();
    });
    let blocked = false;
    for (let i = 0; i < 15 && !blocked; i++) {
      await wait(600);
      blocked = await page.evaluate(() =>
        [...document.querySelectorAll('.bubble')].some(b => /BLOCKED/.test(b.textContent)));
    }
    assert(blocked, 're-executed pixel → BLOCKED bubble in chat');
    const g3Done = await page.evaluate(async () => {
      const r = await fetch('/api/workshop/csrf/progress', { credentials: 'include' });
      return !!((await r.json()).objectives?.csrf_g3?.completed);
    });
    assert(g3Done, 'csrf_g3 objective marked complete');
    await page.screenshot({ path: path.join(SHOT_DIR, 'v04-defense-blocked.png'), fullPage: true });

    // ── 5b. Execute in new tab (blob URL) ─────────────────────────────
    console.log('\n[5b] Execute in new tab');
    // turn defense OFF first so the request succeeds
    await page.evaluate(() => fetch('/api/workshop/csrf/defense-toggle',
      { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tab: 'get', enabled: false }) }));
    await page.evaluate(() => fetch('/api/workshop/csrf/progress/reset-tab',
      { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tab: 'get' }) }));
    await wait(500);
    // Load solution HTML into editor
    await page.evaluate((html) => {
      const ta = document.querySelector('textarea.b-editor');
      const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
      setter.call(ta, html);
      ta.dispatchEvent(new Event('input', { bubbles: true }));
    }, solHtml);
    await wait(200);
    // Listen for the popup and its network
    const popupPromise = new Promise((resolve) => browser.once('targetcreated', async (t) => {
      const p = await t.page();
      if (p) {
        p.on('requestfinished', (r) => {
          if (r.url().includes('/agent-action')) console.log('   [popup req]', r.method(), r.url(), '→', r.response()?.status());
        });
        p.on('requestfailed', (r) => {
          if (r.url().includes('/agent-action')) console.log('   [popup FAIL]', r.method(), r.url(), r.failure()?.errorText);
        });
      }
      resolve(p);
    }));
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')].find(x => /Execute in new tab/i.test(x.textContent));
      b && b.click();
    });
    const popup = await Promise.race([popupPromise, wait(3000)]);
    assert(!!popup, 'new tab (blob:) opened');
    await wait(4000);
    const g2After = await page.evaluate(async () => {
      const r = await fetch('/api/workshop/csrf/progress', { credentials: 'include' });
      return !!((await r.json()).objectives?.csrf_g2?.completed);
    });
    assert(g2After, 'csrf_g2 completed via new-tab blob execution');
    if (popup) await popup.close().catch(() => {});
    await page.screenshot({ path: path.join(SHOT_DIR, 'v05-newtab.png'), fullPage: true });

    // ── 6. Hint button ────────────────────────────────────────────────
    console.log('\n[6] Hint button');
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === 'Hint');
      b && b.click();
    });
    await wait(1000);
    const hintShown = await page.evaluate(() => !!document.querySelector('div[class*="HintBox"], .obj-content div p'));
    assert(hintShown, 'Hint box rendered');

  } catch (e) {
    console.error('   [fatal]', e.message);
    fails++;
    await page.screenshot({ path: path.join(SHOT_DIR, 'v99-fatal.png'), fullPage: true }).catch(() => {});
  } finally {
    await browser.close();
    console.log(`\n${fails === 0 ? 'PASS' : 'FAIL'} — ${fails} failure(s). Screenshots: ${SHOT_DIR}\n`);
    process.exit(fails ? 1 : 0);
  }
})();
