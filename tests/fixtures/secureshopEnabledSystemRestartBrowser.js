'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { qualifySystemRestartBrowser } = require('./secureshopSystemRestartBrowser');
const { configurePage } = require('./fullBackendRenderedSecureShop');

async function qualifyEnabledSystemRestartBrowser({ origin, user, password, root, readOperation, signal }) {
  assert.equal(typeof readOperation, 'function');
  const browser = await require('puppeteer').launch({ headless: true,
    userDataDir: path.join(root, 'system-restart-browser'), args: ['--disable-background-networking'] });
  const blocked = [], errors = [];
  const close = () => browser.close().catch(() => {});
  signal?.addEventListener('abort', close, { once: true });
  let deadline;
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 1100 });
    await configurePage(page, origin, blocked, errors);
    const response = (pathname, method = 'GET') => page.waitForResponse(value => {
      const url = new URL(value.url());
      return url.origin === origin && url.pathname === pathname && value.request().method() === method;
    }, { timeout: 30000 });
    const frameFor = async () => {
      const element = await page.waitForSelector('iframe[title="SecureShop workshop"]');
      const frame = await element.contentFrame();
      assert.ok(frame); await frame.waitForFunction(() => window.origin === 'null'); return frame;
    };
    const clickText = async (frame, text) => {
      await frame.waitForFunction(label => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === label && !button.disabled), {}, text);
      await frame.evaluate(label => [...document.querySelectorAll('button')]
        .find(button => button.textContent.trim() === label && !button.disabled).click(), text);
    };
    const loginPersona = async (frame, username) => {
      await frame.waitForFunction(() => document.querySelector('#ss-login-user')
        || document.querySelector('a[href="/secureshop/login"]'));
      if (!await frame.$('#ss-login-user')) {
        await frame.evaluate(() => document.querySelector('a[href="/secureshop/login"]')?.click());
        await frame.waitForSelector('#ss-login-user');
      }
      await frame.type('#ss-login-user', username); await frame.type('#ss-login-pw', 'student123');
      const pending = response('/api/secureshop/v2/auth/login', 'POST');
      await frame.click('button[type="submit"]'); const result = await pending;
      assert.equal(result.status(), 200); assert.equal((await result.json()).user.role,
        username === 'student_admin' ? 'admin' : 'customer');
      await frame.waitForSelector('[aria-label="Account menu"]');
    };
    const logoutPersona = async frame => {
      await frame.evaluate(() => document.querySelector('[aria-label="Account menu"]')?.click());
      const pending = response('/api/secureshop/v2/auth/logout', 'POST');
      await clickText(frame, 'Sign out'); assert.equal((await pending).status(), 200);
      await frame.waitForFunction(() => !document.querySelector('[aria-label="Account menu"]')
        && (document.querySelector('#ss-login-user') || document.querySelector('a[href="/secureshop/login"]')));
    };
    const openSystem = async () => {
      const frame = await frameFor(); await frame.waitForSelector('[aria-label="Account menu"]');
      if (!await frame.$('a[href="/secureshop/admin/system"]')) {
        await frame.evaluate(() => document.querySelector('a[href="/secureshop/admin"]')?.click());
        await frame.waitForSelector('a[href="/secureshop/admin/system"]');
      }
      await frame.evaluate(() => document.querySelector('a[href="/secureshop/admin/system"]')?.click());
      await frame.waitForSelector('[data-testid="system-restart-panel"]');
      return frame;
    };
    await page.goto(origin + '/workshop-login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[placeholder="Enter your username"]');
    await page.type('input[placeholder="Enter your username"]', user.username);
    await page.type('input[placeholder="Enter your password"]', password);
    const login = response('/api/auth/login', 'POST');
    await page.click('button[type="submit"]'); assert.equal((await login).status(), 200);
    await page.waitForFunction(() => Boolean(localStorage.getItem('token')));
    await page.goto(origin + '/workshop/secureshop', { waitUntil: 'domcontentloaded' });
    let frame = await frameFor(); await loginPersona(frame, 'student_customer');
    const products = await frame.evaluate(async () => {
      const value = await fetch('/api/secureshop/products?limit=1');
      if (!value.ok) throw new Error('Product target preparation failed'); return value.json();
    });
    assert.ok(Array.isArray(products.products) && products.products.length === 1);
    await logoutPersona(frame); await loginPersona(frame, 'student_admin'); frame = await openSystem();
    await frame.evaluate(() => {
      const input = document.querySelector('[data-testid="system-restart-panel"] input[aria-label="Service name"]');
      if (!input) throw new Error('Restart input unavailable');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, 'nginx; whoami'); input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    assert.equal(await frame.$eval('[data-testid="system-restart-panel"] input[aria-label="Service name"]',
      input => input.value), 'nginx; whoami');
    deadline = setTimeout(close, 150000);
    const result = await qualifySystemRestartBrowser({ page, frame, origin, evidenceDirectory: root,
      reopenSystem: openSystem, readOperation });
    assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
    return Object.freeze({ ...result, opaqueFrame: true });
  } finally {
    clearTimeout(deadline); signal?.removeEventListener('abort', close); await browser.close();
  }
}

module.exports = { qualifyEnabledSystemRestartBrowser };
