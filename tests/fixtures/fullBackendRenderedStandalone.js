'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

const SHOP_SESSION = '/api/secureshop/auth/session';
const PLATFORM_STATUS = '/api/auth/status';

function futureExpiry(value, label) {
  const at = Date.parse(value);
  assert.ok(Number.isFinite(at) && at > Date.now(), `${label} needs a real future expiry`);
  return at;
}

async function pause(ms, signal) {
  signal?.throwIfAborted();
  await new Promise((resolve, reject) => {
    const timer = setTimeout(done, ms);
    function done() { signal?.removeEventListener('abort', abort); resolve(); }
    function abort() { clearTimeout(timer); signal?.removeEventListener('abort', abort); reject(signal.reason || Error('Rendered qualification aborted')); }
    signal?.addEventListener('abort', abort, { once: true });
  });
}

async function shopSession(page) {
  return page.evaluate(async path => {
    const response = await fetch(path, { cache: 'no-store' });
    return { status: response.status, body: await response.json() };
  }, SHOP_SESSION);
}

async function platformStatus(page) {
  return page.evaluate(async path => {
    const token = localStorage.getItem('token');
    const response = await fetch(path, { cache: 'no-store',
      headers: token ? { authorization: `Bearer ${token}` } : {} });
    return { status: response.status, body: await response.json() };
  }, PLATFORM_STATUS);
}

async function waitForActualExpiry({ read, page, expiresAt, signal, label }) {
  const expiry = futureExpiry(expiresAt, label);
  assert.ok(expiry - Date.now() <= 300000, `${label} expiry exceeds rendered cohort bound`);
  const deadline = expiry + 20000;
  while (Date.now() < deadline) {
    signal?.throwIfAborted();
    const result = await read(page);
    assert.equal(result.status, 200, `${label} status must remain readable`);
    if (result.body.authenticated === false) {
      assert.ok(Date.now() >= expiry - 1500, `${label} ended before its configured lifetime`);
      return;
    }
    assert.equal(result.body.authenticated, true);
    await pause(Math.min(1000, Math.max(100, expiry - Date.now())), signal);
  }
  throw Error(`${label} remained authenticated after its natural expiry`);
}

async function responseFor(page, pathname, method, trigger) {
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === pathname && response.request().method() === method;
  }, { timeout: 20000 });
  pending.catch(() => {});
  await trigger();
  return pending;
}

async function clickExactButton(frame, label) {
  await frame.waitForFunction(text => {
    const found = [...document.querySelectorAll('button')].filter(button => button.textContent.trim() === text
      && !button.disabled && button.getClientRects().length);
    if (found.length !== 1) return false;
    const button = found[0];
    button.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const rect = button.getBoundingClientRect();
    const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
    if (hit !== button && !button.contains(hit)) return false;
    button.setAttribute('data-standalone-rendered-control', 'selected');
    return true;
  }, {}, label);
  try { await frame.click('[data-standalone-rendered-control="selected"]'); }
  finally { await frame.evaluate(() => document.querySelector('[data-standalone-rendered-control="selected"]')
    ?.removeAttribute('data-standalone-rendered-control')).catch(() => {}); }
}

async function boundShopFrame(page) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    const handle = await page.waitForSelector('iframe[title="SecureShop"]',
      { visible: true, timeout: remaining });
    const frame = await handle.contentFrame();
    assert.ok(frame, 'Owned SecureShop frame must load');
    const isCurrent = () => handle.evaluate(element => element.isConnected
      && document.querySelector('iframe[title="SecureShop"]') === element).catch(() => false);
    try {
      await frame.waitForSelector('button[aria-label="Account menu"]',
        { visible: true, timeout: Math.max(1, deadline - Date.now()) });
      if (await isCurrent()) return frame;
    } catch (error) {
      // A legitimate shop renewal replaces the entire bound frame. Continue
      // only when this exact frame was detached; a stable auth/UI failure stays fatal.
      if (!frame.isDetached() && await isCurrent()) throw error;
    } finally { await handle.dispose().catch(() => {}); }
  }
  throw new Error('Current SecureShop frame did not show the account menu before the original deadline');
}

async function qualifyCustomerComposerLayout(page, evidenceRoot) {
  assert.ok(path.isAbsolute(evidenceRoot));
  const previousViewport = page.viewport();
  let frame;
  try {
    await page.setViewport({ width: 1280, height: 520 });
    frame = await boundShopFrame(page);
    await frame.select('select[id^="agent-lane-task-customer-"]', 'chat');
    const textarea = await frame.waitForSelector('[data-testid="customer-chat-composer-slot"] textarea',
      { visible: true });
    await frame.evaluate(() => {
      const log = document.querySelector('[role="log"][aria-label="Customer conversation"]');
      if (!log) throw Error('Customer conversation unavailable');
      // Layout stress only: inert text is not a chat turn, model reply, or effect.
      const stress = document.createElement('div');
      stress.id = 'q01-layout-stress';
      stress.setAttribute('aria-hidden', 'true');
      stress.style.whiteSpace = 'pre-wrap';
      stress.textContent = Array.from({ length: 60 }, (_, index) => `Layout row ${index + 1}`).join('\n');
      log.appendChild(stress);
    });
    const measure = () => frame.evaluate(() => {
      const lane = document.querySelector('aside[aria-label="Agent activity lane"]');
      const body = lane?.querySelector('.ss-lane__body');
      const slot = lane?.querySelector('[data-testid="customer-chat-composer-slot"]');
      const input = slot?.querySelector('textarea');
      const send = slot?.querySelector('button[type="submit"]');
      if (!body || !slot || !input || !send) return null;
      const footer = slot.getBoundingClientRect();
      const field = input.getBoundingClientRect();
      const button = send.getBoundingClientRect();
      const hit = document.elementFromPoint(button.x + button.width / 2,
        button.y + button.height / 2);
      return { scrollTop: body.scrollTop, scrollHeight: body.scrollHeight,
        clientHeight: body.clientHeight, footerTop: footer.top, footerBottom: footer.bottom,
        field: { left: field.left, right: field.right, top: field.top, bottom: field.bottom },
        button: { left: button.left, right: button.right, top: button.top, bottom: button.bottom },
        viewportWidth: innerWidth, viewportHeight: innerHeight,
        outsideScrollBody: !body.contains(slot),
        hitSend: hit === send || send.contains(hit),
        label: send.textContent.trim() };
    });
    const parentVisibility = state => page.evaluate(child => {
      const iframe = document.querySelector('iframe[title="SecureShop"]');
      if (!iframe || !iframe.clientWidth || !iframe.clientHeight
        || !iframe.offsetWidth || !iframe.offsetHeight) return null;
      const rect = iframe.getBoundingClientRect();
      const scaleX = rect.width / iframe.offsetWidth;
      const scaleY = rect.height / iframe.offsetHeight;
      const project = box => {
        const left = rect.left + (iframe.clientLeft
          + box.left * iframe.clientWidth / child.viewportWidth) * scaleX;
        const right = rect.left + (iframe.clientLeft
          + box.right * iframe.clientWidth / child.viewportWidth) * scaleX;
        const top = rect.top + (iframe.clientTop
          + box.top * iframe.clientHeight / child.viewportHeight) * scaleY;
        const bottom = rect.top + (iframe.clientTop
          + box.bottom * iframe.clientHeight / child.viewportHeight) * scaleY;
        const hit = document.elementFromPoint((left + right) / 2, (top + bottom) / 2);
        return { insideViewport: left >= 0 && right <= innerWidth && top >= 0 && bottom <= innerHeight,
          hitIframe: hit === iframe };
      };
      return { field: project(child.field), button: project(child.button) };
    }, state);
    await frame.evaluate(() => { document.querySelector('.ss-lane__body').scrollTop = 0; });
    const before = await measure();
    assert.ok(before && before.scrollHeight > before.clientHeight + 100,
      'Inert history stress must make the actual lane body scroll');
    await frame.evaluate(() => {
      const body = document.querySelector('.ss-lane__body');
      body.scrollTop = body.scrollHeight;
    });
    const after = await measure();
    assert.ok(after && after.scrollTop > 0);
    for (const state of [before, after]) {
      assert.equal(state.outsideScrollBody, true);
      assert.equal(state.label, 'Send to customer agent');
      assert.equal(state.hitSend, true);
      assert.ok(state.field.top >= 0 && state.field.bottom <= state.viewportHeight);
      assert.ok(state.button.top >= 0 && state.button.bottom <= state.viewportHeight);
      const parent = await parentVisibility(state);
      assert.deepEqual(parent, { field: { insideViewport: true, hitIframe: true },
        button: { insideViewport: true, hitIframe: true } },
      'The top page must leave both customer composer controls visible and reachable');
    }
    assert.ok(Math.abs(after.footerTop - before.footerTop) <= 1
      && Math.abs(after.footerBottom - before.footerBottom) <= 1,
    'Scrolling conversation must leave the customer composer fixed in the lane');
    await textarea.click();
    await textarea.type('Layout-only draft');
    await page.keyboard.down('Shift');
    try { await page.keyboard.press('Enter'); }
    finally { await page.keyboard.up('Shift'); }
    assert.equal(await textarea.evaluate(node => node.value), 'Layout-only draft\n');
    const screenshot = await page.screenshot({ type: 'png' });
    await fs.writeFile(path.join(evidenceRoot, 'q01-customer-composer-short-viewport.png'),
      screenshot, { flag: 'wx', mode: 0o600 });
  } finally {
    if (frame) await frame.evaluate(() => document.querySelector('#q01-layout-stress')?.remove())
      .catch(() => {});
    if (previousViewport) await page.setViewport(previousViewport);
  }
}

async function qualifyCustomerMobileComposer(page, evidenceRoot) {
  assert.ok(path.isAbsolute(evidenceRoot));
  const previousViewport = page.viewport();
  let frame;
  let stage = 'open-drawer';
  try {
    await page.setViewport({ width: 478, height: 640 });
    frame = await boundShopFrame(page);
    await frame.waitForSelector('button[aria-label="Open agent lane"]', { visible: true });
    await frame.click('button[aria-label="Open agent lane"]');
    await frame.waitForSelector('.ss-lane-mobile-content select[id^="agent-lane-task-customer-mobile"]',
      { visible: true });
    await frame.evaluate(() => {
      const body = document.querySelector('.ss-lane-mobile-content .ss-lane__body');
      if (!body) throw new Error('Mobile agent lane history unavailable');
      // The preceding desktop layout check leaves this same lane scrolled to its end.
      body.scrollTop = 0;
    });
    await frame.waitForFunction(() => {
      const select = document.querySelector('.ss-lane-mobile-content select[id^="agent-lane-task-customer-mobile"]');
      if (!select) return false;
      const rect = select.getBoundingClientRect();
      const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return rect.top >= 0 && rect.bottom <= innerHeight && (hit === select || select.contains(hit));
    });
    await frame.select('.ss-lane-mobile-content select[id^="agent-lane-task-customer-mobile"]', 'chat');
    await frame.waitForFunction(() => document.querySelector(
      '.ss-lane-mobile-content select[id^="agent-lane-task-customer-mobile"]')?.value === 'chat');
    stage = 'focus-composer';
    const textareaSelector = '.ss-lane-mobile-content [data-testid="customer-chat-composer-slot"] textarea';
    const textarea = await frame.waitForSelector(
      textareaSelector, { visible: true });
    const deadline = Date.now() + 20000;
    await frame.waitForFunction(selector => {
      const input = document.querySelector(selector);
      if (!input || !input.getClientRects().length) return false;
      const rect = input.getBoundingClientRect();
      const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return rect.width > 0 && rect.height > 0 && rect.left >= 0 && rect.right <= innerWidth
        && rect.top >= 0 && rect.bottom <= innerHeight && (hit === input || input.contains(hit));
    }, { timeout: Math.max(1, deadline - Date.now()) }, textareaSelector);
    await frame.locator(textareaSelector).setTimeout(Math.max(1, deadline - Date.now())).click();
    const desktopDraft = await textarea.evaluate(node => node.value);
    assert.equal(desktopDraft, 'Layout-only draft\n',
      'Responsive layout must retain the unsent desktop draft');
    await textarea.press('ArrowDown');
    await textarea.press('End');
    await page.keyboard.down('Shift');
    try { for (let index = 0; index < desktopDraft.length; index++) await textarea.press('ArrowLeft'); }
    finally { await page.keyboard.up('Shift'); }
    assert.deepEqual(await textarea.evaluate(node => [node.selectionStart, node.selectionEnd]),
      [0, desktopDraft.length], 'Physical keyboard must select the complete retained draft');
    await textarea.press('Backspace');
    assert.equal(await textarea.evaluate(node => node.value), '',
      'Mobile layout check must clear the preceding desktop draft without sending it');
    await textarea.type('Layout-only mobile draft');
    stage = 'measure-composer';
    const child = await frame.evaluate(() => {
      const lane = document.querySelector('.ss-lane-mobile-content aside.ss-lane');
      const body = lane?.querySelector('.ss-lane__body');
      const slot = lane?.querySelector('[data-testid="customer-chat-composer-slot"]');
      const input = slot?.querySelector('textarea');
      const send = slot?.querySelector('button[type="submit"]');
      if (!lane || !body || !slot || !input || !send) return null;
      const box = element => {
        const rect = element.getBoundingClientRect();
        const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
        return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
          hit: hit === element || element.contains(hit) };
      };
      return { laneDisplay: getComputedStyle(lane).display, outsideScrollBody: !body.contains(slot),
        input: box(input), send: box(send), sendEnabled: !send.disabled,
        viewportWidth: innerWidth, viewportHeight: innerHeight, draft: input.value };
    });
    assert.ok(child && child.laneDisplay === 'flex' && child.outsideScrollBody,
      'Mobile drawer must show the existing lane with its customer composer outside history scroll');
    assert.equal(child.draft, 'Layout-only mobile draft');
    assert.equal(child.sendEnabled, true);
    for (const control of [child.input, child.send]) {
      assert.equal(control.hit, true, 'Mobile composer control must be hit-testable in its frame');
      assert.ok(control.left >= 0 && control.right <= child.viewportWidth
        && control.top >= 0 && control.bottom <= child.viewportHeight,
      'Mobile composer control must fit the frame viewport');
    }
    const parent = await page.evaluate(state => {
      const iframe = document.querySelector('iframe[title="SecureShop"]');
      if (!iframe || !iframe.clientWidth || !iframe.clientHeight
        || !iframe.offsetWidth || !iframe.offsetHeight) return null;
      const rect = iframe.getBoundingClientRect();
      const scaleX = rect.width / iframe.offsetWidth;
      const scaleY = rect.height / iframe.offsetHeight;
      return [state.input, state.send].map(box => {
        const left = rect.left + (iframe.clientLeft
          + box.left * iframe.clientWidth / state.viewportWidth) * scaleX;
        const right = rect.left + (iframe.clientLeft
          + box.right * iframe.clientWidth / state.viewportWidth) * scaleX;
        const top = rect.top + (iframe.clientTop
          + box.top * iframe.clientHeight / state.viewportHeight) * scaleY;
        const bottom = rect.top + (iframe.clientTop
          + box.bottom * iframe.clientHeight / state.viewportHeight) * scaleY;
        return { insideViewport: left >= 0 && right <= innerWidth && top >= 0 && bottom <= innerHeight,
          hitIframe: document.elementFromPoint((left + right) / 2, (top + bottom) / 2) === iframe };
      });
    }, child);
    assert.deepEqual(parent, [{ insideViewport: true, hitIframe: true },
      { insideViewport: true, hitIframe: true }],
    'The top page must leave the mobile composer visible and reachable');
    const screenshot = await page.screenshot({ type: 'png' });
    await fs.writeFile(path.join(evidenceRoot, 'q01-customer-composer-mobile-478.png'),
      screenshot, { flag: 'wx', mode: 0o600 });
    await frame.click('button[aria-label="Close"]');
    await frame.waitForFunction(() => {
      const sheet = document.querySelector('.ss-lane-mobile-content')?.closest('[aria-hidden]');
      return sheet?.getAttribute('aria-hidden') === 'true' && sheet.hasAttribute('inert');
    });
  } catch (error) {
    const geometry = { stage, viewport: page.viewport(), iframe: null, child: null };
    try {
      geometry.iframe = await page.evaluate(() => {
        const rect = document.querySelector('iframe[title="SecureShop"]')?.getBoundingClientRect();
        return rect ? { x: rect.x, y: rect.y, width: rect.width, height: rect.height } : null;
      });
      if (frame) geometry.child = await frame.evaluate(() => {
        const rect = element => {
          if (!element) return null;
          const box = element.getBoundingClientRect();
          return { x: box.x, y: box.y, width: box.width, height: box.height };
        };
        const content = document.querySelector('.ss-lane-mobile-content');
        const lane = content?.querySelector('aside.ss-lane');
        const slot = content?.querySelector('[data-testid="customer-chat-composer-slot"]');
        const input = slot?.querySelector('textarea');
        const send = slot?.querySelector('button[type="submit"]');
        const hit = element => {
          if (!element) return false;
          const box = element.getBoundingClientRect();
          const top = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
          return top === element || element.contains(top);
        };
        return { viewport: { width: innerWidth, height: innerHeight },
          sheet: rect(content?.closest('[aria-hidden]')), lane: rect(lane),
          body: rect(lane?.querySelector('.ss-lane__body')), slot: rect(slot),
          input: rect(input), send: rect(send), inputHit: hit(input), sendHit: hit(send) };
      });
    } catch { /* Keep the original mobile-layout failure. */ }
    await fs.writeFile(path.join(evidenceRoot, 'q01-customer-composer-mobile-failure-layout.json'),
      JSON.stringify(geometry), { flag: 'wx', mode: 0o600 }).catch(() => {});
    await page.screenshot({ path: path.join(evidenceRoot, 'q01-customer-composer-mobile-failure.png') })
      .catch(() => {});
    throw error;
  } finally {
    if (previousViewport) await page.setViewport(previousViewport);
  }
}

async function shopLogin(page, origin, shop) {
  await page.goto(origin + '/secureshop/login?next=%2Fsecureshop%2Fcart', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#ss-login-user', { visible: true });
  await page.type('#ss-login-user', shop.username);
  await page.type('#ss-login-pw', shop.password);
  const response = await responseFor(page, '/api/secureshop/auth/login', 'POST',
    () => page.click('button[type="submit"]'));
  assert.equal(response.status(), 200, 'Shop sign-in must use its own cookie endpoint');
  const body = await response.json();
  assert.equal(body.authenticated, true);
  assert.equal(body.user?.username, shop.username);
  const expiry = futureExpiry(body.expiresAt, 'Shop session');
  await boundShopFrame(page);
  const current = await shopSession(page);
  assert.equal(current.status, 200);
  assert.equal(current.body.authenticated, true);
  assert.equal(current.body.user.username, shop.username);
  return expiry;
}

async function platformLogin(page, origin, workshop) {
  await page.goto(origin + '/workshop/login', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
  await page.type('input[placeholder="Enter your username"]', workshop.username);
  await page.type('input[placeholder="Enter your password"]', workshop.password);
  const response = await responseFor(page, '/api/auth/login', 'POST',
    () => page.click('button[type="submit"]'));
  assert.equal(response.status(), 200, 'Workshop sign-in must use platform authority');
  await page.waitForFunction(() => Boolean(localStorage.getItem('token')));
  const current = await platformStatus(page);
  assert.equal(current.status, 200);
  assert.equal(current.body.authenticated, true);
  assert.equal(current.body.user.username, workshop.username);
  return futureExpiry(current.body.sessionInfo?.expiresAt, 'Workshop session');
}

async function rejectCrossRealmCredentials(page, origin, workshop, shop) {
  await page.goto(origin + '/workshop/login', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
  await page.type('input[placeholder="Enter your username"]', shop.username);
  await page.type('input[placeholder="Enter your password"]', shop.password);
  const platform = await responseFor(page, '/api/auth/login', 'POST',
    () => page.click('button[type="submit"]'));
  assert.equal(platform.status(), 401, 'Shop credentials must not enter the workshop');
  assert.equal((await platform.json()).token, undefined);
  assert.equal((await platformStatus(page)).body.authenticated, false);

  await page.goto(origin + '/secureshop/login', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#ss-login-user', { visible: true });
  await page.type('#ss-login-user', workshop.username);
  await page.type('#ss-login-pw', workshop.password);
  const shopResponse = await responseFor(page, '/api/secureshop/auth/login', 'POST',
    () => page.click('button[type="submit"]'));
  assert.equal(shopResponse.status(), 401, 'Workshop credentials must not enter the shop');
  assert.equal((await shopResponse.json()).token, undefined);
  assert.equal((await shopSession(page)).body.authenticated, false);
}

async function shopLogout(page) {
  const frame = await boundShopFrame(page);
  await frame.click('button[aria-label="Account menu"]');
  const response = await responseFor(page, '/api/secureshop/auth/logout', 'POST',
    () => clickExactButton(frame, 'Sign out'));
  assert.equal(response.status(), 200);
  await page.waitForFunction(() => location.pathname === '/secureshop');
  const current = await shopSession(page);
  assert.equal(current.status, 200);
  assert.equal(current.body.authenticated, false);
}

async function platformLogout(page, origin) {
  await page.goto(origin + '/workshop/challenges', { waitUntil: 'domcontentloaded' });
  const deadline = Date.now() + 20000;
  await page.waitForFunction(() => {
    const button = document.querySelector('button[aria-label="Account menu"]');
    if (!button || button.disabled || !button.getClientRects().length) return false;
    button.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const rect = button.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0 || rect.x < 0 || rect.y < 0
      || rect.right > innerWidth || rect.bottom > innerHeight) return false;
    const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
    return hit === button || button.contains(hit);
  }, { timeout: Math.max(1, deadline - Date.now()) });
  await page.locator('button[aria-label="Account menu"]')
    .setTimeout(Math.max(1, deadline - Date.now())).click();
  await page.waitForFunction(() => {
    const button = document.querySelector('button[aria-label="Account menu"]');
    return button?.getAttribute('aria-expanded') === 'true'
      && [...document.querySelectorAll('button')].some(item => item.textContent.trim() === 'Logout'
        && item.getClientRects().length);
  }, { timeout: Math.max(1, deadline - Date.now()) });
  const response = await responseFor(page, '/api/auth/logout', 'POST',
    () => clickExactButton(page, 'Logout'));
  assert.equal(response.status(), 200);
  const current = await platformStatus(page);
  assert.equal(current.status, 200);
  assert.equal(current.body.authenticated, false);
}

async function captureStandaloneFailure(page, evidenceRoot) {
  if (typeof evidenceRoot !== 'string' || !path.isAbsolute(evidenceRoot)) return;
  const state = { pathname: null, parent: null, frame: null, shopAuthenticated: null };
  try {
    state.parent = await page.evaluate(() => ({
      pathname: location.pathname,
      boundHost: Boolean(document.querySelector('main[aria-label="SecureShop"]')),
      boundFrame: Boolean(document.querySelector('iframe[title="SecureShop"]')),
      guestFrame: Boolean(document.querySelector('iframe[title="SecureShop storefront"]')),
      retry: [...document.querySelectorAll('button')].some(button => button.textContent.trim() === 'Retry'),
      opening: Boolean(document.querySelector('main[aria-label="SecureShop"] [role="status"]')),
      error: Boolean(document.querySelector('main[aria-label="SecureShop"] [role="alert"]')),
    }));
    state.pathname = state.parent.pathname;
    const frame = page.frames().find(item => item.parentFrame() === page.mainFrame()
      && item.url().includes('/secureshop-frame.html'));
    if (frame) state.frame = await frame.evaluate(() => ({
      accountMenu: Boolean(document.querySelector('button[aria-label="Account menu"]')),
      loginForm: Boolean(document.querySelector('#ss-login-user')),
      alert: Boolean(document.querySelector('[role="alert"]')),
      status: Boolean(document.querySelector('[role="status"]')),
    }));
    const session = await shopSession(page);
    state.shopAuthenticated = session.status === 200 ? session.body.authenticated === true : null;
  } catch { /* Failure evidence must never replace the primary assertion. */ }
  await fs.writeFile(path.join(evidenceRoot, 'standalone-rendered-failure-state.json'),
    JSON.stringify(state), { mode: 0o600 }).catch(() => {});
  await page.screenshot({ path: path.join(evidenceRoot, 'standalone-rendered-failure.png') })
    .catch(() => {});
}

// The caller owns the pinned browser, proxy, and disposable stores. This checks
// the actual two login forms, cookies, routes and natural DB session expiry;
// it never injects credentials into storage or changes server time.
async function qualifyFullBackendRenderedStandalone({ browser, origin, workshop, shop, productId,
  identityPool, signal, beginBrowserTeardown, evidenceRoot }) {
  assert.ok(Number.isSafeInteger(productId) && productId > 0);
  assert.equal(typeof beginBrowserTeardown, 'function');
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  const errors = [], blocked = [];
  page.setDefaultTimeout(20000);
  page.on('pageerror', error => errors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.protocol === 'data:' || url.origin === origin) void request.continue();
    else { blocked.push(url.origin); void request.abort('blockedbyclient'); }
  });
  await page.setCacheEnabled(false);
  if (typeof page.setViewport === 'function') await page.setViewport({ width: 1280, height: 900 });
  let primaryFailure;
  try {
    await page.goto(origin + '/secureshop', { waitUntil: 'domcontentloaded' });
    const guestHandle = await page.waitForSelector('iframe[title="SecureShop storefront"]', { visible: true });
    const guestFrame = await guestHandle.contentFrame();
    assert.ok(guestFrame, 'Anonymous catalog must use isolated shop frame');
    await guestFrame.waitForSelector('a[href="/secureshop/catalog"]', { visible: true });
    await guestFrame.click('a[href="/secureshop/catalog"]');
    await page.waitForFunction(() => location.pathname === '/secureshop/catalog');
    const card = await guestFrame.waitForSelector('a[href^="/secureshop/product/"]', { visible: true });
    const productRoute = await card.evaluate(element => element.getAttribute('href'));
    assert.match(productRoute, /^\/secureshop\/product\/[1-9][0-9]*$/);
    await card.click();
    await page.waitForFunction(route => location.pathname === route, {}, productRoute);
    await guestFrame.waitForFunction(() => document.body.innerText.includes('Add to cart'));
    const guestHome = await guestFrame.waitForSelector('nav[aria-label="Breadcrumb"] a[href="/secureshop"]', { visible: true });
    await guestHome.click();
    await page.waitForFunction(() => location.pathname === '/secureshop');
    await guestFrame.waitForSelector('a[href="/secureshop/catalog"]', { visible: true });
    assert.equal((await shopSession(page)).body.authenticated, false);
    const bootstrap = await require('./fullBackendRenderedStandaloneBootstrap')
      .qualifyStandaloneBootstrapOnPage({ page, origin, identityPool, signal });
    assert.equal(bootstrap.scope, 'rendered_standalone_bootstrap_and_registration');
    assert.equal(bootstrap.passed, true);
    assert.equal(bootstrap.modelCalls, 0);
    await rejectCrossRealmCredentials(page, origin, workshop, shop);
    await platformLogin(page, origin, workshop);
    await shopLogin(page, origin, shop);
    await qualifyCustomerComposerLayout(page, evidenceRoot);
    await qualifyCustomerMobileComposer(page, evidenceRoot);
    assert.equal((await platformStatus(page)).body.authenticated, true);
    await shopLogout(page);
    assert.equal((await platformStatus(page)).body.authenticated, true,
      'Shop UI sign-out must leave the workshop session active');
    await shopLogin(page, origin, shop);
    await platformLogout(page, origin);
    assert.equal((await shopSession(page)).body.authenticated, true,
      'Workshop UI sign-out must leave the shop session active');

    // Start fresh real sessions for natural expiry; navigating to workshop
    // unmounts the shop frame and stops its legitimate early-renew timer.
    await page.goto(origin + '/secureshop/cart', { waitUntil: 'domcontentloaded' });
    await shopLogout(page);
    const platformExpiry = await platformLogin(page, origin, workshop);
    const shopExpiry = await shopLogin(page, origin, shop);
    assert.ok(shopExpiry < platformExpiry - 30000,
      'Shop session must expire before the independent workshop session');
    await page.goto(origin + '/workshop/challenges', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('button[aria-label="Account menu"]', { visible: true });
    await waitForActualExpiry({ read: shopSession, page, expiresAt: new Date(shopExpiry).toISOString(), signal,
      label: 'Shop session' });
    assert.equal((await platformStatus(page)).body.authenticated, true);
    await page.goto(origin + '/secureshop/cart', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('iframe[title="SecureShop storefront"]', { visible: true });
    assert.equal(new URL(page.url()).pathname, '/secureshop/cart',
      'The public guest cart remains browsable after shop-session expiry');
    assert.equal((await shopSession(page)).body.authenticated, false);
    await page.goto(origin + '/secureshop/account', { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => location.pathname === '/secureshop/login'
      && new URLSearchParams(location.search).get('next') === '/secureshop/account');
    await page.waitForSelector('#ss-login-user', { visible: true });

    // A fresh shop login does not renew the older platform JWT. While the
    // bound shop remains mounted, its own 60-second early-renew path may run.
    await shopLogin(page, origin, shop);
    await waitForActualExpiry({ read: platformStatus, page, expiresAt: new Date(platformExpiry).toISOString(), signal,
      label: 'Workshop session' });
    assert.equal((await shopSession(page)).body.authenticated, true);
    await page.goto(origin + '/workshop/challenges', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
    await page.goto(origin + '/secureshop/cart', { waitUntil: 'domcontentloaded' });
    await boundShopFrame(page);
    assert.equal((await shopSession(page)).body.authenticated, true);
    assert.deepEqual(blocked, []);
    assert.deepEqual(errors, []);
    return { scope: 'rendered_standalone_shop_realm_separation', passed: true,
      checks: { ...bootstrap.checks,
        renderedCoexistence: true, shopExpiry: true, platformExpiry: true } };
  } catch (error) {
    primaryFailure = error;
    await captureStandaloneFailure(page, evidenceRoot);
    throw error;
  } finally {
    let teardownFailure;
    try { beginBrowserTeardown(); } catch (error) { teardownFailure = error; }
    try { await context.close(); } catch (error) {
      teardownFailure = teardownFailure
        ? new AggregateError([teardownFailure, error], 'Browser context teardown failed') : error;
    }
    if (teardownFailure) throw primaryFailure
      ? new AggregateError([primaryFailure, teardownFailure], 'Rendered browser qualification and teardown failed')
      : teardownFailure;
  }
}

module.exports = { qualifyFullBackendRenderedStandalone, futureExpiry };
