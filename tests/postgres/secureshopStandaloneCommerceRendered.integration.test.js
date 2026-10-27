'use strict';

// This cohort runs only through the current-main disposable browser launcher.
// It deliberately has no configured model and records real HTTP/SQL effects.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { capturePolicyRenderer } = require('../fixtures/secureshopOwnedPolicyRendererAdmission');
const { admitCommerceBrowser, observeProductRequests, readBoundedProductError,
  observeOriginalListingReadiness, exactConsequenceDialogButton, practiceSnapshotMetadata,
  practiceSummaryReference } =
  require('../fixtures/secureshopCommerceBrowserAdmission');

const PREFIX = 'PG_SECURESHOP_STANDALONE_COMMERCE_';
// Explicit optional external-send facet; the original commerce defaults are unchanged.
const externalMailOptIn = process.env.SECURESHOP_EXTERNAL_MAIL_RENDERED_SEND === '1';
const externalMailFixture = externalMailOptIn
  ? require('../fixtures/secureshopExternalMailRenderedQualification') : null;
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const ENABLED = process.env.SECURESHOP_STANDALONE_COMMERCE_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));


function disposableUrls() {
  const urls = {}; let nonce; let port;
  for (const [store, name] of Object.entries(STORES)) {
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`;
      const url = new URL(process.env[`${PREFIX}${key}_URL`]);
      assert.equal(url.protocol, 'postgresql:');
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.port, /^[1-9][0-9]{0,4}$/);
      assert.ok(Number(url.port) <= 65535);
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = new RegExp(`^/dvaia_test_agent_host_([0-9a-f]{12})_${name}$`).exec(url.pathname);
      assert.ok(match, `${key} must be an owned disposable store`);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[key] = url.href;
    }
    assert.equal(new URL(urls[`${store}_MIGRATION`]).pathname,
      new URL(urls[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES).map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze(urls);
}

async function stableFrame(page, title = 'SecureShop') {
  const until = Date.now() + 20000;
  while (Date.now() < until) {
    const element = await page.$(`iframe[title="${title}"]`);
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  const diagnostic = await page.evaluate(() => ({
    titles: [...document.querySelectorAll('iframe')].map(frame => frame.title).slice(0, 4),
    alert: document.querySelector('[role="alert"]')?.textContent?.trim().slice(0, 160) || null,
    main: document.querySelector('main[aria-label]')?.getAttribute('aria-label') || null,
  })).catch(() => null);
  const safe = { route: new URL(page.url()).pathname, expectedTitle: title, ...diagnostic };
  throw Object.assign(new Error(`Standalone SecureShop frame did not mount: ${JSON.stringify(safe)}`),
    { code: 'FRAME_NOT_MOUNTED' });
}

async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

async function boundedA11(label, work, timeoutMs) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error(`A11 ${label} timed out`),
        { code: 'A11_STEP_TIMEOUT', step: label })), timeoutMs);
    })]);
  } finally { clearTimeout(timer); }
}

// Pause delivery of one genuine HTTP 200 response. The browser receives the
// server's original bytes when released; no fixture response is substituted.
async function holdOneRealResponse(page, endpoint) {
  const cdp = await page.createCDPSession();
  let paused; let wake; let failure;
  const seen = new Promise(resolve => { wake = resolve; });
  const pending = new Set();
  const onPaused = event => {
    const work = (async () => {
      if (event.request.url === endpoint && !paused) {
        paused = event;
        assert.equal(event.responseStatusCode, 200, `held response must be real HTTP 200: ${endpoint}`);
        wake();
      } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(error => { failure = error; wake(); });
    pending.add(work); void work.finally(() => pending.delete(work));
  };
  cdp.on('Fetch.requestPaused', onPaused);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] });
  return {
    async wait() {
      let timer;
      try { await Promise.race([seen, new Promise((_, reject) => { timer = setTimeout(() =>
        reject(Error(`Real response was not observed: ${endpoint}`)), 20000); })]); }
      finally { clearTimeout(timer); }
      if (failure) throw failure;
      assert.ok(paused);
    },
    async close() {
      if (paused) { const requestId = paused.requestId; paused = null;
        await cdp.send('Fetch.continueRequest', { requestId }); }
      await Promise.all([...pending]);
      await cdp.send('Fetch.disable');
      cdp.off('Fetch.requestPaused', onPaused);
      await cdp.detach();
      if (failure) throw failure;
    },
  };
}

async function shopLoadingSnapshot(page, kind) {
  const state = await page.evaluate(() => {
    const status = document.querySelector('p[role="status"]');
    const spinner = status?.parentElement?.querySelector('.ss-spinner');
    const style = spinner && getComputedStyle(spinner);
    return { text: status?.textContent?.trim() || null, spinner: !!spinner,
      hidden: spinner?.getAttribute('aria-hidden') || null,
      width: style?.width || null, height: style?.height || null,
      borderTop: style?.borderTopColor || null, animation: style?.animationName || null,
      workshop: document.body.textContent.includes('Loading Workshop'),
      root: !!document.querySelector('.ss-root') };
  });
  assert.equal(state.text, 'Opening SecureShop…', `${kind}: accessible shop status`);
  assert.equal(state.spinner, true, `${kind}: original shop spinner`);
  assert.equal(state.hidden, 'true', `${kind}: status text labels loading`);
  assert.equal(state.width, '20px'); assert.equal(state.height, '20px');
  assert.equal(state.borderTop, 'rgb(229, 69, 26)', `${kind}: original copper palette`);
  assert.equal(state.animation, kind === 'lazy-chunk' ? 'spin' : 'ss-spin');
  assert.equal(state.workshop, false, `${kind}: no platform loading chrome`);
  assert.equal(state.root, kind === 'session', `${kind}: expected loading surface`);
}

// Delivery is cut only after the real conversational confirmation returned HTTP
// 200. The browser never receives a substituted success or invented receipt.
async function dropOneCommittedCheckoutResponse(page, endpoint) {
  const cdp = await page.createCDPSession();
  let captured = null; let failure;
  const pending = new Set();
  const onPaused = event => {
    const work = (async () => {
      if (!captured && event.request.url === endpoint && event.request.method === 'POST') {
        assert.equal(event.responseStatusCode, 200, 'loss follows a committed checkout only');
        const request = JSON.parse(event.request.postData);
        const body = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
        const receipt = JSON.parse(Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8').toString());
        assert.deepEqual(Object.keys(request).sort(), ['proposalId']);
        assert.match(request.proposalId, /^[0-9a-f-]{36}$/i);
        assert.equal(receipt.version, 1);
        assert.equal(receipt.operationId, request.proposalId);
        assert.equal(receipt.kind, 'checkout.confirm');
        assert.equal(receipt.status, 'approved');
        assert.equal(receipt.currency, 'USD');
        assert.equal(receipt.replayed, false);
        assert.ok(Number.isSafeInteger(receipt.order?.orderId) && receipt.order.orderId > 0);
        assert.ok(Number.isSafeInteger(receipt.totalCents) && receipt.totalCents >= 0);
        captured = { operationId: request.proposalId, orderId: receipt.order.orderId,
          total: receipt.order.total, totalCents: receipt.totalCents, request };
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(async error => {
      failure = error;
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    });
    pending.add(work); void work.finally(() => pending.delete(work));
  };
  cdp.on('Fetch.requestPaused', onPaused);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] });
  return Object.freeze({
    captured() { if (failure) throw failure; return captured; },
    async close() {
      await Promise.all([...pending]); await cdp.send('Fetch.disable');
      cdp.off('Fetch.requestPaused', onPaused); await cdp.detach();
      if (failure) throw failure;
    },
  });
}

async function typeLabeled(frame, label, value) {
  const id = await frame.$$eval('label', (labels, text) =>
    labels.find(node => node.textContent.trim() === text)?.htmlFor || null, label);
  assert.ok(id, `missing form label ${label}`);
  await frame.type(`[id="${id}"]`, value);
}

// A request-stage loss never reaches Express; a response-stage loss follows a
// genuine committed send. Neither branch substitutes a mail receipt.
async function dropOneMailDelivery(page, endpoint, beforeDelivery) {
  const cdp = await page.createCDPSession();
  let captured; let failure;
  const pending = new Set();
  const onPaused = event => {
    const work = (async () => {
      if (!captured && event.request.url === endpoint && event.request.method === 'POST') {
        const request = JSON.parse(event.request.postData);
        assert.match(request.requestId, /^[0-9a-f-]{36}$/i);
        captured = { request };
        if (!beforeDelivery) {
          assert.equal(event.responseStatusCode, 200, 'ACK loss follows the real saved send');
          const body = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
          captured.receipt = JSON.parse(Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8').toString());
          assert.equal(captured.receipt.ok, true);
          assert.ok(Number.isSafeInteger(captured.receipt.email_id) && captured.receipt.email_id > 0);
        }
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(async error => {
      failure = error;
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    });
    pending.add(work); void work.finally(() => pending.delete(work));
  };
  cdp.on('Fetch.requestPaused', onPaused);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint,
    requestStage: beforeDelivery ? 'Request' : 'Response' }] });
  return Object.freeze({
    captured() { if (failure) throw failure; return captured; },
    async close() {
      await Promise.all([...pending]); await cdp.send('Fetch.disable');
      cdp.off('Fetch.requestPaused', onPaused); await cdp.detach();
      if (failure) throw failure;
    },
  });
}

async function clickMailButton(frame, text, dialogOnly = false, dialogScope = null) {
  const selector = dialogOnly ? '[role="dialog"] button' : 'button';
  // Center-scroll the exact native handle: an intersecting viewport rectangle
  // can still sit beneath the sticky navbar. Never retry a mutation click.
  const findButton = dialogScope
    ? new Function(`return (${exactConsequenceDialogButton.toString()})(
      ${JSON.stringify(dialogScope.title)}, ${JSON.stringify(dialogScope.consequence)},
      ${JSON.stringify(dialogScope.confirmLabel)}, ${JSON.stringify(text)});`)
    : new Function(`return [...document.querySelectorAll(${JSON.stringify(selector)})]
      .find(button => button.textContent.trim() === ${JSON.stringify(text)});`);
  const button = await frame.locator(findButton).setTimeout(20000).setVisibility('visible').waitHandle();
  try {
    await button.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
    await frame.waitForFunction(async node => {
      if (!node?.isConnected || node.disabled) return false;
      const before = node.getBoundingClientRect();
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      if (!node.isConnected || node.disabled) return false;
      const after = node.getBoundingClientRect();
      if (['left', 'top', 'width', 'height'].some(key => before[key] !== after[key])
        || after.width <= 0 || after.height <= 0 || after.left < 0 || after.top < 0
        || after.right > innerWidth || after.bottom > innerHeight) return false;
      const hit = document.elementFromPoint(after.left + after.width / 2, after.top + after.height / 2);
      return hit === node || node.contains(hit);
    }, { timeout: 20000 }, button);
  } catch (cause) {
    const geometry = await button.evaluate(node => {
      const rect = node.getBoundingClientRect();
      const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
      return { connected: node.isConnected, disabled: node.disabled,
        rect: { left: rect.left, top: rect.top, width: rect.width, height: rect.height },
        viewport: { width: innerWidth, height: innerHeight }, hitTag: hit?.tagName || null,
        hitClass: typeof hit?.className === 'string' ? hit.className.slice(0, 100) : null };
    }).catch(() => ({ unavailable: true }));
    throw Object.assign(Error(`Rendered button ${text} is not clickable: ${JSON.stringify(geometry)}`),
      { code: 'FIXTURE_BUTTON_NOT_CLICKABLE', cause });
  }
  await button.click();
}

async function fillCustomerMailDialog(frame, { to, subject, body }) {
  const customerCompose = () => [...document.querySelectorAll('[role="dialog"]')]
    .find(dialog => {
      const form = dialog.querySelector('form.ss-form');
      return dialog.isConnected && dialog.getClientRects().length > 0 && getComputedStyle(dialog).display !== 'none' && getComputedStyle(dialog).visibility !== 'hidden'
        && form && form.querySelector('textarea[placeholder="Type your message. Markdown → HTML on the server."]');
    })?.querySelector('form.ss-form') || null;
  await frame.locator(customerCompose).setVisibility('visible').waitHandle();
  const controls = await frame.evaluate(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => {
      const form = candidate.querySelector('form.ss-form');
      return candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
        && form && form.querySelector('textarea[placeholder="Type your message. Markdown → HTML on the server."]');
    });
    const form = dialog?.querySelector('form.ss-form');
    return form ? [...form.querySelectorAll('input, textarea')].map(node => ({
      tagName: node.tagName, type: node.getAttribute('type'), required: node.required,
    })) : null;
  });
  assert.deepEqual(controls, [
    { tagName: 'INPUT', type: 'text', required: true },
    { tagName: 'INPUT', type: 'text', required: true },
    { tagName: 'TEXTAREA', type: null, required: true },
  ], 'the visible customer Compose dialog exposes recipient, subject, and body controls');
  const customerRecipient = frame.locator(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => {
      const form = candidate.querySelector('form.ss-form');
      return candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
        && form && form.querySelector('textarea[placeholder="Type your message. Markdown → HTML on the server."]');
    });
    return dialog?.querySelector('form.ss-form')?.querySelectorAll('input, textarea')[0] || null;
  });
  const customerSubject = frame.locator(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => {
      const form = candidate.querySelector('form.ss-form');
      return candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
        && form && form.querySelector('textarea[placeholder="Type your message. Markdown → HTML on the server."]');
    });
    return dialog?.querySelector('form.ss-form')?.querySelectorAll('input, textarea')[1] || null;
  });
  const customerBody = frame.locator(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => {
      const form = candidate.querySelector('form.ss-form');
      return candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
        && form && form.querySelector('textarea[placeholder="Type your message. Markdown → HTML on the server."]');
    });
    return dialog?.querySelector('form.ss-form')?.querySelectorAll('input, textarea')[2] || null;
  });
  await customerRecipient.setVisibility('visible').fill(to);
  await customerSubject.setVisibility('visible').fill(subject);
  await customerBody.setVisibility('visible').fill(body);
  assert.deepEqual(await frame.evaluate(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => {
      const form = candidate.querySelector('form.ss-form');
      return candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
        && form && form.querySelector('textarea[placeholder="Type your message. Markdown → HTML on the server."]');
    });
    const fields = dialog?.querySelector('form.ss-form')?.querySelectorAll('input, textarea');
    return { to: fields?.[0]?.value, subject: fields?.[1]?.value, body: fields?.[2]?.value };
  }), { to, subject, body }, 'rendered customer Compose values exactly match the intended message before Send');
}

async function fillMerchantMailDialog(frame, { to, subject, body, from }) {
  const merchantCompose = () => [...document.querySelectorAll('[role="dialog"]')]
    .find(dialog => dialog.isConnected && dialog.getClientRects().length > 0 && getComputedStyle(dialog).display !== 'none' && getComputedStyle(dialog).visibility !== 'hidden'
      && dialog.querySelector('textarea[placeholder="Markdown supported. sanitize:false — <script>, <img onerror=…>, <iframe> pass through."]')) || null;
  await frame.locator(merchantCompose).setVisibility('visible').waitHandle();
  const controls = await frame.evaluate(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
      && candidate.querySelector('textarea[placeholder="Markdown supported. sanitize:false — <script>, <img onerror=…>, <iframe> pass through."]'));
    return dialog ? [...dialog.querySelectorAll('input, textarea')].map(node => ({
      tagName: node.tagName, type: node.getAttribute('type'), required: node.required,
    })) : null;
  });
  assert.deepEqual(controls, [
    { tagName: 'INPUT', type: null, required: false },
    { tagName: 'INPUT', type: null, required: false },
    { tagName: 'INPUT', type: null, required: false },
    { tagName: 'TEXTAREA', type: null, required: false },
  ], 'the visible merchant Compose dialog exposes recipient, sender, subject, and body controls');
  const merchantRecipient = frame.locator(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
      && candidate.querySelector('textarea[placeholder="Markdown supported. sanitize:false — <script>, <img onerror=…>, <iframe> pass through."]'));
    return dialog?.querySelectorAll('input, textarea')[0] || null;
  });
  const merchantSubject = frame.locator(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
      && candidate.querySelector('textarea[placeholder="Markdown supported. sanitize:false — <script>, <img onerror=…>, <iframe> pass through."]'));
    return dialog?.querySelectorAll('input, textarea')[2] || null;
  });
  const merchantBody = frame.locator(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
      && candidate.querySelector('textarea[placeholder="Markdown supported. sanitize:false — <script>, <img onerror=…>, <iframe> pass through."]'));
    return dialog?.querySelectorAll('input, textarea')[3] || null;
  });
  await merchantRecipient.setVisibility('visible').fill(to);
  await merchantSubject.setVisibility('visible').fill(subject);
  await merchantBody.setVisibility('visible').fill(body);
  assert.deepEqual(await frame.evaluate(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(candidate => candidate.isConnected && candidate.getClientRects().length > 0 && getComputedStyle(candidate).display !== 'none' && getComputedStyle(candidate).visibility !== 'hidden'
      && candidate.querySelector('textarea[placeholder="Markdown supported. sanitize:false — <script>, <img onerror=…>, <iframe> pass through."]'));
    const fields = dialog?.querySelectorAll('input, textarea');
    return { to: fields?.[0]?.value, from: fields?.[1]?.value,
      subject: fields?.[2]?.value, body: fields?.[3]?.value };
  }), { to, from, subject, body }, 'rendered merchant Compose values exactly match the intended message before Send');
}

async function fillMailDialog(frame, role, message) {
  await clickMailButton(frame, 'Compose');
  if (role === 'customer') return fillCustomerMailDialog(frame, message);
  if (role === 'merchant') return fillMerchantMailDialog(frame, message);
  throw Error(`Unsupported rendered mail role: ${role}`);
}

async function dropOneCommittedOperationResponse(page, endpoint) {
  const cdp = await page.createCDPSession();
  let captured; let failure; const pending = new Set();
  const observed = [];
  let notifyCapture;
  const captureReady = new Promise(resolve => { notifyCapture = resolve; });
  const onRequest = request => {
    if (request.url() === endpoint && request.method() === 'POST') observed.push('request-dispatched');
  };
  const onResponse = response => {
    if (response.url() === endpoint && response.request().method() === 'POST') {
      observed.push(`response-${response.status()}`);
      if (response.status() >= 400 && !captured) notifyCapture({ error: Object.assign(
        new Error(`Operation POST rejected with HTTP ${response.status()}`),
        { code: 'OPERATION_POST_REJECTED' }) });
    }
  };
  const onFailed = request => {
    if (request.url() === endpoint && request.method() === 'POST') {
      observed.push('request-failed-after-dispatch');
      if (!captured) notifyCapture({ error: Object.assign(
        new Error('Operation POST failed before a committed response'),
        { code: 'OPERATION_POST_UNCONFIRMED' }) });
    }
  };
  page.on('request', onRequest); page.on('response', onResponse); page.on('requestfailed', onFailed);
  const onPaused = event => {
    const work = (async () => {
      if (!captured && event.request.url === endpoint && event.request.method === 'POST') {
        observed.push(`intercepted-${event.responseStatusCode ?? 'pre-response'}`);
        assert.equal(event.responseStatusCode, 200, 'only a real committed operation ACK is lost');
        const request = JSON.parse(event.request.postData);
        const body = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
        const value = JSON.parse(Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8').toString());
        assert.equal(value.ok, true); assert.equal(value.receipt.operationId, request.operationId);
        captured = { request, receipt: value.receipt, acknowledgement: value };
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
        notifyCapture({ captured });
      } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(async error => {
      failure = error;
      notifyCapture({ error });
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    });
    pending.add(work); void work.finally(() => pending.delete(work));
  };
  cdp.on('Fetch.requestPaused', onPaused);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] });
  return { captured() { if (failure) throw failure; return captured; },
    async waitCaptured(timeoutMs = 20000) {
      let timer;
      try {
        const result = await Promise.race([captureReady, new Promise((_, reject) => {
          timer = setTimeout(() => reject(Object.assign(
            new Error(`Committed operation response not observed: ${observed.join(',') || 'no matching request'}`),
            { code: 'COMMITTED_OPERATION_RESPONSE_NOT_OBSERVED' })), timeoutMs);
        })]);
        if (result.error) throw result.error;
        return result.captured;
      } finally { clearTimeout(timer); }
    }, async close() {
    await Promise.all([...pending]); await cdp.send('Fetch.disable');
    cdp.off('Fetch.requestPaused', onPaused);
    page.off('request', onRequest); page.off('response', onResponse); page.off('requestfailed', onFailed);
    await cdp.detach(); if (failure) throw failure;
  } };
}

// Lose only a real, published A18 acknowledgement. The request-stage pause
// proves the trusted parent saved the exact UUID before dispatch.
async function dropOnePublishedPracticeResponse(page, endpoint, referenceKey) {
  const cdp = await page.createCDPSession();
  let captured; let failure; let wake;
  const seen = new Promise(resolve => { wake = resolve; });
  const pending = new Set();
  const onPaused = event => {
    const work = (async () => {
      if (event.request.url !== endpoint || event.request.method !== 'POST' || captured) {
        await cdp.send('Fetch.continueRequest', { requestId: event.requestId }); return;
      }
      if (!event.responseStatusCode) {
        const request = JSON.parse(event.request.postData);
        assert.deepEqual(Object.keys(request), ['operationId']);
        assert.match(request.operationId, /^[0-9a-f-]{36}$/i);
        const saved = await page.evaluate(key => localStorage.getItem(key), referenceKey);
        assert.deepEqual(JSON.parse(saved), { version: 1, operationId: request.operationId });
        await cdp.send('Fetch.continueRequest', { requestId: event.requestId }); return;
      }
      assert.equal(event.responseStatusCode, 200, 'only a real published practice ACK is lost');
      const request = JSON.parse(event.request.postData);
      const body = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
      const result = JSON.parse(Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8').toString());
      assert.deepEqual(Object.keys(result).sort(), ['operationId', 'status', 'sceneId', 'canResume'].sort());
      assert.equal(result.operationId, request.operationId);
      assert.equal(result.status, 'published');
      assert.match(result.sceneId, /^[0-9a-f-]{36}$/i);
      assert.equal(result.canResume, false);
      captured = { request, result };
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      wake();
    })().catch(async error => {
      failure = error; wake();
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    });
    pending.add(work); void work.finally(() => pending.delete(work));
  };
  cdp.on('Fetch.requestPaused', onPaused);
  await cdp.send('Fetch.enable', { patterns: [
    { urlPattern: endpoint, requestStage: 'Request' },
    { urlPattern: endpoint, requestStage: 'Response' },
  ] });
  return { async wait() {
    let timer;
    try { await Promise.race([seen, new Promise((_, reject) => { timer = setTimeout(() =>
      reject(Error('Published practice acknowledgement was not observed')), 20000); })]); }
    finally { clearTimeout(timer); }
    if (failure) throw failure;
    assert.ok(captured);
    return captured;
  }, async close() {
    await Promise.all([...pending]);
    await cdp.send('Fetch.disable');
    cdp.off('Fetch.requestPaused', onPaused);
    await cdp.detach();
    if (failure) throw failure;
  } };
}

async function gallerySnapshot(frame) {
  return frame.evaluate(() => {
    const bounds = element => {
      if (!element) return null;
      const rect = element.getBoundingClientRect();
      const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
      return { x: Math.round(x), y: Math.round(y), width: Math.round(rect.width),
        height: Math.round(rect.height), hit: document.elementFromPoint(x, y)?.getAttribute('aria-label')
          || document.elementFromPoint(x, y)?.tagName || null,
        targetable: element.contains(document.elementFromPoint(x, y)) };
    };
    return {
      previous: bounds(document.querySelector('button[aria-label="Previous image"]')),
      next: bounds(document.querySelector('button[aria-label="Next image"]')),
      selected: [...document.querySelectorAll('button[aria-label^="Show image "]')]
        .map(button => ({ label: button.getAttribute('aria-label'), current: button.getAttribute('aria-current') })),
      main: [...document.querySelectorAll('img[alt^="Gallery fixture "]')]
        .map(image => ({ src: image.src, complete: image.complete, width: image.naturalWidth })).slice(0, 3),
      click: window.__commerceGalleryClick || null,
    };
  });
}

// Values are the ca8b05f template's shared button sizes and variants. Inspect
// real role controls at both widths; hovering never invokes their actions.
async function qualifyRoleButtons(page, surface, role, samples, receiptPath) {
  const sizes = { md: { min: 44, padding: '10px 18px', font: '14px' },
    sm: { min: 34, padding: '6px 12px', font: '13px' },
    lg: { min: 52, padding: '14px 24px', font: '16px' },
    adminCompact: { min: 44, padding: '3px 8px', font: '11px' } };
  const colors = { primary: { normal: 'rgb(229, 69, 26)', hover: 'rgb(198, 60, 21)', text: 'rgb(255, 255, 255)' },
    ghost: { normal: 'rgba(0, 0, 0, 0)', hover: 'rgba(0, 0, 0, 0.04)', text: 'rgb(11, 13, 16)' } };
  const desktopWidths = new Map();
  try {
    for (const width of [1280, 478]) {
      await page.setViewport({ width, height: 900 });
      await surface.evaluate(async () => { await document.fonts.ready; });
      assert.equal(await surface.evaluate(() => document.fonts.check('600 14px Inter')), true,
        `${role}/${width}: Inter must be ready`);
      for (const sample of samples) {
        await page.mouse.move(0, 0);
        const find = new Function(`return [...document.querySelectorAll(${JSON.stringify(sample.selector)})]
          .find(node => node.textContent.trim() === ${JSON.stringify(sample.text)});`);
        const handle = await surface.locator(find).setTimeout(20000).setVisibility('visible').waitHandle();
        await handle.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
        const expected = sizes[sample.size], color = colors[sample.variant];
        await surface.waitForFunction((node, background) => {
          const rect = node.getBoundingClientRect(), css = getComputedStyle(node);
          const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
          return !node.disabled && rect.width > 0 && rect.left >= 0 && rect.right <= innerWidth
            && rect.top >= 0 && rect.bottom <= innerHeight && (hit === node || node.contains(hit))
            && css.backgroundColor === background;
        }, { timeout: 20000 }, handle, color.normal);
        const measured = await handle.evaluate(node => {
          const css = getComputedStyle(node), rect = node.getBoundingClientRect();
          return { width: rect.width, height: rect.height, minHeight: css.minHeight,
            padding: css.padding, fontSize: css.fontSize, fontFamily: css.fontFamily,
            fontWeight: css.fontWeight, radius: css.borderRadius, color: css.color,
            background: css.backgroundColor, lineHeight: css.lineHeight,
            borderY: parseFloat(css.borderTopWidth) + parseFloat(css.borderBottomWidth),
            paddingY: parseFloat(css.paddingTop) + parseFloat(css.paddingBottom),
            textFits: node.scrollWidth <= node.clientWidth + 1 && node.scrollHeight <= node.clientHeight + 1,
            buttonClass: node.classList.contains('ss-btn') };
        });
        assert.equal(measured.buttonClass, true); assert.equal(measured.minHeight, `${expected.min}px`);
        assert.equal(measured.padding, expected.padding); assert.equal(measured.fontSize, expected.font);
        assert.equal(measured.fontWeight, '600'); assert.match(measured.fontFamily, /Inter/);
        assert.equal(measured.radius, '6px'); assert.equal(measured.color, color.text);
        assert.equal(measured.background, color.normal); assert.equal(measured.textFits, true);
        assert.ok(measured.height >= expected.min - 0.1 && measured.height <= expected.min + 2.1,
          `${role}/${sample.text}/${width}: template height mismatch ${measured.height}/${expected.min}`);
        assert.ok(measured.width > 0 && measured.width <= width,
          `${role}/${sample.text}/${width}: clipped width ${measured.width}`);
        if (width === 1280) desktopWidths.set(sample.text, measured.width);
        else if (!sample.stretch) assert.ok(Math.abs(measured.width - desktopWidths.get(sample.text)) <= 1,
          `${role}/${sample.text}: intrinsic width changed across viewports`);
        await handle.hover();
        await surface.waitForFunction((node, background) => getComputedStyle(node).backgroundColor === background,
          { timeout: 20000 }, handle, color.hover);
        const hover = await handle.evaluate(node => ({ background: getComputedStyle(node).backgroundColor,
          width: node.getBoundingClientRect().width, height: node.getBoundingClientRect().height }));
        assert.ok(Math.abs(hover.width - measured.width) <= 1 && Math.abs(hover.height - measured.height) <= 1);
        console.log('A08 button', JSON.stringify({ role, viewportWidth: width, text: sample.text,
          ...measured, hover }));
      }
      await page.mouse.move(0, 0);
      await fs.writeFile(receiptPath.replace(/\.json$/i, '') + `-a08-${role}-${width}.png`,
        await page.screenshot(), { flag: 'wx', mode: 0o600 });
    }
  } finally {
    console.log('A08 viewport restore', role);
    await boundedA11(`a08-${role}-viewport-restore`, () => page.setViewport({ width: 1280, height: 900 }), 5000);
  }
}

test('standalone commerce renders gallery, imports guest cart, and verifies one checkout across reload',
  { skip: !ENABLED, timeout: 330000 }, async () => {
    const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(workspace, process.cwd(), 'qualification requires the current checkout');
    const receiptPath = process.env.SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(receiptPath));
    const build = path.resolve(process.env.SECURESHOP_STANDALONE_COMMERCE_BUILD || path.join(workspace, 'client/build'));
    assert.equal(build, path.join(workspace, 'client/build'));
    for (const file of ['index.html', 'secureshop-frame.html', 'secureshop/product-placeholder.svg', 'favicon.svg'])
      await fs.access(path.join(build, file));
    const shopChunks = (await fs.readdir(path.join(build, 'assets')))
      .filter(file => /^SecureShopStandalone-[A-Za-z0-9_-]+\.js$/.test(file));
    assert.equal(shopChunks.length, 1, 'the real standalone route has one lazy production chunk');
    assert.match(await fs.readFile(path.join(build, 'assets', shopChunks[0]), 'utf8'),
      /Shop session changed during sign-in/, 'held script is the standalone route, not the app entry');
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    const browserAdmission = await admitCommerceBrowser(process.env,
      { workspace, evidencePath: receiptPath, executablePath });

    const urls = disposableUrls();
    const pools = Object.fromEntries(Object.keys(STORES).flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
      const key = `${store}_${role}`;
      return [key, new Pool({ connectionString: urls[key], max: role === 'RUNTIME' ? 12 : 3 })];
    })));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
    const status = { scope: 'current-main standalone no-model rendered commerce, gallery and checkout recovery',
      passed: false, storefrontLoadingRendered: false, galleryRendered: false,
      guestRequestBudget: false, guestLandingResponsive: false,
      guestOpaqueIsolation: false, guestImportReadback: false,
      checkoutOnce: false, checkoutRecovered: false, roleParity: false,
      siblingPrivate: false, adminUsersRenderedPagination: false,
      customerAdminApiDenied: false, auditRenderedPagination: false,
      accessControlVersionedRendered: false,
      adminSyntheticLookupRendered: false, merchantListingsRenderedPagination: false,
      buttonsDesktopTemplateParity: false, buttonsNarrowTemplateParity: false,
      registeredAdminResetRenderedPrivate: false,
      adminRoleChangeRecovered: false, adminBanRecovered: false,
      apiKeyVersionedPrivate: false,
      customerSelfPasswordChanged: false,
      sameShopperConcurrentSessionsRetained: false,
      retainedSceneChooserRendered: false,
      renderedNewPracticeSameCookie: false, renderedNewPracticeExactRecovery: false,
      renderedNewPracticeCartIsolation: false, renderedNewPracticeStorageFailure: false,
      renderedNewPracticeCapacityGuidance: false,
      customerComposeRecoverySingleEffect: false, merchantComposeRecoverySingleEffect: false,
      manualReviewRejectRecovery: false,
      policySavedOperationRecovery: false,
      policyRecovery: { status: 'not-run', reason: 'No explicit external renderer admission supplied' },
      noModelCalls: false };
    let composition; let mailProduction; let server; let browser; let browserBoundary; let profile; let page; let contextB; let contextA18; let contextA18Product; let pageA18; let failure;
    let stage = 'setup'; let resetKeyDirectory; let privateResetRevealPending = false;
    const workDeadline = Date.now() + 280000;
    const externalMailAbort = new AbortController();
    const workStep = (label, work, maxMs = 20000) => {
      const remaining = workDeadline - Date.now();
      if (remaining <= 0) throw Object.assign(new Error(`A11 work deadline reached at ${label}`),
        { code: 'A11_WORK_DEADLINE', step: label });
      return boundedA11(label, work, Math.min(maxMs, remaining));
    };
    const markStage = label => { stage = label; console.log('A11 stage', label); };
    const workWatchdog = setTimeout(() => {
      console.log('A11 work watchdog', stage);
      externalMailAbort.abort();
      // Close only this fixture's browser. This interrupts outstanding UI
      // observations so the test can report the original stage and clean up.
      if (browser) void browser.close().catch(error =>
        console.log('A11 work watchdog close failed', error.code || error.name));
    }, 280000);
    let privateApiKeyVisible = false; let apiKeyRotateFailure = null;
    const apiStatuses = [];
    let boundAuthority = null;
    let legacyBoundFallbackHits = 0;
    const guestRequests = [];
    const pendingGuestApiRequests = new Set();
    const guestApiSettledWaiters = new Set();
    const cleanupErrors = []; let modelCalls = 0; let judgeCalls = 0;
    const providerCalls = []; const pageBApi = [];
    const productServerResponses = [];
    let keyMutationRequests = 0;
    const readinessObserver = observeOriginalListingReadiness({
      isCurrent: () => stage === 'merchant-listings-browser',
    });
    let modelCallsBeforeProductA08 = null; let modelCallsBeforeA16 = null;
    let judgeCallsBeforeA16 = null;
    let externalPolicyRenderer; let policyRenderCalls = 0;
    let retainedSceneA; let retainedSceneB; let retainedSceneForeignChecked = false;
    let sceneChooserDiagnostic = null;
    try {
      for (const [store, directory] of [
        ['IDENTITY', 'identity-migrations'], ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'], ['COMMERCE', 'workshop-migrations/secureshop'],
      ]) await migrate(pools[`${store}_MIGRATION`], path.join(workspace, 'db/postgres', directory));
      await require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed')
        .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed')
        .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seedClient = await pools.COMMERCE_MIGRATION.connect();
      try { await seedClient.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
        await seedClient.query('COMMIT');
      } catch (error) { await seedClient.query('ROLLBACK'); throw error; }
      finally { seedClient.release(); }

      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8), password = 'disposable-commerce-browser';
      const merchantRegistration = await auth.login({ username: 'student_merchant', password: 'student123' });
      const customerName = `buyer_${suffix}`;
      await auth.register({ username: customerName,
        email: `${customerName}@example.invalid`, password, role: 'customer' });
      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      const reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit });
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const unavailableJudge = async () => { judgeCalls++; throw Error('No Judge admitted in commerce cohort'); };
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: reset,
          judge: unavailableJudge,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
        .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
      const couponDependencies = await require('../../server/services/secureshopCouponProduction')
        .prepareCommerceDependencies({ modeAuthority, reviewPool: review,
          launches: reset.launches, mode: 'vuln' });
      const unavailableProvider = Object.fromEntries(['chat', 'finalResponse'].map(method => [method, async () => {
        modelCalls++;
        if (providerCalls.length < 8) providerCalls.push({ method, stage,
          callers: (new Error().stack || '').split('\n').slice(2, 5)
            .map(frame => frame.trim().replaceAll(workspace, '<workspace>').slice(0, 180)) });
        throw new Error('No model admitted in commerce cohort');
      }]));
      externalPolicyRenderer = await capturePolicyRenderer(workspace,
        process.env.SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION);
      const policyRepository = externalPolicyRenderer && require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
        .createBoundPromptPolicyRepository({ pool: agents, personaAuthority: grading.personaAuthority, audit: audit.agents });
      if (policyRepository) await policyRepository.checkReadiness();
      const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
        .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority, audit: audit.agents });
      composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap: grading, scenes, modeAuthority, couponDependencies, toolPolicyRepository,
          fixtures: [], requiredObjectives: ['ss_stored_browser_execution'],
          jwtSecret: 'disposable-commerce-persona-secret-at-least-32-bytes',
          ...(externalPolicyRenderer ? { promptPolicyRepository: policyRepository,
            promptPolicyRenderer: { checkReadiness: () => externalPolicyRenderer.runtime.checkReadiness(),
              render: (...args) => { policyRenderCalls++; return externalPolicyRenderer.runtime.render(...args); } } } : {}),
          agentRuntime: { provider: unavailableProvider } });
      await composition.repositories.personas.ensureTemplates();
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });

      // Create a real merchant listing in the same tenant before mounting the
      // public rendered product page. The absolute favicon URL is set below
      // after the local server binds its owned ephemeral port.
      const mounted = { ...composition };
      // The public gateway intentionally reduces unknown dependency failures to
      // one 503. Retain only internal codes in the private failed-run receipt
      // so this isolated fixture can diagnose rotate without recording a key,
      // token, request body, or error message.
      mounted.personaAuth = Object.freeze({ ...composition.personaAuth,
        async rotateApiKey(input) {
          try { return await composition.personaAuth.rotateApiKey(input); }
          catch (error) {
            apiKeyRotateFailure = Object.freeze({
              name: typeof error?.name === 'string' && error.name.length <= 128 ? error.name : null,
              code: typeof error?.code === 'string' ? error.code : null,
              causeCode: typeof error?.cause?.code === 'string' ? error.cause.code : null,
            });
            throw error;
          }
        },
      });
      const app = express(); app.use(express.json());
      app.use(readinessObserver.middleware);
      app.use((request, response, next) => {
        if (stage === 'a08-customer-buttons'
          && /^\/api\/secureshop\/products\/[1-9]\d*\/(summary|similar)$/.test(request.path)
          && ((request.method === 'POST' && request.path.endsWith('/summary'))
            || (request.method === 'POST' && request.path.endsWith('/similar')))) {
          const row = { method: request.method, path: request.path,
            status: null, finished: false, closed: false };
          productServerResponses.push(row);
          response.once('finish', () => { row.status = response.statusCode; row.finished = true; });
          response.once('close', () => { row.closed = true; });
        }
        next();
      });
      const mailPosts = [];
      const policyPosts = [];
      const reviewDecisionPosts = [];
      const lookupPosts = [];
      const practiceTraffic = [];
      app.use((request, _response, next) => {
        if (/^\/api\/secureshop\/auth\/practices(?:\/[0-9a-f-]{36})?$/.test(request.path))
          practiceTraffic.push({ method: request.method, path: request.path,
            operationId: request.body?.operationId || null, cookie: /(?:^|;)\s*dvaia_shop_session=/.test(request.headers.cookie || ''),
            authorization: request.headers.authorization || null,
            launch: request.headers['x-dvaia-secureshop-launch'] || null });
        if (request.method === 'POST' && request.path === '/api/secureshop/email/send')
          mailPosts.push({ requestId: request.body?.requestId });
        if (request.method === 'POST' && request.path === '/api/secureshop/admin/policies')
          policyPosts.push(structuredClone(request.body));
        if (request.method === 'POST' && /^\/api\/secureshop\/merchant\/reviews\/[1-9]\d*\/(approve|reject)$/.test(request.path))
          reviewDecisionPosts.push({ path: request.path, body: structuredClone(request.body) });
        if (request.method === 'POST' && request.path === '/api/secureshop/admin/users/lookup')
          lookupPosts.push(structuredClone(request.body));
        next();
      });
      server = await new Promise(resolve => { const opened = app.listen(0, '127.0.0.1', () => resolve(opened)); });
      const origin = `http://127.0.0.1:${server.address().port}`;
      const first = await bootstrap(merchantRegistration.context);
      const firstScope = await composition.launches.resolveCapability(first.bearer);
      const firstActor = await composition.personaAuth.authenticateBoundToken({ scope: firstScope,
        token: first.persona.token });
      const persona = { id: firstActor.user.id, role: 'merchant' };
      await composition.catalog.prepareTarget({ scope: firstScope, persona });
      const created = await composition.catalog.createMerchantProduct({ scope: firstScope, persona,
        personaSession: { sessionId: firstActor.sessionId, authorityVersion: firstActor.authorityVersion },
        listing: { name: `Gallery fixture ${suffix}`, description: 'Two owned local images',
          price: 12.5, category: 'fixture', templateSource: '{{source}}',
          images: ['/secureshop/product-placeholder.svg', `${origin}/favicon.svg`] } });
      assert.ok(Number.isSafeInteger(created.productId) && created.productId > 0);
      const stocked = (await review.query(`SELECT product_id,stock_quantity FROM secureshop_review.product_target_products
        WHERE target_id=$1 AND retailer_id=$2 AND status='active' AND stock_quantity>0
        ORDER BY product_id LIMIT 1`,
      [(await scenes.readExisting(firstScope)).targetId, firstActor.user.id])).rows[0];
      assert.ok(Number(stocked?.product_id) > 0 && Number(stocked.stock_quantity) > 0,
        'guest cart and checkout use a real in-stock source product');
      assert.notEqual(Number(stocked.product_id), created.productId,
        'merchant gallery listing starts with zero stock and is not the checkout item');

      // The merchant setup legitimately provisions one scene. G13 measures
      // only the subsequent anonymous browser window, not an empty database.
      const guestProvisioning = async () => ({
        launches: Number((await identity.query('SELECT count(*)::int AS n FROM identity.secureshop_launches')).rows[0].n),
        reservations: Number((await identity.query('SELECT count(*)::int AS n FROM identity.secureshop_target_reservations')).rows[0].n),
        grants: Number((await identity.query('SELECT count(*)::int AS n FROM identity.secureshop_scene_execution_grants')).rows[0].n),
        personaSessions: Number((await agents.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_persona_sessions')).rows[0].n),
        productTargets: Number((await review.query('SELECT count(*)::int AS n FROM secureshop_review.product_targets')).rows[0].n),
      });

      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const cartImport = require('../../server/services/secureshopStandaloneCartImport')
        .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
          personaAuth: composition.personaAuth, commerce: composition.commerce });
      const protectedReset = require('../../server/services/secureshopStandaloneReset')
        .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
          launches: composition.launches, scenes,
          resetCoordinator: reset.launchResetCoordinator, preflight: reset.sceneResetPreflight });
      const realPractices = require('../../server/services/secureshopPracticeAdmission')
        .createSecureShopPracticeAdmission({ repository:
          require('../../server/database/postgres/secureshopPracticeAdmissionRepository')
            .createSecureShopPracticeAdmissionRepository({ pool: identity }), catalog: composition.catalog });
      let denyNextPracticeForCapacity = false;
      const practices = Object.freeze({ read: (...args) => realPractices.read(...args),
        create: (...args) => {
          if (denyNextPracticeForCapacity) {
            denyNextPracticeForCapacity = false;
            throw Object.assign(new Error('Controlled practice capacity'), { code: 'SHOP_PRACTICE_CAPACITY' });
          }
          return realPractices.create(...args);
        } });
      resetKeyDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-commerce-reset-keys-'));
      await fs.chmod(resetKeyDirectory, 0o700);
      const resetKeyFile = path.join(resetKeyDirectory, 'keys.json');
      await fs.writeFile(resetKeyFile, JSON.stringify({ version: 1, activeKeyId: 'native',
        keys: { native: randomBytes(32).toString('base64url') } }), { flag: 'wx', mode: 0o600 });
      const registeredAdminReset = await require('../../server/services/secureshopPasswordResetComposition')
        .prepareRegisteredAdminResetService({ filePath: resetKeyFile, pool: identity });
      assert.ok(registeredAdminReset, 'real protected account reset composition is available');
      mounted.standaloneAuth = Object.freeze({ service: auth, bootstrap, cartImport, reset: protectedReset, practices,
        mode: require('../../server/services/secureshopStandaloneMode')
          .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository }) });
      mounted.publicCatalog = publicCatalog;
      mailProduction = await require('../../server/services/secureshopMailProduction').createMailProduction({
        enabled: true, identityPool: identity, agentsPool: agents, resetComposition: reset,
        personaAuthority: grading.personaAuthority, personaRepository: composition.repositories.personas,
        provider: unavailableProvider,
        promptPolicyRepository: require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
          .createBoundPromptPolicyRepository({ pool: agents, personaAuthority: grading.personaAuthority,
            audit: audit.agents }),
        toolPolicyRepository,
        assessmentDependencies: { ...grading.assessmentDependencies, publicationModes: modeRepository,
          judge: unavailableJudge },
        authenticatePersona: composition.personaAuth.authenticatePersona,
        mode: 'vuln', modeAuthority, mailScenes: composition.mailScenes,
      });
      assert.equal(mailProduction.ready, true); mounted.mail = mailProduction;
      mounted.personaInbox = Object.freeze({ ready: true, router: express.Router() });
      mounted.mcpTrust = Object.freeze({ ready: true, router: express.Router() });
      mounted.ssrf = Object.freeze({ ready: true, router: express.Router() });
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          authenticateToken: (_request, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
      const externalMail = externalMailOptIn ? externalMailFixture.composeExternalMail({
        liveSmtp: true,
        recipient: process.env.SECURESHOP_EXTERNAL_MAIL_TEST_RECIPIENT,
        config: require('../../server/services/secureshopExternalMailTransport').readExternalMailConfiguration(),
        identityPool: identity, composition, grading, signal: externalMailAbort.signal, deadlineAt: workDeadline,
      }) : undefined;
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap, cartImport,
          reset: protectedReset, practices, registeredAdminReset, externalMail,
          mode: mounted.standaloneAuth.mode, allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      // A bound request must terminate in the bound dispatcher. This sentinel
      // makes accidental fall-through to a later legacy mount observable.
      app.use('/api/secureshop', (request, response, next) => {
        if (request.headers['x-dvaia-secureshop-launch']) {
          legacyBoundFallbackHits += 1;
          return response.status(200).json({ legacy: true });
        }
        return next();
      });
      app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
        .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
          isAvailable: async () => true }));
      app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside commerce qualifier' }));
      app.use(express.static(build, { setHeaders: response => response.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));

      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-standalone-commerce-'));
      browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
        executablePath, args: browserAdmission ? browserAdmission.browserArgs({ profile, origin, externalMail: externalMailOptIn }) : [] });
      if (browserAdmission) await browserAdmission.acknowledgeBrowser({ browser, profile });
      if (browserAdmission) browserBoundary = browserAdmission.watchBrowserTargets(browser);
      page = browserBoundary ? await browserBoundary.newPage(browser) : await browser.newPage();
      await page.setViewport({ width: 1280, height: 900 });
      const pageErrors = []; const imageResponses = [];
      const requestStages = new WeakMap();
      page.on('pageerror', error => pageErrors.push(error.message.slice(0, 200)));
      page.on('response', response => {
        const pathname = new URL(response.url()).pathname;
        if (pathname.startsWith('/api/secureshop/')) apiStatuses.push({
          method: response.request().method(), path: pathname, status: response.status(),
          stage: requestStages.get(response.request()) || null,
        });
        if (response.url() === `${origin}/secureshop/product-placeholder.svg`
          || response.url() === `${origin}/favicon.svg`)
          imageResponses.push({ url: response.url(), status: response.status() });
      });
      page.on('request', request => {
        const url = new URL(request.url());
        if (url.origin === origin && url.pathname === '/api/secureshop/v2/auth/users/me/api-keys/rotate'
            && request.method() === 'POST') keyMutationRequests += 1;
        if (url.origin === origin && url.pathname.startsWith('/api/secureshop/')) {
          requestStages.set(request, stage);
          pendingGuestApiRequests.add(request);
          const headers = request.headers();
          if (request.method() === 'GET'
            && url.pathname === '/api/secureshop/merchant/listings/readiness'
            && headers.authorization && headers['x-dvaia-secureshop-launch']) {
            boundAuthority = Object.freeze({ authorization: headers.authorization,
              launch: headers['x-dvaia-secureshop-launch'] });
          }
          guestRequests.push({ stage, method: request.method(), path: `${url.pathname}${url.search}`,
            authorization: Object.hasOwn(headers, 'authorization'),
            launch: Object.hasOwn(headers, 'x-dvaia-secureshop-launch') });
        }
      });
      const settleGuestApiRequest = request => {
        if (!pendingGuestApiRequests.delete(request) || pendingGuestApiRequests.size) return;
        for (const resolve of guestApiSettledWaiters) resolve();
        guestApiSettledWaiters.clear();
      };
      page.on('requestfinished', settleGuestApiRequest);
      page.on('requestfailed', settleGuestApiRequest);
      await page.setRequestInterception(true);
      page.on('request', request => request.url().startsWith(`${origin}/`)
        ? request.continue() : request.abort());
      const guestBefore = await guestProvisioning();
      const guestModelsBefore = modelCalls, guestJudgesBefore = judgeCalls;
      stage = 'storefront-loading';
      const lazyChunk = await holdOneRealResponse(page, `${origin}/assets/${shopChunks[0]}`);
      let firstNavigation;
      try {
        firstNavigation = page.goto(`${origin}/secureshop/product/${created.productId}`,
          { waitUntil: 'domcontentloaded' });
        await lazyChunk.wait();
        await page.waitForFunction(() => [...document.querySelectorAll('p[role="status"]')]
          .some(node => node.textContent?.includes('Opening SecureShop')),
        { timeout: 20000 });
        await shopLoadingSnapshot(page, 'lazy-chunk');
      } finally { await lazyChunk.close(); }
      assert.ok([200, 304].includes((await firstNavigation).status()));
      await stableFrame(page, 'SecureShop storefront');

      // Refresh while the actual cookie-session response is held. The route
      // must show its own spinner, then mount the same guest frame on delivery.
      stage = 'guest-session-refresh';
      const sessionHold = await holdOneRealResponse(page, `${origin}/api/secureshop/auth/session`);
      let refreshNavigation;
      try {
        refreshNavigation = page.reload({ waitUntil: 'domcontentloaded' });
        await sessionHold.wait();
        await page.waitForFunction(() => [...document.querySelectorAll('p[role="status"]')]
          .some(node => node.textContent?.includes('Opening SecureShop')),
        { timeout: 20000 });
        await shopLoadingSnapshot(page, 'session');
      } finally { await sessionHold.close(); }
      assert.ok([200, 304].includes((await refreshNavigation).status()));
      await stableFrame(page, 'SecureShop storefront');
      status.storefrontLoadingRendered = true;
      stage = 'guest-gallery';
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/product/${created.productId}`)).status()));
      const frame = await stableFrame(page, 'SecureShop storefront');
      await frame.waitForSelector('button[aria-label="Show image 2"]', { timeout: 20000 });
      const mainImage = () => frame.$eval(`img[alt="Gallery fixture ${suffix}"]`, image =>
        ({ src: image.src, complete: image.complete, width: image.naturalWidth }));
      const galleryArrow = async (label, thumb, src) => {
        const before = await gallerySnapshot(frame);
        await frame.evaluate(() => {
          window.__commerceGalleryClick = null;
          document.addEventListener('click', event => {
            window.__commerceGalleryClick = { tag: event.target?.tagName || null,
              label: event.target?.getAttribute?.('aria-label') || null,
              ancestor: event.target?.closest?.('button')?.getAttribute('aria-label') || null };
          }, { capture: true, once: true });
        });
        try {
          await frame.$eval(`button[aria-label="${label}"]`, button =>
            button.scrollIntoView({ block: 'center', inline: 'center' }));
          await frame.waitForFunction(target => {
            const button = document.querySelector(`button[aria-label="${target}"]`);
            if (!button) return false;
            const rect = button.getBoundingClientRect();
            const hit = document.elementFromPoint(rect.left + rect.width / 2,
              rect.top + rect.height / 2);
            return button.contains(hit);
          }, { timeout: 3000 }, label);
          await frame.click(`button[aria-label="${label}"]`);
          await frame.waitForFunction((selected, expected) => {
            const button = document.querySelector(`button[aria-label="Show image ${selected}"]`);
            return button?.getAttribute('aria-current') === 'true'
              && [...document.querySelectorAll('img[alt^="Gallery fixture "]')]
                .some(image => image.src === expected && image.complete && image.naturalWidth > 0);
          }, { timeout: 5000 }, thumb, src);
        } catch (cause) {
          const after = await gallerySnapshot(frame).catch(() => null);
          const screenshotPath = receiptPath.replace(/\.json$/i, '') + '-gallery-failure.png';
          await fs.writeFile(screenshotPath, await page.screenshot(), { flag: 'wx', mode: 0o600 });
          throw Object.assign(new Error(`Gallery ${label} did not select image ${thumb}: ${JSON.stringify({
            before, after, pageErrors: pageErrors.slice(-4), imageResponses: imageResponses.slice(-6),
            screenshot: screenshotPath,
          })}`), { code: 'GALLERY_NAVIGATION_UNVERIFIED', cause });
        }
      };
      assert.equal((await mainImage()).src, `${origin}/secureshop/product-placeholder.svg`);
      await frame.click('button[aria-label="Show image 2"]');
      await frame.waitForFunction(src => [...document.querySelectorAll('img')]
        .some(image => image.alt.startsWith('Gallery fixture ') && image.src === src && image.complete
          && image.naturalWidth > 0), {}, `${origin}/favicon.svg`);
      assert.equal((await mainImage()).src, `${origin}/favicon.svg`);
      await galleryArrow('Previous image', 1, `${origin}/secureshop/product-placeholder.svg`);
      await galleryArrow('Next image', 2, `${origin}/favicon.svg`);
      assert.ok(imageResponses.some(row => row.url.endsWith('/secureshop/product-placeholder.svg') && row.status === 200));
      assert.ok(imageResponses.some(row => row.url.endsWith('/favicon.svg') && row.status === 200));
      assert.deepEqual(pageErrors, []);
      status.galleryRendered = true;

      // Observe a real in-frame navigation. It should retain the single shop
      // document and never insert the platform's workshop loading surface.
      await page.evaluate(() => {
        window.__shopWorkshopFlash = document.body.textContent.includes('Loading Workshop');
        window.__shopLoadingObserver = new MutationObserver(() => {
          if (document.body.textContent.includes('Loading Workshop')) window.__shopWorkshopFlash = true;
        });
        window.__shopLoadingObserver.observe(document.body,
          { childList: true, subtree: true, characterData: true });
      });
      await frame.$eval('a[href="/secureshop/catalog"]', link =>
        link.scrollIntoView({ block: 'center', inline: 'center' }));
      await frame.click('a[href="/secureshop/catalog"]');
      await page.waitForFunction(() => location.pathname === '/secureshop/catalog', { timeout: 20000 });
      assert.deepEqual(await page.evaluate(() => {
        window.__shopLoadingObserver.disconnect();
        return { workshopFlash: window.__shopWorkshopFlash,
          shopFrames: document.querySelectorAll('iframe[title^="SecureShop"]').length,
          route: location.pathname };
      }), { workshopFlash: false, shopFrames: 1, route: '/secureshop/catalog' });

      stage = 'a08-landing-buttons';
      await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'no-preference' }]);
      const parentCanary = `guest-parent-${randomUUID()}`;
      await page.evaluate(value => localStorage.setItem('dvaia.guest-isolation-canary', value), parentCanary);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop`)).status()));
      const landingFrame = await stableFrame(page, 'SecureShop storefront');
      await qualifyRoleButtons(page, landingFrame, 'landing', [
        { selector: 'a.ss-btn', text: 'Register', size: 'sm', variant: 'primary' },
        { selector: 'a.ss-btn', text: 'Sign in', size: 'lg', variant: 'primary' },
        { selector: 'a.ss-btn', text: 'Browse as guest', size: 'lg', variant: 'ghost' },
      ], receiptPath);

      // The public guest bridge admits only catalog GETs. Once the final
      // landing page is settled, an additional bounded idle interval must
      // produce no background API polling or protected provisioning.
      await landingFrame.waitForFunction(() => {
        const shelves = [...document.querySelectorAll('.ss-shelf__row')];
        return shelves.length === 3 && shelves.every(row => !row.querySelector('.ss-skel'));
      }, { timeout: 10000 });
      if (pendingGuestApiRequests.size) await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          guestApiSettledWaiters.delete(done);
          reject(new Error(`Guest API requests did not settle: ${pendingGuestApiRequests.size}`));
        }, 10000);
        const done = () => { clearTimeout(timer); resolve(); };
        guestApiSettledWaiters.add(done);
        if (!pendingGuestApiRequests.size) {
          guestApiSettledWaiters.delete(done);
          done();
        }
      });
      const settledGuestRequests = guestRequests.length;
      await new Promise(resolve => setTimeout(resolve, 1200));
      assert.equal(guestRequests.length, settledGuestRequests,
        'settled anonymous landing must not poll the shop API');
      assert.ok(guestRequests.some(row => row.path.startsWith('/api/secureshop/public/')),
        'guest navigation must use real public catalog reads');
      assert.ok(guestRequests.every(row => row.method === 'GET'
        && (row.path.startsWith('/api/secureshop/public/')
          || row.path === '/api/secureshop/auth/session')),
      'guest navigation must not call launch, target, or agent endpoints');
      assert.ok(guestRequests.every(row => !row.authorization && !row.launch),
        'guest requests must carry no persona token or launch bearer');
      const publicReads = guestRequests.filter(row => row.path.startsWith('/api/secureshop/public/'));
      const perTransition = new Set(publicReads.map(row => `${row.stage}\n${row.path}`));
      assert.equal(perTransition.size, publicReads.length,
        'each guest transition must issue each exact catalog read at most once');
      assert.deepEqual(await guestProvisioning(), guestBefore,
        'guest transitions and reload must create no launch, target, grant, or persona session');
      assert.equal(modelCalls, guestModelsBefore);
      assert.equal(judgeCalls, guestJudgesBefore);
      status.guestRequestBudget = true;

      stage = 'guest-landing-and-isolation';
      const desktopLanding = await landingFrame.evaluate(() => {
        const root = document.querySelector('.ss-root');
        const hero = document.querySelector('.ss-landing-hero');
        const footer = document.querySelector('footer.ss-footer');
        const picker = hero?.querySelector('svg[viewBox="0 0 500 460"] > g:last-of-type');
        const css = root && getComputedStyle(root);
        return { title: hero?.querySelector('h1')?.innerText.replace(/\s+/g, ' ').trim() || null,
          shelves: [...document.querySelectorAll('h2.ss-shelf__title')].map(node => node.textContent.trim()),
          rows: [...document.querySelectorAll('.ss-shelf__row')].map(node => ({
            loading: !!node.querySelector('.ss-skel'), error: node.textContent.includes('Products are unavailable'),
            content: node.children.length })),
          columns: hero && getComputedStyle(hero).gridTemplateColumns.split(' ').filter(Boolean).length,
          theme: css && ['--paper', '--ink', '--carbon', '--copper', '--display', '--body']
            .map(key => css.getPropertyValue(key).trim()),
          footer: footer?.textContent.includes('An educational agentic-commerce lab') || false,
          picker: picker ? getComputedStyle(picker).transform : null };
      });
      assert.match(desktopLanding.title || '', /Everything you need\. Now with agents that actually shop for you\./);
      assert.deepEqual(desktopLanding.shelves, ['Electronics', 'Beauty', 'Books']);
      assert.equal(desktopLanding.rows.length, 3);
      assert.ok(desktopLanding.rows.every(row => !row.loading && !row.error && row.content > 0));
      assert.equal(desktopLanding.columns, 2);
      assert.deepEqual(desktopLanding.theme?.slice(0, 4).map(value => value.toLowerCase()),
        ['#f6f5f0', '#0b0d10', '#1a1d22', '#8a6741']);
      assert.ok(desktopLanding.theme?.slice(4).every(Boolean));
      assert.equal(desktopLanding.footer, true);
      assert.ok(desktopLanding.picker && desktopLanding.picker !== 'none');
      await new Promise(resolve => setTimeout(resolve, 300));
      const movingPicker = await landingFrame.$eval('svg[viewBox="0 0 500 460"] > g:last-of-type',
        element => getComputedStyle(element).transform);
      assert.notEqual(movingPicker, desktopLanding.picker, 'warehouse picker must visibly animate');
      const desktopLandingScreenshot = receiptPath.replace(/\.json$/i, '') + '-landing-desktop.png';
      await fs.writeFile(desktopLandingScreenshot, await page.screenshot(), { flag: 'wx', mode: 0o600 });
      await page.setViewport({ width: 390, height: 844 });
      const narrowLanding = await landingFrame.evaluate(() => {
        const hero = document.querySelector('.ss-landing-hero');
        return { width: innerWidth, columns: hero && getComputedStyle(hero).gridTemplateColumns.split(' ').filter(Boolean).length,
          pageWidth: document.documentElement.scrollWidth,
          footer: !!document.querySelector('footer.ss-footer') };
      });
      assert.equal(narrowLanding.width, 390);
      assert.equal(narrowLanding.columns, 1);
      assert.ok(narrowLanding.pageWidth <= narrowLanding.width + 1, 'narrow landing must not overflow horizontally');
      assert.equal(narrowLanding.footer, true);
      const narrowLandingScreenshot = receiptPath.replace(/\.json$/i, '') + '-landing-narrow.png';
      await fs.writeFile(narrowLandingScreenshot, await page.screenshot(), { flag: 'wx', mode: 0o600 });
      await page.setViewport({ width: 1280, height: 900 });
      status.guestLandingResponsive = true;

      const sandbox = await page.$eval('iframe[title="SecureShop storefront"]',
        element => element.getAttribute('sandbox'));
      assert.equal(sandbox, 'allow-scripts allow-forms');
      const guestBoundary = await landingFrame.evaluate(value => {
        const blocked = read => { try { read(); return false; } catch (error) { return error?.name === 'SecurityError'; } };
        return { opaqueOrigin: self.origin === 'null',
          ownLocalStorageBlocked: blocked(() => localStorage.length),
          ownSessionStorageBlocked: blocked(() => sessionStorage.length),
          parentDocumentBlocked: blocked(() => parent.document.body),
          parentStorageBlocked: blocked(() => parent.localStorage.length),
          canaryVisible: document.body.textContent.includes(value) };
      }, parentCanary);
      assert.deepEqual(guestBoundary, { opaqueOrigin: true, ownLocalStorageBlocked: true,
        ownSessionStorageBlocked: true, parentDocumentBlocked: true,
        parentStorageBlocked: true, canaryVisible: false });
      assert.equal(await page.evaluate(() => localStorage.getItem('dvaia.guest-isolation-canary')), parentCanary);
      await page.evaluate(() => localStorage.removeItem('dvaia.guest-isolation-canary'));
      status.guestOpaqueIsolation = true;

      // G20 begins with the real guest frame/cart channel. Parent session
      // storage must be written by the guest UI; the test never forges it.
      stage = 'guest-cart-import';
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/product/${stocked.product_id}`)).status()));
      const guestFrame = await stableFrame(page, 'SecureShop storefront');
      await guestFrame.waitForSelector('button', { timeout: 20000 });
      await guestFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === 'Add to cart' && !button.disabled));
      await guestFrame.evaluate(() => [...document.querySelectorAll('button')]
        .find(button => button.textContent.trim() === 'Add to cart').click());
      await page.waitForFunction(productId => {
        const raw = sessionStorage.getItem('dvaia.secureshop.guest-cart.v1');
        if (!raw) return false;
        try { return JSON.parse(raw).items.some(item => item.productId === productId && item.quantity === 1); }
        catch { return false; }
      }, {}, Number(stocked.product_id));
      const guestSaved = await page.evaluate(() => sessionStorage.getItem('dvaia.secureshop.guest-cart.v1'));
      assert.ok(guestSaved);
      const importResponses = [];
      const cartReadbacks = [];
      const boundErrors = [];
      page.on('response', response => {
        const pathname = new URL(response.url()).pathname;
        if (pathname.startsWith('/api/secureshop/') && response.status() >= 400)
          boundErrors.push({ method: response.request().method(), path: pathname,
            status: response.status() });
        if (response.request().method() === 'POST'
          && pathname === '/api/secureshop/auth/cart-import')
          importResponses.push(response);
        if (response.request().method() === 'GET' && pathname === '/api/secureshop/cart') {
          const observation = { status: response.status(), path: pathname,
            frame: response.frame()?.url().startsWith(`${origin}/secureshop-frame.html`) === true };
          cartReadbacks.push(observation);
          void response.json().then(body => {
            observation.items = Array.isArray(body?.items) ? body.items.map(item => ({
              productId: item.product_id, quantity: item.quantity,
            })).slice(0, 5) : null;
            observation.error = typeof body?.error === 'string' ? body.error.slice(0, 120) : null;
          }).catch(() => { observation.bodyUnavailable = true; });
        }
      });
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()));
      await page.waitForSelector('#ss-login-user');
      stage = 'a08-login-buttons';
      await qualifyRoleButtons(page, page, 'login', [
        { selector: 'button.ss-btn', text: 'Sign in', size: 'md', variant: 'primary', stretch: true },
      ], receiptPath);
      stage = 'guest-cart-import';
      await page.type('#ss-login-user', customerName);
      await page.type('#ss-login-pw', password);
      await page.click('button[type="submit"]');
      await page.waitForSelector('aside[aria-label="Saved guest cart"] button', { timeout: 20000 });
      await page.$eval('aside[aria-label="Saved guest cart"]', aside => {
        const button = [...aside.querySelectorAll('button')]
          .find(candidate => candidate.textContent.trim() === 'Add saved items');
        if (!button) throw new Error('Guest cart import action unavailable');
        button.click();
      });
      try {
        await page.waitForFunction(() => document.querySelector('aside[aria-label="Saved guest cart"]')
          ?.textContent.includes('Your saved items are in your shop cart.'), { timeout: 10000 });
      } catch (cause) {
        const parent = await page.evaluate(() => ({
          route: location.pathname,
          savedCart: document.querySelector('aside[aria-label="Saved guest cart"]')?.textContent.trim().slice(0, 500) || null,
          frameTitles: [...document.querySelectorAll('iframe')].map(frame => frame.title).slice(0, 3),
          savedIntentPresent: sessionStorage.getItem('dvaia.secureshop.guest-cart.v1') !== null,
        }));
        const response = await Promise.all(importResponses.map(async value => {
          const body = await value.json().catch(() => null);
          return { status: value.status(), imported: body?.imported ?? null,
            replayed: body?.replayed ?? null, error: typeof body?.error === 'string' ? body.error.slice(0, 160) : null,
            issues: Array.isArray(body?.issues) ? body.issues.map(row => row.code).slice(0, 5) : [] };
        }));
        const frame = await stableFrame(page).catch(() => null);
        const bound = frame && await frame.evaluate(() => ({
          route: location.pathname,
          cartRows: document.querySelectorAll('table[aria-label="Cart items"] tbody tr').length,
          alert: document.querySelector('[role="alert"]')?.textContent.trim().slice(0, 180) || null,
        })).catch(() => null);
        throw Object.assign(new Error(`Guest import acknowledgement unavailable: ${JSON.stringify({
          parent, response, bound, cartReadbacks: cartReadbacks.slice(-8),
          boundErrors: boundErrors.slice(-8),
          pageErrors: pageErrors.slice(-4),
        })}`), { code: 'GUEST_IMPORT_UNVERIFIED', cause });
      }
      assert.equal(importResponses.length, 1, 'one customer import request follows the guest intent');
      assert.equal(importResponses[0].status(), 200);
      const imported = await importResponses[0].json();
      assert.equal(imported.imported, true);
      assert.equal(imported.items.find(item => item.productId === Number(stocked.product_id))?.quantity, 1);
      assert.equal(await page.evaluate(() => sessionStorage.getItem('dvaia.secureshop.guest-cart.v1')), null,
        'guest intent clears only after the bound cart readback');
      const customerFrame = await stableFrame(page);
      await customerFrame.evaluate(() => {
        const link = document.querySelector('a[href="/secureshop/cart"]');
        if (!link) throw Error('Bound cart link unavailable');
        link.click();
      });
      const importedRowSelector = `table[aria-label="Cart items"] a[href="/secureshop/product/${stocked.product_id}"]`;
      await customerFrame.waitForSelector(importedRowSelector, { timeout: 20000 });
      const cartRow = await customerFrame.$eval(importedRowSelector,
        link => ({ name: link.textContent.trim(), quantity: link.closest('tr')?.querySelector('input.ss-qty__val')?.value }));
      assert.ok(cartRow.name);
      assert.equal(cartRow.quantity, '1', 'rendered bound cart confirms the exact imported product and quantity');
      status.guestImportReadback = true;

      // C15 sends exactly one real bound checkout. The browser creates an owned
      // address and named synthetic payment choice, prepares its exact quote,
      // then loses only the committed confirmation response before authenticated
      // operation GET recovery.
      stage = 'checkout-navigation';
      await customerFrame.click('a[href="/secureshop/checkout"]');
      await customerFrame.waitForFunction(() =>
        [...document.querySelectorAll('.ss-card__meta')]
          .some(node => node.textContent.trim() === 'Saved orders')
        && [...document.querySelectorAll('h2')]
          .some(node => node.textContent.trim() === 'Delivery address'),
      { timeout: 20000 });
      stage = 'checkout-form';
      for (const [label, value] of [
        ['Full name', 'Disposable Buyer'], ['Address', '4 Fixture Way'],
        ['City', 'Test City'], ['State', 'CA'], ['ZIP', '90001'], ['Phone', '5550100'],
      ]) await typeLabeled(customerFrame, label, value);
      await customerFrame.$eval('form button[type="submit"]', button => button.click());
      // A fresh disposable customer has no saved address yet.  Checkout
      // renders the bound address-save handoff in that case; complete the
      // visible review/confirm flow before waiting for the payment step.
      await customerFrame.waitForSelector('section[aria-label="Address setup"]', { timeout: 20000 });
      await customerFrame.waitForFunction(() => {
        const fields = Object.fromEntries([...document.querySelectorAll(
          'section[aria-label="Address setup"] input[aria-label]')]
          .map(input => [input.getAttribute('aria-label'), input.value]));
        return fields['Street address'] === '4 Fixture Way' && fields.City === 'Test City'
          && fields.State === 'CA' && fields.ZIP === '90001';
      }, { timeout: 20000 });
      const addressDraft = await customerFrame.$$eval(
        'section[aria-label="Address setup"] input[aria-label]',
        inputs => Object.fromEntries(inputs.map(input => [input.getAttribute('aria-label'), input.value])));
      assert.equal(addressDraft['Street address'], '4 Fixture Way');
      assert.equal(addressDraft.City, 'Test City');
      assert.equal(addressDraft.State, 'CA');
      assert.equal(addressDraft.ZIP, '90001');
      await customerFrame.waitForFunction(() => {
        const button = document.querySelector('section[aria-label="Address setup"] button');
        return button?.textContent.trim() === 'Review address' && !button.disabled;
      }, { timeout: 20000 });
      await customerFrame.$eval('section[aria-label="Address setup"] button', button => {
        if (button.textContent.trim() !== 'Review address') throw Error('Address review control unavailable');
        button.click();
      });
      await customerFrame.waitForSelector('[aria-label="Address changes to confirm"]', { timeout: 20000 });
      await customerFrame.$eval('section[aria-label="Address setup"] button', button => {
        if (button.textContent.trim() !== 'Confirm address save') throw Error('Address confirmation control unavailable');
        button.click();
      });
      await customerFrame.waitForFunction(() => document.body.textContent.includes('Choose a synthetic practice payment. This checkout never collects card details.')
        && !document.body.textContent.includes('Card number') && !document.body.textContent.includes('CVV'), { timeout: 20000 });
      await customerFrame.waitForSelector('input[name="practice-address"]', { timeout: 20000 });
      await customerFrame.evaluate(() => {
        const button = [...document.querySelectorAll('button')]
          .find(value => value.textContent.trim() === 'Use approved practice payment');
        if (!button) throw Error('Synthetic approved payment control unavailable');
        button.click();
      });
      await customerFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === 'Create selected practice payment'
          && !button.disabled), { timeout: 20000 });
      await customerFrame.evaluate(() => [...document.querySelectorAll('button')]
        .find(button => button.textContent.trim() === 'Create selected practice payment').click());
      await customerFrame.waitForSelector('input[name="practice-payment"]', { timeout: 20000 });
      await customerFrame.$eval('input[name="practice-address"]', input => input.click());
      await customerFrame.$eval('input[name="practice-payment"]', input => input.click());
      const checkoutPosts = [];
      const preparePosts = [];
      page.on('request', request => {
        const pathname = new URL(request.url()).pathname;
        if (request.method() === 'POST' && pathname === '/api/secureshop/customer/commerce/checkout/confirm')
          checkoutPosts.push(request);
        if (request.method() === 'POST' && pathname === '/api/secureshop/customer/commerce/checkout/prepare')
          preparePosts.push(request);
      });
      await customerFrame.$eval('form button[type="submit"]', button => button.click());
      await customerFrame.waitForFunction(() =>
        [...document.querySelectorAll('h2')]
          .some(node => node.textContent.trim() === 'Review your order')
        && [...document.querySelectorAll('button')]
          .some(node => node.textContent.trim() === 'Place order'));
      // A first explicit action only prepares and renders the exact quote. It
      // must not dispatch confirmation before the buyer sees that quote.
      await customerFrame.evaluate(() => [...document.querySelectorAll('button')]
        .find(button => button.textContent.trim() === 'Place order').click());
      await customerFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(node => node.textContent.trim() === 'Confirm exact quote')
        && document.body.textContent.includes('Quote:'), { timeout: 20000 });
      assert.equal(checkoutPosts.length, 0, 'preparing an exact quote cannot confirm checkout');
      stage = 'checkout-commit';
      const loss = await dropOneCommittedCheckoutResponse(page, `${origin}/api/secureshop/customer/commerce/checkout/confirm`);
      await customerFrame.evaluate(() => [...document.querySelectorAll('button')]
        .find(button => button.textContent.trim() === 'Confirm exact quote').click());
      let committed;
      try {
        const until = Date.now() + 30000;
        while (!committed && Date.now() < until) {
          committed = loss.captured();
          if (!committed) await new Promise(resolve => setTimeout(resolve, 50));
        }
        assert.ok(committed, 'the real checkout must commit before delivery loss');
      } finally { await loss.close(); }
      assert.equal(checkoutPosts.length, 1);
      assert.equal(preparePosts.length, 1, 'one exact quote is prepared before confirmation');
      const preparedRequest = JSON.parse(preparePosts[0].postData());
      assert.deepEqual(Object.keys(preparedRequest).sort(), ['addressChoiceId', 'operationId', 'paymentChoiceId']);
      for (const value of Object.values(preparedRequest)) assert.match(value, /^[0-9a-f-]{36}$/i);
      assert.equal(committed.operationId, preparedRequest.operationId);
      status.checkoutOnce = true;

      // A17: an unresolved saved checkout reference must keep the current
      // practice mounted. The real parent chooser may not silently move the
      // buyer to another scene until the exact saved operation is read back.
      stage = 'retained-scene-pending-denial';
      const pendingCheckoutFrame = await page.$('iframe[title="SecureShop"]');
      assert.ok(pendingCheckoutFrame);
      await page.click('button[aria-controls="secureshop-settings"]');
      await page.waitForSelector('#secureshop-settings section[aria-label="Retained shop practices"] button');
      await page.click('#secureshop-settings section[aria-label="Retained shop practices"] button');
      await page.waitForFunction(() => document.querySelector('#secureshop-settings section[aria-label="Retained shop practices"] [role="alert"]')
        ?.textContent.trim() === 'Check saved operation status before choosing another practice.',
      { timeout: 20000 });
      assert.equal(await page.evaluate(oldFrame => oldFrame === document.querySelector('iframe[title="SecureShop"]'),
        pendingCheckoutFrame), true, 'denied selection preserves the original mounted shop frame');
      assert.equal(checkoutPosts.length, 1, 'chooser denial cannot replay checkout');
      await page.click('button[aria-controls="secureshop-settings"]');

      stage = 'checkout-recovery';
      assert.ok([200, 304].includes((await page.reload()).status()));
      const recoveredFrame = await stableFrame(page);
      await recoveredFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(node => node.textContent.trim() === 'Check saved order'), { timeout: 20000 });
      assert.equal(checkoutPosts.length, 1, 'reload must not resubmit uncertain checkout');
      await recoveredFrame.evaluate(() => [...document.querySelectorAll('button')]
        .find(button => button.textContent.trim() === 'Check saved order').click());
      await recoveredFrame.waitForFunction(orderId => document.body.textContent.includes(`order #${orderId}`)
        && document.body.textContent.includes('This receipt was confirmed from saved orders.'),
      { timeout: 20000 }, committed.orderId);
      assert.equal(checkoutPosts.length, 1, 'GET recovery must not issue a second order POST');
      status.checkoutRecovered = true;
      stage = 'commerce-role-readback';
      const cookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(cookie?.httpOnly, true);
      const buyerBase = await auth.authenticate(cookie.value);
      assert.ok(buyerBase);
      const actor = async base => {
        const ready = await bootstrap(base);
        const scope = await composition.launches.resolveCapability(ready.bearer);
        const result = await composition.personaAuth.authenticateBoundToken({ scope,
          token: ready.persona.token });
        return { scope, persona: result.user, personaSession: {
          sessionId: result.sessionId, authorityVersion: result.authorityVersion } };
      };
      const buyer = await actor(buyerBase);
      const buyerHistory = await composition.commerce.checkoutHistory(buyer);
      assert.equal(buyerHistory.operations.filter(row => row.operationId === committed.operationId).length, 1);
      const buyerOrder = await composition.commerce.order({ ...buyer, orderId: committed.orderId });
      assert.equal(buyerOrder.order.id, committed.orderId);
      assert.equal(Number(buyerOrder.order.total_amount), committed.total);
      const siblingName = `commerce_peer_${suffix}`;
      const siblingAccount = await auth.register({ username: siblingName,
        email: `${siblingName}@example.invalid`, password, role: 'customer' });
      const sibling = await actor(siblingAccount.context);
      const siblingCredentials = await bootstrap(siblingAccount.context);
      assert.equal(siblingCredentials.launch.launchId, sibling.scope.launchId);
      const siblingHistory = await composition.commerce.checkoutHistory(sibling);
      assert.deepEqual(siblingHistory.operations, [], 'same-tenant sibling has no buyer checkout history');
      assert.equal(await composition.commerce.order({ ...sibling, orderId: committed.orderId }), null);
      status.siblingPrivate = true;
      const merchant = await actor(merchantRegistration.context);
      const merchantOverview = await composition.commerce.merchantOverview({ ...merchant, days: 30 });
      assert.equal(merchantOverview.kpis.orders.value, 1,
        'the seller of the purchased source item sees one owned order');
      assert.equal(merchantOverview.kpis.revenue.value, committed.total);
      const adminLogin = await auth.login({ username: 'student_admin', password: 'student123' });
      const admin = await actor(adminLogin.context);
      const adminSummary = await composition.admin.kpis(admin);
      assert.equal(adminSummary.total_orders, 1);
      assert.equal(adminSummary.total_revenue, committed.total);
      assert.equal(buyerHistory.operations[0].orderId, committed.orderId);
      status.roleParity = true;

      stage = 'customer-admin-api-denial';
      assert.equal(await recoveredFrame.evaluate(async () =>
        (await fetch('/api/secureshop/admin/users?page=1&pageSize=25')).status), 403,
      'the current standalone customer cannot read the administrator directory');
      assert.equal(await recoveredFrame.evaluate(async () =>
        (await fetch('/api/secureshop/admin/access-control')).status), 403,
      'the current standalone customer cannot read the administrator ACL');
      status.customerAdminApiDenied = true;

      // A17: provision a second owned target through the supported catalog
      // reservation path under a distinct, real merchant login. Discovery
      // adopts its exact active target as a second retained scene. The buyer's
      // earlier scene already contains the committed order above.
      stage = 'retained-scene-setup';
      const originalScenes = await scenes.list(buyer.scope);
      assert.equal(originalScenes.length, 1);
      retainedSceneA = originalScenes[0];
      assert.equal(retainedSceneA.isDefault, true);
      assert.equal((await scenes.readExisting(buyer.scope)).targetId,
        (await scenes.readExisting(firstScope)).targetId);
      const laterMerchantLogin = await auth.login({ username: 'student_merchant', password: 'student123' });
      const laterMerchantReady = await bootstrap(laterMerchantLogin.context);
      const laterMerchantScope = await composition.launches.resolveCapability(laterMerchantReady.bearer);
      const laterMerchantActor = await composition.personaAuth.authenticateBoundToken({ scope: laterMerchantScope,
        token: laterMerchantReady.persona.token });
      assert.equal(laterMerchantActor.user.id, firstActor.user.id);
      assert.notEqual(laterMerchantScope.platformSessionId, firstScope.platformSessionId);
      const retainedCatalog = require('../../server/services/secureshopBoundCatalog')
        .createSecureShopBoundCatalog({ sourcePool: commerce, repository: composition.repositories.products,
          personaAuthority: grading.personaAuthority,
          resolveTarget: scope => composition.launches.reserveProductsTarget({ launchId: scope.launchId,
            platformSessionId: scope.platformSessionId, platformOwnerId: scope.platformOwnerId,
            expectedGeneration: scope.generation }),
          checkCurrent: scope => composition.launches.assertCurrent(scope) });
      const laterTarget = await retainedCatalog.prepareTarget({ scope: laterMerchantScope,
        persona: { id: laterMerchantActor.user.id, role: 'merchant' } });
      assert.notEqual(laterTarget.targetId, (await scenes.readExisting(buyer.scope)).targetId);
      const retainedScenes = await scenes.list(buyer.scope);
      assert.equal(retainedScenes.length, 2, 'real second target becomes an owned retained scene');
      retainedSceneB = retainedScenes.find(scene => scene.id !== retainedSceneA.id);
      assert.ok(retainedSceneB?.id && retainedSceneB.isDefault === false);
      assert.equal((await identity.query(`SELECT product_target_id FROM identity.secureshop_scenes
        WHERE scene_id=$1 AND original_platform_owner_id=$2 AND status='active'`,
      [retainedSceneB.id, buyer.scope.platformOwnerId])).rows[0]?.product_target_id, laterTarget.targetId);
      assert.equal(retainedScenes.find(scene => scene.id === retainedSceneA.id)?.isDefault, true);

      stage = 'retained-scene-chooser';
      await page.click('button[aria-controls="secureshop-settings"]');
      const inspectChooser = () => page.evaluate(() => {
        const section = document.querySelector('#secureshop-settings section[aria-label="Retained shop practices"]');
        const button = section?.querySelector('button');
        const bounds = button?.getBoundingClientRect();
        const hit = bounds && document.elementFromPoint(bounds.left + bounds.width / 2,
          bounds.top + bounds.height / 2);
        return { sectionVisible: !!section, buttonConnected: !!button?.isConnected,
          buttonDisabled: button?.disabled ?? null,
          frameBusy: document.querySelector('[data-testid="secureshop-frame-host"]')?.getAttribute('aria-busy') || null,
          buttonInViewport: !!bounds && bounds.width > 0 && bounds.height > 0
            && bounds.left >= 0 && bounds.top >= 0
            && bounds.right <= innerWidth && bounds.bottom <= innerHeight,
          buttonHit: !!button && (hit === button || button.contains(hit)),
          practiceError: section?.querySelector('[role="alert"]')?.textContent.trim() || null,
          chooserVisible: [...document.querySelectorAll('h1')]
            .some(node => node.textContent.trim() === 'Choose a shop practice.') };
      });
      sceneChooserDiagnostic = { before: await inspectChooser() };
      assert.equal(sceneChooserDiagnostic.before.buttonDisabled, false,
        'retained practice chooser must be enabled before the physical click');
      assert.equal(sceneChooserDiagnostic.before.buttonHit, true,
        'retained practice chooser center must receive the physical click');
      await page.evaluate(() => {
        const button = document.querySelector('#secureshop-settings section[aria-label="Retained shop practices"] button');
        const probe = { target: 0, bubbled: 0, trusted: false };
        const target = event => { probe.target++; probe.trusted ||= event.isTrusted; };
        const bubbled = event => { if (button.contains(event.target)) probe.bubbled++; };
        button.addEventListener('click', target);
        document.addEventListener('click', bubbled);
        window.__a11ChooserClickProbe = { probe, close() {
          button.removeEventListener('click', target);
          document.removeEventListener('click', bubbled);
        } };
      });
      const chooserRequests = [];
      const onChooserRequest = request => {
        if (request.method() === 'GET' && new URL(request.url()).pathname === '/api/secureshop/v2/scenes')
          chooserRequests.push('scenes-get');
      };
      page.on('request', onChooserRequest);
      try {
        await page.click('#secureshop-settings section[aria-label="Retained shop practices"] button');
        sceneChooserDiagnostic.after = await inspectChooser();
        await page.waitForFunction(() => [...document.querySelectorAll('h1')]
          .some(node => node.textContent.trim() === 'Choose a shop practice.'), { timeout: 20000 });
      } finally {
        page.off('request', onChooserRequest);
        sceneChooserDiagnostic.sceneGets = chooserRequests.length;
        sceneChooserDiagnostic.click = await boundedA11('retained-chooser-click-probe', () => page.evaluate(() => {
          const current = window.__a11ChooserClickProbe;
          if (!current) return null;
          current.close();
          delete window.__a11ChooserClickProbe;
          return current.probe;
        }), 3000).catch(() => null);
      }
      const chooserLabels = await page.$$eval('main button strong', nodes => nodes.map(node => node.textContent.trim()));
      assert.deepEqual(chooserLabels, retainedScenes.map(scene => scene.label));
      const selectRenderedScene = async scene => {
        const buttons = await page.$$('main button');
        const button = await (async () => {
          for (const candidate of buttons) {
            if (await candidate.$eval('strong', node => node.textContent.trim()).catch(() => null) === scene.label)
              return candidate;
          }
          return null;
        })();
        assert.ok(button, 'the exact retained scene appears as a physical chooser button');
        const response = page.waitForResponse(value => new URL(value.url()).pathname === '/api/secureshop/v2/scenes/select'
          && value.request().method() === 'POST', { timeout: 20000 })
          .then(value => ({ value }), error => ({ error }));
        await button.click();
        const settled = await response;
        if (settled.error) throw settled.error;
        const selected = settled.value;
        assert.equal(selected.status(), 200);
        assert.deepEqual(JSON.parse(selected.request().postData()), { sceneId: scene.id });
        assert.deepEqual(await selected.json(), { id: scene.id, isDefault: true });
        await stableFrame(page);
        await page.waitForSelector('button[aria-controls="secureshop-settings"]', { timeout: 20000 });
      };
      await selectRenderedScene(retainedSceneB);
      assert.equal((await scenes.readExisting(buyer.scope)).targetId, laterTarget.targetId);
      assert.equal(await composition.commerce.order({ ...buyer, orderId: committed.orderId }), null,
        'the later scene cannot read the earlier scene’s purchase');
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/orders`)).status()));
      let retainedOrdersFrame = await stableFrame(page);
      await retainedOrdersFrame.waitForFunction(() => document.body.textContent.includes('No orders yet'),
        { timeout: 20000 });
      assert.equal(await retainedOrdersFrame.$('table[aria-label="Orders list"]'), null);
      assert.ok([200, 304].includes((await page.reload()).status()));
      retainedOrdersFrame = await stableFrame(page);
      await retainedOrdersFrame.waitForFunction(() => document.body.textContent.includes('No orders yet'),
        { timeout: 20000 });
      assert.equal((await scenes.list(buyer.scope)).find(scene => scene.isDefault)?.id, retainedSceneB.id,
        'the second scene remains selected after a parent reload');

      await page.click('button[aria-controls="secureshop-settings"]');
      await page.click('#secureshop-settings section[aria-label="Retained shop practices"] button');
      await page.waitForFunction(() => [...document.querySelectorAll('h1')]
        .some(node => node.textContent.trim() === 'Choose a shop practice.'), { timeout: 20000 });
      await selectRenderedScene(retainedSceneA);
      assert.equal((await scenes.list(buyer.scope)).find(scene => scene.isDefault)?.id, retainedSceneA.id);
      assert.deepEqual(await composition.commerce.order({ ...buyer, orderId: committed.orderId }), buyerOrder,
        'the earlier scene reopens the unchanged purchased order');
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/orders`)).status()));
      retainedOrdersFrame = await stableFrame(page);
      await retainedOrdersFrame.waitForSelector('table[aria-label="Orders list"]', { timeout: 20000 });
      assert.equal(await retainedOrdersFrame.$eval('table[aria-label="Orders list"]',
        (table, orderId) => [...table.querySelectorAll('tbody tr')]
          .some(row => row.querySelector('td')?.textContent.trim() === `#${orderId}`), committed.orderId), true);
      assert.ok([200, 304].includes((await page.reload()).status()));
      retainedOrdersFrame = await stableFrame(page);
      await retainedOrdersFrame.waitForSelector('table[aria-label="Orders list"]', { timeout: 20000 });
      assert.equal((await scenes.list(buyer.scope)).find(scene => scene.isDefault)?.id, retainedSceneA.id);
      assert.equal(Number((await identity.query(`SELECT status,generation FROM identity.secureshop_launches
        WHERE launch_id=$1`, [buyer.scope.launchId])).rows[0].generation), buyer.scope.generation,
      'scene selection does not reset or advance the original launch generation');
      assert.deepEqual((await identity.query(`SELECT scene_id,status FROM identity.secureshop_scenes
        WHERE scene_id=ANY($1::uuid[]) ORDER BY scene_id`,
      [[retainedSceneA.id, retainedSceneB.id]])).rows.map(row => [row.scene_id, row.status]),
      [retainedSceneA.id, retainedSceneB.id].sort().map(id => [id, 'active']),
      'both scenes remain active; choosing never resets either practice');

      stage = 'a08-customer-buttons';
      modelCallsBeforeProductA08 = modelCalls;
      assert.equal(modelCallsBeforeProductA08, 0,
        'guest, checkout, and earlier customer flows made no unavailable-provider attempt');
      const expectedProductFailures = [
        { method: 'POST', path: `/api/secureshop/products/${stocked.product_id}/summary` },
        { method: 'POST', path: `/api/secureshop/products/${stocked.product_id}/similar` },
      ];
      const productProbe = observeProductRequests(page, origin, expectedProductFailures);
      const productResponse = (method, pathname, status) => page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.origin === origin && url.pathname === pathname
          && response.request().method() === method && response.status() === status;
      }, { timeout: 20000 }).then(response => ({ response }), error => ({ error }));
      const summaryReply = productResponse('POST', expectedProductFailures[0].path, 503);
      try {
        assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/product/${stocked.product_id}`)).status()));
        const customerButtonFrame = await stableFrame(page);
        console.log('A11 Product summary headers await');
        const summary = await workStep('a08-product-summary-response-headers', () => summaryReply, 20000);
        if (summary.error) throw summary.error;
        console.log('A11 Product summary headers complete');
        await readBoundedProductError(summary.response, { workStep, label: 'a08-product-summary-body' });
        await qualifyRoleButtons(page, customerButtonFrame, 'customer', [
          { selector: 'button.ss-btn', text: 'Add to cart', size: 'md', variant: 'primary' },
        ], receiptPath);
        assert.equal(productProbe.snapshot()[1].requests, 0,
          'authenticated Product view does not invoke similar products before the explicit action');
        assert.equal(guestRequests.filter(row => row.stage === 'a08-customer-buttons'
          && row.path.startsWith(`/api/secureshop/products/${stocked.product_id}/similar`)).length, 0,
        'authenticated Product view has not allocated a similar session or model request');

        const similarSessionPath = `/api/secureshop/products/${stocked.product_id}/similar/session`;
        const similarSavedPrefix = `/api/secureshop/products/${stocked.product_id}/similar/sessions/`;
        const similarSessionReply = productResponse('POST', similarSessionPath, 200);
        const similarReply = productResponse('POST', expectedProductFailures[1].path, 503);
        const similarSavedReply = page.waitForResponse(response => {
          const url = new URL(response.url());
          return url.origin === origin && url.pathname.startsWith(similarSavedPrefix)
            && response.request().method() === 'GET' && response.status() === 202;
        }, { timeout: 20000 }).then(response => ({ response }), error => ({ error }));
        const findSimilar = new Function(`return [...document.querySelectorAll('button')]
          .find(node => node.textContent.trim() === 'Find similar products');`);
        const similarButton = await customerButtonFrame.locator(findSimilar)
          .setTimeout(20000).setVisibility('visible').waitHandle();
        assert.equal(await similarButton.evaluate(node => !node.disabled), true);
        await similarButton.click();
        const session = await workStep('a08-product-similar-session-headers',
          () => similarSessionReply, 20000);
        if (session.error) throw session.error;
        const sessionBody = await workStep('a08-product-similar-session-body',
          () => session.response.json(), 5000);
        assert.deepEqual(Object.keys(sessionBody), ['sessionId']);
        assert.match(sessionBody.sessionId,
          /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
        console.log('A11 Product similar headers await');
        const similar = await workStep('a08-product-similar-response-headers',
          () => similarReply, 20000);
        if (similar.error) throw similar.error;
        console.log('A11 Product similar headers complete');
        await readBoundedProductError(similar.response, { workStep, label: 'a08-product-similar-body' });
        const saved = await workStep('a08-product-similar-saved-headers',
          () => similarSavedReply, 20000);
        if (saved.error) throw saved.error;
        const savedPath = new URL(saved.response.url()).pathname;
        assert.match(savedPath, new RegExp(`^${similarSavedPrefix}${sessionBody.sessionId}/requests/[a-f0-9-]{36}$`));
        const savedRequestId = savedPath.split('/').at(-1);
        assert.match(savedRequestId,
          /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
        const savedBody = await workStep('a08-product-similar-saved-body',
          () => saved.response.json(), 5000);
        assert.deepEqual(savedBody, { status: 'pending', sessionId: sessionBody.sessionId,
          requestId: savedRequestId });
        assert.deepEqual(guestRequests.filter(row => row.stage === 'a08-customer-buttons'
          && row.path.startsWith(`/api/secureshop/products/${stocked.product_id}/similar`))
          .map(row => [row.method, row.path]), [
          ['POST', similarSessionPath], ['POST', expectedProductFailures[1].path], ['GET', savedPath],
        ], 'the physical click caused one session, one model POST, then the exact saved read');
        assert.deepEqual(productProbe.snapshot(), expectedProductFailures.map(expected => ({
          ...expected, requests: 1, responseStatuses: [503], finished: 1, failed: 0,
        })), 'both real unavailable model responses have completed browser request lifecycles');
        assert.deepEqual(productServerResponses.map(row => ({ ...row })),
          expectedProductFailures.map(expected => ({ ...expected, status: 503,
            finished: true, closed: true })),
        'both actual model-response writes finished and closed on the server');
      } catch (error) {
        console.log('A11 Product response lifecycle', JSON.stringify({ browser: productProbe.snapshot(),
          server: productServerResponses.map(row => ({ ...row })) }));
        throw error;
      } finally { productProbe.stop(); }
      assert.deepEqual(apiStatuses.filter(row => row.stage === 'a08-customer-buttons'
        && expectedProductFailures.some(expected => row.path === expected.path))
        .sort((left, right) => left.path.localeCompare(right.path)),
      expectedProductFailures.map(expected => ({ ...expected, status: 503, stage: 'a08-customer-buttons' }))
        .sort((left, right) => left.path.localeCompare(right.path)),
      'the automatic summary and explicitly clicked similar requests are exact 503s in the rendered A08 visit');
      assert.equal(modelCalls - modelCallsBeforeProductA08, 2,
        'the automatic summary and clicked similar action make two unavailable-provider attempts');
      assert.deepEqual(providerCalls.map(call => [call.method, call.stage]),
        [['chat', 'a08-customer-buttons'], ['chat', 'a08-customer-buttons']],
        'the unavailable provider was only reached through the two Product graph decisions');

      // All accounts and audit events below belong to this disposable store.
      // The rendered directory must cross its real 25-row page boundary.
      stage = 'admin-users-seed';
      const registeredNames = [];
      for (let index = 0; index < 26; index++) {
        const username = `paged_${suffix}_${String(index).padStart(2, '0')}`;
        const registered = await auth.register({ username, email: `${username}@example.invalid`,
          password, role: 'customer' });
        const member = await auth.establishTenantContext(registered.context);
        assert.equal(member.ownerId, admin.scope.platformOwnerId,
          'pagination actors belong to the same real execution tenant as the administrator');
        // Auth registration alone does not materialize the agents directory.
        // Use the production bootstrap to register this exact tenant actor.
        const ready = await bootstrap(registered.context);
        assert.equal(ready.persona.user.id, registered.user.id);
        assert.equal(ready.persona.user.username, username);
        await auth.logout(registered.token);
        registeredNames.push(username);
      }
      const registeredDirectory = await composition.admin.users({ ...admin,
        query: { page: 1, pageSize: 100 } });
      assert.ok(registeredDirectory.total >= 29,
        'the real bound directory contains seeded roles plus all pagination actors');
      assert.ok(registeredNames.every(name => registeredDirectory.users.some(row =>
        row.username === name && row.identity_kind === 'registered_account')),
      'every pagination row is an actual registered actor in the administrator tenant');
      // Exercise foreign-tenant scene denial while the original buyer's
      // execution capability is still current. The independent protected
      // password reset below may retire sessions and must not be bypassed.
      stage = 'registered-role-ban-setup';
      const roleName = `role_${suffix}`, banName = `ban_${suffix}`;
      const roleRegistration = await auth.register({ username: roleName,
        email: `${roleName}@example.invalid`, password, role: 'customer' });
      const banRegistration = await auth.register({ username: banName,
        email: `${banName}@example.invalid`, password, role: 'customer' });
      const otherTenantId = randomUUID(), otherTenantSlug = `admin_other_${suffix}`;
      await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
        VALUES($1,$2)`, [otherTenantId, otherTenantSlug]);
      for (const registration of [roleRegistration, banRegistration]) {
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
        [otherTenantId, registration.context.principalId, registration.context.shopUserId]);
      }
      // Auth sessions snapshot membership at birth. These fresh cookies know
      // both tenants before the default-tenant administrator operation.
      const roleAccount = await auth.login({ username: roleName, password });
      const banAccount = await auth.login({ username: banName, password });
      const otherTenantAuth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity,
              executionTenantSlug: otherTenantSlug }) });
      const otherTenantSessions = new Map();
      for (const account of [roleAccount, banAccount]) {
        const principal = await otherTenantAuth.authenticate(account.token);
        assert.equal(principal?.principalId, account.context.principalId);
        const execution = await otherTenantAuth.establishTenantContext(principal);
        assert.equal(execution.tenantId, otherTenantId);
        otherTenantSessions.set(account.user.id, execution.sessionId);
      }
      stage = 'retained-scene-foreign-owner-denial';
      assert.ok(retainedSceneA?.id && retainedSceneB?.id);
      const foreignBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: otherTenantAuth });
      const foreignPrincipal = await otherTenantAuth.authenticate(roleAccount.token);
      const foreignReady = await foreignBootstrap(foreignPrincipal);
      const foreignScope = await composition.launches.resolveCapability(foreignReady.bearer);
      assert.notEqual(foreignScope.platformOwnerId, buyer.scope.platformOwnerId);
      assert.deepEqual(await scenes.list(foreignScope), [],
        'a real separately authenticated tenant cannot discover the buyer’s retained scenes');
      await assert.rejects(scenes.select(foreignScope, retainedSceneA.id), { code: 'SHOP_SCENE_STALE' });
      await assert.rejects(scenes.select(foreignScope, retainedSceneB.id), { code: 'SHOP_SCENE_STALE' });
      assert.equal((await scenes.list(buyer.scope)).find(scene => scene.isDefault)?.id, retainedSceneA.id,
        'foreign selection attempts cannot change the buyer’s selected practice');
      retainedSceneForeignChecked = true;
      status.retainedSceneChooserRendered = retainedSceneForeignChecked;
      assert.equal((await page.evaluate(async () =>
        (await fetch('/api/secureshop/auth/logout', { method: 'POST', credentials: 'include',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({}) })).status)), 200);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()));
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', 'student_admin');
      await page.type('#ss-login-pw', 'student123');
      await page.click('button[type="submit"]');
      await stableFrame(page);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/admin/users`)).status()));
      const adminFrame = await stableFrame(page);
      await adminFrame.waitForFunction(() => /page 1 of [2-9]\d* · \d+ total/.test(document.body.textContent),
        { timeout: 20000 });
      await adminFrame.waitForFunction(() => document.querySelectorAll('button[aria-label^="View "]').length === 25,
        { timeout: 20000 });
      const pageOne = await adminFrame.$$eval('button[aria-label^="View "]', buttons =>
        buttons.map(button => button.getAttribute('aria-label').slice(5)));
      assert.equal(pageOne.length, 25);
      assert.ok(pageOne.some(name => registeredNames.includes(name)), 'registered actors appear in the scoped directory');
      const pageButton = async label => {
        const buttons = await adminFrame.$$('button');
        for (const button of buttons) {
          if ((await button.evaluate(node => node.textContent.trim())) === label) {
            await button.evaluate(node => node.scrollIntoView({ block: 'center' }));
            await button.click(); return;
          }
        }
        throw new Error(`Missing rendered pagination control: ${label}`);
      };
      await pageButton('next →');
      await adminFrame.waitForFunction(() => /page 2 of [2-9]\d* · \d+ total/.test(document.body.textContent),
        { timeout: 20000 });
      await adminFrame.waitForFunction(first => {
        const names = [...document.querySelectorAll('button[aria-label^="View "]')]
          .map(button => button.getAttribute('aria-label').slice(5));
        return names.length > 0 && names.length <= 25 && names.every(name => !first.includes(name));
      }, { timeout: 20000 }, pageOne);
      const pageTwo = await adminFrame.$$eval('button[aria-label^="View "]', buttons =>
        buttons.map(button => button.getAttribute('aria-label').slice(5)));
      assert.ok(pageTwo.length >= 1 && pageTwo.length <= 25);
      assert.ok(pageTwo.every(name => !pageOne.includes(name)), 'page two contains distinct scoped actors');
      const detailName = pageTwo.find(name => registeredNames.includes(name));
      assert.ok(detailName, 'a registered actor appears on page two');
      await adminFrame.click(`button[aria-label="View ${detailName}"]`);
      await adminFrame.waitForFunction(name => [...document.querySelectorAll('aside')]
        .some(node => node.querySelector('h3')?.textContent.startsWith('User #')
          && node.textContent.includes(`${name}@example.invalid`)), { timeout: 20000 }, detailName);
      await adminFrame.waitForFunction(() => {
        const button = document.querySelector('button[aria-label="Close details"]');
        if (!button || button.disabled) return false;
        const rect = button.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0 || rect.left < 0 || rect.top < 0
          || rect.right > innerWidth || rect.bottom > innerHeight) return false;
        const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
        return hit === button || button.contains(hit);
      }, { timeout: 10000 });
      await adminFrame.click('button[aria-label="Close details"]');
      await pageButton('← prev');
      await adminFrame.waitForFunction(name => /page 1 of [2-9]\d* · \d+ total/.test(document.body.textContent)
        && [...document.querySelectorAll('button[aria-label^="View "]')].length === 25
        && !!document.querySelector(`button[aria-label="View ${name}"]`), { timeout: 20000 }, pageOne[0]);
      status.adminUsersRenderedPagination = true;

      stage = 'admin-audit-seed';
      const adminCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(adminCookie?.httpOnly, true);
      const currentAdmin = await actor(await auth.authenticate(adminCookie.value));
      stage = 'admin-synthetic-lookup';
      const lookupEvents = async () => (await pools.AGENTS_MIGRATION.query(`SELECT *
        FROM secureshop_agents.bound_audit_events WHERE launch_id=$1 AND action='synthetic_user_lookup'
        ORDER BY event_id`, [currentAdmin.scope.launchId])).rows;
      const lookupBefore = await lookupEvents(), lookupPostsBefore = lookupPosts.length;
      await adminFrame.locator('input[aria-label="Bulk lookup username"]')
        .setVisibility('visible').fill('student_customer');
      assert.equal(await adminFrame.$eval('input[aria-label="Bulk lookup username"]', node => node.value),
        'student_customer');
      const lookupResponse = page.waitForResponse(response =>
        response.url() === `${origin}/api/secureshop/admin/users/lookup`
        && response.request().method() === 'POST', { timeout: 20000 });
      await clickMailButton(adminFrame, 'Look up');
      const lookedUp = await lookupResponse; assert.equal(lookedUp.status(), 200);
      const lookupValue = await lookedUp.json();
      assert.deepEqual(Object.keys(lookupValue).sort(), ['ok', 'synthetic', 'user']);
      assert.equal(lookupValue.ok, true); assert.equal(lookupValue.synthetic, true);
      assert.deepEqual(Object.keys(lookupValue.user).sort(),
        ['id','username','role','email','full_name','phone','password','api_key','session_token'].sort());
      assert.equal(lookupValue.user.id, 1); assert.equal(lookupValue.user.username, 'student_customer');
      assert.equal(lookupValue.user.role, 'customer');
      assert.equal(lookupValue.user.email, 'customer@training.example.invalid');
      assert.equal(lookupValue.user.full_name, 'Synthetic customer');
      assert.equal(lookupValue.user.phone, '+1-202-555-0100');
      assert.ok(/^\$2[aby]\$10\$[./A-Za-z0-9]{53}$/.test(lookupValue.user.password), 'synthetic bcrypt shape');
      assert.ok(/^TRAINING_API_[a-f0-9]{48}$/.test(lookupValue.user.api_key), 'synthetic API key shape');
      assert.ok(/^TRAINING_SESSION_[a-f0-9]{48}$/.test(lookupValue.user.session_token), 'synthetic session shape');
      await adminFrame.waitForFunction(() => [...document.querySelectorAll('pre')].some(node => {
        try { const value = JSON.parse(node.textContent); return value.ok === true
          && value.synthetic === true && value.user?.username === 'student_customer'; } catch { return false; }
      }), { timeout: 20000 });
      const displayedLookup = await adminFrame.evaluate(() => [...document.querySelectorAll('pre')]
        .map(node => { try { return JSON.parse(node.textContent); } catch { return null; } })
        .find(value => value?.synthetic === true));
      assert.ok(JSON.stringify(displayedLookup) === JSON.stringify(lookupValue), 'rendered exact synthetic response');
      assert.deepEqual(lookupPosts.slice(lookupPostsBefore), [{ username: 'student_customer' }]);
      const afterLookup = await lookupEvents(); assert.equal(afterLookup.length, lookupBefore.length + 1);
      const lookupEvent = afterLookup.find(event => !lookupBefore.some(old => old.event_id === event.event_id));
      assert.equal(lookupEvent.source_kind, 'synthetic_user_lookup');
      assert.equal(lookupEvent.target, 'synthetic-directory'); assert.equal(lookupEvent.outcome, 'completed');
      assert.deepEqual(JSON.parse(lookupEvent.params_json), { found: true });
      assert.equal(lookupEvent.launch_id, currentAdmin.scope.launchId);
      assert.equal(lookupEvent.scenario_id, currentAdmin.scope.scenarioId);
      assert.equal(Number(lookupEvent.generation), currentAdmin.scope.generation);
      assert.equal(Number(lookupEvent.original_platform_owner_id), currentAdmin.scope.platformOwnerId);
      assert.equal(Number(lookupEvent.original_platform_session_id), currentAdmin.scope.platformSessionId);
      assert.equal(Number(lookupEvent.shop_user_id), currentAdmin.persona.id);
      assert.equal(lookupEvent.shop_role, 'admin'); assert.equal(lookupEvent.actor, 'admin');
      const syntheticDirectory = (await pools.AGENTS_MIGRATION.query(`SELECT rows_json
        FROM secureshop_agents.bound_synthetic_user_directories WHERE platform_launch_id=$1`,
      [currentAdmin.scope.launchId])).rows;
      assert.equal(syntheticDirectory.length, 1); assert.equal(syntheticDirectory[0].rows_json.length, 3);
      assert.ok(JSON.stringify(syntheticDirectory[0].rows_json.find(row => row.username === 'student_customer'))
        === JSON.stringify(lookupValue.user), 'lookup displays only the retained synthetic directory row');
      status.adminSyntheticLookupRendered = true;
      stage = 'a08-admin-buttons';
      await qualifyRoleButtons(page, adminFrame, 'admin', [
        { selector: 'button.ss-btn', text: 'Look up', size: 'md', variant: 'primary' },
        { selector: 'button.ss-btn', text: 'view', size: 'adminCompact', variant: 'primary' },
      ], receiptPath);
      // A registered sibling's credential reset is protected parent authority;
      // the opaque Users frame can only request this exact target's panel.
      markStage('registered-admin-reset');
      const targetId = siblingAccount.user.id;
      const targetPrincipal = siblingAccount.context.principalId;
      const untouchedIds = [buyerBase.principalId, merchantRegistration.context.principalId,
        (await workStep('registered-admin-authenticate', () => auth.authenticate(adminCookie.value), 10000)).principalId];
      const credentialSnapshot = async () => (await pools.IDENTITY_MIGRATION.query(`SELECT *
        FROM secureshop_auth.principals WHERE principal_id=ANY($1::uuid[]) ORDER BY principal_id`,
      [untouchedIds])).rows;
      const untouchedCredentials = await workStep('registered-admin-credential-snapshot', credentialSnapshot, 10000);
      const resetPath = `/api/secureshop/auth/admin/users/${targetId}`;
      const targetDirectoryResponse = page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.pathname === '/api/secureshop/admin/users' && url.searchParams.get('search') === siblingName
          && response.request().method() === 'GET';
      }, { timeout: 20000 });
      void targetDirectoryResponse.catch(() => {});
      markStage('registered-admin-search');
      await workStep('registered-admin-search-fill', () => adminFrame.locator('input[aria-label="Search users"]')
        .setVisibility('visible').fill(siblingName));
      await workStep('registered-admin-search-render', () => adminFrame.waitForFunction(name => document.querySelectorAll('button[aria-label^="View "]').length === 1
        && !!document.querySelector(`button[aria-label="View ${name}"]`), { timeout: 20000 }, siblingName));
      const targetDirectoryHttp = await workStep('registered-admin-search-response', () => targetDirectoryResponse);
      assert.equal(targetDirectoryHttp.status(), 200);
      const targetDirectory = await workStep('registered-admin-search-json', () => targetDirectoryHttp.json(), 10000);
      const targetRow = targetDirectory.users.find(row => row.id === targetId);
      assert.equal(targetRow?.identity_kind, 'registered_account');
      assert.equal(targetRow.reset_channel, 'protected_account');
      const readinessResponse = page.waitForResponse(response =>
        response.url() === `${origin}${resetPath}/reset-readiness` && response.request().method() === 'GET',
      { timeout: 20000 });
      void readinessResponse.catch(() => {});
      markStage('registered-admin-readiness');
      await workStep('registered-admin-readiness-click', () => clickMailButton(adminFrame, 'reset'));
      const readinessHttp = await workStep('registered-admin-readiness-response', () => readinessResponse);
      assert.equal(readinessHttp.status(), 200);
      const readiness = await workStep('registered-admin-readiness-json', () => readinessHttp.json(), 10000);
      assert.equal(readiness.ok, true); assert.equal(readiness.user.id, targetId);
      assert.equal(readiness.user.username, siblingName); assert.equal(readiness.user.email, siblingAccount.user.email);
      assert.equal(readiness.user.resetAvailable, true);
      markStage('registered-admin-reset-confirm');
      await workStep('registered-admin-reset-panel', () => page.waitForFunction(({ username, email }) => {
        const panel = document.querySelector('section[aria-label="Protected password reset"]');
        return panel?.textContent.includes(username) && panel.textContent.includes(email)
          && [...panel.querySelectorAll('button')].some(node => node.textContent === 'Confirm password reset' && !node.disabled);
      }, { timeout: 20000 }, { username: siblingName, email: siblingAccount.user.email }));
      const resetResponse = page.waitForResponse(response =>
        response.url() === `${origin}${resetPath}/reset-password` && response.request().method() === 'POST',
      { timeout: 20000 });
      void resetResponse.catch(() => {});
      await workStep('registered-admin-reset-click', () => clickMailButton(page, 'Confirm password reset'));
      const resetHttp = await workStep('registered-admin-reset-response', () => resetResponse);
      assert.equal(resetHttp.status(), 200);
      const resetResult = await workStep('registered-admin-reset-json', () => resetHttp.json(), 10000);
      assert.deepEqual(Object.keys(resetResult).sort(), ['ok', 'receipt', 'replayed', 'secretAvailable']);
      assert.equal(resetResult.ok, true); assert.equal(resetResult.replayed, false);
      assert.equal(resetResult.secretAvailable, true);
      const resetReceipt = resetResult.receipt;
      assert.deepEqual(Object.keys(resetReceipt).sort(), ['operationId', 'targetId', 'credentialVersion',
        'authorityVersion', 'receiptSha256', 'expiresAt'].sort());
      assert.equal(resetReceipt.targetId, targetId);
      assert.match(resetReceipt.operationId, /^[0-9a-f-]{36}$/);
      assert.match(resetReceipt.receiptSha256, /^[a-f0-9]{64}$/);
      assert.equal(resetReceipt.credentialVersion, String(BigInt(readiness.user.credentialVersion) + 1n));
      assert.equal(resetReceipt.authorityVersion, String(BigInt(readiness.user.authorityVersion) + 1n));
      const resetIntent = JSON.parse(resetHttp.request().postData());
      assert.deepEqual(resetIntent, { operationId: resetReceipt.operationId,
        expectedCredentialVersion: readiness.user.credentialVersion,
        expectedAuthorityVersion: readiness.user.authorityVersion,
        expectedMembershipVersion: readiness.user.membershipVersion });
      const operationPath = `${resetPath}/password-resets/${resetReceipt.operationId}`;
      markStage('registered-admin-reset-status');
      const statusResponse = page.waitForResponse(response =>
        response.url() === `${origin}${operationPath}` && response.request().method() === 'GET', { timeout: 20000 });
      void statusResponse.catch(() => {});
      await workStep('registered-admin-reset-status-click', () => clickMailButton(page, 'Read reset status'));
      const readHttp = await workStep('registered-admin-reset-status-response', () => statusResponse);
      assert.equal(readHttp.status(), 200);
      assert.deepEqual(await workStep('registered-admin-reset-status-json', () => readHttp.json(), 10000),
        { ok: true, receipt: resetReceipt, secretAvailable: true });
      markStage('registered-admin-reset-old-authority');
      assert.equal(await workStep('registered-admin-old-cookie', () => auth.authenticate(siblingAccount.token), 10000),
        null, 'old target cookie is revoked');
      const oldSession = await workStep('registered-admin-old-session-http', () => fetch(`${origin}/api/secureshop/auth/session`, {
        headers: { cookie: `dvaia_shop_session=${siblingAccount.token}` } }), 10000);
      assert.equal(oldSession.status, 200);
      assert.deepEqual(await workStep('registered-admin-old-session-json', () => oldSession.json(), 10000),
        { authenticated: false, user: null });
      await assert.rejects(workStep('registered-admin-old-context',
        () => auth.establishTenantContext(siblingAccount.context), 10000), { code: 'SHOP_AUTH_INVALID' });
      assert.equal(await workStep('registered-admin-old-launch',
        () => composition.launches.resolveCapability(siblingCredentials.bearer), 10000), null,
        'old execution launch bearer cannot resolve authority');
      await assert.rejects(workStep('registered-admin-old-persona',
        () => composition.personaAuth.authenticateBoundToken({ scope: sibling.scope,
          token: siblingCredentials.persona.token }), 10000), { code: 'STALE_LAUNCH' });
      const liveOldCredentials = (await workStep('registered-admin-old-credential-query', () => pools.IDENTITY_MIGRATION.query(`SELECT
        (SELECT count(*)::int FROM secureshop_auth.sessions WHERE principal_id=$1 AND revoked_at IS NULL) AS sessions,
        (SELECT count(*)::int FROM secureshop_auth.execution_sessions WHERE principal_id=$1 AND revoked_at IS NULL) AS executions`,
      [targetPrincipal]), 10000)).rows[0];
      assert.deepEqual(liveOldCredentials, { sessions: 0, executions: 0 });
      const oldLogin = await workStep('registered-admin-old-login', () => fetch(`${origin}/api/secureshop/auth/login`, { method: 'POST',
        headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ username: siblingName, password }) }), 10000);
      assert.equal(oldLogin.status, 401, 'old target password is denied');

      // Never retain a screenshot or log while the real parent reveals a secret.
      privateResetRevealPending = true;
      markStage('registered-admin-reset-reveal');
      const revealResponse = page.waitForResponse(response => response.url() === `${origin}${operationPath}/reveal`
        && response.request().method() === 'POST', { timeout: 20000 });
      void revealResponse.catch(() => {});
      await workStep('registered-admin-reset-reveal-click', () => clickMailButton(page, 'Reveal temporary password'));
      const revealHttp = await workStep('registered-admin-reset-reveal-response', () => revealResponse);
      assert.equal(revealHttp.status(), 200);
      const reveal = await workStep('registered-admin-reset-reveal-json', () => revealHttp.json(), 10000);
      assert.deepEqual(reveal.receipt, resetReceipt);
      assert.ok(typeof reveal.temporaryPassword === 'string' && /^[A-Za-z0-9_-]{43}$/.test(reveal.temporaryPassword),
        'private temporary credential has canonical shape');
      const temporaryPassword = reveal.temporaryPassword;
      await workStep('registered-admin-reset-reveal-render', () => page.waitForFunction(secret => document.querySelector('output[aria-label="Temporary password"]')?.textContent === secret,
        { timeout: 20000 }, temporaryPassword));
      assert.equal(await workStep('registered-admin-reset-secret-frame', () => adminFrame.evaluate(secret => document.body.textContent.includes(secret), temporaryPassword), 10000), false,
        'temporary credential is never disclosed into the teaching frame');
      assert.equal(await workStep('registered-admin-reset-secret-storage', () => page.evaluate(secret => location.href.includes(secret)
        || Object.values(localStorage).some(value => value.includes(secret))
        || Object.values(sessionStorage).some(value => value.includes(secret)), temporaryPassword), 10000), false,
      'temporary credential is absent from URL and browser storage');
      markStage('registered-admin-reset-acknowledge');
      const acknowledgeResponse = page.waitForResponse(response =>
        response.url() === `${origin}${operationPath}/acknowledge` && response.request().method() === 'POST',
      { timeout: 20000 });
      void acknowledgeResponse.catch(() => {});
      await workStep('registered-admin-reset-ack-click', () => clickMailButton(page, 'Acknowledge and clear password'));
      const ackHttp = await workStep('registered-admin-reset-ack-response', () => acknowledgeResponse);
      assert.equal(ackHttp.status(), 200);
      assert.deepEqual(await workStep('registered-admin-reset-ack-json', () => ackHttp.json(), 10000),
        { ok: true, receipt: resetReceipt, secretAvailable: false });
      await workStep('registered-admin-reset-ack-render', () => page.waitForFunction(() => !document.querySelector('output[aria-label="Temporary password"]')
        && !sessionStorage.getItem('dvaia.secureshop.admin-password-reset.v1'), { timeout: 20000 }));
      privateResetRevealPending = false;
      markStage('registered-admin-reset-verify');
      const deniedReveal = await workStep('registered-admin-reset-denied-reveal-http', () => page.evaluate(async endpoint => (await fetch(endpoint, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({}) })).status,
      `${operationPath}/reveal`), 10000);
      assert.equal(deniedReveal, 503, 'the production router denies an acknowledged recovery envelope');
      await assert.rejects(workStep('registered-admin-reset-denied-reveal-service',
        () => registeredAdminReset.reveal({ token: adminCookie.value, targetId,
          operationId: resetReceipt.operationId }), 10000), { code: 'REGISTERED_RESET_RECOVERY_UNAVAILABLE' });
      const changedLogin = await workStep('registered-admin-new-login-http', () => fetch(`${origin}/api/secureshop/auth/login`, { method: 'POST',
        headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ username: siblingName, password: temporaryPassword }) }), 10000);
      assert.equal(changedLogin.status, 200, 'new private credential authenticates through the production route');
      const changedUser = await workStep('registered-admin-new-login-json', () => changedLogin.json(), 10000);
      assert.equal(changedUser.authenticated, true); assert.equal(changedUser.user.id, targetId);
      const newCookie = changedLogin.headers.get('set-cookie')?.match(/dvaia_shop_session=([^;]+)/)?.[1];
      assert.ok(newCookie, 'successful changed-password login issued a new private cookie');
      await workStep('registered-admin-new-logout', () => auth.logout(decodeURIComponent(newCookie)), 10000);
      const resetRows = (await workStep('registered-admin-reset-row-query', () => pools.IDENTITY_MIGRATION.query(`SELECT receipt_json FROM
        secureshop_auth.registered_admin_reset_operations WHERE target_principal_id=$1`, [targetPrincipal]), 10000)).rows;
      assert.equal(resetRows.length, 1, 'one registered reset operation is retained');
      assert.equal(resetRows[0].receipt_json.operationId, resetReceipt.operationId);
      const recoveryRow = (await workStep('registered-admin-reset-recovery-row-query', () => pools.IDENTITY_MIGRATION.query(`SELECT envelope_json FROM
        secureshop_auth.registered_admin_reset_recovery WHERE operation_id=$1`, [resetReceipt.operationId]), 10000)).rows[0];
      assert.equal(recoveryRow.envelope_json, null, 'acknowledgement clears only the private recovery envelope');
      assert.equal(JSON.stringify(await workStep('registered-admin-unchanged-credentials', credentialSnapshot, 10000))
        === JSON.stringify(untouchedCredentials), true,
        'buyer, merchant and administrator credentials are unchanged');
      assert.equal((await workStep('registered-admin-cookie-check', () => page.cookies(`${origin}/api/secureshop/auth/session`), 10000))
        .find(value => value.name === 'dvaia_shop_session')?.value === adminCookie.value, true,
      'target reset leaves the browser administrator session intact');
      assert.equal(apiStatuses.filter(event => event.method === 'POST' && event.path === `${resetPath}/reset-password`).length, 1);
      status.registeredAdminResetRenderedPrivate = true;
      // The parent panel obscures the frame while open; close it before the
      // existing read-only directory/audit qualification continues.
      markStage('registered-admin-reset-close-panel');
      await workStep('registered-admin-settings-click', () => clickMailButton(page, 'Shop settings'));
      await workStep('registered-admin-settings-hide', () => page.waitForFunction(() => !document.querySelector('#secureshop-settings'), { timeout: 10000 }), 10000);
      const clearedDirectoryResponse = page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.pathname === '/api/secureshop/admin/users' && !url.searchParams.get('search')
          && url.searchParams.get('page') === '1' && url.searchParams.get('pageSize') === '25'
          && response.request().method() === 'GET';
      }, { timeout: 20000 });
      // Keep an early selection assertion as the primary failure if browser
      // cleanup closes this pending response waiter before it is awaited.
      void clearedDirectoryResponse.catch(() => {});
      markStage('registered-admin-reset-clear-search');
      const searchInput = await workStep('registered-admin-clear-search-handle', () => adminFrame.locator('input[aria-label="Search users"]')
        .setVisibility('visible').waitHandle());
      try {
        await workStep('registered-admin-clear-search-scroll', () => searchInput.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' })));
        // Headless Chrome does not consistently map the host select-all
        // shortcut. Select the actual text physically and verify the range.
        await workStep('registered-admin-clear-search-click', () => searchInput.click({ count: 3 }));
        const selection = await workStep('registered-admin-clear-search-selection', () => searchInput.evaluate(node => ({ focused: document.activeElement === node,
          length: node.value.length, start: node.selectionStart, end: node.selectionEnd })));
        assert.equal(selection.focused, true);
        assert.ok(selection.length > 0, 'the previous rendered search value is still present');
        assert.equal(selection.start, 0, 'physical triple-click selects from the start');
        assert.equal(selection.end, selection.length, 'physical triple-click selects the entire search');
        await workStep('registered-admin-clear-search-backspace', () => page.keyboard.press('Backspace'));
      } finally { await boundedA11('registered-admin-clear-search-dispose', () => searchInput.dispose(), 3000); }
      const clearedDirectoryHttp = await workStep('registered-admin-clear-search-response', () => clearedDirectoryResponse);
      assert.equal(clearedDirectoryHttp.status(), 200);
      const clearedDirectory = await workStep('registered-admin-clear-search-json', () => clearedDirectoryHttp.json(), 10000);
      assert.equal(clearedDirectory.page, 1); assert.equal(clearedDirectory.pageSize, 25);
      assert.equal(clearedDirectory.users.length, 25);
      await workStep('registered-admin-clear-search-render', () => adminFrame.waitForFunction(names => document.querySelector('input[aria-label="Search users"]')?.value === ''
        && JSON.stringify([...document.querySelectorAll('button[aria-label^="View "]')]
          .map(node => node.getAttribute('aria-label').slice(5))) === JSON.stringify(names),
      { timeout: 20000 }, clearedDirectory.users.map(user => user.username)));

      stage = 'registered-role-ban-recovery';
      const otherMembershipRows = async () => (await pools.IDENTITY_MIGRATION.query(`SELECT *
        FROM secureshop_auth.tenant_memberships WHERE tenant_id=$1 ORDER BY principal_id`,
      [otherTenantId])).rows;
      const otherMembershipsBefore = await otherMembershipRows();
      const roleOldLaunch = await bootstrap(roleAccount.context);
      const banOldLaunch = await bootstrap(banAccount.context);
      const roleOldScope = await composition.launches.resolveCapability(roleOldLaunch.bearer);
      const banOldScope = await composition.launches.resolveCapability(banOldLaunch.bearer);
      const unaffectedPrincipals = [buyerBase.principalId, merchantRegistration.context.principalId,
        adminLogin.context.principalId, siblingAccount.context.principalId];
      const unaffectedRows = async () => (await pools.IDENTITY_MIGRATION.query(`SELECT *
        FROM secureshop_auth.tenant_memberships WHERE principal_id=ANY($1::uuid[])
        ORDER BY principal_id,tenant_id`, [unaffectedPrincipals])).rows;
      const unaffectedBefore = await unaffectedRows();
      let adminMutationFrame = adminFrame;
      for (const target of [
        { account: roleAccount, name: roleName, action: 'set_role', path: 'role', role: 'merchant', oldLaunch: roleOldLaunch, oldScope: roleOldScope },
        { account: banAccount, name: banName, action: 'ban', path: 'ban', role: 'customer', oldLaunch: banOldLaunch, oldScope: banOldScope },
      ]) {
        const targetId = target.account.user.id;
        const searchResponse = page.waitForResponse(response => {
          const url = new URL(response.url());
          return url.pathname === '/api/secureshop/admin/users'
            && url.searchParams.get('search') === target.name
            && response.request().method() === 'GET';
        }, { timeout: 20000 });
        await adminMutationFrame.locator('input[aria-label="Search users"]')
          .setVisibility('visible').fill(target.name);
        const searchHttp = await searchResponse; assert.equal(searchHttp.status(), 200);
        const targetRow = (await searchHttp.json()).users.find(row => row.id === targetId);
        assert.equal(targetRow?.identity_kind, 'registered_account');
        assert.equal(targetRow?.role, 'customer');
        assert.match(targetRow.authority_version, /^[1-9]\d*$/);
        await adminMutationFrame.waitForFunction(name =>
          !!document.querySelector(`select[aria-label="Change role for ${name}"]`),
        { timeout: 20000 }, target.name);
        const endpoint = `${origin}/api/secureshop/admin/users/${targetId}/${target.path}`;
        const loss = await dropOneCommittedOperationResponse(page, endpoint);
        const mutationRequests = [];
        const onMutationRequest = request => {
          if (request.url() === endpoint && request.method() === 'POST') mutationRequests.push(request);
        };
        page.on('request', onMutationRequest);
        let captured;
        try {
          if (target.action === 'set_role') {
            await adminMutationFrame.select(`select[aria-label="Change role for ${target.name}"]`, 'merchant');
          } else {
            await adminMutationFrame.locator('input[aria-label="Ban reason (audit-log)"]')
              .setVisibility('visible').fill('disposable administrator ban');
            await clickMailButton(adminMutationFrame, 'ban');
          }
          await adminMutationFrame.waitForFunction(name =>
            document.querySelector('[aria-label="Confirm user change"]')?.textContent.includes(name),
          { timeout: 20000 }, target.name);
          assert.equal(mutationRequests.length, 0, 'staging must not submit a role or ban operation');
          if (target.action === 'set_role') {
            await clickMailButton(adminMutationFrame, 'Cancel', true);
            await adminMutationFrame.waitForFunction(() => !document.querySelector('[aria-label="Confirm user change"]'),
              { timeout: 20000 });
            assert.equal(mutationRequests.length, 0, 'cancel must not submit a role operation');
            await adminMutationFrame.select(`select[aria-label="Change role for ${target.name}"]`, 'merchant');
            await adminMutationFrame.waitForFunction(() => !!document.querySelector('[aria-label="Confirm user change"]'),
              { timeout: 20000 });
          }
          assert.equal(mutationRequests.length, 0, 'restaged action remains pre-effect');
          await clickMailButton(adminMutationFrame, 'Confirm user change', true);
          captured = await loss.waitCaptured(20000);
          assert.equal(mutationRequests.length, 1, 'one physical confirmed mutation required');
          await adminMutationFrame.waitForFunction(() => document.body.textContent.includes('Refresh change status'),
            { timeout: 20000 });
        } finally { page.off('request', onMutationRequest); await loss.close(); }
        assert.ok(captured);
        assert.equal(captured.request.expectedVersion, targetRow.authority_version);
        assert.equal(captured.receipt.targetId, targetId);
        assert.equal(captured.receipt.action, target.action);
        assert.equal(captured.receipt.role, target.role);
        assert.equal(captured.receipt.version, String(BigInt(targetRow.authority_version) + 1n));
        assert.equal(captured.acknowledgement.replayed, false);
        const operationId = captured.request.operationId;
        assert.equal(captured.receipt.operationId, operationId);
        assert.ok([200, 304].includes((await page.reload()).status()));
        adminMutationFrame = await stableFrame(page);
        await adminMutationFrame.waitForFunction(() => document.body.textContent.includes('Refresh change status'),
          { timeout: 20000 });
        const readResponse = page.waitForResponse(response =>
          response.url() === `${origin}/api/secureshop/admin/users/operations/${operationId}`
            && response.request().method() === 'GET', { timeout: 20000 });
        await clickMailButton(adminMutationFrame, 'Refresh change status');
        const readHttp = await readResponse; assert.equal(readHttp.status(), 200);
        assert.deepEqual(await readHttp.json(), { ok: true, receipt: captured.receipt });
        await adminMutationFrame.waitForFunction(() => !document.body.textContent.includes('Refresh change status'),
          { timeout: 20000 });
        const currentDirectory = await adminMutationFrame.evaluate(async name => {
          const query = new URLSearchParams({ search: name, page: '1', pageSize: '25' });
          const response = await fetch(`/api/secureshop/admin/users?${query}`);
          return { status: response.status, body: await response.json() };
        }, target.name);
        assert.equal(currentDirectory.status, 200);
        const retainedUser = currentDirectory.body.users.find(row => row.id === targetId);
        assert.equal(retainedUser?.identity_kind, 'registered_account',
          'administrator directory retains the registered target');
        assert.equal(retainedUser.role, target.role);
        assert.equal(retainedUser.authority_version, captured.receipt.version);
        assert.equal(!!retainedUser.banned_at, target.action === 'ban');
        const retainedSearchResponse = page.waitForResponse(response => {
          const url = new URL(response.url());
          return url.pathname === '/api/secureshop/admin/users'
            && url.searchParams.get('search') === target.name
            && response.request().method() === 'GET';
        }, { timeout: 20000 });
        const retainedSearch = adminMutationFrame.locator('input[aria-label="Search users"]');
        await retainedSearch.setVisibility('visible').fill('');
        await retainedSearch.fill(target.name);
        assert.equal((await retainedSearchResponse).status(), 200);
        await adminMutationFrame.waitForFunction(({ name, role, banned }) => {
          const row = document.querySelector(`button[aria-label="View ${name}"]`)
            ?.parentElement?.parentElement;
          return !!row && row.querySelector(`select[aria-label="Change role for ${name}"]`)?.value === role
            && row.textContent.includes(banned ? 'banned ' : 'active');
        }, { timeout: 20000 }, { name: target.name, role: target.role, banned: target.action === 'ban' });
        const operationRows = (await pools.IDENTITY_MIGRATION.query(`SELECT * FROM
          secureshop_auth.tenant_admin_operations WHERE launch_id=$1 AND generation=$2
          AND operation_id=$3`, [currentAdmin.scope.launchId, currentAdmin.scope.generation, operationId])).rows;
        assert.equal(operationRows.length, 1);
        assert.deepEqual(operationRows[0].result_json, captured.receipt);
        assert.equal(operationRows[0].actor_id, currentAdmin.persona.id);
        assert.equal(operationRows[0].target_id, targetId);
        assert.equal(operationRows[0].owner_id, currentAdmin.scope.platformOwnerId);
        assert.equal(operationRows[0].execution_session_id, currentAdmin.scope.platformSessionId);
        assert.equal(operationRows[0].actor_session_id, currentAdmin.personaSession.sessionId);
        assert.equal(await auth.authenticate(target.account.token), null,
          'registered target old cookie cannot authenticate in the changed tenant');
        const otherPrincipal = await otherTenantAuth.authenticate(target.account.token);
        assert.equal(otherPrincipal?.principalId, target.account.context.principalId,
          'the same cookie remains valid in an unchanged tenant');
        const otherExecution = await otherTenantAuth.establishTenantContext(otherPrincipal);
        assert.equal(otherExecution.sessionId, otherTenantSessions.get(targetId),
          'the unrelated tenant execution stays current');
        assert.equal(await composition.launches.resolveCapability(target.oldLaunch.bearer), null,
          'registered target old execution is fenced');
        await assert.rejects(composition.personaAuth.authenticateBoundToken({ scope: target.oldScope,
          token: target.oldLaunch.persona.token }), { code: 'STALE_LAUNCH' });
        const loginHttp = await fetch(`${origin}/api/secureshop/auth/login`, { method: 'POST',
          headers: { origin, 'content-type': 'application/json' },
          body: JSON.stringify({ username: target.name, password }) });
        if (target.action === 'ban') {
          assert.equal(loginHttp.status, 401, 'banned registered target cannot sign in');
          status.adminBanRecovered = true;
        } else {
          assert.equal(loginHttp.status, 200, 'role-changed registered target can reauthenticate');
          const loginUser = await loginHttp.json();
          assert.equal(loginUser.user.id, targetId);
          assert.equal(loginUser.user.role, 'merchant');
          const token = loginHttp.headers.get('set-cookie')
            ?.match(/dvaia_shop_session=([^;]+)/)?.[1];
          assert.ok(token);
          const freshBound = await bootstrap(await auth.authenticate(decodeURIComponent(token)));
          assert.equal(freshBound.persona.user.id, targetId);
          assert.equal(freshBound.persona.user.role, 'merchant');
          await auth.logout(decodeURIComponent(token));
          status.adminRoleChangeRecovered = true;
        }
      }
      assert.equal(JSON.stringify(await unaffectedRows()) === JSON.stringify(unaffectedBefore), true,
        'registered role and ban changes preserve other tenant memberships');
      assert.equal(JSON.stringify(await otherMembershipRows()) === JSON.stringify(otherMembershipsBefore), true,
        'the role and ban targets keep their unrelated tenant memberships byte-for-byte');

      stage = 'admin-access-control-rendered';
      const foreignPolicyHeads = async () => (await pools.AGENTS_MIGRATION.query(`SELECT * FROM
        secureshop_agents.bound_tool_policy_heads WHERE original_platform_owner_id<>$1
        ORDER BY original_platform_owner_id,platform_launch_id`,
      [currentAdmin.scope.platformOwnerId])).rows;
      const foreignPolicyBefore = await foreignPolicyHeads();
      const policyPath = `${origin}/api/secureshop/admin/access-control`;
      const aclLoaded = page.waitForResponse(response => response.url() === policyPath
        && response.request().method() === 'GET' && response.status() === 200,
      { timeout: 20000 });
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/admin/access-control`)).status()));
      const aclFrame = await stableFrame(page);
      const aclInitial = await (await aclLoaded).json();
      assert.equal(aclInitial.ok, true);
      assert.equal(aclInitial.administration.versionedPolicy, true);
      assert.equal(aclInitial.version, '1');
      assert.equal(aclInitial.enforcement_enabled, false);
      const aclCell = '[data-testid="acl-cell-audit.search_by_user-admin"]';
      const aclSwitch = '[data-testid="acl-enforcement-toggle"]';
      await aclFrame.waitForFunction(selector => document.querySelector(selector)?.getAttribute('data-allowed') === 'true',
        { timeout: 20000 }, aclCell);
      assert.equal(aclInitial.tools.find(row => row.tool_name === 'audit.search_by_user')?.admin, true);
      const unsupportedAclTool = aclInitial.tools.find(row => row.readOnly);
      assert.ok(unsupportedAclTool);
      assert.equal(await aclFrame.$eval(`[data-testid="acl-cell-${unsupportedAclTool.tool_name}-admin"]`,
        node => node.disabled), true);
      const clickAclControl = async selector => {
        const control = await aclFrame.$(selector);
        assert.ok(control, `real ACL control ${selector} is present`);
        try {
          await control.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
          await aclFrame.waitForFunction(async node => {
            if (!node?.isConnected || node.disabled || node.getAttribute('aria-disabled') === 'true') return false;
            const before = node.getBoundingClientRect();
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
            const after = node.getBoundingClientRect();
            if (['left', 'top', 'width', 'height'].some(key => before[key] !== after[key])
              || after.width <= 0 || after.height <= 0 || after.top < 0 || after.left < 0
              || after.right > innerWidth || after.bottom > innerHeight) return false;
            const hit = document.elementFromPoint(after.left + after.width / 2, after.top + after.height / 2);
            return hit === node || node.contains(hit);
          }, { timeout: 20000 }, control);
          await control.click();
        } finally { await control.dispose(); }
      };
      const aclReceipts = [];
      const changeAcl = async (selector, kind, expectedVersion, expectedValue) => {
        const response = page.waitForResponse(value => value.url() === `${policyPath}/${kind}`
          && value.request().method() === 'POST', { timeout: 20000 });
        await clickAclControl(selector);
        const changed = await response;
        assert.equal(changed.status(), 200);
        const result = await changed.json();
        assert.equal(result.ok, true);
        assert.equal(result.receipt?.version, expectedVersion);
        assert.equal(result.receipt?.registrySha256, aclInitial.registrySha256);
        const operationId = result.receipt?.operationId;
        assert.match(operationId, /^[0-9a-f-]{36}$/);
        const read = await aclFrame.evaluate(async id => {
          const response = await fetch(`/api/secureshop/admin/access-control/operations/${id}`);
          return { status: response.status, body: await response.json() };
        }, operationId);
        assert.equal(read.status, 200);
        assert.deepEqual(read.body, { ok: true, receipt: result.receipt });
        const policy = await aclFrame.evaluate(async () =>
          (await fetch('/api/secureshop/admin/access-control')).json());
        assert.equal(policy.version, expectedVersion);
        assert.equal(policy.registrySha256, aclInitial.registrySha256);
        if (kind === 'permission') assert.equal(policy.tools.find(row =>
          row.tool_name === 'audit.search_by_user').admin, expectedValue);
        else assert.equal(policy.enforcement_enabled, expectedValue);
        await aclFrame.waitForFunction(({ cell, toggle, kind: selected, value }) => selected === 'permission'
          ? document.querySelector(cell)?.getAttribute('data-allowed') === String(value)
          : document.querySelector(toggle)?.getAttribute('aria-checked') === String(value),
        { timeout: 20000 }, { cell: aclCell, toggle: aclSwitch, kind, value: expectedValue });
        aclReceipts.push(result.receipt);
        return result.receipt;
      };
      await changeAcl(aclCell, 'permission', '2', false);

      await changeAcl(aclSwitch, 'enforcement', '3', true);
      await changeAcl(aclSwitch, 'enforcement', '4', false);
      await changeAcl(aclCell, 'permission', '5', true);
      assert.equal(aclReceipts.length, 4);
      const policyAudit = (await pools.AGENTS_MIGRATION.query(`SELECT action,source_id FROM
        secureshop_agents.bound_audit_events WHERE launch_id=$1 AND scenario_id=$2
        AND generation=$3 AND original_platform_owner_id=$4 AND original_platform_session_id=$5
        AND shop_user_id=$6 AND source_kind='bound_tool_policy'`,
      [currentAdmin.scope.launchId, currentAdmin.scope.scenarioId, currentAdmin.scope.generation,
        currentAdmin.scope.platformOwnerId, currentAdmin.scope.platformSessionId,
        currentAdmin.persona.id])).rows;
      assert.equal(policyAudit.length, 4, 'four versioned UI changes produce four immutable audits');
      assert.equal(policyAudit.every(row => row.action === 'tool_policy_changed'), true);
      assert.deepEqual(policyAudit.map(row => row.source_id).sort(),
        aclReceipts.map(row => row.operationId).sort(),
      'each rendered ACL mutation has its exact retained same-store audit source');
      assert.equal(JSON.stringify(await foreignPolicyHeads()), JSON.stringify(foreignPolicyBefore),
        'standalone ACL mutations leave foreign tenant policy rows unchanged');
      status.accessControlVersionedRendered = true;

      stage = 'admin-audit-seed';
      const auditIds = [randomUUID(), randomUUID()];
      const auditClient = await agents.connect();
      try {
        await auditClient.query('BEGIN');
        for (const [index, eventId] of auditIds.entries()) {
          await audit.agents.append(auditClient, { eventId, scope: currentAdmin.scope,
            persona: { id: currentAdmin.persona.id, role: 'admin' },
            actor: 'rendered-pagination', action: 'page-check', target: `owned:${index}`,
            paramsJson: JSON.stringify({ disposable: true, ordinal: index }),
            outcome: 'completed', sourceKind: 'fixture', sourceId: `audit-page-${index}` });
        }
        await auditClient.query('COMMIT');
      } catch (error) { await auditClient.query('ROLLBACK'); throw error; }
      finally { auditClient.release(); }
      const ownedAudit = await audit.reader.recent(currentAdmin.scope, { limit: 1 });
      assert.equal(ownedAudit.count, 1);
      assert.equal(ownedAudit.hasMore, true);
      assert.ok(auditIds.includes(ownedAudit.events[0].event_id));

      stage = 'admin-audit-rendered-pagination';
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/admin/audit`)).status()));
      const auditFrame = await stableFrame(page);
      await auditFrame.waitForSelector('input[type="number"]', { timeout: 20000 });
      await auditFrame.locator('input[type="number"]').fill('1');
      await auditFrame.waitForFunction(() => document.querySelector('input[type="number"]')?.value === '1'
        && [...document.querySelectorAll('button')].some(button => button.textContent.trim() === 'older events'),
      { timeout: 20000 });
      const visibleAuditId = () => auditFrame.$$eval('[role="button"] .ss-mono', nodes =>
        nodes.map(node => node.textContent.trim()).find(value => value.startsWith('#agents:')) || null);
      const latestId = await visibleAuditId();
      assert.ok(latestId && auditIds.some(id => latestId.includes(id)), 'latest row is an owned fixture event');
      const auditPageButton = async label => {
        const buttons = await auditFrame.$$('button');
        for (const button of buttons) {
          if ((await button.evaluate(node => node.textContent.trim())) === label) {
            await button.evaluate(node => node.scrollIntoView({ block: 'center' }));
            await button.click(); return;
          }
        }
        throw new Error(`Missing rendered audit control: ${label}`);
      };
      await auditPageButton('older events');
      await auditFrame.waitForFunction(id => document.body.textContent.includes('historical page · live refresh paused')
        && (() => { const rows = [...document.querySelectorAll('[role="button"] .ss-mono')]
          .map(node => node.textContent.trim()).filter(text => text.startsWith('#agents:'));
        return rows.length === 1 && rows[0] !== id; })(), { timeout: 20000 }, latestId);
      await auditPageButton('latest events');
      await auditFrame.waitForFunction(id => !document.body.textContent.includes('historical page · live refresh paused')
        && (() => { const rows = [...document.querySelectorAll('[role="button"] .ss-mono')]
          .map(node => node.textContent.trim()).filter(text => text.startsWith('#agents:'));
        return rows.length === 1 && rows[0] === id; })(),
      { timeout: 20000 }, latestId);
      status.auditRenderedPagination = true;

      if (externalPolicyRenderer) {
        stage = 'policy-saved-operation-recovery';
        await externalPolicyRenderer.check();
        assert.notEqual(admin.scope.launchId, currentAdmin.scope.launchId,
          'the real sibling policy namespace has a distinct authenticated launch');
        const siblingHead = await composition.promptPolicies.list(admin);
        await composition.promptPolicies.render({ ...admin, action: 'upsert',
          expectedVersion: siblingHead.version,
          request: { operationId: randomUUID(), name: `sibling-${suffix}`,
            markdown: 'Sibling policy {{ 2 * 3 }}.', targets: ['admin'] } });
        const policySnapshot = async scope => {
          const output = {};
          for (const table of ['heads', 'current', 'revisions', 'operations', 'snapshots']) {
            output[table] = (await pools.AGENTS_MIGRATION.query(
              `SELECT row_to_json(p) AS value FROM secureshop_agents.bound_prompt_policy_${table} p
               WHERE platform_launch_id=$1 ORDER BY row_to_json(p)::text`, [scope.launchId])).rows;
          }
          return output;
        };
        const siblingBefore = await policySnapshot(admin.scope);
        assert.equal(siblingBefore.current.length, 1, 'sibling has an actual persisted policy');
        assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/admin/policies`)).status()));
        let policyFrame = await stableFrame(page);
        await policyFrame.waitForFunction(() => [...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === '+ new policy' && !button.disabled));
        const endpoint = `${origin}/api/secureshop/admin/policies`;
        const initial = await policyFrame.evaluate(async () => {
          const response = await fetch('/api/secureshop/admin/policies');
          return { status: response.status, body: await response.json() };
        });
        assert.equal(initial.status, 200);
        const policyName = `recovery-${suffix}`, markdown = 'Disposable saved policy {{ 6 * 7 }}.';
        await clickMailButton(policyFrame, '+ new policy');
        await policyFrame.locator('.ss-role-modal input[placeholder="e.g. return_policy"]')
          .setVisibility('visible').fill(policyName);
        await policyFrame.locator('.ss-role-modal textarea').setVisibility('visible').fill(markdown);
        assert.deepEqual(await policyFrame.evaluate(() => ({
          name: document.querySelector('.ss-role-modal input').value,
          markdown: document.querySelector('.ss-role-modal textarea').value,
          targets: [...document.querySelectorAll('.ss-role-modal label')]
            .filter(label => label.querySelector('input[type="checkbox"]')?.checked)
            .map(label => label.textContent.trim()),
        })), { name: policyName, markdown, targets: ['customer'] });
        // Cancel the staged create in the real modal before the committed attempt.
        // A hidden/missing modal or a different Cancel button cannot satisfy this check.
        const beforeCancel = await policySnapshot(currentAdmin.scope);
        const postsBeforeCancel = policyPosts.length;
        const rendersBeforeCancel = policyRenderCalls;
        assert.deepEqual(await policyFrame.evaluate(() => {
          const modals = [...document.querySelectorAll('.ss-role-modal')];
          const buttons = modals.length === 1
            ? [...modals[0].querySelectorAll('button')].filter(button =>
                button.textContent.trim() === 'cancel' && button.type === 'button' && !button.disabled)
            : [];
          const firstGlobalCancel = [...document.querySelectorAll('button')]
            .find(button => button.textContent.trim() === 'cancel');
          return { modals: modals.length, buttons: buttons.length,
            helperTargetsModal: firstGlobalCancel === buttons[0] };
        }), { modals: 1, buttons: 1, helperTargetsModal: true });
        await clickMailButton(policyFrame, 'cancel');
        await policyFrame.waitForFunction(() => !document.querySelector('.ss-role-modal'),
          { timeout: 20000 });
        assert.equal(policyPosts.length, postsBeforeCancel,
          'cancel must not submit a policy operation');
        assert.equal(policyRenderCalls, rendersBeforeCancel,
          'cancel must not invoke the policy renderer');
        assert.deepEqual(await policySnapshot(currentAdmin.scope), beforeCancel,
          'cancel must leave all owned policy tables unchanged');
        assert.deepEqual(await policySnapshot(admin.scope), siblingBefore,
          'cancel must leave the sibling policy namespace unchanged');
        await clickMailButton(policyFrame, '+ new policy');
        await policyFrame.locator('.ss-role-modal input[placeholder="e.g. return_policy"]')
          .setVisibility('visible').fill(policyName);
        await policyFrame.locator('.ss-role-modal textarea').setVisibility('visible').fill(markdown);
        const rendersBefore = policyRenderCalls, postsBefore = policyPosts.length;
        const loss = await dropOneCommittedOperationResponse(page, endpoint);
        let committedPolicy;
        try {
          await clickMailButton(policyFrame, 'create');
          await policyFrame.waitForFunction(() => [...document.querySelectorAll('button')]
            .some(button => button.textContent.trim() === 'Refresh operation status' && !button.disabled),
          { timeout: 20000 });
          committedPolicy = loss.captured(); assert.ok(committedPolicy);
        } finally { await loss.close(); }
        const { request, receipt } = committedPolicy;
        assert.deepEqual(request, { name: policyName, markdown, injected_into: ['customer'],
          operationId: receipt.operationId, expectedVersion: initial.body.version });
        assert.equal(receipt.version, String(BigInt(initial.body.version) + 1n));
        assert.equal(receipt.renderResult.rendered, 'Disposable saved policy 42.');
        require('../../server/services/secureshopPromptPolicyContract').validateRenderResult({
          operationId: request.operationId, name: policyName, markdown, targets: ['customer'],
        }, receipt.renderResult);
        assert.equal(policyRenderCalls, rendersBefore + 1);
        assert.equal(policyPosts.length, postsBefore + 1);
        const committedSnapshot = await policySnapshot(currentAdmin.scope);
        assert.equal(committedSnapshot.operations.filter(row =>
          row.value.operation_id === request.operationId).length, 1);
        assert.equal(committedSnapshot.current.filter(row => row.value.name === policyName).length, 1);
        assert.ok([200, 304].includes((await page.reload({ waitUntil: 'domcontentloaded' })).status()));
        policyFrame = await stableFrame(page);
        await policyFrame.waitForFunction(() => [...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Refresh operation status' && !button.disabled));
        assert.equal(policyPosts.length, postsBefore + 1, 'reload does not submit another policy mutation');
        const savedResponse = page.waitForResponse(response =>
          response.url() === `${endpoint}/operations/${request.operationId}`
          && response.request().method() === 'GET', { timeout: 20000 });
        await clickMailButton(policyFrame, 'Refresh operation status');
        const saved = await savedResponse; assert.equal(saved.status(), 200);
        const savedValue = await saved.json(); assert.equal(savedValue.ok, true);
        assert.deepEqual(savedValue.receipt, { ...receipt, replayed: true },
          'GET preserves the entire immutable committed receipt with its exact transport replay marker');
        await policyFrame.waitForFunction(() => ![...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Refresh operation status'));
        assert.equal(policyPosts.length, postsBefore + 1);
        assert.equal(policyRenderCalls, rendersBefore + 1, 'GET recovery never re-renders');
        assert.deepEqual(await policySnapshot(currentAdmin.scope), committedSnapshot,
          'recovery preserves exact version/content/operation and does not append another effect');
        assert.deepEqual(await policySnapshot(admin.scope), siblingBefore, 'real sibling namespace is untouched');
        await externalPolicyRenderer.check();
        status.policySavedOperationRecovery = true;
        status.policyRecovery = { status: 'passed', ...externalPolicyRenderer.identity,
          operationId: request.operationId, version: receipt.version,
          requestSha256: receipt.requestSha256, renderCalls: 1, mutationPosts: 1,
          siblingLaunchId: admin.scope.launchId };
      }

      // C26/M22 exercise manual Compose, never autoreply or objective assessment.
      // One case loses a committed ACK; the other genuinely blocks delivery and
      // requires the explicit same-ID retry with the original dialog payload.
      const mailReadback = async (requestId, expected, personaId) => {
        const rows = (await pools.AGENTS_MIGRATION.query(`SELECT r.operation_id,r.target_id,
          r.caller_id,r.role,r.action,r.result,m.message_id,m.sender_id,m.recipient_id,
          m.from_addr,m.to_addr,m.subject,m.body_markdown
          FROM secureshop_agents.lab_mail_operation_receipts r
          JOIN secureshop_agents.lab_mail_messages m ON m.target_id=r.target_id
            AND m.message_id=(r.result->>'email_id')::bigint
          WHERE r.operation_id=$1`, [requestId])).rows;
        assert.equal(rows.length, 1, 'one immutable send receipt joins one genuine saved message');
        const row = rows[0];
        assert.equal(row.action, 'send'); assert.equal(row.caller_id, personaId);
        assert.equal(row.sender_id, personaId); assert.equal(row.recipient_id, personaId);
        assert.equal(row.from_addr, expected.from); assert.equal(row.to_addr, expected.to);
        assert.equal(row.subject, expected.subject); assert.equal(row.body_markdown, expected.body_markdown);
        assert.equal((await pools.AGENTS_MIGRATION.query(`SELECT count(*)::int n
          FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 AND sender_id=$2 AND subject=$3`,
        [row.target_id, personaId, expected.subject])).rows[0].n, 1, 'transport retry never duplicates the mail effect');
        return row;
      };
      const navigateMail = async route => {
        assert.ok([200, 304].includes((await page.goto(`${origin}${route}`)).status()));
        const frame = await stableFrame(page);
        await frame.waitForFunction(() => [...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Compose' && !button.disabled)
          && !/loading…/i.test(document.body.textContent), { timeout: 20000 });
        return frame;
      };
      for (const role of ['customer', 'merchant']) {
        stage = `${role}-compose-login`;
        assert.equal(await page.evaluate(async () =>
          (await fetch('/api/secureshop/auth/logout', { method: 'POST', credentials: 'include',
            headers: { 'content-type': 'application/json' }, body: JSON.stringify({}) })).status), 200);
        assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()));
        await page.waitForSelector('#ss-login-user');
        await page.type('#ss-login-user', role === 'customer' ? customerName : 'student_merchant');
        await page.type('#ss-login-pw', role === 'customer' ? password : 'student123');
        await page.click('button[type="submit"]'); await stableFrame(page);
        const mailCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
          .find(value => value.name === 'dvaia_shop_session');
        assert.equal(mailCookie?.httpOnly, true);
        const mailActor = await actor(await auth.authenticate(mailCookie.value));
        assert.equal(mailActor.persona.role, role);
        if (role === 'merchant' && externalMailOptIn) {
          stage = 'external-mail-one-confirmed-send';
          const externalMailPrincipal = await auth.authenticate(mailCookie.value);
          const selectedInbox = await externalMailFixture.prepareInbox({ browser, browserBoundary,
            recipient: process.env.SECURESHOP_EXTERNAL_MAIL_TEST_RECIPIENT,
            deadlineAt: Math.min(workDeadline, Date.now() + 90000), networkDeadlineAt: workDeadline,
            signal: externalMailAbort.signal });
          const externalMailDeadline = Math.min(workDeadline, Date.now() + 60000);
          externalMail.arm(externalMailDeadline);
          const externalMailTimer = setTimeout(() => externalMailAbort.abort(), Math.max(0, externalMailDeadline - Date.now()));
          // Reuse only a page already opened/selected by the reviewed inbox
          // browser admission. No guessed mailbox selector or automatic resend.
          try {
          status.externalMail = await workStep(stage, () => externalMailFixture.exerciseRoundTrip({
            inboxPage: selectedInbox.page,
            page, liveSmtp: true,
            recipient: process.env.SECURESHOP_EXTERNAL_MAIL_TEST_RECIPIENT,
            principalId: externalMailPrincipal.principalId,
            deadlineAt: externalMailDeadline, signal: externalMailAbort.signal,
            attempted: externalMail.attempted,
          }), Math.max(1, externalMailDeadline - Date.now()));
          } finally { clearTimeout(externalMailTimer); externalMailAbort.abort(); }
          assert.equal(status.externalMail.outcome, 'smtp_accepted', 'Uncertain delivery: retain operation, never resend');
          assert.equal(status.externalMail.deliveryConfirmed, true, 'SMTP acceptance alone is not browser delivery proof');
        }
        const route = role === 'customer' ? '/secureshop/inbox' : '/secureshop/merchant/inbox';
        for (const beforeDelivery of [false, true]) {
          stage = `${role}-compose-${beforeDelivery ? 'predelivery-retry' : 'lost-ack-recovery'}`;
          let frame = await navigateMail(route);
          const message = { from: mailActor.persona.email, to: mailActor.persona.email,
            subject: `Compose ${role} ${beforeDelivery ? 'retry' : 'ACK'} ${suffix}`,
            body: `Benign disposable ${role} manual delivery verification.` };
          await fillMailDialog(frame, role, message);
          const loss = await dropOneMailDelivery(page, `${origin}/api/secureshop/email/send`, beforeDelivery);
          let interrupted;
          try {
            await clickMailButton(frame, 'Send', true);
            await frame.waitForFunction(() => document.body.textContent.includes('Send not confirmed')
              && [...document.querySelectorAll('[role="dialog"] button')]
                .some(button => button.textContent.trim() === 'Retry pending send' && !button.disabled),
            { timeout: 20000 });
            interrupted = loss.captured(); assert.ok(interrupted, 'the exact send transport was interrupted');
          } finally { await loss.close(); }
          const requestId = interrupted.request.requestId;
          const expected = { from: message.from, to: message.to,
            subject: message.subject, body_markdown: message.body };
          assert.deepEqual(interrupted.request, { ...expected, requestId });
          const deliveredPosts = () => mailPosts.filter(row => row.requestId === requestId).length;
          const recoverPath = `/api/secureshop/email/operations/send/${requestId}`;
          let saved;
          if (beforeDelivery) {
            assert.equal(deliveredPosts(), 0, 'blocked transport never reaches the send route');
            assert.equal((await agents.query(`SELECT count(*)::int n
              FROM secureshop_agents.lab_mail_operation_receipts WHERE operation_id=$1`, [requestId])).rows[0].n, 0);
            const recoveryResponse = page.waitForResponse(response =>
              new URL(response.url()).pathname === recoverPath && response.request().method() === 'GET');
            const sendResponse = page.waitForResponse(response =>
              new URL(response.url()).pathname === '/api/secureshop/email/send'
              && response.request().method() === 'POST'
              && JSON.parse(response.request().postData()).requestId === requestId);
            await clickMailButton(frame, 'Retry pending send', true);
            const unconfirmedResponse = await recoveryResponse;
            assert.equal(unconfirmedResponse.status(), 200);
            const unconfirmed = await unconfirmedResponse.json();
            assert.equal(unconfirmed.status, 'unconfirmed'); assert.equal(unconfirmed.requestId, requestId);
            assert.equal(unconfirmed.canRetrySameId, true);
            const sentResponse = await sendResponse;
            assert.equal(sentResponse.status(), 200);
            assert.deepEqual(JSON.parse(sentResponse.request().postData()), interrupted.request,
              'manual retry carries the exact original ID and payload');
            saved = await sentResponse.json(); assert.equal(saved.ok, true);
            await frame.waitForSelector('[role="dialog"]', { hidden: true, timeout: 20000 });
          } else {
            assert.equal(deliveredPosts(), 1);
            const beforeRecovery = await mailReadback(requestId, expected, mailActor.persona.id);
            assert.equal(Number(beforeRecovery.message_id), interrupted.receipt.email_id);
            assert.ok([200, 304].includes((await page.reload()).status())); frame = await stableFrame(page);
            await frame.waitForFunction(() => [...document.querySelectorAll('button')]
              .some(button => button.textContent.trim() === 'Check pending mail' && !button.disabled),
            { timeout: 20000 });
            assert.equal(deliveredPosts(), 1, 'reload never resubmits the saved operation');
            const recoveryResponse = page.waitForResponse(response =>
              new URL(response.url()).pathname === recoverPath && response.request().method() === 'GET');
            await clickMailButton(frame, 'Check pending mail');
            const recovered = await recoveryResponse;
            assert.equal(recovered.status(), 200); saved = await recovered.json();
            assert.equal(saved.status, 'saved'); assert.equal(saved.requestId, requestId);
            assert.equal(saved.email_id, interrupted.receipt.email_id);
            assert.deepEqual(await mailReadback(requestId, expected, mailActor.persona.id), beforeRecovery,
              'saved GET recovery leaves the exact receipt and message intact');
          }
          assert.equal(deliveredPosts(), 1, 'exactly one send reaches Express per manual operation');
          assert.ok(Number.isSafeInteger(saved.email_id) && saved.email_id > 0);
          await frame.waitForFunction(subject => document.body.textContent.includes(subject)
            && ![...document.querySelectorAll('button')]
              .some(button => button.textContent.trim() === 'Check pending mail'), { timeout: 20000 }, message.subject);
          const retained = await mailReadback(requestId, expected, mailActor.persona.id);
          assert.equal(Number(retained.message_id), saved.email_id);
          assert.ok([200, 304].includes((await page.reload()).status())); frame = await stableFrame(page);
          await frame.waitForFunction(subject => document.body.textContent.includes(subject), { timeout: 20000 }, message.subject);
          assert.equal(deliveredPosts(), 1);
          assert.deepEqual(await mailReadback(requestId, expected, mailActor.persona.id), retained);
        }
        status[role === 'customer' ? 'customerComposeRecoverySingleEffect' : 'merchantComposeRecoverySingleEffect'] = true;
      }
      stage = 'manual-review-reject-recovery';
      // Submit actual pending reviews through the production customer service.
      // The rendered merchant decides only its own product; the second row is
      // retained unchanged to detect an accidental extra decision.
      const reviewCustomerLogin = await auth.login({ username: customerName, password });
      const reviewCustomer = await actor(reviewCustomerLogin.context);
      const manualProductId = Number(stocked.product_id);
      const reviewBodies = [`Manual rejection ${suffix}`, `Untouched pending review ${suffix}`];
      const submittedReviews = [];
      for (const body of reviewBodies) submittedReviews.push(await composition.runtime.application.submitReview({
        ...reviewCustomer, productId: manualProductId, submissionId: randomUUID(),
        authorId: reviewCustomer.persona.id, body, rating: 3,
      }));
      const reviewId = submittedReviews[0].id, unchangedId = submittedReviews[1].id;
      const reviewSnapshot = async id => {
        const rows = (await pools.REVIEW_MIGRATION.query(
          'SELECT row_to_json(r) AS value FROM secureshop_review.reviews r WHERE id=$1', [id])).rows;
        assert.equal(rows.length, 1); return rows[0].value;
      };
      const beforeReview = await reviewSnapshot(reviewId), unchangedReview = await reviewSnapshot(unchangedId);
      assert.equal(beforeReview.status, 'pending'); assert.equal(unchangedReview.status, 'pending');
      assert.equal(Number(beforeReview.product_id), manualProductId);
      assert.equal(Number((await review.query(`SELECT retailer_id FROM secureshop_review.product_target_products
        WHERE target_id=$1 AND product_id=$2`, [(await scenes.readExisting(firstScope)).targetId,
      manualProductId])).rows[0].retailer_id), persona.id);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/merchant/reviews`)).status()));
      let reviewFrame = await stableFrame(page);
      await reviewFrame.waitForFunction(body => [...document.querySelectorAll('article')]
        .some(row => row.textContent.includes(body) && [...row.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Reject' && !button.disabled)),
      { timeout: 20000 }, reviewBodies[0]);
      const pendingList = await reviewFrame.evaluate(async () => {
        const response = await fetch('/api/secureshop/merchant/reviews?status=pending');
        return { status: response.status, body: await response.json() };
      });
      assert.equal(pendingList.status, 200); assert.equal(pendingList.body.manual_decisions.available, true);
      assert.ok(pendingList.body.reviews.some(row => row.id === reviewId && row.status === 'pending'));
      assert.ok(pendingList.body.reviews.some(row => row.id === unchangedId && row.status === 'pending'));
      let openedReject = false;
      for (const row of await reviewFrame.$$('article')) {
        if (!(await row.evaluate(node => node.textContent)).includes(reviewBodies[0])) continue;
        for (const button of await row.$$('button')) {
          if ((await button.evaluate(node => node.textContent.trim())) !== 'Reject') continue;
          await button.evaluate(node => node.scrollIntoView({ block: 'center' }));
          await button.click(); openedReject = true; break;
        }
        break;
      }
      assert.equal(openedReject, true);
      await reviewFrame.waitForSelector('[role="dialog"] textarea', { visible: true });
      const reason = `Off-topic disposable review ${suffix}`;
      await reviewFrame.locator('[role="dialog"] textarea').setVisibility('visible').fill(reason);
      assert.deepEqual(await reviewFrame.evaluate(() => ({
        title: document.querySelector('[role="dialog"] .ss-card__meta')?.textContent.trim(),
        heading: document.querySelector('[role="dialog"] h2')?.textContent.trim(),
        reason: document.querySelector('[role="dialog"] textarea')?.value,
      })), { title: `REJECT REVIEW #${reviewId}`, heading: 'Reason?', reason });
      const decisionPath = `/api/secureshop/merchant/reviews/${reviewId}/reject`;
      const decisionsBefore = reviewDecisionPosts.length;
      const decisionLoss = await dropOneCommittedOperationResponse(page, `${origin}${decisionPath}`);
      let decision;
      try {
        await clickMailButton(reviewFrame, 'Reject', true);
        await reviewFrame.waitForFunction(() => [...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Refresh decision status' && !button.disabled),
        { timeout: 20000 });
        decision = decisionLoss.captured(); assert.ok(decision);
      } finally { await decisionLoss.close(); }
      const operationId = decision.request.operationId;
      assert.deepEqual(decision.request, { operationId, reason });
      assert.equal(decision.acknowledgement.applied, true);
      assert.equal(decision.acknowledgement.review_id, reviewId);
      assert.equal(decision.acknowledgement.executionScopeKey, pendingList.body.manual_decisions.scopeKey);
      assert.equal(decision.receipt.kind, 'manual'); assert.equal(decision.receipt.moderatorKind, 'manual');
      assert.equal(decision.receipt.reviewId, reviewId); assert.equal(decision.receipt.decision, 'rejected');
      assert.equal(decision.receipt.notes, reason); assert.equal(decision.receipt.applied, true);
      assert.equal(decision.receipt.resultStatus, 'rejected');
      assert.equal(decision.receipt.scope.targetId, beforeReview.target_id);
      assert.equal(decision.receipt.actor.id, persona.id); assert.equal(decision.receipt.actor.role, 'merchant');
      const currentDecisionScope = JSON.parse(pendingList.body.manual_decisions.scopeKey);
      assert.equal(currentDecisionScope.length, 6);
      assert.equal(decision.receipt.actor.id, currentDecisionScope[4]);
      assert.equal(decision.receipt.actor.personaSessionId, currentDecisionScope[5]);
      assert.match(decision.receipt.bodySha256, /^[a-f0-9]{64}$/);
      assert.equal(decision.receipt.bodySha256, createHash('sha256').update(reviewBodies[0]).digest('hex'));
      const committedReview = await reviewSnapshot(reviewId);
      assert.equal(committedReview.status, 'rejected'); assert.equal(committedReview.moderator_kind, 'manual');
      assert.equal(committedReview.moderator_notes, reason); assert.ok(committedReview.moderated_at);
      const decisionAudit = async () => (await pools.REVIEW_MIGRATION.query(
        'SELECT row_to_json(a) AS value FROM secureshop_review.bound_audit_events a WHERE event_id=$1',
        [operationId])).rows;
      const committedAudit = await decisionAudit(); assert.equal(committedAudit.length, 1);
      assert.equal(committedAudit[0].value.source_kind, 'review_decision_operation');
      assert.deepEqual(JSON.parse(committedAudit[0].value.params_json).receipt, decision.receipt);
      const sameDecisionPosts = () => reviewDecisionPosts.filter(row => row.body.operationId === operationId);
      assert.deepEqual(sameDecisionPosts(), [{ path: decisionPath, body: { operationId, reason } }]);
      assert.equal(reviewDecisionPosts.length, decisionsBefore + 1);
      assert.ok([200, 304].includes((await page.reload()).status())); reviewFrame = await stableFrame(page);
      await reviewFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === 'Refresh decision status' && !button.disabled),
      { timeout: 20000 });
      assert.equal(sameDecisionPosts().length, 1, 'reload never resends a manual decision');
      const savedDecision = page.waitForResponse(response => response.url()
        === `${origin}/api/secureshop/merchant/reviews/operations/${operationId}`
        && response.request().method() === 'GET', { timeout: 20000 });
      await clickMailButton(reviewFrame, 'Refresh decision status');
      const decisionResponse = await savedDecision; assert.equal(decisionResponse.status(), 200);
      assert.deepEqual(await decisionResponse.json(), { ok: true, receipt: decision.receipt,
        executionScopeKey: decision.acknowledgement.executionScopeKey });
      await reviewFrame.waitForFunction(id => document.body.textContent.includes(`Review #${id} rejected.`)
        && ![...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Refresh decision status'), { timeout: 20000 }, reviewId);
      await reviewFrame.waitForFunction(body => ![...document.querySelectorAll('article')]
        .some(row => row.textContent.includes(body)), { timeout: 20000 }, reviewBodies[0]);
      const afterPending = await reviewFrame.evaluate(async () => {
        const response = await fetch('/api/secureshop/merchant/reviews?status=pending');
        return { status: response.status, body: await response.json() };
      });
      assert.equal(afterPending.status, 200);
      assert.equal(afterPending.body.counts.pending, pendingList.body.counts.pending - 1);
      assert.equal(afterPending.body.counts.rejected, pendingList.body.counts.rejected + 1);
      assert.ok(!afterPending.body.reviews.some(row => row.id === reviewId));
      await reviewFrame.locator(() => [...document.querySelectorAll('button')]
        .find(button => /^Rejected\s*\d+$/.test(button.textContent.trim()))).setVisibility('visible').click();
      await reviewFrame.waitForFunction((body, note) => [...document.querySelectorAll('article')]
        .some(row => row.textContent.includes(body) && row.textContent.includes(`moderator notes: ${note}`)
          && row.textContent.includes('rejected')), { timeout: 20000 }, reviewBodies[0], reason);
      assert.equal(sameDecisionPosts().length, 1, 'saved GET recovery makes no second mutation POST');
      assert.equal(reviewDecisionPosts.length, decisionsBefore + 1, 'no second decision with any operation ID');
      assert.deepEqual(await reviewSnapshot(reviewId), committedReview);
      assert.deepEqual(await decisionAudit(), committedAudit, 'one exact immutable decision receipt survives recovery');
      assert.deepEqual(await reviewSnapshot(unchangedId), unchangedReview, 'the other pending review is untouched');
      status.manualReviewRejectRecovery = true;

      markStage('merchant-listings-catalog');
      const listingStep = async (label, work, maxMs = 12000) => {
        console.log('A11 listing step', label);
        try { return await workStep(`merchant-listings-${label}`, work, maxMs); }
        catch (error) {
          const poolCounts = Object.fromEntries(Object.entries(pools).map(([name, pool]) => [name,
            { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount }]));
          console.log('A11 listing failed', JSON.stringify({ step: label,
            code: error.code || error.name, pools: poolCounts }));
          throw error;
        }
      };
      const listingsCookie = (await listingStep('cookie', () => page.cookies(`${origin}/api/secureshop/auth/session`)))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(listingsCookie?.httpOnly, true);
      const listingsBase = await listingStep('authenticate', () => auth.authenticate(listingsCookie.value));
      const listingsMerchant = await listingStep('actor', () => actor(listingsBase));
      assert.equal(listingsMerchant.persona.role, 'merchant');
      const listingQuery = { page: 1, perPage: 100, sort: 'updated_desc',
        retailerId: listingsMerchant.persona.id, search: null, status: null, category: null };
      const listingBaseline = await listingStep('baseline', () => composition.catalog.listMerchantProducts({ ...listingsMerchant, query: listingQuery }));
      const extraListings = Math.max(0, 21 - listingBaseline.total);
      for (let index = 0; index < extraListings; index++) {
        const result = await listingStep(`create-${index}`, () => composition.catalog.createMerchantProduct({ ...listingsMerchant,
          listing: { name: `Paging listing ${suffix} ${String(index).padStart(2, '0')}`,
            description: 'Disposable owned pagination record', price: 5, category: 'fixture',
            templateSource: '{{source}}', images: [] } }));
        assert.ok(Number.isSafeInteger(result.productId) && result.productId > 0);
      }
      const expectedListingPages = [];
      for (const pageNumber of [1, 2]) expectedListingPages.push(await listingStep(`expected-page-${pageNumber}`,
        () => composition.catalog.listMerchantProducts({
          ...listingsMerchant, query: { ...listingQuery, page: pageNumber, perPage: 20 },
        })));
      const listingTotal = expectedListingPages[0].total, listingPages = Math.ceil(listingTotal / 20);
      assert.ok(listingTotal > 20); assert.equal(expectedListingPages[0].products.length, 20);
      assert.ok(expectedListingPages[1].products.length > 0);
      assert.equal(expectedListingPages[1].total, listingTotal);
      const expectedIds = expectedListingPages.map(result => result.products.map(row => row.id));
      assert.equal(new Set(expectedIds.flat()).size, expectedIds.flat().length);
      markStage('merchant-listings-browser');
      readinessObserver.arm();
      const listingsResponse = pageNumber => page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.pathname === '/api/secureshop/merchant/products'
          && response.request().method() === 'GET' && url.searchParams.get('page') === String(pageNumber)
          && url.searchParams.get('per_page') === '20' && url.searchParams.get('sort') === 'updated_desc'
          && url.searchParams.get('retailer_id') === String(listingsMerchant.persona.id);
      }, { timeout: 20000 });
      const listingReadinessResponse = page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.origin === origin
          && url.pathname === '/api/secureshop/merchant/listings/readiness'
          && response.request().method() === 'GET';
      }, { timeout: 20000 });
      const firstListingsResponse = listingsResponse(1);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/merchant/listings`)).status()));
      const listingsFrame = await stableFrame(page);
      const verifyListingPage = async (responsePromise, pageNumber) => {
        const response = await responsePromise; assert.equal(response.status(), 200);
        const value = await response.json();
        assert.equal(value.page, pageNumber); assert.equal(value.per_page, 20);
        assert.equal(value.total, listingTotal); assert.equal(value.pages, listingPages);
        assert.equal(value.count, expectedIds[pageNumber - 1].length);
        assert.deepEqual(value.products.map(row => row.id), expectedIds[pageNumber - 1]);
        await listingsFrame.waitForFunction((ids, total, current, pages) =>
          document.body.textContent.includes(`${total} products · page ${current} of ${pages}`)
          && JSON.stringify([...document.querySelectorAll('tbody tr[id^="p"]')]
            .map(row => Number(row.id.slice(1)))) === JSON.stringify(ids),
        { timeout: 20000 }, expectedIds[pageNumber - 1], listingTotal, pageNumber, listingPages);
      };
      await verifyListingPage(firstListingsResponse, 1);
      const listingReadinessHttp = await listingReadinessResponse;
      assert.equal(listingReadinessHttp.status(), 503);
      await workStep('merchant-listings-original-readiness-response',
        () => readinessObserver.wait(), 5000);
      readinessObserver.assertBrowserResponse(listingReadinessHttp, origin);
      await listingsFrame.waitForFunction(() => [...document.querySelectorAll('[role="alert"]')]
        .some(node => node.textContent.includes('Listing actions could not be verified (HTTP 503).')),
      { timeout: 20000 });
      assert.ok(boundAuthority?.authorization && boundAuthority?.launch,
        'the rendered bound frame must provide both bearer and launch authority');
      const unknownRouteResults = await page.evaluate(async authority => {
        const request = async (path, method, body) => {
          const response = await fetch(path, {
            method,
            headers: { Authorization: authority.authorization,
              'X-DVAIA-SecureShop-Launch': authority.launch,
              ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          });
          return { status: response.status, body: await response.json() };
        };
        return {
          get: await request('/api/secureshop/merchant/listings/not-registered', 'GET'),
          post: await request('/api/secureshop/merchant/listings/not-registered', 'POST', {}),
        };
      }, boundAuthority);
      for (const result of [unknownRouteResults.get, unknownRouteResults.post]) {
        assert.equal(result.status, 404);
        assert.deepEqual(result.body, { error: 'Bound SecureShop route not found' });
      }
      assert.equal(legacyBoundFallbackHits, 0,
        'bound unknown and disabled actions must not fall through to a legacy mount');
      const nextListingsResponse = listingsResponse(2);
      await clickMailButton(listingsFrame, 'Next'); await verifyListingPage(nextListingsResponse, 2);
      const previousListingsResponse = listingsResponse(1);
      await clickMailButton(listingsFrame, 'Prev'); await verifyListingPage(previousListingsResponse, 1);
      assert.equal((await listingStep('unchanged-total', () => composition.catalog.listMerchantProducts({ ...listingsMerchant, query: listingQuery }))).total,
        listingTotal, 'rendered navigation does not mutate the catalog');
      status.merchantListingsRenderedPagination = true;

      stage = 'a08-merchant-buttons';
      await qualifyRoleButtons(page, listingsFrame, 'merchant', [
        { selector: 'button[data-testid="listings-create-cta"]', text: 'Create listing', size: 'md', variant: 'primary' },
        { selector: 'button.ss-btn', text: 'Next', size: 'sm', variant: 'ghost' },
      ], receiptPath);
      status.buttonsDesktopTemplateParity = true; status.buttonsNarrowTemplateParity = true;

      stage = 'customer-self-password-change';
      const otherPrincipalIds = [merchantRegistration.context.principalId,
        adminLogin.context.principalId, siblingAccount.context.principalId];
      const otherPrincipals = async () => (await pools.IDENTITY_MIGRATION.query(`SELECT *
        FROM secureshop_auth.principals WHERE principal_id=ANY($1::uuid[]) ORDER BY principal_id`,
      [otherPrincipalIds])).rows;
      const beforeSelfChange = await otherPrincipals();
      assert.equal(await page.evaluate(async () => (await fetch('/api/secureshop/auth/logout', {
        method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      })).status), 200);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()));
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', customerName);
      await page.type('#ss-login-pw', password);
      await page.click('button[type="submit"]');
      await stableFrame(page);
      const oldCustomerCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.equal(oldCustomerCookie?.httpOnly, true);
      const oldCustomerPrincipal = await auth.authenticate(oldCustomerCookie.value);
      assert.equal(oldCustomerPrincipal?.shopUserId, buyerBase.shopUserId);
      const oldCustomerLaunch = await bootstrap(oldCustomerPrincipal);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/account`)).status()));
      const accountFrame = await stableFrame(page);
      await accountFrame.waitForFunction(name => document.querySelector('h1')?.textContent.trim() === 'Account'
        && !!document.querySelector('#ss-tab-security')
        && [...document.querySelectorAll('strong')].some(node => node.textContent.trim() === name),
      { timeout: 20000 }, customerName);
      stage = 'customer-api-key-versioning';
      await page.browserContext().overridePermissions(origin, ['clipboard-read', 'clipboard-write']);
      await clickMailButton(accountFrame, 'API Keys');
      await accountFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === 'Generate key' && !button.disabled),
      { timeout: 20000 });
      const keyEndpoint = `${origin}/api/secureshop/v2/auth/users/me/api-keys`;
      // Compare only version and digest, never key plaintext. A canceled
      // confirmation must not even dispatch a browser mutation request.
      const keyState = async () => (await agents.query(`SELECT api_key_version::text AS version,
        encode(api_key_sha256,'hex') AS digest FROM secureshop_agents.bound_persona_api_keys
        WHERE shop_user_id=$1 ORDER BY platform_launch_id,platform_scenario_id,
          platform_launch_generation,original_platform_owner_id,original_platform_session_id`,
      [buyerBase.shopUserId])).rows;
      const waitKeyDialog = (frame, dialog) => frame.waitForFunction(exactConsequenceDialogButton,
        { timeout: 20000 }, dialog.title, dialog.consequence, dialog.confirmLabel,
        dialog.confirmLabel);
      const waitKeyDialogClosed = (frame, title) => frame.waitForFunction(expectedTitle =>
        ![...document.querySelectorAll('[role="dialog"]')].some(node =>
          node.querySelector('#ss-dialog-title')?.textContent.trim() === expectedTitle),
      { timeout: 20000 }, title);
      const generationDialog = { title: 'Generate API key?',
        consequence: 'A new API key will be created and shown after this request succeeds.',
        confirmLabel: 'Confirm generation' };
      const rotationDialog = { title: 'Rotate API key?',
        consequence: 'The current API key will stop working. The replacement key will be shown after this request succeeds.',
        confirmLabel: 'Confirm rotation' };
      const firstKeyState = await keyState();
      assert.equal(firstKeyState.length, 0, 'this new buyer has no prior bound API key');
      const keyRequestsBeforeGeneration = keyMutationRequests;
      privateApiKeyVisible = true;
      await clickMailButton(accountFrame, 'Generate key');
      await waitKeyDialog(accountFrame, generationDialog);
      assert.equal(keyMutationRequests, keyRequestsBeforeGeneration,
        'opening Generate confirmation must not rotate a key');
      await clickMailButton(accountFrame, 'Cancel', true, generationDialog);
      await waitKeyDialogClosed(accountFrame, generationDialog.title);
      assert.equal(keyMutationRequests, keyRequestsBeforeGeneration,
        'Cancel must dispatch no Generate mutation');
      assert.equal(JSON.stringify(await keyState()) === JSON.stringify(firstKeyState), true,
        'Cancel must leave the owner key version and digest unchanged');
      await clickMailButton(accountFrame, 'Generate key');
      await waitKeyDialog(accountFrame, generationDialog);
      const generateResponse = page.waitForResponse(response => response.url() === `${keyEndpoint}/rotate`
        && response.request().method() === 'POST', { timeout: 20000 });
      await clickMailButton(accountFrame, 'Confirm generation', true, generationDialog);
      const generatedHttp = await generateResponse;
      assert.equal(generatedHttp.status(), 200);
      assert.equal(keyMutationRequests, keyRequestsBeforeGeneration + 1);
      const generated = await generatedHttp.json();
      assert.equal(generated.ok, true); assert.equal(generated.version, 1);
      const key1 = generated.api_key;
      assert.equal(typeof key1 === 'string' && /^sk_ss_live_[a-f0-9]{32}$/.test(key1), true,
        'first key is a real generated shop API credential');
      await accountFrame.waitForFunction(value => document.querySelector('input.ss-input[readonly]')?.value === value,
        { timeout: 20000 }, key1);
      await clickMailButton(accountFrame, 'Hide');
      assert.equal(await accountFrame.evaluate(value => {
        const displayed = document.querySelector('input.ss-input[readonly]')?.value;
        return typeof displayed === 'string' && displayed.startsWith(value.slice(0, 12))
          && displayed !== value && displayed.includes('·');
      }, key1), true);
      await clickMailButton(accountFrame, 'Reveal');
      assert.equal(await accountFrame.evaluate(value => document.querySelector('input.ss-input[readonly]')?.value === value,
        key1), true);
      await clickMailButton(accountFrame, 'Copy');
      assert.equal(await page.evaluate(async value => (await navigator.clipboard.readText()) === value, key1), true,
        'real browser clipboard holds the revealed first key');
      const apiOrders = async (key, bearer, detail) => {
        const response = await fetch(`${origin}/api/secureshop/v2/api/orders${detail ? `/${detail}` : ''}`, {
          headers: { 'x-api-key': key, 'x-dvaia-secureshop-launch': bearer },
          signal: AbortSignal.timeout(5000),
        });
        return { status: response.status, body: await response.json() };
      };
      const firstKeyOrders = await apiOrders(key1, oldCustomerLaunch.bearer);
      assert.equal(firstKeyOrders.status, 200);
      assert.ok(firstKeyOrders.body.orders.some(order => Number(order.id) === committed.orderId));
      const beforeRotation = await keyState();
      assert.equal(beforeRotation.length, 1);
      assert.equal(beforeRotation[0].version, '1');
      const keyRequestsBeforeRotation = keyMutationRequests;
      await clickMailButton(accountFrame, 'Rotate key');
      await waitKeyDialog(accountFrame, rotationDialog);
      assert.equal(keyMutationRequests, keyRequestsBeforeRotation,
        'opening Rotate confirmation must not rotate a key');
      await clickMailButton(accountFrame, 'Cancel', true, rotationDialog);
      await waitKeyDialogClosed(accountFrame, rotationDialog.title);
      assert.equal(keyMutationRequests, keyRequestsBeforeRotation,
        'Cancel must dispatch no Rotate mutation');
      assert.equal(JSON.stringify(await keyState()) === JSON.stringify(beforeRotation), true,
        'Cancel must leave the owner key version and digest unchanged');
      await clickMailButton(accountFrame, 'Rotate key');
      await waitKeyDialog(accountFrame, rotationDialog);
      const rotateResponse = page.waitForResponse(response => response.url() === `${keyEndpoint}/rotate`
        && response.request().method() === 'POST', { timeout: 20000 });
      await clickMailButton(accountFrame, 'Confirm rotation', true, rotationDialog);
      const rotatedHttp = await rotateResponse;
      assert.equal(rotatedHttp.status(), 200);
      assert.equal(keyMutationRequests, keyRequestsBeforeRotation + 1);
      const rotated = await rotatedHttp.json();
      assert.equal(rotated.ok, true); assert.equal(rotated.version, 2);
      const key2 = rotated.api_key;
      assert.equal(typeof key2 === 'string' && /^sk_ss_live_[a-f0-9]{32}$/.test(key2), true);
      assert.equal(key2 !== key1, true, 'rotation issues a distinct credential');
      assert.equal((await apiOrders(key1, oldCustomerLaunch.bearer)).status, 401,
        'the old API key is denied after rotation');
      const secondKeyOrders = await apiOrders(key2, oldCustomerLaunch.bearer);
      assert.equal(secondKeyOrders.status, 200);
      assert.ok(secondKeyOrders.body.orders.some(order => Number(order.id) === committed.orderId));
      assert.ok([200, 304].includes((await page.reload()).status()));
      let keyFrame = await stableFrame(page);
      await keyFrame.waitForFunction(name => document.querySelector('h1')?.textContent.trim() === 'Account'
        && !!document.querySelector('#ss-tab-apikeys')
        && [...document.querySelectorAll('strong')].some(node => node.textContent.trim() === name),
      { timeout: 20000 }, customerName);
      const retainedKeyResponse = page.waitForResponse(response => response.url() === keyEndpoint
        && response.request().method() === 'GET', { timeout: 20000 });
      await clickMailButton(keyFrame, 'API Keys');
      const retainedKeyHttp = await retainedKeyResponse;
      assert.equal(retainedKeyHttp.status(), 200);
      const retainedKey = await retainedKeyHttp.json();
      assert.equal(retainedKey.version, 2);
      assert.equal(retainedKey.api_key === key2, true, 'reload reads the current API key version');
      await keyFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === 'Reveal' && !button.disabled),
      { timeout: 20000 });
      await clickMailButton(keyFrame, 'Reveal');
      assert.equal(await keyFrame.evaluate(value => document.querySelector('input.ss-input[readonly]')?.value === value,
        key2), true);
      const keySiblingName = `api_peer_${suffix}`;
      const keySibling = await auth.register({ username: keySiblingName,
        email: `${keySiblingName}@example.invalid`, password, role: 'customer' });
      const keySiblingActor = await actor(keySibling.context);
      const keySiblingLaunch = await bootstrap(keySibling.context);
      assert.equal((await apiOrders(key2, keySiblingLaunch.bearer)).status, 401,
        'buyer key cannot be presented under a sibling launch');
      const siblingIssued = await composition.personaAuth.rotateApiKey({ scope: keySiblingActor.scope,
        shopPersona: keySiblingActor.persona,
        currentSessionId: keySiblingActor.personaSession.sessionId });
      assert.equal(siblingIssued.ok, true);
      assert.equal((await apiOrders(siblingIssued.api_key, keySiblingLaunch.bearer, committed.orderId)).status, 404,
        'sibling API key cannot read the buyer order');
      const siblingKeyOrders = await apiOrders(siblingIssued.api_key, keySiblingLaunch.bearer);
      assert.equal(siblingKeyOrders.status, 200);
      assert.deepEqual(siblingKeyOrders.body.orders, []);
      await clickMailButton(keyFrame, 'Hide');
      privateApiKeyVisible = false;
      status.apiKeyVersionedPrivate = true;

      const accountFrameForPassword = keyFrame;
      await clickMailButton(accountFrameForPassword, 'Security');
      await accountFrameForPassword.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === 'Change password'), { timeout: 20000 });
      await clickMailButton(accountFrameForPassword, 'Change password');
      await page.waitForSelector('#shop-current-password', { timeout: 20000 });
      assert.equal(new URL(page.url()).pathname, '/secureshop/password');
      const nextPassword = `${password}-updated`;
      await page.type('#shop-current-password', password);
      await page.type('#shop-new-password', nextPassword);
      await page.type('#shop-confirm-password', nextPassword);
      const passwordPostsBefore = apiStatuses.filter(row => row.path === '/api/secureshop/auth/password'
        && row.method === 'POST').length;
      const passwordResponse = page.waitForResponse(response => response.url() === `${origin}/api/secureshop/auth/password`
        && response.request().method() === 'POST', { timeout: 20000 });
      await clickMailButton(page, 'Update password');
      const passwordHttp = await passwordResponse;
      assert.equal(passwordHttp.status(), 200);
      assert.deepEqual(await passwordHttp.json(), { authenticated: false, passwordChanged: true });
      await page.waitForFunction(() => location.pathname === '/secureshop/login', { timeout: 20000 });
      assert.equal(apiStatuses.filter(row => row.path === '/api/secureshop/auth/password'
        && row.method === 'POST').length, passwordPostsBefore + 1);
      assert.equal(await auth.authenticate(oldCustomerCookie.value), null);
      assert.equal(await composition.launches.resolveCapability(oldCustomerLaunch.bearer), null);
      const oldPasswordLogin = await fetch(`${origin}/api/secureshop/auth/login`, { method: 'POST',
        headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ username: customerName, password }) });
      assert.equal(oldPasswordLogin.status, 401);
      const newPasswordLogin = await fetch(`${origin}/api/secureshop/auth/login`, { method: 'POST',
        headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ username: customerName, password: nextPassword }) });
      assert.equal(newPasswordLogin.status, 200);
      const changedCustomer = await newPasswordLogin.json();
      assert.equal(changedCustomer.user.id, buyerBase.shopUserId);
      const changedCookie = newPasswordLogin.headers.get('set-cookie')
        ?.match(/dvaia_shop_session=([^;]+)/)?.[1];
      assert.ok(changedCookie);
      await auth.logout(decodeURIComponent(changedCookie));
      assert.equal(JSON.stringify(await otherPrincipals()) === JSON.stringify(beforeSelfChange), true,
        'self-service password change leaves sibling, merchant and admin principal rows unchanged');
      status.customerSelfPasswordChanged = true;

      // A16: two simultaneously authorized cookies for one registered buyer
      // share the selected shop's cart and order state. Mutation replay remains
      // bound to the execution which admitted it; the other session uses the
      // historical receipt read path instead.
      stage = 'same-shopper-concurrent-sessions';
      modelCallsBeforeA16 = modelCalls;
      judgeCallsBeforeA16 = judgeCalls;
      const armedActor = async base => {
        const ready = await bootstrap(base);
        const scope = await composition.launches.resolveCapability(ready.bearer);
        const verified = await composition.personaAuth.authenticateBoundToken({ scope,
          token: ready.persona.token });
        return { ready, actor: { scope, persona: verified.user, personaSession: {
          sessionId: verified.sessionId, authorityVersion: verified.authorityVersion } } };
      };
      const parallelName = `parallel_${suffix}`;
      const sessionA = await auth.register({ username: parallelName,
        email: `${parallelName}@example.invalid`, password, role: 'customer' });
      const { ready: credentialsA, actor: actorA } = await armedActor(sessionA.context);
      const selectedA = await scenes.readExisting(actorA.scope);
      assert.ok(selectedA?.targetId);
      await composition.commerce.add({ ...actorA,
        productId: Number(stocked.product_id), quantity: 1 });
      contextB = await browser.createBrowserContext();
      const pageB = browserBoundary ? await browserBoundary.newPage(contextB) : await contextB.newPage();
      await pageB.setViewport({ width: 1280, height: 900 });
      if (browserAdmission) await browserAdmission.guardPageRequests(pageB, origin);
      pageB.on('response', response => {
        const url = new URL(response.url());
        if (url.origin === origin && url.pathname.startsWith('/api/secureshop/') && pageBApi.length < 32)
          pageBApi.push({ method: response.request().method(), path: url.pathname,
            status: response.status() });
      });
      let sessionBBoundHeaders = null;
      pageB.on('request', request => {
        if (request.method() !== 'GET' || new URL(request.url()).pathname !== '/api/secureshop/cart') return;
        const headers = request.headers();
        if (headers['x-dvaia-secureshop-launch'] && /^Bearer \S+$/.test(headers.authorization || '')) {
          sessionBBoundHeaders = { launch: headers['x-dvaia-secureshop-launch'],
            persona: headers.authorization.slice('Bearer '.length) };
        }
      });
      assert.ok([200, 304].includes((await pageB.goto(
        `${origin}/secureshop/login?next=%2Fsecureshop%2Fcart`)).status()));
      await pageB.waitForSelector('#ss-login-user');
      await pageB.type('#ss-login-user', parallelName);
      await pageB.type('#ss-login-pw', password);
      await pageB.click('button[type="submit"]');
      await stableFrame(pageB);
      await pageB.waitForFunction(() => location.pathname === '/secureshop/cart',
        { timeout: 20000 });
      const cookieB = (await pageB.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.ok(cookieB?.httpOnly && cookieB.value !== sessionA.token);
      const baseB = await auth.authenticate(cookieB.value);
      assert.ok(baseB);
      const cartB = await stableFrame(pageB);
      const parallelRow = `table[aria-label="Cart items"] a[href="/secureshop/product/${stocked.product_id}"]`;
      await cartB.waitForSelector(parallelRow, { timeout: 20000 });
      assert.ok(sessionBBoundHeaders, 'B’s rendered cart read used a real bound launch and persona');
      const scopeB = await composition.launches.resolveCapability(sessionBBoundHeaders.launch);
      const verifiedB = await composition.personaAuth.authenticateBoundToken({ scope: scopeB,
        token: sessionBBoundHeaders.persona });
      const actorB = { scope: scopeB, persona: verifiedB.user, personaSession: {
        sessionId: verifiedB.sessionId, authorityVersion: verifiedB.authorityVersion } };
      assert.equal(actorA.persona.id, actorB.persona.id);
      assert.notEqual(actorA.scope.platformSessionId, actorB.scope.platformSessionId);
      assert.notEqual(actorA.personaSession.sessionId, actorB.personaSession.sessionId);
      const selectedB = await scenes.readExisting(actorB.scope);
      assert.equal(selectedB.targetId, selectedA.targetId);
      assert.equal((await auth.authenticate(sessionA.token))?.shopUserId, actorA.persona.id);
      const sharedCart = await cartB.$eval(parallelRow, link => ({
        quantity: link.closest('tr')?.querySelector('input.ss-qty__val')?.value,
      }));
      assert.equal(sharedCart.quantity, '1', 'B renders A’s retained cart line');
      const currentCartB = await cartB.evaluate(async () => {
        const response = await fetch('/api/secureshop/cart');
        return { status: response.status, body: await response.json() };
      });
      assert.equal(currentCartB.status, 200);
      const lineB = currentCartB.body.items.find(item => item.product_id === Number(stocked.product_id));
      assert.ok(Number.isSafeInteger(lineB?.id) && lineB.id > 0);
      const updateB = await cartB.evaluate(async id => {
        const response = await fetch(`/api/secureshop/cart/${id}`, { method: 'PATCH',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({ quantity: 2 }) });
        return { status: response.status, body: await response.json() };
      }, lineB.id);
      assert.equal(updateB.status, 200);
      assert.equal(updateB.body.changes, 1);
      assert.equal((await composition.commerce.cart(actorA)).items.find(item =>
        item.product_id === Number(stocked.product_id))?.quantity, 2,
      'A reads B’s committed cart update while both sessions remain live');
      const parallelOperationId = randomUUID();
      const parallelIntent = { shipping_address: '16 Parallel Way', payment_method: 'test-card',
        operationId: parallelOperationId };
      const postAsB = body => cartB.evaluate(async input => {
        const response = await fetch('/api/secureshop/orders', { method: 'POST',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify(input) });
        return { status: response.status, body: await response.json() };
      }, body);
      const parallelCheckout = await postAsB(parallelIntent);
      assert.equal(parallelCheckout.status, 200);
      const parallelOrderId = parallelCheckout.body.order_id;
      assert.ok(Number.isSafeInteger(parallelOrderId) && parallelOrderId > 0);
      assert.deepEqual(await postAsB(parallelIntent), parallelCheckout,
        'same live B execution replays the exact committed checkout receipt');
      assert.equal((await postAsB({ ...parallelIntent, shipping_address: 'Changed intent' })).status, 409);
      const currentReceiptA = await fetch(`${origin}/api/secureshop/orders/operations/${parallelOperationId}`,
        { headers: { cookie: `dvaia_shop_session=${sessionA.token}`,
          'x-dvaia-secureshop-launch': credentialsA.bearer,
          authorization: `Bearer ${credentialsA.persona.token}` } });
      assert.equal(currentReceiptA.status, 200, 'A is still authorized before its logout');
      assert.equal((await currentReceiptA.json()).order.id, parallelOrderId);
      const replayFromA = await fetch(`${origin}/api/secureshop/orders`, { method: 'POST',
        headers: { origin, cookie: `dvaia_shop_session=${sessionA.token}`,
          'x-dvaia-secureshop-launch': credentialsA.bearer,
          authorization: `Bearer ${credentialsA.persona.token}`,
          'content-type': 'application/json' }, body: JSON.stringify(parallelIntent) });
      assert.equal(replayFromA.status, 409,
        'A cannot use B’s operation ID as a mutation replay even for the same shopper');
      assert.equal((await composition.commerce.order({ ...actorA, orderId: parallelOrderId }))?.order.id,
        parallelOrderId, 'A reads B’s retained order through the same selected scene');
      assert.equal((await composition.commerce.checkoutHistory(actorA)).operations
        .filter(row => row.operationId === parallelOperationId).length, 1);
      const parallelCounts = (await review.query(`SELECT
        (SELECT count(*)::int FROM secureshop_review.product_target_orders
          WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3) AS orders,
        (SELECT count(*)::int FROM secureshop_review.bound_commerce_operations
          WHERE target_id=$1 AND shop_user_id=$2 AND operation_id=$4 AND state='completed') AS receipts`,
      [selectedA.targetId, actorA.persona.id, parallelOrderId, parallelOperationId])).rows[0];
      assert.deepEqual(parallelCounts, { orders: 1, receipts: 1 });
      assert.ok([200, 304].includes((await pageB.goto(`${origin}/secureshop/orders`)).status()));
      const ordersB = await stableFrame(pageB);
      await ordersB.waitForFunction(orderId => [...document.querySelectorAll('table[aria-label="Orders list"] tbody tr')]
        .some(row => row.querySelector('td')?.textContent.trim() === `#${orderId}`),
      { timeout: 20000 }, parallelOrderId);
      await auth.logout(sessionA.token);
      assert.equal(await auth.authenticate(sessionA.token), null);
      await assert.rejects(composition.commerce.cart(actorA));
      const deniedA = await fetch(`${origin}/api/secureshop/orders/operations/${parallelOperationId}`,
        { headers: { cookie: `dvaia_shop_session=${sessionA.token}`,
          'x-dvaia-secureshop-launch': credentialsA.bearer,
          authorization: `Bearer ${credentialsA.persona.token}` } });
      assert.equal(deniedA.status, 401);
      const retainedB = await ordersB.evaluate(async operationId => {
        const response = await fetch(`/api/secureshop/orders/operations/${operationId}`);
        return { status: response.status, body: await response.json() };
      }, parallelOperationId);
      assert.equal(retainedB.status, 200);
      assert.equal(retainedB.body.order.id, parallelOrderId);
      const parallelSibling = await auth.register({ username: `parallel_peer_${suffix}`,
        email: `parallel_peer_${suffix}@example.invalid`, password, role: 'customer' });
      const { ready: parallelSiblingCredentials, actor: actorSibling } =
        await armedActor(parallelSibling.context);
      assert.deepEqual((await composition.commerce.cart(actorSibling)).items, []);
      assert.deepEqual(await composition.commerce.orders(actorSibling), []);
      const siblingReceipt = await fetch(`${origin}/api/secureshop/orders/operations/${parallelOperationId}`,
        { headers: { cookie: `dvaia_shop_session=${parallelSibling.token}`,
          'x-dvaia-secureshop-launch': parallelSiblingCredentials.bearer,
          authorization: `Bearer ${parallelSiblingCredentials.persona.token}` } });
      assert.equal(siblingReceipt.status, 404);
      const replayFromSibling = await fetch(`${origin}/api/secureshop/orders`, { method: 'POST',
        headers: { origin, cookie: `dvaia_shop_session=${parallelSibling.token}`,
          'x-dvaia-secureshop-launch': parallelSiblingCredentials.bearer,
          authorization: `Bearer ${parallelSiblingCredentials.persona.token}`,
          'content-type': 'application/json' }, body: JSON.stringify(parallelIntent) });
      assert.equal(replayFromSibling.status, 409);
      assert.deepEqual((await review.query(`SELECT
        (SELECT count(*)::int FROM secureshop_review.product_target_orders
          WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3) AS orders,
        (SELECT count(*)::int FROM secureshop_review.bound_commerce_operations
          WHERE target_id=$1 AND shop_user_id=$2 AND operation_id=$4 AND state='completed') AS receipts`,
      [selectedA.targetId, actorA.persona.id, parallelOrderId, parallelOperationId])).rows[0],
      { orders: 1, receipts: 1 }, 'denied replays did not alter the committed effect');
      assert.equal((await auth.authenticate(cookieB.value))?.shopUserId, actorB.persona.id);
      await contextB.close();
      contextB = null;
      status.sameShopperConcurrentSessionsRetained = true;

      assert.equal(apiStatuses.filter(row => row.path.includes('/email/')
        && (/assessment$/.test(row.path) || row.path.includes('/auto-reply/'))).length, 0,
      'manual Compose never invokes autoreply or objective grading');
      assert.equal(judgeCallsBeforeA16, 0,
        `Judge calls before A16: ${judgeCallsBeforeA16}`);
      assert.equal(judgeCalls - judgeCallsBeforeA16, 0,
        `Judge calls during A16: ${judgeCalls - judgeCallsBeforeA16}; B API: ${JSON.stringify(pageBApi)}`);
      assert.equal(modelCallsBeforeA16, 2,
        `unavailable provider attempts before A16: ${JSON.stringify(providerCalls)}`);
      assert.equal(modelCalls - modelCallsBeforeA16, 0,
        `unavailable provider attempts during A16: ${JSON.stringify(providerCalls)}; B API: ${JSON.stringify(pageBApi)}`);
      assert.deepEqual(providerCalls.map(call => [call.method, call.stage]),
        [['chat', 'a08-customer-buttons'], ['chat', 'a08-customer-buttons']],
        'no other fixture flow invoked the unavailable provider');
      status.unavailableProviderAttempts = modelCalls;
      // This cohort supplies only the throwing unavailable provider. It has no
      // configured transport and no response capable of establishing model provenance.
      status.actualModelCalls = 0;
      status.noModelCalls = true;
      // Product's saved summary operation is a real reason to deny a practice
      // switch. Exercise that guard without clearing the reference or using
      // this customer's browser storage for the separate A18 recovery matrix.
      stage = 'a18-product-saved-operation-guard';
      const shopStateNames = await import('../../client/src/pages/secureshop/utils/shopStorage.mjs');
      const allowedSnapshotFields = Object.entries(shopStateNames)
        .filter(([name, value]) => /^SHOP_[A-Z_]+_KEY$/.test(name) && typeof value === 'string')
        .map(([, value]) => value);
      const guardName = `practice_product_${suffix}`;
      await auth.register({ username: guardName,
        email: `${guardName}@example.invalid`, password, role: 'customer' });
      contextA18Product = await browser.createBrowserContext();
      const productPage = browserBoundary
        ? await browserBoundary.newPage(contextA18Product) : await contextA18Product.newPage();
      await productPage.setViewport({ width: 1280, height: 900 });
      if (browserAdmission) await browserAdmission.guardPageRequests(productPage, origin);
      const guardProductReads = [];
      productPage.on('request', request => {
        const route = new URL(request.url());
        if (route.origin === origin && /^\/api\/secureshop\/products\/\d+\/(?:summary|similar)$/.test(route.pathname))
          guardProductReads.push({ method: request.method(), path: route.pathname });
      });
      assert.ok([200, 304].includes((await productPage.goto(`${origin}/secureshop/login?next=%2Fsecureshop`)).status()));
      await productPage.waitForSelector('#ss-login-user');
      await productPage.type('#ss-login-user', guardName);
      await productPage.type('#ss-login-pw', password);
      await productPage.click('button[type="submit"]');
      await productPage.waitForFunction(() => document.querySelector('iframe[title="SecureShop"]')
        || [...document.querySelectorAll('h1')].some(node => node.textContent.trim() === 'Choose a shop practice.'),
      { timeout: 20000 });
      if (await productPage.$('main button strong')) {
        const initialChoice = (await productPage.$$('main button'))[0];
        assert.ok(initialChoice, 'Product guard customer can choose the existing scene');
        const initialSelection = productPage.waitForResponse(value => new URL(value.url()).pathname
          === '/api/secureshop/v2/scenes/select' && value.request().method() === 'POST', { timeout: 20000 })
          .then(value => ({ value }), error => ({ error }));
        await initialChoice.click();
        const settled = await initialSelection;
        if (settled.error) throw settled.error;
        assert.equal(settled.value.status(), 200);
      }
      await stableFrame(productPage);
      const guardCookie = (await productPage.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.ok(guardCookie?.httpOnly && guardCookie.value);
      const guardBase = await auth.authenticate(guardCookie.value);
      assert.ok(guardBase?.principalId);
      const guardBootstrap = await bootstrap(guardBase);
      const guardScope = await composition.launches.resolveCapability(guardBootstrap.bearer);
      const guardPractice = (await scenes.list(guardScope)).find(row => row.isDefault);
      const guardTarget = await scenes.readExisting(guardScope);
      assert.ok(guardPractice?.id && guardTarget?.targetId);
      const guardProduct = (await review.query(`SELECT product_id FROM secureshop_review.product_target_products
        WHERE target_id=$1 AND status='active' AND stock_quantity>0 ORDER BY product_id LIMIT 1`,
      [guardTarget.targetId])).rows[0];
      assert.ok(Number(guardProduct?.product_id) > 0);
      assert.ok([200, 304].includes((await productPage.goto(`${origin}/secureshop/product/${guardProduct.product_id}`)).status()));
      const guardFrame = await stableFrame(productPage);
      await guardFrame.waitForFunction(() => [...document.querySelectorAll('button')]
        .some(button => button.textContent.trim() === 'Add to cart' && !button.disabled), { timeout: 20000 });
      const guardAdd = await (async () => {
        for (const button of await guardFrame.$$('button')) {
          if (await button.evaluate(node => node.textContent.trim() === 'Add to cart' && !node.disabled)) return button;
        }
        return null;
      })();
      assert.ok(guardAdd);
      await guardAdd.click();
      await guardFrame.click('a[href="/secureshop/cart"]');
      const guardCartLine = `table[aria-label="Cart items"] a[href="/secureshop/product/${guardProduct.product_id}"]`;
      await guardFrame.waitForSelector(guardCartLine, { timeout: 20000 });
      assert.equal(await guardFrame.$eval(guardCartLine,
        link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1');
      const guardSnapshotInput = {
        scopeKey: `dvaia:secureshop:${guardBootstrap.launch.launchId.toLowerCase()}:${guardBootstrap.launch.generation}`,
        sceneId: guardPractice.id.toLowerCase(), allowedFields: allowedSnapshotFields,
        summaryKey: shopStateNames.SHOP_PRODUCT_SUMMARY_KEY,
      };
      const guardSnapshot = await workStep('a18-product-reference', async () => {
        const referenceDeadline = Date.now() + 19000;
        while (Date.now() < referenceDeadline) {
          const value = await productPage.evaluate(practiceSnapshotMetadata, guardSnapshotInput);
          if (value.summaryRefPresent && value.summaryRefParseable && value.summaryRefHasEntries) return value;
          await sleep(50);
        }
        throw new Error('Product saved summary operation unavailable before practice guard');
      });
      assert.ok(guardSnapshot.summaryRefEntryCount > 0, 'Product created one or more retained summary operations');
      assert.ok(guardProductReads.some(row => row.method === 'POST'
        && row.path === `/api/secureshop/products/${guardProduct.product_id}/summary`),
      'the retained Product reference follows its real summary request');
      const guardReferenceHandle = await productPage.evaluateHandle(practiceSummaryReference, guardSnapshotInput);
      const guardReferenceKey = `dvaia:secureshop:practice-admission:v1:${guardBase.principalId.toLowerCase()}`;
      try {
        assert.equal(await productPage.evaluate(key => localStorage.getItem(key), guardReferenceKey), null);
        const guardPostsBefore = practiceTraffic.filter(row => row.method === 'POST').length;
        if (!await productPage.$('#secureshop-settings'))
          await productPage.click('button[aria-controls="secureshop-settings"]');
        const guardNewPractice = await (async () => {
          for (const button of await productPage.$$('#secureshop-settings section[aria-label="Retained shop practices"] button')) {
            if (await button.evaluate(node => node.textContent.trim()) === 'New practice') return button;
          }
          return null;
        })();
        assert.ok(guardNewPractice && await guardNewPractice.evaluate(node => !node.disabled));
        await guardNewPractice.click();
        await productPage.waitForFunction(() => document.querySelector(
          '#secureshop-settings section[aria-label="Retained shop practices"] [role="alert"]')
          ?.textContent.includes('Check saved operation status before choosing another practice.'),
        { timeout: 20000 });
        assert.equal(practiceTraffic.filter(row => row.method === 'POST').length, guardPostsBefore,
          'Product saved-operation guard denies the switch before any practice POST');
        assert.equal(await productPage.evaluate(key => localStorage.getItem(key), guardReferenceKey), null);
        assert.equal((await scenes.list(guardScope)).find(row => row.isDefault)?.id, guardPractice.id);
        assert.equal((await scenes.readExisting(guardScope)).targetId, guardTarget.targetId);
        assert.equal(await guardFrame.$eval(guardCartLine,
          link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1',
        'denied Product switch preserves the original UI-written cart');
        assert.equal(await productPage.evaluate(practiceSummaryReference, guardSnapshotInput, guardReferenceHandle), true,
          'the exact saved Product operation reference remains unchanged after denial');
      } finally { await guardReferenceHandle.dispose(); }
      await contextA18Product.close(); contextA18Product = null;

      // A18's fault, recovery and cart-isolation matrix uses a separate clean
      // customer and physical Catalog Add, with no Product-page operation ref.
      // The original work and test deadlines remain unchanged.
      stage = 'a18-new-practice';
      const practiceName = `practice_${suffix}`;
      await auth.register({ username: practiceName,
        email: `${practiceName}@example.invalid`, password, role: 'customer' });
      contextA18 = await browser.createBrowserContext();
      const practicePage = pageA18 = browserBoundary
        ? await browserBoundary.newPage(contextA18) : await contextA18.newPage();
      await practicePage.setViewport({ width: 1280, height: 900 });
      if (browserAdmission) await browserAdmission.guardPageRequests(practicePage, origin);
      const practiceRequests = [];
      const practiceProductReads = [];
      practicePage.on('request', request => {
        const route = new URL(request.url());
        if (route.origin === origin && route.pathname.startsWith('/api/secureshop/auth/practices'))
          practiceRequests.push({ method: request.method(), path: route.pathname });
        if (route.origin === origin && /^\/api\/secureshop\/products\/\d+\/(?:summary|similar)$/.test(route.pathname))
          practiceProductReads.push({ method: request.method(), path: route.pathname });
      });
      assert.ok([200, 304].includes((await practicePage.goto(`${origin}/secureshop/login?next=%2Fsecureshop`)).status()));
      await practicePage.waitForSelector('#ss-login-user');
      await practicePage.type('#ss-login-user', practiceName);
      await practicePage.type('#ss-login-pw', password);
      await practicePage.click('button[type="submit"]');
      await practicePage.waitForFunction(() => document.querySelector('iframe[title="SecureShop"]')
        || [...document.querySelectorAll('h1')].some(node => node.textContent.trim() === 'Choose a shop practice.'),
      { timeout: 20000 });
      if (await practicePage.$('main button strong')) {
        const initialChoice = (await practicePage.$$('main button'))[0];
        assert.ok(initialChoice, 'fresh customer can choose an existing scene');
        const initialSelection = practicePage.waitForResponse(value => new URL(value.url()).pathname
          === '/api/secureshop/v2/scenes/select' && value.request().method() === 'POST', { timeout: 20000 })
          .then(value => ({ value }), error => ({ error }));
        await initialChoice.click();
        const settled = await initialSelection;
        if (settled.error) throw settled.error;
        assert.equal(settled.value.status(), 200);
      }
      await stableFrame(practicePage);
      const practiceCookie = (await practicePage.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session');
      assert.ok(practiceCookie?.httpOnly && practiceCookie.value);
      const practiceBase = await auth.authenticate(practiceCookie.value);
      assert.ok(practiceBase?.principalId);
      const referenceKey = `dvaia:secureshop:practice-admission:v1:${practiceBase.principalId.toLowerCase()}`;
      const beforePractice = await bootstrap(practiceBase);
      const beforePracticeScope = await composition.launches.resolveCapability(beforePractice.bearer);
      const beforePracticeScenes = await scenes.list(beforePracticeScope);
      const originalPractice = beforePracticeScenes.find(row => row.isDefault);
      assert.ok(originalPractice?.id, 'fresh customer has one selected original scene');
      const originalTarget = await scenes.readExisting(beforePracticeScope);
      assert.ok(originalTarget?.targetId);
      const originalProduct = (await review.query(`SELECT product_id,name FROM secureshop_review.product_target_products
        WHERE target_id=$1 AND status='active' AND stock_quantity>0 ORDER BY product_id LIMIT 1`,
      [originalTarget.targetId])).rows[0];
      assert.ok(Number(originalProduct?.product_id) > 0, 'selected original scene has a real in-stock product');
      const clickNewPractice = async () => {
        if (!await practicePage.$('#secureshop-settings'))
          await practicePage.click('button[aria-controls="secureshop-settings"]');
        const buttons = await practicePage.$$('#secureshop-settings section[aria-label="Retained shop practices"] button');
        const button = await (async () => {
          for (const candidate of buttons) {
            if (await candidate.evaluate(node => node.textContent.trim()) === 'New practice') return candidate;
          }
          return null;
        })();
        assert.ok(button && await button.evaluate(node => !node.disabled));
        await button.click();
      };
      const cartLine = `table[aria-label="Cart items"] a[href="/secureshop/product/${originalProduct.product_id}"]`;
      assert.ok([200, 304].includes((await practicePage.goto(`${origin}/secureshop/catalog?q=${encodeURIComponent(originalProduct.name)}`)).status()));
      const practiceCatalog = await stableFrame(practicePage);
      const catalogCard = `a[href="/secureshop/product/${originalProduct.product_id}"]`;
      await practiceCatalog.waitForSelector(`${catalogCard} button`, { timeout: 20000 });
      const catalogAdd = await practiceCatalog.$(`${catalogCard} button`);
      assert.ok(catalogAdd && await catalogAdd.evaluate(node => node.textContent.trim() === 'Add' && !node.disabled),
        'the clean customer sees the selected in-stock Catalog Add control');
      await (await practiceCatalog.$(catalogCard)).hover();
      await catalogAdd.click();
      await practiceCatalog.click('a[href="/secureshop/cart"]');
      await practiceCatalog.waitForSelector(cartLine, { timeout: 20000 });
      assert.equal(await practiceCatalog.$eval(cartLine,
        link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1',
      'the original cart line was added through the clean customer Catalog UI');
      assert.equal(practiceProductReads.length, 0, 'Catalog Add does not open Product summary or similar operations');
      assert.equal(await practicePage.evaluate(key => localStorage.getItem(key), referenceKey), null);

      // Controlled native-storage failure must keep the original frame and
      // never dispatch A18. It is restored before the real admission.
      const snapshotMetadata = await practicePage.evaluate(practiceSnapshotMetadata, {
        scopeKey: `dvaia:secureshop:${beforePractice.launch.launchId.toLowerCase()}:${beforePractice.launch.generation}`,
        sceneId: originalPractice.id.toLowerCase(), allowedFields: allowedSnapshotFields,
        summaryKey: shopStateNames.SHOP_PRODUCT_SUMMARY_KEY,
      });
      assert.equal(snapshotMetadata.summaryRefPresent, false,
        'the separately registered Catalog customer has no Product summary operation');
      assert.equal(snapshotMetadata.unknownNonNullField, false,
        'the clean customer has no unrecognized retained-reference field');
      console.log('A11 A18 pre-storage snapshot metadata', JSON.stringify({ ...snapshotMetadata,
        practicePostRequests: practiceRequests.filter(row => row.method === 'POST').length }));
      stage = 'a18-storage-failure';
      const postsBeforeStorageFailure = practiceTraffic.filter(row => row.method === 'POST').length;
      await practicePage.evaluate(() => {
        window.__practiceSetItem = Storage.prototype.setItem;
        Storage.prototype.setItem = function(key, value) {
          if (String(key).startsWith('dvaia:secureshop:practice-admission:v1:'))
            throw new DOMException('Controlled parent storage denial', 'SecurityError');
          return window.__practiceSetItem.call(this, key, value);
        };
      });
      try {
        await clickNewPractice();
        await practicePage.waitForFunction(() => document.querySelector(
          '#secureshop-settings section[aria-label="Retained shop practices"] [role="alert"]')
          ?.textContent.includes('Controlled parent storage denial'), { timeout: 20000 });
        assert.equal(practiceTraffic.filter(row => row.method === 'POST').length, postsBeforeStorageFailure);
        assert.equal(await practicePage.evaluate(key => localStorage.getItem(key), referenceKey), null);
        assert.equal((await scenes.list(beforePracticeScope)).find(row => row.isDefault)?.id, originalPractice.id);
        const restoredFrame = await stableFrame(practicePage);
        await restoredFrame.waitForSelector('a[href="/secureshop/cart"]', { timeout: 20000 });
        await restoredFrame.click('a[href="/secureshop/cart"]');
        await restoredFrame.waitForSelector(cartLine, { timeout: 20000 });
        assert.equal(await restoredFrame.$eval(cartLine,
          link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1',
        'storage refusal retains the UI-written cart in the original scene');
        status.renderedNewPracticeStorageFailure = true;
      } finally {
        await practicePage.evaluate(() => {
          if (window.__practiceSetItem) Storage.prototype.setItem = window.__practiceSetItem;
          delete window.__practiceSetItem;
        });
      }
      assert.ok([200, 304].includes((await practicePage.reload()).status()));
      const reloadedOriginalFrame = await stableFrame(practicePage);
      await reloadedOriginalFrame.waitForSelector('a[href="/secureshop/cart"]', { timeout: 20000 });
      if (!await reloadedOriginalFrame.$(cartLine))
        await reloadedOriginalFrame.click('a[href="/secureshop/cart"]');
      await reloadedOriginalFrame.waitForSelector(cartLine, { timeout: 20000 });
      assert.equal(await reloadedOriginalFrame.$eval(cartLine,
        link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1',
      'reload and the rendered Cart link recover the unchanged old-scene cart');

      // A real capacity-shaped 409 is injected at the route service boundary;
      // the separate native cohort proves physical 256-resource admission.
      stage = 'a18-controlled-capacity';
      denyNextPracticeForCapacity = true;
      const capacityPostBefore = practiceTraffic.filter(row => row.method === 'POST').length;
      const capacityResponse = practicePage.waitForResponse(value => new URL(value.url()).pathname
        === '/api/secureshop/auth/practices' && value.request().method() === 'POST', { timeout: 20000 })
        .then(value => ({ value }), error => ({ error }));
      await clickNewPractice();
      const capacitySettled = await capacityResponse;
      if (capacitySettled.error) throw capacitySettled.error;
      assert.equal(capacitySettled.value.status(), 409, 'the controlled fault uses the real auth route');
      const capacityBody = await capacitySettled.value.json();
      assert.equal(capacityBody.code, 'SHOP_PRACTICE_CAPACITY');
      assert.equal(capacityBody.operationId,
        JSON.parse(capacitySettled.value.request().postData()).operationId);
      await practicePage.waitForFunction(() => document.querySelector(
        '#secureshop-settings section[aria-label="Retained shop practices"] [role="alert"]')
        ?.textContent.includes('Practice capacity is full'), { timeout: 20000 });
      assert.equal(denyNextPracticeForCapacity, false);
      assert.equal(practiceTraffic.filter(row => row.method === 'POST').length, capacityPostBefore + 1);
      assert.equal(await practicePage.evaluate(key => localStorage.getItem(key), referenceKey), null,
        'exact preclaim reference clears after the confirmed 409');
      assert.equal((await scenes.list(beforePracticeScope)).find(row => row.isDefault)?.id, originalPractice.id);
      const capacityFrame = await stableFrame(practicePage);
      await capacityFrame.waitForSelector('a[href="/secureshop/cart"]', { timeout: 20000 });
      await capacityFrame.click('a[href="/secureshop/cart"]');
      await capacityFrame.waitForSelector(cartLine, { timeout: 20000 });
      assert.equal(await capacityFrame.$eval(cartLine,
        link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1',
      'confirmed capacity refusal preserves the original UI-written cart');
      status.renderedNewPracticeCapacityGuidance = true;

      stage = 'a18-published-ack-loss';
      const practiceEndpoint = `${origin}/api/secureshop/auth/practices`;
      const publishedLoss = await dropOnePublishedPracticeResponse(practicePage, practiceEndpoint, referenceKey);
      let published;
      try {
        await clickNewPractice();
        published = await publishedLoss.wait();
        await practicePage.waitForFunction(() => [...document.querySelectorAll('h1')]
          .some(node => node.textContent.trim() === 'Check a saved new practice.'), { timeout: 20000 });
      } finally { await publishedLoss.close(); }
      assert.deepEqual(JSON.parse(await practicePage.evaluate(key => localStorage.getItem(key), referenceKey)),
        { version: 1, operationId: published.request.operationId });
      assert.equal((await practicePage.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session')?.value, practiceCookie.value);
      assert.equal(practiceTraffic.filter(row => row.method === 'POST').length, capacityPostBefore + 2,
        'only the controlled 409 and one committed publication were posted');
      status.renderedNewPracticeSameCookie = true;

      stage = 'a18-exact-get-recovery';
      const beforeRecovery = practiceRequests.length;
      const exactRecoveryPath = `/api/secureshop/auth/practices/${published.request.operationId}`;
      const recoveryResponse = practicePage.waitForResponse(value => new URL(value.url()).pathname
        === exactRecoveryPath && value.request().method() === 'GET' && value.status() === 200,
      { timeout: 20000 }).then(value => ({ value }), error => ({ error }));
      assert.ok([200, 304].includes((await practicePage.reload()).status()));
      const recoverySettled = await recoveryResponse;
      if (recoverySettled.error) throw recoverySettled.error;
      assert.deepEqual(await recoverySettled.value.json(), published.result,
        'exact GET reads the published journal result without a replacement POST');
      await stableFrame(practicePage);
      await practicePage.waitForFunction(key => localStorage.getItem(key) === null,
        { timeout: 20000 }, referenceKey);
      const recoveryRequests = practiceRequests.slice(beforeRecovery);
      const recoveryGets = recoveryRequests.filter(row => row.method === 'GET'
        && row.path.startsWith('/api/secureshop/auth/practices/'));
      assert.ok(recoveryGets.length >= 1, 'reload checks the saved practice');
      assert.ok(recoveryGets.every(row => row.path === exactRecoveryPath),
      'every recovery read uses only the exact persisted UUID');
      assert.equal(recoveryRequests.filter(row => row.method === 'POST'
        && row.path === '/api/secureshop/auth/practices').length, 0);
      assert.equal(await practicePage.evaluate(key => localStorage.getItem(key), referenceKey), null);
      const afterPractice = await bootstrap(practiceBase);
      const afterPracticeScope = await composition.launches.resolveCapability(afterPractice.bearer);
      const afterScenes = await scenes.list(afterPracticeScope);
      assert.notEqual(afterPractice.launch.launchId, beforePractice.launch.launchId);
      assert.notEqual(afterPracticeScope.platformSessionId, beforePracticeScope.platformSessionId);
      assert.equal(afterScenes.find(row => row.isDefault)?.id, published.result.sceneId);
      assert.ok(afterScenes.some(row => row.id === originalPractice.id), 'the prior scene remains owned');
      assert.ok(beforePracticeScenes.every(row => afterScenes.some(retained => retained.id === row.id)),
        'admission retains every pre-existing owned scene');
      assert.equal((await identity.query(`SELECT count(*)::int AS n FROM identity.secureshop_scenes
        WHERE scene_id=ANY($1::uuid[]) AND status='active'`,
      [[retainedSceneA.id, retainedSceneB.id]])).rows[0].n, 2,
      'the earlier buyer and sibling practice scenes remain active');
      assert.equal((await identity.query(`SELECT count(*)::int AS n FROM secureshop_auth.practice_publications
        WHERE operation_id=$1 AND scene_id=$2`, [published.request.operationId, published.result.sceneId])).rows[0].n, 1);
      assert.ok(practiceTraffic.filter(row => row.method === 'POST').every(row => row.cookie
        && row.authorization === null && row.launch === null), 'A18 mutation uses only the shop cookie');
      assert.ok(practiceTraffic.filter(row => row.method === 'GET').every(row => row.cookie
        && row.authorization === null && row.launch === null), 'A18 recovery uses only the shop cookie');
      assert.equal(await practicePage.evaluate(() => document.body.textContent.includes('Loading Workshop')), false);
      status.renderedNewPracticeExactRecovery = true;

      stage = 'a18-cart-isolation';
      assert.ok([200, 304].includes((await practicePage.goto(`${origin}/secureshop/cart`)).status()));
      const newCart = await stableFrame(practicePage);
      await newCart.waitForFunction(() => document.body.textContent.includes('Your cart is empty'), { timeout: 20000 });
      assert.equal(await newCart.$(cartLine), null, 'new execution does not inherit the old local cart');
      await practicePage.click('button[aria-controls="secureshop-settings"]');
      await practicePage.click('#secureshop-settings section[aria-label="Retained shop practices"] button');
      await practicePage.waitForFunction(() => [...document.querySelectorAll('h1')]
        .some(node => node.textContent.trim() === 'Choose a shop practice.'), { timeout: 20000 });
      const oldChoice = await (async () => {
        for (const button of await practicePage.$$('main button')) {
          if (await button.$eval('strong', node => node.textContent.trim()).catch(() => null) === originalPractice.label)
            return button;
        }
        return null;
      })();
      assert.ok(oldChoice, 'the original scene appears in the physical retained chooser');
      const oldSelection = practicePage.waitForResponse(value => new URL(value.url()).pathname
        === '/api/secureshop/v2/scenes/select' && value.request().method() === 'POST', { timeout: 20000 })
        .then(value => ({ value }), error => ({ error }));
      await oldChoice.click();
      const oldSelected = await oldSelection;
      if (oldSelected.error) throw oldSelected.error;
      assert.equal(oldSelected.value.status(), 200);
      assert.deepEqual(JSON.parse(oldSelected.value.request().postData()), { sceneId: originalPractice.id });
      await stableFrame(practicePage);
      assert.equal((await scenes.list(afterPracticeScope)).find(row => row.isDefault)?.id, originalPractice.id);
      assert.ok([200, 304].includes((await practicePage.goto(`${origin}/secureshop/cart`)).status()));
      await (await stableFrame(practicePage)).waitForSelector(cartLine, { timeout: 20000 });
      assert.equal(await (await stableFrame(practicePage)).$eval(cartLine,
        link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1');
      assert.ok([200, 304].includes((await practicePage.reload()).status()));
      await (await stableFrame(practicePage)).waitForSelector(cartLine, { timeout: 20000 });
      assert.equal(await (await stableFrame(practicePage)).$eval(cartLine,
        link => link.closest('tr')?.querySelector('input.ss-qty__val')?.value), '1',
      'returning to the prior scene and reloading preserves the UI-written cart');
      assert.equal((await practicePage.cookies(`${origin}/api/secureshop/auth/session`))
        .find(value => value.name === 'dvaia_shop_session')?.value, practiceCookie.value);
      assert.equal((await scenes.readExisting(afterPracticeScope)).targetId, originalTarget.targetId,
        'the returned scene resolves the original product target under current authority');
      assert.equal((await identity.query(`SELECT product_target_id FROM identity.secureshop_scenes
        WHERE scene_id=$1 AND status='active'`, [originalPractice.id])).rows[0]?.product_target_id,
      originalTarget.targetId, 'the prior scene birth target remains unchanged');
      status.renderedNewPracticeCartIsolation = true;
      const expectedProductReads = [
        { method: 'POST', path: `/api/secureshop/products/${guardProduct.product_id}/summary` },
        { method: 'GET', path: `/api/secureshop/products/${guardProduct.product_id}/similar` },
      ];
      assert.ok(guardProductReads.every(read => expectedProductReads.some(expected =>
        expected.method === read.method && expected.path === read.path)),
      `A18 Product guard only dispatched its exact automatic reads: ${JSON.stringify(guardProductReads)}`);
      assert.equal(practiceProductReads.length, 0, 'clean Catalog customer did not open Product');
      const a18ProviderCalls = providerCalls.slice(status.unavailableProviderAttempts);
      assert.equal(providerCalls.length, modelCalls, 'all unavailable-provider attempts have captured source evidence');
      assert.ok(a18ProviderCalls.every(call => call.method === 'chat'
        && call.callers.some(frame => frame.includes('secureshopBoundProductAssist.js'))),
      `A18 provider attempts must come only from the Product graph: ${JSON.stringify(a18ProviderCalls)}`);
      assert.ok(a18ProviderCalls.length <= guardProductReads.length,
      `A18 Product graph attempts need exact rendered requests: ${JSON.stringify({ a18ProviderCalls, guardProductReads })}`);
      status.unavailableProviderAttempts = modelCalls;
      status.unavailableProviderAccounting = {
        version: 1,
        baselineAuthenticatedProductAttempts: 2,
        productAutomaticRenderedReadRequests: guardProductReads.length,
        productAutomaticAssistAttempts: a18ProviderCalls.length,
        productAutomaticAssistSource: 'secureshopBoundProductAssist',
      };
      await contextA18.close(); contextA18 = null;
      if (externalPolicyRenderer) await externalPolicyRenderer.check();
      if (browserAdmission) await browserAdmission.verifyBuild();
      if (browserBoundary) browserBoundary.assertNoUnexpectedTargets();
      assert.equal(judgeCalls, 0, 'whole commerce cohort must not invoke a Judge');
      status.passed = true;
    } catch (error) {
      failure = error;
      console.log('A11 failed', JSON.stringify({ stage, code: error.code || error.name,
        step: error.step || null }));
      if (page && !page.isClosed()) {
        const safe = { stage, apiStatuses: apiStatuses.slice(-16) };
        if (sceneChooserDiagnostic) safe.sceneChooserDiagnostic = sceneChooserDiagnostic;
        try {
          if (pageA18 && !pageA18.isClosed() && stage.startsWith('a18-')) {
            safe.practice = await boundedA11('failure-practice-diagnostic', () => pageA18.evaluate(() => ({ route: location.pathname,
              heading: document.querySelector('h1')?.textContent.trim().slice(0, 100) || null,
              alerts: [...document.querySelectorAll('[role="alert"],[role="status"]')]
                .map(node => node.textContent.trim().slice(0, 120)).slice(0, 4),
              frameTitles: [...document.querySelectorAll('iframe')].map(frame => frame.title).slice(0, 3),
            })), 3000);
          }
          safe.parent = await boundedA11('failure-parent-diagnostic', () => page.evaluate(() => ({ route: location.pathname,
            headings: [...document.querySelectorAll('h1,h2')].map(node => node.textContent.trim().slice(0, 80)).slice(0, 6),
            alerts: [...document.querySelectorAll('[role="alert"],[role="status"]')]
              .map(node => node.textContent.trim().slice(0, 120)).slice(0, 5),
          })), 3000);
          const frame = page.frames().find(value => value.url().includes('/secureshop-frame.html'));
          safe.frame = frame && await boundedA11('failure-frame-diagnostic', () => frame.evaluate(() => {
            const link = document.querySelector('a[href="/secureshop/checkout"]');
            const rect = link?.getBoundingClientRect();
            const hit = rect && document.elementFromPoint(rect.left + rect.width / 2,
              rect.top + rect.height / 2);
            return { route: location.pathname,
              headings: [...document.querySelectorAll('h1,h2')].map(node => node.textContent.trim().slice(0, 80)).slice(0, 6),
              buttons: [...document.querySelectorAll('button')].map(node => node.textContent.trim().slice(0, 60)).filter(Boolean).slice(0, 12),
              alerts: [...document.querySelectorAll('[role="alert"],[role="status"]')]
                .map(node => node.textContent.trim().slice(0, 120)).slice(0, 5),
              checkoutLink: link ? { targetable: link.contains(hit), hit: hit?.tagName || null,
                y: Math.round(rect.top + rect.height / 2) } : null };
          }), 3000);
          if (!privateResetRevealPending && !privateApiKeyVisible
            && !await page.$('output[aria-label="Temporary password"]')) {
            const screenshotPath = receiptPath.replace(/\.json$/i, '') + '-failure.png';
            await boundedA11('failure-screenshot', async () => fs.writeFile(screenshotPath,
              await page.screenshot(), { flag: 'wx', mode: 0o600 }), 5000);
            safe.screenshot = screenshotPath;
          } else safe.screenshot = 'withheld: private reset recovery is open';
        } catch (diagnosticError) { safe.diagnosticError = diagnosticError.name; }
        failure = Object.assign(new Error(`${error.message}; browser state: ${JSON.stringify(safe)}`),
          { code: error.code, cause: error });
        if (typeof error.stack === 'string') failure.stack =
          `${error.stack}\nBrowser state: ${JSON.stringify(safe)}`;
      }
    }
    finally {
      externalMailAbort.abort();
      readinessObserver.stop();
      clearTimeout(workWatchdog);
      console.log('A11 cleanup start', stage);
      const cleanupDeadline = Date.now() + 24000;
      let browserCloseFailed = false;
      const closes = [
        ['a18-context', () => contextA18?.close()], ['a18-product-context', () => contextA18Product?.close()],
        ['secondary-context', () => contextB?.close()],
        ['browser', () => browser?.close()], ['http-server', () => closeServer(server)],
        ['mail-production', () => mailProduction?.close()],
        ['browser-assessment', () => composition?.closeBrowserAssessment()],
        ['browser-profile', () => {
          if (browserCloseFailed) throw Object.assign(new Error('Browser close was not verified'),
            { code: 'A11_BROWSER_CLOSE_UNVERIFIED' });
          if (browserAdmission) return; // Independently captured launcher retires this exact owned profile.
          return profile && fs.rm(profile, { recursive: true, force: true });
        }],
        ['reset-key-directory', () => resetKeyDirectory && fs.rm(resetKeyDirectory, { recursive: true, force: true })],
        ['lease-pool', () => leasePool.end()],
        ...Object.entries(pools).map(([name, pool]) => [`pool-${name.toLowerCase()}`, () => pool.end()]),
      ];
      for (const [label, close] of closes) {
        const remaining = cleanupDeadline - Date.now();
        if (remaining <= 0) { cleanupErrors.push(Object.assign(new Error(`A11 cleanup deadline at ${label}`),
          { code: 'A11_CLEANUP_DEADLINE', step: label })); break; }
        console.log('A11 cleanup', label);
        try { await boundedA11(`cleanup-${label}`, close, Math.min(3000, remaining)); }
        catch (error) {
          if (label === 'browser') browserCloseFailed = true;
          cleanupErrors.push(error);
          console.log('A11 cleanup failed', JSON.stringify({ step: label, code: error.code || error.name }));
        }
      }
      if (cleanupErrors.length) status.passed = false;
      try { await boundedA11('cleanup-evidence-write', () => fs.writeFile(receiptPath, JSON.stringify({ ...status,
        cleanupComplete: cleanupErrors.length === 0,
        ...(failure ? { failure: { name: failure.name, code: failure.code || null,
          stage: failure.step || stage } } : {}),
        ...(apiKeyRotateFailure ? { privateApiKeyRotateFailure: apiKeyRotateFailure } : {}) }, null, 2),
      { flag: 'wx', mode: 0o600 }), 3000); }
      catch (error) { cleanupErrors.push(error); }
    }
    if (failure && cleanupErrors.length) {
      console.log('A11 cleanup incomplete', cleanupErrors.map(error => error.step || error.code || error.name).join(','));
      throw failure;
    }
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Commerce cleanup or evidence write failed');
    if (failure) throw failure;
    assert.equal(status.passed, true);
  });
