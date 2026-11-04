'use strict';

const net = require('node:net');

const DEFAULT_MAX_HTML_BYTES = 65536;
const DEFAULT_MAX_POST_BYTES = 65536;
const DEFAULT_MAX_RESPONSE_BYTES = 65536;
const MAX_BLOCKED_REQUESTS = 64;
const BOUNDARY = 'intercepted same-site cross-origin .invalid browser fixture; deployed origins are not qualified';
const VICTIM_DOCUMENT_BOUNDARY = 'intercepted victim-origin .invalid browser fixture; deployed origins are not qualified';

function coded(message, code, name = 'Error') {
  const error = new Error(message);
  error.code = code;
  error.name = name;
  return error;
}

function parseOrigin(value, label) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError(`Invalid ${label} origin`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash || !url.hostname.endsWith('.invalid')) {
    throw new TypeError(`Invalid ${label} origin`);
  }
  return url;
}

function siteOf(url) {
  const labels = url.hostname.split('.');
  return `${url.protocol}//${labels.slice(-2).join('.')}`;
}

function validateCookie(cookie) {
  if (!cookie || typeof cookie !== 'object'
    || typeof cookie.name !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(cookie.name)
    || typeof cookie.value !== 'string' || !cookie.value.length || cookie.value.length > 256
    || /[;\u0000-\u001f\u007f]/.test(cookie.value)) {
    throw new TypeError('Invalid synthetic victim cookie');
  }
  return { name: cookie.name, value: cookie.value };
}

function hasExactCookie(header, expected) {
  if (typeof header !== 'string') return false;
  return header.split(';').some(part => {
    const index = part.indexOf('=');
    return index > 0 && part.slice(0, index).trim() === expected.name
      && part.slice(index + 1).trim() === expected.value;
  });
}

function frozenObservation(request, documentOrigin, cookie, limits) {
  const url = request.url();
  const headers = request.headers();
  const postData = request.postData() ?? null;
  if (Buffer.byteLength(url) > 2048 || (postData !== null && Buffer.byteLength(postData) > limits.maxPostBytes)) {
    throw coded('Observed request exceeds browser executor limits', 'CSRF_BROWSER_REQUEST_TOO_LARGE');
  }
  let frameOrigin = null;
  try { frameOrigin = new URL(request.frame()?.url() || '').origin; } catch {}
  if (frameOrigin !== documentOrigin) throw coded('Victim request did not originate in the selected document frame', 'CSRF_BROWSER_WRONG_FRAME');
  return Object.freeze({
    url,
    method: request.method(),
    postData,
    resourceType: request.resourceType(),
    frameOrigin,
    contentType: String(headers['content-type'] || '').slice(0, 160),
    cookiePresent: hasExactCookie(headers.cookie, cookie),
  });
}

function validateCallbackResponse(value, maxBytes) {
  if (!value || typeof value !== 'object' || !Number.isSafeInteger(value.status)
    || value.status < 200 || value.status > 599 || (value.status >= 300 && value.status < 400)) {
    throw coded('Invalid browser callback response', 'CSRF_BROWSER_INVALID_RESPONSE');
  }
  const body = value.body == null ? '' : value.body;
  if (typeof body !== 'string' && !Buffer.isBuffer(body)) {
    throw coded('Invalid browser callback body', 'CSRF_BROWSER_INVALID_RESPONSE');
  }
  if (Buffer.byteLength(body) > maxBytes) {
    throw coded('Browser callback response is too large', 'CSRF_BROWSER_INVALID_RESPONSE');
  }
  const contentType = value.contentType == null ? 'text/plain; charset=utf-8' : value.contentType;
  if (typeof contentType !== 'string' || !contentType.length || contentType.length > 160 || /[\r\n]/.test(contentType)) {
    throw coded('Invalid browser callback content type', 'CSRF_BROWSER_INVALID_RESPONSE');
  }
  return { status: value.status, body, contentType };
}

function abortRace(promise, signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  let listener;
  const aborted = new Promise((_, reject) => {
    listener = () => reject(signal.reason);
    signal.addEventListener('abort', listener, { once: true });
  });
  return Promise.race([Promise.resolve(promise), aborted])
    .finally(() => signal.removeEventListener('abort', listener));
}

async function acquireResource(promise, signal, dispose) {
  const pending = Promise.resolve(promise);
  let resource;
  try {
    resource = await abortRace(pending, signal);
  } catch (error) {
    // The underlying browser operation cannot itself be cancelled. If it
    // completes after the abort won the race, dispose its late result instead
    // of leaving an untracked context or page behind.
    if (signal.aborted) pending.then(value => dispose(value)).catch(() => {});
    throw error;
  }
  if (signal.aborted) {
    await dispose(resource).catch(() => {});
    throw signal.reason;
  }
  return resource;
}

function createCsrfBrowserExecutor({ puppeteer, attackerOrigin, victimOrigin,
  victimPath = '/api/workshop/csrf/agent-action', documentOrigin = 'attacker', documentInteraction = 'none', timeoutMs = 10000,
  maxHtmlBytes = DEFAULT_MAX_HTML_BYTES, maxPostBytes = DEFAULT_MAX_POST_BYTES,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, maxConcurrent = 4 } = {}) {
  const attacker = parseOrigin(attackerOrigin, 'attacker');
  const victim = parseOrigin(victimOrigin, 'victim');
  // Selected only by the trusted server constructor, never by learner request data.
  if (!['attacker', 'victim'].includes(documentOrigin)) throw new TypeError('Invalid browser document origin mode');
  if (!['none', 'reader-hover'].includes(documentInteraction)
    || (documentInteraction !== 'none' && documentOrigin !== 'victim')) {
    throw new TypeError('Invalid browser document interaction');
  }
  const document = documentOrigin === 'victim' ? victim : attacker;
  const boundary = documentOrigin === 'victim' ? VICTIM_DOCUMENT_BOUNDARY : BOUNDARY;
  if (attacker.origin === victim.origin || siteOf(attacker) !== siteOf(victim)) {
    throw new TypeError('Browser origins must be same-site and cross-origin');
  }
  if (typeof victimPath !== 'string' || !victimPath.startsWith('/') || victimPath.includes('?') || victimPath.includes('#')) {
    throw new TypeError('Invalid victim path');
  }
  for (const [value, min, max, label] of [
    [timeoutMs, 500, require('./csrfRuntimeBudget').browserMs, 'timeout'], [maxHtmlBytes, 1, 262144, 'HTML limit'],
    [maxPostBytes, 1, 262144, 'POST limit'], [maxResponseBytes, 1, 262144, 'response limit'],
    [maxConcurrent, 1, 16, 'concurrency limit'],
  ]) if (!Number.isInteger(value) || value < min || value > max) throw new RangeError(`Invalid ${label}`);

  let browserPromise;
  let proxyPromise;
  let proxyServer;
  const proxySockets = new Set();
  let active = 0;
  const activeExecutions = new Set();
  let closed = false;
  let closingPromise;

  async function getProxy() {
    if (!proxyPromise) proxyPromise = new Promise((resolve, reject) => {
      proxyServer = net.createServer(socket => {
        proxySockets.add(socket);
        socket.once('close', () => proxySockets.delete(socket));
        socket.destroy();
      });
      proxyServer.once('error', reject);
      proxyServer.listen(0, '127.0.0.1', () => resolve(proxyServer.address().port));
    });
    return proxyPromise;
  }

  async function getBrowser() {
    if (!browserPromise) {
      // BROWSER_NO_SANDBOX=1 drops the SUID sandbox on Fargate (no SYS_ADMIN); the
      // container is the isolation boundary. Unset locally keeps the real sandbox.
      const noSandboxArgs = process.env.BROWSER_NO_SANDBOX === '1' ? ['--no-sandbox', '--disable-setuid-sandbox'] : [];
      browserPromise = getProxy().then(port => (puppeteer || require('puppeteer')).launch({
        headless: true,
        args: [`--proxy-server=http://127.0.0.1:${port}`, '--proxy-bypass-list=<-loopback>',
          '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
          '--webrtc-ip-handling-policy=disable_non_proxied_udp', ...noSandboxArgs],
      }));
      browserPromise.catch(() => { browserPromise = undefined; });
    }
    return browserPromise;
  }

  async function execute({ html, victimCookie, signal, onRequest } = {}) {
    if (closed) throw coded('CSRF browser executor is closed', 'CSRF_BROWSER_CLOSED');
    if (typeof html !== 'string' || !html.length || Buffer.byteLength(html) > maxHtmlBytes) {
      throw coded('Invalid or oversized browser payload', 'CSRF_BROWSER_INVALID_HTML', 'TypeError');
    }
    if (typeof onRequest !== 'function') throw new TypeError('Browser request callback required');
    if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('Valid abort signal required');
    const cookie = validateCookie(victimCookie);
    if (active >= maxConcurrent) throw coded('CSRF browser executor is busy', 'CSRF_BROWSER_BUSY');
    active += 1;
    const controller = new AbortController();
    let resolveDrain;
    const execution = { controller, drain: new Promise(resolve => { resolveDrain = resolve; }) };
    activeExecutions.add(execution);
    const timeout = setTimeout(() => controller.abort(coded('CSRF browser execution timed out', 'CSRF_BROWSER_TIMEOUT', 'AbortError')), timeoutMs);
    const externalAbort = () => controller.abort(signal.reason || coded('CSRF browser execution cancelled', 'CSRF_BROWSER_CANCELLED', 'AbortError'));
    signal?.addEventListener('abort', externalAbort, { once: true });
    if (signal?.aborted) externalAbort();
    let context;
    let page;
    let contextClosePromise;
    let pageClosePromise;
    const closeContext = value => {
      if (!value) return Promise.resolve();
      if (!contextClosePromise) contextClosePromise = Promise.resolve().then(() => value.close());
      return contextClosePromise;
    };
    const closePage = value => {
      if (!value) return Promise.resolve();
      if (!pageClosePromise) pageClosePromise = Promise.resolve().then(() => value.close());
      return pageClosePromise;
    };
    let actionReserved = false;
    let interaction = 'load';
    let initialDocumentReserved = false;
    let admittedCallback = null;
    let settleAction;
    let rejectAction;
    const action = new Promise((resolve, reject) => { settleAction = resolve; rejectAction = reject; });
    // Abort can happen while Chrome is still launching, before execute reaches
    // the action wait. Observe the rejection immediately without changing what
    // the later await receives.
    action.catch(() => {});
    const blockedRequests = [];
    let blockedRequestsTruncated = false;
    const recordBlocked = request => {
      if (blockedRequests.length >= MAX_BLOCKED_REQUESTS) { blockedRequestsTruncated = true; return; }
      blockedRequests.push(Object.freeze({ url: request.url().slice(0, 500), method: request.method(), resourceType: request.resourceType() }));
    };
    const documentUrl = new URL('/__owasp_ai_goat_csrf_browser_attempt__', document).href;
    const closeOnAbort = () => {
      closePage(page).catch(() => {});
      closeContext(context).catch(() => {});
      rejectAction(controller.signal.reason);
    };
    controller.signal.addEventListener('abort', closeOnAbort, { once: true });
    try {
      controller.signal.throwIfAborted();
      const browser = await abortRace(getBrowser(), controller.signal);
      controller.signal.throwIfAborted();
      context = await acquireResource(browser.createBrowserContext(), controller.signal, closeContext);
      page = await acquireResource(context.newPage(), controller.signal, closePage);
      await abortRace(page.setBypassServiceWorker(true), controller.signal);
      page.on('popup', popup => popup.close().catch(() => {}));
      await abortRace(page.setRequestInterception(true), controller.signal);
      page.on('request', request => {
        (async () => {
          const requestUrl = new URL(request.url());
          if (!initialDocumentReserved && request.isNavigationRequest() && request.url() === documentUrl
            && request.frame() === page.mainFrame()) {
            initialDocumentReserved = true;
            await request.respond({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
            return;
          }
          const exactVictimPath = requestUrl.origin === victim.origin && requestUrl.pathname === victimPath;
          if (exactVictimPath && request.method() === 'OPTIONS') {
            const headers = request.headers();
            const requestedMethod = String(headers['access-control-request-method'] || '').toUpperCase();
            const requestedHeaders = String(headers['access-control-request-headers'] || '')
              .split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
            if (headers.origin === document.origin && requestedMethod === 'POST'
              && requestedHeaders.every(value => value === 'content-type')) {
              await request.respond({ status: 204, headers: {
                'access-control-allow-origin': document.origin,
                'access-control-allow-credentials': 'true',
                'access-control-allow-methods': 'GET, POST, OPTIONS',
                'access-control-allow-headers': 'Content-Type',
                vary: 'Origin',
              } });
              return;
            }
          }
          if (exactVictimPath && ['GET', 'POST'].includes(request.method()) && !actionReserved) {
            // Reserve before awaiting the callback so parallel page requests cannot
            // execute the action more than once.
            actionReserved = true;
            const observation = frozenObservation(request, document.origin, cookie, { maxPostBytes });
            if (!observation.cookiePresent) throw coded('Browser request did not carry the synthetic victim cookie', 'CSRF_BROWSER_COOKIE_MISSING');
            // Once admitted, the private callback may already be inside a real
            // effect. Cancellation closes Chrome immediately, but execute must
            // retain its outer owner lease until this callback drains.
            controller.signal.throwIfAborted();
            try { admittedCallback = Promise.resolve(onRequest(observation, Object.freeze({ signal: controller.signal }))); }
            catch (error) { admittedCallback = Promise.reject(error); }
            const callbackValue = await admittedCallback;
            controller.signal.throwIfAborted();
            const response = validateCallbackResponse(callbackValue, maxResponseBytes);
            let observeResponse;
            const browserResponse = new Promise(resolve => {
              observeResponse = received => { if (received.request() === request) resolve(received); };
              page.on('response', observeResponse);
            });
            try {
              await request.respond({ status: response.status, contentType: response.contentType, body: response.body,
                headers: { 'access-control-allow-origin': document.origin, 'access-control-allow-credentials': 'true', vary: 'Origin' } });
              const received = await abortRace(browserResponse, controller.signal);
              controller.signal.throwIfAborted();
              if (received.status() !== response.status) throw coded('Browser response status mismatch', 'CSRF_BROWSER_RESPONSE_MISMATCH');
              settleAction(Object.freeze({ observation, responseStatus: received.status(), responseObserved: true, boundary, interaction,
                blockedRequests: Object.freeze([...blockedRequests]), blockedRequestsTruncated }));
            } finally { page.off('response', observeResponse); }
            return;
          }
          recordBlocked(request);
          await request.abort('blockedbyclient');
        })().catch(error => {
          request.abort('blockedbyclient').catch(() => {});
          rejectAction(error);
        });
      });
      await abortRace(page.setCookie({ name: cookie.name, value: cookie.value, url: victim.origin,
        httpOnly: true, sameSite: 'Lax', secure: victim.protocol === 'https:' }), controller.signal);
      await abortRace(page.goto(documentUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs }), controller.signal);
      if (documentInteraction === 'reader-hover' && !actionReserved) {
        // A real pointer movement models reading-pane interaction for the shipped
        // hover lessons. Never interpret or invoke the handler outside Chrome.
        const targets = await abortRace(page.$$('[onmouseover]'), controller.signal);
        try {
          for (const target of targets.slice(0, 8)) {
            controller.signal.throwIfAborted();
            if (actionReserved) break;
            const box = await abortRace(target.boundingBox(), controller.signal);
            controller.signal.throwIfAborted();
            if (actionReserved) break;
            if (!box || box.width <= 0 || box.height <= 0) continue;
            interaction = 'reader-hover';
            await abortRace(target.hover(), controller.signal);
          }
        } finally {
          await Promise.allSettled(targets.map(target => target.dispose()));
        }
      }
      return await abortRace(action, controller.signal);
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', externalAbort);
      controller.signal.removeEventListener('abort', closeOnAbort);
      await closePage(page).catch(() => {});
      await closeContext(context).catch(() => {});
      // Do not release the concurrency slot or caller's owner run while an
      // admitted callback can still be completing an effect.
      await admittedCallback?.catch(() => {});
      active -= 1;
      activeExecutions.delete(execution);
      resolveDrain();
    }
  }

  function close() {
    if (closingPromise) return closingPromise;
    closed = true;
    closingPromise = (async () => {
      const reason = coded('CSRF browser executor is closing', 'CSRF_BROWSER_CLOSED', 'AbortError');
      const draining = [...activeExecutions];
      for (const execution of draining) execution.controller.abort(reason);
      await Promise.allSettled(draining.map(execution => execution.drain));
      const pending = browserPromise;
      browserPromise = undefined;
      if (pending) await pending.then(browser => browser.close()).catch(() => {});
      for (const socket of proxySockets) socket.destroy();
      if (proxyServer) await new Promise(resolve => proxyServer.close(resolve));
      proxyServer = undefined;
      proxyPromise = undefined;
    })();
    return closingPromise;
  }

  return Object.freeze({ execute, close });
}

module.exports = { createCsrfBrowserExecutor, BOUNDARY, VICTIM_DOCUMENT_BOUNDARY, DEFAULT_MAX_HTML_BYTES, MAX_BLOCKED_REQUESTS };
