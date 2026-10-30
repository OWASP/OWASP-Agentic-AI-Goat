'use strict';

// Test-only, closed current-host admission for the original whole-commerce
// browser cohort. The ordinary external-evidence fixture remains unchanged.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomBytes } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { buildInventory } = require('../postgres/adminQ05RenderedScenario');
const { readInheritedFifoGrant } = require('./inheritedFifoGrant');
const { captureBrowserRecord } = require('./secureshopDarwinBrowserBirth');

const PREFIX = 'SECURESHOP_COMMERCE_';
const COHORT = 'standalone-commerce-browser';
const SESSION_REVOKE_COHORT = 'account-session-revoke-browser';
const SESSION_REVOKE_OTHER_COHORT = 'account-session-revoke-other-browser';
const ACCOUNT_AVATAR_COHORT = 'account-avatar-browser';
const CHECKOUT_COHORT = 'customer-checkout-browser';
const PROFILE_COHORT = 'customer-profile-browser';
const CART_COHORT = 'customer-cart-lifecycle-browser';
const PAYMENT_COHORT = 'customer-payment-setup-browser';
const OLDER_ORDERS_COHORT = 'customer-older-orders-browser';
const CHECKOUT_FENCES_COHORT = 'customer-checkout-fences';
const MANUAL_CHECKOUT_COHORT = 'customer-manual-checkout-browser';
const SHA256 = /^[a-f0-9]{64}$/;

function commerceVariant(variant) {
  if (variant === 'customer-manual-checkout') return Object.freeze({
    cohort: MANUAL_CHECKOUT_COHORT, selector: 'SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_NATIVE',
    receipt: 'customer-manual-checkout-browser.json',
    birth: 'customer-manual-checkout-browser-birth.json',
    ack: 'customer-manual-checkout-browser-ack.json', kind: 'customer_manual_checkout_browser',
    profile: 'owasp-ai-goat-customer-manual-checkout-',
  });
  if (variant === 'customer-out-of-stock') return Object.freeze({
    cohort: 'customer-out-of-stock-browser', selector: 'SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE',
    receipt: 'customer-out-of-stock-browser.json', birth: 'customer-out-of-stock-browser-birth.json',
    ack: 'customer-out-of-stock-browser-ack.json', kind: 'customer_out_of_stock_browser',
    profile: 'owasp-ai-goat-customer-out-of-stock-',
  });
  if (variant === 'customer-product-details') return Object.freeze({
    cohort: 'customer-product-disambiguation-browser', selector: 'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE',
    receipt: 'customer-product-disambiguation-browser.json', birth: 'customer-product-details-browser-birth.json',
    ack: 'customer-product-details-browser-ack.json', kind: 'customer_product_details_browser',
    profile: 'owasp-ai-goat-customer-product-details-',
  });
  if (variant === 'customer-refund-handoff') return Object.freeze({
    cohort: 'customer-refund-handoff-browser', selector: 'SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE',
    receipt: 'customer-refund-handoff-browser.json', birth: 'customer-refund-handoff-browser-birth.json',
    ack: 'customer-refund-handoff-browser-ack.json', kind: 'customer_refund_handoff_browser',
    profile: 'owasp-ai-goat-customer-refund-handoff-',
  });
  if (variant === 'customer-address-setup') return Object.freeze({
    cohort: 'customer-address-setup-browser', selector: 'SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE',
    receipt: 'customer-address-setup-browser.json', birth: 'customer-address-setup-browser-birth.json',
    ack: 'customer-address-setup-browser-ack.json', kind: 'customer_address_setup_browser',
    profile: 'owasp-ai-goat-customer-address-setup-',
  });
  if (variant === undefined) return Object.freeze({
    cohort: COHORT, selector: 'SECURESHOP_STANDALONE_COMMERCE_NATIVE',
    receipt: 'standalone-commerce-browser.json', birth: 'standalone-commerce-browser-birth.json',
    ack: 'standalone-commerce-browser-ack.json', kind: 'standalone_commerce_browser',
  });
  if (variant === 'account-session-revoke') return Object.freeze({
    cohort: SESSION_REVOKE_COHORT, selector: 'SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE',
    receipt: 'account-current-session-revoke-browser-v2.json', birth: 'account-session-revoke-browser-birth.json',
    ack: 'account-session-revoke-browser-ack.json', kind: 'account_session_revoke_browser',
    profile: 'owasp-ai-goat-standalone-commerce-',
  });
  if (variant === 'account-session-revoke-other') return Object.freeze({
    cohort: SESSION_REVOKE_OTHER_COHORT, selector: 'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE',
    receipt: 'account-other-session-revoke-browser-v1.json',
    birth: 'account-session-revoke-other-browser-birth.json',
    ack: 'account-session-revoke-other-browser-ack.json',
    kind: 'account_session_revoke_other_browser', profile: 'owasp-ai-goat-standalone-commerce-',
  });
  if (variant === 'account-avatar') return Object.freeze({
    cohort: ACCOUNT_AVATAR_COHORT, selector: 'SECURESHOP_ACCOUNT_AVATAR_NATIVE',
    receipt: 'account-avatar-browser-v1.json', birth: 'account-avatar-browser-birth.json',
    ack: 'account-avatar-browser-ack.json', kind: 'account_avatar_browser',
    profile: 'owasp-ai-goat-account-avatar-',
  });
  if (variant === 'customer-profile') return Object.freeze({
    cohort: PROFILE_COHORT, selector: 'SECURESHOP_CUSTOMER_PROFILE_NATIVE',
    receipt: 'customer-profile-browser.json', birth: 'customer-profile-browser-birth.json',
    ack: 'customer-profile-browser-ack.json', kind: 'customer_profile_browser',
    profile: 'owasp-ai-goat-customer-profile-',
  });
  if (variant === 'customer-cart-lifecycle') return Object.freeze({
    cohort: CART_COHORT, selector: 'SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE',
    receipt: 'customer-cart-lifecycle-browser.json',
    birth: 'customer-cart-lifecycle-browser-birth.json',
    ack: 'customer-cart-lifecycle-browser-ack.json', kind: 'customer_cart_lifecycle_browser',
    profile: 'owasp-ai-goat-customer-cart-lifecycle-',
  });
  if (variant === 'customer-payment-setup') return Object.freeze({
    cohort: PAYMENT_COHORT, selector: 'SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE',
    receipt: 'customer-payment-setup-browser.json',
    birth: 'customer-payment-setup-browser-birth.json',
    ack: 'customer-payment-setup-browser-ack.json', kind: 'customer_payment_setup_browser',
    profile: 'owasp-ai-goat-customer-payment-setup-',
  });
  if (variant === 'customer-older-orders') return Object.freeze({
    cohort: OLDER_ORDERS_COHORT, selector: 'SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE',
    receipt: 'customer-older-orders-browser.json', birth: 'customer-older-orders-browser-birth.json',
    ack: 'customer-older-orders-browser-ack.json', kind: 'customer_older_orders_browser',
    profile: 'owasp-ai-goat-customer-older-orders-',
  });
  if (variant === 'customer-checkout-fences') return Object.freeze({
    cohort: CHECKOUT_FENCES_COHORT, selector: 'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE',
    receipt: 'customer-checkout-fences.json', birth: 'customer-checkout-fences-browser-birth.json',
    ack: 'customer-checkout-fences-browser-ack.json', kind: 'customer_checkout_fences_browser',
    profile: 'owasp-ai-goat-customer-checkout-fences-',
  });
  assert.ok(variant === 'customer-checkout',
    'only account-session-revoke, customer-checkout, customer-profile, customer-cart-lifecycle, customer-payment-setup, customer-older-orders or customer-checkout-fences variants are admitted');
  return Object.freeze({
    cohort: CHECKOUT_COHORT, selector: 'SECURESHOP_CUSTOMER_CHECKOUT_NATIVE',
    receipt: 'customer-checkout-browser.json', birth: 'customer-checkout-browser-birth.json',
    ack: 'customer-checkout-browser-ack.json', kind: 'customer_checkout_browser',
    profile: 'owasp-ai-goat-customer-checkout-',
  });
}

function observeProductRequests(page, origin, expected) {
  const records = expected.map(({ method, path: pathname }) =>
    ({ method, path: pathname, requests: [] }));
  const selected = request => {
    try {
      const url = new URL(request.url());
      return url.origin === origin
        ? records.find(row => row.method === request.method() && row.path === url.pathname) : null;
    } catch { return null; }
  };
  const onRequest = request => {
    const row = selected(request);
    if (row) row.requests.push({ request, status: null, finished: false, failed: false });
  };
  const entryFor = request => {
    const row = selected(request);
    return row?.requests.find(item => item.request === request) || null;
  };
  const onResponse = response => {
    const entry = entryFor(response.request());
    if (entry) entry.status = response.status();
  };
  const onFinished = request => {
    const entry = entryFor(request);
    if (entry) entry.finished = true;
  };
  const onFailed = request => {
    const entry = entryFor(request);
    if (entry) entry.failed = true;
  };
  page.on('request', onRequest);
  page.on('response', onResponse);
  page.on('requestfinished', onFinished);
  page.on('requestfailed', onFailed);
  return {
    snapshot: () => records.map(row => ({ method: row.method, path: row.path,
      requests: row.requests.length,
      responseStatuses: row.requests.map(item => item.status),
      finished: row.requests.filter(item => item.finished).length,
      failed: row.requests.filter(item => item.failed).length })),
    stop: () => {
      page.off('request', onRequest);
      page.off('response', onResponse);
      page.off('requestfinished', onFinished);
      page.off('requestfailed', onFailed);
    },
  };
}

// Deliberately self-contained so Puppeteer can serialize this same selector
// into the rendered frame; contract tests execute it against a real DOM.
function exactConsequenceDialogButton(title, consequence, confirmLabel, desiredLabel) {
  const matching = [...document.querySelectorAll('[role="dialog"]')].filter(dialog =>
    dialog.querySelector('#ss-dialog-title')?.textContent.trim() === title);
  if (matching.length !== 1) return null;
  const dialog = matching[0];
  if (dialog.getAttribute('aria-modal') !== 'true' || dialog.getAttribute('aria-hidden') === 'true'
      || dialog.hasAttribute('inert') || !dialog.textContent.includes(consequence)) return null;
  const buttons = [...dialog.querySelectorAll('button')];
  const named = label => buttons.filter(button => button.textContent.trim() === label);
  if (named('Cancel').length !== 1 || named(confirmLabel).length !== 1) return null;
  const selected = named(desiredLabel);
  return selected.length === 1 && !selected[0].disabled ? selected[0] : null;
}

// Diagnostic only: this runs in the original parent browser page immediately
// before a controlled storage fault. It never returns a storage value, token,
// operation identifier, or unrecognized field name.
function practiceSnapshotMetadata({ scopeKey, sceneId, allowedFields, summaryKey }, storage = globalThis.localStorage) {
  const result = { marker: 'unavailable', snapshotFound: false, jsonValid: false,
    nonNullFields: [], unknownNonNullField: false, summaryRefPresent: false,
    summaryRefParseable: false, summaryRefHasEntries: false, summaryRefEntryCount: 0 };
  if (typeof scopeKey !== 'string' || !/^owasp-ai-goat:secureshop:[0-9a-f-]{36}:[1-9]\d*$/.test(scopeKey)
      || typeof sceneId !== 'string' || !/^[0-9a-f-]{36}$/.test(sceneId)
      || !Array.isArray(allowedFields) || allowedFields.length > 80
      || allowedFields.some(name => typeof name !== 'string' || name.length > 100)
      || new Set(allowedFields).size !== allowedFields.length
      || typeof summaryKey !== 'string' || !allowedFields.includes(summaryKey)) return result;
  let raw;
  try {
    const marker = storage.getItem(`${scopeKey}:scene-storage-v1`);
    if (marker !== null && marker !== '1') { result.marker = 'invalid'; return result; }
    result.marker = marker === null ? 'base' : 'scene';
    raw = storage.getItem(marker === null ? scopeKey : `${scopeKey}:scene:${sceneId}`);
  } catch { result.marker = 'read-error'; return result; }
  if (raw === null) return result;
  result.snapshotFound = true;
  if (typeof raw !== 'string' || raw.length > 2 * 1024 * 1024) return result;
  let snapshot;
  try { snapshot = JSON.parse(raw); } catch { return result; }
  if (!snapshot || Object.getPrototypeOf(snapshot) !== Object.prototype || Array.isArray(snapshot)) return result;
  result.jsonValid = true;
  const allow = new Set(allowedFields);
  for (const [name, value] of Object.entries(snapshot)) {
    if (value === null) continue;
    if (!allow.has(name)) { result.unknownNonNullField = true; continue; }
    if (name !== 'secureshop_v2_token' && name !== 'ss_guest_cart') result.nonNullFields.push(name);
  }
  result.nonNullFields.sort();
  result.summaryRefPresent = snapshot[summaryKey] != null;
  // A parseable container says nothing about individual entries or whether
  // the operation completed; it is only a bounded diagnostic shape signal.
  if (result.summaryRefPresent && typeof snapshot[summaryKey] === 'string'
      && snapshot[summaryKey].length <= 16384) {
    try {
      const reference = JSON.parse(snapshot[summaryKey]);
      if (reference && [1, 2].includes(reference.version) && Array.isArray(reference.entries)
          && reference.entries.length <= 32) {
        result.summaryRefParseable = true;
        result.summaryRefHasEntries = reference.entries.length > 0;
        result.summaryRefEntryCount = reference.entries.length;
      }
    } catch { /* Shape only; never return saved reference content. */ }
  }
  return result;
}

// Capture an object with a browser-only JSHandle, then compare in that browser.
// A primitive string handle can expose its value in CDP RemoteObject metadata.
// Never call jsonValue on this object or return the saved string to Node.
function practiceSummaryReference({ scopeKey, sceneId, summaryKey }, original, storage = globalThis.localStorage) {
  const comparing = original !== undefined;
  if (typeof scopeKey !== 'string' || !/^owasp-ai-goat:secureshop:[0-9a-f-]{36}:[1-9]\d*$/.test(scopeKey)
      || typeof sceneId !== 'string' || !/^[0-9a-f-]{36}$/.test(sceneId)
      || typeof summaryKey !== 'string' || summaryKey.length > 100) return comparing ? false : null;
  let value = null;
  try {
    const marker = storage.getItem(`${scopeKey}:scene-storage-v1`);
    if (marker !== null && marker !== '1') return comparing ? false : null;
    const raw = storage.getItem(marker === null ? scopeKey : `${scopeKey}:scene:${sceneId}`);
    if (typeof raw !== 'string' || raw.length > 2 * 1024 * 1024) return comparing ? false : null;
    const snapshot = JSON.parse(raw);
    if (!snapshot || Object.getPrototypeOf(snapshot) !== Object.prototype || Array.isArray(snapshot))
      return comparing ? false : null;
    value = snapshot[summaryKey];
  } catch { return comparing ? false : null; }
  if (typeof value !== 'string' || !value || value.length > 16384) return comparing ? false : null;
  return comparing ? original && typeof original === 'object'
    && typeof original.value === 'string' && value === original.value : { value };
}

async function readBoundedProductError(response, { workStep, label }) {
  assert.equal(response.status(), 503, `${label} must retain its real HTTP 503`);
  console.log('A11 Product body await', label);
  const body = await workStep(label, () => response.json(), 5000);
  assert.ok(isDeepStrictEqual(body, { error: 'Bound SecureShop operation unavailable' }),
    `${label} must retain the exact unavailable-operation JSON`);
  console.log('A11 Product body complete', label);
}

// Observe only the original readiness HTTP response. The rendered client may
// deliberately cancel its error body, so CDP cannot reliably retrieve it.
// This passive test-only observer never changes the bytes sent to that client.
function observeOriginalListingReadiness({ isCurrent }) {
  const pathname = '/api/secureshop/merchant/listings/readiness';
  const headerName = 'x-owasp-ai-goat-commerce-readiness-observation';
  const nonce = randomBytes(16).toString('hex');
  const limit = 4096;
  let armed = false;
  let seen = 0;
  let captured = null;
  let settle;
  const observed = new Promise(resolve => { settle = resolve; });
  const restore = () => {
    if (!captured?.response) return;
    const { response, write, end, onFinish, onClose } = captured;
    response.write = write;
    response.end = end;
    response.off('finish', onFinish);
    response.off('close', onClose);
    captured.response = null;
  };
  const stop = () => { armed = false; restore(); settle(); };
  const captureChunk = (chunk, encoding) => {
    if (chunk == null || typeof chunk === 'function') return;
    if (captured.error) return;
    let size;
    if (typeof chunk === 'string') {
      if (encoding != null && typeof encoding !== 'string' && typeof encoding !== 'function') {
        captured.error = 'unsupported-encoding'; return;
      }
      if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
        captured.error = 'unsupported-encoding'; return;
      }
      size = Buffer.byteLength(chunk, typeof encoding === 'string' ? encoding : 'utf8');
    } else if (Buffer.isBuffer(chunk) || chunk instanceof Uint8Array) size = chunk.byteLength;
    else { captured.error = 'unsupported-chunk'; return; }
    if (size > limit - captured.bytes) { captured.error = 'overflow'; return; }
    if (size === 0) return;
    // Copy only after the cap check: callers can reuse/mutate their Buffer.
    const copy = typeof chunk === 'string'
      ? Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8') : Buffer.from(chunk);
    captured.chunks.push(copy);
    captured.bytes += copy.length;
  };
  const middleware = (request, response, next) => {
    if (!armed || !isCurrent() || request.method !== 'GET' || request.path !== pathname) {
      next(); return;
    }
    seen += 1;
    if (seen > 1) { next(); return; }
    response.setHeader(headerName, nonce);
    const write = response.write;
    const end = response.end;
    captured = { response, write, end, chunks: [], bytes: 0, error: null,
      finished: false, closed: false, status: null, encoding: null, contentType: null,
      onFinish: null, onClose: null };
    let insideEnd = false;
    captured.onFinish = () => {
      captured.finished = true;
      captured.status = response.statusCode;
      captured.encoding = response.getHeader('content-encoding');
      captured.contentType = response.getHeader('content-type');
    };
    captured.onClose = () => { captured.closed = true; restore(); settle(); };
    response.once('finish', captured.onFinish);
    response.once('close', captured.onClose);
    response.write = function (...args) {
      if (!insideEnd) captureChunk(args[0], args[1]);
      return write.apply(this, args);
    };
    response.end = function (...args) {
      captureChunk(args[0], args[1]);
      insideEnd = true;
      try { return end.apply(this, args); }
      finally { insideEnd = false; }
    };
    next();
  };
  const arm = () => {
    assert.equal(armed, false);
    assert.equal(seen, 0);
    assert.equal(isCurrent(), true, 'readiness observer must arm only in its original UI stage');
    armed = true;
  };
  const assertBrowserResponse = (response, origin) => {
    try {
      assert.equal(seen, 1, 'exactly one original readiness request required');
      assert.ok(captured, 'original readiness response missing');
      assert.equal(captured.error, null, 'original readiness response exceeded capture bounds');
      assert.equal(captured.finished, true, 'original readiness response did not finish');
      assert.equal(captured.closed, true, 'original readiness response did not close');
      assert.equal(captured.status, 503);
      assert.ok(captured.encoding == null || captured.encoding === 'identity',
        'original readiness response must use identity encoding');
      assert.match(String(captured.contentType), /^application\/json(?:;|$)/i);
      assert.equal(response.status(), 503);
      assert.equal(response.request().method(), 'GET');
      const url = new URL(response.url());
      assert.equal(url.origin, origin);
      assert.equal(url.pathname, pathname);
      assert.equal(url.search, '');
      assert.equal(response.headers()[headerName], nonce,
        'browser response must match this original server response');
      const emitted = new TextDecoder('utf-8', { fatal: true })
        .decode(Buffer.concat(captured.chunks));
      assert.deepEqual(JSON.parse(emitted), { error: 'Bound SecureShop operation unavailable' },
        'original server-emitted readiness JSON must remain exact');
    } finally { stop(); }
  };
  return { arm, middleware, wait: () => observed, assertBrowserResponse, stop };
}

function privateDirectory(directory) {
  const info = fs.lstatSync(directory);
  assert.ok(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid());
  assert.equal(info.mode & 0o777, 0o700);
  assert.equal(fs.realpathSync(directory), directory);
}

function validateCommerceGrant(grant, { workspace, evidencePath, buildSha256,
  snapshotSha256, chromium, chromiumSha256, launcherPid, workerPid, variant }) {
  const selected = commerceVariant(variant);
  assert.ok(grant && typeof grant === 'object' && !Array.isArray(grant));
  assert.deepEqual(Object.keys(grant).sort(), ['version', 'cohort', 'launcherPid', 'workerPid',
    'nonce', 'workspace', 'evidencePath', 'buildSha256', 'snapshotSha256',
    'outerSandbox', 'chromium', 'chromiumSha256'].sort());
  assert.equal(grant.version, 1);
  assert.equal(grant.cohort, selected.cohort);
  assert.equal(grant.launcherPid, launcherPid);
  assert.equal(grant.workerPid, workerPid);
  assert.match(grant.nonce, SHA256);
  assert.equal(grant.workspace, workspace);
  assert.equal(grant.evidencePath, evidencePath);
  assert.equal(grant.buildSha256, buildSha256);
  assert.equal(grant.snapshotSha256, snapshotSha256);
  assert.equal(grant.outerSandbox, 'repository-only');
  assert.equal(grant.chromium, chromium);
  assert.equal(grant.chromiumSha256, chromiumSha256);
  return { admitted: true };
}

async function admitCommerceBrowser(env, { workspace, evidencePath, executablePath, variant }) {
  const selected = commerceVariant(variant);
  if (env[`${PREFIX}TEST_NO_SANDBOX`] === undefined) {
    assert.ok(!path.resolve(evidencePath).startsWith(`${workspace}${path.sep}`),
      'ordinary commerce evidence must remain outside the checkout');
    return null;
  }
  assert.equal(env[`${PREFIX}TEST_NO_SANDBOX`], '1');
  assert.equal(env[selected.selector], '1');
  for (const other of ['SECURESHOP_STANDALONE_COMMERCE_NATIVE',
    'SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE',
    'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE', 'SECURESHOP_ACCOUNT_AVATAR_NATIVE',
    'SECURESHOP_CUSTOMER_CHECKOUT_NATIVE',
    'SECURESHOP_CUSTOMER_PROFILE_NATIVE', 'SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE',
    'SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE', 'SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE',
    'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE', 'SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE',
    'SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE',
    'SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE', 'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE',
    'SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_NATIVE']) {
    if (other !== selected.selector) assert.equal(env[other], undefined);
  }
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.NODE_ENV, 'test');
  assert.equal(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE, workspace);
  assert.equal(workspace, process.cwd());
  if (env.SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION !== undefined) {
    assert.equal(selected.cohort, COHORT);
    assert.equal(env.SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION,
      path.join(workspace, 'tasks/qualification/commerce-policy-renderer/admission.json'));
  }
  const run = path.dirname(evidencePath);
  assert.equal(path.dirname(run), path.join(workspace, 'tasks/qualification'));
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  assert.equal(evidencePath, path.join(run, selected.receipt));
  const tempRoot = path.join(run, 'runtime/tmp');
  assert.equal(env.TMPDIR, tempRoot);
  assert.equal(env.MAC_CHROMIUM_TMPDIR, tempRoot);
  assert.equal(env[`${PREFIX}BROWSER_RECORD_PATH`],
    path.join(run, selected.birth));
  assert.equal(env[`${PREFIX}BROWSER_ACK_PATH`],
    path.join(run, selected.ack));
  assert.match(env[`${PREFIX}BROWSER_SHA256`], SHA256);
  assert.match(env[`${PREFIX}SNAPSHOT_SHA256`], SHA256);
  assert.match(env[`${PREFIX}BUILD_SHA256`], SHA256);
  assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
    path.join(workspace, 'tests/postgres/secureshop_darwin_browser_birth.py'));
  assert.ok(path.isAbsolute(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON));
  assert.equal(fs.realpathSync(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON),
    env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON);
  assert.equal(executablePath, env.PUPPETEER_EXECUTABLE_PATH);
  assert.equal(fs.realpathSync(executablePath), executablePath);
  assert.equal(env.SECURESHOP_STANDALONE_COMMERCE_BUILD || path.join(workspace, 'client/build'),
    path.join(workspace, 'client/build'));
  if (variant === 'customer-checkout') assert.equal(env.SECURESHOP_CUSTOMER_CHECKOUT_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-manual-checkout') assert.equal(env.SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-out-of-stock') assert.equal(env.SECURESHOP_CUSTOMER_OUT_OF_STOCK_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-product-details') assert.equal(env.SECURESHOP_CUSTOMER_PRODUCT_DETAILS_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-refund-handoff') assert.equal(env.SECURESHOP_CUSTOMER_REFUND_HANDOFF_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-profile') assert.equal(env.SECURESHOP_CUSTOMER_PROFILE_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-cart-lifecycle') assert.equal(env.SECURESHOP_CUSTOMER_CART_LIFECYCLE_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-payment-setup') assert.equal(env.SECURESHOP_CUSTOMER_PAYMENT_SETUP_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-older-orders') assert.equal(env.SECURESHOP_CUSTOMER_OLDER_ORDERS_BUILD,
    path.join(workspace, 'client/build'));
  if (variant === 'customer-checkout-fences') assert.equal(env.SECURESHOP_CUSTOMER_CHECKOUT_FENCES_BUILD,
    path.join(workspace, 'client/build'));
  for (const directory of [run, path.join(run, 'runtime'), tempRoot]) privateDirectory(directory);
  const verifyBuild = async () => {
    const inventory = await buildInventory(path.join(workspace, 'client/build'));
    assert.equal(inventory.sha256, env[`${PREFIX}BUILD_SHA256`],
      'commerce existing production build pin mismatch');
  };
  await verifyBuild();
  assert(/^(0|[1-9]\d*)$/.test(env[`${PREFIX}ADMISSION_FD`] || '')
    && Number.isSafeInteger(Number(env[`${PREFIX}ADMISSION_FD`]))
    && Number(env[`${PREFIX}ADMISSION_FD`]) > 2,
  'commerce inherited admission pipe required');
  const grant = await readInheritedFifoGrant(env, `${PREFIX}ADMISSION_FD`, 'Commerce');
  validateCommerceGrant(grant, { workspace, evidencePath,
    buildSha256: env[`${PREFIX}BUILD_SHA256`], snapshotSha256: env[`${PREFIX}SNAPSHOT_SHA256`],
    chromium: executablePath, chromiumSha256: env[`${PREFIX}BROWSER_SHA256`],
    launcherPid: process.ppid, workerPid: process.pid, variant });

  function browserArgs({ profile, origin, externalMail = false }) {
    privateDirectory(profile);
    assert.equal(path.dirname(profile), tempRoot);
    const profilePrefix = selected.profile || 'owasp-ai-goat-standalone-commerce-';
    assert.ok(path.basename(profile).startsWith(profilePrefix));
    assert.match(path.basename(profile).slice(profilePrefix.length), /^[A-Za-z0-9_-]+$/);
    const target = new URL(origin);
    assert.equal(target.origin, origin);
    assert.equal(target.protocol, 'http:');
    assert.equal(target.hostname, '127.0.0.1');
    assert.match(target.port, /^[1-9]\d{0,4}$/);
    assert.ok(Number(target.port) <= 65535);
    // Dedicated original-commerce opt-in only. This is configured proxy/DNS
    // routing, not a claim of browser-wide or kernel network confinement.
    assert.equal(typeof externalMail, 'boolean');
    if (externalMail) {
      assert.equal(variant, undefined);
      assert.equal(env.SECURESHOP_STANDALONE_COMMERCE_NATIVE, '1');
      assert.equal(env.SECURESHOP_EXTERNAL_MAIL_RENDERED_SEND, '1');
    }
    const hosts = externalMail ? ';sharklasers.com;www.sharklasers.com;www.guerrillamail.com' : '';
    const dns = externalMail ? ', EXCLUDE sharklasers.com, EXCLUDE www.sharklasers.com, EXCLUDE www.guerrillamail.com' : '';
    return ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
      '--disable-domain-reliability', '--disable-quic',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--proxy-server=http://blocked.invalid:9', `--proxy-bypass-list=127.0.0.1;localhost;[::1]${hosts}`,
      `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]${dns}`];
  }

  function watchBrowserTargets(browser) {
    let expectedPageCreations = 0;
    let unexpectedTarget = null;
    browser.on('targetcreated', target => {
      if (target.type() === 'page' && expectedPageCreations > 0) {
        expectedPageCreations -= 1;
        return;
      }
      unexpectedTarget ||= target.type();
      // The fixture has four explicitly admitted pages. A popup has
      // no authorized request policy and must not stay open.
      if (target.type() === 'page') void target.page().then(page => page?.close()).catch(() => {});
    });
    return {
      async newPage(context) {
        expectedPageCreations += 1;
        try {
          const page = await context.newPage();
          assert.equal(expectedPageCreations, 0, 'commerce page birth not observed');
          assert.equal(unexpectedTarget, null, 'unexpected commerce browser target');
          return page;
        } catch (error) {
          expectedPageCreations = 0;
          throw error;
        }
      },
      assertNoUnexpectedTargets() {
        assert.equal(expectedPageCreations, 0);
        assert.equal(unexpectedTarget, null, 'unexpected commerce browser target');
      },
    };
  }

  async function guardPageRequests(page, origin) {
    const target = new URL(origin);
    assert.equal(target.origin, origin);
    assert.equal(target.protocol, 'http:');
    assert.equal(target.hostname, '127.0.0.1');
    await page.setRequestInterception(true);
    page.on('request', request => {
      let allowed = false;
      try { allowed = new URL(request.url()).origin === origin; } catch { /* deny malformed URL */ }
      return allowed ? request.continue() : request.abort();
    });
  }

  async function acknowledgeBrowser({ browser, profile }) {
    privateDirectory(profile);
    assert.equal(path.dirname(profile), tempRoot);
    const pid = browser.process()?.pid;
    assert.ok(Number.isSafeInteger(pid) && pid > 1);
    const record = captureBrowserRecord({ root: workspace, kind: selected.kind,
      pid, executablePath, executableSha256: env[`${PREFIX}BROWSER_SHA256`] });
    const recordPath = env[`${PREFIX}BROWSER_RECORD_PATH`];
    const temporary = `${recordPath}.${process.pid}.tmp`;
    await fs.promises.writeFile(temporary, `${JSON.stringify(record)}\n`, { flag: 'wx', mode: 0o600 });
    await fs.promises.rename(temporary, recordPath);
    const expected = createHash('sha256').update(await fs.promises.readFile(recordPath)).digest('hex');
    const until = Date.now() + 15000;
    while (Date.now() < until) {
      let value;
      try { value = JSON.parse(await fs.promises.readFile(env[`${PREFIX}BROWSER_ACK_PATH`], 'utf8')); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        await new Promise(resolve => setTimeout(resolve, 25));
        continue;
      }
      const info = await fs.promises.lstat(env[`${PREFIX}BROWSER_ACK_PATH`]);
      assert.ok(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
        && (info.mode & 0o777) === 0o600);
      assert.deepEqual(value, { schemaVersion: 1, recordSha256: expected, parentPid: process.pid,
        browserPid: pid, profile });
      return;
    }
    throw new Error('Commerce independent live browser capture acknowledgement unavailable');
  }
  return { browserArgs, watchBrowserTargets, guardPageRequests, acknowledgeBrowser, verifyBuild };
}

module.exports = { admitCommerceBrowser, validateCommerceGrant,
  observeProductRequests, readBoundedProductError, observeOriginalListingReadiness,
  exactConsequenceDialogButton, practiceSnapshotMetadata, practiceSummaryReference };
