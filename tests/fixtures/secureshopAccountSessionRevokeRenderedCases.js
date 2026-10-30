'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

const SCOPE = 'standalone-account-session-revoke-rendered-v1';
const CURRENT_SCOPE = 'standalone-account-current-session-revoke-rendered-v2';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function revokePath(id) {
  assert.equal(typeof id, 'string');
  assert.match(id, UUID);
  return `/api/secureshop/v2/auth/users/me/sessions/${id}/revoke`;
}

function assertReceipt(row) {
  assert(row && Object.getPrototypeOf(row) === Object.prototype);
  assert.deepEqual(Object.keys(row).sort(), ['scope', 'version', 'passed', 'physical', 'state',
    'authority', 'recovery', 'sibling', 'calls'].sort());
  assert.equal(row.version, 1);
  assert.equal(row.scope, SCOPE);
  assert.equal(row.passed, true);
  assert.deepEqual(row.physical, { cancelPosts: 0, preConfirmPosts: 0,
    confirmedPosts: 1, foreignDeniedPosts: 1, confirmedStatus: 200, selectedDialogExact: true,
    browserAckLost: true, serverReplySha256: row.physical?.serverReplySha256 });
  assert.match(row.physical.serverReplySha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(row.state, { twoSameLaunchSessions: true, selectedRevoked: true,
    currentRetained: true, selectedTokenDenied: true, currentTokenAccepted: true,
    auditBound: true });
  assert.deepEqual(row.authority, { capturedBrowserBearer: true,
    sameLaunchOwnerSession: true, foreignSessionDenied: true, foreignHttpDenied: true });
  assert.deepEqual(row.recovery, { operationIdAvailable: false,
    explicitSessionsGet: true, noSecondPost: true });
  assert.deepEqual(row.sibling, { preexistingNonempty: true, unchanged: true });
  assert.deepEqual(row.calls, { model: 0, judge: 0, credit: 0 });
  return true;
}

function assertCurrentReceipt(row) {
  assert(row && Object.getPrototypeOf(row) === Object.prototype);
  assert.deepEqual(Object.keys(row).sort(), ['scope', 'version', 'passed', 'physical', 'state',
    'authority', 'recovery', 'sibling', 'calls'].sort());
  assert.equal(row.version, 2);
  assert.equal(row.scope, CURRENT_SCOPE);
  assert.equal(row.passed, true);
  assert.deepEqual(row.physical, { cancelPosts: 0, preConfirmPosts: 0,
    confirmedPosts: 1, foreignDeniedPosts: 1, confirmedStatus: 200,
    selectedDialogExact: true });
  assert.deepEqual(row.state, { originalCurrentRevoked: true,
    originalTokenDenied: true, freshAuthAccepted: true, freshSessionDistinct: true,
    auditBound: true });
  assert.deepEqual(row.authority, { capturedBrowserBearer: true,
    exactCurrentSession: true, sameOriginalLaunchOwnerSession: true,
    foreignSessionDenied: true, foreignHttpDenied: true });
  assert.deepEqual(row.recovery, { operationIdAvailable: false,
    browserConfirmedReply: true, noSecondPost: true });
  assert.deepEqual(row.sibling, { preexistingNonempty: true, unchanged: true });
  assert.deepEqual(row.calls, { model: 0, judge: 0, credit: 0 });
  return true;
}

// The callback must return the browser's genuine selected row. A caller cannot
// make a different session pass merely by changing the expected text.
function selectedRow(row, expected) {
  assert(row && expected && typeof row === 'object' && typeof expected === 'object');
  assert.equal(row.id, expected.id);
  assert.equal(row.is_current, false);
  assert.equal(row.user_agent, expected.user_agent);
  assert.equal(row.ip, expected.ip);
  assert.match(row.id, UUID);
  return Object.freeze({ id: row.id, userAgent: row.user_agent, ip: row.ip });
}

function selectedCurrentRow(row, expected) {
  assert(row && expected && typeof row === 'object' && typeof expected === 'object');
  assert.equal(row.id, expected.id);
  assert.equal(row.is_current, true);
  assert.equal(row.user_agent, expected.user_agent);
  assert.equal(row.ip, expected.ip);
  assert.match(row.id, UUID);
  return Object.freeze({ id: row.id, userAgent: row.user_agent || 'Unknown browser',
    ip: row.ip || 'unknown IP' });
}

async function capturePhysicalResponse(page, predicate, click, timeout = 20000) {
  assert.equal(typeof page?.waitForResponse, 'function');
  assert.equal(typeof predicate, 'function');
  assert.equal(typeof click, 'function');
  assert(Number.isSafeInteger(timeout) && timeout > 0 && timeout <= 20000);
  const controller = new AbortController();
  // Observe rejection before a physical locator can spend its full timeout.
  // Always retire this waiter; an unsuccessful click cannot leave a listener
  // that later mistakes another operation's response for this confirmation.
  const pending = page.waitForResponse(predicate, { timeout, signal: controller.signal })
    .then(value => ({ value }), error => ({ error }));
  try {
    await click();
    const result = await pending;
    if (result.error) throw result.error;
    return result.value;
  } finally {
    controller.abort();
    await pending;
  }
}

async function admitAccountAfterPhysicalLogin({ page, origin, buyerName, buyerId,
  authenticate, findAccountFrame }) {
  assert(page && typeof page.waitForFunction === 'function' && typeof page.cookies === 'function');
  assert.equal(typeof authenticate, 'function');
  assert.equal(typeof findAccountFrame, 'function');
  try {
    await page.waitForFunction(() => location.pathname === '/secureshop/account', { timeout: 20000 });
  } catch {
    const pathname = new URL(page.url()).pathname;
    const route = ['/secureshop/login', '/secureshop/home', '/secureshop/account'].includes(pathname)
      ? pathname : 'other';
    throw Error(`Completed account navigation unavailable: ${route}`);
  }
  const cookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
    .find(value => value.name === 'owasp_ai_goat_shop_session');
  assert.equal(cookie?.httpOnly, true, 'completed shop login cookie required');
  const buyer = await authenticate(cookie.value);
  assert.equal(buyer?.shopUserId, buyerId, 'authenticated exact buyer required');
  assert.equal(buyer?.username, buyerName, 'authenticated exact buyer required');
  assert.equal(buyer?.role, 'customer', 'authenticated customer required');
  return findAccountFrame(page, buyerName);
}

async function loseOneCompletedAck(page, endpoint) {
  const cdp = await page.createCDPSession(); let found = null; let failure = null;
  const pending = new Set();
  const onPaused = event => {
    const task = (async () => {
      if (event.request.url === endpoint && event.request.method === 'POST' && !found) {
        assert.equal(event.responseStatusCode, 200, 'loss only after genuine server completion');
        const reply = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
        const bytes = Buffer.from(reply.body, reply.base64Encoded ? 'base64' : 'utf8');
        assert(bytes.length > 0 && bytes.length <= 4096, 'bounded real server reply required');
        assert.deepEqual(JSON.parse(bytes.toString('utf8')), { ok: true });
        found = { status: event.responseStatusCode,
          replySha256: createHash('sha256').update(bytes).digest('hex') };
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(async error => { failure = error;
      try { await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }); }
      catch (cleanupError) { failure = new AggregateError([error, cleanupError], 'CDP response retirement failed'); }
    });
    pending.add(task); void task.finally(() => pending.delete(task));
  };
  cdp.on('Fetch.requestPaused', onPaused);
  try { await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] }); }
  catch (error) {
    try { cdp.off('Fetch.requestPaused', onPaused); await cdp.detach(); }
    catch (cleanupError) { throw new AggregateError([error, cleanupError], 'CDP setup retirement failed'); }
    throw error;
  }
  return { observed: () => { if (failure) throw failure; return found; },
    async close() {
      const errors = [];
      try { await Promise.all([...pending]); } catch (error) { errors.push(error); }
      try { await cdp.send('Fetch.disable'); } catch (error) { errors.push(error); }
      try { cdp.off('Fetch.requestPaused', onPaused); } catch (error) { errors.push(error); }
      try { await cdp.detach(); } catch (error) { errors.push(error); }
      if (failure) errors.unshift(failure);
      if (errors.length) throw new AggregateError(errors, 'CDP response retirement failed');
    } };
}

module.exports = { SCOPE, CURRENT_SCOPE, revokePath, assertReceipt, assertCurrentReceipt,
  selectedRow, selectedCurrentRow, capturePhysicalResponse,
  admitAccountAfterPhysicalLogin, loseOneCompletedAck };
