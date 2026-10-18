'use strict';
// Reusable authenticated entry only. The ten semantic cases remain pending;
// opening the real frame is never an objective completion assertion.
const assert = require('node:assert/strict');
const { QUALIFIED_OBJECTIVE_IDS, WORKSHOP_KEY } = require('../../server/config/secureshopCurriculum');
function assertCanonicalSecureShopChallenge(body) {
  assert.equal(body?.success, true);assert.ok(Array.isArray(body.challenges));
  const matches = body.challenges.filter(row => row.workshopKey === WORKSHOP_KEY || row.id === WORKSHOP_KEY);
  assert.equal(matches.length, 1, 'Exactly one visible SecureShop challenge');
  const challenge = matches[0];assert.ok(Array.isArray(challenge.objectives));
  assert.deepEqual(challenge.objectives.map(row => row.id).sort(), [...QUALIFIED_OBJECTIVE_IDS].sort());
  assert.equal(challenge.totalObjectives, QUALIFIED_OBJECTIVE_IDS.length);
  return challenge;
}
function pendingSecureShopCoverage() {
  return Object.freeze({ scope: 'secureshop_authenticated_rendered_entry', qualified: false,
    objectives: Object.freeze(QUALIFIED_OBJECTIVE_IDS.map(id => Object.freeze({ id, status: 'pending' }))) });
}
async function openRenderedSecureShopSession({ browser, origin, user, password, verifySession, timeoutMs = 15000 }) {
  assert.equal(typeof verifySession, 'function');assert.ok(Number.isSafeInteger(user?.id));
  const url = new URL(origin);assert.equal(url.origin, origin);assert.equal(url.protocol, 'http:');assert.equal(url.hostname, '127.0.0.1');assert.ok(url.port);
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 60000);
  const context = await browser.createBrowserContext();
  try {
    const page = await context.newPage();page.setDefaultTimeout(timeoutMs);
    await page.setRequestInterception(true);
    const onRequest = request => {
      const target = new URL(request.url());
      const action = target.origin === origin || target.protocol === 'data:' ? request.continue() : request.abort('blockedbyclient');
      // Context closure can race interception completion; errors are handled.
      void action.catch(() => {});
    };
    page.on('request', onRequest);
    const matches = (response, pathname, method) => new URL(response.url()).origin === origin
      && new URL(response.url()).pathname === pathname && response.request().method() === method;
    await page.goto(origin + '/workshop-login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
    await page.waitForSelector('input[placeholder="Enter your password"]', { visible: true });
    await page.type('input[placeholder="Enter your username"]', user.username);
    await page.type('input[placeholder="Enter your password"]', password);
    const login = page.waitForResponse(response => matches(response, '/api/auth/login', 'POST'));
    void login.catch(() => {});
    await page.click('button[type="submit"]');
    const response = await login;assert.equal(response.status(), 200);
    const authenticated = await response.json();assert.equal(Number(authenticated.user.id), user.id);
    await verifySession(authenticated.token, user.id);
    const catalog = page.waitForResponse(response => matches(response, '/api/workshop/challenges', 'GET'));
    void catalog.catch(() => {});
    await page.goto(origin + '/workshop/secureshop', { waitUntil: 'domcontentloaded' });
    const catalogResponse = await catalog;
    // First request in this fresh context must provide body evidence; do not
    // accept an unbound 304 as a successful catalog read.
    assert.equal(catalogResponse.status(), 200);
    const challenge = assertCanonicalSecureShopChallenge(await catalogResponse.json());
    const element = await page.waitForSelector('iframe[title="SecureShop workshop"]', { visible: true });
    const frame = await element.contentFrame();assert.ok(frame);
    await frame.waitForFunction(() => window.origin === 'null', { polling: 100 });
    return Object.freeze({ page, frame, challenge, coverage: pendingSecureShopCoverage(),
      // Credentials remain private in the browser/login verifier; never expose
      // or replace the server-issued launch bearer from this helper.
      close: () => context.close() });
  } catch (error) {
    try { await context.close(); } catch (cleanup) { throw new AggregateError([error,cleanup], 'SecureShop entry and cleanup failed'); }
    throw error;
  }
}
module.exports = { assertCanonicalSecureShopChallenge, pendingSecureShopCoverage, openRenderedSecureShopSession };
