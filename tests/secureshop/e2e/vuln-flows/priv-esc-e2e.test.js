/**
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @location server/services/secureshop/supervisors/customerSupervisor.js
 * @location client/src/pages/secureshop/components/RoleSwitcher.jsx
 *
 * Puppeteer E2E — customer session gets escalated to admin via a role-switch
 * API call (mirrors the effect of a prompt-injection-triggered
 * `user-management.set_role` tool call). After the flip, the admin overview
 * page renders visible admin-only content.
 *
 * Rationale: the whole point of LLM06 is that the role change persists across
 * sessions and there's no re-auth gate. We prove that at the UI level by
 * visiting /admin/overview after the escalation and verifying the admin
 * elements render.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { bootE2eServer, launchE2eBrowser } = require('../../fixtures/e2eServer.js');

test('e2e/priv-esc: customer → admin via set-role API → admin overview page accessible', {timeout:90000}, async t => {
  const server = await bootE2eServer({test:t});
  const {browser,close:closeBrowser} = await launchE2eBrowser(t,server);
  try {
    // ---- Step 1: baseline — student_c has role=customer ------------------
    const { rows: [rowBefore] } = await server.state.shop.query(
      `SELECT role FROM secureshop.shop_users WHERE username='student_c'`);
    assert.equal(rowBefore.role, 'customer', 'baseline: student_c starts as customer');

    // ---- Step 2: fire the escalation via the priv-esc API sink -----------
    // The API endpoint mirrors what a jailbroken customer supervisor would
    // achieve by emitting `user-management.set_role({role:"admin"})`.
    const escResp = await fetch(`${server.baseUrl}/api/secureshop/session/set-role`, {
      signal: AbortSignal.timeout(10000),
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'student_c', role: 'admin' }),
    });
    assert.equal(escResp.status, 200);
    const escBody = await escResp.json();
    assert.equal(escBody.role, 'admin');

    // ---- Step 3: DB reflects the flip ------------------------------------
    const { rows: [rowAfter] } = await server.state.shop.query(
      `SELECT role FROM secureshop.shop_users WHERE username='student_c'`);
    assert.equal(rowAfter.role, 'admin', 'priv-esc: student_c is now admin');

    // ---- Step 4: open the SPA authenticated as the now-elevated student_c
    // Wave 2A wrapped /secureshop/v2/admin/* in <RequireAuth>. Seed the v2
    // auth token BEFORE navigation so the SPA hydrates as student_c, who at
    // this point has role=admin (thanks to step 2's priv-esc API call).
    const page = await browser.newPage();
    await page.evaluateOnNewDocument(() => {
      try { localStorage.setItem('secureshop_v2_token', 'e2e:student_c'); } catch {}
    });
    // Point Puppeteer to the origin then also set the legacy ss_role cookie
    // (some Wave-1 UI still reads it as a hint for the AgentLane).
    await page.goto(`${server.baseUrl}/secureshop/v2/`, { waitUntil: 'networkidle0', timeout: 30000 });
    await page.setCookie({
      name: 'ss_role', value: 'admin',
      domain: '127.0.0.1', path: '/', httpOnly: false, secure: false,
    });

    // ---- Step 5: navigate to /admin/overview (was previously locked) ----
    await page.goto(`${server.baseUrl}/secureshop/v2/admin`, {
      waitUntil: 'networkidle0',
      timeout: 30000,
    });

    // The admin overview page should render with at least one admin-only
    // element (e.g. containing the word "Admin" or "Users"). We check for
    // the presence of the "Overview" heading structure the shell renders.
    await page.waitForSelector('.ss-nav__brand', { timeout: 15000 });
    const bodyText = await page.evaluate(() => document.body.innerText);
    // /admin renders SSv2AOverview — look for typical admin-lane copy.
    assert.match(bodyText, /admin/i, 'admin page rendered (contains "admin" text)');
    // Persistence check — hit whoami (v2 auth endpoint) with the token to
    // confirm the elevated role landed server-side too.
    const who = await page.evaluate(() =>
      fetch('/api/secureshop/v2/auth/whoami', {
        signal: AbortSignal.timeout(10000),
        headers: { Authorization: `Bearer ${localStorage.getItem('secureshop_v2_token')}` },
      }).then(r => r.json())
    );
    assert.equal(who.user.role, 'admin', 'v2 whoami confirms elevated role');
  } finally {
    try { await closeBrowser(); } finally { await server.close(); }
  }
});
