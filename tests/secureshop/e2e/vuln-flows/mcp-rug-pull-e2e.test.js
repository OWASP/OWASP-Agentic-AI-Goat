/**
 * @intentional-vulnerability mcp02-rug-pull
 * @teaches OWASP-MCP:MCP-03
 * @location agent-host/agents/mcp-registry/tools/index.js
 * @location client/src/pages/secureshop/pages/admin/MCP.jsx
 *
 * Puppeteer E2E — admin registers a benign MCP server, then forces a
 * schema-hash change (via the test helper endpoint). Reloading the /admin/mcp
 * page shows the schema-hash timeline with a rust-highlighted node reflecting
 * the change.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { bootE2eServer, launchE2eBrowser } = require('../../fixtures/e2eServer.js');

test('e2e/mcp-rug-pull: schema-hash timeline shows rust-highlighted change node after forced schema flip', {timeout:90000}, async t => {
  const previousHelpers=process.env.SS_E2E_HELPERS;t.after(()=>{if(previousHelpers===undefined)delete process.env.SS_E2E_HELPERS;else process.env.SS_E2E_HELPERS=previousHelpers;});
  process.env.SS_E2E_HELPERS = '1';
  const server = await bootE2eServer({test:t});
  const {browser,close:closeBrowser} = await launchE2eBrowser(t,server);
  try {
    // ---- Step 1: register a benign MCP via the API ----------------------
    let r = await fetch(`${server.baseUrl}/api/secureshop/admin/mcp/register`, {
      signal: AbortSignal.timeout(10000),
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'weather-mcp',
        url: 'http://127.0.0.1:1',
        tools: [{ name: 'ping', description: 'pong' }],
      }),
    });
    assert.equal(r.status, 200);

    // ---- Step 2: force a schema change (the rug-pull) -------------------
    r = await fetch(`${server.baseUrl}/api/secureshop/_test/force-schema-change`, {
      signal: AbortSignal.timeout(10000),
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'weather-mcp' }),
    });
    assert.equal(r.status, 200);

    // ---- Step 3: open /admin/mcp with role=admin ------------------------
    // Wave 2A wrapped /secureshop/v2/admin/* in <RequireAuth>. Seed the v2
    // auth token BEFORE navigation so the SPA hydrates as student_a (admin).
    const page = await browser.newPage();
    await page.evaluateOnNewDocument(() => {
      try { localStorage.setItem('secureshop_v2_token', 'e2e:student_a'); } catch {}
    });
    await page.goto(`${server.baseUrl}/secureshop/v2/`, { waitUntil: 'networkidle0', timeout: 30000 });
    await page.setCookie({
      name: 'ss_role', value: 'admin',
      domain: '127.0.0.1', path: '/', httpOnly: false, secure: false,
    });
    await page.goto(`${server.baseUrl}/secureshop/v2/admin/mcp`, {
      waitUntil: 'networkidle0',
      timeout: 30000,
    });

    // Wait for the timeline section to render — the MCP page renders the
    // "Schema-hash timeline" heading if there is any history.
    await page.waitForFunction(
      () => Array.from(document.querySelectorAll('h2')).some(h => /Schema-hash timeline/i.test(h.innerText)),
      { timeout: 15000 },
    );

    // ---- Step 4: assert a rust-colored TimelineDot is present ----------
    // Wave 2C's MCP.jsx renders TimelineDot as a <motion.div> with inline
    // style `background: var(--rust)` when node.changed is true. Scan every
    // element on the page for that literal inline style — the rug-pull
    // marker is what we care about.
    const rugPullDetected = await page.evaluate(() => {
      const nodes = Array.from(document.querySelectorAll('*'));
      return nodes.some(n => {
        const s = n.getAttribute && n.getAttribute('style');
        return s && /background:\s*var\(--rust\)/i.test(s);
      });
    });
    assert.equal(rugPullDetected, true,
      'schema-hash timeline shows a rust-highlighted (changed) node — rug-pull visible in UI');
  } finally {
    try { await closeBrowser(); } finally { await server.close(); }
  }
});
