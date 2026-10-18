const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability xss-reflected-search
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/product-search/tools/search.js
 * @location client/src/pages/secureshop/components/AgentLane/Turn.jsx
 *
 * The product-search.search tool echoes the raw query into echo_html
 * (unit-level sink). The AgentLane Turn component renders the supervisor
 * reply via dangerouslySetInnerHTML (DOM-level sink). Together these give
 * a reflected-XSS end-to-end: chat "search for <script>window.__reflected=1
 * </script>", the tool echoes the raw query, the supervisor forwards it into
 * the assistant_message, and the client renders it as HTML.
 */
test('xss-reflected-search: search response echoes raw query into echo_html', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { search } = require(path.join(REPO, 'agent-host/agents/product-search/tools/search.js'));
    const payload = `<script>alert('rXSS')</script>`;
    const r = await search({ query: payload });
    assert.match(r.echo_html, /<script>alert\('rXSS'\)<\/script>/);
    assert.ok(!/&lt;script&gt;/.test(r.echo_html), 'query must not be HTML-escaped');
  } finally {
    await s.close();
  }
});

test('xss-reflected-search: end-to-end via customerSupervisor SSE stream', async t => {
  const s = await seedShop();
  t.after(async () => { await s.close(); });
  const a = await seedAgents();
  t.after(async () => { await a.close(); });
  purgeToolCaches();
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'isolated-reflected-search-secret';
  const token = jwt.sign({ id: 1, role: 'customer', username: 'fixture' }, process.env.JWT_SECRET, { algorithm: 'HS256' });

  const { bootTestStack } = require(path.join(REPO, 'tests/secureshop/fixtures/bootTestStack.js'));
  const boot = await bootTestStack({ port: 8291 });
  try {
    // Script the supervisor: call product-search.search, then reflect the
    // tool_result content verbatim in the assistant_message. This models the
    // real vulnerability shape — the LLM parrots the query back inside its
    // final reply, and the UI renders it via dangerouslySetInnerHTML.
    const provider = boot.provider;
    provider.script([
      { stop: 'tool_use', tool_uses: [{
        name: 'product-search.search',
        args: { query: `<script>window.__reflected=1</script>` },
      }] },
      {
        stop: 'end_turn_reactive',
        textMatcher: (toolContent) => {
          // The MockProvider passes the last tool result content back to us;
          // include it verbatim in the reply. That's how a real vulnerable
          // supervisor answers "reflect the search echo".
          return `Search results:\n\n${toolContent}`;
        },
      },
    ]);

    // Boot the customer route on an ephemeral port.
    const app = express();
    app.use(bodyParser.json({ limit: '2mb' }));
    const buildRouter = require(path.join(REPO, 'server/routes/secureshop/customer.js'));
    app.use('/api/secureshop', buildRouter({
      pool: boot.pool, manifest: boot.manifest, provider,
    }));
    const server = app.listen(0);
    await new Promise((r) => server.once('listening', r));
    const port = server.address().port;

    try {
      // 1. Create a session.
      const sess = await new Promise((resolve, reject) => {
        const req = http.request({
          method: 'POST', hostname: '127.0.0.1', port,
          path: '/api/secureshop/agents/customer/session',
          headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
        }, (res) => {
          let buf = ''; res.on('data', (c) => buf += c);
          res.on('end', () => resolve(JSON.parse(buf)));
        });
        req.on('error', reject);
        req.write(JSON.stringify({ userId: 1 }));
        req.end();
      });
      const sessionId = sess.sessionId;

      // 2. Send a chat message and consume the SSE stream.
      const streamBody = await new Promise((resolve, reject) => {
        const req = http.request({
          method: 'POST', hostname: '127.0.0.1', port,
          path: '/api/secureshop/agents/customer/chat',
          headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
        }, (res) => {
          let buf = ''; res.on('data', (c) => buf += c.toString('utf8'));
          res.on('end', () => resolve(buf));
        });
        req.on('error', reject);
        req.write(JSON.stringify({
          sessionId,
          message: `search for <script>window.__reflected=1</script> laptops`,
        }));
        req.end();
      });

      // 3. Assert the reflected payload survives all the way into the
      //    assistant_message SSE frame the browser would consume.
      assert.match(streamBody, /event: assistant_message/);
      assert.match(
        streamBody,
        /<script>window.__reflected=1<\/script>/,
        'assistant_message must contain the raw echoed <script> payload',
      );
      assert.ok(
        !/&lt;script&gt;/.test(streamBody),
        'stream body must NOT contain HTML-escaped <script>',
      );

      // Wave 5A F10 — the tool_result SSE frame carries the raw echo_html
      // field verbatim (nested inside the MCP { content: [{ text: JSON }] }
      // envelope, so it appears as `\"echo_html\"` in the raw SSE stream).
      // The HopDetailSheet client component reads that field and renders it
      // via dangerouslySetInnerHTML. Assert the field is present in the
      // stream so the client-side render surface is fed.
      assert.match(streamBody, /event: tool_result/);
      assert.match(streamBody, /echo_html/,
        'tool_result frame must expose echo_html to the client');
      assert.match(streamBody, /<b><script>window\.__reflected=1<\/script><\/b>/,
        'echo_html wraps the raw <script> payload — client renders as live DOM');
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  } finally {
    await boot.close();
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  }
});

test('xss-reflected-search: F10 — HopDetailSheet extracts echo_html for dangerouslySetInnerHTML', async () => {
  // Serialized-DOM assertion: verify the _pickEchoHtml helper picks the
  // echo_html field out of both possible tool-result envelopes (bare object
  // and MCP { content: [{ type: 'text', text: JSON }] } shape). This is
  // deliberately a unit test, not a full browser render — the DOM sink lives
  // in `dangerouslySetInnerHTML={{ __html: echoHtml }}` in HopDetailSheet.jsx.
  const src = fs.readFileSync(
    path.join(REPO, 'client/src/pages/secureshop/components/AgentLane/HopDetailSheet.jsx'),
    'utf8',
  );
  // Confirm the render surface is wired: dangerouslySetInnerHTML with __html: echoHtml.
  assert.match(src, /dangerouslySetInnerHTML=\{\{\s*__html:\s*String\(echoHtml\)/,
    'HopDetailSheet must render echo_html via dangerouslySetInnerHTML');
  assert.match(src, /_pickEchoHtml/,
    'HopDetailSheet must call _pickEchoHtml on the hop result');
  // Confirm the helper handles both envelope shapes.
  assert.match(src, /result\.echo_html/);
  assert.match(src, /parsed\.echo_html/);
});
