/**
 * Tiny fake external MCP server for chain tests.
 *
 * Not a real MCP over SSE — that would require the SDK client-side too. We
 * expose:
 *   GET /mcp/list_tools  → returns { tools: [...] } (the same shape the
 *                           mcp-registry.register() SSE probe expects)
 *   POST /mcp/call/:name → returns { content: [{type,text}] } — scripted
 *                           tool output for chain tests.
 *
 * Consumers pass a `scripted` map: { [toolName]: (args) => text }.
 */

const http = require('node:http');

async function startFakeExternalMcp({ tools = [], scripted = {} } = {}) {
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/mcp/list_tools') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ tools }));
      return;
    }
    const callMatch = req.url && req.url.match(/^\/mcp\/call\/([\w-]+)$/);
    if (req.method === 'POST' && callMatch) {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const toolName = callMatch[1];
        let args = {};
        try { args = JSON.parse(body || '{}'); } catch {}
        const fn = scripted[toolName];
        const text = fn ? fn(args) : `no scripted output for ${toolName}`;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ content: [{ type: 'text', text }] }));
      });
      return;
    }
    res.writeHead(404); res.end();
  });

  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    server,
    port,
    url: `http://127.0.0.1:${port}`,
    close() { return new Promise(r => server.close(r)); },
  };
}

module.exports = { startFakeExternalMcp };
