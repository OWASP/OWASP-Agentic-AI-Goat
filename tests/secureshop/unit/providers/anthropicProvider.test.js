const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../../..');
const { AnthropicProvider } = require(path.join(REPO, 'server/services/secureshop/providers/anthropicProvider.js'));

function fakeAnthropic(port, response) {
  const srv = http.createServer((req, res) => {
    let body = ''; req.on('data', c => body += c);
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(response));
    });
  });
  return new Promise((r) => srv.listen(port, () => r(srv)));
}

test('AnthropicProvider maps tool_use blocks to unified shape', async () => {
  const srv = await fakeAnthropic(15100, {
    content: [{ type: 'tool_use', id: 'toolu_1', name: 'product-search.search', input: { q: 'x' } }],
    stop_reason: 'tool_use',
  });
  const p = new AnthropicProvider({ apiKey: 'sk-test', baseUrl: 'http://127.0.0.1:15100' });
  const r = await p.chat({ system: 'sys', messages: [{ role: 'user', content: 'find' }], tools: [{ agent: 'product-search', tool: 'search', description: '', inputSchema: {} }], role: 'customer' });
  assert.equal(r.stop_reason, 'tool_use');
  assert.equal(r.tool_uses[0].name, 'product-search.search');
  assert.deepEqual(r.tool_uses[0].args, { q: 'x' });
  srv.close();
});

test('AnthropicProvider maps text blocks to end_turn', async () => {
  const srv = await fakeAnthropic(15101, {
    content: [{ type: 'text', text: 'hello' }],
    stop_reason: 'end_turn',
  });
  const p = new AnthropicProvider({ apiKey: 'sk-test', baseUrl: 'http://127.0.0.1:15101' });
  const r = await p.chat({ system: '', messages: [], tools: [], role: 'customer' });
  assert.equal(r.stop_reason, 'end_turn');
  assert.equal(r.text, 'hello');
  srv.close();
});
