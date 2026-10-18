const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

test('DPI browser and dev/preview proxies outlast the existing bounded owner run', async () => {
  const route = fs.readFileSync(path.join(__dirname, '../server/routes/promptInjectionWorkshop.js'), 'utf8');
  const client = fs.readFileSync(path.join(__dirname, '../client/src/pages/challenges/DirectPromptInjectionChallenge.js'), 'utf8');
  const owner = Number(route.match(/family: 'DPI', defaultTimeoutMs: (\d+)/)[1]);
  const send = client.slice(client.indexOf("axios.post('/api/workshop/prompt-injection/chat'"));
  const request = Number(send.match(/timeout: (\d+)/)[1]);
  assert.equal(owner, 300000, 'do not extend the owner run to accommodate transport');
  assert.ok(60000 + 120000 + 90000 < owner, 'decoder, final answer and Judge fit within the owner deadline');
  assert.ok(request > owner && request <= owner + 30000, 'browser can receive an owned terminal result');
  const { default: configure } = await import(pathToFileURL(path.resolve(__dirname, '../client/vite.config.mjs')));
  const config = configure({command:'serve', mode:'development'});
  for (const surface of ['server', 'preview']) {
    const proxy = config[surface].proxy['/api/workshop/prompt-injection/chat'];
    assert.ok(proxy.timeout > request && proxy.timeout <= request + 30000);
    assert.equal(proxy.proxyTimeout, proxy.timeout);
  }
});
