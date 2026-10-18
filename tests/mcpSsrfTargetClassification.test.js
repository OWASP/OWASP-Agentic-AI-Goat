'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const targets = require('../server/services/mcp/targets');
const { McpSandboxShell } = require('../server/services/mcp/sandboxShell');

test('public URL words, spoofed hosts, credentials and unsupported schemes never map to the internal lab', async t => {
  const requests = [];
  t.mock.method(globalThis, 'fetch', async url => { requests.push(url); throw Error('unexpected request'); });
  const shell = new McpSandboxShell('classification-negative');
  for (const url of [
    'https://example.com/api/token?internal=169.254.169.254',
    'https://api.example.com:8080/metadata/instance',
    'http://169.254.169.254.example.com/latest/meta-data',
    'http://localhost.example.com/admin', 'http://monitoring.internal.example.com/health',
    'http://169.254.169.254@example.com/admin', 'http://user:pass@localhost/admin',
    'file:///etc/passwd', 'ftp://127.0.0.1/admin', 'not a URL',
  ]) {
    assert.equal(targets.classifySsrfTarget(url), null, url);
    assert.equal((await targets.fetchViaSsrfTarget(url)).ok, false);
    const result = await shell.toolFetchUrl(url);
    assert.equal(result.achieved, false); assert.equal(result.blocked, true);
  }
  assert.deepEqual(requests, []);
});

test('internal destinations retain intentional SSRF mapping and health remains ungraded', async t => {
  const requests = [], effects = [];
  t.mock.method(globalThis, 'fetch', async url => {
    requests.push(url); return new Response('controlled lab body', { status: 200 });
  });
  const shell = new McpSandboxShell('classification-positive', { allowLegacySsrfFixture: true,
    listener: { append: value => effects.push(value), read: () => effects },
  });
  for (const url of ['http://10.0.1.100:8080/admin', 'http://192.168.1.2/secret',
    'http://172.16.1.2/api', 'http://127.0.0.1/admin', 'http://[::1]/admin',
    'https://api.acme-corp.internal/admin', 'http://localhost./admin']) {
    const result = await shell.toolFetchUrl(url);
    assert.equal(result.achieved, true); assert.equal(result.real, true);
    assert.ok(result.targetUrl.endsWith('/internal/admin'));
  }
  const meta = await shell.toolFetchUrl('http://169.254.169.254/latest/meta-data/iam/security-credentials/');
  assert.equal(meta.achieved, true);
  assert.ok(meta.targetUrl.endsWith('/latest/meta-data/iam/security-credentials/mcp-ops-instance-role'));
  const before = effects.length;
  for (const url of ['http://monitoring.internal/', 'http://10.0.1.100:8080/health?token=x',
    'http://169.254.169.254/health']) {
    const result = await shell.toolFetchUrl(url);
    assert.equal(result.achieved, false); assert.equal(result.real, true);
    assert.ok(result.targetUrl.endsWith('/health'));
  }
  assert.equal(effects.length, before);
  assert.equal(requests.length, 11);
});

test('failed HTTP responses cannot produce an SSRF achievement or listener effect', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response('not found', { status: 404 }));
  const effects = [];
  const shell = new McpSandboxShell('classification-http-error', { allowLegacySsrfFixture: true,
    listener: { append: value => effects.push(value), read: () => effects },
  });
  const result = await shell.toolFetchUrl('http://169.254.169.254/missing');
  assert.equal(result.achieved, false);
  assert.equal(result.real, true);
  assert.match(result.error, /HTTP 404/);
  assert.equal(result.backendDown, undefined);
  assert.deepEqual(effects, []);
});
