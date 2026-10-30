'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os'); const fs = require('node:fs'); const path = require('node:path');
const { browserNetworkPolicy, cleanBrowserEnvironment, networkProbeSource } = require('./fixtures/fullBackendBrowserNetworkPolicy');
test('network policy permits only exact proxy egress and exact DevTools listener', () => {
  const policy = browserNetworkPolicy({ proxyPort: 12345, devtoolsPort: 12346 });
  assert.ok(policy.indexOf('(deny network*)') < policy.indexOf('(allow network-outbound'));
  assert.deepEqual(policy.match(/\(allow network-[^\n]+/g), [
    '(allow network-outbound (remote tcp "localhost:12345"))',
    '(allow network-bind (local tcp "localhost:12346"))',
    '(allow network-inbound (local tcp "localhost:12346"))',
  ]);
  for (const bad of [0, 80, 65536, '12345', '12345") (allow network*)', NaN]) assert.throws(() => browserNetworkPolicy({ proxyPort: bad, devtoolsPort: 12346 }));
  assert.throws(() => browserNetworkPolicy({ proxyPort: 12345, devtoolsPort: 12345 }));
});
test('clean child environment excludes inherited credential and loader variables', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-policy-test-')));
  try {
    assert.deepEqual(Object.keys(cleanBrowserEnvironment(root)).sort(), ['HOME','PATH','TEMP','TMP','TMPDIR']);
    assert.throws(() => cleanBrowserEnvironment('relative'));
    fs.symlinkSync(root, path.join(root, 'link')); assert.throws(() => cleanBrowserEnvironment(path.join(root, 'link')));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('OS probe distinguishes policy denial from an absent listener', () => {
  const source = networkProbeSource({ proxyPort: 12345, deniedPort: 12347 });
  assert.doesNotThrow(() => new Function(source));
  assert.match(source, /\['EPERM','EACCES'\]\.includes\(denied\)/);
  assert.doesNotMatch(source, /ECONNREFUSED/);
  assert.match(source, /connect\(443,'192\.0\.2\.1'\)/);
  assert.match(source, /externalDeniedByPolicy:\['EPERM','EACCES'\]\.includes\(external\)/);
  assert.throws(() => networkProbeSource({ proxyPort: 12345, deniedPort: 12345 }));
});
