'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { parseUrl, run } = require('../sidecars/sandbox-runner/owned-http/worker');
const manifest = require('../sidecars/sandbox-runner/owned-http/network-manifest.json');
test('raw URL parser retains destination path/query and rejects unsupported authority', () => {
  const raw='http://169.254.169.254/latest/meta-data/?role=training';
  assert.equal(parseUrl(raw).href,raw);
  for(const value of ['https://example.test/','file:///etc/passwd','http://user:pass@metadata.training/','http://metadata.training/#x','x'.repeat(2049),null]) assert.throws(()=>parseUrl(value));
});
test('bounded closed worker admission rejects caller-shaped extra authority before sockets',async()=>{
  for(const input of [{url:'http://metadata.training/',mode:'vuln',canary:'a'.repeat(64),address:'127.0.0.1'},{url:'http://metadata.training/',mode:'mock',canary:'a'.repeat(64)},{url:'http://metadata.training/',mode:'vuln',canary:'private data'}]) await assert.rejects(run(input),/invalid_input/);
});
test('compiled listener constants match immutable manifest addresses and ports',()=>{
  const source=fs.readFileSync(require.resolve('../sidecars/sandbox-runner/owned-http/namespace-init.c'),'utf8');
  assert.deepEqual(manifest.listeners.map(x=>x.address),['169.254.169.254','10.0.1.100','10.0.2.10','192.0.2.10']);
  assert.deepEqual(manifest.listeners.map(x=>x.port),[80,8080,80,80]);
  for(const x of manifest.listeners)assert.ok(source.includes('"'+x.address+'"'));
  assert.match(source,/ports\[\]=\{80,8080,80,80\}/);
});
