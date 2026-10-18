'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '../sidecars/sandbox-runner/owned-system');
const { runLocalSystemListener } = require('../sidecars/sandbox-runner/owned-system/local-listener-entry');

test('local entry rejects absent, extra and arbitrary modes before loading a listener', async () => {
  for (const argv of [[], ['other'], ['config', 'diagnostic'], ['../http-listener'], ['--help']]) {
    let calls = 0; const output = [];
    const result = await runLocalSystemListener({ argv, runConfig: () => { calls++; },
      runDiagnostic: () => { calls++; }, runRestart: () => { calls++; }, write: value => output.push(value) });
    assert.equal(result, 1); assert.equal(calls, 0);
    assert.deepEqual(output, ['SYSTEM_LOCAL_LISTENER_MODE_INVALID\n']);
  }
});

test('local entry preserves existing explicit enable/token configuration and lifecycle exit', async () => {
  for (const mode of ['config', 'diagnostic', 'restart']) {
    const env = Object.freeze({ PRIVATE_TEST_MARKER: 'not-logged' }); const calls = [];
    const selected = async options => { assert.equal(options.env, env); calls.push(mode); return 7; };
    assert.equal(await runLocalSystemListener({ argv: [mode], env,
      runConfig: mode === 'config' ? selected : () => assert.fail('wrong listener'),
      runDiagnostic: mode === 'diagnostic' ? selected : () => assert.fail('wrong listener'),
      runRestart: mode === 'restart' ? selected : () => assert.fail('wrong listener'),
      write: () => assert.fail('entry must not log configuration') }), 7);
    assert.deepEqual(calls, [mode]);
  }
});

test('unexpected listener failure is categorical and real CLI never defaults to enabled', async () => {
  let output = '';
  assert.equal(await runLocalSystemListener({ argv: ['config'], runConfig: async () => { throw Error('private credential'); },
    write: text => { output += text; } }), 1);
  assert.equal(output, 'SYSTEM_LOCAL_LISTENER_FAILED\n');
  const child = spawnSync(process.execPath, [path.join(root, 'local-listener-entry.js')],
    { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 3000 });
  assert.equal(child.status, 1); assert.equal(child.stdout, 'SYSTEM_LOCAL_LISTENER_MODE_INVALID\n');
  assert.equal(child.stderr, '');
});

for (const imageFile of ['Dockerfile.local', 'Dockerfile.local.amd64.candidate']) test(`${imageFile} contains the complete fixed JS dependency closure and checked assets`, () => {
  const dockerfile = fs.readFileSync(path.join(root, imageFile), 'utf8');
  const copy = dockerfile.split('\n').find(line => line.startsWith('COPY --chown=0:0 local-listener-entry.js '));
  const packaged = new Set(copy.split(/\s+/).slice(2, -1));
  for (const file of packaged) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    for (const [, dependency] of source.matchAll(/require\(['"]\.\/([^'"]+)['"]\)/g)) {
      assert.ok(packaged.has(dependency + '.js'), `${file} requires missing ${dependency}`);
    }
  }
  require('../sidecars/sandbox-runner/owned-system/executor').loadAssets();
  assert.deepEqual([...packaged].filter(name => /qualification|attack|native/.test(name)),
    imageFile === 'Dockerfile.local' ? ['upload-preview-native-qualification.js'] : []);
});

test('local image pins reviewed architecture/base and fixed helper paths without activating or mounting', () => {
  const source = fs.readFileSync(path.join(root, 'Dockerfile.local'), 'utf8');
  assert.match(source, /^FROM node@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1$/m);
  assert.match(source, /test "\$\(dpkg --print-architecture\)" = arm64/);
  for (const name of ['config-init', 'config-supervisor', 'diagnostic-init', 'diagnostic-supervisor', 'restart-init', 'restart-supervisor']) {
    assert.match(source, new RegExp('gcc -static -O2 -Wall -Wextra -Werror [^\\n]+ -o /usr/local/libexec/dvaia-system-' + name));
  }
  assert.match(source, /sha256sum "\$file"/); assert.match(source, /USER 10001:10001/);
  assert.match(source, /restart-systemctl/); assert.match(source, /\/var\/lib\/dvaia-owned-restart/);
  assert.match(source, /find \/opt\/dvaia-owned-system -type f -exec chmod 0444 \{\} \+/);
  assert.doesNotMatch(source, /^(?:ENV|VOLUME|EXPOSE|CMD|ADD)\s/m);
});
