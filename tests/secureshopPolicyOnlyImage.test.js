'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const dockerfile = fs.readFileSync(path.join(root, 'sidecars/sandbox-runner/policy-render/Dockerfile'), 'utf8');

test('dedicated image packages only the checked strict policy renderer', () => {
  assert.match(dockerfile, /FROM docker\.io\/library\/node:26\.10\.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1/g);
  assert.match(dockerfile, /gcc -static[^\n]*process-supervisor\.c[^\n]*dvaia-policy-render-supervisor/);
  assert.match(dockerfile, /gcc -static[^\n]*policy-init\.c[^\n]*dvaia-policy-render-init/);
  assert.match(dockerfile, /COPY policy-render\/listener\.js policy-render\/executor\.js policy-render\/http-handler\.js policy-render\/worker\.js/);
  assert.match(dockerfile, /COPY policy-render\/assets \.\/policy-render\/assets/);
  assert.match(dockerfile, /COPY policy-render\/secureshopPromptPolicyContract\.js \/server\/services\/secureshopPromptPolicyContract\.js/);
  assert.match(dockerfile, /USER 10001:10001/);
  assert.match(dockerfile, /ENTRYPOINT \["\/usr\/local\/bin\/node", "\/app\/policy-render\/listener\.js"\]/);
  for (const forbidden of [/COPY index\.js/, /COPY entrypoint\.sh/, /COPY labfs/, /COPY ownedTargetApi\.js/,
    /COPY mcpTargets\.js/, /COPY protected-operations/, /\bVOLUME\b/]) {
    assert.doesNotMatch(dockerfile, forbidden);
  }
  const canonical = fs.readFileSync(path.join(root, 'server/services/secureshopPromptPolicyContract.js'));
  const packaged = fs.readFileSync(path.join(root, 'sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract.js'));
  assert.deepEqual(packaged, canonical);
});
